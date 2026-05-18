//! yggdrasil — high-performance TCP/UDP reverse proxy for residential upstreams.
//!
//! This crate is structured as a library exposing the server's subsystems
//! plus a thin `bin/yggdrasil` entrypoint (`src/main.rs`). The library
//! layout exists so that:
//!
//! * Integration tests in `tests/` can drive the full server stack via
//!   public APIs (heartbeat invariance, IP-change, hot-reload).
//! * Criterion benches in `benches/` can target the actual production
//!   types (the UDP flow table in particular) without going through
//!   socket IO.
//!
//! Every subsystem is `pub` at the crate root; consumers depending on
//! internals are expected to be either the binary entrypoint or the
//! integration test / bench suite living inside this crate.

pub mod rules;
pub mod cli;
pub mod commands;
pub mod config;
pub mod control;
pub mod heartbeat;
pub mod log;
pub mod metrics;
pub mod pending_peers;
pub mod proxy;
pub mod systemd;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio_util::sync::CancellationToken;

use ratatoskr::auth::{StaticKeyPair, PUBLIC_KEY_LEN};

use crate::control::ControlServer;
use crate::heartbeat::{HeartbeatServer, PeerState, UNENROLLED_PEER_KEY};
use crate::pending_peers::PendingPeerStore;
use crate::proxy::resolver::ResolverFactory;
use crate::proxy::supervisor::{CertConfig, ProxySupervisor};

/// Default rule-watcher debounce. Small enough to feel snappy for an admin
/// editing TOML; large enough to coalesce editor `write → rename` storms.
pub const RULE_DEBOUNCE: Duration = Duration::from_millis(250);

/// Run the proxy server. This is the function the `yggdrasil run` subcommand
/// invokes; tests can call it directly to drive the full server stack.
///
/// The function returns when SIGINT/SIGTERM is observed or when the supplied
/// config / rules directory is invalid in a way that prevents startup.
///
/// At this layer `run` is a thin dispatcher: it loads and validates the
/// config (applying CLI overrides), then hands off to [`run_relay`] or
/// [`run_terminal`]. Tests that want to drive a specific mode without the
/// CLI machinery can call those directly.
pub async fn run(args: cli::RunArgs) -> Result<()> {
    let mut config = config::ServerConfig::load(&args.config)
        .with_context(|| format!("loading server config from {}", args.config.display()))?;

    // CLI overrides applied after config load. `--mode` overrides the
    // `[server].mode` field, `--rules-dir` overrides `[server].rules_dir`,
    // `--bind` overrides `[server].default_bind`. We re-validate so that an
    // override (e.g. flipping mode → terminal on a relay-shaped config) is
    // caught by the same matrix as a TOML-only config would be.
    if let Some(mode) = args.mode {
        config.server.mode = mode.into();
    }
    if let Some(ref dir) = args.rules_dir {
        config.server.rules_dir = dir.clone();
    }
    if let Some(ip) = args.bind {
        config.server.default_bind = Some(ip);
    }
    config
        .validate()
        .with_context(|| "re-validating config after applying CLI overrides")?;

    match config.server.mode {
        config::Mode::Relay => run_relay(args, config).await,
        config::Mode::Terminal => run_terminal(args, config).await,
    }
}

/// Run the relay-mode daemon: heartbeat server, peer state, pending-peer
/// store, dynamic-IP-resolved proxies.
pub async fn run_relay(args: cli::RunArgs, config: config::ServerConfig) -> Result<()> {
    // Validation in `ServerConfig::validate` guarantees `heartbeat_listen` is
    // `Some` in relay mode.
    let heartbeat_listen = config
        .server
        .heartbeat_listen
        .expect("relay mode requires heartbeat_listen (validated)");

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config  = %args.config.display(),
        mode = config.server.mode.as_str(),
        heartbeat_listen = %heartbeat_listen,
        rules_dir = %config.server.rules_dir.display(),
        "yggdrasil starting"
    );

    // 1. Load our long-term X25519 identity.
    let local_keys = StaticKeyPair::load_from_file(&config.server.identity_file)
        .with_context(|| {
            format!(
                "loading server identity from {}",
                config.server.identity_file.display()
            )
        })?;

    // 2. Resolve the configured peer. An empty `peer.public_key_hex` is
    //    legitimate: the daemon comes up in TOFU staging mode, accepts no
    //    handshakes, but records each unknown candidate to
    //    `state_dir/pending_peers.toml` for the operator to approve via
    //    `yggdrasilctl peer approve <fingerprint>`.
    let peer_pubkey = if config.peer.public_key_hex.is_empty() {
        tracing::warn!(
            "no peer enrolled (peer.public_key_hex empty). \
             Daemon will accept no traffic until you approve a candidate via \
             `yggdrasilctl peer approve <fingerprint>`."
        );
        UNENROLLED_PEER_KEY
    } else {
        decode_pubkey_hex(&config.peer.public_key_hex)
            .context("decoding peer.public_key_hex")?
    };
    let peer_state = PeerState::new(peer_pubkey);
    if peer_state.is_peer_enrolled() {
        tracing::info!(
            peer = %peer_state.fingerprint(),
            "peer identity loaded"
        );
    }

    // 2b. TOFU staging store, persisted under state_dir.
    let pending_store = Arc::new(
        PendingPeerStore::load(&config.server.state_dir)
            .context("loading pending peer store")?,
    );

    // 3. One shutdown token rules them all. SIGTERM/SIGINT cancels it; both
    //    the heartbeat server and the proxy supervisor observe it.
    let shutdown = CancellationToken::new();

    // 4. Metrics exporter. Set up before anything emits metrics so the global
    //    recorder is the prometheus one and not the no-op fallback.
    if let Err(e) = metrics::init(config.metrics.listen, ratatoskr::control::Mode::Relay) {
        tracing::warn!(error = %e, "metrics exporter failed to start; continuing without it");
    }

    // 5. Heartbeat control plane.
    let hb = HeartbeatServer::bind(
        heartbeat_listen,
        local_keys,
        peer_state.clone(),
        pending_store.clone(),
        shutdown.clone(),
    )
    .await
    .context("binding heartbeat server")?;
    let hb_handle = tokio::spawn(async move {
        if let Err(e) = hb.run().await {
            tracing::error!(error = %e, "heartbeat server exited with error");
        }
    });

    // 6. Rule-driven proxy supervisor.
    let resolver_factory = ResolverFactory::new_relay(peer_state.clone());
    let supervisor = ProxySupervisor::spawn(
        config.server.rules_dir.clone(),
        RULE_DEBOUNCE,
        resolver_factory,
        config.server.default_bind,
        CertConfig::from_server_section(
            config.server.cert_dir.clone(),
            config.server.default_cert.clone(),
            config.server.default_key.clone(),
        ),
        shutdown.clone(),
    )
    .await
    .context("spawning proxy supervisor")?;

    // 7. UDS control surface for `yggdrasilctl`.
    let control = ControlServer::bind(
        config.control.socket.clone(),
        ratatoskr::control::Mode::Relay,
        Some(peer_state.clone()),
        &supervisor,
        Some(pending_store.clone()),
        args.config.clone(),
        shutdown.clone(),
    )
    .await
    .context("binding control socket")?;

    tracing::info!(
        control_socket = %control.socket_path().display(),
        "yggdrasil running"
    );

    // 7b. All subsystems are up; notify systemd we are ready. No-op when
    //     NOTIFY_SOCKET is unset (local dev, docker without --systemd).
    systemd::notify_ready();

    // 8. Wait for shutdown signal, then bring everything down cleanly.
    wait_for_shutdown().await;
    tracing::info!("yggdrasil shutting down");
    shutdown.cancel();
    control.stop().await;
    supervisor.stop().await;
    let _ = hb_handle.await;
    Ok(())
}

/// Run the terminal-mode daemon: no heartbeat, no peer state, no pending
/// peers. Just the proxy supervisor (with a static resolver factory),
/// metrics exporter, and the control socket.
///
/// The identity file is loaded and the public-key fingerprint logged for
/// future cross-daemon authentication features; it is not used on the wire
/// today.
pub async fn run_terminal(args: cli::RunArgs, config: config::ServerConfig) -> Result<()> {
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config  = %args.config.display(),
        mode = config.server.mode.as_str(),
        rules_dir = %config.server.rules_dir.display(),
        "yggdrasil starting"
    );

    // 1. Load our long-term X25519 identity. Even in terminal mode the daemon
    //    keeps a stable identity for future cross-daemon authentication
    //    features; today it does not appear on the wire.
    let _local_keys = StaticKeyPair::load_from_file(&config.server.identity_file)
        .with_context(|| {
            format!(
                "loading server identity from {}",
                config.server.identity_file.display()
            )
        })?;
    tracing::info!("identity loaded; not used on the wire in terminal mode");

    // 2. Shutdown token observed by the supervisor and control server.
    let shutdown = CancellationToken::new();

    // 3. Metrics exporter. Set up before anything emits metrics so the global
    //    recorder is the prometheus one and not the no-op fallback.
    if let Err(e) = metrics::init(config.metrics.listen, ratatoskr::control::Mode::Terminal) {
        tracing::warn!(error = %e, "metrics exporter failed to start; continuing without it");
    }

    // 4. Rule-driven proxy supervisor with a terminal-mode factory: every
    //    rule must carry `upstream_addr`; `upstream_port` rules are rejected
    //    by `ResolverFactory::build`.
    let resolver_factory = ResolverFactory::new_terminal();
    let supervisor = ProxySupervisor::spawn(
        config.server.rules_dir.clone(),
        RULE_DEBOUNCE,
        resolver_factory,
        config.server.default_bind,
        CertConfig::from_server_section(
            config.server.cert_dir.clone(),
            config.server.default_cert.clone(),
            config.server.default_key.clone(),
        ),
        shutdown.clone(),
    )
    .await
    .context("spawning proxy supervisor")?;

    // 5. UDS control surface for `yggdrasilctl`. Terminal mode has no peer
    //    identity, so the peer-related endpoints return
    //    `not_supported_in_terminal_mode`.
    let control = ControlServer::bind(
        config.control.socket.clone(),
        ratatoskr::control::Mode::Terminal,
        None,
        &supervisor,
        None,
        args.config.clone(),
        shutdown.clone(),
    )
    .await
    .context("binding control socket")?;

    tracing::info!(
        control_socket = %control.socket_path().display(),
        "yggdrasil running"
    );

    // 5b. All subsystems are up; notify systemd we are ready. No-op when
    //     NOTIFY_SOCKET is unset (local dev, docker without --systemd).
    systemd::notify_ready();

    // 6. Wait for shutdown signal, then bring everything down cleanly.
    wait_for_shutdown().await;
    tracing::info!("yggdrasil shutting down");
    shutdown.cancel();
    control.stop().await;
    supervisor.stop().await;
    Ok(())
}

async fn wait_for_shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to install SIGTERM handler");
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("received SIGINT"),
        _ = sigterm.recv()          => tracing::info!("received SIGTERM"),
    }
}

fn decode_pubkey_hex(hex_str: &str) -> Result<[u8; PUBLIC_KEY_LEN]> {
    let bytes = hex::decode(hex_str).context("not valid hex")?;
    let arr: [u8; PUBLIC_KEY_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("expected exactly {PUBLIC_KEY_LEN} bytes, got {}", bytes.len()))?;
    Ok(arr)
}
