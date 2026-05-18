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

pub mod branches;
pub mod cli;
pub mod commands;
pub mod config;
pub mod control;
pub mod heartbeat;
pub mod log;
pub mod metrics;
pub mod pending_peers;
pub mod proxy;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio_util::sync::CancellationToken;

use yggdrasil_proto::auth::{StaticKeyPair, PUBLIC_KEY_LEN};

use crate::control::ControlServer;
use crate::heartbeat::{HeartbeatServer, PeerState, UNENROLLED_PEER_KEY};
use crate::pending_peers::PendingPeerStore;
use crate::proxy::supervisor::ProxySupervisor;

/// Default branch-watcher debounce. Small enough to feel snappy for an admin
/// editing TOML; large enough to coalesce editor `write → rename` storms.
pub const BRANCH_DEBOUNCE: Duration = Duration::from_millis(250);

/// Run the proxy server. This is the function the `yggdrasil run` subcommand
/// invokes; tests can call it directly to drive the full server stack.
///
/// The function returns when SIGINT/SIGTERM is observed or when the supplied
/// config / branch directory is invalid in a way that prevents startup.
pub async fn run(args: cli::RunArgs) -> Result<()> {
    let config = config::ServerConfig::load(&args.config)
        .with_context(|| format!("loading server config from {}", args.config.display()))?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config  = %args.config.display(),
        heartbeat_listen = %config.server.heartbeat_listen,
        branches_dir     = %config.server.branches_dir.display(),
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
    if let Err(e) = metrics::init(config.metrics.listen) {
        tracing::warn!(error = %e, "metrics exporter failed to start; continuing without it");
    }

    // 5. Heartbeat control plane.
    let hb = HeartbeatServer::bind(
        config.server.heartbeat_listen,
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

    // 6. Branch-driven proxy supervisor.
    let supervisor = ProxySupervisor::spawn(
        config.server.branches_dir.clone(),
        BRANCH_DEBOUNCE,
        peer_state.clone(),
        shutdown.clone(),
    )
    .await
    .context("spawning proxy supervisor")?;

    // 7. UDS control surface for `yggdrasilctl`.
    let control = ControlServer::bind(
        config.control.socket.clone(),
        peer_state.clone(),
        &supervisor,
        pending_store.clone(),
        args.config.clone(),
        shutdown.clone(),
    )
    .await
    .context("binding control socket")?;

    tracing::info!(
        control_socket = %control.socket_path().display(),
        "yggdrasil running"
    );

    // 8. Wait for shutdown signal, then bring everything down cleanly.
    wait_for_shutdown().await;
    tracing::info!("yggdrasil shutting down");
    shutdown.cancel();
    control.stop().await;
    supervisor.stop().await;
    let _ = hb_handle.await;
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
