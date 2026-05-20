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
pub mod chain;
pub mod cli;
pub mod config;
pub mod control;
pub mod health;
pub mod heartbeat;
pub mod log;
pub mod metrics;
pub mod pending_peers;
pub mod proxy;
pub mod systemd;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;

use ratatoskr::auth::StaticKeyPair;

use crate::chain::{ChainAcceptor, ChainClient, ChainClientConfig, ChainClientHandle};
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

    // CLI overrides applied after config load. `--rules-dir` overrides
    // `[server].rules_dir`, `--bind` overrides `[server].default_bind`.
    if let Some(ref dir) = args.rules_dir {
        config.server.rules_dir = dir.clone();
    }
    if let Some(ip) = args.bind {
        config.server.default_bind = Some(ip);
    }
    config
        .validate()
        .with_context(|| "re-validating config after applying CLI overrides")?;

    let mode = config
        .derived_mode()
        .with_context(|| "deriving effective mode from [dial]/[accept]")?;
    if let Some(required) = args.require_mode {
        let required = config::Mode::from(required);
        anyhow::ensure!(
            mode == required,
            "--require-mode={} but config resolves to {}",
            required.as_str(),
            mode.as_str()
        );
    }

    match mode {
        config::Mode::Gateway | config::Mode::Relay => run_relay(args, config, mode).await,
        config::Mode::Terminal => run_terminal(args, config, mode).await,
    }
}

/// Run the relay-mode daemon: optional inbound chain listener, peer
/// state, pending-peer store, dynamic-IP-resolved proxies. May also dial
/// an upstream chain client when `[dial]` is configured.
pub async fn run_relay(
    args: cli::RunArgs,
    config: config::ServerConfig,
    mode: config::Mode,
) -> Result<()> {
    let wire_mode: ratatoskr::control::Mode = mode.into();
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config  = %args.config.display(),
        mode = mode.as_str(),
        accept_listen = ?config.accept.as_ref().map(|a| a.listen),
        dial_endpoint = ?config.dial.as_ref().map(|d| &d.endpoint),
        rules_dir = %config.server.rules_dir.display(),
        "yggdrasil starting"
    );

    // 1. Load (or auto-generate) our long-term X25519 identity.
    let local_keys = load_or_generate_identity(&config.server.identity_file)?;

    // 2. Resolve the configured inbound peer from `[accept].pubkey`.
    //    No `[accept]` means the daemon has no inbound chain peer at
    //    all; we still keep a TOFU staging hook here for the future
    //    `yggdrasilctl identity add-accept` flow.
    let downstream_pubkey = match config.accept.as_ref() {
        Some(acc) => *acc
            .pubkey
            .as_x25519()
            .expect("PubKey::X25519 only variant in v1"),
        None => UNENROLLED_PEER_KEY,
    };
    let peer_state = PeerState::new(downstream_pubkey);
    if peer_state.is_peer_enrolled() {
        tracing::info!(
            downstream = %peer_state.fingerprint(),
            "downstream identity loaded"
        );
    }

    // 2b. TOFU staging store, persisted under state_dir.
    let pending_store = Arc::new(
        PendingPeerStore::load(&config.server.state_dir)
            .context("loading pending peer store")?,
    );

    // 3. One shutdown token rules them all.
    let shutdown = CancellationToken::new();

    // 4. Metrics exporter. Set up before anything emits metrics so the
    //    global recorder is the prometheus one and not the no-op fallback.
    //    The [`IntrospectionSlot`] is created up front and populated in
    //    step 5b once the supervisor exists — see [`crate::chain::introspection`]
    //    for the ordering rationale.
    let introspection_slot = metrics::new_introspection_slot();
    let prom_handle = metrics::install_recorder(wire_mode)
        .context("installing prometheus recorder")?;
    if let Err(e) = metrics::spawn_http(
        config.metrics.listen,
        wire_mode,
        prom_handle.clone(),
        Some(introspection_slot.clone()),
    )
    .await
    {
        tracing::warn!(error = %e, "metrics http listener failed to bind; continuing without it");
    }

    // 5. Rule-driven proxy supervisor. Built *before* the heartbeat
    //    listener so the chain acceptor can hold a handle to it.
    let resolver_factory = match mode {
        config::Mode::Gateway => ResolverFactory::new_gateway(peer_state.clone()),
        config::Mode::Relay => ResolverFactory::new_relay(peer_state.clone()),
        config::Mode::Terminal => unreachable!("run_relay only dispatched for gateway/relay"),
    };
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

    // 5a. Phase 5B introspection state. Constructed now that the
    //     supervisor exists. The `/internal/derived-rules` endpoint
    //     reads this lazily through `introspection_slot`.
    //
    //     `record_apply` writers:
    //     * the chain acceptor (on a relay) — attached below.
    //     * the predicate publisher (on a terminal) — does not apply
    //       in `run_relay`; terminals install their own state in
    //       [`crate::run_terminal`].
    let introspection_state = crate::chain::IntrospectionState::new(
        ratatoskr::pubkey::PubKey::x25519(*local_keys.public_key()),
        config.dial.as_ref().map(|d| d.pubkey),
        config.accept.as_ref().map(|a| a.pubkey),
        supervisor.handle(),
    );
    if introspection_slot.set(introspection_state.clone()).is_err() {
        // Slot was constructed fresh above; nobody else can have set
        // it. If this ever fires, the orchestration layer has been
        // reordered incorrectly.
        anyhow::bail!("introspection slot set twice; orchestration ordering bug");
    }

    // 5b. Chain acceptor — receive-side dispatcher for inbound
    //     `PredicateSetUpdate` envelopes. Built only when a listener is
    //     configured: without a listener we never receive Control
    //     packets, so the acceptor would be unused. Persists per-origin
    //     versions under `state_dir/chain-predicates.toml`.
    let chain_acceptor = if config.accept.is_some() {
        use std::net::{IpAddr, Ipv4Addr};
        let bind_addr = config
            .server
            .default_bind
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let derive_cfg = crate::chain::DeriveConfig {
            bind_addr,
            // Phase 3 does not yet plumb a relay-wide PROXY-protocol
            // policy; derived TCP rules are emitted without PROXY
            // headers until a future phase adds the config knob.
            proxy_protocol: None,
        };
        Some(
            ChainAcceptor::load(
                supervisor.handle(),
                derive_cfg,
                &config.server.state_dir,
            )
            .context("loading chain acceptor state")?,
        )
    } else {
        None
    };

    // 5c. Attach the introspection sink to the chain acceptor so the
    //     `/internal/derived-rules` snapshot updates on every inbound
    //     `PredicateSetUpdate` the relay accepts. Relays without a
    //     chain listener never accept pushes, so they skip this wiring
    //     — the snapshot's `predicates` array stays empty for the
    //     daemon's lifetime, which is the correct semantic.
    if let Some(acc) = chain_acceptor.as_ref() {
        acc.set_introspection(introspection_state.clone())
            .map_err(|_| anyhow::anyhow!("introspection set twice on acceptor"))?;
    }

    // 6. Heartbeat (chain) listener — only when [accept] is set.
    //    A pure-proxy relay (no downstream/listener, only an upstream) is
    //    a legitimate mid-chain configuration that does no inbound work.
    let hb_handle = if let Some(accept) = config.accept.as_ref() {
        let (hb, _outbound) = HeartbeatServer::bind(
            accept.listen,
            local_keys.clone(),
            peer_state.clone(),
            pending_store.clone(),
            chain_acceptor.clone(),
            shutdown.clone(),
        )
        .await
        .context("binding chain listener")?;

        Some(tokio::spawn(async move {
            if let Err(e) = hb.run().await {
                tracing::error!(error = %e, "chain listener exited with error");
            }
        }))
    } else {
        None
    };

    // 6b. Outbound chain client — only when [dial] is set.
    //     Phase 3B does not push predicates from relays; the handle is
    //     therefore unused on this path. We still keep the chain client
    //     spawned so mid-chain relays maintain their upstream session.
    let chain_client_join = match build_chain_client(&config, &local_keys, shutdown.clone()) {
        Some(built) => {
            let client = built.client;
            let join = tokio::spawn(async move {
                if let Err(e) = client.run().await {
                    tracing::error!(error = %e, "chain client exited with error");
                }
            });
            Some(join)
        }
        None => None,
    };
    let has_chain_upstream = config.dial.is_some();

    // 7. UDS control surface for `yggdrasilctl`.
    let control = ControlServer::bind(
        config.control.socket.clone(),
        wire_mode,
        Some(peer_state.clone()),
        &supervisor,
        Some(pending_store.clone()),
        args.config.clone(),
        has_chain_upstream,
        prom_handle.clone(),
        Some(introspection_state.clone()),
        shutdown.clone(),
    )
    .await
    .context("binding control socket")?;

    tracing::info!(
        control_socket = %control.socket_path().display(),
        "yggdrasil running"
    );

    health::mark_ready();
    systemd::notify_ready_with_status(&format!(
        "mode={}, accept={}, dial={}",
        mode.as_str(),
        if config.accept.is_some() { "yes" } else { "no" },
        if config.dial.is_some() { "yes" } else { "no" },
    ));

    wait_for_shutdown().await;
    tracing::info!("yggdrasil shutting down");
    shutdown.cancel();
    control.stop().await;
    supervisor.stop().await;
    if let Some(handle) = hb_handle {
        let _ = handle.await;
    }
    if let Some(handle) = chain_client_join {
        let _ = handle.await;
    }
    Ok(())
}

/// Run the terminal-mode daemon: no inbound chain listener, no peer
/// state, no pending peers. Just the proxy supervisor (with a static
/// resolver factory), metrics exporter, the control socket, and an
/// optional outbound chain client.
pub async fn run_terminal(
    args: cli::RunArgs,
    config: config::ServerConfig,
    mode: config::Mode,
) -> Result<()> {
    let wire_mode: ratatoskr::control::Mode = mode.into();
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config  = %args.config.display(),
        mode = mode.as_str(),
        dial_endpoint = ?config.dial.as_ref().map(|d| &d.endpoint),
        rules_dir = %config.server.rules_dir.display(),
        "yggdrasil starting"
    );

    // 1. Load (or auto-generate) our long-term X25519 identity. The
    //    terminal daemon uses this on the wire whenever it dials an
    //    upstream via the chain client.
    let local_keys = load_or_generate_identity(&config.server.identity_file)?;

    // 2. Shutdown token observed by the supervisor, the chain client, and
    //    the control server.
    let shutdown = CancellationToken::new();

    // 3. Metrics exporter. The [`IntrospectionSlot`] is created up
    //    front and populated in step 4a once the supervisor exists.
    let introspection_slot = metrics::new_introspection_slot();
    let prom_handle = metrics::install_recorder(wire_mode)
        .context("installing prometheus recorder")?;
    if let Err(e) = metrics::spawn_http(
        config.metrics.listen,
        wire_mode,
        prom_handle.clone(),
        Some(introspection_slot.clone()),
    )
    .await
    {
        tracing::warn!(error = %e, "metrics http listener failed to bind; continuing without it");
    }

    // 3b. Outbound chain client — only when [dial] is set.
    //     A terminal node without an upstream is still useful (pure local
    //     proxy), so absence is not an error.
    let (chain_client_join, chain_client_handle) =
        match build_chain_client(&config, &local_keys, shutdown.clone()) {
            Some(built) => {
                let handle = built.handle.clone();
                let client = built.client;
                let join = tokio::spawn(async move {
                    if let Err(e) = client.run().await {
                        tracing::error!(error = %e, "chain client exited with error");
                    }
                });
                (Some(join), Some(handle))
            }
            None => (None, None),
        };
    let has_chain_upstream = config.dial.is_some();

    // 4. Rule-driven proxy supervisor with a terminal-mode factory: every
    //    rule must carry `target_addr`; `target_port` rules are
    //    rejected by `ResolverFactory::build`.
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

    // 4a. Phase 5B introspection state. Terminals have no inbound
    //     chain listener, so `record_apply` is exclusively driven by
    //     the predicate publisher's success branch. `downstream` is
    //     always `None` here (terminals don't accept downstream
    //     connections).
    let introspection_state = crate::chain::IntrospectionState::new(
        ratatoskr::pubkey::PubKey::x25519(*local_keys.public_key()),
        config.dial.as_ref().map(|d| d.pubkey),
        None,
        supervisor.handle(),
    );
    if introspection_slot.set(introspection_state.clone()).is_err() {
        anyhow::bail!("introspection slot set twice; orchestration ordering bug");
    }

    // 5. UDS control surface. Terminal mode has no downstream identity, so
    //    peer-related endpoints return `not_supported_in_terminal_mode`.
    let control = ControlServer::bind(
        config.control.socket.clone(),
        wire_mode,
        None,
        &supervisor,
        None,
        args.config.clone(),
        has_chain_upstream,
        prom_handle.clone(),
        Some(introspection_state.clone()),
        shutdown.clone(),
    )
    .await
    .context("binding control socket")?;

    // 5b. Predicate publisher — only when the chain client is present.
    //     Watches the supervisor's `current_set` channel and pushes each
    //     applied [`RuleSet`] upstream as a `PredicateSetUpdate` envelope.
    //     Pure-local terminals (no upstream) have no one to push to and
    //     this publisher is skipped.
    //
    //     The publisher carries the introspection state through so it
    //     can update the `/internal/derived-rules` snapshot on each
    //     successful upstream ack (Phase 5B).
    let predicate_publisher_join = chain_client_handle.as_ref().map(|handle| {
        let origin = ratatoskr::pubkey::PubKey::x25519(*local_keys.public_key());
        let supervisor_handle = supervisor.handle();
        chain::predicate_publisher::spawn(
            supervisor_handle.current_set_rx(),
            handle.clone(),
            origin,
            config.server.state_dir.clone(),
            Some(introspection_state.clone()),
            shutdown.clone(),
        )
    });

    tracing::info!(
        control_socket = %control.socket_path().display(),
        "yggdrasil running"
    );

    health::mark_ready();
    systemd::notify_ready_with_status(&format!(
        "mode={}, dial={}",
        mode.as_str(),
        if config.dial.is_some() { "yes" } else { "no" },
    ));

    wait_for_shutdown().await;
    tracing::info!("yggdrasil shutting down");
    shutdown.cancel();
    control.stop().await;
    supervisor.stop().await;
    if let Some(handle) = predicate_publisher_join {
        let _ = handle.await;
    }
    if let Some(handle) = chain_client_join {
        let _ = handle.await;
    }
    Ok(())
}

/// Load the static X25519 identity from `path`, generating + persisting it
/// (mode 0600) if the file does not exist. Logs the fingerprint either way.
fn load_or_generate_identity(path: &std::path::Path) -> Result<StaticKeyPair> {
    if path.exists() {
        let kp = StaticKeyPair::load_from_file(path)
            .with_context(|| format!("loading identity from {}", path.display()))?;
        tracing::info!(
            identity_file = %path.display(),
            fingerprint = %kp.fingerprint(),
            "identity loaded"
        );
        Ok(kp)
    } else {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("creating identity directory {}", parent.display())
                })?;
            }
        }
        let kp = StaticKeyPair::generate().context("generating identity")?;
        kp.save_to_file(path)
            .with_context(|| format!("writing identity to {}", path.display()))?;
        tracing::info!(
            identity_file = %path.display(),
            fingerprint = %kp.fingerprint(),
            "identity auto-generated on first start"
        );
        Ok(kp)
    }
}

/// Built but un-spawned chain client. Returned by [`build_chain_client`]
/// so the caller can drive it with [`tokio::spawn`] on `client.run()`.
struct BuiltChainClient {
    client: ChainClient,
    handle: ChainClientHandle,
}

/// Build the outbound chain client when `[dial]` is configured,
/// *without* spawning. Returns `None` when no `[dial]` section is set
/// (a legitimate configuration for pure-proxy nodes and root relays).
fn build_chain_client(
    config: &config::ServerConfig,
    local_keys: &StaticKeyPair,
    shutdown: CancellationToken,
) -> Option<BuiltChainClient> {
    let up = config.dial.as_ref()?;
    let upstream_pubkey = *up
        .pubkey
        .as_x25519()
        .expect("PubKey::X25519 only variant in v1");
    let cfg = ChainClientConfig {
        endpoint: up.endpoint.clone(),
        upstream_pubkey,
        local_keys: local_keys.clone(),
        heartbeat_interval: up.heartbeat_interval,
        rekey_interval: up.rekey_interval,
        body_handler: None,
    };
    let upstream_fp = ratatoskr::auth::public_key_fingerprint(&upstream_pubkey);
    tracing::info!(
        upstream_endpoint = %up.endpoint,
        upstream_fingerprint = %upstream_fp,
        heartbeat_interval = ?up.heartbeat_interval,
        rekey_interval = ?up.rekey_interval,
        "building chain client"
    );
    let client = ChainClient::new(cfg, shutdown);
    let handle = client.handle();
    Some(BuiltChainClient { client, handle })
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

