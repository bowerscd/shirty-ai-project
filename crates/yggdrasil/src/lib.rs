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

use crate::chain::{ChainAcceptor, ChainClient, ChainClientConfig, ChainClientHandle, TunnelAllowList, TunnelManager};
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

/// Run the relay-mode daemon: optional inbound chain listener, peer
/// state, pending-peer store, dynamic-IP-resolved proxies. May also dial
/// an upstream chain client when `[chain.upstream]` is configured.
pub async fn run_relay(args: cli::RunArgs, config: config::ServerConfig) -> Result<()> {
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config  = %args.config.display(),
        mode = config.server.mode.as_str(),
        chain_listener = ?config.chain.listener.as_ref().map(|l| l.listen),
        chain_upstream = ?config.chain.upstream.as_ref().map(|u| &u.endpoint),
        rules_dir = %config.server.rules_dir.display(),
        "yggdrasil starting"
    );

    // 1. Load (or auto-generate) our long-term X25519 identity.
    let local_keys = load_or_generate_identity(&config.server.identity_file)?;

    // 2. Resolve the configured downstream. No `[chain.downstream]` means
    //    the daemon comes up in TOFU staging mode (when a listener is also
    //    configured); a candidate may then be approved via
    //    `yggdrasilctl identity add-downstream`.
    let downstream_pubkey = match config.chain.downstream.as_ref() {
        Some(dn) => *dn
            .pubkey
            .as_x25519()
            .expect("PubKey::X25519 only variant in v1"),
        None => {
            if config.chain.listener.is_some() {
                tracing::warn!(
                    "no downstream enrolled ([chain.downstream] absent). \
                     Daemon will accept no traffic until you approve a candidate via \
                     `yggdrasilctl identity add-downstream`."
                );
            }
            UNENROLLED_PEER_KEY
        }
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
    if let Err(e) = metrics::init(config.metrics.listen, ratatoskr::control::Mode::Relay).await {
        tracing::warn!(error = %e, "metrics exporter failed to start; continuing without it");
    }

    // 5. Rule-driven proxy supervisor. Built *before* the heartbeat
    //    listener so the chain acceptor can hold a handle to it.
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

    // 5b. Chain acceptor — receive-side dispatcher for inbound
    //     `PredicateSetUpdate` envelopes. Built only when a listener is
    //     configured: without a listener we never receive Control
    //     packets, so the acceptor would be unused. Persists per-origin
    //     versions under `state_dir/chain-predicates.toml`.
    let chain_acceptor = if config.chain.listener.is_some() {
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

    // 6. Heartbeat (chain) listener — only when [chain.listener] is set.
    //    A pure-proxy relay (no downstream/listener, only an upstream) is
    //    a legitimate mid-chain configuration that does no inbound work.
    let hb_handle = if let Some(listener) = config.chain.listener.as_ref() {
        let (hb, outbound) = HeartbeatServer::bind(
            listener.listen,
            local_keys.clone(),
            peer_state.clone(),
            pending_store.clone(),
            chain_acceptor.clone(),
            shutdown.clone(),
        )
        .await
        .context("binding chain listener")?;

        // Phase 4B tunnel terminator. Only meaningful alongside a
        // chain listener (the inbound side decodes `TunnelOpen`); a
        // pure-upstream relay has nothing to terminate.
        if let Some(acc) = chain_acceptor.as_ref() {
            let allow = TunnelAllowList {
                allow_loopback: config.chain.tunnel.allow_loopback,
                allowed_targets: config
                    .chain
                    .tunnel
                    .allowed_targets
                    .iter()
                    .copied()
                    .collect(),
            };
            let mgr = TunnelManager::new(
                allow,
                ratatoskr::pubkey::PubKey::x25519(*local_keys.public_key()),
                outbound.sender(),
            );
            // First call wins; if some future refactor sets it twice
            // we surface that as a hard error so the operator notices.
            acc.set_tunnel_manager(mgr)
                .map_err(|_| anyhow::anyhow!("tunnel manager set twice"))?;
        } else {
            // No acceptor means we'll never decode Tunnel* bodies; drop
            // the outbound handle so the server's keepalive is the only
            // sender (channel stays open, nobody writes to it).
            drop(outbound);
        }

        Some(tokio::spawn(async move {
            if let Err(e) = hb.run().await {
                tracing::error!(error = %e, "chain listener exited with error");
            }
        }))
    } else {
        None
    };

    // 6b. Outbound chain client — only when [chain.upstream] is set.
    //     Phase 3B does not push predicates from relays; the handle is
    //     therefore unused on this path. We still keep the chain client
    //     spawned so mid-chain relays maintain their upstream session.
    let chain_client = spawn_chain_client(&config, &local_keys, shutdown.clone());
    let _chain_client_handle = chain_client.as_ref().map(|c| c.handle.clone());
    let chain_initiator = chain_client.as_ref().map(|c| c.initiator.clone());
    let chain_client_join = chain_client.map(|c| c.join);

    // 7. UDS control surface for `yggdrasilctl`.
    let control = ControlServer::bind(
        config.control.socket.clone(),
        ratatoskr::control::Mode::Relay,
        Some(peer_state.clone()),
        &supervisor,
        Some(pending_store.clone()),
        args.config.clone(),
        chain_initiator,
        shutdown.clone(),
    )
    .await
    .context("binding control socket")?;

    tracing::info!(
        control_socket = %control.socket_path().display(),
        "yggdrasil running"
    );

    health::mark_ready();
    systemd::notify_ready();

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
pub async fn run_terminal(args: cli::RunArgs, config: config::ServerConfig) -> Result<()> {
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config  = %args.config.display(),
        mode = config.server.mode.as_str(),
        chain_upstream = ?config.chain.upstream.as_ref().map(|u| &u.endpoint),
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

    // 3. Metrics exporter.
    if let Err(e) = metrics::init(config.metrics.listen, ratatoskr::control::Mode::Terminal).await {
        tracing::warn!(error = %e, "metrics exporter failed to start; continuing without it");
    }

    // 3b. Outbound chain client — only when [chain.upstream] is set.
    //     A terminal node without an upstream is still useful (pure local
    //     proxy), so absence is not an error.
    let chain_client = spawn_chain_client(&config, &local_keys, shutdown.clone());
    let chain_client_handle = chain_client.as_ref().map(|c| c.handle.clone());
    let chain_initiator = chain_client.as_ref().map(|c| c.initiator.clone());
    let chain_client_join = chain_client.map(|c| c.join);

    // 4. Rule-driven proxy supervisor with a terminal-mode factory: every
    //    rule must carry `upstream_addr`; `upstream_port` rules are
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

    // 5. UDS control surface. Terminal mode has no downstream identity, so
    //    peer-related endpoints return `not_supported_in_terminal_mode`.
    let control = ControlServer::bind(
        config.control.socket.clone(),
        ratatoskr::control::Mode::Terminal,
        None,
        &supervisor,
        None,
        args.config.clone(),
        chain_initiator,
        shutdown.clone(),
    )
    .await
    .context("binding control socket")?;

    // 5b. Predicate publisher — only when the chain client is present.
    //     Watches the supervisor's `current_set` channel and pushes each
    //     applied [`RuleSet`] upstream as a `PredicateSetUpdate` envelope.
    //     Pure-local terminals (no upstream) have no one to push to and
    //     this publisher is skipped.
    let predicate_publisher_join = chain_client_handle.as_ref().map(|handle| {
        let origin = ratatoskr::pubkey::PubKey::x25519(*local_keys.public_key());
        let supervisor_handle = supervisor.handle();
        chain::predicate_publisher::spawn(
            supervisor_handle.current_set_rx(),
            handle.clone(),
            origin,
            config.server.state_dir.clone(),
            shutdown.clone(),
        )
    });

    tracing::info!(
        control_socket = %control.socket_path().display(),
        "yggdrasil running"
    );

    health::mark_ready();
    systemd::notify_ready();

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

/// Spawned chain client — the join handle plus a cloneable
/// [`ChainClientHandle`] for callers that want to enqueue control
/// envelopes (e.g. the predicate publisher on terminals) and the
/// [`TunnelInitiator`] wired as the client's body handler.
///
/// The initiator is `Some` whenever the chain client is spawned; it is
/// passed into [`ControlServer::bind`] so the `OpenChainTunnel` UDS
/// hijack can find a place to forward operator bytes.
struct SpawnedChainClient {
    join: tokio::task::JoinHandle<()>,
    handle: ChainClientHandle,
    initiator: Arc<crate::chain::TunnelInitiator>,
}

/// Spawn the outbound chain client when `[chain.upstream]` is configured.
/// Returns `None` when no upstream is set (a legitimate configuration for
/// pure-proxy nodes and root relays).
fn spawn_chain_client(
    config: &config::ServerConfig,
    local_keys: &StaticKeyPair,
    shutdown: CancellationToken,
) -> Option<SpawnedChainClient> {
    let up = config.chain.upstream.as_ref()?;
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
        "spawning chain client"
    );
    let mut client = ChainClient::new(cfg, shutdown);
    let handle = client.handle();
    // Build the tunnel initiator using the live handle, then install its
    // body handler before `client.run()` begins draining the chain
    // socket. The handler is a synchronous `Arc<dyn Fn>` so installing
    // it after construction is just a pointer swap.
    let initiator = crate::chain::TunnelInitiator::new(
        handle.clone(),
        ratatoskr::pubkey::PubKey::x25519(upstream_pubkey),
    );
    client.set_body_handler(initiator.body_handler());
    let join = tokio::spawn(async move {
        if let Err(e) = client.run().await {
            tracing::error!(error = %e, "chain client exited with error");
        }
    });
    Some(SpawnedChainClient { join, handle, initiator })
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

