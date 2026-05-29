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

pub mod chain;
pub mod cli;
pub mod config;
pub mod control;
pub mod health;
pub mod heartbeat;
pub mod lan_cidrs;
pub mod log;
pub mod metrics;
pub mod nat;
pub mod pending_peers;
pub mod profile;
pub mod proxy;
pub mod rules;
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
    let node_name = config.resolved_name();
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config  = %args.config.display(),
        mode = mode.as_str(),
        name = %node_name,
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
        PendingPeerStore::load(&config.server.state_dir).context("loading pending peer store")?,
    );

    // 3. One shutdown token rules them all.
    let shutdown = CancellationToken::new();

    // 4. Metrics recorder. Set up before anything emits metrics so the
    //    global recorder is the prometheus one and not the no-op fallback.
    //    Text exposition is served exclusively over the UDS via
    //    [`ratatoskr::control::Request::Metrics`]; there is no HTTP
    //    listener.
    let prom_handle =
        metrics::install_recorder(wire_mode).context("installing prometheus recorder")?;

    // 4b. Shared canary arm table. Held by the supervisor (so every
    //     per-rule TCP/UDP proxy can short-circuit canary-tagged
    //     traffic to in-process echoes) AND by the chain acceptor
    //     (which installs arm entries on `CanaryArm` envelopes). The
    //     table is empty until an operator runs `yggdrasilctl chain
    //     canary`, so this only allocates the `Arc<DashMap>` shell.
    let canary_arm_table = Arc::new(crate::proxy::canary::CanaryArmTable::new());

    // 5. Rule-driven proxy supervisor. Built *before* the heartbeat
    //    listener so the chain acceptor can hold a handle to it.
    let resolver_factory = match mode {
        config::Mode::Gateway => ResolverFactory::new_gateway(peer_state.clone()),
        config::Mode::Relay => ResolverFactory::new_relay(peer_state.clone()),
        config::Mode::Terminal => unreachable!("run_relay only dispatched for gateway/relay"),
    };
    let supervisor = ProxySupervisor::spawn_with_cert_store(
        config.server.rules_dir.clone(),
        RULE_DEBOUNCE,
        resolver_factory,
        config.server.default_bind,
        config.server.workers,
        CertConfig::from_server_section(
            config.server.cert_dir.clone(),
            config.server.default_cert.clone(),
            config.server.default_key.clone(),
            config.server.http_redirect_port,
            config.server.https_listen,
            config.server.https_http3,
            config.server.https_alt_svc,
            config.server.https_request_body_limit,
            resolve_lan_cidrs(&config),
        ),
        Arc::new(crate::proxy::certs::CertStore::new()),
        config.server.graceful_drain_timeout,
        Arc::clone(&canary_arm_table),
        shutdown.clone(),
    )
    .await
    .context("spawning proxy supervisor")?;

    // 5a. Phase 5B introspection state. Constructed now that the
    //     supervisor exists. Passed by reference into the UDS control
    //     server (for `Request::DerivedRules`) and into the chain
    //     acceptor (`record_apply` writer on a relay).
    let introspection_state = crate::chain::IntrospectionState::new(
        ratatoskr::pubkey::PubKey::x25519(*local_keys.public_key()),
        config.dial.as_ref().map(|d| d.pubkey),
        config.accept.as_ref().map(|a| a.pubkey),
        supervisor.handle(),
    );

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
            // L4 (`Protocol::Tcp` / `Protocol::Udp`) derived rules don't
            // get PROXY headers — non-yggdrasil L4 backends (game servers,
            // SSH, etc.) don't speak PROXY. HTTPS predicates are different:
            // their derived rules always carry `proxy_protocol = V2`
            // unconditionally in `rule_from_https_predicate` because both
            // ends of the chain HTTPS leg are yggdrasil.
            proxy_protocol: None,
        };
        Some(
            ChainAcceptor::load(supervisor.handle(), derive_cfg, &config.server.state_dir)
                .context("loading chain acceptor state")?,
        )
    } else {
        None
    };

    // 5c. Attach the introspection sink to the chain acceptor so the
    //     `Request::DerivedRules` snapshot updates on every inbound
    //     `PredicateSetUpdate` the relay accepts. Relays without a
    //     chain listener never accept pushes, so they skip this wiring
    //     — the snapshot's `predicates` array stays empty for the
    //     daemon's lifetime, which is the correct semantic.
    if let Some(acc) = chain_acceptor.as_ref() {
        acc.set_introspection(introspection_state.clone())
            .map_err(|_| anyhow::anyhow!("introspection set twice on acceptor"))?;
    }

    // 6. Build the outbound chain client (un-spawned) *before* binding
    //    the heartbeat listener so we can hand the chain client's
    //    upstream handle to the acceptor for `ChainHopQuery`
    //    forwarding. The client itself is spawned later, after its
    //    body handler is wired.
    let built_chain_client = build_chain_client(&config, &local_keys, shutdown.clone());
    if let (Some(acc), Some(built)) = (chain_acceptor.as_ref(), built_chain_client.as_ref()) {
        acc.set_upstream(built.handle.clone())
            .map_err(|_| anyhow::anyhow!("upstream set twice on acceptor"))?;
    }
    if let Some(acc) = chain_acceptor.as_ref() {
        acc.set_mode(wire_mode)
            .map_err(|_| anyhow::anyhow!("mode set twice on acceptor"))?;
        acc.set_node_name(node_name.clone())
            .map_err(|_| anyhow::anyhow!("node_name set twice on acceptor"))?;
        acc.set_arm_table(Arc::clone(&canary_arm_table))
            .map_err(|_| anyhow::anyhow!("arm_table set twice on acceptor"))?;
    }

    // 6a. Heartbeat (chain) listener — only when [accept] is set.
    //    A pure-proxy relay (no downstream/listener, only an upstream) is
    //    a legitimate mid-chain configuration that does no inbound work.
    let hb_handle = if let Some(accept) = config.accept.as_ref() {
        let (hb, outbound) = HeartbeatServer::bind(
            accept.listen,
            local_keys.clone(),
            peer_state.clone(),
            pending_store.clone(),
            chain_acceptor.clone(),
            shutdown.clone(),
        )
        .await
        .context("binding chain listener")?;
        // Wire the downstream-facing outbound channel into the
        // acceptor so it can emit `ChainHopReply` envelopes back to
        // the querier.
        if let Some(acc) = chain_acceptor.as_ref() {
            acc.set_outbound(outbound.sender())
                .map_err(|_| anyhow::anyhow!("outbound set twice on acceptor"))?;
        }

        Some(tokio::spawn(async move {
            if let Err(e) = hb.run().await {
                tracing::error!(error = %e, "chain listener exited with error");
            }
        }))
    } else {
        None
    };

    // 6b. Spawn the outbound chain client now that the acceptor is
    //     wired. The client's body handler routes inbound
    //     `ChainHopReply` envelopes through the shared `QueryRouter`
    //     so awaiting `query_upstream` callers resolve correctly.
    let (chain_client_join, chain_client_handle) = match built_chain_client {
        Some(mut built) => {
            let router_handler = built.client.query_router().install_into_body_handler(None);
            built.client.set_body_handler(router_handler);
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

    // 7. Optional NAT-traversal mapper. Opt-in via
    //    `[server].nat_traversal`; default off, in which case the
    //    helper returns `None` without holding any resources. When
    //    enabled, the mapper observes the supervisor's `current_set`
    //    watch plus the chain `[accept].listen` socket, and asks the
    //    residential gateway (PCP or NAT-PMP, per config) to forward
    //    inbound traffic to each operator-declared listener.
    let nat_mapper = spawn_nat_mapper(
        config.server.nat_traversal,
        config.accept.as_ref().map(|a| a.listen),
        config.server.https_listen,
        config.server.https_http3,
        supervisor.handle(),
        shutdown.clone(),
    )
    .await;

    // 8. UDS control surface for `yggdrasilctl`.
    let control = ControlServer::bind(
        config.control.socket.clone(),
        wire_mode,
        node_name.clone(),
        Some(peer_state.clone()),
        &supervisor,
        Some(pending_store.clone()),
        args.config.clone(),
        has_chain_upstream,
        prom_handle.clone(),
        Some(introspection_state.clone()),
        chain_client_handle.clone(),
        None, // relay nodes never wire an AcmeManager (no HTTPS rules)
        nat_mapper.as_ref().map(|m| m.handle()),
        Arc::clone(&canary_arm_table),
        resolve_lan_cidrs(&config),
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

    let sighup_join = spawn_sighup_handler(supervisor.reload_trigger(), shutdown.clone());

    let profiler =
        profile::Profiler::start_if_configured(shutdown.clone()).context("activate profiler")?;

    select_shutdown_or_profile(&profiler).await;
    tracing::info!("yggdrasil shutting down");
    if let Some(t) = config.server.graceful_drain_timeout {
        systemd::notify_stopping(&format!("Draining ({}s budget)", t.as_secs()));
    } else {
        systemd::notify_stopping("Stopping");
    }
    shutdown.cancel();
    control.stop().await;
    supervisor.stop().await;
    if let Some(mapper) = nat_mapper {
        mapper.shutdown().await;
    }
    let _ = sighup_join.await;
    if let Some(handle) = hb_handle {
        let _ = handle.await;
    }
    if let Some(handle) = chain_client_join {
        let _ = handle.await;
    }
    if let Some(p) = profiler {
        if let Err(e) = p.flush() {
            tracing::warn!(error = %e, "profiler flush failed");
        }
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
    let node_name = config.resolved_name();
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config  = %args.config.display(),
        mode = mode.as_str(),
        name = %node_name,
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

    // 3. Metrics recorder. The introspection state is constructed in
    //    step 4a and passed directly into the UDS control server.
    let prom_handle =
        metrics::install_recorder(wire_mode).context("installing prometheus recorder")?;

    // 3b. Outbound chain client — only when [dial] is set.
    //     A terminal node without an upstream is still useful (pure local
    //     proxy), so absence is not an error.
    let (chain_client_join, chain_client_handle) =
        match build_chain_client(&config, &local_keys, shutdown.clone()) {
            Some(mut built) => {
                let router_handler = built.client.query_router().install_into_body_handler(None);
                built.client.set_body_handler(router_handler);
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
    //    rule must carry `target`; `target_port` rules are
    //    rejected by `ResolverFactory::build`.
    let resolver_factory = ResolverFactory::new_terminal();

    // 4a. Share one `CertStore` between the supervisor and the ACME
    //     manager so the renewer's `reload_host` calls touch the
    //     same map the cert watcher updates.
    let cert_store = std::sync::Arc::new(crate::proxy::certs::CertStore::new());

    // 4b. Build the optional ACME manager. Only meaningful on
    //     terminal-mode nodes (relays passthrough TLS without
    //     terminating, so they never load an HTTPS rule and never
    //     have a `cert = "acme"` route). When `[acme]` is absent the
    //     supervisor's `CertConfig.acme` stays `None`, which keeps
    //     the redirect listener in its pre-ACME behaviour.
    let acme_manager = match config.acme.as_ref() {
        Some(acme_cfg) => Some(
            crate::proxy::acme::AcmeManager::spawn(
                acme_cfg.clone(),
                config.server.cert_dir.clone(),
                std::sync::Arc::clone(&cert_store),
                shutdown.clone(),
            )
            .context("building ACME manager")?,
        ),
        None => None,
    };

    // Kick off the wildcard issuance flow for [acme].domain at startup.
    // The renewer manages issue + scheduled renewal in the background;
    // we don't await its completion here (it can take minutes).
    if let Some(acme_mgr) = acme_manager.as_ref() {
        if let Err(e) = acme_mgr.start_wildcard().await {
            tracing::warn!(
                error = %e,
                "wildcard ACME bootstrap failed; serving with whatever's currently on disk \
                 ([server].default_cert / cert_dir convention)"
            );
        }
    }

    let mut cert_config = CertConfig::from_server_section(
        config.server.cert_dir.clone(),
        config.server.default_cert.clone(),
        config.server.default_key.clone(),
        config.server.http_redirect_port,
        config.server.https_listen,
        config.server.https_http3,
        config.server.https_alt_svc,
        config.server.https_request_body_limit,
        resolve_lan_cidrs(&config),
    );
    if let Some(acme_mgr) = acme_manager.clone() {
        cert_config = cert_config.with_acme(acme_mgr);
    }

    // Shared canary arm table — see `run_relay` for the rationale.
    // Terminals are the canary's echo terminus, so they always carry
    // an arm table; idle daemons just hold an empty `Arc<DashMap>`.
    let canary_arm_table = Arc::new(crate::proxy::canary::CanaryArmTable::new());

    let supervisor = ProxySupervisor::spawn_with_cert_store(
        config.server.rules_dir.clone(),
        RULE_DEBOUNCE,
        resolver_factory,
        config.server.default_bind,
        config.server.workers,
        cert_config,
        cert_store,
        config.server.graceful_drain_timeout,
        Arc::clone(&canary_arm_table),
        shutdown.clone(),
    )
    .await
    .context("spawning proxy supervisor")?;
    let _ = &acme_manager; // kept alive for the supervisor's lifetime

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

    // 4c. Optional NAT-traversal mapper. Terminals never set
    //     `[accept]`, so the only listeners we can map are the rule
    //     ones — but home-hosted terminals are the most common case
    //     for needing this.
    let nat_mapper = spawn_nat_mapper(
        config.server.nat_traversal,
        None,
        config.server.https_listen,
        config.server.https_http3,
        supervisor.handle(),
        shutdown.clone(),
    )
    .await;

    // 5. UDS control surface. Terminal mode has no downstream identity, so
    //    peer-related endpoints return `not_supported_in_terminal_mode`.
    let control = ControlServer::bind(
        config.control.socket.clone(),
        wire_mode,
        node_name.clone(),
        None,
        &supervisor,
        None,
        args.config.clone(),
        has_chain_upstream,
        prom_handle.clone(),
        Some(introspection_state.clone()),
        chain_client_handle.clone(),
        acme_manager.clone(),
        nat_mapper.as_ref().map(|m| m.handle()),
        Arc::clone(&canary_arm_table),
        resolve_lan_cidrs(&config),
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
    //     can update the `Request::DerivedRules` snapshot on each
    //     successful upstream ack.
    let predicate_publisher_join = chain_client_handle.as_ref().map(|handle| {
        let origin = ratatoskr::pubkey::PubKey::x25519(*local_keys.public_key());
        let supervisor_handle = supervisor.handle();
        let https_meta = chain::predicate_extractor::HttpsPredicateMeta {
            listen_port: config.server.https_listen.port(),
            http3: config.server.https_http3,
        };
        chain::predicate_publisher::spawn(
            supervisor_handle.current_set_rx(),
            handle.clone(),
            origin,
            config.server.state_dir.clone(),
            https_meta,
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

    let sighup_join = spawn_sighup_handler(supervisor.reload_trigger(), shutdown.clone());

    let profiler =
        profile::Profiler::start_if_configured(shutdown.clone()).context("activate profiler")?;

    select_shutdown_or_profile(&profiler).await;
    tracing::info!("yggdrasil shutting down");
    if let Some(t) = config.server.graceful_drain_timeout {
        systemd::notify_stopping(&format!("Draining ({}s budget)", t.as_secs()));
    } else {
        systemd::notify_stopping("Stopping");
    }
    shutdown.cancel();
    control.stop().await;
    supervisor.stop().await;
    if let Some(mapper) = nat_mapper {
        mapper.shutdown().await;
    }
    let _ = sighup_join.await;
    if let Some(handle) = predicate_publisher_join {
        let _ = handle.await;
    }
    if let Some(handle) = chain_client_join {
        let _ = handle.await;
    }
    if let Some(p) = profiler {
        if let Err(e) = p.flush() {
            tracing::warn!(error = %e, "profiler flush failed");
        }
    }
    Ok(())
}

/// Resolve `[server].lan_cidrs` (or the default set when unset) and
/// log the resolved set at startup. Called once per supervisor spawn.
fn resolve_lan_cidrs(config: &config::ServerConfig) -> std::sync::Arc<crate::lan_cidrs::LanCidrs> {
    let lan = crate::lan_cidrs::LanCidrs::resolve(config.server.lan_cidrs.as_deref())
        .expect("config validator pre-checked CIDR syntax");
    tracing::info!(
        source = %lan.source().as_str(),
        cidrs = ?lan.as_strings(),
        "lan_cidrs resolved"
    );
    std::sync::Arc::new(lan)
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
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating identity directory {}", parent.display()))?;
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
        local_bind: config.server.default_bind,
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

/// Spawn the NAT-traversal mapper if it is enabled in config.
///
/// Discovery failures (no default route, /proc/net/route unreadable)
/// are logged as warnings and downgraded to a `None` return: the
/// daemon continues to run with the mapper effectively disabled.
/// Operators can fix the network situation and restart, or simply
/// configure port forwarding manually.
async fn spawn_nat_mapper(
    mode: nat::NatTraversalMode,
    accept_listen: Option<std::net::SocketAddr>,
    https_listen: std::net::SocketAddr,
    https_http3: bool,
    supervisor: crate::proxy::supervisor::SupervisorHandle,
    shutdown: CancellationToken,
) -> Option<nat::NatMapper> {
    if !mode.is_enabled() {
        return None;
    }
    let params = nat::NatMapperParams {
        mode,
        accept_listen,
        rule_set_rx: supervisor.current_set_rx(),
        shutdown,
        https_listen,
        https_http3,
        gateway_override: None,
        shutdown_release_timeout: None,
    };
    match nat::NatMapper::spawn(params).await {
        Ok(m) => {
            tracing::info!(
                target: "yggdrasil::nat",
                mode = mode.as_str(),
                "NAT-traversal mapper running"
            );
            Some(m)
        }
        Err(nat::mapper::MapperSpawnError::Disabled) => None,
        Err(nat::mapper::MapperSpawnError::Discovery(reason)) => {
            tracing::warn!(
                target: "yggdrasil::nat",
                mode = mode.as_str(),
                error = %reason,
                "NAT-traversal mapper could not discover a default gateway; continuing without it"
            );
            None
        }
    }
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

/// Either wait for a real shutdown signal, or — if `YGGDRASIL_PROFILE_DURATION`
/// fired before that — return as soon as the profiler hits its deadline.
/// In the latter case the daemon still proceeds through the normal shutdown
/// sequence; we just don't keep it running forever for the sake of a
/// finite-duration profile capture.
async fn select_shutdown_or_profile(profiler: &Option<profile::Profiler>) {
    match profiler {
        Some(p) => {
            tokio::select! {
                _ = wait_for_shutdown() => {}
                _ = p.wait_for_deadline() => {
                    tracing::info!("profile deadline elapsed; initiating shutdown");
                }
            }
        }
        None => wait_for_shutdown().await,
    }
}

/// Spawn a SIGHUP handler that calls `force_reload` on every signal.
/// Returns a join handle scoped to `shutdown` — the task exits cleanly
/// when the parent cancels.
///
/// This is what makes `systemctl reload yggdrasil` (paired with
/// `Type=notify-reload` in the unit file) trigger an actual rule rescan
/// rather than just delivering the signal into the void. The reload work
/// itself runs on the supervisor task; this handler only nudges it.
fn spawn_sighup_handler(
    reload_trigger: crate::rules::ReloadTrigger,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGHUP handler; reload-on-SIGHUP disabled");
                return;
            }
        };
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                got = sighup.recv() => {
                    if got.is_none() {
                        return;
                    }
                    tracing::info!("received SIGHUP; requesting rules reload");
                    reload_trigger.force_reload();
                }
            }
        }
    })
}
