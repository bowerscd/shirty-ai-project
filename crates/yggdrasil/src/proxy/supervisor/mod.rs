//! Cross-rule proxy supervisor.
//!
//! Owns a [`RuleWatcher`] and reconciles each delivered [`RuleUpdate`]
//! against the currently-running proxy set: spawns proxies for added rules,
//! stops proxies for removed rules, and swaps proxies for changed rules.
//! Unchanged rules are left strictly alone — their `TcpListener` /
//! `UdpSocket` and any in-flight UDP flows survive the reload untouched.
//!
//! This is the rule-level analogue of the heartbeat-level "same-IP
//! heartbeats don't disturb the data plane" invariance: a hot reload that
//! only touches rule A must not interrupt rule B.
//!
//! ## Module layout (Phase B3 split)
//!
//! - [`cert_config`] — `CertConfig` extracted from the server config.
//! - [`handle`] — per-rule proxy handle enum (`ProxyHandle`,
//!   `HttpsHandle`, `ActiveProxy`); internal to the supervisor.
//! - [`reconcile`] — the supervisor loop, rule-diff application,
//!   and per-rule spawn helpers.
//!
//! [`RuleWatcher`]: crate::rules::RuleWatcher
//! [`RuleUpdate`]: crate::rules::RuleUpdate

pub mod cert_config;
mod handle;
mod reconcile;

pub use cert_config::CertConfig;

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use ratatoskr::rule::{Protocol, RuleSet};

use crate::proxy::canary::CanaryArmTable;
use crate::proxy::certs::{CertStore, CertWatcher};
use crate::proxy::resolver::ResolverFactory;
use crate::rules::{ReloadTrigger, RuleWatcher};

/// Snapshot of one supervised proxy used by tests and (later) by yggdrasilctl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySnapshot {
    pub name: String,
    pub protocol: Protocol,
    pub listen: SocketAddr,
    /// Stable, human-readable description of the dial target. The exact
    /// shape is supplied by [`crate::proxy::resolver::UpstreamResolver::describe`]:
    /// relay-mode rules render as `dynamic:peer:<port>`; terminal-mode
    /// rules render as `static:<ip>:<port>`. Not a parse target — just for
    /// control-plane reporting.
    pub upstream_description: String,
    /// For HTTPS rules: number of routes that ended up cert-less (no
    /// cert source resolved across the precedence chain). These
    /// routes are served by the per-IP companion listener's plaintext
    /// path; the cert store doesn't carry an entry for them. Zero
    /// for non-HTTPS rules and for HTTPS rules whose every route
    /// resolved a cert source.
    pub cert_less_route_count: usize,
}

/// Handle to a running supervisor.
pub struct ProxySupervisor {
    cancel: CancellationToken,
    main_handle: JoinHandle<()>,
    snapshot_rx: tokio::sync::watch::Receiver<Vec<ProxySnapshot>>,
    rules_dir: PathBuf,
    reload_trigger: ReloadTrigger,
    /// Shared cert store: used by every HTTPS frontend as `ResolvesServerCert`
    /// and read by the `yggdrasilctl local status` control-plane verb
    /// (cert summary section).
    cert_store: Arc<CertStore>,
    /// Filesystem watcher for the PEM files referenced by HTTPS routes.
    /// Re-resolves any host whose backing cert or key changes on disk and
    /// emits `yggdrasil_https_cert_reload_total{result}` per outcome.
    /// Kept alive for the lifetime of the supervisor — drop tears down
    /// the underlying inotify watch.
    _cert_watcher: Arc<CertWatcher>,
    /// Cloneable side of the external rule-set apply channel. Held here
    /// so [`ProxySupervisor::handle`] can clone it for callers.
    apply_tx: mpsc::Sender<RuleSet>,
    /// Latest [`RuleSet`] applied by the supervisor (file-watch *or*
    /// external push, whichever ran most recently). Subscribers receive a
    /// new value after every successful apply; the supervisor itself owns
    /// the sender, so receivers' `borrow()` always reflects the freshest
    /// applied set.
    current_set_rx: watch::Receiver<RuleSet>,
}

/// Cloneable cross-task handle for external callers that need to push
/// new rule sets into a running supervisor (notably the chain control
/// plane's predicate-receive path on relays, and the predicate-publisher
/// task on terminals which only observes `current_set` rather than
/// authoring pushes).
#[derive(Debug, Clone)]
pub struct SupervisorHandle {
    apply_tx: mpsc::Sender<RuleSet>,
    current_set_rx: watch::Receiver<RuleSet>,
}

/// Returned by [`SupervisorHandle::apply_ruleset`] when the supervisor
/// task has exited (shutdown or panic).
#[derive(Debug, thiserror::Error)]
#[error("proxy supervisor is shut down")]
pub struct SupervisorShutDown;

impl SupervisorHandle {
    /// Enqueue a new [`RuleSet`] for application. The supervisor computes
    /// the diff against its current state internally and applies it on
    /// its own task, identical to a file-watch reload. Returns once the
    /// push is enqueued (not once it has been applied).
    ///
    /// Use [`SupervisorHandle::current_set_rx`] to observe when the
    /// pushed set has been applied: the watch fires after each successful
    /// apply.
    pub async fn apply_ruleset(&self, set: RuleSet) -> Result<(), SupervisorShutDown> {
        self.apply_tx
            .send(set)
            .await
            .map_err(|_| SupervisorShutDown)
    }

    /// Subscribe to the supervisor's `current_set` watch. The receiver's
    /// initial value is the empty default set; subsequent values are the
    /// applied set after each successful reload (from any source).
    pub fn current_set_rx(&self) -> watch::Receiver<RuleSet> {
        self.current_set_rx.clone()
    }

    /// Test-only constructor for unit tests that need a
    /// [`SupervisorHandle`] without spinning up a full supervisor task.
    /// The returned handle has a live `current_set_rx` (seeded with
    /// `initial`) but a dead `apply_tx` — `apply_ruleset` will fail
    /// with [`SupervisorShutDown`] on the first call.
    #[cfg(test)]
    pub(crate) fn __test_new(initial: RuleSet) -> (Self, watch::Sender<RuleSet>) {
        let (apply_tx, _apply_rx) = mpsc::channel::<RuleSet>(1);
        let (current_set_tx, current_set_rx) = watch::channel::<RuleSet>(initial);
        // The receiver is intentionally dropped: tests that use this
        // path do not call `apply_ruleset`. Holding the sender alive
        // keeps the watch open until the test ends.
        drop(_apply_rx);
        (
            Self {
                apply_tx,
                current_set_rx,
            },
            current_set_tx,
        )
    }
}

impl ProxySupervisor {
    /// Spawn the supervisor. The initial rule load happens synchronously
    /// inside `RuleWatcher::spawn` so a malformed rules directory aborts
    /// startup loudly. Subsequent reload failures are logged and ignored
    /// (previous good set retained).
    ///
    /// `shutdown` is observed cooperatively: cancelling it stops the
    /// supervisor and all child proxies.
    ///
    /// `graceful_drain_timeout` (sourced from `[server].graceful_drain_timeout`)
    /// is consulted on shutdown only — hot rule-reload always stops the
    /// affected proxy instantly so the new rule set can take effect. See
    /// [`crate::proxy::tcp::TcpProxy::stop`] for the per-proxy mechanics.
    ///
    /// Equivalent to [`ProxySupervisor::spawn_with_cert_store`] with a
    /// freshly-built empty store; callers that need to share the store
    /// with an `AcmeManager` use the explicit form.
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn(
        rules_dir: impl Into<PathBuf>,
        debounce: Duration,
        resolver_factory: ResolverFactory,
        default_bind: Option<IpAddr>,
        default_workers: Option<usize>,
        cert_config: CertConfig,
        graceful_drain_timeout: Option<Duration>,
        shutdown: CancellationToken,
    ) -> Result<Self> {
        Self::spawn_with_cert_store(
            rules_dir,
            debounce,
            resolver_factory,
            default_bind,
            default_workers,
            cert_config,
            Arc::new(CertStore::new()),
            graceful_drain_timeout,
            Arc::new(CanaryArmTable::new()),
            shutdown,
        )
        .await
    }

    /// Variant that takes a caller-built `Arc<CertStore>`. The caller
    /// retains a clone so external subsystems (notably the
    /// `AcmeManager`'s renewer task) can call `reload_host` against
    /// the same map the supervisor's cert watcher updates. The
    /// `arm_table` is the daemon-wide canary arm table (see
    /// [`CanaryArmTable`]); the supervisor threads it into every
    /// per-rule TCP / UDP proxy so the rule listeners can short-
    /// circuit canary-tagged traffic to in-process echoes.
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn_with_cert_store(
        rules_dir: impl Into<PathBuf>,
        debounce: Duration,
        resolver_factory: ResolverFactory,
        default_bind: Option<IpAddr>,
        default_workers: Option<usize>,
        cert_config: CertConfig,
        cert_store: Arc<CertStore>,
        graceful_drain_timeout: Option<Duration>,
        arm_table: Arc<CanaryArmTable>,
        shutdown: CancellationToken,
    ) -> Result<Self> {
        let rules_dir: PathBuf = rules_dir.into();
        let watcher = RuleWatcher::spawn(&rules_dir, debounce)
            .with_context(|| format!("spawn rule watcher for {}", rules_dir.display()))?;
        let reload_trigger = watcher.reload_trigger();

        let cancel = shutdown.child_token();
        let (snapshot_tx, snapshot_rx) = tokio::sync::watch::channel(Vec::<ProxySnapshot>::new());

        // External-push channel. Capacity 8 lets the chain dispatcher
        // burst a few coalesced sets back-to-back without blocking, while
        // still applying backpressure if the supervisor falls catastrophically
        // behind (which would be a bug worth surfacing).
        let (apply_tx, apply_rx) = mpsc::channel::<RuleSet>(8);
        let (current_set_tx, current_set_rx) = watch::channel::<RuleSet>(RuleSet::default());

        // Share the rule watcher's debounce window with the cert
        // watcher — operators expect both to coalesce on the same
        // tempo.
        let cert_watcher = CertWatcher::spawn(Arc::clone(&cert_store), debounce, cancel.clone())
            .map(Arc::new)
            .context("spawn cert watcher")?;

        let main_cancel = cancel.clone();
        let main_handle = tokio::spawn(reconcile::supervisor_loop(
            watcher,
            apply_rx,
            current_set_tx,
            resolver_factory,
            default_bind,
            default_workers,
            cert_config,
            Arc::clone(&cert_store),
            Arc::clone(&cert_watcher),
            graceful_drain_timeout,
            arm_table,
            main_cancel,
            snapshot_tx,
        ));

        Ok(Self {
            cancel,
            main_handle,
            snapshot_rx,
            rules_dir,
            reload_trigger,
            cert_store,
            _cert_watcher: cert_watcher,
            apply_tx,
            current_set_rx,
        })
    }

    pub fn rules_dir(&self) -> &Path {
        &self.rules_dir
    }

    /// Cheap clone-friendly handle for requesting reloads (used by the UDS
    /// control surface).
    pub fn reload_trigger(&self) -> ReloadTrigger {
        self.reload_trigger.clone()
    }

    /// Current snapshot of running proxies. Cheap; reads from a `watch` cell.
    pub fn snapshot(&self) -> Vec<ProxySnapshot> {
        self.snapshot_rx.borrow().clone()
    }

    /// Borrow the inner snapshot receiver. Lets the control surface read the
    /// current proxy set without copying it on every `status` request.
    pub fn snapshot_receiver(&self) -> tokio::sync::watch::Receiver<Vec<ProxySnapshot>> {
        self.snapshot_rx.clone()
    }

    /// Returns when the supervised set first becomes non-empty *or* the
    /// `timeout` elapses. Intended for tests; production callers should
    /// observe via the snapshot/metrics endpoints.
    pub async fn wait_for_nonempty(&self, timeout: Duration) -> bool {
        let mut rx = self.snapshot_rx.clone();
        if !rx.borrow().is_empty() {
            return true;
        }
        let res = tokio::time::timeout(timeout, async {
            while rx.changed().await.is_ok() {
                if !rx.borrow().is_empty() {
                    return true;
                }
            }
            false
        })
        .await;
        res.unwrap_or(false)
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = self.main_handle.await;
    }

    /// Shared cert store: used by every HTTPS frontend as `ResolvesServerCert`
    /// and read by the `yggdrasilctl local status` control-plane verb
    /// (cert summary section).
    pub fn cert_store(&self) -> Arc<CertStore> {
        Arc::clone(&self.cert_store)
    }

    /// Cloneable handle for external callers that need to push rule sets
    /// into the supervisor or observe the most-recently-applied set.
    /// Used by the chain control plane's predicate-receive path on relays
    /// and the predicate-publisher task on terminals.
    pub fn handle(&self) -> SupervisorHandle {
        SupervisorHandle {
            apply_tx: self.apply_tx.clone(),
            current_set_rx: self.current_set_rx.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::heartbeat::PeerState;
    use ratatoskr::rule::Rule;

    /// All supervisor tests run in relay mode against an unenrolled
    /// `PeerState` (rules never have to dial upstream during these tests —
    /// only the supervisor wiring is exercised).
    fn relay_factory() -> (ResolverFactory, std::sync::Arc<PeerState>) {
        let peer = PeerState::new([0u8; 32]);
        let factory = ResolverFactory::new_relay(peer.clone());
        (factory, peer)
    }

    fn tcp_rule_toml(name: &str, port: u16, target_port: u16) -> String {
        format!(
            r#"
            [[rule]]
            name = "{name}"
            listen = "127.0.0.1:{port}"
            protocol = "tcp"
            target_port = {target_port}
            "#,
        )
    }

    fn udp_rule_toml(name: &str, port: u16, target_port: u16) -> String {
        format!(
            r#"
            [[rule]]
            name = "{name}"
            listen = "127.0.0.1:{port}"
            protocol = "udp"
            target_port = {target_port}
            idle_timeout = "30s"
            "#,
        )
    }

    /// Pick a free OS-assigned TCP port (no guarantee it'll still be free —
    /// these tests use UDP fallback / retry logic where it matters).
    async fn free_port() -> u16 {
        let s = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        s.local_addr().unwrap().port()
        // listener drops here → port returns to OS
    }

    async fn await_snapshot_len(supervisor: &ProxySupervisor, target: usize) {
        let mut rx = supervisor.snapshot_rx.clone();
        if rx.borrow().len() == target {
            return;
        }
        let res = tokio::time::timeout(Duration::from_secs(5), async {
            while rx.changed().await.is_ok() {
                if rx.borrow().len() == target {
                    return;
                }
            }
        })
        .await;
        assert!(
            res.is_ok(),
            "timeout waiting for snapshot of len {target}; have {:?}",
            supervisor.snapshot()
        );
    }

    #[tokio::test]
    async fn spawns_proxies_for_initial_rule_set() {
        let dir = tempfile::tempdir().unwrap();
        let port_a = free_port().await;
        let port_b = free_port().await;
        std::fs::write(
            dir.path().join("a.toml"),
            tcp_rule_toml("alpha", port_a, 9001),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("b.toml"),
            udp_rule_toml("beta", port_b, 9002),
        )
        .unwrap();

        let (factory, _peer) = relay_factory();
        let shutdown = CancellationToken::new();
        let sup = ProxySupervisor::spawn(
            dir.path().to_path_buf(),
            Duration::from_millis(50),
            factory,
            None,
            None,
            CertConfig::default(),
            None,
            shutdown.clone(),
        )
        .await
        .unwrap();

        await_snapshot_len(&sup, 2).await;
        let snaps = sup.snapshot();
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[0].name, "alpha");
        assert_eq!(snaps[1].name, "beta");
        assert_eq!(snaps[1].protocol, Protocol::Udp);

        sup.stop().await;
    }

    #[tokio::test]
    async fn adding_a_file_spawns_a_new_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let port_a = free_port().await;
        std::fs::write(
            dir.path().join("a.toml"),
            tcp_rule_toml("alpha", port_a, 9001),
        )
        .unwrap();

        let (factory, _peer) = relay_factory();
        let shutdown = CancellationToken::new();
        let sup = ProxySupervisor::spawn(
            dir.path().to_path_buf(),
            Duration::from_millis(50),
            factory,
            None,
            None,
            CertConfig::default(),
            None,
            shutdown.clone(),
        )
        .await
        .unwrap();

        await_snapshot_len(&sup, 1).await;

        let port_b = free_port().await;
        std::fs::write(
            dir.path().join("b.toml"),
            udp_rule_toml("beta", port_b, 9002),
        )
        .unwrap();

        await_snapshot_len(&sup, 2).await;
        let names: Vec<_> = sup.snapshot().into_iter().map(|s| s.name).collect();
        assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()]);

        sup.stop().await;
    }

    #[tokio::test]
    async fn removing_a_file_stops_the_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let port_a = free_port().await;
        let port_b = free_port().await;
        std::fs::write(
            dir.path().join("a.toml"),
            tcp_rule_toml("alpha", port_a, 9001),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("b.toml"),
            tcp_rule_toml("beta", port_b, 9002),
        )
        .unwrap();

        let (factory, _peer) = relay_factory();
        let shutdown = CancellationToken::new();
        let sup = ProxySupervisor::spawn(
            dir.path().to_path_buf(),
            Duration::from_millis(50),
            factory,
            None,
            None,
            CertConfig::default(),
            None,
            shutdown.clone(),
        )
        .await
        .unwrap();

        await_snapshot_len(&sup, 2).await;
        std::fs::remove_file(dir.path().join("b.toml")).unwrap();
        await_snapshot_len(&sup, 1).await;

        assert_eq!(sup.snapshot()[0].name, "alpha");
        sup.stop().await;
    }

    #[tokio::test]
    async fn changing_one_rule_does_not_disturb_others() {
        // This is the rule-level analogue of the heartbeat-invariance
        // guarantee: editing rule B must leave rule A's listener untouched.
        let dir = tempfile::tempdir().unwrap();
        let port_a = free_port().await;
        let port_b = free_port().await;
        std::fs::write(
            dir.path().join("a.toml"),
            tcp_rule_toml("alpha", port_a, 9001),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("b.toml"),
            tcp_rule_toml("beta", port_b, 9002),
        )
        .unwrap();

        let (factory, _peer) = relay_factory();
        let shutdown = CancellationToken::new();
        let sup = ProxySupervisor::spawn(
            dir.path().to_path_buf(),
            Duration::from_millis(50),
            factory,
            None,
            None,
            CertConfig::default(),
            None,
            shutdown.clone(),
        )
        .await
        .unwrap();

        await_snapshot_len(&sup, 2).await;
        let snap0 = sup.snapshot();
        let alpha_listen_before = snap0.iter().find(|s| s.name == "alpha").unwrap().listen;
        let beta_listen_before = snap0.iter().find(|s| s.name == "beta").unwrap().listen;

        // Change beta's target_port only (listen stays the same so we can
        // assert socket-address stability). alpha must NOT be touched.
        std::fs::write(
            dir.path().join("b.toml"),
            tcp_rule_toml("beta", port_b, 9999),
        )
        .unwrap();

        // Wait for the snapshot to actually reflect the change. We look for
        // an alpha-still-present + beta-with-new-upstream snapshot. The
        // resolver renders relay-mode upstreams as `dynamic:peer:<port>`.
        let mut rx = sup.snapshot_rx.clone();
        let saw_swap = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                {
                    let s = rx.borrow();
                    let alpha = s.iter().find(|x| x.name == "alpha");
                    let beta = s.iter().find(|x| x.name == "beta");
                    if let (Some(a), Some(b)) = (alpha, beta) {
                        if a.listen == alpha_listen_before
                            && b.upstream_description.ends_with(":9999")
                        {
                            return true;
                        }
                    }
                }
                if rx.changed().await.is_err() {
                    return false;
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(
            saw_swap,
            "timed out waiting for beta upstream port=9999 swap"
        );

        let snap1 = sup.snapshot();
        let alpha_listen_after = snap1.iter().find(|s| s.name == "alpha").unwrap().listen;
        let beta_listen_after = snap1.iter().find(|s| s.name == "beta").unwrap().listen;
        let beta_upstream_after = &snap1
            .iter()
            .find(|s| s.name == "beta")
            .unwrap()
            .upstream_description;

        // Alpha must be untouched.
        assert_eq!(
            alpha_listen_before, alpha_listen_after,
            "alpha's listen address changed across an unrelated reload"
        );
        // Beta's listen port hasn't changed (we kept the port and only swapped
        // target_port), but the proxy was respawned (which is fine — we're
        // not promising socket-identity across changes to the same rule).
        assert_eq!(beta_listen_before, beta_listen_after);
        assert!(
            beta_upstream_after.ends_with(":9999"),
            "expected beta upstream_description to end in :9999, got {beta_upstream_after:?}"
        );

        sup.stop().await;
    }

    #[tokio::test]
    async fn shutdown_token_stops_supervisor_and_proxies() {
        let dir = tempfile::tempdir().unwrap();
        let port_a = free_port().await;
        std::fs::write(
            dir.path().join("a.toml"),
            tcp_rule_toml("alpha", port_a, 9001),
        )
        .unwrap();

        let (factory, _peer) = relay_factory();
        let shutdown = CancellationToken::new();
        let sup = ProxySupervisor::spawn(
            dir.path().to_path_buf(),
            Duration::from_millis(50),
            factory,
            None,
            None,
            CertConfig::default(),
            None,
            shutdown.clone(),
        )
        .await
        .unwrap();

        await_snapshot_len(&sup, 1).await;
        let listen = sup.snapshot()[0].listen;

        // Cancel via the *parent* token; the supervisor's child token should
        // observe and tear everything down.
        shutdown.cancel();
        let _ = sup.main_handle.await;

        // The port should now be re-bindable (the proxy fully released it).
        let rebind = tokio::net::TcpListener::bind(listen).await;
        assert!(
            rebind.is_ok(),
            "expected port {listen} to be free after supervisor shutdown, but bind failed: {:?}",
            rebind.err()
        );
    }

    #[tokio::test]
    async fn invalid_rules_directory_fails_spawn() {
        let dir = tempfile::tempdir().unwrap();
        // Two rules with the same name → RuleSet validation fails.
        std::fs::write(
            dir.path().join("a.toml"),
            tcp_rule_toml("dup", free_port().await, 9001),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("b.toml"),
            tcp_rule_toml("dup", free_port().await, 9002),
        )
        .unwrap();

        let (factory, _peer) = relay_factory();
        let shutdown = CancellationToken::new();
        let res = ProxySupervisor::spawn(
            dir.path().to_path_buf(),
            Duration::from_millis(50),
            factory,
            None,
            None,
            CertConfig::default(),
            None,
            shutdown,
        )
        .await;
        assert!(res.is_err(), "expected duplicate-rule-name error");
    }

    /// External `SupervisorHandle::apply_ruleset` pushes a fresh
    /// [`RuleSet`] into a running supervisor; the supervisor recomputes
    /// the diff against its own `current_set` and applies it identically
    /// to a file-watcher event.
    #[tokio::test]
    async fn external_apply_ruleset_swaps_active_proxies() {
        let dir = tempfile::tempdir().unwrap();
        // File-watcher sees no rule files; current_set starts empty.
        let (factory, _peer) = relay_factory();
        let shutdown = CancellationToken::new();
        let sup = ProxySupervisor::spawn(
            dir.path().to_path_buf(),
            Duration::from_millis(50),
            factory,
            None,
            None,
            CertConfig::default(),
            None,
            shutdown.clone(),
        )
        .await
        .unwrap();

        // Wait for the initial empty-file-set sync to land.
        await_snapshot_len(&sup, 0).await;

        // External push: one TCP rule.
        let handle = sup.handle();
        let port = free_port().await;
        let rule = Rule {
            name: "ext-alpha".to_string(),
            listen: format!("127.0.0.1:{port}").parse().unwrap(),
            protocol: Protocol::Tcp,
            target_port: Some(9001),
            target_addr: None,
            target_host: None,
            idle_timeout: None,
            proxy_protocol: None,
            routes: None,
            cert_dir: None,
            http3: None,
            alt_svc: None,
        };
        let set = RuleSet::from_rules(vec![rule]).unwrap();
        handle.apply_ruleset(set.clone()).await.unwrap();

        await_snapshot_len(&sup, 1).await;
        let snaps = sup.snapshot();
        assert_eq!(snaps[0].name, "ext-alpha");

        // The current_set watch should also reflect the applied set.
        let mut rx = handle.current_set_rx();
        // Spin briefly: the watch send happens after the snapshot send.
        for _ in 0..50 {
            if rx.borrow_and_update().rules().len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(rx.borrow().rules().len(), 1);
        assert_eq!(rx.borrow().rules()[0].name, "ext-alpha");

        // External push of an empty set tears down the proxy.
        handle.apply_ruleset(RuleSet::default()).await.unwrap();
        await_snapshot_len(&sup, 0).await;

        sup.stop().await;
    }
}
