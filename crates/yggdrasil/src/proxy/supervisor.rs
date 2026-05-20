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

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use ratatoskr::rule::{Protocol, Rule, RuleSet};

use crate::rules::{RuleUpdate, RuleWatcher, ReloadTrigger};

use super::certs::{load_rule_into_store, CertStore, CertWatcher};
use super::http_frontend::{HttpFrontend, RedirectListener};
use super::resolver::{ResolverFactory, UpstreamResolver};
use super::tcp::TcpProxy;
use super::udp::UdpProxy;

/// Certificate-loading configuration extracted from `ServerSection`. Held
/// by the supervisor and consulted whenever an HTTPS rule's routes need to
/// be reified into the shared [`CertStore`].
#[derive(Debug, Clone, Default)]
pub struct CertConfig {
    pub cert_dir:      PathBuf,
    pub default_cert:  Option<PathBuf>,
    pub default_key:   Option<PathBuf>,
    /// Port for the HTTP→HTTPS redirect listener. `None` (default) uses
    /// the standard `:80`. Tests and operators without privileged-port
    /// access can set this to any other value (including `0` for an
    /// ephemeral port).
    pub redirect_port: Option<u16>,
}

impl CertConfig {
    pub fn from_server_section(
        cert_dir:     PathBuf,
        default_cert: Option<PathBuf>,
        default_key:  Option<PathBuf>,
    ) -> Self {
        Self { cert_dir, default_cert, default_key, redirect_port: None }
    }
}

/// Type-erased handle to a running per-rule proxy.
enum ProxyHandle {
    Tcp(TcpProxy),
    Udp(UdpProxy),
    Https(HttpsHandle),
}

/// HTTPS handle bundles the frontend with the hostnames it registered into
/// the per-IP redirect listener, so we can deregister cleanly on stop.
struct HttpsHandle {
    frontend:        HttpFrontend,
    redirect_hosts:  Vec<String>,
    redirect_ip:     IpAddr,
    listen:          SocketAddr,
    rule:            Rule,
}

impl ProxyHandle {
    fn local_addr(&self) -> SocketAddr {
        match self {
            Self::Tcp(p) => p.local_addr(),
            Self::Udp(p) => p.local_addr(),
            Self::Https(h) => h.listen,
        }
    }

    fn rule(&self) -> &Rule {
        match self {
            Self::Tcp(p) => p.rule(),
            Self::Udp(p) => p.rule(),
            Self::Https(h) => &h.rule,
        }
    }

    async fn stop(self) {
        match self {
            Self::Tcp(p) => p.stop().await,
            Self::Udp(p) => p.stop().await,
            Self::Https(h) => h.frontend.stop().await,
        }
    }
}

/// Snapshot of one supervised proxy used by tests and (later) by yggdrasilctl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySnapshot {
    pub name: String,
    pub protocol: Protocol,
    pub listen: SocketAddr,
    /// Stable, human-readable description of the dial target. The exact
    /// shape is supplied by [`UpstreamResolver::describe`]: relay-mode rules
    /// render as `dynamic:peer:<port>`; terminal-mode rules render as
    /// `static:<ip>:<port>`. Not a parse target — just for control-plane
    /// reporting.
    pub upstream_description: String,
}

/// Handle to a running supervisor.
pub struct ProxySupervisor {
    cancel: CancellationToken,
    main_handle: JoinHandle<()>,
    snapshot_rx: tokio::sync::watch::Receiver<Vec<ProxySnapshot>>,
    rules_dir: PathBuf,
    reload_trigger: ReloadTrigger,
    /// Shared cert store: used by every HTTPS frontend as `ResolvesServerCert`
    /// and read by the `yggdrasilctl certs list` control-plane verb.
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
        self.apply_tx.send(set).await.map_err(|_| SupervisorShutDown)
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
    pub async fn spawn(
        rules_dir: impl Into<PathBuf>,
        debounce: Duration,
        resolver_factory: ResolverFactory,
        default_bind: Option<IpAddr>,
        cert_config: CertConfig,
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
        let (current_set_tx, current_set_rx) =
            watch::channel::<RuleSet>(RuleSet::default());

        let cert_store = Arc::new(CertStore::new());
        // Share the rule watcher's debounce window with the cert
        // watcher — operators expect both to coalesce on the same
        // tempo.
        let cert_watcher = CertWatcher::spawn(
            Arc::clone(&cert_store),
            debounce,
            cancel.clone(),
        )
        .map(Arc::new)
        .context("spawn cert watcher")?;

        let main_cancel = cancel.clone();
        let main_handle = tokio::spawn(supervisor_loop(
            watcher,
            apply_rx,
            current_set_tx,
            resolver_factory,
            default_bind,
            cert_config,
            Arc::clone(&cert_store),
            Arc::clone(&cert_watcher),
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
    /// and read by the `yggdrasilctl certs list` control-plane verb.
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

#[allow(clippy::too_many_arguments)]
async fn supervisor_loop(
    mut watcher: RuleWatcher,
    mut apply_rx: mpsc::Receiver<RuleSet>,
    current_set_tx: watch::Sender<RuleSet>,
    resolver_factory: ResolverFactory,
    default_bind: Option<IpAddr>,
    cert_config: CertConfig,
    cert_store: Arc<CertStore>,
    cert_watcher: Arc<CertWatcher>,
    cancel: CancellationToken,
    snapshot_tx: tokio::sync::watch::Sender<Vec<ProxySnapshot>>,
) {
    let mut active: HashMap<String, ActiveProxy> = HashMap::new();
    let mut redirect_listeners: HashMap<IpAddr, RedirectListener> = HashMap::new();
    // Supervisor-owned source of truth. Both the file watcher and the
    // external apply channel feed RuleSets in; we always compute the diff
    // against this field so the two sources can coexist without their
    // notions of "previous" diverging.
    let mut current_set: RuleSet = RuleSet::default();

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                tracing::info!("supervisor received shutdown signal");
                break;
            }
            update = watcher.recv() => {
                match update {
                    Some(u) => {
                        // Watcher emits {set, diff}, but we ignore the diff
                        // and recompute against `current_set` so external
                        // pushes between file events are honoured.
                        let RuleUpdate { set, diff: _ } = u;
                        apply_set(
                            &mut active,
                            &mut redirect_listeners,
                            &mut current_set,
                            set,
                            "file_watcher",
                            &resolver_factory,
                            default_bind,
                            &cert_config,
                            &cert_store,
                            &cert_watcher,
                            &cancel,
                        )
                        .await;
                        let _ = current_set_tx.send(current_set.clone());
                        publish_snapshot(&active, &snapshot_tx, &cert_store);
                    }
                    None => {
                        tracing::warn!("rule watcher channel closed; supervisor exiting");
                        break;
                    }
                }
            }
            ext = apply_rx.recv() => {
                match ext {
                    Some(set) => {
                        apply_set(
                            &mut active,
                            &mut redirect_listeners,
                            &mut current_set,
                            set,
                            "external_push",
                            &resolver_factory,
                            default_bind,
                            &cert_config,
                            &cert_store,
                            &cert_watcher,
                            &cancel,
                        )
                        .await;
                        let _ = current_set_tx.send(current_set.clone());
                        publish_snapshot(&active, &snapshot_tx, &cert_store);
                    }
                    None => {
                        // All SupervisorHandle clones dropped. Not an exit
                        // condition by itself — we keep serving the file
                        // watcher — but we won't get any further external
                        // pushes. Continue without `ext` ever firing again.
                    }
                }
            }
        }
    }

    // Shutdown: stop every active proxy concurrently. Drain the snapshot
    // last so observers see the empty set on the way out.
    let active_drained: Vec<ActiveProxy> = active.drain().map(|(_, p)| p).collect();
    let stops = active_drained.into_iter().map(|p| p.handle.stop());
    futures::future::join_all(stops).await;
    // Tear down any leftover redirect listeners.
    let redirect_drained: Vec<RedirectListener> =
        redirect_listeners.drain().map(|(_, l)| l).collect();
    let red_stops = redirect_drained.into_iter().map(|l| l.stop());
    futures::future::join_all(red_stops).await;
    publish_snapshot(&active, &snapshot_tx, &cert_store);
    tracing::info!("supervisor shut down");
}

/// Active record: the running proxy plus the resolver description it was
/// spawned with (snapshotted at spawn time so the control surface doesn't
/// have to re-derive it).
struct ActiveProxy {
    handle: ProxyHandle,
    upstream_description: String,
}

#[allow(clippy::too_many_arguments)]
async fn apply_set(
    active: &mut HashMap<String, ActiveProxy>,
    redirect_listeners: &mut HashMap<IpAddr, RedirectListener>,
    current_set: &mut RuleSet,
    new_set: RuleSet,
    source: &'static str,
    resolver_factory: &ResolverFactory,
    default_bind: Option<IpAddr>,
    cert_config: &CertConfig,
    cert_store: &Arc<CertStore>,
    cert_watcher: &Arc<CertWatcher>,
    parent_cancel: &CancellationToken,
) {
    // Compute the diff against the supervisor-owned current state, not
    // whatever the input source thinks the previous state was. This is
    // what lets file-watch and chain-push coexist on a single supervisor.
    let diff = current_set.diff(&new_set);
    tracing::debug!(
        source = source,
        added = diff.added.len(),
        changed = diff.changed.len(),
        removed = diff.removed.len(),
        unchanged = diff.unchanged.len(),
        "supervisor applying rule set"
    );
    let set = new_set.clone();
    apply_update(
        active,
        redirect_listeners,
        RuleUpdate { set, diff },
        resolver_factory,
        default_bind,
        cert_config,
        cert_store,
        cert_watcher,
        parent_cancel,
    )
    .await;
    *current_set = new_set;
}

#[allow(clippy::too_many_arguments)]
async fn apply_update(
    active: &mut HashMap<String, ActiveProxy>,
    redirect_listeners: &mut HashMap<IpAddr, RedirectListener>,
    update: RuleUpdate,
    resolver_factory: &ResolverFactory,
    default_bind: Option<IpAddr>,
    cert_config: &CertConfig,
    cert_store: &Arc<CertStore>,
    cert_watcher: &Arc<CertWatcher>,
    parent_cancel: &CancellationToken,
) {
    let RuleUpdate { set, diff } = update;

    // 1. Remove proxies for removed rules. Includes unregistering their
    //    cert routes from the shared store and unhooking from the per-IP
    //    redirect listener.
    for removed in &diff.removed {
        if let Some(ap) = active.remove(&removed.name) {
            tracing::info!(
                rule = %removed.name,
                listen = %ap.handle.local_addr(),
                "stopping removed rule"
            );
            // Unregister redirect-listener hosts before stop (idempotent).
            if let ProxyHandle::Https(h) = &ap.handle {
                if let Some(rl) = redirect_listeners.get(&h.redirect_ip) {
                    for host in &h.redirect_hosts {
                        rl.unregister_host(host);
                    }
                }
            }
            // Unregister this rule's routes from the cert store and the
            // cert watcher's path index.
            unload_rule_from_cert_store(cert_store, cert_watcher, removed);
            ap.handle.stop().await;
        }
    }

    // 2. Swap proxies for changed rules. Stop-then-spawn (not the reverse)
    //    because both bind the same listen address — they can't coexist.
    for change in &diff.changed {
        if let Some(old) = active.remove(&change.old.name) {
            tracing::info!(
                rule = %change.old.name,
                old_listen = %old.handle.local_addr(),
                new_listen = %change.new.listen,
                "swapping changed rule"
            );
            if let ProxyHandle::Https(h) = &old.handle {
                if let Some(rl) = redirect_listeners.get(&h.redirect_ip) {
                    for host in &h.redirect_hosts {
                        rl.unregister_host(host);
                    }
                }
            }
            unload_rule_from_cert_store(cert_store, cert_watcher, &change.old);
            old.handle.stop().await;
        }
        match spawn_proxy_for_rule(
            change.new.clone(),
            resolver_factory,
            default_bind,
            cert_config,
            cert_store,
            cert_watcher,
            redirect_listeners,
            parent_cancel,
            active,
        )
        .await
        {
            Ok(ap) => {
                active.insert(change.new.name.clone(), ap);
            }
            Err(e) => {
                tracing::error!(
                    rule = %change.new.name,
                    error = %e,
                    "failed to spawn replacement proxy for changed rule; rule is now offline"
                );
            }
        }
    }

    // 3. Spawn proxies for added rules.
    for added in &diff.added {
        match spawn_proxy_for_rule(
            added.clone(),
            resolver_factory,
            default_bind,
            cert_config,
            cert_store,
            cert_watcher,
            redirect_listeners,
            parent_cancel,
            active,
        )
        .await
        {
            Ok(ap) => {
                tracing::info!(
                    rule = %added.name,
                    listen = %ap.handle.local_addr(),
                    protocol = added.protocol.as_str(),
                    upstream = %ap.upstream_description,
                    "added rule online"
                );
                active.insert(added.name.clone(), ap);
            }
            Err(e) => {
                tracing::error!(
                    rule = %added.name,
                    error = %e,
                    "failed to spawn proxy for new rule"
                );
            }
        }
    }

    // 4. Garbage-collect any redirect listeners whose host set is now empty
    //    (i.e. the last HTTPS rule referring to that IP went away).
    let dead_ips: Vec<IpAddr> = redirect_listeners
        .iter()
        .filter(|(_, l)| l.is_empty())
        .map(|(ip, _)| *ip)
        .collect();
    for ip in dead_ips {
        if let Some(l) = redirect_listeners.remove(&ip) {
            tracing::info!(ip = %ip, "tearing down idle HTTP→HTTPS redirect listener");
            l.stop().await;
        }
    }

    // 5. Unchanged rules: do nothing. (Their listeners and any in-flight
    //    flows are preserved.) The trace below is for observability only;
    //    it does not mutate state.
    if !diff.unchanged.is_empty() {
        tracing::trace!(
            unchanged = diff.unchanged.len(),
            "unchanged rules left undisturbed"
        );
    }
    let _ = set; // currently only the diff is needed
}

fn unload_rule_from_cert_store(
    cert_store:   &Arc<CertStore>,
    cert_watcher: &Arc<CertWatcher>,
    rule:         &Rule,
) {
    if rule.protocol != Protocol::Https {
        return;
    }
    if let Some(routes) = rule.routes.as_ref() {
        for r in routes {
            cert_watcher.unregister(&r.hostname);
            cert_store.remove(&r.hostname);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn spawn_proxy_for_rule(
    rule: Rule,
    resolver_factory: &ResolverFactory,
    default_bind: Option<IpAddr>,
    cert_config: &CertConfig,
    cert_store: &Arc<CertStore>,
    cert_watcher: &Arc<CertWatcher>,
    redirect_listeners: &mut HashMap<IpAddr, RedirectListener>,
    parent_cancel: &CancellationToken,
    active: &HashMap<String, ActiveProxy>,
) -> Result<ActiveProxy> {
    // Apply server-wide default_bind override before any uniqueness or
    // listener-binding work. The rule itself is left untouched in the
    // RuleSet (so reload diffs work) — we only clone-and-override here.
    let rule = rule.with_bind_override(default_bind);

    // Listen-exclusivity: a single SocketAddr cannot be claimed twice. The
    // OS would reject the second bind anyway, but checking here gives a
    // clearer error and is essential for the implicit `:80` claim made by
    // HTTPS rules.
    let claimed: HashSet<SocketAddr> = collect_claimed_addrs(active);
    if claimed.contains(&rule.listen) {
        anyhow::bail!(
            "rule {:?}: listen address {} is already claimed by another rule",
            rule.name,
            rule.listen,
        );
    }

    // HTTPS rules also implicitly claim `(listen.ip(), 80)` for the
    // redirect listener. Two HTTPS rules on the same IP share the
    // listener (refcounted), so the conflict is only with non-HTTPS rules
    // claiming :80.
    if rule.protocol == Protocol::Https {
        let implicit_80 = SocketAddr::new(rule.listen.ip(), 80);
        if claimed.contains(&implicit_80) {
            anyhow::bail!(
                "rule {:?}: implicit HTTP→HTTPS redirect on {} clashes with \
                 another rule already listening there",
                rule.name,
                implicit_80,
            );
        }
    }

    match rule.protocol {
        Protocol::Tcp | Protocol::Udp => {
            let resolver: UpstreamResolver = resolver_factory
                .build(&rule)
                .with_context(|| format!("build resolver for rule {:?}", rule.name))?;
            let upstream_description = resolver.describe();
            let handle = match rule.protocol {
                Protocol::Tcp => ProxyHandle::Tcp(TcpProxy::spawn(rule, resolver).await?),
                Protocol::Udp => ProxyHandle::Udp(UdpProxy::spawn(rule, resolver).await?),
                Protocol::Https => unreachable!(),
            };
            Ok(ActiveProxy {
                handle,
                upstream_description,
            })
        }
        Protocol::Https => {
            spawn_https_rule(
                rule,
                cert_config,
                cert_store,
                cert_watcher,
                redirect_listeners,
                parent_cancel,
            )
            .await
        }
    }
}

/// Walk every active proxy and collect the SocketAddrs it claims. For
/// HTTPS rules this includes the implicit `(ip, 80)` redirect claim.
fn collect_claimed_addrs(active: &HashMap<String, ActiveProxy>) -> HashSet<SocketAddr> {
    let mut out = HashSet::new();
    for ap in active.values() {
        let listen = ap.handle.local_addr();
        out.insert(listen);
        if let ProxyHandle::Https(_) = &ap.handle {
            out.insert(SocketAddr::new(listen.ip(), 80));
        }
    }
    out
}

async fn spawn_https_rule(
    rule:               Rule,
    cert_config:        &CertConfig,
    cert_store:         &Arc<CertStore>,
    cert_watcher:       &Arc<CertWatcher>,
    redirect_listeners: &mut HashMap<IpAddr, RedirectListener>,
    parent_cancel:      &CancellationToken,
) -> Result<ActiveProxy> {
    // 1. Load each route's certificate into the shared store. If any route
    //    fails we abort the whole rule and roll back what we loaded so the
    //    store doesn't get a half-applied rule.
    let routes = rule
        .routes
        .as_ref()
        .filter(|r| !r.is_empty())
        .with_context(|| {
            format!(
                "HTTPS rule {:?}: routes list is empty; validator should have rejected this",
                rule.name,
            )
        })?;

    let mut loaded_hosts: Vec<String> = Vec::with_capacity(routes.len());
    let load_result = load_rule_into_store(
        &rule,
        cert_store,
        &cert_config.cert_dir,
        cert_config
            .default_cert
            .as_deref()
            .zip(cert_config.default_key.as_deref()),
    );
    if let Err(e) = load_result {
        // Roll back any entries we did manage to set (load_rule_into_store
        // is best-effort but may have inserted some before failing).
        for host in routes.iter().map(|r| r.hostname.clone()) {
            cert_store.remove(&host);
        }
        // Emit per-route reload-failed counters. We can't know exactly which
        // route hit the error, so we count the rule itself as failing on its
        // first route — this is good enough as an alert signal.
        if let Some(first) = routes.first() {
            metrics::counter!(
                "yggdrasil_https_cert_reload_total",
                "route" => first.hostname.to_ascii_lowercase(),
                "result" => "err",
            )
            .increment(1);
        }
        return Err(e).with_context(|| format!("load certs for HTTPS rule {:?}", rule.name));
    }
    for r in routes {
        let host_lower = r.hostname.to_ascii_lowercase();
        loaded_hosts.push(host_lower.clone());
        // Register the route's disk paths with the cert watcher (a no-op
        // for ephemeral routes, since their `watched_paths()` is empty).
        let paths = cert_store.watched_paths_for(&host_lower);
        cert_watcher.register(&host_lower, &paths);
        metrics::counter!(
            "yggdrasil_https_cert_reload_total",
            "route" => host_lower,
            "result" => "ok",
        )
        .increment(1);
    }

    // 2. Spawn (or look up) the per-IP redirect listener.
    let ip = rule.listen.ip();
    if let std::collections::hash_map::Entry::Vacant(e) = redirect_listeners.entry(ip) {
        let port = cert_config.redirect_port.unwrap_or(80);
        let rl = RedirectListener::spawn(ip, port, parent_cancel.clone())
            .await
            .with_context(|| format!("spawn HTTP→HTTPS redirect listener on {ip}:{port}"))?;
        e.insert(rl);
    }
    let rl = redirect_listeners.get(&ip).expect("just inserted");
    let redirect_hosts: Vec<String> = loaded_hosts.clone();
    for host in &redirect_hosts {
        rl.register_host(host);
    }

    // 3. Spawn the HTTPS frontend.
    let frontend_res = HttpFrontend::spawn(
        &rule,
        Arc::clone(cert_store),
        parent_cancel.clone(),
    )
    .await;
    let frontend = match frontend_res {
        Ok(f) => f,
        Err(e) => {
            // Roll back redirect registration + cert watcher + cert store entries.
            if let Some(rl) = redirect_listeners.get(&ip) {
                for host in &redirect_hosts {
                    rl.unregister_host(host);
                }
            }
            for host in &loaded_hosts {
                cert_watcher.unregister(host);
                cert_store.remove(host);
            }
            return Err(e).with_context(|| format!("spawn HTTPS frontend for rule {:?}", rule.name));
        }
    };

    let listen = frontend.local_addr();
    let handle = ProxyHandle::Https(HttpsHandle {
        frontend,
        redirect_hosts,
        redirect_ip: ip,
        listen,
        rule: rule.clone(),
    });

    Ok(ActiveProxy {
        handle,
        upstream_description: format!("https:{} routes", routes.len()),
    })
}

fn publish_snapshot(
    active: &HashMap<String, ActiveProxy>,
    snapshot_tx: &tokio::sync::watch::Sender<Vec<ProxySnapshot>>,
    cert_store: &Arc<CertStore>,
) {
    let mut snaps: Vec<ProxySnapshot> = active
        .values()
        .map(|ap| ProxySnapshot {
            name: ap.handle.rule().name.clone(),
            protocol: ap.handle.rule().protocol,
            listen: ap.handle.local_addr(),
            upstream_description: ap.upstream_description.clone(),
        })
        .collect();
    snaps.sort_by(|a, b| a.name.cmp(&b.name));
    metrics::gauge!("yggdrasil_rules_loaded").set(snaps.len() as f64);
    metrics::gauge!("yggdrasil_https_routes").set(cert_store.len() as f64);
    let _ = snapshot_tx.send(snaps);
}

// Convenience for the supervisor: the `RuleSet` type is referenced for
// future expansion (e.g. per-set metadata) but isn't required by the diff
// itself. Keep the import path intact so downstream commits can use it.
#[allow(dead_code)]
fn _rule_set_marker(_: &RuleSet) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::heartbeat::PeerState;

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
            CertConfig::default(),
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
            CertConfig::default(),
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
            CertConfig::default(),
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
            CertConfig::default(),
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
        assert!(saw_swap, "timed out waiting for beta upstream port=9999 swap");

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
            CertConfig::default(),
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
            CertConfig::default(),
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
            CertConfig::default(),
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
        handle
            .apply_ruleset(RuleSet::default())
            .await
            .unwrap();
        await_snapshot_len(&sup, 0).await;

        sup.stop().await;
    }
}
