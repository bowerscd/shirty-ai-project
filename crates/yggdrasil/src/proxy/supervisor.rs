//! Cross-rule proxy supervisor.
//!
//! Owns a [`BranchWatcher`] and reconciles each delivered [`BranchUpdate`]
//! against the currently-running proxy set: spawns proxies for added rules,
//! stops proxies for removed rules, and swaps proxies for changed rules.
//! Unchanged rules are left strictly alone — their `TcpListener` /
//! `UdpSocket` and any in-flight UDP flows survive the reload untouched.
//!
//! This is the branch-level analogue of the heartbeat-level "same-IP
//! heartbeats don't disturb the data plane" invariance: a hot reload that
//! only touches rule A must not interrupt rule B.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use yggdrasil_proto::branch::{BranchSet, Protocol, Rule};

use crate::branches::{BranchUpdate, BranchWatcher, ReloadTrigger};
use crate::heartbeat::PeerState;

use super::tcp::TcpProxy;
use super::udp::UdpProxy;

/// Type-erased handle to a running per-rule proxy.
enum ProxyHandle {
    Tcp(TcpProxy),
    Udp(UdpProxy),
}

impl ProxyHandle {
    fn local_addr(&self) -> SocketAddr {
        match self {
            Self::Tcp(p) => p.local_addr(),
            Self::Udp(p) => p.local_addr(),
        }
    }

    fn rule(&self) -> &Rule {
        match self {
            Self::Tcp(p) => p.rule(),
            Self::Udp(p) => p.rule(),
        }
    }

    async fn stop(self) {
        match self {
            Self::Tcp(p) => p.stop().await,
            Self::Udp(p) => p.stop().await,
        }
    }
}

/// Snapshot of one supervised proxy used by tests and (later) by yggdrasilctl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySnapshot {
    pub name: String,
    pub protocol: Protocol,
    pub listen: SocketAddr,
    pub upstream_port: u16,
}

/// Handle to a running supervisor.
pub struct ProxySupervisor {
    cancel: CancellationToken,
    main_handle: JoinHandle<()>,
    snapshot_rx: tokio::sync::watch::Receiver<Vec<ProxySnapshot>>,
    branch_dir: PathBuf,
    reload_trigger: ReloadTrigger,
}

impl ProxySupervisor {
    /// Spawn the supervisor. The initial branch load happens synchronously
    /// inside `BranchWatcher::spawn` so a malformed branch directory aborts
    /// startup loudly. Subsequent reload failures are logged and ignored
    /// (previous good set retained).
    ///
    /// `shutdown` is observed cooperatively: cancelling it stops the
    /// supervisor and all child proxies.
    pub async fn spawn(
        branch_dir: impl Into<PathBuf>,
        debounce: Duration,
        peer_state: Arc<PeerState>,
        shutdown: CancellationToken,
    ) -> Result<Self> {
        let branch_dir: PathBuf = branch_dir.into();
        let watcher = BranchWatcher::spawn(&branch_dir, debounce)
            .with_context(|| format!("spawn branch watcher for {}", branch_dir.display()))?;
        let reload_trigger = watcher.reload_trigger();

        let cancel = shutdown.child_token();
        let (snapshot_tx, snapshot_rx) = tokio::sync::watch::channel(Vec::<ProxySnapshot>::new());

        let main_cancel = cancel.clone();
        let main_handle = tokio::spawn(supervisor_loop(
            watcher,
            peer_state,
            main_cancel,
            snapshot_tx,
        ));

        Ok(Self {
            cancel,
            main_handle,
            snapshot_rx,
            branch_dir,
            reload_trigger,
        })
    }

    pub fn branch_dir(&self) -> &Path {
        &self.branch_dir
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
}

async fn supervisor_loop(
    mut watcher: BranchWatcher,
    peer_state: Arc<PeerState>,
    cancel: CancellationToken,
    snapshot_tx: tokio::sync::watch::Sender<Vec<ProxySnapshot>>,
) {
    let mut active: HashMap<String, ProxyHandle> = HashMap::new();

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
                        apply_update(&mut active, u, &peer_state).await;
                        publish_snapshot(&active, &snapshot_tx);
                    }
                    None => {
                        tracing::warn!("branch watcher channel closed; supervisor exiting");
                        break;
                    }
                }
            }
        }
    }

    // Shutdown: stop every active proxy concurrently. Drain the snapshot
    // last so observers see the empty set on the way out.
    let handles: Vec<ProxyHandle> = active.drain().map(|(_, p)| p).collect();
    let stops = handles.into_iter().map(|p| p.stop());
    futures::future::join_all(stops).await;
    publish_snapshot(&active, &snapshot_tx);
    tracing::info!("supervisor shut down");
}

async fn apply_update(
    active: &mut HashMap<String, ProxyHandle>,
    update: BranchUpdate,
    peer_state: &Arc<PeerState>,
) {
    let BranchUpdate { set, diff } = update;

    // 1. Remove proxies for removed rules.
    for removed in &diff.removed {
        if let Some(handle) = active.remove(&removed.name) {
            tracing::info!(
                rule = %removed.name,
                listen = %handle.local_addr(),
                "stopping removed rule"
            );
            handle.stop().await;
        }
    }

    // 2. Swap proxies for changed rules. Stop-then-spawn (not the reverse)
    //    because both bind the same listen address — they can't coexist.
    for change in &diff.changed {
        if let Some(old) = active.remove(&change.old.name) {
            tracing::info!(
                rule = %change.old.name,
                old_listen = %old.local_addr(),
                new_listen = %change.new.listen,
                "swapping changed rule"
            );
            old.stop().await;
        }
        match spawn_proxy_for_rule(change.new.clone(), peer_state).await {
            Ok(handle) => {
                active.insert(change.new.name.clone(), handle);
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
        match spawn_proxy_for_rule(added.clone(), peer_state).await {
            Ok(handle) => {
                tracing::info!(
                    rule = %added.name,
                    listen = %handle.local_addr(),
                    protocol = added.protocol.as_str(),
                    "added rule online"
                );
                active.insert(added.name.clone(), handle);
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

    // 4. Unchanged rules: do nothing. (Their listeners and any in-flight
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

async fn spawn_proxy_for_rule(
    rule: Rule,
    peer_state: &Arc<PeerState>,
) -> Result<ProxyHandle> {
    match rule.protocol {
        Protocol::Tcp => {
            let p = TcpProxy::spawn(rule, peer_state.clone()).await?;
            Ok(ProxyHandle::Tcp(p))
        }
        Protocol::Udp => {
            let p = UdpProxy::spawn(rule, peer_state.clone()).await?;
            Ok(ProxyHandle::Udp(p))
        }
    }
}

fn publish_snapshot(
    active: &HashMap<String, ProxyHandle>,
    snapshot_tx: &tokio::sync::watch::Sender<Vec<ProxySnapshot>>,
) {
    let mut snaps: Vec<ProxySnapshot> = active
        .values()
        .map(|p| ProxySnapshot {
            name: p.rule().name.clone(),
            protocol: p.rule().protocol,
            listen: p.local_addr(),
            upstream_port: p.rule().upstream_port,
        })
        .collect();
    snaps.sort_by(|a, b| a.name.cmp(&b.name));
    metrics::gauge!("yggdrasil_branches_loaded").set(snaps.len() as f64);
    let _ = snapshot_tx.send(snaps);
}

// Convenience for the supervisor: the `BranchSet` type is referenced for
// future expansion (e.g. per-set metadata) but isn't required by the diff
// itself. Keep the import path intact so downstream commits can use it.
#[allow(dead_code)]
fn _branch_set_marker(_: &BranchSet) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn tcp_rule_toml(name: &str, port: u16, upstream_port: u16) -> String {
        format!(
            r#"
            [[rule]]
            name = "{name}"
            listen = "127.0.0.1:{port}"
            protocol = "tcp"
            upstream_port = {upstream_port}
            "#,
        )
    }

    fn udp_rule_toml(name: &str, port: u16, upstream_port: u16) -> String {
        format!(
            r#"
            [[rule]]
            name = "{name}"
            listen = "127.0.0.1:{port}"
            protocol = "udp"
            upstream_port = {upstream_port}
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
    async fn spawns_proxies_for_initial_branch_set() {
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

        let peer = PeerState::new([0u8; 32]);
        let shutdown = CancellationToken::new();
        let sup = ProxySupervisor::spawn(
            dir.path().to_path_buf(),
            Duration::from_millis(50),
            peer,
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

        let peer = PeerState::new([0u8; 32]);
        let shutdown = CancellationToken::new();
        let sup = ProxySupervisor::spawn(
            dir.path().to_path_buf(),
            Duration::from_millis(50),
            peer,
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

        let peer = PeerState::new([0u8; 32]);
        let shutdown = CancellationToken::new();
        let sup = ProxySupervisor::spawn(
            dir.path().to_path_buf(),
            Duration::from_millis(50),
            peer,
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
        // This is the branch-level analogue of the heartbeat-invariance
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

        let peer = PeerState::new([0u8; 32]);
        let shutdown = CancellationToken::new();
        let sup = ProxySupervisor::spawn(
            dir.path().to_path_buf(),
            Duration::from_millis(50),
            peer,
            shutdown.clone(),
        )
        .await
        .unwrap();

        await_snapshot_len(&sup, 2).await;
        let snap0 = sup.snapshot();
        let alpha_listen_before = snap0.iter().find(|s| s.name == "alpha").unwrap().listen;
        let beta_listen_before = snap0.iter().find(|s| s.name == "beta").unwrap().listen;

        // Change beta's upstream_port only (listen stays the same so we can
        // assert socket-address stability). alpha must NOT be touched.
        std::fs::write(
            dir.path().join("b.toml"),
            tcp_rule_toml("beta", port_b, 9999),
        )
        .unwrap();

        // Wait for the snapshot to actually reflect the change. We look for
        // an alpha-still-present + beta-with-new-upstream snapshot.
        let mut rx = sup.snapshot_rx.clone();
        let saw_swap = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                {
                    let s = rx.borrow();
                    let alpha = s.iter().find(|x| x.name == "alpha");
                    let beta = s.iter().find(|x| x.name == "beta");
                    if let (Some(a), Some(b)) = (alpha, beta) {
                        if a.listen == alpha_listen_before && b.upstream_port == 9999 {
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
        assert!(saw_swap, "timed out waiting for beta upstream_port=9999 swap");

        let snap1 = sup.snapshot();
        let alpha_listen_after = snap1.iter().find(|s| s.name == "alpha").unwrap().listen;
        let beta_listen_after = snap1.iter().find(|s| s.name == "beta").unwrap().listen;
        let beta_upstream_after = snap1
            .iter()
            .find(|s| s.name == "beta")
            .unwrap()
            .upstream_port;

        // Alpha must be untouched.
        assert_eq!(
            alpha_listen_before, alpha_listen_after,
            "alpha's listen address changed across an unrelated reload"
        );
        // Beta's listen port hasn't changed (we kept the port and only swapped
        // upstream_port), but the proxy was respawned (which is fine — we're
        // not promising socket-identity across changes to the same rule).
        assert_eq!(beta_listen_before, beta_listen_after);
        assert_eq!(beta_upstream_after, 9999);

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

        let peer = PeerState::new([0u8; 32]);
        let shutdown = CancellationToken::new();
        let sup = ProxySupervisor::spawn(
            dir.path().to_path_buf(),
            Duration::from_millis(50),
            peer,
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
    async fn invalid_branch_directory_fails_spawn() {
        let dir = tempfile::tempdir().unwrap();
        // Two rules with the same name → BranchSet validation fails.
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

        let peer = PeerState::new([0u8; 32]);
        let shutdown = CancellationToken::new();
        let res = ProxySupervisor::spawn(
            dir.path().to_path_buf(),
            Duration::from_millis(50),
            peer,
            shutdown,
        )
        .await;
        assert!(res.is_err(), "expected duplicate-rule-name error");
    }
}
