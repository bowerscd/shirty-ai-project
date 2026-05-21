//! Per-rule UDP proxy with on-demand flow table.
//!
//! ## Architecture
//!
//! Each [`UdpProxy`] owns:
//!
//! * One frontend `UdpSocket` bound to `rule.listen`.
//! * A `DashMap<SocketAddr, Arc<FlowEntry>>` keyed by client address.
//! * Four cooperating tasks (all rooted at a single `CancellationToken`):
//!   1. **Frontend loop** — `recv_from` on the listener, dispatches to flows.
//!   2. **Reaper** — periodic sweep that evicts flows past `idle_timeout`.
//!   3. **IP-change watcher** — awaits `peer_state.watch()` and drains all
//!      flows when the residential IP changes value.
//!   4. **Per-flow upstream loop** (one per active flow) — reads return
//!      datagrams from the upstream socket and forwards them to the client.
//!
//! ## Heartbeat invariance (critical invariant)
//!
//! The flow table is **only** invalidated when `PeerState.current_ip`
//! actually changes value (`HeartbeatEffect::IpChanged` /
//! `HeartbeatEffect::FirstHeartbeat`). Heartbeats that re-confirm the
//! existing IP do not fire the watch and therefore do not disturb the
//! table — every existing flow keeps its upstream socket pair, preserving
//! stateful UDP sessions like Factorio dedicated servers across the
//! dial-side heartbeat cadence.
//!
//! The IP-change watcher uses `watch::Receiver::changed().await`, so it is
//! literally impossible for unchanged values to wake it up.
//!
//! ## Capacity
//!
//! Per-rule flow cap defaults to [`MAX_FLOWS_PER_RULE_DEFAULT`] = 65 536.
//! When full, new client addresses are dropped and counted under
//! `yggdrasil_udp_flows_rejected_total{rule,reason="cap"}`. The
//! single-datagram receive buffer is 65 535 B (full IP MTU).

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use ratatoskr::rule::Rule;

use super::resolver::{UpstreamResolver, WatchHandle};

/// Default cap on concurrent client flows per UDP rule. Sized to cover any
/// realistic residential workload while bounding FD / memory cost.
pub const MAX_FLOWS_PER_RULE_DEFAULT: usize = 65_536;

/// Maximum UDP payload we'll read from the frontend socket. Equal to the
/// largest possible IP datagram payload; jumbo / fragmented packets that
/// arrive intact will not be truncated by us.
const RECV_BUFFER_LEN: usize = 65_535;

/// One per active `(client_addr) → (peer_ip, target_port)` flow.
struct FlowEntry {
    upstream_sock: Arc<UdpSocket>,
    /// Milliseconds since [`UdpProxy::start`]. Updated on every datagram in
    /// either direction. Wraps after ~584 million years.
    last_seen_ms: AtomicU64,
    /// Aborted by the IP-change watcher (and the reaper, via `abort`).
    upstream_task: tokio::task::AbortHandle,
}

/// Handle to a running per-rule UDP proxy.
pub struct UdpProxy {
    rule: Rule,
    cancel: CancellationToken,
    local_addr: SocketAddr,
    /// One handle that resolves when all four background tasks have exited.
    main_handle: tokio::task::JoinHandle<()>,
    flows: Arc<DashMap<SocketAddr, Arc<FlowEntry>>>,
}

impl UdpProxy {
    /// Bind the frontend socket and spawn the proxy tasks.
    pub async fn spawn(rule: Rule, resolver: UpstreamResolver) -> Result<Self> {
        Self::spawn_with_cap(rule, resolver, MAX_FLOWS_PER_RULE_DEFAULT).await
    }

    /// Same as [`UdpProxy::spawn`] but with an explicit flow cap; intended
    /// for tests that want to exercise the soft-cap path without binding
    /// thousands of sockets.
    pub async fn spawn_with_cap(
        rule: Rule,
        resolver: UpstreamResolver,
        max_flows: usize,
    ) -> Result<Self> {
        let frontend = UdpSocket::bind(rule.listen)
            .await
            .with_context(|| format!("bind UDP frontend for rule {:?} on {}", rule.name, rule.listen))?;
        let local_addr = frontend.local_addr().context("read UdpSocket local_addr")?;
        let frontend = Arc::new(frontend);

        let cancel = CancellationToken::new();
        let flows: Arc<DashMap<SocketAddr, Arc<FlowEntry>>> = Arc::new(DashMap::new());
        let start = Instant::now();
        let idle_timeout = rule.resolved_idle_timeout();

        let inner = UdpProxyInner {
            rule: rule.clone(),
            frontend: frontend.clone(),
            resolver: resolver.clone(),
            flows: flows.clone(),
            cancel: cancel.clone(),
            start,
            max_flows,
            idle_timeout,
        };

        let main_handle = tokio::spawn(inner.run());

        tracing::info!(
            rule = %rule.name,
            listen = %local_addr,
            upstream = %resolver.describe(),
            idle_timeout_secs = idle_timeout.as_secs(),
            max_flows,
            "UDP rule listening"
        );

        Ok(Self {
            rule,
            cancel,
            local_addr,
            main_handle,
            flows,
        })
    }

    pub fn rule(&self) -> &Rule {
        &self.rule
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Currently-tracked flow count (snapshot; may change immediately).
    pub fn active_flows(&self) -> usize {
        self.flows.len()
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = self.main_handle.await;
    }
}

struct UdpProxyInner {
    rule: Rule,
    frontend: Arc<UdpSocket>,
    resolver: UpstreamResolver,
    flows: Arc<DashMap<SocketAddr, Arc<FlowEntry>>>,
    cancel: CancellationToken,
    start: Instant,
    max_flows: usize,
    idle_timeout: Duration,
}

impl UdpProxyInner {
    async fn run(self) {
        let frontend_task = {
            let s = self.clone_ctx();
            tokio::spawn(async move { s.frontend_loop().await })
        };
        let reaper_task = {
            let s = self.clone_ctx();
            tokio::spawn(async move { s.reaper_loop().await })
        };
        // Only dynamic resolvers (relay mode) can change their dial target,
        // so static (terminal) resolvers don't need an ipchange watcher at
        // all — it would just park on a NeverFires future, wasting a task.
        let ipchange_task = if self.resolver.is_dynamic() {
            let s = self.clone_ctx();
            Some(tokio::spawn(async move { s.ipchange_loop().await }))
        } else {
            None
        };

        // Cancellation propagates to all spawned tasks via the shared
        // token. Wait for them to wind down before returning.
        match ipchange_task {
            Some(ipc) => {
                let _ = tokio::join!(frontend_task, reaper_task, ipc);
            }
            None => {
                let _ = tokio::join!(frontend_task, reaper_task);
            }
        }

        // Final flow-table cleanup: aborts any straggler upstream tasks.
        for entry in self.flows.iter() {
            entry.value().upstream_task.abort();
        }
        self.flows.clear();
        tracing::debug!(rule = %self.rule.name, "UDP proxy shutdown complete");
    }

    fn clone_ctx(&self) -> Self {
        Self {
            rule: self.rule.clone(),
            frontend: self.frontend.clone(),
            resolver: self.resolver.clone(),
            flows: self.flows.clone(),
            cancel: self.cancel.clone(),
            start: self.start,
            max_flows: self.max_flows,
            idle_timeout: self.idle_timeout,
        }
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    async fn frontend_loop(self) {
        let mut buf = vec![0u8; RECV_BUFFER_LEN];
        loop {
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => {
                    tracing::debug!(rule = %self.rule.name, "UDP frontend loop received cancel");
                    return;
                }
                res = self.frontend.recv_from(&mut buf) => {
                    let (n, client_addr) = match res {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!(rule = %self.rule.name, error = %e, "UDP recv_from failed");
                            continue;
                        }
                    };
                    self.handle_inbound(&buf[..n], client_addr).await;
                }
            }
        }
    }

    async fn handle_inbound(&self, payload: &[u8], client_addr: SocketAddr) {
        // Fast path: existing flow.
        if let Some(entry) = self.flows.get(&client_addr) {
            entry.last_seen_ms.store(self.now_ms(), Ordering::Relaxed);
            if let Err(e) = entry.upstream_sock.send(payload).await {
                tracing::debug!(
                    rule = %self.rule.name,
                    client = %client_addr,
                    error = %e,
                    "upstream send failed; flow may be stale (will be reaped)"
                );
            }
            return;
        }

        // No flow yet. Need a resolved dial target and capacity.
        let Some(target_addr) = self.resolver.current_target() else {
            tracing::debug!(
                rule = %self.rule.name,
                client = %client_addr,
                "drop UDP datagram: upstream not yet resolvable (no heartbeat received)"
            );
            return;
        };

        if self.flows.len() >= self.max_flows {
            tracing::warn!(
                rule = %self.rule.name,
                client = %client_addr,
                cap = self.max_flows,
                "drop UDP datagram: flow table at cap"
            );
            metrics::counter!(
                "yggdrasil_udp_flows_rejected_total",
                "rule" => self.rule.name.clone(),
                "reason" => "cap",
            )
            .increment(1);
            return;
        }

        let entry = match self.create_flow(client_addr, target_addr).await {
            Some(e) => e,
            None => return,
        };

        if let Err(e) = entry.upstream_sock.send(payload).await {
            tracing::debug!(
                rule = %self.rule.name,
                client = %client_addr,
                upstream = %target_addr,
                error = %e,
                "first upstream send on new flow failed"
            );
            // Don't tear the flow down — recv loops may still be useful and
            // the reaper will clean up if it stays idle.
        }
    }

    async fn create_flow(
        &self,
        client_addr: SocketAddr,
        target_addr: SocketAddr,
    ) -> Option<Arc<FlowEntry>> {
        // Ephemeral upstream socket, connected so subsequent send/recv go
        // directly without an addr lookup.
        let bind_addr: SocketAddr = match target_addr.ip() {
            IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            IpAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        let sock = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    rule = %self.rule.name,
                    client = %client_addr,
                    error = %e,
                    "bind ephemeral upstream UDP socket failed"
                );
                return None;
            }
        };
        if let Err(e) = sock.connect(target_addr).await {
            tracing::warn!(
                rule = %self.rule.name,
                client = %client_addr,
                upstream = %target_addr,
                error = %e,
                "connect upstream UDP socket failed"
            );
            return None;
        }
        let upstream_sock = Arc::new(sock);

        // Per-flow upstream→client task.
        let task_us = upstream_sock.clone();
        let task_frontend = self.frontend.clone();
        let task_cancel = self.cancel.child_token();
        let task_rule_name = self.rule.name.clone();
        let task_flows = self.flows.clone();
        let task_client = client_addr;
        let task_start = self.start;
        // The JoinHandle is dropped at end of statement (detaches the task);
        // we keep the AbortHandle for cancellation via the flow table.
        let upstream_handle = tokio::spawn(async move {
            upstream_to_client_loop(
                task_rule_name,
                task_us,
                task_frontend,
                task_client,
                task_cancel,
                task_flows,
                task_start,
            )
            .await;
        })
        .abort_handle();

        let entry = Arc::new(FlowEntry {
            upstream_sock,
            last_seen_ms: AtomicU64::new(self.now_ms()),
            upstream_task: upstream_handle,
        });

        // Insert. If another concurrent datagram beat us to it (very rare —
        // requires two datagrams from the same client_addr to arrive while
        // the table miss-path is in flight), prefer the existing entry and
        // discard ours.
        match self.flows.entry(client_addr) {
            dashmap::mapref::entry::Entry::Occupied(o) => {
                entry.upstream_task.abort();
                let existing = o.get().clone();
                drop(entry);
                Some(existing)
            }
            dashmap::mapref::entry::Entry::Vacant(v) => {
                tracing::debug!(
                    rule = %self.rule.name,
                    client = %client_addr,
                    upstream = %target_addr,
                    "new UDP flow"
                );
                v.insert(entry.clone());
                Some(entry)
            }
        }
    }

    async fn reaper_loop(self) {
        // Scan at least once per second so test-sized idle_timeouts still
        // get evicted promptly, while still being cheap (a DashMap iter is
        // O(n) with minimal per-element cost).
        let interval = std::cmp::max(self.idle_timeout / 4, Duration::from_millis(100));
        loop {
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => return,
                _ = tokio::time::sleep(interval) => {}
            }
            self.reap_idle();
        }
    }

    fn reap_idle(&self) {
        let now_ms = self.now_ms();
        let idle_ms = self.idle_timeout.as_millis() as u64;
        let mut victims = Vec::new();
        for entry in self.flows.iter() {
            let last = entry.value().last_seen_ms.load(Ordering::Relaxed);
            if now_ms.saturating_sub(last) >= idle_ms {
                victims.push(*entry.key());
            }
        }
        for client in victims {
            if let Some((_, entry)) = self.flows.remove(&client) {
                entry.upstream_task.abort();
                tracing::debug!(
                    rule = %self.rule.name,
                    client = %client,
                    "reaped idle UDP flow"
                );
            }
        }
    }

    async fn ipchange_loop(self) {
        // Only spawned for Dynamic resolvers. The watch handle's initial
        // `borrow_and_update` consumption mirrors what the old peer_state
        // path did: do NOT treat the initial None→Some as a "drain" event,
        // because at that moment there are no flows to drain anyway (no
        // flow can have been created before the resolver had a target).
        let mut handle: WatchHandle = self.resolver.watch_ip_changes();
        if let WatchHandle::Dynamic(ref mut rx) = handle {
            let _ = rx.borrow_and_update();
        }
        loop {
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => return,
                changed = handle.changed() => {
                    if changed.is_err() {
                        return; // sender dropped → shutdown imminent
                    }
                    // Read the post-change target for logging only; the
                    // drain itself is target-agnostic.
                    let new_target = self.resolver.current_target();
                    self.drain_all_flows(new_target.map(|a| a.ip()));
                }
            }
        }
    }

    fn drain_all_flows(&self, new_ip: Option<IpAddr>) {
        let count_before = self.flows.len();
        // Abort then clear. Using retain(false) over clear() to access the
        // entries and abort their tasks atomically per-shard.
        self.flows.retain(|_, entry| {
            entry.upstream_task.abort();
            false
        });
        if count_before > 0 {
            metrics::counter!(
                "yggdrasil_udp_flows_drained_on_ip_change_total",
                "rule" => self.rule.name.clone(),
            )
            .increment(count_before as u64);
        }
        tracing::info!(
            rule = %self.rule.name,
            new_peer_ip = ?new_ip,
            flows_drained = count_before,
            "peer IP changed; drained UDP flow table"
        );
    }
}

async fn upstream_to_client_loop(
    rule_name: String,
    upstream: Arc<UdpSocket>,
    frontend: Arc<UdpSocket>,
    client_addr: SocketAddr,
    cancel: CancellationToken,
    flows: Arc<DashMap<SocketAddr, Arc<FlowEntry>>>,
    start: Instant,
) {
    let mut buf = vec![0u8; RECV_BUFFER_LEN];
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            res = upstream.recv(&mut buf) => {
                let n = match res {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::debug!(
                            rule = %rule_name,
                            client = %client_addr,
                            error = %e,
                            "upstream recv failed; flow ending"
                        );
                        // Remove ourselves so the next client datagram
                        // creates a fresh flow.
                        flows.remove(&client_addr);
                        return;
                    }
                };
                if let Err(e) = frontend.send_to(&buf[..n], client_addr).await {
                    tracing::debug!(
                        rule = %rule_name,
                        client = %client_addr,
                        error = %e,
                        "frontend send_to client failed"
                    );
                    continue;
                }
                // Touch last_seen for the return-traffic direction too.
                if let Some(entry) = flows.get(&client_addr) {
                    let now_ms = start.elapsed().as_millis() as u64;
                    entry.last_seen_ms.store(now_ms, Ordering::Relaxed);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::heartbeat::PeerState;

    /// Wrap a peer state in a Dynamic resolver — mirrors the production
    /// `ResolverFactory::new_relay(...).build(rule)` path without dragging
    /// the factory machinery into per-proxy unit tests.
    fn dynamic_resolver(peer: Arc<PeerState>, port: u16) -> UpstreamResolver {
        UpstreamResolver::Dynamic {
            peer_state: peer,
            port,
        }
    }

    /// Background UDP echo server. Returns its bound addr.
    async fn echo_server() -> SocketAddr {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let (n, from) = match sock.recv_from(&mut buf).await {
                    Ok(r) => r,
                    Err(_) => return,
                };
                let _ = sock.send_to(&buf[..n], from).await;
            }
        });
        addr
    }

    fn udp_rule(name: &str, target_port: u16, idle_secs: u64) -> Rule {
        let f = ratatoskr::rule::RuleFile::from_toml(
            "test.toml",
            &format!(
                r#"
                [[rule]]
                name = "{name}"
                listen = "127.0.0.1:0"
                protocol = "udp"
                target_port = {target_port}
                idle_timeout = "{idle_secs}s"
                "#,
            ),
        )
        .unwrap();
        f.rule.into_iter().next().unwrap()
    }

    async fn send_recv(client: &UdpSocket, proxy_addr: SocketAddr, msg: &[u8]) -> Vec<u8> {
        client.send_to(msg, proxy_addr).await.unwrap();
        let mut buf = vec![0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("recv timed out")
            .unwrap();
        buf.truncate(n);
        buf
    }

    #[tokio::test]
    async fn echoes_datagram_through_proxy() {
        let upstream = echo_server().await;
        let peer = PeerState::new([0u8; 32]);
        let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());
        let proxy = UdpProxy::spawn(
            udp_rule("echo", upstream.port(), 60),
            dynamic_resolver(peer, upstream.port()),
        )
        .await
        .unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let got = send_recv(&client, proxy.local_addr(), b"hello").await;
        assert_eq!(got, b"hello");
        assert_eq!(proxy.active_flows(), 1);

        proxy.stop().await;
    }

    #[tokio::test]
    async fn each_client_gets_its_own_flow() {
        let upstream = echo_server().await;
        let peer = PeerState::new([0u8; 32]);
        let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());
        let proxy = UdpProxy::spawn(
            udp_rule("multi", upstream.port(), 60),
            dynamic_resolver(peer, upstream.port()),
        )
        .await
        .unwrap();

        let c1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let c2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let c3 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        assert_eq!(send_recv(&c1, proxy.local_addr(), b"one").await, b"one");
        assert_eq!(send_recv(&c2, proxy.local_addr(), b"two").await, b"two");
        assert_eq!(send_recv(&c3, proxy.local_addr(), b"three").await, b"three");

        assert_eq!(proxy.active_flows(), 3);
        proxy.stop().await;
    }

    #[tokio::test]
    async fn drops_datagram_when_no_peer_yet() {
        let upstream = echo_server().await;
        let peer = PeerState::new([0u8; 32]);
        // No record_heartbeat → current_ip is None.

        let proxy = UdpProxy::spawn(
            udp_rule("nopeer", upstream.port(), 60),
            dynamic_resolver(peer, upstream.port()),
        )
        .await
        .unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(b"silent", proxy.local_addr())
            .await
            .unwrap();
        let mut buf = [0u8; 2048];
        let res = tokio::time::timeout(Duration::from_millis(500), client.recv_from(&mut buf)).await;
        assert!(res.is_err(), "expected timeout — no peer IP means drop");
        assert_eq!(proxy.active_flows(), 0);

        proxy.stop().await;
    }

    #[tokio::test]
    async fn reaper_evicts_idle_flow() {
        let upstream = echo_server().await;
        let peer = PeerState::new([0u8; 32]);
        let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());
        // 200ms idle_timeout. reaper interval ≈ max(50ms, 100ms) = 100ms.
        let rule = {
            let mut r = udp_rule("idle", upstream.port(), 1);
            r.idle_timeout = Some(Duration::from_millis(200));
            r
        };
        let proxy = UdpProxy::spawn(rule, dynamic_resolver(peer, upstream.port())).await.unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let _ = send_recv(&client, proxy.local_addr(), b"x").await;
        assert_eq!(proxy.active_flows(), 1);

        // Wait long enough for the flow to age out and the reaper to fire.
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(
            proxy.active_flows(),
            0,
            "reaper should have evicted the idle flow"
        );

        proxy.stop().await;
    }

    #[tokio::test]
    async fn ip_change_drains_flow_table() {
        let upstream = echo_server().await;
        let peer = PeerState::new([0u8; 32]);
        let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());
        let proxy = UdpProxy::spawn(
            udp_rule("drain", upstream.port(), 60),
            dynamic_resolver(peer.clone(), upstream.port()),
        )
        .await
        .unwrap();

        // Establish 3 flows.
        let c1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let c2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let c3 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert_eq!(send_recv(&c1, proxy.local_addr(), b"1").await, b"1");
        assert_eq!(send_recv(&c2, proxy.local_addr(), b"2").await, b"2");
        assert_eq!(send_recv(&c3, proxy.local_addr(), b"3").await, b"3");
        assert_eq!(proxy.active_flows(), 3);

        // Simulate an IP change via the same PeerState.
        let _ = peer.record_heartbeat("198.51.100.1:1".parse().unwrap());

        // The watcher task should drain the table promptly.
        for _ in 0..50 {
            if proxy.active_flows() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            proxy.active_flows(),
            0,
            "IP change must drain the flow table"
        );

        proxy.stop().await;
    }

    #[tokio::test]
    async fn same_ip_heartbeats_do_not_drain_flow_table() {
        // *The* critical invariance test for stateful UDP games. We send a
        // burst of heartbeat-style record_heartbeat calls from the same IP
        // with rotating ports (mirroring residential NAT port rotation) and
        // assert the flow table is unaffected.
        let upstream = echo_server().await;
        let peer = PeerState::new([0u8; 32]);
        let _ = peer.record_heartbeat("127.0.0.1:1000".parse().unwrap());
        let proxy = UdpProxy::spawn(
            udp_rule("invariance", upstream.port(), 60),
            dynamic_resolver(peer.clone(), upstream.port()),
        )
        .await
        .unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let _ = send_recv(&client, proxy.local_addr(), b"start").await;
        assert_eq!(proxy.active_flows(), 1);
        let upstream_sock_addr = {
            let entry = proxy.flows.get(&client.local_addr().unwrap()).unwrap();
            entry.upstream_sock.local_addr().unwrap()
        };

        // 200 same-IP heartbeats with rotating source ports.
        for port in 2000..2200u16 {
            let _ = peer.record_heartbeat(format!("127.0.0.1:{port}").parse().unwrap());
        }

        // Give the (non-)drain task a chance to NOT run.
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(
            proxy.active_flows(),
            1,
            "same-IP heartbeats must not drain the flow table"
        );

        // The flow's upstream socket is the *same socket* — not replaced.
        let now_sock_addr = {
            let entry = proxy.flows.get(&client.local_addr().unwrap()).unwrap();
            entry.upstream_sock.local_addr().unwrap()
        };
        assert_eq!(
            upstream_sock_addr, now_sock_addr,
            "upstream socket must be preserved across same-IP heartbeats"
        );

        // And the flow still works for real traffic.
        assert_eq!(send_recv(&client, proxy.local_addr(), b"end").await, b"end");

        proxy.stop().await;
    }

    #[tokio::test]
    async fn soft_cap_rejects_new_flows_when_full() {
        let upstream = echo_server().await;
        let peer = PeerState::new([0u8; 32]);
        let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());
        // cap = 2.
        let proxy = UdpProxy::spawn_with_cap(
            udp_rule("cap", upstream.port(), 60),
            dynamic_resolver(peer, upstream.port()),
            2,
        )
        .await
        .unwrap();

        let c1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let c2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let c3 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        assert_eq!(send_recv(&c1, proxy.local_addr(), b"a").await, b"a");
        assert_eq!(send_recv(&c2, proxy.local_addr(), b"b").await, b"b");
        assert_eq!(proxy.active_flows(), 2);

        // Third client should be dropped — no echo back.
        c3.send_to(b"c", proxy.local_addr()).await.unwrap();
        let mut buf = [0u8; 32];
        let res = tokio::time::timeout(Duration::from_millis(500), c3.recv_from(&mut buf)).await;
        assert!(res.is_err(), "expected drop at cap, got {res:?}");
        assert_eq!(proxy.active_flows(), 2);

        proxy.stop().await;
    }

    #[tokio::test]
    async fn stop_aborts_per_flow_tasks() {
        let upstream = echo_server().await;
        let peer = PeerState::new([0u8; 32]);
        let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());
        let proxy = UdpProxy::spawn(
            udp_rule("stop", upstream.port(), 60),
            dynamic_resolver(peer, upstream.port()),
        )
        .await
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let _ = send_recv(&client, proxy.local_addr(), b"x").await;
        assert_eq!(proxy.active_flows(), 1);

        let flows = proxy.flows.clone();
        proxy.stop().await;

        // After stop, the flow table should be empty.
        assert_eq!(flows.len(), 0);
    }
}
