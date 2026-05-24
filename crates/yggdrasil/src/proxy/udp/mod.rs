//! Per-rule UDP proxy with on-demand flow table.
//!
//! ## Architecture
//!
//! Each [`UdpProxy`] owns:
//!
//! * N frontend `UdpSocket`s bound to `rule.listen` (one per worker).
//! * N per-worker `DashMap<SocketAddr, Arc<FlowEntry>>` shards keyed by client address.
//! * Cooperating tasks (all rooted at a single `CancellationToken`):
//!   1. **Frontend workers** — `recv_from` on worker listeners, dispatching to flows.
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
//! `yggdrasil_udp_flows_rejected_total{rule,worker,reason="cap"}`. The
//! single-datagram receive buffer is 65 535 B (full IP MTU).

#[cfg(target_os = "linux")]
pub mod recvmmsg_linux;
#[cfg(target_os = "linux")]
pub mod sendmmsg_linux;

mod batch_recv;

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};
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

/// Resolve the SO_REUSEPORT worker count from the daemon-wide
/// `[server].workers` setting. `None` falls back to
/// `available_parallelism()`. Per-rule overrides are not exposed;
/// fan-out is a kernel-level concern (the kernel hash-distributes
/// incoming traffic across the workers sharing an `addr:port`), so a
/// per-rule knob would buy nothing a global default doesn't already
/// provide.
pub(crate) fn resolve_workers(server_default: Option<usize>) -> usize {
    server_default
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        })
        .max(1)
}

/// One per active `(client_addr) → (peer_ip, target_port)` flow.
struct FlowEntry {
    upstream_sock: Arc<UdpSocket>,
    /// Worker frontend socket on which this client flow first arrived.
    frontend: Arc<UdpSocket>,
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
    shards: Vec<Arc<DashMap<SocketAddr, Arc<FlowEntry>>>>,
}

impl UdpProxy {
    /// Bind frontend sockets and spawn the proxy tasks.
    ///
    /// Default workers fall back to `available_parallelism()`; flow
    /// cap is [`MAX_FLOWS_PER_RULE_DEFAULT`].
    pub async fn spawn(rule: Rule, resolver: UpstreamResolver) -> Result<Self> {
        let workers = resolve_workers(None);
        Self::spawn_with(rule, resolver, MAX_FLOWS_PER_RULE_DEFAULT, workers).await
    }

    /// Same as [`UdpProxy::spawn`] but with an explicit flow cap; intended
    /// for tests that want to exercise the soft-cap path without binding
    /// thousands of sockets.
    pub async fn spawn_with_cap(
        rule: Rule,
        resolver: UpstreamResolver,
        max_flows: usize,
    ) -> Result<Self> {
        let workers = resolve_workers(None);
        Self::spawn_with(rule, resolver, max_flows, workers).await
    }

    /// Bind frontend sockets and spawn the proxy tasks with explicit flow cap
    /// and worker count. `workers == 0` is rejected.
    ///
    /// ## Threading model
    ///
    /// Each worker runs on its own dedicated OS thread, hosting its own
    /// `tokio::runtime::Builder::new_current_thread()` runtime. The
    /// frontend `recvmmsg` loop and every per-flow `upstream_to_client`
    /// task spawned by that worker stay pinned to that thread — no
    /// cross-thread tokio task migration, no cross-worker futex
    /// notifications on the hot path. The orchestrator tasks (reaper +
    /// IP-change watcher) and everything else in the daemon continue
    /// to run on the global multi-thread runtime the daemon was
    /// started with. This mirrors nginx's per-worker event-loop shape
    /// (the udp-measure-out strace data identified cross-worker
    /// futex calls as the dominant UDP overhead).
    pub async fn spawn_with(
        rule: Rule,
        resolver: UpstreamResolver,
        max_flows: usize,
        workers: usize,
    ) -> Result<Self> {
        ensure!(workers > 0, "UDP worker count must be >= 1");

        let requested_workers = workers;
        #[cfg(unix)]
        let effective_workers = requested_workers;
        #[cfg(not(unix))]
        let effective_workers = if requested_workers > 1 {
            tracing::warn!(
                rule = %rule.name,
                requested_workers,
                "UDP SO_REUSEPORT is unavailable on this platform; using one worker"
            );
            1
        } else {
            requested_workers
        };

        // Bind the frontend sockets synchronously as `std::net::UdpSocket`s.
        // Each one is moved into its worker thread, which calls
        // `tokio::net::UdpSocket::from_std` inside its own runtime so the
        // socket is registered with that runtime's reactor (and only
        // that one). Building tokio sockets here would tie them to the
        // global runtime's reactor and defeat the per-worker pinning.
        let frontend_stds = build_frontend_std_sockets(rule.listen, effective_workers)
            .with_context(|| {
                format!(
                    "bind {effective_workers} UDP frontend worker(s) for rule {:?} on {}",
                    rule.name, rule.listen
                )
            })?;
        let local_addr = frontend_stds
            .first()
            .context("no UDP frontend sockets built")?
            .local_addr()
            .context("read UdpSocket local_addr")?;

        let cancel = CancellationToken::new();
        let shards: Vec<Arc<DashMap<SocketAddr, Arc<FlowEntry>>>> = (0..effective_workers)
            .map(|_| Arc::new(DashMap::new()))
            .collect();
        let flow_count = Arc::new(AtomicUsize::new(0));
        let start = Instant::now();
        let idle_timeout = rule.resolved_idle_timeout();

        // Spawn one OS thread per worker. Each thread builds a
        // `current_thread` tokio runtime, registers its frontend socket
        // with that runtime, and runs the worker's frontend loop —
        // which in turn spawns one per-flow upstream task per active
        // flow, all on the same single-threaded runtime.
        let mut worker_threads = Vec::with_capacity(effective_workers);
        for (worker_id, std_sock) in frontend_stds.into_iter().enumerate() {
            let cancel_t = cancel.clone();
            let rule_t = rule.clone();
            let resolver_t = resolver.clone();
            let shard_t = Arc::clone(&shards[worker_id]);
            let flow_count_t = Arc::clone(&flow_count);
            let max_flows_t = max_flows;
            let thread_name = format!("ygg-udp-{}-{}", rule.name, worker_id);
            let handle = std::thread::Builder::new()
                .name(thread_name)
                .spawn(move || {
                    let rt = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(rt) => rt,
                        Err(e) => {
                            tracing::error!(
                                rule = %rule_t.name,
                                worker_id,
                                error = %e,
                                "UDP worker: failed to build current_thread runtime; worker exiting"
                            );
                            return;
                        }
                    };
                    rt.block_on(async move {
                        let frontend = match UdpSocket::from_std(std_sock) {
                            Ok(s) => Arc::new(s),
                            Err(e) => {
                                tracing::error!(
                                    rule = %rule_t.name,
                                    worker_id,
                                    error = %e,
                                    "UDP worker: UdpSocket::from_std failed; worker exiting"
                                );
                                return;
                            }
                        };
                        let worker = UdpWorker {
                            worker_id,
                            frontend,
                            rule: rule_t,
                            resolver: resolver_t,
                            flows: shard_t,
                            flow_count: flow_count_t,
                            cancel: cancel_t,
                            start,
                            max_flows: max_flows_t,
                        };
                        worker.frontend_loop().await;
                    });
                })
                .context("spawn UDP worker OS thread")?;
            worker_threads.push(handle);
        }

        let inner = UdpProxyInner {
            rule: rule.clone(),
            resolver: resolver.clone(),
            shards: shards.clone(),
            flow_count: Arc::clone(&flow_count),
            cancel: cancel.clone(),
            start,
            max_flows,
            idle_timeout,
        };

        let main_handle = tokio::spawn(inner.run(worker_threads));

        metrics::gauge!(
            "yggdrasil_workers",
            "rule" => rule.name.clone(),
            "protocol" => "udp",
        )
        .set(effective_workers as f64);
        for worker_id in 0..effective_workers {
            set_udp_active_flows(&rule.name, worker_id, 0);
        }
        tracing::info!(
            rule = %rule.name,
            listen = %local_addr,
            upstream = %resolver.describe(),
            idle_timeout_secs = idle_timeout.as_secs(),
            max_flows,
            workers = effective_workers,
            "UDP rule listening"
        );

        Ok(Self {
            rule,
            cancel,
            local_addr,
            main_handle,
            shards,
        })
    }

    pub fn rule(&self) -> &Rule {
        &self.rule
    }

    /// All worker sockets share this local address; return the first worker's address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Currently-tracked flow count (snapshot; may change immediately).
    pub fn active_flows(&self) -> usize {
        self.shards.iter().map(|shard| shard.len()).sum()
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = self.main_handle.await;
    }
}

/// Synchronously bind `workers` UDP frontend sockets on `addr`, returning
/// them as plain `std::net::UdpSocket`s. Each socket has `SO_REUSEADDR`,
/// `SO_REUSEPORT` (Unix), and `SO_BUSY_POLL` (Linux best-effort) set; the
/// caller is responsible for converting them into tokio `UdpSocket`s on
/// the appropriate per-worker runtime.
///
/// We use the std type rather than tokio's because each socket needs to
/// be registered with the **worker's** runtime reactor (not the global
/// daemon runtime). Tokio's `UdpSocket::bind` would tie the socket to
/// whichever runtime called this function — defeating the per-worker
/// pinning the spawn path is built around.
fn build_frontend_std_sockets(
    addr: SocketAddr,
    workers: usize,
) -> std::io::Result<Vec<std::net::UdpSocket>> {
    debug_assert!(workers > 0);

    let mut sockets = Vec::with_capacity(workers);
    let first = build_frontend_std_socket(addr)?;
    let bind_addr = first.local_addr()?;
    sockets.push(first);
    for _ in 1..workers {
        sockets.push(build_frontend_std_socket(bind_addr)?);
    }
    Ok(sockets)
}

fn build_frontend_std_socket(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = Domain::for_address(addr);
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    Ok(sock.into())
}

fn increment_udp_datagrams_received(rule: &str, worker_id: usize, count: usize) {
    metrics::counter!(
        "yggdrasil_udp_datagrams_received_total",
        "rule" => rule.to_owned(),
        "worker" => worker_id.to_string(),
    )
    .increment(count as u64);
}

fn increment_udp_bytes(rule: &str, worker_id: usize, direction: &'static str, count: usize) {
    metrics::counter!(
        "yggdrasil_udp_bytes_total",
        "rule" => rule.to_owned(),
        "worker" => worker_id.to_string(),
        "direction" => direction,
    )
    .increment(count as u64);
}

fn increment_udp_flows_admitted(rule: &str, worker_id: usize) {
    metrics::counter!(
        "yggdrasil_udp_flows_admitted_total",
        "rule" => rule.to_owned(),
        "worker" => worker_id.to_string(),
    )
    .increment(1);
}

fn increment_udp_send_errors(rule: &str, worker_id: usize, direction: &'static str) {
    metrics::counter!(
        "yggdrasil_udp_send_errors_total",
        "rule" => rule.to_owned(),
        "worker" => worker_id.to_string(),
        "direction" => direction,
    )
    .increment(1);
}

fn increment_udp_dropped_no_peer(rule: &str, worker_id: usize) {
    metrics::counter!(
        "yggdrasil_udp_dropped_no_peer_total",
        "rule" => rule.to_owned(),
        "worker" => worker_id.to_string(),
    )
    .increment(1);
}

fn record_udp_upstream_bind_seconds(rule: &str, result: &'static str, secs: f64) {
    metrics::histogram!(
        "yggdrasil_udp_upstream_bind_seconds",
        "rule" => rule.to_owned(),
        "result" => result,
    )
    .record(secs);
}

fn increment_udp_flows_rejected(rule: &str, worker_id: usize, reason: &'static str) {
    metrics::counter!(
        "yggdrasil_udp_flows_rejected_total",
        "rule" => rule.to_owned(),
        "worker" => worker_id.to_string(),
        "reason" => reason,
    )
    .increment(1);
}

fn increment_udp_flows_drained(rule: &str, worker_id: usize, count: usize) {
    metrics::counter!(
        "yggdrasil_udp_flows_drained_on_ip_change_total",
        "rule" => rule.to_owned(),
        "worker" => worker_id.to_string(),
    )
    .increment(count as u64);
}

fn set_udp_active_flows(rule: &str, worker_id: usize, active: usize) {
    metrics::gauge!(
        "yggdrasil_udp_active_flows",
        "rule" => rule.to_owned(),
        "worker" => worker_id.to_string(),
    )
    .set(active as f64);
}

struct UdpProxyInner {
    rule: Rule,
    resolver: UpstreamResolver,
    shards: Vec<Arc<DashMap<SocketAddr, Arc<FlowEntry>>>>,
    flow_count: Arc<AtomicUsize>,
    cancel: CancellationToken,
    start: Instant,
    max_flows: usize,
    idle_timeout: Duration,
}

struct UdpWorker {
    worker_id: usize,
    frontend: Arc<UdpSocket>,
    rule: Rule,
    resolver: UpstreamResolver,
    flows: Arc<DashMap<SocketAddr, Arc<FlowEntry>>>,
    flow_count: Arc<AtomicUsize>,
    cancel: CancellationToken,
    start: Instant,
    max_flows: usize,
}

struct FlowAccounting {
    worker_id: usize,
    flow_count: Arc<AtomicUsize>,
    start: Instant,
}

impl UdpProxyInner {
    /// Orchestrate the proxy's non-worker tasks (reaper + IP-change
    /// watcher) on the daemon's global runtime, and wait for the
    /// per-worker OS threads to join. Cancellation is propagated
    /// through `self.cancel`, which every worker thread observes.
    async fn run(self, worker_threads: Vec<std::thread::JoinHandle<()>>) {
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

        // Per-worker OS threads exit when `self.cancel` is fired. We
        // wait for them via `spawn_blocking` so we don't block a
        // multi-thread runtime worker on `JoinHandle::join`.
        let worker_joins: Vec<_> = worker_threads
            .into_iter()
            .map(|h| tokio::task::spawn_blocking(move || h.join()))
            .collect();
        let _ = futures::future::join_all(worker_joins).await;

        // Cancellation propagates to all spawned tasks via the shared
        // token. Wait for them to wind down before returning.
        match ipchange_task {
            Some(ipc) => {
                let _ = tokio::join!(reaper_task, ipc);
            }
            None => {
                let _ = reaper_task.await;
            }
        }

        // Final flow-table cleanup: aborts any straggler upstream tasks.
        for shard in &self.shards {
            for entry in shard.iter() {
                entry.value().upstream_task.abort();
            }
            shard.clear();
        }
        for (worker_id, shard) in self.shards.iter().enumerate() {
            set_udp_active_flows(&self.rule.name, worker_id, shard.len());
        }
        self.flow_count.store(0, Ordering::Release);
        tracing::debug!(rule = %self.rule.name, "UDP proxy shutdown complete");
    }

    fn clone_ctx(&self) -> Self {
        Self {
            rule: self.rule.clone(),
            resolver: self.resolver.clone(),
            shards: self.shards.clone(),
            flow_count: Arc::clone(&self.flow_count),
            cancel: self.cancel.clone(),
            start: self.start,
            max_flows: self.max_flows,
            idle_timeout: self.idle_timeout,
        }
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

impl UdpWorker {
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn try_reserve_flow(&self) -> bool {
        let mut current = self.flow_count.load(Ordering::Relaxed);
        loop {
            if current >= self.max_flows {
                return false;
            }
            match self.flow_count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(next) => current = next,
            }
        }
    }

    async fn frontend_loop(self) {
        let mut recv = batch_recv::BatchRecv::new(Arc::clone(&self.frontend));
        let mut scratch = batch_recv::BatchScratch::new();
        loop {
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => {
                    tracing::debug!(
                        rule = %self.rule.name,
                        worker_id = self.worker_id,
                        "UDP frontend loop received cancel"
                    );
                    return;
                }
                res = recv.recv(&mut scratch) => {
                    let n = match res {
                        Ok(n) => n,
                        Err(e) => {
                            tracing::warn!(
                                rule = %self.rule.name,
                                worker_id = self.worker_id,
                                error = %e,
                                "UDP batch recv failed"
                            );
                            continue;
                        }
                    };
                    increment_udp_datagrams_received(&self.rule.name, self.worker_id, n);
                    let owned: Vec<(Vec<u8>, SocketAddr)> = recv
                        .iter(&scratch, n)
                        .map(|d| (d.payload.to_vec(), d.from))
                        .collect();
                    for (payload, client_addr) in owned {
                        self.handle_inbound(&payload, client_addr).await;
                    }
                }
            }
        }
    }

    async fn handle_inbound(&self, payload: &[u8], client_addr: SocketAddr) {
        // Fast path: existing flow.
        if let Some(entry) = self.flows.get(&client_addr) {
            entry.last_seen_ms.store(self.now_ms(), Ordering::Relaxed);
            match entry.upstream_sock.send(payload).await {
                Ok(_) => {
                    increment_udp_bytes(
                        &self.rule.name,
                        self.worker_id,
                        "client_to_upstream",
                        payload.len(),
                    );
                }
                Err(e) => {
                    increment_udp_send_errors(
                        &self.rule.name,
                        self.worker_id,
                        "client_to_upstream",
                    );
                    tracing::debug!(
                        rule = %self.rule.name,
                        client = %client_addr,
                        error = %e,
                        "upstream send failed; flow may be stale (will be reaped)"
                    );
                }
            }
            return;
        }

        // No flow yet. Need a resolved dial target and capacity.
        let Some(target_addr) = self.resolver.current_target() else {
            increment_udp_dropped_no_peer(&self.rule.name, self.worker_id);
            tracing::debug!(
                rule = %self.rule.name,
                client = %client_addr,
                "drop UDP datagram: upstream not yet resolvable (no heartbeat received)"
            );
            return;
        };

        if self.flow_count.load(Ordering::Relaxed) >= self.max_flows {
            tracing::warn!(
                rule = %self.rule.name,
                client = %client_addr,
                cap = self.max_flows,
                "drop UDP datagram: flow table at cap"
            );
            increment_udp_flows_rejected(&self.rule.name, self.worker_id, "cap");
            return;
        }

        let entry = match self.create_flow(client_addr, target_addr).await {
            Some(e) => e,
            None => return,
        };

        match entry.upstream_sock.send(payload).await {
            Ok(_) => {
                increment_udp_bytes(
                    &self.rule.name,
                    self.worker_id,
                    "client_to_upstream",
                    payload.len(),
                );
            }
            Err(e) => {
                increment_udp_send_errors(&self.rule.name, self.worker_id, "client_to_upstream");
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
        let bind_start = Instant::now();
        let sock = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(e) => {
                record_udp_upstream_bind_seconds(
                    &self.rule.name,
                    "error",
                    bind_start.elapsed().as_secs_f64(),
                );
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
            record_udp_upstream_bind_seconds(
                &self.rule.name,
                "error",
                bind_start.elapsed().as_secs_f64(),
            );
            tracing::warn!(
                rule = %self.rule.name,
                client = %client_addr,
                upstream = %target_addr,
                error = %e,
                "connect upstream UDP socket failed"
            );
            return None;
        }
        record_udp_upstream_bind_seconds(&self.rule.name, "ok", bind_start.elapsed().as_secs_f64());
        let upstream_sock = Arc::new(sock);

        // Per-flow upstream→client task.
        let task_us = upstream_sock.clone();
        let task_frontend = self.frontend.clone();
        // Use a plain `Arc` clone (= one atomic increment) rather than a
        // child token (= linked-list bookkeeping in the parent registry
        // + a drop hook per flow). Nothing cancels an individual flow
        // independently of the worker, so the child-token semantics are
        // unused — they're pure per-flow overhead.
        let task_cancel = self.cancel.clone();
        let task_rule_name = self.rule.name.clone();
        let task_shard = Arc::clone(&self.flows);
        let task_accounting = FlowAccounting {
            worker_id: self.worker_id,
            flow_count: Arc::clone(&self.flow_count),
            start: self.start,
        };
        let task_client = client_addr;
        // The JoinHandle is dropped at end of statement (detaches the task);
        // we keep the AbortHandle for cancellation via the flow table.
        let upstream_handle = tokio::spawn(async move {
            upstream_to_client_loop(
                task_rule_name,
                task_us,
                task_frontend,
                task_client,
                task_cancel,
                task_shard,
                task_accounting,
            )
            .await;
        })
        .abort_handle();

        let entry = Arc::new(FlowEntry {
            upstream_sock,
            frontend: self.frontend.clone(),
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
                if !self.try_reserve_flow() {
                    entry.upstream_task.abort();
                    return None;
                }
                tracing::debug!(
                    rule = %self.rule.name,
                    worker_id = self.worker_id,
                    client = %client_addr,
                    upstream = %target_addr,
                    "new UDP flow"
                );
                v.insert(entry.clone());
                increment_udp_flows_admitted(&self.rule.name, self.worker_id);
                set_udp_active_flows(&self.rule.name, self.worker_id, self.flows.len());
                Some(entry)
            }
        }
    }
}

impl UdpProxyInner {
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
        for (worker_id, shard) in self.shards.iter().enumerate() {
            let mut victims = Vec::new();
            for entry in shard.iter() {
                let last = entry.value().last_seen_ms.load(Ordering::Relaxed);
                if now_ms.saturating_sub(last) >= idle_ms {
                    victims.push(*entry.key());
                }
            }
            let mut reaped = 0;
            for client in victims {
                if let Some((_, entry)) = shard.remove(&client) {
                    self.flow_count.fetch_sub(1, Ordering::AcqRel);
                    entry.upstream_task.abort();
                    reaped += 1;
                    tracing::debug!(
                        rule = %self.rule.name,
                        worker_id,
                        client = %client,
                        "reaped idle UDP flow"
                    );
                }
            }
            if reaped > 0 {
                set_udp_active_flows(&self.rule.name, worker_id, shard.len());
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
        let mut total = 0;
        for (worker_id, shard) in self.shards.iter().enumerate() {
            let mut drained = 0;
            shard.retain(|_, entry| {
                entry.upstream_task.abort();
                drained += 1;
                false
            });
            if drained > 0 {
                self.flow_count.fetch_sub(drained, Ordering::AcqRel);
                increment_udp_flows_drained(&self.rule.name, worker_id, drained);
            }
            set_udp_active_flows(&self.rule.name, worker_id, shard.len());
            total += drained;
        }
        tracing::info!(
            rule = %self.rule.name,
            new_peer_ip = ?new_ip,
            flows_drained = total,
            "peer IP changed; drained UDP flow table across all shards"
        );
    }
}

async fn upstream_to_client_loop(
    rule_name: String,
    upstream: Arc<UdpSocket>,
    frontend: Arc<UdpSocket>,
    client_addr: SocketAddr,
    cancel: CancellationToken,
    shard: Arc<DashMap<SocketAddr, Arc<FlowEntry>>>,
    accounting: FlowAccounting,
) {
    // Try the batched path first. On Linux + a healthy `recvmmsg` syscall
    // (default on modern kernels) we drain up to `UPSTREAM_BATCH` datagrams
    // per wake-up. On non-Linux, on ENOSYS / EPERM (kernel too old or
    // seccomp-filtered), or when the AsyncFd registration fails, we fall
    // through to the single-recv path that matches the pre-batching
    // behaviour byte-for-byte.
    #[cfg(target_os = "linux")]
    {
        use recvmmsg_linux::{BatchBuf, BatchReader};
        use sendmmsg_linux::BatchSender;
        const UPSTREAM_BATCH: usize = 16;

        match BatchReader::from_udp_socket(&upstream) {
            Ok(reader) => {
                let mut buf = BatchBuf::new(UPSTREAM_BATCH);
                // The frontend BatchSender is best-effort: if it can't
                // register (e.g. seccomp policy on AsyncFd), we keep
                // the receive batching and fall back to per-datagram
                // `send_to` on the send side.
                let sender = match BatchSender::from_udp_socket(&frontend) {
                    Ok(s) => Some(s),
                    Err(e) => {
                        tracing::debug!(
                            rule = %rule_name,
                            client = %client_addr,
                            error = %e,
                            "sendmmsg unavailable; using per-datagram send_to on frontend"
                        );
                        None
                    }
                };
                upstream_to_client_loop_batched(
                    &rule_name,
                    &frontend,
                    client_addr,
                    cancel,
                    &shard,
                    &accounting,
                    reader,
                    &mut buf,
                    sender.as_ref(),
                )
                .await;
                return;
            }
            Err(e) => {
                // One-time fallback to per-datagram recv. Most likely
                // cause is a seccomp policy or an unusually old kernel.
                tracing::debug!(
                    rule = %rule_name,
                    client = %client_addr,
                    error = %e,
                    "recvmmsg unavailable; falling back to per-datagram recv on upstream"
                );
            }
        }
    }

    upstream_to_client_loop_single(
        rule_name,
        upstream,
        frontend,
        client_addr,
        cancel,
        shard,
        accounting,
    )
    .await;
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
async fn upstream_to_client_loop_batched(
    rule_name: &str,
    frontend: &UdpSocket,
    client_addr: SocketAddr,
    cancel: CancellationToken,
    shard: &DashMap<SocketAddr, Arc<FlowEntry>>,
    accounting: &FlowAccounting,
    reader: recvmmsg_linux::BatchReader,
    buf: &mut recvmmsg_linux::BatchBuf,
    sender: Option<&sendmmsg_linux::BatchSender>,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            res = reader.recv_batch(buf) => {
                let n = match res {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::debug!(
                            rule = %rule_name,
                            client = %client_addr,
                            error = %e,
                            "upstream recvmmsg failed; flow ending"
                        );
                        if shard.remove(&client_addr).is_some() {
                            accounting.flow_count.fetch_sub(1, Ordering::AcqRel);
                            set_udp_active_flows(rule_name, accounting.worker_id, shard.len());
                        }
                        return;
                    }
                };
                if n == 0 {
                    continue;
                }
                upstream_batch_forward(
                    rule_name,
                    frontend,
                    client_addr,
                    shard,
                    accounting,
                    buf,
                    n,
                    sender,
                )
                .await;
            }
        }
    }
}

/// Shared body of [`upstream_to_client_loop_batched`]'s fast and slow
/// recv paths: take `n` datagrams sitting in `buf`, forward them to
/// `client_addr` via `sendmmsg` (or `send_to` fallback), update
/// per-direction byte counters, and refresh `last_seen_ms`.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
async fn upstream_batch_forward(
    rule_name: &str,
    frontend: &UdpSocket,
    client_addr: SocketAddr,
    shard: &DashMap<SocketAddr, Arc<FlowEntry>>,
    accounting: &FlowAccounting,
    buf: &recvmmsg_linux::BatchBuf,
    n: usize,
    sender: Option<&sendmmsg_linux::BatchSender>,
) {
    // Pick the send socket once per batch. The same flow's
    // frontend never changes mid-batch, so this is correct.
    // Fallback to the caller-provided `frontend` when the
    // flow has been concurrently removed (rare; we'll exit
    // next iteration via the cancel arm).
    let frontend_arc = shard.get(&client_addr).map(|entry| entry.frontend.clone());
    let send_target: &UdpSocket = frontend_arc.as_deref().unwrap_or(frontend);

    // Try sendmmsg first when available. The caller wires
    // the BatchSender to the per-rule frontend socket; if
    // the flow's `frontend_arc` differs (which would only
    // happen across rule reloads — currently rare), we
    // fall through to per-datagram `send_to`.
    let mut total_bytes = 0usize;
    let mut send_errs = 0usize;
    let used_sendmmsg = if let Some(sender) = sender {
        if std::ptr::eq(send_target, frontend) {
            // Collect payload slices for the batch send.
            let dgrams: Vec<recvmmsg_linux::Datagram<'_>> =
                recvmmsg_linux::iter_received(buf, n).collect();
            let payloads: Vec<&[u8]> = dgrams.iter().map(|d| d.payload).collect();
            match sender.send_batch(&payloads, client_addr).await {
                Ok(sent) => {
                    for d in &dgrams[..sent] {
                        total_bytes += d.payload.len();
                    }
                    // Any unsent tail: fall through to
                    // per-datagram for those (rare under
                    // healthy buffer pressure).
                    for d in &dgrams[sent..] {
                        match send_target.send_to(d.payload, client_addr).await {
                            Ok(_) => total_bytes += d.payload.len(),
                            Err(_) => send_errs += 1,
                        }
                    }
                    true
                }
                Err(e) => {
                    tracing::debug!(
                        rule = %rule_name,
                        client = %client_addr,
                        error = %e,
                        "sendmmsg batch failed; falling back to per-datagram for this batch"
                    );
                    false
                }
            }
        } else {
            false
        }
    } else {
        false
    };

    if !used_sendmmsg {
        for dgram in recvmmsg_linux::iter_received(buf, n) {
            match send_target.send_to(dgram.payload, client_addr).await {
                Ok(_) => total_bytes += dgram.payload.len(),
                Err(e) => {
                    send_errs += 1;
                    tracing::debug!(
                        rule = %rule_name,
                        client = %client_addr,
                        error = %e,
                        "frontend send_to client failed"
                    );
                }
            }
        }
    }

    if total_bytes > 0 {
        increment_udp_bytes(
            rule_name,
            accounting.worker_id,
            "upstream_to_client",
            total_bytes,
        );
    }
    for _ in 0..send_errs {
        increment_udp_send_errors(rule_name, accounting.worker_id, "upstream_to_client");
    }

    // Touch last_seen once per batch (not per datagram) —
    // the batch is small enough that the in-batch tail
    // bias is negligible, and the savings are real on
    // flows with many datagrams per wake-up.
    if let Some(entry) = shard.get(&client_addr) {
        let now_ms = accounting.start.elapsed().as_millis() as u64;
        entry.last_seen_ms.store(now_ms, Ordering::Relaxed);
    }
}

async fn upstream_to_client_loop_single(
    rule_name: String,
    upstream: Arc<UdpSocket>,
    frontend: Arc<UdpSocket>,
    client_addr: SocketAddr,
    cancel: CancellationToken,
    shard: Arc<DashMap<SocketAddr, Arc<FlowEntry>>>,
    accounting: FlowAccounting,
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
                        if shard.remove(&client_addr).is_some() {
                            accounting.flow_count.fetch_sub(1, Ordering::AcqRel);
                            set_udp_active_flows(&rule_name, accounting.worker_id, shard.len());
                        }
                        return;
                    }
                };
                let send_frontend = shard
                    .get(&client_addr)
                    .map(|entry| entry.frontend.clone())
                    .unwrap_or_else(|| frontend.clone());
                match send_frontend.send_to(&buf[..n], client_addr).await {
                    Ok(_) => {
                        increment_udp_bytes(
                            &rule_name,
                            accounting.worker_id,
                            "upstream_to_client",
                            n,
                        );
                    }
                    Err(e) => {
                        increment_udp_send_errors(
                            &rule_name,
                            accounting.worker_id,
                            "upstream_to_client",
                        );
                        tracing::debug!(
                            rule = %rule_name,
                            client = %client_addr,
                            error = %e,
                            "frontend send_to client failed"
                        );
                        continue;
                    }
                }
                // Touch last_seen for the return-traffic direction too.
                if let Some(entry) = shard.get(&client_addr) {
                    let now_ms = accounting.start.elapsed().as_millis() as u64;
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

    fn static_resolver(addr: SocketAddr) -> UpstreamResolver {
        UpstreamResolver::Static { addr }
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

    async fn wait_for_active_flows(proxy: &UdpProxy, expected: usize) {
        for _ in 0..100 {
            if proxy.active_flows() == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(proxy.active_flows(), expected);
    }

    async fn assert_recv_timeout(client: &UdpSocket, timeout: Duration) {
        let mut buf = [0u8; 2048];
        let res = tokio::time::timeout(timeout, client.recv_from(&mut buf)).await;
        assert!(res.is_err(), "expected timeout, got {res:?}");
    }

    fn flow_for(proxy: &UdpProxy, client_addr: SocketAddr) -> Arc<FlowEntry> {
        proxy
            .shards
            .iter()
            .find_map(|shard| {
                shard
                    .get(&client_addr)
                    .map(|entry| Arc::clone(entry.value()))
            })
            .unwrap()
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
    async fn multi_worker_echoes_all_clients() {
        let upstream = echo_server().await;
        let peer = PeerState::new([0u8; 32]);
        let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());
        let proxy = UdpProxy::spawn_with(
            udp_rule("multi-worker", upstream.port(), 60),
            dynamic_resolver(peer, upstream.port()),
            MAX_FLOWS_PER_RULE_DEFAULT,
            4,
        )
        .await
        .unwrap();

        let mut handles = Vec::new();
        for i in 0..32u8 {
            let addr = proxy.local_addr();
            handles.push(tokio::spawn(async move {
                let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let msg = vec![i, i, i];
                client.send_to(&msg, addr).await.unwrap();
                let mut buf = vec![0u8; 16];
                let (n, _) =
                    tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
                        .await
                        .unwrap()
                        .unwrap();
                buf.truncate(n);
                buf
            }));
        }
        for (i, h) in handles.into_iter().enumerate() {
            let got = h.await.unwrap();
            assert_eq!(got, vec![i as u8, i as u8, i as u8]);
        }
        proxy.stop().await;
    }

    #[tokio::test]
    async fn worker_count_smoke_echoes_distinct_clients() {
        for workers in [1usize, 2, 4, 8] {
            let upstream = echo_server().await;
            let peer = PeerState::new([0u8; 32]);
            let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());
            let proxy = UdpProxy::spawn_with(
                udp_rule(&format!("worker-smoke-{workers}"), upstream.port(), 60),
                dynamic_resolver(peer, upstream.port()),
                MAX_FLOWS_PER_RULE_DEFAULT,
                workers,
            )
            .await
            .unwrap();

            let clients = 4 * workers;
            let mut keepalive = Vec::with_capacity(clients);
            for i in 0..clients {
                let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let msg = format!("workers={workers};client={i}").into_bytes();
                assert_eq!(send_recv(&client, proxy.local_addr(), &msg).await, msg);
                keepalive.push(client);
            }
            wait_for_active_flows(&proxy, clients).await;
            proxy.stop().await;
        }
    }

    #[tokio::test]
    async fn spawn_with_rejects_zero_workers() {
        let upstream = echo_server().await;
        let peer = PeerState::new([0u8; 32]);
        let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());
        let result = UdpProxy::spawn_with(
            udp_rule("zero-workers", upstream.port(), 60),
            dynamic_resolver(peer, upstream.port()),
            MAX_FLOWS_PER_RULE_DEFAULT,
            0,
        )
        .await;

        match result {
            Ok(proxy) => {
                proxy.stop().await;
                panic!("workers = 0 should be rejected");
            }
            Err(err) => assert!(
                err.to_string().contains("worker count"),
                "unexpected error: {err:#}"
            ),
        }
    }

    #[tokio::test]
    async fn shards_are_isolated_per_worker() {
        let upstream = echo_server().await;
        let peer = PeerState::new([0u8; 32]);
        let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());
        let proxy = UdpProxy::spawn_with(
            udp_rule("shards", upstream.port(), 60),
            dynamic_resolver(peer, upstream.port()),
            MAX_FLOWS_PER_RULE_DEFAULT,
            4,
        )
        .await
        .unwrap();

        // Send 32 datagrams from 32 different ephemeral source ports.
        let mut clients = Vec::new();
        for _ in 0..32 {
            let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            c.send_to(b"x", proxy.local_addr()).await.unwrap();
            clients.push(c);
        }
        for _ in 0..20 {
            if proxy.active_flows() == 32 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(proxy.active_flows(), 32);

        #[cfg(unix)]
        {
            let shard_sizes: Vec<_> = proxy.shards.iter().map(|shard| shard.len()).collect();
            let non_empty = shard_sizes.iter().filter(|&&size| size > 0).count();
            assert!(
                non_empty > 1,
                "expected flows in more than one shard, shard sizes: {shard_sizes:?}"
            );
        }

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
        client.send_to(b"silent", proxy.local_addr()).await.unwrap();
        assert_recv_timeout(&client, Duration::from_millis(500)).await;
        assert_eq!(proxy.active_flows(), 0);

        proxy.stop().await;
    }

    #[tokio::test]
    async fn static_resolver_closed_port_does_not_panic() {
        let closed_addr = {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            sock.local_addr().unwrap()
        };
        let proxy = UdpProxy::spawn(
            udp_rule("static-closed", closed_addr.port(), 60),
            static_resolver(closed_addr),
        )
        .await
        .unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"closed", proxy.local_addr()).await.unwrap();
        for _ in 0..20 {
            if proxy.active_flows() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_recv_timeout(&client, Duration::from_millis(250)).await;
        assert!(
            proxy.active_flows() <= 1,
            "closed static target should not create duplicate flows"
        );

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
        let proxy = UdpProxy::spawn(rule, dynamic_resolver(peer, upstream.port()))
            .await
            .unwrap();

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
    async fn reaper_evicts_idle_flows_across_all_shards() {
        let upstream = echo_server().await;
        let peer = PeerState::new([0u8; 32]);
        let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());
        let rule = {
            let mut r = udp_rule("idle-shards", upstream.port(), 1);
            r.idle_timeout = Some(Duration::from_millis(200));
            r
        };
        let proxy = UdpProxy::spawn_with(
            rule,
            dynamic_resolver(peer, upstream.port()),
            MAX_FLOWS_PER_RULE_DEFAULT,
            4,
        )
        .await
        .unwrap();

        let clients = 32;
        let mut keepalive = Vec::with_capacity(clients);
        for _ in 0..clients {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client.send_to(b"idle", proxy.local_addr()).await.unwrap();
            keepalive.push(client);
        }
        wait_for_active_flows(&proxy, clients).await;
        let initial_shard_sizes: Vec<_> = proxy.shards.iter().map(|shard| shard.len()).collect();
        #[cfg(unix)]
        assert!(
            initial_shard_sizes.iter().all(|&len| len > 0),
            "expected every shard to receive at least one flow: {initial_shard_sizes:?}"
        );

        tokio::time::sleep(Duration::from_millis(700)).await;
        assert!(
            proxy.shards.iter().all(|shard| shard.is_empty()),
            "all shards should be empty after idle reap"
        );
        assert_eq!(proxy.active_flows(), 0);

        proxy.stop().await;
    }

    #[tokio::test]
    async fn return_traffic_updates_last_seen() {
        let upstream_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let upstream = upstream_sock.local_addr().unwrap();
        let (received_tx, received_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (n, from) = upstream_sock.recv_from(&mut buf).await.unwrap();
            let _ = received_tx.send(());
            let _ = release_rx.await;
            let _ = upstream_sock.send_to(&buf[..n], from).await;
        });

        let peer = PeerState::new([0u8; 32]);
        let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());
        let proxy = UdpProxy::spawn(
            udp_rule("return-touch", upstream.port(), 60),
            dynamic_resolver(peer, upstream.port()),
        )
        .await
        .unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"touch", proxy.local_addr()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), received_rx)
            .await
            .expect("upstream did not receive request")
            .unwrap();
        wait_for_active_flows(&proxy, 1).await;

        let entry = flow_for(&proxy, client.local_addr().unwrap());
        let before_return = entry.last_seen_ms.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(20)).await;
        release_tx.send(()).unwrap();

        let mut buf = vec![0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("recv timed out")
            .unwrap();
        assert_eq!(&buf[..n], b"touch");

        for _ in 0..50 {
            if entry.last_seen_ms.load(Ordering::Relaxed) > before_return {
                proxy.stop().await;
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("return traffic did not advance last_seen_ms");
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
    async fn ip_change_drains_all_shards() {
        let upstream = echo_server().await;
        let peer = PeerState::new([0u8; 32]);
        let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());
        let proxy = UdpProxy::spawn_with(
            udp_rule("drain-all", upstream.port(), 60),
            dynamic_resolver(peer.clone(), upstream.port()),
            MAX_FLOWS_PER_RULE_DEFAULT,
            4,
        )
        .await
        .unwrap();

        let mut clients = Vec::new();
        for _ in 0..16 {
            let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            c.send_to(b"x", proxy.local_addr()).await.unwrap();
            clients.push(c);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(proxy.active_flows() >= 1, "flows should be established");

        let _ = peer.record_heartbeat("198.51.100.1:1".parse().unwrap());
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert_eq!(proxy.active_flows(), 0, "all shards should be drained");
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
        let client_addr = client.local_addr().unwrap();
        let upstream_sock_addr = flow_for(&proxy, client_addr)
            .upstream_sock
            .local_addr()
            .unwrap();

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
        let now_sock_addr = flow_for(&proxy, client_addr)
            .upstream_sock
            .local_addr()
            .unwrap();
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
        assert_recv_timeout(&c3, Duration::from_millis(500)).await;
        assert_eq!(proxy.active_flows(), 2);

        proxy.stop().await;
    }

    #[tokio::test]
    async fn multi_worker_soft_cap_rejects_new_flows_when_full() {
        let upstream = echo_server().await;
        let peer = PeerState::new([0u8; 32]);
        let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());
        let proxy = UdpProxy::spawn_with(
            udp_rule("cap-multi-worker", upstream.port(), 60),
            dynamic_resolver(peer, upstream.port()),
            4,
            4,
        )
        .await
        .unwrap();

        let mut accepted = Vec::new();
        for i in 0..4u8 {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            assert_eq!(send_recv(&client, proxy.local_addr(), &[i]).await, vec![i]);
            accepted.push(client);
        }
        assert_eq!(proxy.active_flows(), 4);

        let mut rejected = Vec::new();
        for i in 4..8u8 {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client.send_to(&[i], proxy.local_addr()).await.unwrap();
            rejected.push(client);
        }
        for client in &rejected {
            assert_recv_timeout(client, Duration::from_millis(500)).await;
        }
        assert_eq!(
            proxy.active_flows(),
            4,
            "global flow cap should stay saturated after rejected clients"
        );

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

        let shards = proxy.shards.clone();
        proxy.stop().await;

        // After stop, all flow-table shards should be empty.
        assert_eq!(shards.iter().map(|shard| shard.len()).sum::<usize>(), 0);
    }
}
