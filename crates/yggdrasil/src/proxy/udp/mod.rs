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

use ratatoskr::canary::CANARY_TOKEN_LEN;
use ratatoskr::rule::{Protocol, ProxyProto, Rule};

use super::canary::CanaryArmTable;
use super::proxy_protocol;
use super::resolver::{UpstreamResolver, WatchHandle};

/// Default cap on concurrent client flows per UDP rule. Sized to cover any
/// realistic residential workload while bounding FD / memory cost.
pub const MAX_FLOWS_PER_RULE_DEFAULT: usize = 65_536;

/// Maximum UDP payload we'll read from the frontend socket. Equal to the
/// largest possible IP datagram payload; jumbo / fragmented packets that
/// arrive intact will not be truncated by us.
const RECV_BUFFER_LEN: usize = 65_535;

/// TTL on pending real-client entries stashed by `handle_inbound` after
/// decoding a PROXY-v2 first-datagram. The follow-up application
/// datagram should arrive within a few milliseconds on a healthy chain
/// (PROXY and Initial are sent back-to-back on the same connected
/// upstream socket); 5 s is generous slack that still bounds the worst
/// case where the application datagram never arrives at all.
const PENDING_PROXY_TTL: Duration = Duration::from_secs(5);

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
    /// cap is [`MAX_FLOWS_PER_RULE_DEFAULT`]; inbound PROXY-protocol
    /// consumption is off (see [`UdpProxy::spawn_with_arm_table`] for
    /// the rationale and when to enable it).
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
    /// and worker count. `workers == 0` is rejected. Convenience alias for
    /// callers that don't participate in the daemon-wide canary surface;
    /// installs an empty arm-table and disables inbound PROXY consumption.
    pub async fn spawn_with(
        rule: Rule,
        resolver: UpstreamResolver,
        max_flows: usize,
        workers: usize,
    ) -> Result<Self> {
        Self::spawn_with_arm_table(
            rule,
            resolver,
            max_flows,
            workers,
            false,
            Arc::new(CanaryArmTable::new()),
        )
        .await
    }

    /// Bind frontend sockets and spawn the proxy tasks with explicit
    /// flow cap, worker count, inbound PROXY-protocol flag, and canary
    /// arm-table. `workers == 0` is rejected.
    ///
    /// `expect_inbound_proxy` enables PROXY-v2 first-datagram
    /// consumption on the inbound side of each new flow. Set to `true`
    /// only on mid-chain Relay nodes for chain-derived UDP rules where
    /// the upstream Gateway / Relay always emits a PROXY-v2 first
    /// datagram per flow. With this enabled the worker stashes the
    /// decoded real client and uses it when emitting its own outbound
    /// PROXY-v2 first datagram, so a 3+ hop chain preserves the real
    /// client IP all the way to the terminal's HTTP/3 interpose.
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
    ///
    /// ## Canary intercept
    ///
    /// The frontend loop calls `arm_table.is_armed(rule.listen, Udp)`
    /// on each received batch. When false (the steady state), the
    /// datagram is passed through to the normal flow-table dispatcher
    /// with zero added cost. When true, each datagram's first 32
    /// bytes are matched against the table; matching datagrams are
    /// echoed back to the source from the frontend socket and do not
    /// allocate a flow-table entry.
    pub async fn spawn_with_arm_table(
        rule: Rule,
        resolver: UpstreamResolver,
        max_flows: usize,
        workers: usize,
        expect_inbound_proxy: bool,
        arm_table: Arc<CanaryArmTable>,
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
            let arm_table_t = Arc::clone(&arm_table);
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
                        let local_addr = match frontend.local_addr() {
                            Ok(a) => a,
                            Err(e) => {
                                tracing::error!(
                                    rule = %rule_t.name,
                                    worker_id,
                                    error = %e,
                                    "UDP worker: frontend local_addr lookup failed; worker exiting"
                                );
                                return;
                            }
                        };
                        let worker = UdpWorker {
                            worker_id,
                            frontend,
                            rule: rule_t,
                            local_addr,
                            resolver: resolver_t,
                            flows: shard_t,
                            flow_count: flow_count_t,
                            cancel: cancel_t,
                            start,
                            max_flows: max_flows_t,
                            arm_table: arm_table_t,
                            expect_inbound_proxy,
                            pending_real_clients: Arc::new(DashMap::new()),
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
    /// Resolved bound address of `frontend`. Used for arm-table
    /// lookups instead of `rule.listen`, because the rule's literal
    /// `listen` may carry port `0` (kernel-assigned) and the actual
    /// listener lives at the OS-resolved port.
    local_addr: SocketAddr,
    resolver: UpstreamResolver,
    flows: Arc<DashMap<SocketAddr, Arc<FlowEntry>>>,
    flow_count: Arc<AtomicUsize>,
    cancel: CancellationToken,
    start: Instant,
    max_flows: usize,
    /// Per-daemon arm table. The frontend loop consults it on every
    /// datagram via the O(1) `is_armed` shard probe; matching
    /// token-prefixed datagrams are echoed in-process at the frontend
    /// socket and never enter the flow table.
    arm_table: Arc<CanaryArmTable>,
    /// Multi-hop client-IP bridging: when `true`, the worker peeks
    /// every new-flow datagram for a PROXY-v2 header and, on hit,
    /// stashes the decoded real client in `pending_real_clients` to
    /// override the kernel-observed client for the next datagram's
    /// outbound PROXY emission. Set only on mid-chain Relay nodes
    /// for HTTPS-derived UDP rules where the upstream Gateway / Relay
    /// always emits a PROXY-v2 first datagram per flow.
    expect_inbound_proxy: bool,
    /// Per-(kernel client_addr) cache of "the upstream chain hop just
    /// told us the real client behind this kernel peer". Populated by
    /// `handle_inbound` when it decodes a PROXY-v2 first-datagram;
    /// drained on the *next* (application) datagram from the same
    /// kernel peer. Entries older than `PENDING_PROXY_TTL` are reaped
    /// alongside the flow reaper so an orphaned PROXY datagram (no
    /// application follow-up) doesn't leak indefinitely.
    pending_real_clients: Arc<DashMap<SocketAddr, (SocketAddr, Instant)>>,
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
            // Step 1: wait for the next batch. Most of this section
            // is spent parked on epoll readiness; the time recorded
            // here is wall-clock until recv.recv() returns.
            let res = {
                let _g = crate::profile::section("udp", "frontend_wait");
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
                    res = recv.recv(&mut scratch) => res,
                }
            };

            // Step 2: copy + dispatch the batch.
            let _g = crate::profile::section("udp", "frontend_process_batch");
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
            // Canary fast-path: when at least one canary is in flight
            // against this rule's `(listen, Udp)`, peek the first 32
            // bytes of each datagram in the batch and route matching
            // probe traffic to an in-process echo. The cold path
            // (no canary armed, the steady state) is one DashMap
            // shard probe per batch, not per datagram.
            let arm_active = self.arm_table.is_armed(self.local_addr, Protocol::Udp);

            // The hot path runs synchronously against borrowed slices
            // from the recvmmsg scratch buffer (zero per-packet alloc).
            // Datagrams that need an `await` — flow creation, PROXY
            // header decoding, sending under WOULD_BLOCK back-pressure
            // — are collected into `slow_path` and serviced after the
            // borrow-borrow scope. This pattern keeps the steady-state
            // every-packet-hits-existing-flow case allocation-free
            // (the dominant case for any UDP rule once it's warm).
            let mut slow_path: Vec<(Vec<u8>, SocketAddr)> = Vec::new();
            {
                let _g = crate::profile::section("udp", "frontend_dispatch_batch");
                for d in recv.iter(&scratch, n) {
                    if arm_active
                        && d.payload.len() >= CANARY_TOKEN_LEN
                        && self.arm_table.match_token(
                            self.local_addr,
                            Protocol::Udp,
                            &{
                                let mut prefix = [0u8; CANARY_TOKEN_LEN];
                                prefix.copy_from_slice(&d.payload[..CANARY_TOKEN_LEN]);
                                prefix
                            },
                        )
                    {
                        // Echo the entire datagram (token included)
                        // back to the source from this worker's
                        // frontend socket. The originator strips the
                        // token prefix on receive. The datagram does
                        // not consume a flow-table slot.
                        match self.frontend.try_send_to(d.payload, d.from) {
                            Ok(_) => {
                                metrics::counter!(
                                    "yggdrasil_udp_canary_echo_total",
                                    "rule" => self.rule.name.clone(),
                                    "worker" => self.worker_id.to_string(),
                                )
                                .increment(1);
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                // Kernel socket buffer full — fall back to the
                                // async send below so we don't drop the canary
                                // echo silently.
                                slow_path.push((d.payload.to_vec(), d.from));
                            }
                            Err(e) => {
                                tracing::debug!(
                                    rule = %self.rule.name,
                                    worker_id = self.worker_id,
                                    client = %d.from,
                                    error = %e,
                                    "UDP canary echo send_to failed"
                                );
                            }
                        }
                        continue;
                    }
                    if !self.try_handle_inbound_fast(d.payload, d.from) {
                        slow_path.push((d.payload.to_vec(), d.from));
                    }
                }
            }

            for (payload, client_addr) in slow_path {
                // Re-classify: the canary table is sampled once per
                // batch on the hot path; a slow-path entry that got
                // here via try_send_to WOULD_BLOCK is still a canary
                // echo. The cold-path send through `frontend.send_to`
                // applies kernel back-pressure.
                if arm_active && payload.len() >= CANARY_TOKEN_LEN {
                    let mut prefix = [0u8; CANARY_TOKEN_LEN];
                    prefix.copy_from_slice(&payload[..CANARY_TOKEN_LEN]);
                    if self
                        .arm_table
                        .match_token(self.local_addr, Protocol::Udp, &prefix)
                    {
                        if let Err(e) = self.frontend.send_to(&payload, client_addr).await {
                            tracing::debug!(
                                rule = %self.rule.name,
                                worker_id = self.worker_id,
                                client = %client_addr,
                                error = %e,
                                "UDP canary echo async send_to failed"
                            );
                        } else {
                            metrics::counter!(
                                "yggdrasil_udp_canary_echo_total",
                                "rule" => self.rule.name.clone(),
                                "worker" => self.worker_id.to_string(),
                            )
                            .increment(1);
                        }
                        continue;
                    }
                }
                self.handle_inbound(&payload, client_addr).await;
            }
        }
    }

    /// Synchronous fast path for the steady-state existing-flow case.
    /// Returns `true` if the datagram was fully handled here; `false`
    /// when the caller must fall back to the async [`Self::handle_inbound`]
    /// (new flow, WOULD_BLOCK back-pressure, or any other path that
    /// needs to await).
    ///
    /// Keeping this synchronous + slice-borrowing is what lets the
    /// outer batch loop iterate over `recvmmsg`'s scratch buffer
    /// without allocating per packet. The cold path (new flow, PROXY
    /// header decode, etc.) is unchanged and runs async on owned bytes.
    fn try_handle_inbound_fast(&self, payload: &[u8], client_addr: SocketAddr) -> bool {
        let _g = crate::profile::section("udp", "handle_inbound_fast");
        let entry = {
            let _g = crate::profile::section("udp", "flow_lookup");
            match self.flows.get(&client_addr) {
                Some(e) => e.clone(),
                None => return false,
            }
        };
        entry.last_seen_ms.store(self.now_ms(), Ordering::Relaxed);
        let send_result = {
            let _g = crate::profile::section("udp", "upstream_try_send");
            entry.upstream_sock.try_send(payload)
        };
        match send_result {
            Ok(_) => {
                increment_udp_bytes(
                    &self.rule.name,
                    self.worker_id,
                    "client_to_upstream",
                    payload.len(),
                );
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Kernel send buffer full — fall back to the async
                // path so the datagram gets sent with back-pressure
                // rather than dropped silently.
                false
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
                    "upstream try_send failed; flow may be stale (will be reaped)"
                );
                // Don't fall back to async — the error is terminal
                // (flow's stale upstream, kernel reset, etc.), and
                // retrying via async-send hits the same error path.
                true
            }
        }
    }

    async fn handle_inbound(&self, payload: &[u8], client_addr: SocketAddr) {
        let _g = crate::profile::section("udp", "handle_inbound");
        // Fast path: existing flow.
        let lookup_result = {
            let _g = crate::profile::section("udp", "flow_lookup");
            self.flows.get(&client_addr).map(|e| e.clone())
        };
        if let Some(entry) = lookup_result {
            entry.last_seen_ms.store(self.now_ms(), Ordering::Relaxed);
            let send_result = {
                let _g = crate::profile::section("udp", "upstream_send");
                entry.upstream_sock.send(payload).await
            };
            match send_result {
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

        // Multi-hop bridging: on a mid-chain Relay, the upstream chain
        // hop sends a PROXY-v2 first datagram per new flow before the
        // application bytes (the QUIC Initial). Decode, stash the real
        // client in `pending_real_clients`, and bail — the next
        // datagram from the same `client_addr` carries the
        // application payload and triggers `create_flow` below, which
        // drains the stash and uses the decoded address in its own
        // outbound PROXY emission. This makes 3+ hop chains preserve
        // the real client IP all the way to the terminal's HTTP/3
        // interpose.
        //
        // Gated on `expect_inbound_proxy` so non-chain UDP rules (game
        // ports etc.) don't pay any per-datagram parse cost and don't
        // mis-classify a genuine application datagram that happens to
        // start with the v2 magic bytes (which by construction no
        // valid QUIC packet can, but other arbitrary L4 protocols
        // could in theory).
        if self.expect_inbound_proxy {
            if let Some(endpoints) = proxy_protocol::decode_v2_from_datagram(payload) {
                self.pending_real_clients
                    .insert(client_addr, (endpoints.client, Instant::now()));
                return;
            }
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

        // Drain any pending PROXY-decoded real client for this flow.
        // Expired entries (older than `PENDING_PROXY_TTL`) are dropped
        // here as a lazy reaper.
        let outbound_client_addr = match self.pending_real_clients.remove(&client_addr) {
            Some((_, (real, stashed_at))) if stashed_at.elapsed() <= PENDING_PROXY_TTL => real,
            _ => client_addr,
        };

        // PROXY v2 first-datagram for HTTPS UDP/QUIC chain traffic. The
        // derive step sets `proxy_protocol = Some(V2)` on HTTPS-derived UDP
        // rules so the terminal's h3 interpose socket can decode this
        // standalone datagram and remember the real client for subsequent
        // QUIC datagrams on the same 5-tuple. Emit only V2; V1 is text-only
        // and not meaningful as a datagram (the validator rejects V1 on UDP
        // rules). Failures here are non-fatal — the next application
        // datagram still goes through; the terminal just doesn't learn the
        // real client IP for this flow and falls back to the relay-observed
        // peer addr.
        if let Some(ProxyProto::V2) = self.rule.proxy_protocol {
            let header = proxy_protocol::encode_header(
                ProxyProto::V2,
                outbound_client_addr,
                self.local_addr,
            );
            if let Err(e) = entry.upstream_sock.send(&header).await {
                tracing::debug!(
                    rule = %self.rule.name,
                    client = %outbound_client_addr,
                    upstream = %target_addr,
                    error = %e,
                    "PROXY v2 first-datagram send failed; flow continues without client-IP propagation"
                );
            }
        }

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
        // Step 1: wait for the upstream to deliver a batch. Most of
        // this section is spent parked on epoll readiness.
        let res = {
            let _g = crate::profile::section("udp", "upstream_wait");
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return,
                res = reader.recv_batch(buf) => res,
            }
        };
        // Step 2: forward the batch back to the client.
        let _g = crate::profile::section("udp", "upstream_process_batch");
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
    let _g = crate::profile::section("udp", "upstream_batch_forward");
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
            let send_result = {
                let _g = crate::profile::section("udp", "sendmmsg_to_client");
                sender.send_batch(&payloads, client_addr).await
            };
            match send_result {
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

    // ---- Canary intercept ----

    #[tokio::test]
    async fn canary_armed_token_match_echoes_at_frontend() {
        // No upstream backend exists — the resolver points at a closed
        // port. If the canary fast-path works, the client still gets
        // its datagram back. No flow-table entry should be created.
        let arm_table = Arc::new(CanaryArmTable::new());
        let proxy = UdpProxy::spawn_with_arm_table(
            udp_rule("canary-udp", 1, 60),
            static_resolver("127.0.0.1:1".parse().unwrap()),
            MAX_FLOWS_PER_RULE_DEFAULT,
            1,
            false,
            Arc::clone(&arm_table),
        )
        .await
        .unwrap();
        let listen = proxy.local_addr();

        let token = [0xABu8; CANARY_TOKEN_LEN];
        arm_table.arm(listen, Protocol::Udp, token, Duration::from_secs(5));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut payload = Vec::with_capacity(CANARY_TOKEN_LEN + 5);
        payload.extend_from_slice(&token);
        payload.extend_from_slice(b"hello");
        client.send_to(&payload, listen).await.unwrap();

        let mut buf = [0u8; CANARY_TOKEN_LEN + 5];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("recv timed out")
            .unwrap();
        assert_eq!(n, CANARY_TOKEN_LEN + 5);
        // Whole datagram (token included) echoed back verbatim.
        assert_eq!(&buf[..CANARY_TOKEN_LEN], &token);
        assert_eq!(&buf[CANARY_TOKEN_LEN..], b"hello");
        // No flow-table entry was allocated.
        assert_eq!(proxy.active_flows(), 0);

        proxy.stop().await;
    }

    #[tokio::test]
    async fn canary_unarmed_table_forwards_normally_even_with_token_prefix() {
        // Arm-table empty: the fast path is skipped, the datagram
        // (token-prefixed or not) is forwarded to the configured
        // backend and echoed there. Same semantics as plain UDP
        // proxying.
        let upstream = echo_server().await;
        let arm_table = Arc::new(CanaryArmTable::new());
        let proxy = UdpProxy::spawn_with_arm_table(
            udp_rule("canary-cold-udp", upstream.port(), 60),
            static_resolver(upstream),
            MAX_FLOWS_PER_RULE_DEFAULT,
            1,
            false,
            arm_table,
        )
        .await
        .unwrap();
        let listen = proxy.local_addr();

        let token = [0xCDu8; CANARY_TOKEN_LEN];
        let mut payload = Vec::with_capacity(CANARY_TOKEN_LEN + 5);
        payload.extend_from_slice(&token);
        payload.extend_from_slice(b"world");
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let got = send_recv(&client, listen, &payload).await;
        assert_eq!(got.len(), CANARY_TOKEN_LEN + 5);
        assert_eq!(&got[..CANARY_TOKEN_LEN], &token);
        assert_eq!(&got[CANARY_TOKEN_LEN..], b"world");
        // Normal forwarding path: a flow-table entry IS created.
        assert_eq!(proxy.active_flows(), 1);

        proxy.stop().await;
    }

    #[tokio::test]
    async fn canary_armed_with_wrong_token_falls_through_to_backend() {
        // Table is hot (some arm exists), but the datagram's prefix
        // doesn't match. The intercept must not consume it; the
        // backend's echo sees the datagram verbatim and the flow
        // table picks up a normal entry.
        let upstream = echo_server().await;
        let arm_table = Arc::new(CanaryArmTable::new());
        let proxy = UdpProxy::spawn_with_arm_table(
            udp_rule("canary-wrong-udp", upstream.port(), 60),
            static_resolver(upstream),
            MAX_FLOWS_PER_RULE_DEFAULT,
            1,
            false,
            Arc::clone(&arm_table),
        )
        .await
        .unwrap();
        let listen = proxy.local_addr();

        let armed_token = [0x11u8; CANARY_TOKEN_LEN];
        arm_table.arm(listen, Protocol::Udp, armed_token, Duration::from_secs(5));

        let unrelated_prefix = [0x22u8; CANARY_TOKEN_LEN];
        let mut payload = Vec::with_capacity(CANARY_TOKEN_LEN + 3);
        payload.extend_from_slice(&unrelated_prefix);
        payload.extend_from_slice(b"abc");

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let got = send_recv(&client, listen, &payload).await;
        // Backend's echo returned the prefix + payload verbatim —
        // proves the intercept did not consume the datagram.
        assert_eq!(&got[..CANARY_TOKEN_LEN], &unrelated_prefix);
        assert_eq!(&got[CANARY_TOKEN_LEN..], b"abc");
        assert_eq!(proxy.active_flows(), 1);

        proxy.stop().await;
    }

    #[tokio::test]
    async fn canary_armed_short_datagram_falls_through() {
        // Datagram is shorter than CANARY_TOKEN_LEN bytes; the
        // intercept skips it without trying to match and the normal
        // flow-table dispatch runs.
        let upstream = echo_server().await;
        let arm_table = Arc::new(CanaryArmTable::new());
        let proxy = UdpProxy::spawn_with_arm_table(
            udp_rule("canary-short-udp", upstream.port(), 60),
            static_resolver(upstream),
            MAX_FLOWS_PER_RULE_DEFAULT,
            1,
            false,
            Arc::clone(&arm_table),
        )
        .await
        .unwrap();
        let listen = proxy.local_addr();

        arm_table.arm(
            listen,
            Protocol::Udp,
            [0x33u8; CANARY_TOKEN_LEN],
            Duration::from_secs(5),
        );

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let got = send_recv(&client, listen, b"hi").await;
        assert_eq!(&got, b"hi");
        assert_eq!(proxy.active_flows(), 1);

        proxy.stop().await;
    }

    /// Background UDP capture: records every datagram it receives without
    /// echoing. Returns `(bound addr, mpsc receiver of (payload, peer))`.
    /// Used to assert PROXY-v2 first-datagram emission on the relay's
    /// upstream socket.
    async fn capture_server() -> (
        SocketAddr,
        tokio::sync::mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
    ) {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        if tx.send((buf[..n].to_vec(), from)).is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
        (addr, rx)
    }

    fn udp_rule_with_proxy_v2(name: &str, target_port: u16) -> Rule {
        let f = ratatoskr::rule::RuleFile::from_toml(
            "test.toml",
            &format!(
                r#"
                [[rule]]
                name = "{name}"
                listen = "127.0.0.1:0"
                protocol = "udp"
                target_port = {target_port}
                idle_timeout = "60s"
                proxy_protocol = "v2"
                "#,
            ),
        )
        .unwrap();
        f.rule.into_iter().next().unwrap()
    }

    #[tokio::test]
    async fn emits_proxy_v2_first_datagram_on_new_flow() {
        let (upstream_addr, mut upstream_rx) = capture_server().await;
        let peer = PeerState::new([0u8; 32]);
        let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());

        let proxy = UdpProxy::spawn(
            udp_rule_with_proxy_v2("h3", upstream_addr.port()),
            dynamic_resolver(peer, upstream_addr.port()),
        )
        .await
        .unwrap();
        let proxy_listen = proxy.local_addr();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        client
            .send_to(b"first-quic-initial", proxy_listen)
            .await
            .unwrap();

        // First datagram on the upstream must be the PROXY v2 header,
        // describing (client_addr -> proxy_listen).
        let (first, _) = tokio::time::timeout(Duration::from_secs(2), upstream_rx.recv())
            .await
            .expect("first datagram timeout")
            .expect("capture closed");
        let decoded = crate::proxy::proxy_protocol::decode_v2_from_datagram(&first)
            .expect("first datagram must be a valid PROXY v2 header");
        assert_eq!(decoded.client, client_addr);
        assert_eq!(decoded.server, proxy_listen);

        // Second datagram must be the actual application payload.
        let (second, _) = tokio::time::timeout(Duration::from_secs(2), upstream_rx.recv())
            .await
            .expect("application datagram timeout")
            .expect("capture closed");
        assert_eq!(&second, b"first-quic-initial");

        proxy.stop().await;
    }

    #[tokio::test]
    async fn does_not_emit_proxy_v2_when_rule_lacks_proxy_protocol() {
        // L4 UDP rules (no proxy_protocol set, e.g. game ports) must NOT
        // emit a PROXY header — the application payload must arrive at
        // the upstream byte-for-byte as the client sent it.
        let (upstream_addr, mut upstream_rx) = capture_server().await;
        let peer = PeerState::new([0u8; 32]);
        let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());

        let proxy = UdpProxy::spawn(
            udp_rule("game", upstream_addr.port(), 60),
            dynamic_resolver(peer, upstream_addr.port()),
        )
        .await
        .unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(b"raw-payload", proxy.local_addr())
            .await
            .unwrap();

        let (first, _) = tokio::time::timeout(Duration::from_secs(2), upstream_rx.recv())
            .await
            .expect("first datagram timeout")
            .expect("capture closed");
        assert_eq!(&first, b"raw-payload");
        // Verify the upstream didn't also receive a stray PROXY header.
        let drained = tokio::time::timeout(Duration::from_millis(100), upstream_rx.recv()).await;
        assert!(
            drained.is_err(),
            "expected no second datagram on a non-PROXY rule, got: {drained:?}"
        );

        proxy.stop().await;
    }

    /// Multi-hop UDP client-IP bridging: with `expect_inbound_proxy = true`
    /// the worker decodes any PROXY-v2 first datagram the upstream chain
    /// hop emitted, stashes the real client, and uses it when synthesising
    /// its own outbound PROXY emission on the next (application)
    /// datagram. Mirrors the TCP `bridges_inbound_proxy_v2_to_outbound`
    /// invariant: 3+ hop UDP/HTTP-3 chains preserve the real client IP.
    #[tokio::test]
    async fn bridges_inbound_proxy_v2_to_outbound_first_datagram() {
        let (upstream_addr, mut upstream_rx) = capture_server().await;
        let peer = PeerState::new([0u8; 32]);
        let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());

        let proxy = UdpProxy::spawn_with_arm_table(
            udp_rule_with_proxy_v2("h3-midhop", upstream_addr.port()),
            dynamic_resolver(peer, upstream_addr.port()),
            MAX_FLOWS_PER_RULE_DEFAULT,
            1,
            true,
            Arc::new(CanaryArmTable::new()),
        )
        .await
        .unwrap();
        let proxy_listen = proxy.local_addr();

        // The client (standing in for the upstream chain hop) sends a
        // PROXY-v2 first datagram claiming the real client is
        // 203.0.113.45, then the actual application bytes.
        let real_client: SocketAddr = "203.0.113.45:54321".parse().unwrap();
        let server_dst: SocketAddr = "198.51.100.4:443".parse().unwrap();
        let inbound_proxy = crate::proxy::proxy_protocol::encode_header(
            ratatoskr::rule::ProxyProto::V2,
            real_client,
            server_dst,
        );

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&inbound_proxy, proxy_listen).await.unwrap();
        // Small spacing so the worker reaches the pending-stash path
        // before the application datagram arrives. Without it the two
        // datagrams could be batched and the second would create a
        // flow before the first's pending entry is recorded — a real-
        // world race the workers see in production but the loopback-
        // fast-path makes more likely in tests.
        tokio::time::sleep(Duration::from_millis(20)).await;
        client.send_to(b"app-bytes", proxy_listen).await.unwrap();

        // First upstream datagram = our outbound PROXY-v2 carrying the
        // real client (NOT 127.0.0.1, NOT the test client's addr).
        let (outbound_proxy, _) = tokio::time::timeout(Duration::from_secs(2), upstream_rx.recv())
            .await
            .expect("outbound PROXY timeout")
            .expect("capture closed");
        let decoded =
            crate::proxy::proxy_protocol::decode_v2_from_datagram(&outbound_proxy).expect("decode");
        assert_eq!(
            decoded.client, real_client,
            "outbound PROXY must carry the real client decoded from inbound, \
             not the kernel-observed test-client addr"
        );
        assert_eq!(decoded.server, proxy_listen);

        // Second upstream datagram = the application payload.
        let (app, _) = tokio::time::timeout(Duration::from_secs(2), upstream_rx.recv())
            .await
            .expect("app datagram timeout")
            .expect("capture closed");
        assert_eq!(&app, b"app-bytes");

        proxy.stop().await;
    }

    /// Sanity: with `expect_inbound_proxy = false` (Gateway-mode or any
    /// non-chain UDP rule), an inbound PROXY-v2-looking datagram is NOT
    /// consumed as PROXY — it would be treated as application data and
    /// forwarded raw. Mirrors the TCP correctness invariant.
    #[tokio::test]
    async fn does_not_consume_inbound_proxy_when_flag_off_udp() {
        let (upstream_addr, mut upstream_rx) = capture_server().await;
        let peer = PeerState::new([0u8; 32]);
        let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());

        let proxy = UdpProxy::spawn_with_arm_table(
            udp_rule_with_proxy_v2("h3-gateway", upstream_addr.port()),
            dynamic_resolver(peer, upstream_addr.port()),
            MAX_FLOWS_PER_RULE_DEFAULT,
            1,
            false,
            Arc::new(CanaryArmTable::new()),
        )
        .await
        .unwrap();
        let proxy_listen = proxy.local_addr();

        let inbound_proxy = crate::proxy::proxy_protocol::encode_header(
            ratatoskr::rule::ProxyProto::V2,
            "203.0.113.45:54321".parse().unwrap(),
            "198.51.100.4:443".parse().unwrap(),
        );
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        client.send_to(&inbound_proxy, proxy_listen).await.unwrap();

        // First upstream datagram = our outbound PROXY-v2 with the
        // *kernel-observed* client (127.0.0.1) because we treated the
        // inbound PROXY bytes as application data.
        let (outbound_proxy, _) = tokio::time::timeout(Duration::from_secs(2), upstream_rx.recv())
            .await
            .expect("outbound PROXY timeout")
            .expect("capture closed");
        let decoded =
            crate::proxy::proxy_protocol::decode_v2_from_datagram(&outbound_proxy).expect("decode");
        assert_eq!(
            decoded.client, client_addr,
            "outbound PROXY must carry the kernel-observed client when expect_inbound_proxy=false"
        );

        // Second upstream datagram = the inbound PROXY bytes,
        // forwarded as application data unchanged.
        let (app, _) = tokio::time::timeout(Duration::from_secs(2), upstream_rx.recv())
            .await
            .expect("app datagram timeout")
            .expect("capture closed");
        assert_eq!(
            app.as_slice(),
            inbound_proxy.as_slice(),
            "inbound PROXY bytes should pass through as raw application data when flag is off"
        );

        proxy.stop().await;
    }
}
