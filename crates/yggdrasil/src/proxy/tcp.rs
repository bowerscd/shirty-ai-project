//! Per-rule TCP proxy.
//!
//! Each [`TcpProxy`] owns `workers` `tokio::net::TcpListener`s bound to
//! `rule.listen` via `SO_REUSEADDR + SO_REUSEPORT` (the same primitive
//! `proxy/udp/mod.rs` uses for UDP frontend fan-out), one accept loop
//! per listener, and a single [`CancellationToken`] cascade for clean
//! shutdown. With `workers = 1` the proxy short-circuits to a single
//! plain bind — the SO_REUSEPORT machinery only kicks in for `> 1`.
//!
//! Per-connection lifecycle (unchanged regardless of worker count):
//!
//! 1. `accept()` returns `(client, client_addr)`.
//! 2. Resolve the current dial target via [`UpstreamResolver::current_target`].
//!    `None` (relay before first heartbeat) → accept-then-close with a `debug`
//!    log so listeners stay up for debugging. Bump `tcp_connect_no_peer_total`.
//! 3. `TcpStream::connect(target)`. On error, log + close the client. Bump
//!    `tcp_connect_failed_total`.
//! 4. If `rule.proxy_protocol` is set, write the header to the upstream
//!    stream before any application bytes.
//! 5. `tokio::io::copy_bidirectional(client, upstream)` until either side
//!    EOFs or errors. Bump byte counters in both directions.
//!
//! On dial-target change (relay IP-change), in-flight TCP connections are
//! **left alone** — the application layer is already broken because the
//! upstream IP changed; force-closing the socket adds no signal beyond what
//! the network already delivered. New accepts pick up the new target.
//! Terminal-mode resolvers never change their target, so the question is
//! moot there.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use tokio::io::{copy_bidirectional_with_sizes, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use ratatoskr::canary::CANARY_TOKEN_LEN;
use ratatoskr::rule::{Protocol, Rule};

use super::canary::CanaryArmTable;
use super::proxy_protocol;
use super::resolver::UpstreamResolver;

/// Per-listener backlog. 1024 is the default Linux `somaxconn`; higher
/// values are silently capped by the kernel unless the operator raises
/// `net.core.somaxconn`. Matches what tokio's `TcpListener::bind` requests.
const LISTEN_BACKLOG: i32 = 1024;

/// Per-direction forwarding buffer used by [`copy_bidirectional_with_sizes`].
/// Tokio's plain [`copy_bidirectional`] defaults to 8 KiB; nginx's `stream`
/// module's `proxy_buffer_size` defaults to 16 KiB. 32 KiB halves syscall
/// rate vs nginx on bulk TCP transfers (the dominant overhead on
/// loopback throughput benches) while still fitting two buffers per
/// connection in a 64 KiB L1d on most modern CPUs. Empirically chosen
/// over 64 KiB because the marginal syscall savings beyond 32 KiB are
/// small and the extra working set hurts cache locality on hosts with
/// many concurrent connections.
const FORWARD_BUFFER_SIZE: usize = 32 * 1024;

/// How long the per-accept canary-token peek waits for the first
/// [`CANARY_TOKEN_LEN`] bytes to arrive before giving up. Real client
/// connections that don't send anything in this window fall through to
/// the normal forwarding path — the kernel buffer is untouched by the
/// peek so the upstream `copy_bidirectional` reads them normally.
/// 200 ms is short enough that the worst-case "real client, slow start"
/// added latency is invisible to humans, and long enough that genuine
/// canary probe traffic (which we control) is reliably caught.
const CANARY_PEEK_TIMEOUT: Duration = Duration::from_millis(200);

/// Handle to a running per-rule TCP proxy. Drop to stop (the cancellation
/// token cascade aborts the accept loops and lets in-flight connections
/// finish naturally).
pub struct TcpProxy {
    rule: Arc<Rule>,
    /// Cancels the accept loops only. Firing it stops new connections
    /// from being accepted but leaves in-flight per-connection tasks
    /// alone — they continue until `conn_cancel` fires (the drain
    /// timeout backstop, or `cancel()` for legacy abrupt-stop).
    accept_cancel: CancellationToken,
    /// Cancels every in-flight per-connection task. Per-task
    /// `tokio::select!` arms observe this and tear `copy_bidirectional`
    /// down on cancel. Kept separate from `accept_cancel` so the
    /// drain path can stop accepting without instantly aborting
    /// in-flight conversations.
    conn_cancel: CancellationToken,
    local_addr: SocketAddr,
    /// One handle per accept worker. `stop()` awaits all of them.
    worker_handles: Vec<tokio::task::JoinHandle<()>>,
    /// Tracks every per-connection task spawned by the accept loops.
    /// On graceful drain (`stop(Some(timeout))`), the accept loops are
    /// cancelled first (no new spawns), then we wait on the tracker
    /// for in-flight connections to finish naturally — bounded by the
    /// caller's timeout. Any task still alive when the timeout fires
    /// is then explicitly cancelled via `conn_cancel`.
    conn_tracker: TaskTracker,
}

impl TcpProxy {
    /// Bind `workers` listeners and spawn accept loops with no canary
    /// arm-table wired (`is_armed` always returns false). Convenience
    /// alias used by tests and by call sites that don't participate in
    /// the daemon-wide canary surface.
    pub async fn spawn(rule: Rule, resolver: UpstreamResolver, workers: usize) -> Result<Self> {
        Self::spawn_with_arm_table(
            rule,
            resolver,
            workers,
            false,
            Arc::new(CanaryArmTable::new()),
        )
        .await
    }

    /// Bind `workers` listeners (via SO_REUSEPORT when `workers > 1`) and
    /// spawn one accept loop per listener. Returns once every socket is
    /// listening, so callers can rely on connect attempts succeeding
    /// immediately after this resolves. `workers == 0` is rejected.
    ///
    /// `expect_inbound_proxy` enables PROXY-protocol consumption on the
    /// inbound side of each accepted connection. Set to `true` only on
    /// mid-chain Relay nodes for chain-derived rules, where the
    /// upstream Gateway / Relay always prepends a PROXY-v2 header on
    /// every connection. With this enabled the proxy uses the decoded
    /// client when synthesising its own outbound PROXY emission, so a
    /// 3+ hop chain preserves the original client IP all the way to
    /// the terminal. Off by default — turning it on for an
    /// arbitrary peer would deadlock server-speaks-first protocols.
    ///
    /// The `arm_table` is consulted on every accepted connection: when
    /// at least one canary is in flight for this rule's `(listen,
    /// Tcp)`, the first [`CANARY_TOKEN_LEN`] bytes are peeked and
    /// compared against the table; matching connections short-circuit
    /// to an in-process echo without reaching the configured backend.
    /// Non-matching and unarmed-table connections take the normal
    /// upstream forwarding path with zero added cost beyond an O(1)
    /// shard probe.
    pub async fn spawn_with_arm_table(
        rule: Rule,
        resolver: UpstreamResolver,
        workers: usize,
        expect_inbound_proxy: bool,
        arm_table: Arc<CanaryArmTable>,
    ) -> Result<Self> {
        ensure!(workers > 0, "TCP worker count must be >= 1");

        let requested_workers = workers;
        #[cfg(unix)]
        let effective_workers = requested_workers;
        #[cfg(not(unix))]
        let effective_workers = if requested_workers > 1 {
            tracing::warn!(
                rule = %rule.name,
                requested_workers,
                "TCP SO_REUSEPORT is unavailable on this platform; using one worker"
            );
            1
        } else {
            requested_workers
        };

        let listeners = build_tcp_listener_sockets(rule.listen, effective_workers)
            .await
            .with_context(|| {
                format!(
                    "bind TCP listener for rule {:?} on {}",
                    rule.name, rule.listen
                )
            })?;
        debug_assert_eq!(listeners.len(), effective_workers);
        let local_addr = listeners[0]
            .local_addr()
            .context("read TcpListener local_addr")?;

        // Share the rule across every accepted connection via `Arc` so
        // the per-accept hot path doesn't deep-clone the rule (which
        // would allocate the `name` String and chase every Option /
        // Vec field). The accept loop clones the `Arc` — a single
        // atomic increment — and passes that into the spawned
        // per-connection task.
        let rule_arc = Arc::new(rule);

        let accept_cancel = CancellationToken::new();
        let conn_cancel = CancellationToken::new();
        let conn_tracker = TaskTracker::new();
        let mut worker_handles = Vec::with_capacity(effective_workers);
        for (worker_id, listener) in listeners.into_iter().enumerate() {
            let task_accept_cancel = accept_cancel.clone();
            let task_conn_cancel = conn_cancel.clone();
            let task_rule = Arc::clone(&rule_arc);
            let task_resolver = resolver.clone();
            let task_local = local_addr;
            let task_tracker = conn_tracker.clone();
            let task_arm_table = Arc::clone(&arm_table);
            let handle = tokio::spawn(async move {
                run_accept_loop(
                    task_rule,
                    task_resolver,
                    listener,
                    task_local,
                    worker_id,
                    expect_inbound_proxy,
                    task_accept_cancel,
                    task_conn_cancel,
                    task_tracker,
                    task_arm_table,
                )
                .await;
            });
            worker_handles.push(handle);
        }

        tracing::info!(
            rule = %rule_arc.name,
            listen = %local_addr,
            upstream = %resolver.describe(),
            proxy_protocol = ?rule_arc.proxy_protocol,
            workers = effective_workers,
            "TCP rule listening"
        );

        metrics::gauge!(
            "yggdrasil_workers",
            "rule" => rule_arc.name.clone(),
            "protocol" => "tcp",
        )
        .set(effective_workers as f64);

        Ok(Self {
            rule: rule_arc,
            accept_cancel,
            conn_cancel,
            local_addr,
            worker_handles,
            conn_tracker,
        })
    }

    pub fn rule(&self) -> &Rule {
        &self.rule
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Trigger abrupt shutdown — equivalent to `stop(None)` shape:
    /// fires both the accept-loop cancel and the in-flight
    /// connection cancel, then returns. Does NOT await; call
    /// [`TcpProxy::stop`] to actually wait for tasks to wind down.
    pub fn cancel(&self) {
        self.accept_cancel.cancel();
        self.conn_cancel.cancel();
    }

    /// Cancel the accept loops and wait for them to exit. With
    /// `drain_timeout = Some(t)`, additionally wait up to `t` for
    /// in-flight per-connection tasks to finish naturally before
    /// cancelling them (zero-downtime graceful drain). With `None`
    /// (the historical default), both accept loops and per-conn
    /// tasks are cancelled together — preserves the pre-drain
    /// abrupt-stop behaviour byte-for-byte.
    ///
    /// In-flight TCP connections in the drain window proceed
    /// undisturbed: their `tokio::select!` arm observes
    /// `conn_cancel`, not `accept_cancel`. Only after the drain
    /// timeout fires (or `None` was passed) does `conn_cancel`
    /// trigger, at which point `copy_bidirectional` is torn down.
    pub async fn stop(self, drain_timeout: Option<Duration>) {
        self.accept_cancel.cancel();
        for handle in self.worker_handles {
            let _ = handle.await;
        }
        // Close the tracker before waiting (TaskTracker contract: wait
        // only resolves once `close` has been called AND the in-flight
        // count is zero). Closing is safe here because the accept loops
        // have already exited above, so no new spawns can land.
        self.conn_tracker.close();
        match drain_timeout {
            Some(t) if !t.is_zero() => {
                let drained = tokio::time::timeout(t, self.conn_tracker.wait()).await;
                let remaining = self.conn_tracker.len();
                match drained {
                    Ok(()) => {
                        tracing::debug!(
                            rule = %self.rule.name,
                            "TCP graceful drain complete: all connections finished naturally"
                        );
                    }
                    Err(_elapsed) => {
                        tracing::warn!(
                            rule = %self.rule.name,
                            timeout_secs = t.as_secs(),
                            remaining,
                            "TCP graceful drain timeout expired; cancelling surviving connections"
                        );
                        self.conn_cancel.cancel();
                        // Short final wait to let the now-cancelled
                        // tasks observe the signal and exit cleanly.
                        let _ = tokio::time::timeout(
                            Duration::from_millis(250),
                            self.conn_tracker.wait(),
                        )
                        .await;
                    }
                }
            }
            _ => {
                // Legacy behaviour: tear in-flight connections down
                // immediately so the runtime drop on exit doesn't
                // have to abort them.
                self.conn_cancel.cancel();
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_accept_loop(
    rule: Arc<Rule>,
    resolver: UpstreamResolver,
    listener: TcpListener,
    local_addr: SocketAddr,
    worker_id: usize,
    expect_inbound_proxy: bool,
    accept_cancel: CancellationToken,
    conn_cancel: CancellationToken,
    conn_tracker: TaskTracker,
    arm_table: Arc<CanaryArmTable>,
) {
    loop {
        tokio::select! {
            biased;
            _ = accept_cancel.cancelled() => {
                tracing::debug!(rule = %rule.name, worker = worker_id, "TCP accept loop received cancel");
                return;
            }
            res = listener.accept() => {
                let (client, client_addr) = match res {
                    Ok(c) => c,
                    Err(e) => {
                        // Common transient errors: too many open files,
                        // peer reset before accept(). Log + continue —
                        // bringing down the listener over a single EBADF
                        // would amplify whatever caused the error.
                        tracing::warn!(rule = %rule.name, worker = worker_id, error = %e, "TCP accept failed");
                        metrics::counter!(
                            "yggdrasil_tcp_accept_errors_total",
                            "rule" => rule.name.clone(),
                            "worker" => worker_id.to_string(),
                        )
                        .increment(1);
                        continue;
                    }
                };
                metrics::counter!(
                    "yggdrasil_tcp_accept_total",
                    "rule" => rule.name.clone(),
                    "worker" => worker_id.to_string(),
                )
                .increment(1);

                // Canary fast-path: when at least one canary is in
                // flight against this rule's `(listen, Tcp)`, peek
                // the first 32 bytes of the connection and route
                // matching probe traffic to an in-process echo
                // instead of dialing the configured backend.
                //
                // The cold path (no canary armed, the steady state)
                // is a single DashMap shard probe; once that returns
                // `false`, we skip the peek entirely and proceed to
                // the existing resolver/forwarding logic with no
                // added cost.
                if arm_table.is_armed(local_addr, Protocol::Tcp) {
                    match peek_and_match_canary_token(&client, &arm_table, local_addr).await {
                        Some(matched_token) => {
                            tracing::debug!(
                                rule = %rule.name,
                                worker = worker_id,
                                client = %client_addr,
                                "canary token matched; routing to in-process echo"
                            );
                            metrics::counter!(
                                "yggdrasil_tcp_canary_echo_total",
                                "rule" => rule.name.clone(),
                            )
                            .increment(1);
                            let conn_rule = Arc::clone(&rule);
                            let task_conn_cancel = conn_cancel.clone();
                            conn_tracker.spawn(async move {
                                run_canary_echo(
                                    conn_rule,
                                    client,
                                    client_addr,
                                    matched_token,
                                    task_conn_cancel,
                                )
                                .await;
                            });
                            continue;
                        }
                        None => {
                            // No matching token (or peek timed out /
                            // returned < CANARY_TOKEN_LEN bytes). Fall
                            // through to normal forwarding; the peek
                            // does not consume buffered bytes so the
                            // upstream's `copy_bidirectional` sees
                            // them verbatim.
                        }
                    }
                }

                let target_addr = match resolver.current_target() {
                    Some(addr) => addr,
                    None => {
                        // Relay before first heartbeat. (Static resolvers
                        // always return Some.)
                        tracing::debug!(
                            rule = %rule.name,
                            worker = worker_id,
                            client = %client_addr,
                            "drop connection: upstream not yet resolvable (no heartbeat received)"
                        );
                        metrics::counter!(
                            "yggdrasil_tcp_dropped_no_peer_total",
                            "rule" => rule.name.clone(),
                        )
                        .increment(1);
                        // Tokio drops `client` here → socket close.
                        continue;
                    }
                };
                // Cheap clones: `Arc::clone` is a single atomic increment,
                // and `CancellationToken::clone` is also an `Arc` clone (no
                // child-token registration, which would add a parent-side
                // linked-list entry + drop hook per connection — pure
                // overhead for our use case since nothing cancels an
                // individual connection independently of the worker).
                //
                // Per-connection tasks observe `conn_cancel`, NOT the
                // accept loop's cancel — so the drain path can stop
                // accepting without instantly aborting in-flight
                // conversations.
                let conn_rule = Arc::clone(&rule);
                let task_conn_cancel = conn_cancel.clone();
                // Spawn through the TaskTracker so the parent TcpProxy
                // can wait on the in-flight set during graceful drain.
                // Tracker tracking is a single atomic counter
                // increment+decrement per spawn; no per-task linked
                // list or registration.
                conn_tracker.spawn(async move {
                    handle_connection(
                        conn_rule,
                        client,
                        client_addr,
                        target_addr,
                        local_addr,
                        expect_inbound_proxy,
                        task_conn_cancel,
                    )
                    .await;
                });
            }
        }
    }
}

/// Peek the first [`CANARY_TOKEN_LEN`] bytes of an accepted connection
/// without consuming them, and check whether they match a live arm in
/// the table. Returns `Some(token)` on match and `None` otherwise
/// (no match, peek timeout, or fewer than `CANARY_TOKEN_LEN` bytes
/// available within [`CANARY_PEEK_TIMEOUT`]).
///
/// The peek leaves the kernel receive buffer intact, so connections
/// that fall through this check have all their bytes available for
/// the normal `copy_bidirectional` forwarding path.
async fn peek_and_match_canary_token(
    client: &TcpStream,
    arm_table: &CanaryArmTable,
    local_addr: SocketAddr,
) -> Option<[u8; CANARY_TOKEN_LEN]> {
    let mut buf = [0u8; CANARY_TOKEN_LEN];
    let peeked = tokio::time::timeout(CANARY_PEEK_TIMEOUT, client.peek(&mut buf)).await;
    let n = match peeked {
        Ok(Ok(n)) => n,
        Ok(Err(_)) | Err(_) => return None,
    };
    if n < CANARY_TOKEN_LEN {
        return None;
    }
    if arm_table.match_token(local_addr, Protocol::Tcp, &buf) {
        Some(buf)
    } else {
        None
    }
}

/// In-process echo handler for a canary-matched TCP connection.
/// Reads (and discards) the [`CANARY_TOKEN_LEN`]-byte token prefix
/// that triggered the match, then loops reading bytes from the client
/// and writing them straight back until either side closes or the
/// drain cancel fires.
///
/// The configured backend is never contacted — the entire conversation
/// stays in-process, which is the point of `chain canary`: it tests
/// the rule's data path without depending on the rule's actual
/// backend being reachable.
async fn run_canary_echo(
    rule: Arc<Rule>,
    mut client: TcpStream,
    client_addr: SocketAddr,
    _matched_token: [u8; CANARY_TOKEN_LEN],
    cancel: CancellationToken,
) {
    // Consume the token bytes from the kernel buffer so the echo
    // loop sees only the probe payload.
    let mut token_drain = [0u8; CANARY_TOKEN_LEN];
    if let Err(e) = client.read_exact(&mut token_drain).await {
        tracing::debug!(
            rule = %rule.name,
            client = %client_addr,
            error = %e,
            "canary echo: failed to drain token prefix"
        );
        return;
    }

    let (mut read_half, mut write_half) = client.split();
    tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            tracing::debug!(
                rule = %rule.name,
                client = %client_addr,
                "canary echo: cancel signal, tearing down"
            );
        }
        res = tokio::io::copy(&mut read_half, &mut write_half) => {
            match res {
                Ok(n) => tracing::debug!(
                    rule = %rule.name,
                    client = %client_addr,
                    bytes_echoed = n,
                    "canary echo complete"
                ),
                Err(e) => tracing::debug!(
                    rule = %rule.name,
                    client = %client_addr,
                    error = %e,
                    "canary echo: io error"
                ),
            }
        }
    }
    // Half-close write side so the client's `read` returns EOF.
    let _ = write_half.shutdown().await;
}

/// Bind `workers` TCP listeners on `addr`. With `workers == 1` falls back
/// to a single `TcpListener::bind` (no SO_REUSEPORT setup, matches the
/// pre-fan-out behaviour byte-for-byte). With `workers > 1` uses
/// `socket2` to set `SO_REUSEADDR + SO_REUSEPORT` on each socket so the
/// kernel hash-distributes incoming SYNs across them.
async fn build_tcp_listener_sockets(
    addr: SocketAddr,
    workers: usize,
) -> io::Result<Vec<TcpListener>> {
    debug_assert!(workers > 0);
    if workers == 1 {
        return TcpListener::bind(addr).await.map(|l| vec![l]);
    }

    let mut listeners = Vec::with_capacity(workers);
    let first = build_tcp_listener_socket(addr)?;
    let bind_addr = first.local_addr()?;
    listeners.push(first);
    for _ in 1..workers {
        listeners.push(build_tcp_listener_socket(bind_addr)?);
    }
    Ok(listeners)
}

fn build_tcp_listener_socket(addr: SocketAddr) -> io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = Domain::for_address(addr);
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(LISTEN_BACKLOG)?;
    let std_sock: std::net::TcpListener = sock.into();
    TcpListener::from_std(std_sock)
}

async fn handle_connection(
    rule: Arc<Rule>,
    mut client: TcpStream,
    mut client_addr: SocketAddr,
    target_addr: SocketAddr,
    server_listen: SocketAddr,
    expect_inbound_proxy: bool,
    cancel: CancellationToken,
) {
    // Connect to upstream first. If this fails, close the client without
    // sending anything (no PROXY-protocol header, no half-open).
    let connect_start = std::time::Instant::now();
    let mut upstream = match TcpStream::connect(target_addr).await {
        Ok(s) => {
            metrics::histogram!(
                "yggdrasil_tcp_upstream_connect_seconds",
                "rule" => rule.name.clone(),
                "result" => "ok",
            )
            .record(connect_start.elapsed().as_secs_f64());
            s
        }
        Err(e) => {
            metrics::histogram!(
                "yggdrasil_tcp_upstream_connect_seconds",
                "rule" => rule.name.clone(),
                "result" => "error",
            )
            .record(connect_start.elapsed().as_secs_f64());
            metrics::counter!(
                "yggdrasil_tcp_upstream_connect_errors_total",
                "rule" => rule.name.clone(),
            )
            .increment(1);
            tracing::warn!(
                rule = %rule.name,
                client = %client_addr,
                upstream = %target_addr,
                error = %e,
                "upstream connect failed"
            );
            return;
        }
    };

    // Multi-hop client-IP recovery: on a mid-chain relay, the upstream
    // chain hop prepends a PROXY-v2 header to each new connection. Peel
    // it off and use the decoded client when synthesising our own
    // outbound PROXY emission below, so the next hop sees the real
    // client rather than us.
    //
    // We only do this read when the caller explicitly expects an
    // inbound PROXY header (`expect_inbound_proxy = true`). Without
    // that gate, a server-speaks-first protocol (FTP / SMTP / MySQL
    // banner / etc.) — or any test that opens a TCP without sending —
    // would block here forever waiting for the client to send a byte
    // that never comes. `expect_inbound_proxy` is only set on
    // mid-chain Relay nodes for chain-derived rules where the
    // upstream Gateway / Relay always emits PROXY-v2.
    let leftover = if expect_inbound_proxy {
        match proxy_protocol::read_optional_header(&mut client).await {
            Ok(decode) => {
                if let Some(endpoints) = decode.endpoints {
                    client_addr = endpoints.client;
                }
                decode.leftover
            }
            Err(e) => {
                tracing::warn!(
                    rule = %rule.name,
                    client = %client_addr,
                    upstream = %target_addr,
                    error = %e,
                    "inbound PROXY-protocol read failed"
                );
                return;
            }
        }
    } else {
        Vec::new()
    };

    // PROXY-protocol header (if configured) goes out before any client bytes.
    if let Some(version) = rule.proxy_protocol {
        if let Err(e) =
            proxy_protocol::write_header(&mut upstream, version, client_addr, server_listen).await
        {
            tracing::warn!(
                rule = %rule.name,
                client = %client_addr,
                upstream = %target_addr,
                version = ?version,
                error = %e,
                "PROXY-protocol header write failed"
            );
            return;
        }
    }

    // Re-inject any bytes that `read_optional_header` peeked but did
    // not consume as PROXY (the lookalike-rejection paths return up to
    // 12 bytes here). Without this the upstream would miss the start
    // of the application stream.
    if !leftover.is_empty() {
        if let Err(e) = upstream.write_all(&leftover).await {
            tracing::warn!(
                rule = %rule.name,
                client = %client_addr,
                upstream = %target_addr,
                error = %e,
                "leftover-from-PROXY-peek write to upstream failed"
            );
            return;
        }
    }

    // Disable Nagle on both sides for latency-sensitive payloads. Most game
    // protocols want this; bulk-transfer cases will be measurement-driven
    // (the bench harness will tell us if this hurts iperf-style tests, in
    // which case we'll gate it behind a per-rule option).
    let _ = client.set_nodelay(true);
    let _ = upstream.set_nodelay(true);

    let pumping = copy_bidirectional_with_sizes(
        &mut client,
        &mut upstream,
        FORWARD_BUFFER_SIZE,
        FORWARD_BUFFER_SIZE,
    );
    tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            tracing::debug!(
                rule = %rule.name,
                client = %client_addr,
                "connection cancelled during shutdown"
            );
        }
        res = pumping => match res {
            Ok((c2u, u2c)) => {
                metrics::counter!(
                    "yggdrasil_tcp_bytes_total",
                    "rule" => rule.name.clone(),
                    "direction" => "client_to_upstream",
                )
                .increment(c2u);
                metrics::counter!(
                    "yggdrasil_tcp_bytes_total",
                    "rule" => rule.name.clone(),
                    "direction" => "upstream_to_client",
                )
                .increment(u2c);
                tracing::debug!(
                    rule = %rule.name,
                    client = %client_addr,
                    upstream = %target_addr,
                    client_to_upstream_bytes = c2u,
                    upstream_to_client_bytes = u2c,
                    "TCP connection closed cleanly"
                );
            }
            Err(e) if is_benign_close(&e) => {
                tracing::trace!(
                    rule = %rule.name,
                    client = %client_addr,
                    upstream = %target_addr,
                    error = %e,
                    "TCP connection closed (peer reset or shutdown)"
                );
            }
            Err(e) => {
                tracing::warn!(
                    rule = %rule.name,
                    client = %client_addr,
                    upstream = %target_addr,
                    error = %e,
                    "TCP copy_bidirectional failed"
                );
            }
        }
    }
}

fn is_benign_close(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatoskr::rule::ProxyProto;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::heartbeat::PeerState;

    /// Build a dynamic resolver for relay tests — mirrors the production
    /// `ResolverFactory::new_relay(...).build(rule)` path without dragging
    /// the factory machinery into per-proxy unit tests.
    fn dynamic_resolver(peer: Arc<PeerState>, port: u16) -> UpstreamResolver {
        UpstreamResolver::Dynamic {
            peer_state: peer,
            port,
        }
    }

    /// Static resolver for terminal-style tests.
    fn static_resolver(addr: SocketAddr) -> UpstreamResolver {
        UpstreamResolver::Static { addr }
    }

    async fn echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = sock.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        (addr, handle)
    }

    /// Build a rule that listens on `127.0.0.1:0` (kernel-assigned port) and
    /// forwards to `127.0.0.1:target_port`.
    fn rule(name: &str, target_port: u16, proxy_protocol: Option<ProxyProto>) -> Rule {
        use std::str::FromStr;
        let f = ratatoskr::rule::RuleFile::from_toml(
            "test.toml",
            &format!(
                r#"
                [[rule]]
                name = "{name}"
                listen = "127.0.0.1:0"
                protocol = "tcp"
                target_port = {target_port}
                {}
                "#,
                proxy_protocol
                    .map(|p| format!(
                        "proxy_protocol = \"{}\"",
                        match p {
                            ProxyProto::V1 => "v1",
                            ProxyProto::V2 => "v2",
                        }
                    ))
                    .unwrap_or_default()
            ),
        )
        .unwrap();
        let mut r = f.rule.into_iter().next().unwrap();
        // Force a stable test name path independent of the toml form above.
        r.name = name.to_string();
        // Listen on an OS-assigned port even if the literal "0" gets canonicalised.
        r.listen = SocketAddr::from_str("127.0.0.1:0").unwrap();
        r
    }

    #[tokio::test]
    async fn proxies_bytes_bidirectionally() {
        let (upstream, _us) = echo_server().await;
        let peer = PeerState::new(None);
        let _ = peer.record_heartbeat("127.0.0.1:9999".parse().unwrap());

        let proxy = TcpProxy::spawn(
            rule("echo", upstream.port(), None),
            dynamic_resolver(peer, upstream.port()),
            1,
        )
        .await
        .unwrap();
        let listen = proxy.local_addr();

        let mut client = TcpStream::connect(listen).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        proxy.stop(None).await;
    }

    #[tokio::test]
    async fn drops_connection_when_no_peer_yet() {
        let (upstream, _us) = echo_server().await;
        let peer = PeerState::new(None);
        // Note: no record_heartbeat call → current_ip is None.

        let proxy = TcpProxy::spawn(
            rule("nopeer", upstream.port(), None),
            dynamic_resolver(peer, upstream.port()),
            1,
        )
        .await
        .unwrap();
        let listen = proxy.local_addr();

        // The accept succeeds (we want listeners up for debugging), then
        // the proxy task drops the socket. The client either sees EOF on a
        // read or a write that succeeds but goes nowhere.
        let mut client = TcpStream::connect(listen).await.unwrap();
        let _ = client.write_all(b"hi").await; // may or may not error
        let mut buf = [0u8; 1];
        let r = tokio::time::timeout(Duration::from_millis(500), client.read(&mut buf))
            .await
            .expect("read timed out");
        match r {
            Ok(0) => {} // EOF — expected
            Ok(n) => panic!("read returned {n} bytes; expected EOF"),
            Err(e) => {
                // Connection reset is also acceptable.
                assert!(
                    matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                    ),
                    "unexpected error kind: {:?}",
                    e.kind()
                );
            }
        }
        proxy.stop(None).await;
    }

    #[tokio::test]
    async fn emits_proxy_protocol_v1_header_to_upstream() {
        // Custom upstream that captures the first bytes it receives.
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = upstream.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut buf = Vec::new();
            // Read until \r\n so we capture exactly the v1 header.
            let mut byte = [0u8; 1];
            loop {
                let n = sock.read(&mut byte).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n") {
                    break;
                }
                if buf.len() > 200 {
                    break;
                }
            }
            let _ = tx.send(buf);
        });

        let peer = PeerState::new(None);
        let _ = peer.record_heartbeat("127.0.0.1:9999".parse().unwrap());
        let proxy = TcpProxy::spawn(
            rule("v1head", target_addr.port(), Some(ProxyProto::V1)),
            dynamic_resolver(peer, target_addr.port()),
            1,
        )
        .await
        .unwrap();
        let listen = proxy.local_addr();
        let _client = TcpStream::connect(listen).await.unwrap();

        let header = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("header timeout")
            .expect("oneshot dropped");
        let s = std::str::from_utf8(&header).unwrap();
        assert!(
            s.starts_with("PROXY TCP4 127.0.0.1 127.0.0.1 "),
            "unexpected header: {s:?}"
        );
        assert!(s.ends_with("\r\n"));

        proxy.stop(None).await;
    }

    /// Multi-hop client-IP bridging: when `expect_inbound_proxy = true`,
    /// the proxy reads any PROXY-v2 header the upstream chain hop
    /// prepended and uses the decoded client when emitting its own
    /// outbound PROXY-v2 header. The next hop downstream sees the
    /// ORIGINAL client (not the previous hop's address), so 3+ hop
    /// chains preserve the real client IP all the way to the terminal.
    #[tokio::test]
    async fn bridges_inbound_proxy_v2_to_outbound() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = upstream.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 28];
            sock.read_exact(&mut buf).await.unwrap();
            let _ = tx.send(buf);
        });

        let peer = PeerState::new(None);
        let _ = peer.record_heartbeat("127.0.0.1:9999".parse().unwrap());
        let proxy = TcpProxy::spawn_with_arm_table(
            rule("midhop", target_addr.port(), Some(ProxyProto::V2)),
            dynamic_resolver(peer, target_addr.port()),
            1,
            true,
            Arc::new(CanaryArmTable::new()),
        )
        .await
        .unwrap();
        let listen = proxy.local_addr();

        let real_client: SocketAddr = "203.0.113.45:54321".parse().unwrap();
        let server_dst: SocketAddr = "198.51.100.4:443".parse().unwrap();
        let inbound_header =
            crate::proxy::proxy_protocol::encode_header(ProxyProto::V2, real_client, server_dst);

        let mut client = TcpStream::connect(listen).await.unwrap();
        client.write_all(&inbound_header).await.unwrap();

        let outbound = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("outbound timeout")
            .expect("oneshot dropped");

        let decoded =
            crate::proxy::proxy_protocol::decode_v2_from_datagram(&outbound).expect("decode v2");
        assert_eq!(decoded.client, real_client);
        assert_eq!(decoded.server, listen);

        proxy.stop(None).await;
    }

    /// Sanity: when `expect_inbound_proxy = false` (the default —
    /// Gateway-mode or any non-chain TCP proxy), an inbound PROXY-v2
    /// header is NOT consumed. It would be forwarded as application
    /// bytes. This is the correctness invariant that lets
    /// server-speaks-first protocols (SMTP, FTP, MySQL banner) keep
    /// working alongside chain HTTPS in the same daemon.
    #[tokio::test]
    async fn does_not_consume_inbound_proxy_when_flag_off() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = upstream.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 56];
            sock.read_exact(&mut buf).await.unwrap();
            let _ = tx.send(buf);
        });

        let peer = PeerState::new(None);
        let _ = peer.record_heartbeat("127.0.0.1:9999".parse().unwrap());
        let proxy = TcpProxy::spawn(
            rule("gateway-mode", target_addr.port(), Some(ProxyProto::V2)),
            dynamic_resolver(peer, target_addr.port()),
            1,
        )
        .await
        .unwrap();
        let listen = proxy.local_addr();

        let inbound_header = crate::proxy::proxy_protocol::encode_header(
            ProxyProto::V2,
            "203.0.113.45:54321".parse().unwrap(),
            "198.51.100.4:443".parse().unwrap(),
        );
        let mut client = TcpStream::connect(listen).await.unwrap();
        client.write_all(&inbound_header).await.unwrap();

        let outbound = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("outbound timeout")
            .expect("oneshot dropped");

        let our_proxy = &outbound[..28];
        let decoded = crate::proxy::proxy_protocol::decode_v2_from_datagram(our_proxy)
            .expect("decode our outbound v2");
        assert_eq!(
            decoded.client.ip().to_string(),
            "127.0.0.1",
            "outbound PROXY must carry our kernel-observed peer when expect_inbound_proxy=false"
        );
        assert_eq!(
            &outbound[28..56],
            inbound_header.as_slice(),
            "inbound PROXY bytes should pass through to upstream untouched when flag is off"
        );

        proxy.stop(None).await;
    }

    #[tokio::test]
    async fn closes_when_upstream_unreachable() {
        let peer = PeerState::new(None);
        let _ = peer.record_heartbeat("127.0.0.1:9999".parse().unwrap());
        // Port 1 is reserved and won't have anything listening on a normal box.
        let proxy = TcpProxy::spawn(rule("noupstream", 1, None), dynamic_resolver(peer, 1), 1)
            .await
            .unwrap();
        let listen = proxy.local_addr();

        let mut client = TcpStream::connect(listen).await.unwrap();
        let mut buf = [0u8; 1];
        let r = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("read timed out — proxy did not close client after upstream failure");
        match r {
            Ok(0) => {}
            Ok(n) => panic!("read returned {n} bytes"),
            Err(e) => assert!(
                matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ),
                "unexpected kind {:?}",
                e.kind()
            ),
        }
        proxy.stop(None).await;
    }

    #[tokio::test]
    async fn stop_cancels_in_flight_connection() {
        let (upstream, _us) = echo_server().await;
        let peer = PeerState::new(None);
        let _ = peer.record_heartbeat("127.0.0.1:9999".parse().unwrap());
        let proxy = TcpProxy::spawn(
            rule("cancel", upstream.port(), None),
            dynamic_resolver(peer, upstream.port()),
            1,
        )
        .await
        .unwrap();
        let listen = proxy.local_addr();
        let mut client = TcpStream::connect(listen).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();

        // Stop the proxy. The accept loop exits; the existing connection
        // task receives cancellation (it was a child token of the loop's
        // cancellation token).
        proxy.stop(None).await;

        // The client connection should EOF promptly.
        let mut buf = [0u8; 1];
        let r = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("read timed out");
        match r {
            Ok(0) => {}
            Ok(n) => panic!("read returned {n} bytes"),
            Err(e) => assert!(
                matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ),
                "unexpected kind {:?}",
                e.kind()
            ),
        }
    }

    #[tokio::test]
    async fn fan_out_distributes_accepts_across_workers() {
        // With workers > 1, the four sockets all bind the same (addr, port)
        // via SO_REUSEPORT and the kernel hash-distributes incoming SYNs
        // across them. We don't try to assert *which* worker sees a given
        // connect (that depends on the kernel hash); we just confirm:
        //   1. spawn(workers=4) succeeds (proves four reuseport-binds
        //      worked on the same port);
        //   2. echo round-trips still succeed after fan-out;
        //   3. stop() awaits all worker tasks.
        let (upstream, _us) = echo_server().await;
        let peer = PeerState::new(None);
        let _ = peer.record_heartbeat("127.0.0.1:9999".parse().unwrap());

        let proxy = TcpProxy::spawn(
            rule("fanout", upstream.port(), None),
            dynamic_resolver(peer, upstream.port()),
            4,
        )
        .await
        .unwrap();
        let listen = proxy.local_addr();

        // Sixteen sequential connect+echo cycles; with reuseport, SYNs land
        // across the four worker accept queues. The test only cares that
        // every cycle round-trips, not which worker handled which.
        for i in 0..16u8 {
            let mut client = TcpStream::connect(listen).await.unwrap();
            let payload = [i, i.wrapping_add(1), i.wrapping_add(2), i.wrapping_add(3)];
            client.write_all(&payload).await.unwrap();
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, payload, "round-trip mismatch on iteration {i}");
        }

        proxy.stop(None).await;
    }

    /// Graceful-drain happy path: an in-flight bidirectional copy
    /// completes naturally during `stop(Some(timeout))`, and `stop`
    /// returns once the connection finishes — well within the
    /// timeout budget.
    #[tokio::test]
    async fn graceful_drain_lets_inflight_connection_finish() {
        let (upstream, _us) = echo_server().await;
        let peer = PeerState::new(None);
        let _ = peer.record_heartbeat("127.0.0.1:9999".parse().unwrap());

        let proxy = TcpProxy::spawn(
            rule("echo", upstream.port(), None),
            dynamic_resolver(peer, upstream.port()),
            1,
        )
        .await
        .unwrap();
        let listen = proxy.local_addr();

        let mut client = TcpStream::connect(listen).await.unwrap();
        client.write_all(b"hi").await.unwrap();
        let mut buf = [0u8; 2];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi");

        // Close the client's write side so the proxy's `copy_bidirectional`
        // sees EOF and terminates. Without this nudge the connection task
        // would hang on the kernel forever and the drain timeout would
        // fire instead — that's covered by the next test.
        client.shutdown().await.unwrap();

        let stop_start = std::time::Instant::now();
        proxy.stop(Some(Duration::from_secs(5))).await;
        let elapsed = stop_start.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "graceful drain should return promptly when conn finishes; took {elapsed:?}"
        );
    }

    /// Graceful-drain timeout path: an in-flight connection is
    /// deliberately stuck (peer never sends EOF and never reads),
    /// so the drain window expires. `stop(Some(timeout))` must
    /// return within `timeout` rather than waiting indefinitely.
    #[tokio::test]
    async fn graceful_drain_returns_when_timeout_expires() {
        let (upstream, _us) = echo_server().await;
        let peer = PeerState::new(None);
        let _ = peer.record_heartbeat("127.0.0.1:9999".parse().unwrap());

        let proxy = TcpProxy::spawn(
            rule("echo", upstream.port(), None),
            dynamic_resolver(peer, upstream.port()),
            1,
        )
        .await
        .unwrap();
        let listen = proxy.local_addr();

        // Open a connection and keep both ends parked. We don't
        // write anything; the proxy task is blocked in
        // copy_bidirectional waiting for bytes that never come.
        let client = TcpStream::connect(listen).await.unwrap();
        // Give the accept loop a moment to actually spawn the per-conn
        // task; without it stop() races and the tracker may be empty
        // when we drain. The proxy doesn't expose its TaskTracker
        // count, so this is the irreducible "wait for accept" budget.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let drain_budget = Duration::from_millis(250);
        let stop_start = std::time::Instant::now();
        proxy.stop(Some(drain_budget)).await;
        let elapsed = stop_start.elapsed();
        // Must have waited at least the drain window before giving up.
        assert!(
            elapsed >= drain_budget,
            "stop returned too fast ({elapsed:?}); should have waited at least {drain_budget:?}"
        );
        // Must NOT have waited multiples of the window (no hang).
        assert!(
            elapsed < drain_budget * 4,
            "stop hung past the drain budget ({elapsed:?} vs budget {drain_budget:?})"
        );
        drop(client);
    }

    // ---- Canary intercept ----

    #[tokio::test]
    async fn canary_armed_token_match_routes_to_in_process_echo() {
        // No backend exists at all — `target_port = 1` is intentionally
        // unreachable. If the canary fast path is wired correctly the
        // client still sees its bytes echoed.
        let arm_table = Arc::new(CanaryArmTable::new());
        let proxy = TcpProxy::spawn_with_arm_table(
            rule("canary-tcp", 1, None),
            static_resolver("127.0.0.1:1".parse().unwrap()),
            1,
            false,
            Arc::clone(&arm_table),
        )
        .await
        .unwrap();
        let listen = proxy.local_addr();

        let token = [0xABu8; CANARY_TOKEN_LEN];
        arm_table.arm(listen, Protocol::Tcp, token, Duration::from_secs(5));

        let mut client = TcpStream::connect(listen).await.unwrap();
        // Send the 32-byte token + a payload; expect the payload back.
        client.write_all(&token).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        proxy.stop(None).await;
    }

    #[tokio::test]
    async fn canary_unarmed_table_forwards_normally_even_with_token_prefix() {
        // Arm-table empty: the fast path should be skipped entirely
        // and the (random-looking) prefix forwarded verbatim to the
        // backend's echo server. End-to-end semantics match the
        // plain proxy.
        let (upstream, _us) = echo_server().await;
        let arm_table = Arc::new(CanaryArmTable::new());
        let proxy = TcpProxy::spawn_with_arm_table(
            rule("canary-cold", upstream.port(), None),
            static_resolver(upstream),
            1,
            false,
            arm_table,
        )
        .await
        .unwrap();
        let listen = proxy.local_addr();

        let token = [0xCDu8; CANARY_TOKEN_LEN];
        let mut client = TcpStream::connect(listen).await.unwrap();
        client.write_all(&token).await.unwrap();
        client.write_all(b"world").await.unwrap();
        let mut buf = [0u8; CANARY_TOKEN_LEN + 5];
        client.read_exact(&mut buf).await.unwrap();
        // Token bytes pass through the echo server too — the proxy
        // did NOT consume them.
        assert_eq!(&buf[..CANARY_TOKEN_LEN], &token);
        assert_eq!(&buf[CANARY_TOKEN_LEN..], b"world");

        proxy.stop(None).await;
    }

    #[tokio::test]
    async fn canary_armed_with_wrong_token_falls_through_to_backend() {
        // Arm with one token but send a different prefix: the peek
        // is performed (table is "hot") but match_token returns
        // false, so traffic forwards to the backend. The peek must
        // not have consumed the bytes; the backend's echo sees them
        // verbatim.
        let (upstream, _us) = echo_server().await;
        let arm_table = Arc::new(CanaryArmTable::new());
        let proxy = TcpProxy::spawn_with_arm_table(
            rule("canary-wrong-token", upstream.port(), None),
            static_resolver(upstream),
            1,
            false,
            Arc::clone(&arm_table),
        )
        .await
        .unwrap();
        let listen = proxy.local_addr();

        let armed_token = [0x11u8; CANARY_TOKEN_LEN];
        arm_table.arm(listen, Protocol::Tcp, armed_token, Duration::from_secs(5));

        let unrelated_prefix = [0x22u8; CANARY_TOKEN_LEN];
        let mut client = TcpStream::connect(listen).await.unwrap();
        client.write_all(&unrelated_prefix).await.unwrap();
        client.write_all(b"abc").await.unwrap();
        let mut buf = [0u8; CANARY_TOKEN_LEN + 3];
        client.read_exact(&mut buf).await.unwrap();
        // Backend's echo returned both the prefix bytes and the
        // payload verbatim — proves the peek did not consume them.
        assert_eq!(&buf[..CANARY_TOKEN_LEN], &unrelated_prefix);
        assert_eq!(&buf[CANARY_TOKEN_LEN..], b"abc");

        proxy.stop(None).await;
    }

    #[tokio::test]
    async fn canary_armed_short_client_send_falls_through() {
        // Arm the table, then have the client send fewer than
        // CANARY_TOKEN_LEN bytes within the peek timeout. The peek
        // returns < 32 bytes; we fall through to the backend, which
        // echoes the partial payload back.
        let (upstream, _us) = echo_server().await;
        let arm_table = Arc::new(CanaryArmTable::new());
        let proxy = TcpProxy::spawn_with_arm_table(
            rule("canary-short", upstream.port(), None),
            static_resolver(upstream),
            1,
            false,
            Arc::clone(&arm_table),
        )
        .await
        .unwrap();
        let listen = proxy.local_addr();

        arm_table.arm(
            listen,
            Protocol::Tcp,
            [0x33u8; CANARY_TOKEN_LEN],
            Duration::from_secs(5),
        );

        let mut client = TcpStream::connect(listen).await.unwrap();
        // Short payload; less than CANARY_TOKEN_LEN bytes. Peek
        // timeout fires; we fall through.
        client.write_all(b"hi").await.unwrap();
        // The peek timeout is short (200ms); after that the proxy
        // will dial the backend and start forwarding. Wait long
        // enough to clear the peek window.
        let mut buf = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut buf))
            .await
            .expect("read should complete after peek timeout")
            .expect("backend echo should succeed");
        assert_eq!(&buf, b"hi");

        proxy.stop(None).await;
    }
}
