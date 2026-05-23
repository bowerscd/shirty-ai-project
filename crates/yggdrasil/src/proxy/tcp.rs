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
//!    log so listeners stay up for debugging. Bump `tcp_connect_no_peer_total`
//!    (Phase 9).
//! 3. `TcpStream::connect(target)`. On error, log + close the client. Bump
//!    `tcp_connect_failed_total`.
//! 4. If `rule.proxy_protocol` is set, write the header to the upstream
//!    stream before any application bytes.
//! 5. `tokio::io::copy_bidirectional(client, upstream)` until either side
//!    EOFs or errors. Bump byte counters in both directions (Phase 9).
//!
//! On dial-target change (relay IP-change), in-flight TCP connections are
//! **left alone** — the application layer is already broken because the
//! upstream IP changed; force-closing the socket adds no signal beyond what
//! the network already delivered. New accepts pick up the new target.
//! Terminal-mode resolvers never change their target, so the question is
//! moot there.

use std::io;
use std::net::SocketAddr;

use anyhow::{ensure, Context, Result};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use ratatoskr::rule::Rule;

use super::proxy_protocol;
use super::resolver::UpstreamResolver;

/// Per-listener backlog. 1024 is the default Linux `somaxconn`; higher
/// values are silently capped by the kernel unless the operator raises
/// `net.core.somaxconn`. Matches what tokio's `TcpListener::bind` requests.
const LISTEN_BACKLOG: i32 = 1024;

/// Handle to a running per-rule TCP proxy. Drop to stop (the cancellation
/// token cascade aborts the accept loops and lets in-flight connections
/// finish naturally).
pub struct TcpProxy {
    rule: Rule,
    cancel: CancellationToken,
    local_addr: SocketAddr,
    /// One handle per accept worker. `stop()` awaits all of them.
    worker_handles: Vec<tokio::task::JoinHandle<()>>,
}

impl TcpProxy {
    /// Bind `workers` listeners (via SO_REUSEPORT when `workers > 1`) and
    /// spawn one accept loop per listener. Returns once every socket is
    /// listening, so callers can rely on connect attempts succeeding
    /// immediately after this resolves. `workers == 0` is rejected.
    pub async fn spawn(rule: Rule, resolver: UpstreamResolver, workers: usize) -> Result<Self> {
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

        let cancel = CancellationToken::new();
        let mut worker_handles = Vec::with_capacity(effective_workers);
        for (worker_id, listener) in listeners.into_iter().enumerate() {
            let task_cancel = cancel.clone();
            let task_rule = rule.clone();
            let task_resolver = resolver.clone();
            let task_local = local_addr;
            let handle = tokio::spawn(async move {
                run_accept_loop(
                    task_rule,
                    task_resolver,
                    listener,
                    task_local,
                    worker_id,
                    task_cancel,
                )
                .await;
            });
            worker_handles.push(handle);
        }

        tracing::info!(
            rule = %rule.name,
            listen = %local_addr,
            upstream = %resolver.describe(),
            proxy_protocol = ?rule.proxy_protocol,
            workers = effective_workers,
            "TCP rule listening"
        );

        metrics::gauge!(
            "yggdrasil_workers",
            "rule" => rule.name.clone(),
            "protocol" => "tcp",
        )
        .set(effective_workers as f64);

        Ok(Self {
            rule,
            cancel,
            local_addr,
            worker_handles,
        })
    }

    pub fn rule(&self) -> &Rule {
        &self.rule
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Trigger shutdown. Does NOT wait for in-flight connections — call
    /// [`TcpProxy::stop`] to await full shutdown of the accept loops.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Cancel and wait for every accept loop to exit. In-flight
    /// per-connection tasks are cancelled via the same cascade and given
    /// a chance to drain, but this method does not wait for them.
    pub async fn stop(self) {
        self.cancel.cancel();
        for handle in self.worker_handles {
            let _ = handle.await;
        }
    }
}

async fn run_accept_loop(
    rule: Rule,
    resolver: UpstreamResolver,
    listener: TcpListener,
    local_addr: SocketAddr,
    worker_id: usize,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
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
                        continue;
                    }
                };

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
                        // Tokio drops `client` here → socket close.
                        continue;
                    }
                };
                let conn_rule = rule.clone();
                let conn_cancel = cancel.child_token();
                tokio::spawn(async move {
                    handle_connection(
                        conn_rule,
                        client,
                        client_addr,
                        target_addr,
                        local_addr,
                        conn_cancel,
                    )
                    .await;
                });
            }
        }
    }
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
    rule: Rule,
    mut client: TcpStream,
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    server_listen: SocketAddr,
    cancel: CancellationToken,
) {
    // Connect to upstream first. If this fails, close the client without
    // sending anything (no PROXY-protocol header, no half-open).
    let mut upstream = match TcpStream::connect(target_addr).await {
        Ok(s) => s,
        Err(e) => {
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

    // Disable Nagle on both sides for latency-sensitive payloads. Most game
    // protocols want this; bulk-transfer cases will be measurement-driven
    // (Phase 11 benches will tell us if this hurts iperf-style tests, in
    // which case we'll gate it behind a per-rule option).
    let _ = client.set_nodelay(true);
    let _ = upstream.set_nodelay(true);

    let pumping = copy_bidirectional(&mut client, &mut upstream);
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
        let peer = PeerState::new([0u8; 32]);
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

        proxy.stop().await;
    }

    #[tokio::test]
    async fn drops_connection_when_no_peer_yet() {
        let (upstream, _us) = echo_server().await;
        let peer = PeerState::new([0u8; 32]);
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
        proxy.stop().await;
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

        let peer = PeerState::new([0u8; 32]);
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

        proxy.stop().await;
    }

    #[tokio::test]
    async fn closes_when_upstream_unreachable() {
        let peer = PeerState::new([0u8; 32]);
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
        proxy.stop().await;
    }

    #[tokio::test]
    async fn stop_cancels_in_flight_connection() {
        let (upstream, _us) = echo_server().await;
        let peer = PeerState::new([0u8; 32]);
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
        proxy.stop().await;

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
        let peer = PeerState::new([0u8; 32]);
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

        proxy.stop().await;
    }
}
