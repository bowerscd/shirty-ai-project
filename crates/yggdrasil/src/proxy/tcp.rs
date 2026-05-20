//! Per-rule TCP proxy.
//!
//! Each [`TcpProxy`] owns one `tokio::net::TcpListener` bound to
//! `rule.listen`, an accept loop running on its own task, and a
//! [`CancellationToken`] for clean shutdown.
//!
//! Per-connection lifecycle:
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

use anyhow::{Context, Result};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use ratatoskr::rule::Rule;

use super::proxy_protocol;
use super::resolver::UpstreamResolver;

/// Handle to a running per-rule TCP proxy. Drop to stop (the cancellation
/// token cascade aborts the listener task and lets in-flight connections
/// finish naturally).
pub struct TcpProxy {
    rule: Rule,
    cancel: CancellationToken,
    local_addr: SocketAddr,
    handle: tokio::task::JoinHandle<()>,
}

impl TcpProxy {
    /// Bind the listener and spawn the accept loop. Returns once the socket
    /// is listening so callers can rely on connect attempts succeeding
    /// immediately after this resolves.
    pub async fn spawn(rule: Rule, resolver: UpstreamResolver) -> Result<Self> {
        let listener = TcpListener::bind(rule.listen)
            .await
            .with_context(|| format!("bind TCP listener for rule {:?} on {}", rule.name, rule.listen))?;
        let local_addr = listener.local_addr().context("read TcpListener local_addr")?;

        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task_rule = rule.clone();
        let task_resolver = resolver.clone();
        let task_local = local_addr;

        let handle = tokio::spawn(async move {
            run_accept_loop(task_rule, task_resolver, listener, task_local, task_cancel).await;
        });

        tracing::info!(
            rule = %rule.name,
            listen = %local_addr,
            upstream = %resolver.describe(),
            proxy_protocol = ?rule.proxy_protocol,
            "TCP rule listening"
        );

        Ok(Self {
            rule,
            cancel,
            local_addr,
            handle,
        })
    }

    pub fn rule(&self) -> &Rule {
        &self.rule
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Trigger shutdown. Does NOT wait for in-flight connections — drop the
    /// handle (which awaits the task on Drop indirectly via JoinHandle) or
    /// call [`TcpProxy::stop`] to await full shutdown.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Cancel and wait for the accept loop to exit. In-flight per-connection
    /// tasks are also cancelled via the cancellation cascade and given a
    /// chance to drain, but this method does not wait for them.
    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = self.handle.await;
    }
}

async fn run_accept_loop(
    rule: Rule,
    resolver: UpstreamResolver,
    listener: TcpListener,
    local_addr: SocketAddr,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                tracing::debug!(rule = %rule.name, "TCP accept loop received cancel");
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
                        tracing::warn!(rule = %rule.name, error = %e, "TCP accept failed");
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
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use ratatoskr::rule::ProxyProto;

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
        let proxy = TcpProxy::spawn(rule("noupstream", 1, None), dynamic_resolver(peer, 1))
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
}
