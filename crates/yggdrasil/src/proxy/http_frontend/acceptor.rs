//! TCP accept loop + per-connection PROXY-protocol/TLS/HTTP dispatch.
//!
//! Split out from the original monolithic `http_frontend.rs` (Phase B4).

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskCtx, Poll};

use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, warn};

use ratatoskr::rule::Rule;

use crate::proxy::proxy_protocol;

use super::backend::BackendClient;
use super::request::{serve_request, ConnContext};
use super::route::RouteTable;

#[allow(clippy::too_many_arguments)]
pub(super) async fn accept_loop(
    rule_name: String,
    rule: Arc<Rule>,
    listener: TcpListener,
    local_addr: SocketAddr,
    acceptor: TlsAcceptor,
    routes: Arc<RouteTable>,
    client: BackendClient,
    emit_alt_svc: bool,
    accept_cancel: CancellationToken,
    conn_cancel: CancellationToken,
    conn_tracker: TaskTracker,
) {
    loop {
        tokio::select! {
            biased;
            _ = accept_cancel.cancelled() => {
                debug!(rule = %rule_name, "HTTPS accept loop received cancel");
                return;
            }
            res = listener.accept() => {
                let (tcp, peer_addr) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(rule = %rule_name, error = %e, "HTTPS accept failed");
                        continue;
                    }
                };
                // tcp_nodelay improves request latency for small payloads.
                if let Err(e) = tcp.set_nodelay(true) {
                    debug!(rule = %rule_name, error = %e, "set_nodelay failed");
                }
                let conn_rule_name = rule_name.clone();
                let conn_rule = Arc::clone(&rule);
                let conn_acceptor = acceptor.clone();
                let conn_routes = Arc::clone(&routes);
                let conn_client = client.clone();
                // Per-connection task observes `conn_cancel` (the drain
                // backstop), NOT `accept_cancel`. See `HttpFrontend::stop`
                // for the rationale.
                let task_conn_cancel = conn_cancel.child_token();
                // Spawn through the tracker so HttpFrontend::stop can
                // wait on the in-flight TLS-connection set during
                // graceful drain.
                conn_tracker.spawn(async move {
                    if let Err(e) = handle_tcp_connection(
                        conn_rule_name,
                        conn_rule,
                        tcp,
                        peer_addr,
                        local_addr,
                        conn_acceptor,
                        conn_routes,
                        conn_client,
                        emit_alt_svc,
                        task_conn_cancel,
                    )
                    .await
                    {
                        debug!(error = %e, "HTTPS connection ended with error");
                    }
                });
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_tcp_connection(
    rule_name: String,
    rule: Arc<Rule>,
    mut tcp: TcpStream,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    acceptor: TlsAcceptor,
    routes: Arc<RouteTable>,
    client: BackendClient,
    emit_alt_svc: bool,
    cancel: CancellationToken,
) -> io::Result<()> {
    // Step 1: optional PROXY-protocol header. We only consume it; the
    // backend will see the recovered client address via X-Forwarded-For.
    let decode = proxy_protocol::read_optional_header(&mut tcp).await?;

    let client_addr = decode.endpoints.map(|e| e.client).unwrap_or(peer_addr);

    // Step 2: build a stream that re-feeds any peeked-but-not-PROXY bytes.
    let stream = PrefixedStream::new(decode.leftover, tcp);

    // Step 3: TLS handshake.
    let tls = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            // unknown_sni / unrecognized_name lands here as alert; fingerprint
            // counters live in the metrics module and are bumped by the
            // supervisor when it observes accept failures (we just log).
            debug!(
                rule = %rule_name,
                client = %client_addr,
                error = %e,
                "TLS handshake failed"
            );
            metrics::counter!(
                "yggdrasil_https_tls_handshakes_total",
                "rule" => rule_name.clone(),
                "result" => classify_tls_error(&e),
            )
            .increment(1);
            return Ok(());
        }
    };
    metrics::counter!(
        "yggdrasil_https_tls_handshakes_total",
        "rule" => rule_name.clone(),
        "result" => "ok".to_string(),
    )
    .increment(1);

    // Step 4: detect ALPN to choose HTTP/1 vs HTTP/2 service.
    let alpn_is_h2 = tls
        .get_ref()
        .1
        .alpn_protocol()
        .map(|p| p == b"h2")
        .unwrap_or(false);

    let conn_ctx = Arc::new(ConnContext {
        rule: Some(rule),
        rule_name: rule_name.clone(),
        client_addr,
        local_addr,
        routes: Arc::clone(&routes),
        client: client.clone(),
        tls: true,
        emit_alt_svc,
    });

    let service = service_fn(move |req: hyper::Request<Incoming>| {
        let ctx = Arc::clone(&conn_ctx);
        async move { Ok::<_, Infallible>(serve_request(ctx, req).await) }
    });

    let io = TokioIo::new(tls);

    let serve_res = if alpn_is_h2 {
        let conn = http2::Builder::new(TokioExecutor::new()).serve_connection(io, service);
        tokio::pin!(conn);
        tokio::select! {
            r = &mut conn => r.map_err(io::Error::other),
            _ = cancel.cancelled() => {
                // Best-effort drain — h2 has no graceful_shutdown on this
                // builder shape, so just abort.
                Ok(())
            }
        }
    } else {
        let conn = http1::Builder::new()
            .keep_alive(true)
            .serve_connection(io, service)
            .with_upgrades();
        tokio::pin!(conn);
        tokio::select! {
            r = &mut conn => r.map_err(io::Error::other),
            _ = cancel.cancelled() => {
                Ok(())
            }
        }
    };

    if let Err(e) = serve_res {
        debug!(rule = %rule_name, error = %e, "hyper serve_connection ended");
    }

    Ok(())
}

fn classify_tls_error(e: &io::Error) -> String {
    // tokio-rustls collapses rustls errors into io::Error; we classify based
    // on the inner string (best-effort but stable enough for ops metrics).
    let s = e.to_string();
    if s.contains("UnrecognizedName") || s.contains("unrecognized_name") {
        "unknown_sni".into()
    } else {
        "alert".into()
    }
}

// =============================================================================
// PrefixedStream — splice peeked PROXY-protocol leftover bytes back in front
// of the TCP read stream so TLS sees them as the start of ClientHello.
// =============================================================================

pin_project_lite::pin_project! {
    pub struct PrefixedStream<S> {
        prefix: Vec<u8>,
        prefix_pos: usize,
        #[pin]
        inner: S,
    }
}

impl<S> PrefixedStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            prefix_pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskCtx<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.project();
        if *me.prefix_pos < me.prefix.len() {
            let remaining = &me.prefix[*me.prefix_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            *me.prefix_pos += to_copy;
            return Poll::Ready(Ok(()));
        }
        me.inner.poll_read(cx, buf)
    }
}

impl<S: AsyncWrite> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskCtx<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}
