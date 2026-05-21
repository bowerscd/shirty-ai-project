//! HTTPS L7 frontend for `protocol = "https"` rules.
//!
//! Architecture
//! ============
//!
//! Each HTTPS rule produces:
//!
//! * One **HTTPS acceptor** bound to `rule.listen` (typically `:443`).
//! * One per-IP shared **`:80` redirect listener** (see [`RedirectListener`])
//!   that the supervisor wires up. The redirect listener is intentionally
//!   *not* owned by this struct — multiple HTTPS rules listening on the same
//!   IP share a single port-80 socket via the supervisor's refcount map.
//!
//! Per inbound TCP connection on the HTTPS port:
//!
//! 1. **Optional PROXY-protocol decode.** If the upstream relay was
//!    configured with `proxy_protocol = "v1" | "v2"`, the terminal sees a
//!    well-formed header. We consume it (we do **not** re-emit) and use the
//!    declared client address as the `X-Forwarded-For` source. Absent or
//!    malformed-but-not-magic prefix: the bytes are spliced back in front
//!    of the stream and TLS reads them as the start of `ClientHello`.
//! 2. **TLS handshake** via `tokio_rustls::TlsAcceptor` driving a
//!    `rustls::ServerConfig` whose `cert_resolver` is the shared
//!    [`CertStore`]. Unknown SNI → rustls emits `unrecognized_name` and the
//!    handshake fails (the connection is dropped). ALPN advertises `h2` and
//!    `http/1.1`.
//! 3. **Hyper serve** of the resulting TLS stream. Per request:
//!    a. Extract `Host` (HTTP/1.1) or `:authority` (HTTP/2). Missing or
//!    malformed → drop the TCP (close the TLS stream).
//!    b. Lookup the route in the per-rule [`RouteTable`]. No match → 404.
//!    c. Detect WebSocket upgrade. If yes, we forward the request to the
//!    backend, watch for a `101 Switching Protocols` response, then
//!    hijack both sides and `copy_bidirectional` until either closes.
//!    d. Otherwise: normal forward. Strip pre-existing `X-Forwarded-*` /
//!    `X-Real-IP` / RFC 7239 `Forwarded` (untrusted; we own the inbound
//!    edge). Strip hop-by-hop per RFC 7230 §6.1 (`Connection`,
//!    `Transfer-Encoding`, `Upgrade`, etc.). Inject `X-Forwarded-For`,
//!    `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Real-IP`. Rewrite the
//!    request URI authority to the route's `upstream`. Preserve the
//!    inbound `Host` header so the backend sees what the client sent.
//!    Dial via a hyper-util `legacy::Client` with a connection pool so
//!    sequential requests reuse a keep-alive socket. Backend unreachable
//!    → 502 plain. On success, optionally inject `Strict-Transport-
//!    Security` per the route's HSTS policy.
//!
//! Failure modes are deliberately curt: the L7 surface fronts arbitrary
//! application servers and giving away detailed error pages here would
//! invite fingerprinting.

use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use http::header::{
    HeaderMap, HeaderName, HeaderValue, CONNECTION, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION,
    TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::uri::{Authority, Scheme, Uri};
use http::{Request, Response, StatusCode, Version};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as LegacyClient;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use url::Url;

use ratatoskr::rule::{HttpRoute, Rule};

use super::certs::CertStore;
use super::proxy_protocol;

// =============================================================================
// Public types
// =============================================================================

/// Owning handle for an HTTPS rule's listener task. Cancelling tears down
/// the acceptor; in-flight connections finish naturally.
pub struct HttpFrontend {
    rule_name: String,
    local_addr: SocketAddr,
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for HttpFrontend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpFrontend")
            .field("rule_name", &self.rule_name)
            .field("local_addr", &self.local_addr)
            .finish()
    }
}

impl HttpFrontend {
    /// Bind `rule.listen` and start the HTTPS acceptor. Returns once the
    /// socket is listening.
    ///
    /// `cert_store` is shared across all HTTPS frontends in the supervisor
    /// and used as the rustls `ResolvesServerCert`. The supervisor is
    /// responsible for ensuring the store contains entries for every
    /// hostname this rule serves *before* `spawn` is called.
    pub async fn spawn(
        rule: &Rule,
        cert_store: Arc<CertStore>,
        parent: CancellationToken,
    ) -> Result<Self> {
        let routes = rule
            .routes
            .as_ref()
            .filter(|r| !r.is_empty())
            .with_context(|| {
                format!(
                    "HTTPS rule {:?} has no routes; validator should have rejected this",
                    rule.name,
                )
            })?;

        let route_table = Arc::new(RouteTable::build(routes));

        // Build rustls ServerConfig with the shared cert store as resolver
        // and ALPN advertising h2 + http/1.1.
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(cert_store);
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind(rule.listen).await.with_context(|| {
            format!(
                "bind HTTPS listener for rule {:?} on {}",
                rule.name, rule.listen,
            )
        })?;
        let local_addr = listener
            .local_addr()
            .context("read HTTPS TcpListener local_addr")?;

        let cancel = parent.child_token();
        let backend_client = build_backend_client();

        let task_rule_name = rule.name.clone();
        let task_cancel = cancel.clone();
        let task_routes = Arc::clone(&route_table);
        let task_acceptor = acceptor.clone();
        let task_client = backend_client.clone();
        let task_local = local_addr;

        let handle = tokio::spawn(async move {
            accept_loop(
                task_rule_name,
                listener,
                task_local,
                task_acceptor,
                task_routes,
                task_client,
                task_cancel,
            )
            .await;
        });

        info!(
            rule = %rule.name,
            listen = %local_addr,
            routes = route_table.len(),
            "HTTPS rule listening"
        );

        Ok(Self {
            rule_name: rule.name.clone(),
            local_addr,
            cancel,
            handle,
        })
    }

    pub fn rule_name(&self) -> &str {
        &self.rule_name
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = self.handle.await;
    }
}

// =============================================================================
// Backend dialer
// =============================================================================

/// HTTP/1.1 + HTTP/2 capable client that pools connections per (host, port).
/// One instance per frontend; cloning is cheap (it's an Arc internally).
type BackendClient = LegacyClient<HttpConnector, BoxBody<Bytes, hyper::Error>>;

fn build_backend_client() -> BackendClient {
    let mut http = HttpConnector::new();
    http.set_nodelay(true);
    http.enforce_http(true); // refuse non-http:// upstreams; HTTPS upstreams unsupported in this phase.
    http.set_connect_timeout(Some(Duration::from_secs(5)));
    LegacyClient::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(32)
        .build::<_, BoxBody<Bytes, hyper::Error>>(http)
}

// =============================================================================
// RouteTable — exact (case-insensitive) hostname → route mapping
// =============================================================================

pub struct RouteTable {
    by_host: HashMap<String, RouteEntry>,
}

struct RouteEntry {
    target: Url,
    hsts: Option<HstsHeader>,
}

#[derive(Clone)]
struct HstsHeader(HeaderValue);

impl RouteTable {
    fn build(routes: &[HttpRoute]) -> Self {
        let mut by_host = HashMap::with_capacity(routes.len());
        for r in routes {
            let hsts = r.hsts.map(|cfg| {
                let mut v = format!("max-age={}", cfg.max_age);
                if cfg.include_subdomains {
                    v.push_str("; includeSubDomains");
                }
                if cfg.preload {
                    v.push_str("; preload");
                }
                // Safety: composed from %u32 + ASCII literals only.
                HstsHeader(HeaderValue::from_str(&v).expect("HSTS header is ASCII"))
            });
            by_host.insert(
                r.hostname.to_ascii_lowercase(),
                RouteEntry {
                    target: r.target.clone(),
                    hsts,
                },
            );
        }
        Self { by_host }
    }

    fn lookup(&self, host: &str) -> Option<&RouteEntry> {
        // Strip trailing dot ("foo.example.com.") and port if present.
        let host = host.trim_end_matches('.');
        let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
        self.by_host.get(&host.to_ascii_lowercase())
    }

    pub fn len(&self) -> usize {
        self.by_host.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_host.is_empty()
    }

    /// Iterate hostnames (for the `:80` redirect listener's knowledge of
    /// which hosts to accept).
    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.by_host.keys().map(|s| s.as_str())
    }
}

// =============================================================================
// Accept loop
// =============================================================================

#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    rule_name: String,
    listener: TcpListener,
    local_addr: SocketAddr,
    acceptor: TlsAcceptor,
    routes: Arc<RouteTable>,
    client: BackendClient,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
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
                let conn_rule = rule_name.clone();
                let conn_acceptor = acceptor.clone();
                let conn_routes = Arc::clone(&routes);
                let conn_client = client.clone();
                let conn_cancel = cancel.child_token();
                tokio::spawn(async move {
                    if let Err(e) = handle_tcp_connection(
                        conn_rule,
                        tcp,
                        peer_addr,
                        local_addr,
                        conn_acceptor,
                        conn_routes,
                        conn_client,
                        conn_cancel,
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

// =============================================================================
// Per-connection: PROXY-protocol → TLS → hyper serve
// =============================================================================

#[allow(clippy::too_many_arguments)]
async fn handle_tcp_connection(
    rule_name: String,
    mut tcp: TcpStream,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    acceptor: TlsAcceptor,
    routes: Arc<RouteTable>,
    client: BackendClient,
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
        rule_name: rule_name.clone(),
        client_addr,
        local_addr,
        routes: Arc::clone(&routes),
        client: client.clone(),
    });

    let service = service_fn(move |req: Request<Incoming>| {
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

use std::task::{Context as TaskCtx, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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

// =============================================================================
// Per-request handler
// =============================================================================

struct ConnContext {
    rule_name: String,
    client_addr: SocketAddr,
    local_addr: SocketAddr,
    routes: Arc<RouteTable>,
    client: BackendClient,
}

async fn serve_request(
    ctx: Arc<ConnContext>,
    req: Request<Incoming>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let started = Instant::now();
    let method = req.method().clone();
    let original_uri = req.uri().clone();

    // -------------------------------------------------------------------
    // Extract Host (h1) or :authority (h2). Missing → drop with no body.
    // -------------------------------------------------------------------
    let host = match extract_host(&req) {
        Some(h) => h,
        None => {
            debug!(
                rule = %ctx.rule_name,
                client = %ctx.client_addr,
                "request missing Host / :authority; closing"
            );
            // Returning an empty body with 400 is acceptable. The plan says
            // "drop TCP" for h1.0 / missing-Host; on h2 we have no way to
            // close just the stream without a status, so 400 is the closest
            // honest answer. The connection itself is the caller's choice.
            return short_response(StatusCode::BAD_REQUEST, "");
        }
    };

    // -------------------------------------------------------------------
    // Route lookup.
    // -------------------------------------------------------------------
    let (route_label, route) = match ctx.routes.lookup(&host) {
        Some(r) => {
            let label = host
                .rsplit_once(':')
                .map(|(h, _)| h)
                .unwrap_or(&host)
                .to_ascii_lowercase();
            (label, r)
        }
        None => {
            debug!(
                rule = %ctx.rule_name,
                host = %host,
                "no route for Host; replying 404"
            );
            let resp = short_response(StatusCode::NOT_FOUND, "no route\n");
            record_request_metrics(&ctx.rule_name, "_unknown", &resp, started);
            return resp;
        }
    };

    // -------------------------------------------------------------------
    // WebSocket detection: any HTTP/1.1 request with `Upgrade: websocket`
    // and `Connection: upgrade`. HTTP/2 WebSocket (RFC 8441) uses CONNECT;
    // we don't currently negotiate that and let it fall through as a normal
    // CONNECT, which the backend may handle as it sees fit.
    // -------------------------------------------------------------------
    let is_websocket = req.version() == Version::HTTP_11 && is_websocket_upgrade(req.headers());

    let upstream_url = route.target.clone();
    let hsts_header = route.hsts.clone();

    // -------------------------------------------------------------------
    // Forward.
    // -------------------------------------------------------------------
    let resp = if is_websocket {
        forward_websocket(Arc::clone(&ctx), req, &upstream_url, &host).await
    } else {
        forward_normal(Arc::clone(&ctx), req, &upstream_url, &host).await
    };

    let mut resp = match resp {
        Ok(r) => r,
        Err(e) => {
            debug!(
                rule = %ctx.rule_name,
                route = %route_label,
                method = %method,
                uri = %original_uri,
                error = %e,
                "upstream forward failed"
            );
            short_response(StatusCode::BAD_GATEWAY, "")
        }
    };

    // HSTS opt-in. Safe to inject even on error responses we generated; in
    // practice 502s won't be flagged by browsers for HSTS purposes anyway.
    if let Some(h) = hsts_header {
        resp.headers_mut().insert(
            HeaderName::from_static("strict-transport-security"),
            h.0.clone(),
        );
    }

    record_request_metrics(&ctx.rule_name, &route_label, &resp, started);
    resp
}

fn record_request_metrics(
    rule: &str,
    route: &str,
    resp: &Response<BoxBody<Bytes, hyper::Error>>,
    start: Instant,
) {
    let status = resp.status().as_u16();
    let class = match status {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    };
    metrics::counter!(
        "yggdrasil_http_requests_total",
        "rule" => rule.to_string(),
        "route" => route.to_string(),
        "status_class" => class.to_string(),
    )
    .increment(1);
    metrics::histogram!(
        "yggdrasil_http_request_duration_seconds",
        "rule" => rule.to_string(),
        "route" => route.to_string(),
    )
    .record(start.elapsed().as_secs_f64());
}

// =============================================================================
// Forward: normal request
// =============================================================================

async fn forward_normal(
    ctx: Arc<ConnContext>,
    req: Request<Incoming>,
    upstream_url: &Url,
    host: &str,
) -> anyhow::Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let (mut parts, body) = req.into_parts();

    // Strip untrusted forwarding metadata, strip hop-by-hop, inject our
    // own X-Forwarded-* / X-Real-IP. Preserve the inbound Host header.
    sanitise_request_headers(&mut parts.headers);
    inject_forwarded_headers(&mut parts.headers, ctx.client_addr.ip(), host);

    // Rewrite URI authority to the backend.
    let new_uri = build_upstream_uri(&parts.uri, upstream_url)?;
    parts.uri = new_uri;
    parts.version = Version::HTTP_11; // backend leg is always h1 in this phase.

    let body = body
        .map_err(|e| {
            // Map incoming-side errors to hyper::Error indirectly via io::Error;
            // BoxBody requires a consistent error type.
            tracing::trace!(error = %e, "request body error");
            e
        })
        .boxed();

    let outgoing = Request::from_parts(parts, body);
    let resp = ctx
        .client
        .request(outgoing)
        .await
        .context("backend request")?;

    let (mut resp_parts, resp_body) = resp.into_parts();
    sanitise_response_headers(&mut resp_parts.headers);
    let resp_body = resp_body.boxed();
    Ok(Response::from_parts(resp_parts, resp_body))
}

// =============================================================================
// Forward: WebSocket
// =============================================================================

async fn forward_websocket(
    ctx: Arc<ConnContext>,
    req: Request<Incoming>,
    upstream_url: &Url,
    host: &str,
) -> anyhow::Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let (mut parts, body) = req.into_parts();
    // Capture the original on_upgrade future before we rewrite anything.
    let client_upgrade =
        hyper::upgrade::on(Request::from_parts(parts.clone(), Empty::<Bytes>::new()));
    sanitise_request_headers_for_websocket(&mut parts.headers);
    inject_forwarded_headers(&mut parts.headers, ctx.client_addr.ip(), host);

    let new_uri = build_upstream_uri(&parts.uri, upstream_url)?;
    parts.uri = new_uri;
    parts.version = Version::HTTP_11;

    let body = body.boxed();
    let outgoing = Request::from_parts(parts, body);

    let mut backend_resp = ctx
        .client
        .request(outgoing)
        .await
        .context("backend websocket handshake")?;

    if backend_resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        // Not a successful upgrade; forward the response verbatim (minus
        // hop-by-hop) so the client sees what the backend said.
        let (mut resp_parts, resp_body) = backend_resp.into_parts();
        sanitise_response_headers(&mut resp_parts.headers);
        let resp_body = resp_body.boxed();
        return Ok(Response::from_parts(resp_parts, resp_body));
    }

    // Both sides agreed; hijack the upgrade and bridge.
    let backend_upgrade = hyper::upgrade::on(&mut backend_resp);
    let rule_name = ctx.rule_name.clone();
    tokio::spawn(async move {
        let client = match client_upgrade.await {
            Ok(c) => c,
            Err(e) => {
                debug!(rule = %rule_name, error = %e, "client websocket upgrade failed");
                return;
            }
        };
        let backend = match backend_upgrade.await {
            Ok(b) => b,
            Err(e) => {
                debug!(rule = %rule_name, error = %e, "backend websocket upgrade failed");
                return;
            }
        };
        let mut client = TokioIo::new(client);
        let mut backend = TokioIo::new(backend);
        if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut backend).await {
            debug!(rule = %rule_name, error = %e, "websocket copy ended");
        }
    });

    let (resp_parts, _) = backend_resp.into_parts();
    let resp = Response::from_parts(
        resp_parts,
        Empty::<Bytes>::new().map_err(|e| match e {}).boxed(),
    );
    Ok(resp)
}

// =============================================================================
// Header surgery
// =============================================================================

/// Header names to strip from inbound requests: pre-existing forwarding
/// claims (untrusted, we own the inbound edge) plus hop-by-hop per RFC 7230
/// §6.1. We do *not* strip Host — the route lookup needs it, and the
/// backend cares.
fn sanitise_request_headers(headers: &mut HeaderMap) {
    strip_hop_by_hop(headers);
    strip_forwarding_claims(headers);
}

/// Same as `sanitise_request_headers` but preserves `Upgrade` and
/// `Connection` (which carries `upgrade`) so the backend sees the WebSocket
/// handshake intact.
fn sanitise_request_headers_for_websocket(headers: &mut HeaderMap) {
    // Remove only the strictly-hop-by-hop names that aren't part of the
    // upgrade negotiation itself.
    for name in [
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
    ] {
        headers.remove(name);
    }
    // Also strip any `Connection`-listed tokens that aren't `upgrade`. We do
    // a coarse approach: keep Connection as-is if it lists upgrade,
    // otherwise drop it.
    let keep_connection = headers
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);
    if !keep_connection {
        headers.remove(CONNECTION);
    }
    strip_forwarding_claims(headers);
}

fn sanitise_response_headers(headers: &mut HeaderMap) {
    strip_hop_by_hop(headers);
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    // RFC 7230 §6.1 allows `Connection: <token>` to nominate further
    // hop-by-hop headers. Collect those tokens *first*, before we remove
    // the Connection header itself, otherwise we can't see them.
    let tokens: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .filter_map(|tok| {
            let t = tok.trim();
            if t.eq_ignore_ascii_case("close") || t.eq_ignore_ascii_case("keep-alive") {
                None
            } else {
                HeaderName::from_bytes(t.as_bytes()).ok()
            }
        })
        .collect();
    for t in tokens {
        headers.remove(t);
    }
    for name in [
        CONNECTION,
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
    ] {
        headers.remove(name);
    }
}

fn strip_forwarding_claims(headers: &mut HeaderMap) {
    headers.remove(HeaderName::from_static("x-forwarded-for"));
    headers.remove(HeaderName::from_static("x-forwarded-proto"));
    headers.remove(HeaderName::from_static("x-forwarded-host"));
    headers.remove(HeaderName::from_static("x-forwarded-port"));
    headers.remove(HeaderName::from_static("x-real-ip"));
    headers.remove(HeaderName::from_static("forwarded"));
}

fn inject_forwarded_headers(headers: &mut HeaderMap, client_ip: IpAddr, host: &str) {
    let ip_str = match client_ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => v6.to_string(),
    };
    if let Ok(v) = HeaderValue::from_str(&ip_str) {
        headers.insert(HeaderName::from_static("x-forwarded-for"), v.clone());
        headers.insert(HeaderName::from_static("x-real-ip"), v);
    }
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("https"),
    );
    if let Ok(v) = HeaderValue::from_str(host) {
        headers.insert(HeaderName::from_static("x-forwarded-host"), v);
    }
}

fn extract_host<B>(req: &Request<B>) -> Option<String> {
    // HTTP/2: :authority is canonical. HTTP/1.1: Host header.
    if let Some(auth) = req.uri().authority() {
        return Some(auth.as_str().to_string());
    }
    req.headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let upgrade_ws = headers
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let conn_upgrade = headers
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);
    upgrade_ws && conn_upgrade
}

fn build_upstream_uri(orig: &Uri, upstream: &Url) -> anyhow::Result<Uri> {
    let path_and_query = orig.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let authority = match (upstream.host_str(), upstream.port_or_known_default()) {
        (Some(h), Some(p)) => format!("{h}:{p}"),
        (Some(h), None) => h.to_string(),
        _ => anyhow::bail!("upstream URL has no host"),
    };
    let authority = Authority::try_from(authority.as_bytes()).context("authority parse")?;
    Ok(Uri::builder()
        .scheme(Scheme::HTTP)
        .authority(authority)
        .path_and_query(path_and_query)
        .build()?)
}

fn short_response(
    status: StatusCode,
    body: &'static str,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = Full::new(Bytes::from_static(body.as_bytes()))
        .map_err(|e| match e {})
        .boxed();
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body)
        .expect("static response builds")
}

// =============================================================================
// Plain `:80` redirect listener (shared per IP across all HTTPS rules)
// =============================================================================

/// One per (supervisor, IpAddr). Owns a TCP listener bound to `(ip, 80)`
/// and serves nothing but `301 Moved Permanently` redirects to the
/// matching HTTPS URL. Hosts that don't match any active route get a 404.
pub struct RedirectListener {
    ip: IpAddr,
    local_addr: SocketAddr,
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
    /// Per-IP set of hostnames that should be redirected to HTTPS. The
    /// supervisor mutates this on rule reload.
    hosts: Arc<parking_lot::RwLock<HostSet>>,
}

impl std::fmt::Debug for RedirectListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedirectListener")
            .field("ip", &self.ip)
            .field("local_addr", &self.local_addr)
            .finish()
    }
}

/// Mapping host → refcount (number of HTTPS rules claiming this host on the
/// shared IP). When refcount drops to zero the host is forgotten.
#[derive(Default)]
struct HostSet {
    by_host: HashMap<String, usize>,
}

impl HostSet {
    fn contains(&self, host: &str) -> bool {
        self.by_host.contains_key(&host.to_ascii_lowercase())
    }

    fn add(&mut self, host: &str) {
        *self.by_host.entry(host.to_ascii_lowercase()).or_insert(0) += 1;
    }

    fn remove(&mut self, host: &str) {
        let key = host.to_ascii_lowercase();
        if let Some(c) = self.by_host.get_mut(&key) {
            *c -= 1;
            if *c == 0 {
                self.by_host.remove(&key);
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.by_host.is_empty()
    }
}

impl RedirectListener {
    pub async fn spawn(ip: IpAddr, port: u16, parent: CancellationToken) -> Result<Self> {
        let bind = SocketAddr::new(ip, port);
        let listener = TcpListener::bind(bind)
            .await
            .with_context(|| format!("bind :{port} redirect listener on {bind}"))?;
        let local_addr = listener.local_addr().context("read redirect local_addr")?;

        let hosts = Arc::new(parking_lot::RwLock::new(HostSet::default()));
        let cancel = parent.child_token();

        let task_hosts = Arc::clone(&hosts);
        let task_cancel = cancel.clone();

        let handle = tokio::spawn(async move {
            redirect_accept_loop(listener, task_hosts, task_cancel).await;
        });

        info!(bind = %local_addr, "HTTP→HTTPS redirect listener active");

        Ok(Self {
            ip,
            local_addr,
            cancel,
            handle,
            hosts,
        })
    }

    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Register a hostname for redirect handling. Refcounted; the listener
    /// retains the host until the matching `unregister_host` call.
    pub fn register_host(&self, host: &str) {
        self.hosts.write().add(host);
    }

    pub fn unregister_host(&self, host: &str) {
        self.hosts.write().remove(host);
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.read().is_empty()
    }

    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = self.handle.await;
    }
}

async fn redirect_accept_loop(
    listener: TcpListener,
    hosts: Arc<parking_lot::RwLock<HostSet>>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            res = listener.accept() => {
                let (tcp, peer) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, "redirect listener accept failed");
                        continue;
                    }
                };
                let h = Arc::clone(&hosts);
                let c = cancel.child_token();
                tokio::spawn(async move {
                    if let Err(e) = serve_redirect(tcp, peer, h, c).await {
                        debug!(client = %peer, error = %e, "redirect connection ended");
                    }
                });
            }
        }
    }
}

async fn serve_redirect(
    tcp: TcpStream,
    _peer: SocketAddr,
    hosts: Arc<parking_lot::RwLock<HostSet>>,
    _cancel: CancellationToken,
) -> io::Result<()> {
    let io = TokioIo::new(tcp);
    let service = service_fn(move |req: Request<Incoming>| {
        let h = Arc::clone(&hosts);
        async move {
            let resp = build_redirect_response(req, &h);
            Ok::<_, Infallible>(resp)
        }
    });
    if let Err(e) = http1::Builder::new()
        .keep_alive(true)
        .serve_connection(io, service)
        .await
    {
        debug!(error = %e, "redirect serve_connection ended");
    }
    Ok(())
}

fn build_redirect_response(
    req: Request<Incoming>,
    hosts: &Arc<parking_lot::RwLock<HostSet>>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let host = match extract_host(&req) {
        Some(h) => h,
        None => return short_response(StatusCode::BAD_REQUEST, ""),
    };
    let bare_host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(&host);
    if !hosts.read().contains(bare_host) {
        return short_response(StatusCode::NOT_FOUND, "no route\n");
    }
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let location = format!("https://{bare_host}{path_and_query}");
    let body = Empty::<Bytes>::new().map_err(|e| match e {}).boxed();
    Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header(http::header::LOCATION, location)
        .body(body)
        .expect("redirect response builds")
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;
    use http::Request as HttpRequest;

    fn req_with(headers: &[(&'static str, &'static str)]) -> HttpRequest<()> {
        let mut b = HttpRequest::builder().uri("/foo").method(Method::GET);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap()
    }

    #[test]
    fn strip_hop_by_hop_removes_listed_names() {
        let mut h = HeaderMap::new();
        h.insert(CONNECTION, HeaderValue::from_static("close, foo"));
        h.insert(TE, HeaderValue::from_static("trailers"));
        h.insert(UPGRADE, HeaderValue::from_static("websocket"));
        h.insert(
            HeaderName::from_static("foo"),
            HeaderValue::from_static("bar"),
        );
        h.insert(
            HeaderName::from_static("x-keep"),
            HeaderValue::from_static("yes"),
        );
        strip_hop_by_hop(&mut h);
        assert!(!h.contains_key(CONNECTION));
        assert!(!h.contains_key(TE));
        assert!(!h.contains_key(UPGRADE));
        assert!(!h.contains_key(HeaderName::from_static("foo")));
        assert_eq!(h.get(HeaderName::from_static("x-keep")).unwrap(), "yes");
    }

    #[test]
    fn strip_forwarding_claims_removes_all_variants() {
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("1.2.3.4"),
        );
        h.insert(
            HeaderName::from_static("x-forwarded-proto"),
            HeaderValue::from_static("http"),
        );
        h.insert(
            HeaderName::from_static("x-real-ip"),
            HeaderValue::from_static("5.6.7.8"),
        );
        h.insert(
            HeaderName::from_static("forwarded"),
            HeaderValue::from_static("for=lies"),
        );
        strip_forwarding_claims(&mut h);
        assert!(h.is_empty());
    }

    #[test]
    fn inject_forwarded_headers_writes_canonical_values() {
        let mut h = HeaderMap::new();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        inject_forwarded_headers(&mut h, ip, "api.example.com");
        assert_eq!(h.get("x-forwarded-for").unwrap(), "203.0.113.7");
        assert_eq!(h.get("x-real-ip").unwrap(), "203.0.113.7");
        assert_eq!(h.get("x-forwarded-proto").unwrap(), "https");
        assert_eq!(h.get("x-forwarded-host").unwrap(), "api.example.com");
    }

    #[test]
    fn is_websocket_upgrade_requires_both_signals() {
        let r1 = req_with(&[("upgrade", "websocket"), ("connection", "upgrade")]);
        assert!(is_websocket_upgrade(r1.headers()));
        let r2 = req_with(&[("upgrade", "websocket")]);
        assert!(!is_websocket_upgrade(r2.headers()));
        let r3 = req_with(&[("connection", "upgrade")]);
        assert!(!is_websocket_upgrade(r3.headers()));
        let r4 = req_with(&[("upgrade", "h2c"), ("connection", "upgrade")]);
        assert!(!is_websocket_upgrade(r4.headers()));
    }

    #[test]
    fn extract_host_prefers_authority_then_host_header() {
        let r = HttpRequest::builder()
            .uri("https://api.example.com/foo")
            .body(())
            .unwrap();
        assert_eq!(extract_host(&r).as_deref(), Some("api.example.com"));

        let r = HttpRequest::builder()
            .uri("/foo")
            .header("host", "app.example.com")
            .body(())
            .unwrap();
        assert_eq!(extract_host(&r).as_deref(), Some("app.example.com"));

        let r = HttpRequest::builder().uri("/foo").body(()).unwrap();
        assert_eq!(extract_host(&r), None);
    }

    #[test]
    fn route_table_lookup_is_case_insensitive_and_strips_port() {
        let routes = vec![HttpRoute {
            hostname: "API.example.com".into(),
            target: "http://10.0.0.1:8080".parse().unwrap(),
            cert: None,
            key: None,
            hsts: None,
        }];
        let t = RouteTable::build(&routes);
        assert!(t.lookup("api.example.com").is_some());
        assert!(t.lookup("API.example.com").is_some());
        assert!(t.lookup("api.example.com:443").is_some());
        assert!(t.lookup("api.example.com.").is_some());
        assert!(t.lookup("other.example.com").is_none());
    }

    #[test]
    fn build_upstream_uri_rewrites_authority_and_preserves_path() {
        let orig: Uri = "/api/v1/foo?bar=1".parse().unwrap();
        let up: Url = "http://10.0.0.1:8080/ignored-path".parse().unwrap();
        let out = build_upstream_uri(&orig, &up).unwrap();
        assert_eq!(out.scheme_str(), Some("http"));
        assert_eq!(out.authority().unwrap().as_str(), "10.0.0.1:8080");
        assert_eq!(out.path(), "/api/v1/foo");
        assert_eq!(out.query(), Some("bar=1"));
    }

    #[test]
    fn host_set_refcounts_correctly() {
        let mut s = HostSet::default();
        assert!(!s.contains("a"));
        s.add("a");
        s.add("a");
        s.add("b");
        assert!(s.contains("a"));
        assert!(s.contains("b"));
        s.remove("a");
        assert!(s.contains("a"));
        s.remove("a");
        assert!(!s.contains("a"));
        assert!(s.contains("b"));
    }
}
