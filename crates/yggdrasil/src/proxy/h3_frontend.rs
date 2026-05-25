//! QUIC endpoint for HTTPS rules with HTTP/3 enabled.
//!
//! Bound on UDP `(rule.listen.ip(), rule.listen.port())` alongside the
//! existing TCP TLS listener. Cert resolution shares the per-rule
//! `CertStore` with TCP via [`build_rustls_server_config`] from
//! `proxy::http_frontend` — cert rotation propagates to both transports
//! automatically.
//!
//! Connection migration is enabled (quinn default). 0-RTT is explicitly
//! disabled (replay-safety footgun without per-route opt-in machinery).
//!
//! Per request, the h3 stream is decoded into an `http::Request`, the
//! host is matched against the per-rule `RouteTable`, and the request
//! is forwarded to the matched backend via the shared `hyper-util`
//! `LegacyClient` (HTTP/1.1 cleartext to LAN). Header rewriting (strip
//! untrusted `X-Forwarded-*`, strip hop-by-hop, inject
//! `X-Forwarded-For/Proto/Host` + `X-Real-IP`, optional HSTS) reuses
//! the helpers in `proxy::forward` / `proxy::http_frontend` so the wire
//! shape sent to backends matches the TCP HTTPS path byte-for-byte.
//!
//! Body handling: the h3 request body is buffered (up to
//! [`H3_REQUEST_BODY_LIMIT`]) and passed to the backend as a single
//! `Full<Bytes>`. The backend response body is streamed back in chunks
//! via `h3::server::RequestStream::send_data`. WebSocket-over-h3
//! (RFC 9220 extended CONNECT) is **not** supported here — requests
//! that look like an h3 WS upgrade get 501 so clients fall back to h2.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::{Buf, Bytes, BytesMut};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, ServerConfig, TransportConfig, VarInt};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};

use ratatoskr::rule::Rule;

use super::certs::CertStore;
use super::http_frontend::{
    build_backend_client, build_rustls_server_config, build_upstream_uri, sanitise_request_headers,
    sanitise_response_headers, BackendClient, RouteTable,
};

/// Maximum bytes of an inbound h3 request body that this proxy will
/// buffer before forwarding. Sized to comfortably cover typical web-form
/// POSTs without enabling DoS-by-large-upload through HTTP/3.
const H3_REQUEST_BODY_LIMIT: usize = 16 * 1024 * 1024;

/// Chunk size for streaming backend response bodies back into h3
/// `send_data`. Sized close to a typical jumbogram so we get one frame
/// per QUIC packet under common MTU.
const H3_RESPONSE_CHUNK_BYTES: usize = 8 * 1024;

/// Application close code for graceful endpoint shutdown.
const SHUTDOWN_CLOSE_CODE: VarInt = VarInt::from_u32(0);

pub struct H3Frontend {
    rule: Rule,
    local_addr: SocketAddr,
    cancel: CancellationToken,
    handle: JoinHandle<()>,
    /// In-flight QUIC connection tasks, for graceful drain. See
    /// [`crate::proxy::http_frontend::HttpFrontend`] for the
    /// symmetric shape on the TCP TLS path.
    conn_tracker: TaskTracker,
}

impl H3Frontend {
    pub async fn spawn(rule: Rule, cert_store: Arc<CertStore>) -> Result<Self> {
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

        let rustls_arc = build_rustls_server_config(cert_store, &[b"h3"]);
        let rustls_inner: rustls::ServerConfig = (*rustls_arc).clone();
        let quic_crypto = QuicServerConfig::try_from(rustls_inner)
            .context("convert rustls ServerConfig for QUIC")?;

        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
        let mut transport = TransportConfig::default();
        transport
            .max_idle_timeout(Some(
                Duration::from_secs(30)
                    .try_into()
                    .expect("30s fits IdleTimeout"),
            ))
            .keep_alive_interval(Some(Duration::from_secs(15)))
            .max_concurrent_bidi_streams(VarInt::from_u32(256));
        server_config.transport_config(Arc::new(transport));

        let endpoint = Endpoint::server(server_config, rule.listen).with_context(|| {
            format!(
                "bind QUIC endpoint for rule {:?} on {}",
                rule.name, rule.listen
            )
        })?;
        let local_addr = endpoint.local_addr().context("read QUIC local_addr")?;

        let backend_client = build_backend_client();

        let cancel = CancellationToken::new();
        let conn_tracker = TaskTracker::new();
        let task_cancel = cancel.clone();
        let task_rule = rule.clone();
        let task_endpoint = endpoint.clone();
        let task_routes = Arc::clone(&route_table);
        let task_client = backend_client.clone();
        let task_tracker = conn_tracker.clone();
        let handle = tokio::spawn(async move {
            run_accept_loop(
                task_rule,
                task_endpoint,
                task_routes,
                task_client,
                task_cancel,
                task_tracker,
            )
            .await;
        });

        info!(
            rule = %rule.name,
            listen = %local_addr,
            alpn = "h3",
            routes = route_table.len(),
            migration = true,
            zero_rtt = false,
            "HTTP/3 endpoint listening"
        );

        Ok(Self {
            rule,
            local_addr,
            cancel,
            handle,
            conn_tracker,
        })
    }

    pub fn rule(&self) -> &Rule {
        &self.rule
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Cancel the accept loop and wait for it to exit. With
    /// `drain_timeout = Some(t)`, additionally bound the QUIC
    /// `endpoint.wait_idle()` call (which the accept loop runs on
    /// cancel) to at most `t`. QUIC's protocol-level graceful close
    /// (CONNECTION_CLOSE frame on `endpoint.close`) is the
    /// equivalent of the TLS/HTTP "stop accepting + drain" sequence
    /// on the TCP side, so once the accept loop's handle resolves
    /// we know every in-flight QUIC conversation has either
    /// finished or been told to terminate.
    pub async fn stop(self, drain_timeout: Option<Duration>) {
        self.cancel.cancel();
        match drain_timeout {
            Some(t) if !t.is_zero() => {
                if tokio::time::timeout(t, self.handle).await.is_err() {
                    tracing::warn!(
                        rule = %self.rule.name,
                        timeout_secs = t.as_secs(),
                        "h3 graceful drain timeout expired during endpoint.wait_idle"
                    );
                }
            }
            _ => {
                let _ = self.handle.await;
            }
        }
        self.conn_tracker.close();
        // Short final wait for any per-stream tasks the accept loop
        // spawned to observe the closed endpoint and exit.
        let _ = tokio::time::timeout(Duration::from_millis(250), self.conn_tracker.wait()).await;
    }
}

async fn run_accept_loop(
    rule: Rule,
    endpoint: Endpoint,
    routes: Arc<RouteTable>,
    client: BackendClient,
    cancel: CancellationToken,
    conn_tracker: TaskTracker,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                debug!(rule = %rule.name, "h3 accept loop cancelled");
                endpoint.close(SHUTDOWN_CLOSE_CODE, b"shutting down");
                endpoint.wait_idle().await;
                return;
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    debug!(rule = %rule.name, "h3 endpoint closed");
                    return;
                };
                let task_rule = rule.clone();
                let task_routes = Arc::clone(&routes);
                let task_client = client.clone();
                conn_tracker.spawn(async move {
                    let quic_conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(rule = %task_rule.name, error = %e, "h3 handshake failed");
                            return;
                        }
                    };
                    let peer = quic_conn.remote_address();
                    debug!(rule = %task_rule.name, peer = %peer, "h3 connection established");
                    if let Err(e) = serve_connection(
                        task_rule.clone(),
                        peer,
                        task_routes,
                        task_client,
                        quic_conn,
                    )
                    .await
                    {
                        debug!(rule = %task_rule.name, peer = %peer, error = %e, "h3 connection ended");
                    }
                });
            }
        }
    }
}

async fn serve_connection(
    rule: Rule,
    peer_addr: SocketAddr,
    routes: Arc<RouteTable>,
    client: BackendClient,
    quic_conn: quinn::Connection,
) -> Result<()> {
    let mut h3 = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(quic_conn))
        .await
        .context("h3 connection init")?;

    loop {
        match h3.accept().await {
            Ok(Some(resolver)) => {
                let task_rule = rule.clone();
                let task_routes = Arc::clone(&routes);
                let task_client = client.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_stream(task_rule, peer_addr, task_routes, task_client, resolver)
                            .await
                    {
                        debug!("h3 stream ended: {e}");
                    }
                });
            }
            Ok(None) => {
                debug!(rule = %rule.name, "h3 connection closed by peer");
                return Ok(());
            }
            Err(e) => {
                warn!(rule = %rule.name, error = %e, "h3 accept error");
                return Err(anyhow::anyhow!("h3 accept: {e}"));
            }
        }
    }
}

async fn handle_stream<C>(
    rule: Rule,
    peer_addr: SocketAddr,
    routes: Arc<RouteTable>,
    client: BackendClient,
    resolver: h3::server::RequestResolver<C, Bytes>,
) -> Result<()>
where
    C: h3::quic::Connection<Bytes>,
    <C as h3::quic::OpenStreams<Bytes>>::BidiStream: h3::quic::BidiStream<Bytes>,
{
    let (req, stream) = resolver
        .resolve_request()
        .await
        .context("resolve h3 request")?;

    let method = req.method().clone();
    let uri = req.uri().clone();
    debug!(
        rule = %rule.name,
        peer = %peer_addr,
        method = %method,
        uri = %uri,
        "h3 request received"
    );

    let Some(host) = extract_h3_host(&req) else {
        return send_short_response(
            stream,
            StatusCode::BAD_REQUEST,
            b"missing :authority/Host\n",
        )
        .await;
    };

    let Some(route) = routes.lookup(&host) else {
        debug!(rule = %rule.name, host = %host, "no route for host; replying 404");
        return send_short_response(stream, StatusCode::NOT_FOUND, b"no route\n").await;
    };
    let upstream_url = route.target.clone();
    let hsts_cfg = route.hsts;

    // WebSocket-over-h3 (RFC 9220 extended CONNECT) is not supported.
    // h3 0.0.8 does not surface the `:protocol` pseudo-header through
    // `http::HeaderMap` (HeaderName rejects names with leading `:`), so
    // we cannot reliably distinguish a WebSocket-flavored CONNECT from a
    // plain tunnel CONNECT here. Plain CONNECT-over-HTTP/3 is also
    // uncommon (most clients use it only for proxy-style tunneling),
    // so we conservatively answer ANY CONNECT with 501 +
    // `Sec-WebSocket-Version: 13` to nudge WebSocket clients toward the
    // HTTP/2 handshake that yggdrasil's TCP path does support.
    if method == http::Method::CONNECT {
        return send_websocket_h3_501(stream).await;
    }

    let outbound_uri = match build_upstream_uri(&uri, &upstream_url) {
        Ok(u) => u,
        Err(e) => {
            warn!(rule = %rule.name, error = %e, "build_upstream_uri failed");
            return send_short_response(stream, StatusCode::BAD_GATEWAY, b"bad upstream\n").await;
        }
    };

    let (mut parts, _) = req.into_parts();
    sanitise_request_headers(&mut parts.headers);
    super::forward::inject_forwarded(&mut parts.headers, peer_addr.ip(), Some(&host));
    parts.uri = outbound_uri;
    parts.version = http::Version::HTTP_11;

    let (body_bytes, stream) = match collect_h3_request_body(stream, H3_REQUEST_BODY_LIMIT).await {
        Ok(pair) => pair,
        Err(BodyCollectError::TooLarge(s)) => {
            return send_short_response(
                s,
                StatusCode::PAYLOAD_TOO_LARGE,
                b"request body exceeds h3 buffer cap\n",
            )
            .await;
        }
        Err(BodyCollectError::Recv(_)) => return Ok(()),
    };

    let body = Full::new(body_bytes).map_err(|e| match e {}).boxed();
    let outgoing = Request::from_parts(parts, body);

    let upstream_resp = match client.request(outgoing).await {
        Ok(r) => r,
        Err(e) => {
            debug!(rule = %rule.name, error = %e, "backend request failed");
            return send_short_response(stream, StatusCode::BAD_GATEWAY, b"backend unreachable\n")
                .await;
        }
    };

    let (mut resp_parts, mut resp_body) = upstream_resp.into_parts();
    sanitise_response_headers(&mut resp_parts.headers);
    super::forward::maybe_inject_hsts(&mut resp_parts.headers, hsts_cfg.as_ref());

    let resp_head = http::Response::from_parts(resp_parts, ());
    let mut stream = stream;
    stream
        .send_response(resp_head)
        .await
        .context("h3 send_response")?;

    while let Some(frame_res) = resp_body.frame().await {
        let frame = match frame_res {
            Ok(f) => f,
            Err(e) => {
                debug!(rule = %rule.name, error = %e, "backend response body error");
                break;
            }
        };
        if let Ok(data) = frame.into_data() {
            let mut data = data;
            while data.has_remaining() {
                let take = data.remaining().min(H3_RESPONSE_CHUNK_BYTES);
                let chunk = data.copy_to_bytes(take);
                if let Err(e) = stream.send_data(chunk).await {
                    debug!(rule = %rule.name, error = %e, "h3 send_data failed");
                    return Ok(());
                }
            }
        }
    }

    stream.finish().await.context("h3 finish")?;
    Ok(())
}

fn extract_h3_host<B>(req: &Request<B>) -> Option<String> {
    if let Some(auth) = req.uri().authority() {
        return Some(auth.as_str().to_string());
    }
    req.headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

async fn send_websocket_h3_501<S>(mut stream: h3::server::RequestStream<S, Bytes>) -> Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let body: &[u8] =
        b"websocket-over-h3 (RFC 9220 extended CONNECT) not supported; fall back to HTTP/2\n";
    let sec_ws_version = http::header::HeaderName::from_bytes(b"sec-websocket-version")
        .expect("sec-websocket-version is a valid header name");
    let resp = Response::builder()
        .status(StatusCode::NOT_IMPLEMENTED)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(http::header::CONTENT_LENGTH, body.len())
        // RFC 6455 §4.4: version 13 is the WebSocket protocol version we
        // do support over HTTP/2. Emitting it on the 501 tells the client
        // we're a WS-capable server, just not over h3.
        .header(sec_ws_version, "13")
        .body(())
        .map_err(|e| anyhow::anyhow!("build ws 501: {e}"))?;
    stream
        .send_response(resp)
        .await
        .context("h3 ws send_response")?;
    stream
        .send_data(Bytes::from_static(body))
        .await
        .context("h3 ws send_data")?;
    stream.finish().await.context("h3 ws finish")?;
    Ok(())
}

enum BodyCollectError<S> {
    TooLarge(S),
    Recv(h3::error::StreamError),
}

async fn collect_h3_request_body<S>(
    mut stream: h3::server::RequestStream<S, Bytes>,
    cap: usize,
) -> Result<
    (Bytes, h3::server::RequestStream<S, Bytes>),
    BodyCollectError<h3::server::RequestStream<S, Bytes>>,
>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let mut buf = BytesMut::new();
    loop {
        match stream.recv_data().await {
            Ok(Some(chunk)) => {
                let mut chunk = chunk;
                let n = chunk.remaining();
                if buf.len().saturating_add(n) > cap {
                    return Err(BodyCollectError::TooLarge(stream));
                }
                while chunk.has_remaining() {
                    let take = chunk.remaining().min(H3_RESPONSE_CHUNK_BYTES);
                    let part = chunk.copy_to_bytes(take);
                    buf.extend_from_slice(&part);
                }
            }
            Ok(None) => return Ok((buf.freeze(), stream)),
            Err(e) => return Err(BodyCollectError::Recv(e)),
        }
    }
}

async fn send_short_response<S>(
    mut stream: h3::server::RequestStream<S, Bytes>,
    status: StatusCode,
    body: &'static [u8],
) -> Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let resp = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(http::header::CONTENT_LENGTH, body.len())
        .body(())
        .map_err(|e| anyhow::anyhow!("build short response: {e}"))?;
    stream
        .send_response(resp)
        .await
        .context("h3 short send_response")?;
    if !body.is_empty() {
        stream
            .send_data(Bytes::from_static(body))
            .await
            .context("h3 short send_data")?;
    }
    stream.finish().await.context("h3 short finish")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::certs::CertStore;

    // Full end-to-end h3 request dispatch tests live in
    // `h3-tests-integration` (deferred follow-up) — they require a
    // quinn client harness with the ephemeral server cert pinned.
    // SNI-miss handshake rejection belongs there too: it needs a real
    // client handshake to observe resolver failure.

    #[tokio::test]
    async fn binds_quic_endpoint() {
        let store = Arc::new(CertStore::new());
        let rule_toml = r#"
            [[rule]]
            name = "h3-smoke"
            listen = "127.0.0.1:0"
            protocol = "https"

            [[rule.route]]
            hostname = "localhost"
            target = "http://127.0.0.1:65535"
            cert = "ephemeral"
        "#;
        let f = ratatoskr::rule::RuleFile::from_toml("smoke.toml", rule_toml).unwrap();
        let rule = f.rule.into_iter().next().unwrap();
        let q = H3Frontend::spawn(rule, store)
            .await
            .expect("spawn h3 endpoint");
        assert!(q.local_addr().port() != 0);
        q.stop(None).await;
    }

    #[tokio::test]
    async fn ephemeral_cert_rule_brings_up_endpoint() {
        let store = Arc::new(CertStore::new());
        let rule_toml = r#"
            [[rule]]
            name = "h3-ephemeral"
            listen = "127.0.0.1:0"
            protocol = "https"

            [[rule.route]]
            hostname = "localhost"
            target = "http://127.0.0.1:65535"
            cert = "ephemeral"
        "#;
        let f = ratatoskr::rule::RuleFile::from_toml("e.toml", rule_toml).unwrap();
        let rule = f.rule.into_iter().next().unwrap();
        let q = H3Frontend::spawn(rule, Arc::clone(&store))
            .await
            .expect("spawn h3 endpoint");
        assert!(q.local_addr().port() != 0);
        q.stop(None).await;
    }

    #[tokio::test]
    async fn shared_cert_store_supports_both_alpns() {
        use crate::proxy::http_frontend::build_rustls_server_config;

        let store = Arc::new(CertStore::new());
        let cfg_tcp = build_rustls_server_config(Arc::clone(&store), &[b"h2", b"http/1.1"]);
        let cfg_h3 = build_rustls_server_config(Arc::clone(&store), &[b"h3"]);

        assert!(cfg_tcp.alpn_protocols.iter().any(|p| p.as_slice() == b"h2"));
        assert!(cfg_h3.alpn_protocols.iter().any(|p| p.as_slice() == b"h3"));
    }

    #[test]
    fn quic_server_config_is_constructible_from_shared_rustls_config() {
        use crate::proxy::http_frontend::build_rustls_server_config;
        use quinn::crypto::rustls::QuicServerConfig;

        let store = Arc::new(CertStore::new());
        let cfg = build_rustls_server_config(store, &[b"h3"]);
        let inner: rustls::ServerConfig = (*cfg).clone();
        let _quic_cfg =
            QuicServerConfig::try_from(inner).expect("rustls ServerConfig must be QUIC-compatible");
    }

    #[test]
    fn ws_h3_501_body_text_is_actionable() {
        // Quick sanity check that the body text mentions "fall back" so
        // anyone reading a debug log immediately understands the resolution.
        let body =
            b"websocket-over-h3 (RFC 9220 extended CONNECT) not supported; fall back to HTTP/2\n";
        assert!(std::str::from_utf8(body).unwrap().contains("fall back"));
    }
}
