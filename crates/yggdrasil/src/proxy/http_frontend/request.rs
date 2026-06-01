//! Per-request handling: route lookup, forward, header surgery, websocket
//! upgrade bridging.
//!

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use bytes::Bytes;
use http::header::{
    HeaderMap, HeaderName, HeaderValue, CONNECTION, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION,
    TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::{Request, Response, StatusCode, Version};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tracing::debug;
use url::Url;

use crate::proxy::forward::{
    apply_static_response_headers, build_upstream_uri, inject_forwarded, maybe_inject_hsts,
    strip_hop_by_hop, strip_untrusted_forwarding,
};

use super::backend::BackendClient;

pub(crate) struct ConnContext {
    /// Owning [`Rule`] for this connection. Only consulted by the
    /// alt-svc injection path, which is gated on [`Self::tls`] and so
    /// never reads `rule` on the companion listener's plaintext path.
    /// `None` is therefore acceptable when `tls == false`; the
    /// HTTPS frontend always sets `Some`.
    pub(crate) rule: Option<Arc<ratatoskr::rule::Rule>>,
    pub(crate) rule_name: String,
    pub(crate) client_addr: SocketAddr,
    /// Shared route table. Held under a `RwLock` so the supervisor can
    /// hot-swap the entries on route addition / removal / edit without
    /// disturbing in-flight TLS connections or HTTP/2 streams. Read
    /// once per request via a brief read-guard; the matched route's
    /// data is cloned out and the guard is dropped before any
    /// `.await`.
    pub(crate) routes: Arc<parking_lot::RwLock<super::route::RouteTable>>,
    pub(crate) client: BackendClient,
    /// `true` when this connection was accepted on a TLS-terminated
    /// listener (the HTTPS frontend, also HTTP/3). `false` when accepted
    /// on the per-IP companion listener's `:80` plaintext path.
    /// Controls the injected `X-Forwarded-Proto` header and gates the
    /// `Alt-Svc` advertisement (plaintext responses don't advertise an
    /// HTTP/3 alternative).
    pub(crate) tls: bool,
    /// Should the frontend emit `Alt-Svc: h3=":..."` on TLS responses?
    /// Equivalent to `[server].https_http3 && [server].https_alt_svc`
    /// — we only advertise h3 when the h3 listener actually exists and
    /// the operator hasn't suppressed alt-svc.
    pub(crate) emit_alt_svc: bool,
}

impl ConnContext {
    /// Client-facing scheme as seen on the wire. Used by
    /// [`crate::proxy::forward::inject_forwarded`] to fill
    /// `X-Forwarded-Proto`.
    pub(crate) fn forwarded_scheme(&self) -> &'static str {
        if self.tls {
            "https"
        } else {
            "http"
        }
    }
}

pub(crate) async fn serve_request(
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
            let mut resp = short_response(StatusCode::BAD_REQUEST, "");
            maybe_inject_alt_svc(&mut resp, &ctx);
            return resp;
        }
    };

    // -------------------------------------------------------------------
    // Route lookup. Clone the matched route's data out under a brief
    // read-guard so the supervisor's hot-swap path (which takes a
    // write-guard) is never blocked behind an in-flight request, and
    // so the (parking_lot, !Send) guard never crosses an `.await`.
    // -------------------------------------------------------------------
    let route_data: Option<(String, Url, Option<ratatoskr::rule::HstsConfig>, std::collections::BTreeMap<String, String>)> = {
        let routes = ctx.routes.read();
        routes.lookup(&host).map(|r| {
            let label = host
                .rsplit_once(':')
                .map(|(h, _)| h)
                .unwrap_or(&host)
                .to_ascii_lowercase();
            (label, r.target.clone(), r.hsts, r.headers.clone())
        })
    };
    let (route_label, upstream_url, hsts_header, static_headers) = match route_data {
        Some(t) => t,
        None => {
            debug!(
                rule = %ctx.rule_name,
                host = %host,
                "no route for Host; replying 404"
            );
            let mut resp = short_response(StatusCode::NOT_FOUND, "no route\n");
            maybe_inject_alt_svc(&mut resp, &ctx);
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
    maybe_inject_hsts(resp.headers_mut(), hsts_header.as_ref());

    // Per-route static response headers (X-Robots-Tag, CSP,
    // X-Frame-Options, ...). Applied AFTER HSTS so operator-set headers
    // get the final word; HSTS uses its own reserved name and is
    // disallowed from `[[route]].headers` at config-load time anyway.
    apply_static_response_headers(resp.headers_mut(), &static_headers);

    maybe_inject_alt_svc(&mut resp, &ctx);
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
    inject_forwarded(
        &mut parts.headers,
        ctx.client_addr.ip(),
        Some(host),
        ctx.forwarded_scheme(),
    );

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
    inject_forwarded(
        &mut parts.headers,
        ctx.client_addr.ip(),
        Some(host),
        ctx.forwarded_scheme(),
    );

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

/// Header names to strip from inbound requests: pre-existing forwarding
/// claims (untrusted, we own the inbound edge) plus hop-by-hop per RFC 7230
/// §6.1. We do *not* strip Host — the route lookup needs it, and the
/// backend cares.
pub(crate) fn sanitise_request_headers(headers: &mut HeaderMap) {
    strip_hop_by_hop(headers);
    strip_untrusted_forwarding(headers);
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
    strip_untrusted_forwarding(headers);
}

pub(crate) fn sanitise_response_headers(headers: &mut HeaderMap) {
    strip_hop_by_hop(headers);
}

/// Append `Alt-Svc: h3=":<port>"; ma=86400` to a TCP HTTPS response when
/// the rule has HTTP/3 enabled. Idempotent: if the header is already set,
/// the existing value wins. Skipped for non-TLS responses (the
/// companion listener's plaintext `:80` path doesn't advertise an
/// HTTP/3 alternative because there isn't one — h3 requires TLS) and
/// for connections lacking a `rule` reference (companion path).
fn maybe_inject_alt_svc<B>(resp: &mut http::Response<B>, ctx: &ConnContext) {
    if !ctx.tls {
        return;
    }
    if !ctx.emit_alt_svc {
        return;
    }
    let Some(rule) = ctx.rule.as_ref() else {
        return;
    };
    if rule.protocol != ratatoskr::rule::Protocol::Https {
        return;
    }

    let alt_svc = HeaderName::from_static("alt-svc");
    if resp.headers().contains_key(&alt_svc) {
        return;
    }

    let value = format!("h3=\":{}\"; ma=86400", rule.listen.port());
    if let Ok(hv) = HeaderValue::from_str(&value) {
        resp.headers_mut().insert(alt_svc, hv);
    }
}

pub(crate) fn extract_host<B>(req: &Request<B>) -> Option<String> {
    // HTTP/2: :authority is canonical. HTTP/1.1: Host header.
    if let Some(auth) = req.uri().authority() {
        return Some(auth.as_str().to_string());
    }
    req.headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

pub(crate) fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
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

pub(crate) fn short_response(
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
}
