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
//!
//! ## Module layout (Phase B4 split)
//!
//! - [`acceptor`] — TCP accept loop + PROXY/TLS/HTTP per-connection
//!   dispatch and `PrefixedStream`.
//! - [`backend`] — pooled `hyper_util` HTTP backend client.
//! - [`request`] — per-request route lookup, forward, header surgery,
//!   websocket upgrade bridging.
//! - [`route`] — `RouteTable` hostname → upstream mapping.
//! - [`redirect`] — shared `:80` HTTP→HTTPS redirect listener.

mod acceptor;
mod backend;
mod redirect;
mod request;
mod route;

pub use redirect::RedirectListener;
pub use route::RouteTable;

pub(crate) use backend::{build_backend_client, BackendClient};
pub(crate) use request::{sanitise_request_headers, sanitise_response_headers};

// `build_upstream_uri` is re-exported here so callers that historically
// reached for `super::http_frontend::build_upstream_uri` (notably the
// HTTP/3 frontend) keep their import paths unchanged.
pub(crate) use crate::proxy::forward::build_upstream_uri;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::info;

use ratatoskr::rule::Rule;

use crate::proxy::certs::CertStore;

/// Build a `rustls::ServerConfig` for an HTTPS rule.
///
/// `alpns` is caller-supplied so the same builder serves both the TCP
/// acceptor (`["h2", "http/1.1"]`) and the future QUIC acceptor (`["h3"]`).
/// The cert_resolver is the shared per-supervisor `CertStore` — every HTTPS
/// rule uses the same store, so cert rotation propagates uniformly.
///
/// Cert rotation that updates the underlying `CertStore` is observed by both
/// TCP and QUIC acceptors automatically — both hold an `Arc<dyn
/// ResolvesServerCert>` pointing at the same store.
///
/// Returns an `Arc<ServerConfig>` so callers can clone it cheaply when they
/// need to hand it to both `tokio_rustls::TlsAcceptor` and
/// `quinn::crypto::rustls::QuicServerConfig::try_from(...)`.
pub(crate) fn build_rustls_server_config(
    cert_store: Arc<CertStore>,
    alpns: &[&[u8]],
) -> Arc<ServerConfig> {
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(cert_store);
    cfg.alpn_protocols = alpns.iter().map(|alpn| alpn.to_vec()).collect();
    Arc::new(cfg)
}

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

        let server_config = build_rustls_server_config(cert_store, &[b"h2", b"http/1.1"]);
        let acceptor = TlsAcceptor::from(server_config);

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

        let task_rule = Arc::new(rule.clone());
        let task_rule_name = rule.name.clone();
        let task_cancel = cancel.clone();
        let task_routes = Arc::clone(&route_table);
        let task_acceptor = acceptor.clone();
        let task_client = backend_client.clone();
        let task_local = local_addr;

        let handle = tokio::spawn(async move {
            acceptor::accept_loop(
                task_rule_name,
                task_rule,
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

#[cfg(test)]
mod tests {
    use super::*;
    use http::Uri;
    use url::Url;

    #[test]
    fn server_config_is_quic_compatible() {
        let store = Arc::new(CertStore::new());
        let cfg = build_rustls_server_config(store, &[b"h3"]);
        let inner: rustls::ServerConfig = (*cfg).clone();
        let _quic_cfg = quinn::crypto::rustls::QuicServerConfig::try_from(inner)
            .expect("ServerConfig must be QUIC-compatible");
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
}
