//! Plain `:80` redirect listener (shared per IP across all HTTPS rules).
//!
//! Split out from the original monolithic `http_frontend.rs` (Phase B4).

use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::proxy::acme::http01::{parse_challenge_path, AcmeResponder};

use super::request::{extract_host, short_response};

/// One per `(supervisor, IpAddr)`. Owns a TCP listener bound to `(ip, 80)`
/// and serves:
///
/// * `GET /.well-known/acme-challenge/<token>` — when an ACME
///   responder is attached and the token is registered, returns the
///   key-authorization as `text/plain`.
/// * Everything else — `301 Moved Permanently` to the matching HTTPS
///   URL when the host is registered, `404` otherwise.
pub struct RedirectListener {
    ip: IpAddr,
    local_addr: SocketAddr,
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
    /// Per-IP set of hostnames that should be redirected to HTTPS. The
    /// supervisor mutates this on rule reload.
    hosts: Arc<parking_lot::RwLock<HostSet>>,
    /// Optional ACME HTTP-01 responder. Attached at supervisor startup
    /// when an `[acme]` section is configured. `None` on daemons that
    /// don't use ACME — the redirect listener then behaves as before.
    acme: Arc<parking_lot::RwLock<Option<AcmeResponder>>>,
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
        let acme: Arc<parking_lot::RwLock<Option<AcmeResponder>>> =
            Arc::new(parking_lot::RwLock::new(None));
        let cancel = parent.child_token();

        let task_hosts = Arc::clone(&hosts);
        let task_acme = Arc::clone(&acme);
        let task_cancel = cancel.clone();

        let handle = tokio::spawn(async move {
            redirect_accept_loop(listener, task_hosts, task_acme, task_cancel).await;
        });

        info!(bind = %local_addr, "HTTP→HTTPS redirect listener active");

        Ok(Self {
            ip,
            local_addr,
            cancel,
            handle,
            hosts,
            acme,
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

    /// Attach (or replace) the ACME HTTP-01 responder for this listener.
    /// When set, inbound `/.well-known/acme-challenge/<token>` requests
    /// are answered with the registered key-authorization (status `200
    /// text/plain`) instead of being redirected.
    pub fn set_acme_responder(&self, responder: AcmeResponder) {
        *self.acme.write() = Some(responder);
    }

    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = self.handle.await;
    }
}

async fn redirect_accept_loop(
    listener: TcpListener,
    hosts: Arc<parking_lot::RwLock<HostSet>>,
    acme: Arc<parking_lot::RwLock<Option<AcmeResponder>>>,
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
                let a = Arc::clone(&acme);
                let c = cancel.child_token();
                tokio::spawn(async move {
                    if let Err(e) = serve_redirect(tcp, peer, h, a, c).await {
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
    acme: Arc<parking_lot::RwLock<Option<AcmeResponder>>>,
    _cancel: CancellationToken,
) -> io::Result<()> {
    let io = TokioIo::new(tcp);
    let service = service_fn(move |req: Request<Incoming>| {
        let h = Arc::clone(&hosts);
        let a = Arc::clone(&acme);
        async move {
            let resp = build_redirect_response(req, &h, &a);
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
    acme: &Arc<parking_lot::RwLock<Option<AcmeResponder>>>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    // ACME HTTP-01 challenge: matches before the redirect path so the
    // CA gets its key-auth instead of being bounced to https://.
    let path = req.uri().path();
    if let Some(token) = parse_challenge_path(path) {
        if let Some(responder) = acme.read().as_ref() {
            if let Some(key_auth) = responder.lookup(token) {
                let body = Full::new(Bytes::from(key_auth))
                    .map_err(|e| match e {})
                    .boxed();
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(body)
                    .expect("acme-challenge response builds");
            }
        }
        // Path looked like a challenge but the token is unknown —
        // explicitly 404 rather than 301-ing to HTTPS, which would
        // confuse the CA.
        return short_response(StatusCode::NOT_FOUND, "");
    }

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

#[cfg(test)]
mod tests {
    use super::*;

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
