//! Per-IP `:80` companion listener.
//!
//! Originally a minimal HTTP→HTTPS redirector (the old
//! `RedirectListener`); now broadened into a four-step pipeline that
//! also serves cert-less route plaintext traffic to LAN peers. One
//! instance per `(supervisor, IpAddr)`.
//!
//! ## Pipeline
//!
//! 1. **ACME** — `GET /.well-known/acme-challenge/<token>` is served
//!    regardless of source IP (per Let's Encrypt's HTTP-01 docs the
//!    challenge can only be done on port 80, and the CA's prober must
//!    reach this from the public internet).
//! 2. **Cert-less route** — if the inbound TCP peer's IP is in the
//!    resolved [`LanCidrs`] set AND `Host` matches a cert-less route
//!    in [`Self::plaintext_routes`], proxy plaintext via
//!    [`crate::proxy::http_frontend::request::serve_request`] with
//!    `ConnContext { tls: false, .. }`. Reuses the full HTTPS request
//!    pipeline (`sanitise_request_headers`, `inject_forwarded`,
//!    `build_upstream_uri`, hop-by-hop strip, WebSocket upgrade).
//! 3. **Cert'd-host redirect** — else if `Host` matches a cert'd
//!    hostname in the per-IP [`HostSet`], emit
//!    `301 Location: https://<host><path>` regardless of source IP
//!    (a WAN browser that typed `http://` deserves the redirect; the
//!    response leaks no backend bytes).
//! 4. **404** — else.
//!
//! Step 2's source-IP filter is the trust boundary for cert-less
//! routes; see [`crate::lan_cidrs`] for the criterion and its
//! grounding.

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

use crate::lan_cidrs::LanCidrsSnapshot;
use crate::proxy::acme::http01::{parse_challenge_path, AcmeResponder};

use super::backend::{build_backend_client, BackendClient};
use super::request::{extract_host, serve_request, short_response, ConnContext};
use super::route::RouteTable;

/// One per `(supervisor, IpAddr)`. Owns a TCP listener bound to
/// `(ip, 80)` (or the configured `http_redirect_port`).
///
/// The type name is kept as `RedirectListener` for source-level
/// continuity with the original implementation, but the contract is
/// now broader — see the module-level docs for the four-step pipeline.
pub struct RedirectListener {
    ip: IpAddr,
    local_addr: SocketAddr,
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
    /// Per-IP set of cert'd hostnames that should be redirected to
    /// HTTPS. The supervisor mutates this on rule reload via
    /// `register_host` / `unregister_host`.
    hosts: Arc<parking_lot::RwLock<HostSet>>,
    /// Per-IP table of cert-less routes (`HttpRoute` with no cert
    /// source resolved). The supervisor mutates this on rule reload
    /// via `register_plaintext_routes` / `unregister_plaintext_routes`.
    /// Lookups are gated by the source-IP filter in
    /// [`Self::lan_cidrs`].
    plaintext_routes: Arc<parking_lot::RwLock<RouteTable>>,
    /// Resolved LAN-CIDR snapshot — see [`crate::lan_cidrs`]. `None`
    /// before the supervisor has called [`Self::set_lan_cidrs`];
    /// while `None`, cert-less route serving is suppressed (the
    /// safe default).
    lan_cidrs: Arc<parking_lot::RwLock<Option<LanCidrsSnapshot>>>,
    /// Optional ACME HTTP-01 responder. Attached at supervisor startup
    /// when an `[acme]` section is configured.
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
            .with_context(|| format!("bind :{port} companion listener on {bind}"))?;
        let local_addr = listener.local_addr().context("read companion local_addr")?;

        let hosts = Arc::new(parking_lot::RwLock::new(HostSet::default()));
        let plaintext_routes = Arc::new(parking_lot::RwLock::new(RouteTable::build(&[], "")));
        let lan_cidrs: Arc<parking_lot::RwLock<Option<LanCidrsSnapshot>>> =
            Arc::new(parking_lot::RwLock::new(None));
        let acme: Arc<parking_lot::RwLock<Option<AcmeResponder>>> =
            Arc::new(parking_lot::RwLock::new(None));
        let task_client = build_backend_client();
        let cancel = parent.child_token();

        let task_hosts = Arc::clone(&hosts);
        let task_plaintext = Arc::clone(&plaintext_routes);
        let task_lan = Arc::clone(&lan_cidrs);
        let task_acme = Arc::clone(&acme);
        let task_cancel = cancel.clone();
        let task_local = local_addr;

        let handle = tokio::spawn(async move {
            companion_accept_loop(
                listener,
                task_local,
                task_hosts,
                task_plaintext,
                task_lan,
                task_acme,
                task_client,
                task_cancel,
            )
            .await;
        });

        info!(bind = %local_addr, "companion (:80) listener active");

        Ok(Self {
            ip,
            local_addr,
            cancel,
            handle,
            hosts,
            plaintext_routes,
            lan_cidrs,
            acme,
        })
    }

    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Register a cert'd hostname for HTTPS redirect handling.
    /// Refcounted; the listener retains the host until the matching
    /// `unregister_host` call.
    pub fn register_host(&self, host: &str) {
        self.hosts.write().add(host);
    }

    pub fn unregister_host(&self, host: &str) {
        self.hosts.write().remove(host);
    }

    /// True when neither cert'd hosts nor cert-less routes are
    /// registered on this listener. Used by the supervisor to decide
    /// when the per-IP companion can be torn down.
    pub fn is_empty(&self) -> bool {
        self.hosts.read().is_empty() && self.plaintext_routes.read().is_empty()
    }

    /// Aggregate this rule's cert-less routes into the per-IP
    /// plaintext route table. Returns the list of hostnames that
    /// collided with previously-registered routes (different rule's
    /// route for the same hostname) — the supervisor surfaces these
    /// as a `WARN` for the operator.
    pub fn register_plaintext_routes(
        &self,
        routes: &[ratatoskr::rule::HttpRoute],
        rule_name: &str,
    ) -> Vec<String> {
        self.plaintext_routes.write().extend(routes, rule_name)
    }

    /// Drop every cert-less route contributed by `rule_name`. Called
    /// on rule removal or before re-registering a changed rule's
    /// routes during hot reload.
    pub fn unregister_plaintext_routes(&self, rule_name: &str) -> Vec<String> {
        self.plaintext_routes.write().remove_by_rule(rule_name)
    }

    /// Install or replace the resolved [`LanCidrs`] snapshot. The
    /// supervisor calls this once at startup and again on hot reload
    /// when `[server].lan_cidrs` changes. Setting `None` suppresses
    /// the cert-less route branch entirely until a new snapshot
    /// arrives.
    pub fn set_lan_cidrs(&self, snapshot: Option<LanCidrsSnapshot>) {
        *self.lan_cidrs.write() = snapshot;
    }

    /// Attach (or replace) the ACME HTTP-01 responder for this listener.
    /// When set, inbound `/.well-known/acme-challenge/<token>` requests
    /// are answered with the registered key-authorization (status `200
    /// text/plain`) instead of falling through to the redirect / 404
    /// branches.
    pub fn set_acme_responder(&self, responder: AcmeResponder) {
        *self.acme.write() = Some(responder);
    }

    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = self.handle.await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn companion_accept_loop(
    listener: TcpListener,
    local_addr: SocketAddr,
    hosts: Arc<parking_lot::RwLock<HostSet>>,
    plaintext_routes: Arc<parking_lot::RwLock<RouteTable>>,
    lan_cidrs: Arc<parking_lot::RwLock<Option<LanCidrsSnapshot>>>,
    acme: Arc<parking_lot::RwLock<Option<AcmeResponder>>>,
    backend_client: BackendClient,
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
                        warn!(error = %e, "companion listener accept failed");
                        continue;
                    }
                };
                let h = Arc::clone(&hosts);
                let pr = Arc::clone(&plaintext_routes);
                let lc = Arc::clone(&lan_cidrs);
                let a = Arc::clone(&acme);
                let bc = backend_client.clone();
                let c = cancel.child_token();
                tokio::spawn(async move {
                    if let Err(e) = serve_companion(
                        tcp, peer, local_addr, h, pr, lc, a, bc, c,
                    ).await {
                        debug!(client = %peer, error = %e, "companion connection ended");
                    }
                });
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_companion(
    tcp: TcpStream,
    peer: SocketAddr,
    local_addr: SocketAddr,
    hosts: Arc<parking_lot::RwLock<HostSet>>,
    plaintext_routes: Arc<parking_lot::RwLock<RouteTable>>,
    lan_cidrs: Arc<parking_lot::RwLock<Option<LanCidrsSnapshot>>>,
    acme: Arc<parking_lot::RwLock<Option<AcmeResponder>>>,
    backend_client: BackendClient,
    _cancel: CancellationToken,
) -> io::Result<()> {
    let io_stream = TokioIo::new(tcp);
    let service = service_fn(move |req: Request<Incoming>| {
        let h = Arc::clone(&hosts);
        let pr = Arc::clone(&plaintext_routes);
        let lc = Arc::clone(&lan_cidrs);
        let a = Arc::clone(&acme);
        let bc = backend_client.clone();
        async move {
            let resp = dispatch(req, peer, local_addr, &h, &pr, &lc, &a, &bc).await;
            Ok::<_, Infallible>(resp)
        }
    });

    // .with_upgrades() enables WebSocket support on cert-less routes.
    if let Err(e) = http1::Builder::new()
        .keep_alive(true)
        .serve_connection(io_stream, service)
        .with_upgrades()
        .await
    {
        debug!(error = %e, "companion serve_connection ended");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn dispatch(
    req: Request<Incoming>,
    peer: SocketAddr,
    local_addr: SocketAddr,
    hosts: &Arc<parking_lot::RwLock<HostSet>>,
    plaintext_routes: &Arc<parking_lot::RwLock<RouteTable>>,
    lan_cidrs: &Arc<parking_lot::RwLock<Option<LanCidrsSnapshot>>>,
    acme: &Arc<parking_lot::RwLock<Option<AcmeResponder>>>,
    backend_client: &BackendClient,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    // ---- Step 1: ACME ------------------------------------------------
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

    // ---- Step 2: cert-less plaintext serving --------------------------
    // Snapshot the routes + lan_cidrs to decide whether this request is
    // eligible. We do not hold the lock across the await — we clone the
    // matched RouteEntry's data out.
    let plaintext_match: Option<(String, String, url::Url)> = {
        // Inner scope so the read guard is released before async work.
        let routes = plaintext_routes.read();
        routes
            .lookup(bare_host)
            .map(|e| (e.rule_name.clone(), bare_host.to_string(), e.target.clone()))
    };
    if let Some((rule_name, _host, target)) = plaintext_match {
        // LAN-CIDR membership test. `None` snapshot means
        // cert-less serving is suppressed for safety.
        let lan_allows: bool = lan_cidrs
            .read()
            .as_ref()
            .map(|lc| lc.contains(peer.ip()))
            .unwrap_or(false);
        if lan_allows {
            metrics::counter!(
                "yggdrasil_certless_requests_total",
                "rule" => rule_name.clone(),
                "hostname" => bare_host.to_string(),
            )
            .increment(1);

            // Build a fresh ConnContext for this request. The route
            // table contains only this one route (the matched one) so
            // serve_request's lookup re-resolves it — this matches the
            // existing :443 path where the per-route Arc<RouteTable>
            // is shared across the whole connection.
            //
            // We could also clone the per-IP table, but the matched
            // route is the only one this request needs. The single-
            // route table keeps memory bounded per-request.
            use ratatoskr::rule::HttpRoute;
            let single_route = vec![HttpRoute {
                hostname: bare_host.to_string(),
                target,
                hsts: None,
                headers: std::collections::BTreeMap::new(),
            }];
            let route_table = Arc::new(RouteTable::build(&single_route, &rule_name));
            let ctx = Arc::new(ConnContext {
                rule: None,
                rule_name: rule_name.clone(),
                client_addr: peer,
                local_addr,
                routes: route_table,
                client: backend_client.clone(),
                tls: false,
                emit_alt_svc: false,
            });
            // Stash so the compiler doesn't think we're using moved
            // values across the await below.
            let _ = backend_client; // ensure we keep ownership semantics consistent
            return serve_request(ctx, req).await;
        } else {
            // Cert-less route exists for this hostname but the source
            // IP isn't in lan_cidrs. Counter-intuitively we still
            // return 404 (not 403) — exposing the existence of the
            // route would be a small information leak, and 404 is
            // what an unconfigured server would say.
            metrics::counter!(
                "yggdrasil_certless_requests_denied_total",
                "rule" => rule_name,
                "reason" => "peer_not_in_lan_cidrs",
            )
            .increment(1);
            return short_response(StatusCode::NOT_FOUND, "no route\n");
        }
    }

    // ---- Step 3: HTTPS-host 301 redirect ------------------------------
    if hosts.read().contains(bare_host) {
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let location = format!("https://{bare_host}{path_and_query}");
        let body = Empty::<Bytes>::new().map_err(|e| match e {}).boxed();
        return Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header(http::header::LOCATION, location)
            .body(body)
            .expect("redirect response builds");
    }

    // ---- Step 4: 404 --------------------------------------------------
    short_response(StatusCode::NOT_FOUND, "no route\n")
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
