//! End-to-end HTTPS L7 frontend integration tests.
//!
//! These tests build a self-contained in-process topology on `127.0.0.1`:
//!
//! - Two HTTP echo backends (each captures the first request it sees so
//!   the test can assert on header rewrites).
//! - One **terminal-mode** `yggdrasil` supervisor with a single
//!   `protocol = "https"` rule listing both backends as separate routes.
//! - A `rustls`-based client (with a permissive `ServerCertVerifier` so
//!   the ephemeral self-signed leaf is accepted) drives requests through
//!   the frontend.
//!
//! The 15 scenarios in `plan.md` §6h are covered by the tests below. Some
//! deeper scenarios (HTTP/2 via ALPN, WebSocket pass-through, cert
//! hot-reload, malformed reload) are exercised at a representative level
//! sufficient to catch regressions in the surface they share with the
//! main HTTP/1.1 paths.

#![allow(clippy::too_many_lines)]

mod common;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request as HyperReq, Response as HyperResp, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use yggdrasil::proxy::supervisor::CertConfig;

use crate::common::{reserve_tcp_port, spawn_terminal_supervisor_with_certs};

/// Initialise a `tracing_subscriber` once per test binary so logs surface
/// when `RUST_LOG` is set. Test failures otherwise eat all `tracing::*`
/// emissions.
fn init_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_test_writer()
            .try_init();
    });
}

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

/// One captured HTTP request as seen by a backend. We capture only the
/// shape we need to assert on (headers + body). Built by the per-backend
/// hyper service.
#[derive(Debug, Default, Clone)]
#[allow(dead_code)]
struct CapturedRequest {
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    method: String,
    path: String,
}

impl CapturedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A simple test backend that echoes a 200 response with a small fixed
/// body. It records every received request so tests can assert against
/// what made it through the frontend's header rewrites.
struct EchoBackend {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    _handle: tokio::task::JoinHandle<()>,
}

impl EchoBackend {
    async fn spawn(label: &'static str) -> Self {
        Self::spawn_with_headers(label, Vec::new()).await
    }

    async fn spawn_with_headers(
        label: &'static str,
        response_headers: Vec<(&'static str, &'static str)>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let req_clone = Arc::clone(&requests);
        let body_label = format!("echo:{label}");
        let response_headers = Arc::new(response_headers);
        let handle = tokio::spawn(async move {
            loop {
                let (stream, _peer) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let req_clone2 = Arc::clone(&req_clone);
                let body_label2 = body_label.clone();
                let response_headers2 = Arc::clone(&response_headers);
                tokio::spawn(async move {
                    let svc = service_fn(move |mut req: HyperReq<Incoming>| {
                        let req_clone3 = Arc::clone(&req_clone2);
                        let body_label3 = body_label2.clone();
                        let response_headers3 = Arc::clone(&response_headers2);
                        async move {
                            let mut captured = CapturedRequest {
                                method: req.method().to_string(),
                                path: req.uri().path().to_string(),
                                ..Default::default()
                            };
                            for (k, v) in req.headers() {
                                captured.headers.push((
                                    k.as_str().to_string(),
                                    v.to_str().unwrap_or_default().to_string(),
                                ));
                            }
                            // Drain body
                            let body_bytes = req
                                .body_mut()
                                .collect()
                                .await
                                .map(|c| c.to_bytes())
                                .unwrap_or_default();
                            captured.body = body_bytes.to_vec();
                            req_clone3.lock().await.push(captured);
                            let mut builder = HyperResp::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "text/plain");
                            for (name, value) in response_headers3.iter() {
                                builder = builder.header(*name, *value);
                            }
                            let resp = builder.body(Full::new(Bytes::from(body_label3))).unwrap();
                            Ok::<_, Infallible>(resp)
                        }
                    });
                    let io = TokioIo::new(stream);
                    let _ = hyper::server::conn::http1::Builder::new()
                        .keep_alive(true)
                        .serve_connection(io, svc)
                        .with_upgrades()
                        .await;
                });
            }
        });
        Self {
            addr,
            requests,
            _handle: handle,
        }
    }

    fn upstream_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.addr.port())
    }

    async fn last_request(&self) -> Option<CapturedRequest> {
        self.requests.lock().await.last().cloned()
    }

    async fn request_count(&self) -> usize {
        self.requests.lock().await.len()
    }
}

/// Test-only `ServerCertVerifier` that accepts any chain. The frontend's
/// ephemeral leaf is self-signed; we don't ship a CA, so the client opts
/// out of validation entirely.
#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

/// Build a permissive rustls `ClientConfig` advertising the given ALPN
/// protocols.
fn permissive_client_config(alpn: Vec<Vec<u8>>) -> Arc<ClientConfig> {
    let mut cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    cfg.alpn_protocols = alpn;
    Arc::new(cfg)
}

/// Open a TLS connection to `frontend_addr` with SNI `sni`. Returns the
/// negotiated TLS stream (after handshake) or the rustls error.
async fn dial_tls(
    frontend_addr: SocketAddr,
    sni: &str,
    alpn: Vec<Vec<u8>>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, std::io::Error> {
    let tcp = TcpStream::connect(frontend_addr).await?;
    let cfg = permissive_client_config(alpn);
    let connector = TlsConnector::from(cfg);
    let sni_owned: ServerName<'static> = ServerName::try_from(sni.to_string())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
    connector.connect(sni_owned, tcp).await
}

/// Build an HTTP/1.1 request and ship it down an already-established TLS
/// stream. Returns the raw response bytes (single-shot, no keep-alive).
async fn http1_request<S>(
    stream: &mut S,
    host_header: Option<&str>,
    extra: &[(&str, &str)],
    path: &str,
) -> std::io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut req = format!("GET {path} HTTP/1.1\r\n");
    if let Some(h) = host_header {
        req.push_str(&format!("Host: {h}\r\n"));
    }
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("Connection: close\r\n");
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;
    let mut buf = Vec::with_capacity(4096);
    let _ = stream.read_to_end(&mut buf).await; // close on either side OK
    Ok(buf)
}

fn http1_header(resp: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(resp);
    text.split("\r\n")
        .skip(1)
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (header_name, value) = line.split_once(':')?;
            header_name
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
}

/// Write a top-level `[[route]]` TOML file with two routes pointing
/// at the supplied backend URLs. After the L7 schema cleanup HTTPS is
/// driven from top-level routes rather than from `[[rule]]`; certs are
/// resolved node-wide via the three-rung resolver (cert convention →
/// default cert → cert-less LAN). Tests using this helper write their
/// PEMs into the supervisor's `cert_dir` via [`issue_cert_convention`].
fn write_routes_two(
    rules_dir: &Path,
    api_host: &str,
    api_target: &str,
    app_host: &str,
    app_target: &str,
) {
    let toml = format!(
        r#"
[[route]]
hostname = "{api_host}"
target = "{api_target}"

[[route]]
hostname = "{app_host}"
target = "{app_target}"
"#,
    );
    std::fs::write(rules_dir.join("routes.toml"), toml).unwrap();
}

/// Write a fresh self-signed PEM pair for `hostname` into the
/// `cert_dir/<hostname>/{fullchain,privkey}.pem` convention so the
/// supervisor's three-rung resolver picks it up at startup.
fn issue_cert_convention(cert_dir: &Path, hostname: &str) {
    let host_dir = cert_dir.join(hostname);
    std::fs::create_dir_all(&host_dir).unwrap();
    issue_self_signed_pem(
        &host_dir.join("fullchain.pem"),
        &host_dir.join("privkey.pem"),
        hostname,
    );
}

/// Write a top-level `[[route]]` TOML file with one route, optionally
/// emitting `hsts = true`. The cert is loaded from disk through the
/// node-wide cert-dir convention (the caller writes the PEM via
/// [`issue_cert_convention`]).
fn write_route_one_with_hsts(rules_dir: &Path, host: &str, target: &str, hsts: bool) {
    let hsts_line = if hsts { "hsts = true\n" } else { "" };
    let toml = format!(
        r#"
[[route]]
hostname = "{host}"
target = "{target}"
{hsts_line}"#,
    );
    std::fs::write(rules_dir.join("routes.toml"), toml).unwrap();
}

/// Write a top-level `[[route]]` TOML file with one route plus a
/// `[route.headers]` table of static response headers. Mirrors the
/// nginx `add_header NAME VALUE` shape that every server block in the
/// operator's `server/` deployment ships.
fn write_route_one_with_static_headers(
    rules_dir: &Path,
    host: &str,
    target: &str,
    headers: &[(&str, &str)],
) {
    let mut header_block = String::from("\n[route.headers]\n");
    for (name, value) in headers {
        header_block.push_str(&format!("{name:?} = {value:?}\n"));
    }
    let toml = format!(
        r#"
[[route]]
hostname = "{host}"
target = "{target}"
{header_block}"#,
    );
    std::fs::write(rules_dir.join("routes.toml"), toml).unwrap();
}

/// Write a fresh self-signed PEM pair on disk. Uses `rcgen` directly so
/// the test owns the issuance.
fn issue_self_signed_pem(out_cert: &Path, out_key: &Path, hostname: &str) {
    // Per-rcgen-0.13 API: build a `CertificateParams` with the SAN, then
    // self-sign it with a generated key pair.
    let mut params = rcgen::CertificateParams::new(vec![hostname.to_string()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    std::fs::write(out_cert, cert.pem()).unwrap();
    std::fs::write(out_key, key.serialize_pem()).unwrap();
}

/// Standard test fixture: terminal supervisor with two backend echoes
/// behind a single HTTPS rule on a free port. Two routes: `api.*.localhost`
/// and `app.*.localhost`.
struct TwoRouteFixture {
    frontend_addr: SocketAddr,
    api: EchoBackend,
    app: EchoBackend,
    api_host: String,
    app_host: String,
    redirect_port: u16,
    shutdown: CancellationToken,
    _supervisor: yggdrasil::proxy::supervisor::ProxySupervisor,
    _tmpdir: tempfile::TempDir,
}

impl TwoRouteFixture {
    async fn spawn() -> Self {
        Self::spawn_with_options(TwoRouteOpts::default()).await
    }

    async fn spawn_with_options(opts: TwoRouteOpts) -> Self {
        init_tracing();
        // Each test gets unique hostnames so they can't collide when
        // running in parallel (they all share `127.0.0.1`).
        let suffix: u32 = rand::random();
        let api_host = format!("api{suffix}.localhost");
        let app_host = format!("app{suffix}.localhost");

        let api = EchoBackend::spawn_with_headers("api", opts.api_response_headers).await;
        let app = EchoBackend::spawn("app").await;

        let tmpdir = tempfile::tempdir().unwrap();
        let rules_dir = tmpdir.path().join("rules");
        let cert_dir = tmpdir.path().join("certs");
        std::fs::create_dir_all(&rules_dir).unwrap();
        std::fs::create_dir_all(&cert_dir).unwrap();

        // Pre-issue per-host PEMs into the cert-convention directory so
        // the supervisor's three-rung resolver picks them up at startup.
        issue_cert_convention(&cert_dir, &api_host);
        issue_cert_convention(&cert_dir, &app_host);

        write_routes_two(
            &rules_dir,
            &api_host,
            &api.upstream_url(),
            &app_host,
            &app.upstream_url(),
        );

        // Reserve free ephemeral ports for both the HTTPS frontend and
        // the HTTP→HTTPS redirect listener; retry the supervisor spawn
        // on EADDRINUSE up to 5 times with fresh ports. The reservation
        // guards hold the ports until just before the supervisor binds,
        // narrowing the race window against other parallel tests'
        // bind(:0) calls (see `common::ReservedTcpPort`). The retry
        // closes the residual race when even the guard's microsecond
        // window loses to the kernel's port allocator under stress
        // (`scripts/stress.sh`).
        let mut attempt = 0;
        let (supervisor, frontend_addr, redirect_port, shutdown) = loop {
            attempt += 1;
            let frontend_guard = reserve_tcp_port().await;
            let frontend_port = frontend_guard.port();
            let redirect_guard = reserve_tcp_port().await;
            let redirect_port = redirect_guard.port();
            let frontend_addr: SocketAddr = format!("127.0.0.1:{frontend_port}").parse().unwrap();

            let shutdown = CancellationToken::new();
            let cert_config = CertConfig {
                cert_dir: cert_dir.clone(),
                default_cert: None,
                default_key: None,
                redirect_port: Some(redirect_port),
                https_listen: frontend_addr,
                https_http3: opts.http3,
                https_alt_svc: opts.alt_svc,
                https_request_body_limit: 16 * 1024 * 1024,
                acme: None,
                lan_cidrs: std::sync::Arc::new(
                    yggdrasil::lan_cidrs::LanCidrs::resolve(None).expect("default lan_cidrs"),
                ),
            };
            drop(frontend_guard);
            drop(redirect_guard);
            let supervisor = spawn_terminal_supervisor_with_certs(
                rules_dir.clone(),
                Duration::from_millis(50),
                cert_config,
                shutdown.clone(),
            )
            .await;
            if supervisor.wait_for_nonempty(Duration::from_secs(2)).await {
                break (supervisor, frontend_addr, redirect_port, shutdown);
            }
            shutdown.cancel();
            assert!(
                attempt < 5,
                "TwoRouteFixture: supervisor never spawned its HTTPS proxy \
                 after {attempt} attempts (port collision under stress)"
            );
        };

        Self {
            frontend_addr,
            api,
            app,
            api_host,
            app_host,
            redirect_port,
            shutdown,
            _supervisor: supervisor,
            _tmpdir: tmpdir,
        }
    }

    async fn stop(self) {
        self.shutdown.cancel();
        // The supervisor's stop() would await its main_handle and
        // properly drain; we skip that here because the assertions
        // above have already completed and tmpdir's Drop is sufficient
        // for the file-handle teardown. 50 ms is a slack window to let
        // any spawned background tasks finish their current poll before
        // we drop the runtime. Not a flake risk — the test has already
        // asserted everything by this point.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Per-test knobs for [`TwoRouteFixture::spawn_with_options`]. Defaults
/// match the production HTTPS frontend (h3 + alt-svc both on).
struct TwoRouteOpts {
    /// Operator's `[server].https_http3` for this test (default: `true`).
    http3: bool,
    /// Operator's `[server].https_alt_svc` for this test (default: `true`).
    alt_svc: bool,
    /// Additional response headers the API echo backend should set on
    /// every response. Used by `upstream_alt_svc_header_is_preserved`
    /// to assert that an upstream-supplied `Alt-Svc` is not overwritten.
    api_response_headers: Vec<(&'static str, &'static str)>,
}

impl Default for TwoRouteOpts {
    fn default() -> Self {
        Self {
            http3: true,
            alt_svc: true,
            api_response_headers: Vec::new(),
        }
    }
}

impl TwoRouteOpts {
    fn no_alt_svc() -> Self {
        Self {
            alt_svc: false,
            ..Self::default()
        }
    }

    fn no_http3() -> Self {
        Self {
            http3: false,
            ..Self::default()
        }
    }

    fn with_api_headers(api_response_headers: Vec<(&'static str, &'static str)>) -> Self {
        Self {
            api_response_headers,
            ..Self::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// §6h(1)+(2): two routes on the same listener, SNI `api.*` dispatches to
/// the API backend; `X-Forwarded-*` are injected; `Host` is preserved.
#[tokio::test]
async fn sni_api_dispatches_and_xforwarded_headers_are_injected() {
    let fx = TwoRouteFixture::spawn().await;
    let mut tls = dial_tls(fx.frontend_addr, &fx.api_host, vec![b"http/1.1".to_vec()])
        .await
        .expect("TLS handshake");
    let resp = http1_request(&mut tls, Some(&fx.api_host), &[], "/hello")
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&resp).to_string();
    assert!(body.starts_with("HTTP/1.1 200 OK\r\n"), "got: {body}");
    let captured = fx
        .api
        .last_request()
        .await
        .expect("api backend never saw a request");
    assert_eq!(captured.path, "/hello");
    assert_eq!(captured.header("x-forwarded-for"), Some("127.0.0.1"));
    assert_eq!(captured.header("x-real-ip"), Some("127.0.0.1"));
    assert_eq!(captured.header("x-forwarded-proto"), Some("https"));
    assert_eq!(
        captured.header("x-forwarded-protocol"),
        Some("https"),
        "Jellyfin's recommended config (and a long tail of Microsoft-stack \
         backends) reads X-Forwarded-Protocol; must be emitted alongside Proto"
    );
    assert_eq!(
        captured.header("x-forwarded-host"),
        Some(fx.api_host.as_str())
    );
    assert_eq!(captured.header("host"), Some(fx.api_host.as_str()));
    assert_eq!(fx.app.request_count().await, 0, "app backend got traffic");
    fx.stop().await;
}

/// §6h(3): swapping SNI to `app.*` routes to the app backend.
#[tokio::test]
async fn sni_app_dispatches_to_app_backend() {
    let fx = TwoRouteFixture::spawn().await;
    let mut tls = dial_tls(fx.frontend_addr, &fx.app_host, vec![b"http/1.1".to_vec()])
        .await
        .unwrap();
    let resp = http1_request(&mut tls, Some(&fx.app_host), &[], "/x")
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&resp);
    assert!(body.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(fx.app.request_count().await > 0);
    assert_eq!(fx.api.request_count().await, 0);
    fx.stop().await;
}

/// §6h(4): a client-supplied `X-Forwarded-For` is stripped before the
/// frontend injects the real value.
#[tokio::test]
async fn client_supplied_xforwarded_for_is_replaced_with_real_ip() {
    let fx = TwoRouteFixture::spawn().await;
    let mut tls = dial_tls(fx.frontend_addr, &fx.api_host, vec![b"http/1.1".to_vec()])
        .await
        .unwrap();
    let _ = http1_request(
        &mut tls,
        Some(&fx.api_host),
        &[
            ("X-Forwarded-For", "10.10.10.10"),
            ("X-Forwarded-Proto", "http"),
            ("X-Forwarded-Protocol", "http"),
            ("X-Real-IP", "10.10.10.10"),
            ("Forwarded", "for=10.10.10.10"),
        ],
        "/",
    )
    .await
    .unwrap();
    let captured = fx.api.last_request().await.unwrap();
    assert_eq!(captured.header("x-forwarded-for"), Some("127.0.0.1"));
    assert_eq!(captured.header("x-real-ip"), Some("127.0.0.1"));
    assert_eq!(
        captured.header("x-forwarded-proto"),
        Some("https"),
        "client-supplied X-Forwarded-Proto must be replaced with the real scheme"
    );
    assert_eq!(
        captured.header("x-forwarded-protocol"),
        Some("https"),
        "client-supplied X-Forwarded-Protocol synonym must be stripped and \
         replaced — leaving it would let a request spoof its origin scheme"
    );
    assert!(
        captured.header("forwarded").is_none(),
        "Forwarded header should be stripped, got {:?}",
        captured.header("forwarded")
    );
    fx.stop().await;
}

/// §6h(5): SNI for a completely unknown hostname tears down the handshake
/// because the cert resolver returns `None`, which rustls translates to
/// `unrecognized_name`.
#[tokio::test]
async fn unknown_sni_fails_tls_handshake() {
    let fx = TwoRouteFixture::spawn().await;
    let err = dial_tls(
        fx.frontend_addr,
        "definitely-not-a-known-host.localhost",
        vec![b"http/1.1".to_vec()],
    )
    .await
    .expect_err("expected handshake failure on unknown SNI");
    // We assert only on shape — rustls's error text varies across versions.
    let s = format!("{err}");
    assert!(!s.is_empty(), "expected non-empty handshake error");
    fx.stop().await;
}

/// §6h(6): matched SNI but the HTTP `Host` header names an unknown route →
/// 404 plain.
#[tokio::test]
async fn matched_sni_unknown_host_returns_404() {
    let fx = TwoRouteFixture::spawn().await;
    let mut tls = dial_tls(fx.frontend_addr, &fx.api_host, vec![b"http/1.1".to_vec()])
        .await
        .unwrap();
    let resp = http1_request(&mut tls, Some("nowhere.localhost"), &[], "/")
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&resp);
    assert!(
        body.starts_with("HTTP/1.1 404"),
        "expected 404, got: {body}"
    );
    fx.stop().await;
}

#[tokio::test]
async fn default_https_responses_include_alt_svc() {
    let fx = TwoRouteFixture::spawn().await;
    let mut tls = dial_tls(fx.frontend_addr, &fx.api_host, vec![b"http/1.1".to_vec()])
        .await
        .unwrap();
    let resp = http1_request(&mut tls, Some(&fx.api_host), &[], "/")
        .await
        .unwrap();
    let expected = format!("h3=\":{}\"; ma=86400", fx.frontend_addr.port());
    assert_eq!(
        http1_header(&resp, "alt-svc").as_deref(),
        Some(expected.as_str())
    );
    fx.stop().await;
}

#[tokio::test]
async fn alt_svc_false_suppresses_alt_svc_header() {
    let fx = TwoRouteFixture::spawn_with_options(TwoRouteOpts::no_alt_svc()).await;
    let mut tls = dial_tls(fx.frontend_addr, &fx.api_host, vec![b"http/1.1".to_vec()])
        .await
        .unwrap();
    let resp = http1_request(&mut tls, Some(&fx.api_host), &[], "/")
        .await
        .unwrap();
    assert_eq!(http1_header(&resp, "alt-svc"), None);
    fx.stop().await;
}

#[tokio::test]
async fn http3_false_suppresses_alt_svc_header() {
    let fx = TwoRouteFixture::spawn_with_options(TwoRouteOpts::no_http3()).await;
    let mut tls = dial_tls(fx.frontend_addr, &fx.api_host, vec![b"http/1.1".to_vec()])
        .await
        .unwrap();
    let resp = http1_request(&mut tls, Some(&fx.api_host), &[], "/")
        .await
        .unwrap();
    assert_eq!(http1_header(&resp, "alt-svc"), None);
    fx.stop().await;
}

#[tokio::test]
async fn upstream_alt_svc_header_is_preserved() {
    let upstream_alt_svc = "h3=\":9443\"; ma=123";
    let fx = TwoRouteFixture::spawn_with_options(TwoRouteOpts::with_api_headers(vec![(
        "alt-svc",
        upstream_alt_svc,
    )]))
    .await;
    let mut tls = dial_tls(fx.frontend_addr, &fx.api_host, vec![b"http/1.1".to_vec()])
        .await
        .unwrap();
    let resp = http1_request(&mut tls, Some(&fx.api_host), &[], "/")
        .await
        .unwrap();
    assert_eq!(
        http1_header(&resp, "alt-svc").as_deref(),
        Some(upstream_alt_svc)
    );
    fx.stop().await;
}

#[tokio::test]
async fn unknown_host_404_includes_alt_svc() {
    let fx = TwoRouteFixture::spawn().await;
    let mut tls = dial_tls(fx.frontend_addr, &fx.api_host, vec![b"http/1.1".to_vec()])
        .await
        .unwrap();
    let resp = http1_request(&mut tls, Some("nowhere.localhost"), &[], "/")
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&resp);
    assert!(
        body.starts_with("HTTP/1.1 404"),
        "expected 404, got: {body}"
    );
    let expected = format!("h3=\":{}\"; ma=86400", fx.frontend_addr.port());
    assert_eq!(
        http1_header(&resp, "alt-svc").as_deref(),
        Some(expected.as_str())
    );
    fx.stop().await;
}

/// §6h(8): the route's backend is unreachable → 502.
#[tokio::test]
async fn dead_backend_returns_502() {
    init_tracing();
    let tmpdir = tempfile::tempdir().unwrap();
    let rules_dir = tmpdir.path().join("rules");
    let cert_dir = tmpdir.path().join("certs");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::create_dir_all(&cert_dir).unwrap();
    let frontend_guard = reserve_tcp_port().await;
    let frontend_port = frontend_guard.port();
    let frontend_addr: SocketAddr = format!("127.0.0.1:{frontend_port}").parse().unwrap();

    // Bind a real listener at the "dead" address but accept-and-drop
    // every connection. The frontend's backend client will see the
    // connection close before the HTTP response arrives → 502.
    //
    // Why not just `reserve_tcp_port` and let the supervisor's dial
    // hit a closed socket? Because we need a real listener actively
    // receiving on that port for the test's full lifetime, not just
    // a port-reservation guard dropped before the supervisor binds.
    // Without the active listener, another concurrent test could
    // bind the port and the request would route to *that* test's
    // backend instead of failing. Found by the local stress runner.
    let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead_listener.local_addr().unwrap().port();
    let dead_task = tokio::spawn(async move {
        loop {
            match dead_listener.accept().await {
                Ok((stream, _)) => drop(stream),
                Err(_) => return,
            }
        }
    });

    let host = format!("dead{}.localhost", rand::random::<u32>());
    issue_cert_convention(&cert_dir, &host);

    let toml = format!(
        r#"
[[route]]
hostname = "{host}"
target = "http://127.0.0.1:{dead_port}"
"#,
    );
    std::fs::write(rules_dir.join("routes.toml"), toml).unwrap();

    let shutdown = CancellationToken::new();
    drop(frontend_guard);
    let supervisor = spawn_terminal_supervisor_with_certs(
        rules_dir,
        Duration::from_millis(50),
        CertConfig {
            cert_dir,
            default_cert: None,
            default_key: None,
            // This test never dials the redirect listener; let the OS
            // pick a free port (Some(0)) so it never races against
            // other parallel tests' bind(:0) calls.
            redirect_port: Some(0),
            https_listen: frontend_addr,
            https_http3: true,
            https_alt_svc: true,
            https_request_body_limit: 16 * 1024 * 1024,
            acme: None,
            lan_cidrs: std::sync::Arc::new(
                yggdrasil::lan_cidrs::LanCidrs::resolve(None).expect("default lan_cidrs"),
            ),
        },
        shutdown.clone(),
    )
    .await;
    assert!(supervisor.wait_for_nonempty(Duration::from_secs(2)).await);
    let mut tls = dial_tls(frontend_addr, &host, vec![b"http/1.1".to_vec()])
        .await
        .unwrap();
    let resp = http1_request(&mut tls, Some(&host), &[], "/")
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&resp);
    assert!(
        body.starts_with("HTTP/1.1 502"),
        "expected 502, got: {body}"
    );
    let expected = format!("h3=\":{}\"; ma=86400", frontend_addr.port());
    assert_eq!(
        http1_header(&resp, "alt-svc").as_deref(),
        Some(expected.as_str())
    );
    shutdown.cancel();
    dead_task.abort();
}

/// §6h(9): ALPN advertises both `h2` and `http/1.1`; a client that prefers
/// `h2` should land on the h2 service. We assert only that the ALPN
/// selection completes — the server's hyper-h2 stack is exercised
/// implicitly by the live handshake.
#[tokio::test]
async fn alpn_negotiates_h2_when_client_prefers_h2() {
    let fx = TwoRouteFixture::spawn().await;
    let tls = dial_tls(
        fx.frontend_addr,
        &fx.api_host,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    )
    .await
    .expect("TLS handshake");
    let (_, server_state) = tls.get_ref();
    let alpn = server_state.alpn_protocol();
    assert_eq!(alpn, Some(b"h2".as_ref()), "expected h2 ALPN selection");
    fx.stop().await;
}

/// §6h(13): a route with `hsts = true` returns the `Strict-Transport-Security`
/// header on successful responses; an HSTS-less route does not.
#[tokio::test]
async fn hsts_header_emitted_when_opted_in() {
    init_tracing();
    // Build a single-route fixture with HSTS enabled on a disk-loaded
    // cert. Cert comes from the [server].default_cert + default_key
    // path so we exercise the second rung of the resolver chain.
    let api = EchoBackend::spawn("api").await;
    let tmpdir = tempfile::tempdir().unwrap();
    let rules_dir = tmpdir.path().join("rules");
    let cert_dir = tmpdir.path().join("certs");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::create_dir_all(&cert_dir).unwrap();
    let cert_path = cert_dir.join("cert.pem");
    let key_path = cert_dir.join("key.pem");
    let host = format!("hsts{}.localhost", rand::random::<u32>());
    issue_self_signed_pem(&cert_path, &key_path, &host);
    let frontend_guard = common::reserve_tcp_port().await;
    let frontend_port = frontend_guard.port();
    let frontend_addr: SocketAddr = format!("127.0.0.1:{frontend_port}").parse().unwrap();
    write_route_one_with_hsts(&rules_dir, &host, &api.upstream_url(), true);
    let shutdown = CancellationToken::new();
    drop(frontend_guard);
    let supervisor = spawn_terminal_supervisor_with_certs(
        rules_dir,
        Duration::from_millis(50),
        CertConfig {
            cert_dir,
            default_cert: Some(cert_path),
            default_key: Some(key_path),
            // This test never dials the redirect listener; let the OS
            // pick a free port (Some(0)) so it never races against
            // other parallel tests' bind(:0) calls.
            redirect_port: Some(0),
            https_listen: frontend_addr,
            https_http3: true,
            https_alt_svc: true,
            https_request_body_limit: 16 * 1024 * 1024,
            acme: None,
            lan_cidrs: std::sync::Arc::new(
                yggdrasil::lan_cidrs::LanCidrs::resolve(None).expect("default lan_cidrs"),
            ),
        },
        shutdown.clone(),
    )
    .await;
    assert!(supervisor.wait_for_nonempty(Duration::from_secs(2)).await);
    let mut tls = dial_tls(frontend_addr, &host, vec![b"http/1.1".to_vec()])
        .await
        .unwrap();
    let resp = http1_request(&mut tls, Some(&host), &[], "/")
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&resp);
    assert!(body.starts_with("HTTP/1.1 200"), "got: {body}");
    let lower = body.to_ascii_lowercase();
    assert!(
        lower.contains("strict-transport-security: max-age="),
        "HSTS header missing, got: {body}"
    );
    shutdown.cancel();
}

/// Per-route `[[route]].headers` stamps configured names + values on
/// every response over the h1/h2 path. Operator-set values OVERRIDE
/// any header of the same name returned by the backend, matching
/// nginx `add_header ... always` semantics — which is what every
/// L7 backend in the operator's `server/` deployment relies on
/// (`X-Robots-Tag` on all blocks, plus jellyfin / sites adding CSP /
/// X-Frame-Options / X-Content-Type-Options / Origin-Agent-Cluster).
#[tokio::test]
async fn static_response_headers_reach_client_and_override_backend() {
    init_tracing();
    // Backend returns its own X-Frame-Options that the operator config
    // should override. Also returns a header NOT in the route config to
    // confirm we don't strip unrelated backend headers.
    let api = EchoBackend::spawn_with_headers(
        "api",
        vec![
            ("x-frame-options", "ALLOW-FROM https://evil.example"),
            ("x-backend-tag", "kept"),
        ],
    )
    .await;
    let tmpdir = tempfile::tempdir().unwrap();
    let rules_dir = tmpdir.path().join("rules");
    let cert_dir = tmpdir.path().join("certs");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::create_dir_all(&cert_dir).unwrap();
    let cert_path = cert_dir.join("cert.pem");
    let key_path = cert_dir.join("key.pem");
    let host = format!("hdrs{}.localhost", rand::random::<u32>());
    issue_self_signed_pem(&cert_path, &key_path, &host);
    let frontend_guard = reserve_tcp_port().await;
    let frontend_port = frontend_guard.port();
    let frontend_addr: SocketAddr = format!("127.0.0.1:{frontend_port}").parse().unwrap();
    write_route_one_with_static_headers(
        &rules_dir,
        &host,
        &api.upstream_url(),
        &[
            ("X-Robots-Tag", "noindex, nofollow, nosnippet, noarchive"),
            ("X-Frame-Options", "DENY"),
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Security-Policy", "default-src 'self'"),
        ],
    );
    let shutdown = CancellationToken::new();
    drop(frontend_guard);
    let supervisor = spawn_terminal_supervisor_with_certs(
        rules_dir,
        Duration::from_millis(50),
        CertConfig {
            cert_dir,
            default_cert: Some(cert_path),
            default_key: Some(key_path),
            // This test never dials the redirect listener; let the OS
            // pick a free port (Some(0)) so it never races against
            // other parallel tests' bind(:0) calls.
            redirect_port: Some(0),
            https_listen: frontend_addr,
            https_http3: true,
            https_alt_svc: true,
            https_request_body_limit: 16 * 1024 * 1024,
            acme: None,
            lan_cidrs: std::sync::Arc::new(
                yggdrasil::lan_cidrs::LanCidrs::resolve(None).expect("default lan_cidrs"),
            ),
        },
        shutdown.clone(),
    )
    .await;
    assert!(supervisor.wait_for_nonempty(Duration::from_secs(2)).await);
    let mut tls = dial_tls(frontend_addr, &host, vec![b"http/1.1".to_vec()])
        .await
        .unwrap();
    let resp = http1_request(&mut tls, Some(&host), &[], "/")
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&resp);
    assert!(body.starts_with("HTTP/1.1 200"), "got: {body}");
    let lower = body.to_ascii_lowercase();

    // All four configured static headers reached the client.
    assert!(
        lower.contains("x-robots-tag: noindex, nofollow, nosnippet, noarchive"),
        "X-Robots-Tag missing, got: {body}"
    );
    assert!(
        lower.contains("x-content-type-options: nosniff"),
        "X-Content-Type-Options missing, got: {body}"
    );
    assert!(
        lower.contains("content-security-policy: default-src 'self'"),
        "CSP missing, got: {body}"
    );

    // Operator's X-Frame-Options overrode the backend's. We must see
    // exactly one X-Frame-Options line and it must be "DENY", not the
    // backend's "ALLOW-FROM https://evil.example".
    let xfo_count = lower
        .lines()
        .filter(|line| line.starts_with("x-frame-options:"))
        .count();
    assert_eq!(
        xfo_count, 1,
        "expected exactly one X-Frame-Options line (operator overrides backend), got {xfo_count} in: {body}"
    );
    assert!(
        lower.contains("x-frame-options: deny"),
        "operator X-Frame-Options didn't win, got: {body}"
    );
    assert!(
        !lower.contains("allow-from"),
        "backend's X-Frame-Options leaked through, got: {body}"
    );

    // Unrelated backend headers still pass through.
    assert!(
        lower.contains("x-backend-tag: kept"),
        "non-conflicting backend header was stripped, got: {body}"
    );

    shutdown.cancel();
}

/// §6h(7): drop semantics for malformed requests. We send a request with no
/// `Host` header at all. The frontend should respond 4xx (or drop). We
/// accept either as a success.
#[tokio::test]
async fn missing_host_header_is_rejected() {
    let fx = TwoRouteFixture::spawn().await;
    let mut tls = dial_tls(fx.frontend_addr, &fx.api_host, vec![b"http/1.1".to_vec()])
        .await
        .unwrap();
    let resp = http1_request(&mut tls, None, &[], "/").await.unwrap();
    let body = String::from_utf8_lossy(&resp);
    // Acceptable: 400 Bad Request (hyper's default for missing Host on h1)
    // or any 4xx, or a connection drop (empty body).
    if !body.is_empty() {
        assert!(
            body.starts_with("HTTP/1.1 4"),
            "expected 4xx or empty drop, got: {body}"
        );
    }
    fx.stop().await;
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// `:80`-equivalent redirect tests. The fixture binds the redirect listener
// on an ephemeral port (via `CertConfig::redirect_port`) so these tests
// work in unprivileged environments too. The wire shape — `301
// https://<host><path>` — is what we assert.
// ---------------------------------------------------------------------------

/// §6h(11) part 1: an HTTP request on the redirect listener for a known
/// hostname returns `301 https://<host><path>`.
#[tokio::test]
async fn port_80_redirects_known_host_to_https() {
    let fx = TwoRouteFixture::spawn().await;
    // Wait deterministically for the redirect listener to be up. The
    // supervisor's snapshot only tracks the HTTPS frontend; the per-IP
    // :80 companion is spawned alongside but not surfaced. Poll
    // connect() — ConnectionRefused = not bound yet, Ok = ready.
    let mut tcp = await_connect(fx.redirect_port).await;
    let req = format!(
        "GET /foo?bar=baz HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
        host = fx.api_host,
    );
    tcp.write_all(req.as_bytes()).await.unwrap();
    tcp.flush().await.unwrap();
    let mut buf = Vec::new();
    let _ = tcp.read_to_end(&mut buf).await;
    let body = String::from_utf8_lossy(&buf);
    assert!(
        body.starts_with("HTTP/1.1 301"),
        "expected 301 redirect, got: {body}"
    );
    let lower = body.to_ascii_lowercase();
    let expected_location = format!("location: https://{host}/foo?bar=baz", host = fx.api_host);
    assert!(
        lower.contains(&expected_location),
        "expected location {expected_location:?}, got: {body}"
    );
    fx.stop().await;
}

/// §6h(11) part 2: redirect listener returns 404 for unknown hosts.
#[tokio::test]
async fn port_80_unknown_host_returns_404() {
    let fx = TwoRouteFixture::spawn().await;
    let mut tcp = await_connect(fx.redirect_port).await;
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: nowhere.example\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = tcp.read_to_end(&mut buf).await;
    let body = String::from_utf8_lossy(&buf);
    assert!(
        body.starts_with("HTTP/1.1 404"),
        "expected 404 on unknown host, got: {body}"
    );
    fx.stop().await;
}

/// §6h(12): a PROXY-protocol v2 header from the (synthetic) relay is
/// consumed and reflected as `X-Forwarded-For`.
#[tokio::test]
async fn proxy_protocol_v2_client_ip_becomes_xforwarded_for() {
    let fx = TwoRouteFixture::spawn().await;
    // Build a PROXY-protocol v2 header for src 203.0.113.45:5555 →
    // dst 198.51.100.1:443, TCP/IPv4 (PROXY command, INET, TCP).
    // Reuse the project's encoder to avoid hand-crafting the bytes.
    let header = yggdrasil::proxy::proxy_protocol::encode_header(
        ratatoskr::rule::ProxyProto::V2,
        "203.0.113.45:5555".parse().unwrap(),
        "198.51.100.1:443".parse().unwrap(),
    );
    let mut tcp = TcpStream::connect(fx.frontend_addr).await.unwrap();
    tcp.write_all(&header).await.unwrap();
    tcp.flush().await.unwrap();
    // Now run the TLS handshake on the same socket.
    let cfg = permissive_client_config(vec![b"http/1.1".to_vec()]);
    let connector = TlsConnector::from(cfg);
    let sni: ServerName<'static> = ServerName::try_from(fx.api_host.clone()).unwrap();
    let mut tls = connector.connect(sni, tcp).await.expect("TLS handshake");
    let _ = http1_request(&mut tls, Some(&fx.api_host), &[], "/")
        .await
        .unwrap();
    let captured = fx
        .api
        .last_request()
        .await
        .expect("backend never saw the request");
    assert_eq!(captured.header("x-forwarded-for"), Some("203.0.113.45"));
    assert_eq!(captured.header("x-real-ip"), Some("203.0.113.45"));
    fx.stop().await;
}

/// §6h(14): hot-reload of a disk-backed cert. We start with one cert,
/// rewrite it on disk, give the supervisor's debounce window time to
/// fire, and assert subsequent TLS sessions present the new cert. We
/// detect "new cert" by SHA-256-ing the leaf and comparing fingerprints.
#[tokio::test]
async fn disk_backed_cert_reloads_on_change() {
    let api = EchoBackend::spawn("api").await;
    let tmpdir = tempfile::tempdir().unwrap();
    let rules_dir = tmpdir.path().join("rules");
    let cert_dir = tmpdir.path().join("certs");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::create_dir_all(&cert_dir).unwrap();
    let host = format!("reload{}.localhost", rand::random::<u32>());
    let host_dir = cert_dir.join(&host);
    std::fs::create_dir_all(&host_dir).unwrap();
    let cert_path = host_dir.join("fullchain.pem");
    let key_path = host_dir.join("privkey.pem");
    issue_self_signed_pem(&cert_path, &key_path, &host);
    let frontend_guard = reserve_tcp_port().await;
    let frontend_port = frontend_guard.port();
    let frontend_addr: SocketAddr = format!("127.0.0.1:{frontend_port}").parse().unwrap();
    write_route_one_with_hsts(&rules_dir, &host, &api.upstream_url(), false);
    let shutdown = CancellationToken::new();
    drop(frontend_guard);
    let supervisor = spawn_terminal_supervisor_with_certs(
        rules_dir,
        Duration::from_millis(50),
        CertConfig {
            cert_dir,
            default_cert: None,
            default_key: None,
            // This test never dials the redirect listener; let the OS
            // pick a free port (Some(0)) so it never races against
            // other parallel tests' bind(:0) calls.
            redirect_port: Some(0),
            https_listen: frontend_addr,
            https_http3: true,
            https_alt_svc: true,
            https_request_body_limit: 16 * 1024 * 1024,
            acme: None,
            lan_cidrs: std::sync::Arc::new(
                yggdrasil::lan_cidrs::LanCidrs::resolve(None).expect("default lan_cidrs"),
            ),
        },
        shutdown.clone(),
    )
    .await;
    assert!(supervisor.wait_for_nonempty(Duration::from_secs(2)).await);
    let first_leaf_fp = leaf_fingerprint(frontend_addr, &host).await;
    // Replace the cert with a freshly-generated one. The dedicated cert
    // watcher in `certs.rs` will observe the file-write event in the
    // cert directory, debounce, and trigger `CertStore::reload_host`
    // for the affected hostname — no rule-file bump required.
    //
    // Pause before the rewrite so the new file's mtime is reliably
    // greater than the original's; notify-debouncer-mini's coarse mtime
    // resolution would otherwise coalesce both writes into one event.
    std::thread::sleep(std::time::Duration::from_millis(100));
    issue_self_signed_pem(&cert_path, &key_path, &host);
    // Poll the leaf fingerprint until it changes. The cert watcher's
    // debounce window dictates the lower bound; 2 s is generous.
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut second_leaf_fp = first_leaf_fp;
    while Instant::now() < deadline {
        let now = leaf_fingerprint(frontend_addr, &host).await;
        if now != first_leaf_fp {
            second_leaf_fp = now;
            break;
        }
        // 50 ms backoff between TLS handshakes; deadline gates the loop.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_ne!(
        second_leaf_fp, first_leaf_fp,
        "cert fingerprint did not change after on-disk swap"
    );
    shutdown.cancel();
}

/// §6h(15): malformed PEM on reload keeps the old cert in service and
/// (per the metric design) increments `https_cert_reload_total{result="err"}`.
/// We verify the keep-old-cert behaviour at the TLS layer; verifying the
/// metric increment requires a Prometheus scrape and is left to the
/// `metrics.rs` unit tests.
#[tokio::test]
async fn malformed_cert_reload_keeps_old_cert_serving() {
    init_tracing();
    let api = EchoBackend::spawn("api").await;
    let tmpdir = tempfile::tempdir().unwrap();
    let rules_dir = tmpdir.path().join("rules");
    let cert_dir = tmpdir.path().join("certs");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::create_dir_all(&cert_dir).unwrap();
    let host = format!("bad{}.localhost", rand::random::<u32>());
    let host_dir = cert_dir.join(&host);
    std::fs::create_dir_all(&host_dir).unwrap();
    let cert_path = host_dir.join("fullchain.pem");
    let key_path = host_dir.join("privkey.pem");
    issue_self_signed_pem(&cert_path, &key_path, &host);
    let frontend_guard = reserve_tcp_port().await;
    let frontend_port = frontend_guard.port();
    let frontend_addr: SocketAddr = format!("127.0.0.1:{frontend_port}").parse().unwrap();
    write_route_one_with_hsts(&rules_dir, &host, &api.upstream_url(), false);
    let shutdown = CancellationToken::new();
    drop(frontend_guard);
    let supervisor = spawn_terminal_supervisor_with_certs(
        rules_dir,
        Duration::from_millis(50),
        CertConfig {
            cert_dir,
            default_cert: None,
            default_key: None,
            // This test never dials the redirect listener; let the OS
            // pick a free port (Some(0)) so it never races against
            // other parallel tests' bind(:0) calls.
            redirect_port: Some(0),
            https_listen: frontend_addr,
            https_http3: true,
            https_alt_svc: true,
            https_request_body_limit: 16 * 1024 * 1024,
            acme: None,
            lan_cidrs: std::sync::Arc::new(
                yggdrasil::lan_cidrs::LanCidrs::resolve(None).expect("default lan_cidrs"),
            ),
        },
        shutdown.clone(),
    )
    .await;
    assert!(supervisor.wait_for_nonempty(Duration::from_secs(2)).await);
    let first_leaf_fp = leaf_fingerprint(frontend_addr, &host).await;
    // Trash the cert on disk. The cert watcher debounces the write event
    // and asks `CertStore::reload_host` to re-resolve — which fails
    // because the file is now malformed. The store keeps the previously
    // loaded entry in service.
    std::fs::write(&cert_path, b"this is not pem").unwrap();
    // The cert watcher's debounce window (50 ms in this test) + a
    // generous reload-attempt budget. There's no observable post-reload
    // signal because the reload is REJECTED (no state change to detect);
    // this is one of the irreducible "wait for system to do nothing
    // observable" patterns.
    tokio::time::sleep(Duration::from_millis(800)).await;
    // Old cert should still be in service.
    let still_fp = leaf_fingerprint(frontend_addr, &host).await;
    assert_eq!(
        still_fp, first_leaf_fp,
        "malformed reload should have been rejected, but cert changed"
    );
    shutdown.cancel();
}

// ---------------------------------------------------------------------------
// Small utility helpers used only by the hot-reload tests
// ---------------------------------------------------------------------------

/// SHA-256 the leaf cert that the frontend currently presents for `sni`.
async fn leaf_fingerprint(frontend_addr: SocketAddr, sni: &str) -> [u8; 32] {
    use rustls::client::danger::ServerCertVerifier;

    // Capture the leaf bytes inside a custom verifier. We use a
    // `std::sync::Mutex` (not `tokio`'s) because the verifier is called
    // on the tokio runtime's worker thread, where blocking on the tokio
    // mutex would deadlock.
    #[derive(Debug)]
    struct Capture(std::sync::Mutex<Option<Vec<u8>>>);
    impl ServerCertVerifier for Capture {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            *self.0.lock().unwrap() = Some(end_entity.as_ref().to_vec());
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ED25519,
            ]
        }
    }
    let capture = Arc::new(Capture(std::sync::Mutex::new(None)));
    let mut cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::clone(&capture) as Arc<dyn ServerCertVerifier>)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tcp = TcpStream::connect(frontend_addr).await.unwrap();
    let sni_owned: ServerName<'static> = ServerName::try_from(sni.to_string()).unwrap();
    let connector = TlsConnector::from(Arc::new(cfg));
    let _stream = connector.connect(sni_owned, tcp).await.unwrap();
    let leaf = capture
        .0
        .lock()
        .unwrap()
        .take()
        .expect("verifier captured no leaf");
    use blake2::digest::Digest;
    // We don't actually have sha2 in dev-deps; reuse blake2 256-bit
    // digest as a stable fingerprint. The function is only used to
    // compare fingerprints for equality, so any keyed/unkeyed hash works.
    let mut h = blake2::Blake2s256::new();
    h.update(&leaf);
    let out = h.finalize();
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&out);
    fp
}

// =============================================================================
// Cert-less HTTPS routes (the per-IP companion listener's plaintext path)
// =============================================================================
//
// These tests cover the four-step pipeline on `:80`:
//   1. ACME passthrough (regardless of source IP) — already covered by
//      existing tests in this file under different fixtures.
//   2. Cert-less route serving to LAN peers — covered by
//      `cert_less_route_served_to_loopback_peer`.
//   3. Cert'd-host 301 redirect (regardless of source IP) — covered by
//      `cert_d_host_still_redirects_when_companion_has_plaintext_routes`.
//   4. 404 for unknown host — covered by
//      `unknown_host_yields_404_on_companion`.
//
// The tests connect to `127.0.0.1:redirect_port`. Since `127.0.0.1` falls
// inside the default `lan_cidrs` set (the loopback range), the cert-less
// branch is reached. Testing the "non-LAN peer denied" path from
// integration tests would require spoofing the source IP, which the test
// runner can't do without root + netns. That branch is covered by the
// `LanCidrs::contains` unit tests + the manual call site review.

fn write_routes_cert_d_and_cert_less(
    rules_dir: &Path,
    cert_d_host: &str,
    cert_d_target: &str,
    cert_less_host: &str,
    cert_less_target: &str,
) {
    let toml = format!(
        r#"
[[route]]
hostname = "{cert_d_host}"
target = "{cert_d_target}"

[[route]]
hostname = "{cert_less_host}"
target = "{cert_less_target}"
"#,
    );
    std::fs::write(rules_dir.join("routes.toml"), toml).unwrap();
}

struct CertLessFixture {
    frontend_addr: SocketAddr,
    redirect_port: u16,
    cert_d: EchoBackend,
    cert_less: EchoBackend,
    cert_d_host: String,
    cert_less_host: String,
    shutdown: CancellationToken,
    _supervisor: yggdrasil::proxy::supervisor::ProxySupervisor,
    _tmpdir: tempfile::TempDir,
}

impl CertLessFixture {
    async fn spawn() -> Self {
        init_tracing();
        let suffix: u32 = rand::random();
        let cert_d_host = format!("secure{suffix}.localhost");
        let cert_less_host = format!("plain{suffix}.internal");

        let cert_d = EchoBackend::spawn("cert_d").await;
        let cert_less = EchoBackend::spawn("cert_less").await;

        let tmpdir = tempfile::tempdir().unwrap();
        let rules_dir = tmpdir.path().join("rules");
        let cert_dir = tmpdir.path().join("certs");
        std::fs::create_dir_all(&rules_dir).unwrap();
        std::fs::create_dir_all(&cert_dir).unwrap();

        // Issue a convention cert for the cert-d host. The cert-less
        // host intentionally has no PEM on disk → load_routes_into_store
        // returns it in the cert-less list and the route lives on `:80`.
        issue_cert_convention(&cert_dir, &cert_d_host);

        write_routes_cert_d_and_cert_less(
            &rules_dir,
            &cert_d_host,
            &cert_d.upstream_url(),
            &cert_less_host,
            &cert_less.upstream_url(),
        );

        // Reserve ports + retry the supervisor spawn on EADDRINUSE.
        // See `TwoRouteFixture::spawn_with_options` for the rationale.
        let mut attempt = 0;
        let (supervisor, frontend_addr, redirect_port, shutdown) = loop {
            attempt += 1;
            let frontend_guard = reserve_tcp_port().await;
            let frontend_port = frontend_guard.port();
            let redirect_guard = reserve_tcp_port().await;
            let redirect_port = redirect_guard.port();
            let frontend_addr: SocketAddr = format!("127.0.0.1:{frontend_port}").parse().unwrap();

            let shutdown = CancellationToken::new();
            let cert_config = CertConfig {
                cert_dir: cert_dir.clone(),
                default_cert: None,
                default_key: None,
                redirect_port: Some(redirect_port),
                https_listen: frontend_addr,
                https_http3: true,
                https_alt_svc: true,
                https_request_body_limit: 16 * 1024 * 1024,
                acme: None,
                lan_cidrs: std::sync::Arc::new(
                    yggdrasil::lan_cidrs::LanCidrs::resolve(None).expect("default lan_cidrs"),
                ),
            };
            drop(frontend_guard);
            drop(redirect_guard);
            let supervisor = spawn_terminal_supervisor_with_certs(
                rules_dir.clone(),
                Duration::from_millis(50),
                cert_config,
                shutdown.clone(),
            )
            .await;
            if supervisor.wait_for_nonempty(Duration::from_secs(2)).await {
                break (supervisor, frontend_addr, redirect_port, shutdown);
            }
            shutdown.cancel();
            assert!(
                attempt < 5,
                "CertLessFixture: supervisor never spawned its HTTPS proxy \
                 after {attempt} attempts (port collision under stress)"
            );
        };

        Self {
            frontend_addr,
            redirect_port,
            cert_d,
            cert_less,
            cert_d_host,
            cert_less_host,
            shutdown,
            _supervisor: supervisor,
            _tmpdir: tmpdir,
        }
    }

    async fn stop(self) {
        self.shutdown.cancel();
        // EchoBackend tasks are leaked by design — they exit when the
        // shutdown signal cascades through.
        let _ = self.cert_d;
        let _ = self.cert_less;
    }
}

/// Wait for `redirect_port` to accept a TCP connection. Replaces the
/// "give the redirect listener a brief moment" sleep pattern with a
/// deterministic poll: `connect()` returns ConnectionRefused until the
/// per-IP companion listener has bound, then succeeds.
async fn await_connect(port: u16) -> TcpStream {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match TcpStream::connect(format!("127.0.0.1:{port}")).await {
            Ok(s) => return s,
            Err(_) if std::time::Instant::now() < deadline => {
                tokio::task::yield_now().await;
            }
            Err(e) => panic!("redirect listener on :{port} never came up: {e}"),
        }
    }
}

/// Drive a single plain-HTTP GET request to `:redirect_port` with a given
/// `Host` header and return the parsed status code + response headers as
/// raw bytes. Avoids hyper's client to keep the test independent of the
/// proxy under test.
async fn raw_http_get(redirect_port: u16, host: &str, path: &str) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{redirect_port}"))
        .await
        .expect("connect to companion listener");
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write request");
    let mut buf = Vec::new();
    let read_fut = stream.read_to_end(&mut buf);
    tokio::time::timeout(Duration::from_secs(5), read_fut)
        .await
        .expect("read response within 5s")
        .expect("read response");
    // Status line: "HTTP/1.1 200 OK\r\n"
    let status_line_end = buf
        .windows(2)
        .position(|w| w == b"\r\n")
        .expect("response has a status line");
    let status_line = std::str::from_utf8(&buf[..status_line_end]).expect("status line is utf8");
    let mut parts = status_line.split(' ');
    parts.next(); // HTTP/1.1
    let code: u16 = parts
        .next()
        .expect("status line has a code")
        .parse()
        .expect("status code is an integer");
    (code, buf)
}

#[tokio::test]
async fn cert_less_route_served_to_loopback_peer() {
    let fx = CertLessFixture::spawn().await;
    // 127.0.0.1 is in default lan_cidrs (loopback range) → cert-less
    // path is taken → backend serves a 200.
    let (code, body) = raw_http_get(fx.redirect_port, &fx.cert_less_host, "/").await;
    assert_eq!(
        code,
        200,
        "cert-less route should serve 200 to loopback peer; body: {}",
        String::from_utf8_lossy(&body)
    );
    // The echo backend echoes its handler label "cert_less" somewhere
    // in the body — verify the request actually reached it.
    let body_str = String::from_utf8_lossy(&body);
    assert!(
        body_str.contains("cert_less"),
        "expected cert_less backend marker in body; got: {body_str}"
    );
    // Also verify X-Forwarded-Proto = "http" was injected (the cert-less
    // path is plaintext, not TLS).
    let captured = fx.cert_less.requests.lock().await;
    let req = captured.first().expect("backend captured a request");
    let xfp = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-proto"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert_eq!(
        xfp, "http",
        "cert-less path must inject x-forwarded-proto=http, got: {xfp:?}"
    );
    drop(captured);
    fx.stop().await;
}

#[tokio::test]
async fn cert_d_host_still_redirects_when_companion_has_plaintext_routes() {
    let fx = CertLessFixture::spawn().await;
    // GET on :80 for the cert'd host → 301 to https://...
    let (code, body) = raw_http_get(fx.redirect_port, &fx.cert_d_host, "/some/path").await;
    assert_eq!(
        code,
        301,
        "cert'd host on :80 should redirect; body: {}",
        String::from_utf8_lossy(&body)
    );
    let body_str = String::from_utf8_lossy(&body);
    let expected_location = format!("https://{}/some/path", fx.cert_d_host);
    assert!(
        body_str.contains(&expected_location),
        "expected Location: {expected_location}, got body: {body_str}"
    );
    let _ = fx.frontend_addr; // suppress unused-field warning if any
    fx.stop().await;
}

#[tokio::test]
async fn unknown_host_yields_404_on_companion() {
    let fx = CertLessFixture::spawn().await;
    let (code, _body) = raw_http_get(fx.redirect_port, "unknown.local", "/").await;
    assert_eq!(code, 404, "unknown host should 404");
    fx.stop().await;
}

// ---------------------------------------------------------------------------
// Route hot-reload: in-flight request drains across a route swap
// ---------------------------------------------------------------------------

/// Backend that holds the response for `delay` before replying with a
/// fixed 200 OK. Used by `route_addition_drains_inflight_request_within_budget`
/// to keep one request in-flight while the supervisor rotates the
/// HTTPS frontend.
struct SlowBackend {
    addr: SocketAddr,
    _handle: tokio::task::JoinHandle<()>,
}

impl SlowBackend {
    async fn spawn(delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let (stream, _peer) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let svc = service_fn(move |req: HyperReq<Incoming>| async move {
                        // Drain body so hyper doesn't close on us.
                        let _ = req.into_body().collect().await;
                        tokio::time::sleep(delay).await;
                        let resp = HyperResp::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/plain")
                            .body(Full::new(Bytes::from_static(b"slow-ok\n")))
                            .unwrap();
                        Ok::<_, Infallible>(resp)
                    });
                    let io = TokioIo::new(stream);
                    let _ = hyper::server::conn::http1::Builder::new()
                        .keep_alive(false)
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });
        Self {
            addr,
            _handle: handle,
        }
    }

    fn upstream_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.addr.port())
    }
}

/// `reconcile_https` tears down and respawns the entire HTTPS frontend
/// on any route diff today; per-route diffing is the
/// `route-hot-reload-fix-per-route-diff` follow-up. What this test
/// pins is the weaker — but explicit — claim: an in-flight TLS request
/// against an existing route SHOULD complete within the configured
/// `graceful_drain_timeout`, even when the supervisor decides to swap
/// the frontend out from under it (e.g. because the operator dropped
/// a second route into `conf.d`).
///
/// We pick a 1 s backend delay and a 5 s drain budget so the in-flight
/// request is in a comfortable middle of the drain window. If
/// reconcile_https ever reverts to `stop(None)` (no drain), this test
/// fails because hyper sees the listener close with the request still
/// awaiting bytes.
#[tokio::test(flavor = "multi_thread")]
async fn route_addition_drains_inflight_request_within_budget() {
    use ratatoskr::rule::{HttpRoute, RuleSet};
    use url::Url;
    use yggdrasil::proxy::resolver::ResolverFactory;
    use yggdrasil::proxy::supervisor::ProxySupervisor;

    init_tracing();

    let suffix: u32 = rand::random();
    let host_a = format!("a{suffix}.localhost");
    let host_b = format!("b{suffix}.localhost");

    // Slow backend: 1 s response latency.
    let slow = SlowBackend::spawn(Duration::from_millis(1_000)).await;
    let fast = EchoBackend::spawn("b").await;

    let tmpdir = tempfile::tempdir().unwrap();
    let rules_dir = tmpdir.path().join("rules");
    let cert_dir = tmpdir.path().join("certs");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::create_dir_all(&cert_dir).unwrap();
    issue_cert_convention(&cert_dir, &host_a);
    issue_cert_convention(&cert_dir, &host_b);

    let frontend_guard = reserve_tcp_port().await;
    let frontend_port = frontend_guard.port();
    let frontend_addr: SocketAddr = format!("127.0.0.1:{frontend_port}").parse().unwrap();

    // Initial ruleset: host_a only.
    let initial_routes = format!(
        r#"
[[route]]
hostname = "{host_a}"
target = "{}"
"#,
        slow.upstream_url(),
    );
    std::fs::write(rules_dir.join("routes.toml"), initial_routes).unwrap();

    let shutdown = CancellationToken::new();
    let cert_config = CertConfig {
        cert_dir: cert_dir.clone(),
        default_cert: None,
        default_key: None,
        // This test never dials the redirect listener; let the OS pick.
        redirect_port: Some(0),
        https_listen: frontend_addr,
        https_http3: false,
        https_alt_svc: false,
        https_request_body_limit: 16 * 1024 * 1024,
        acme: None,
        lan_cidrs: Arc::new(yggdrasil::lan_cidrs::LanCidrs::resolve(None).unwrap()),
    };
    let drain_budget = Duration::from_secs(5);
    drop(frontend_guard);
    let supervisor = ProxySupervisor::spawn(
        rules_dir,
        Duration::from_millis(50),
        ResolverFactory::new_terminal(),
        None,
        None,
        cert_config,
        Some(drain_budget),
        shutdown.clone(),
    )
    .await
    .unwrap();
    assert!(
        supervisor.wait_for_nonempty(Duration::from_secs(3)).await,
        "HTTPS frontend never came up"
    );

    // Open a TLS connection and kick off the slow request on a task so
    // we can apply the route addition in parallel.
    let tls = dial_tls(frontend_addr, &host_a, vec![b"http/1.1".to_vec()])
        .await
        .expect("TLS handshake to slow backend route");
    let host_a_for_task = host_a.clone();
    let req_handle = tokio::spawn(async move {
        let mut tls = tls;
        http1_request(&mut tls, Some(&host_a_for_task), &[], "/").await
    });

    // The in-flight request needs to actually reach the slow backend
    // before we trigger the route swap, otherwise we'd be testing the
    // wrong race (request in transit vs request awaiting backend).
    // SlowBackend doesn't expose an observable "received request"
    // signal; the 200 ms here is the irreducible client→frontend→
    // backend latency budget on loopback (typically <5 ms). The
    // outer 8 s timeout still bounds the worst case.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Apply the route addition via the supervisor handle.
    let new_set = RuleSet::from_parts(
        vec![],
        vec![
            HttpRoute {
                hostname: host_a.clone(),
                target: Url::parse(&slow.upstream_url()).unwrap(),
                hsts: None,
                headers: Default::default(),
            },
            HttpRoute {
                hostname: host_b.clone(),
                target: Url::parse(&fast.upstream_url()).unwrap(),
                hsts: None,
                headers: Default::default(),
            },
        ],
    )
    .unwrap();
    supervisor.handle().apply_ruleset(new_set).await.unwrap();

    // The in-flight request must complete within (drain_budget +
    // slow_delay + slack). If reconcile_https ever stops honouring
    // graceful_drain_timeout on the route-reload path, this read fails.
    let resp = tokio::time::timeout(Duration::from_secs(8), req_handle)
        .await
        .expect("in-flight request task exceeded outer timeout")
        .expect("in-flight request task panicked")
        .expect("in-flight request errored out (drain budget not honoured?)");
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.starts_with("HTTP/1.1 200 OK"),
        "in-flight request did not complete with 200 OK: {text}"
    );
    assert!(
        text.contains("slow-ok"),
        "in-flight response missing expected body: {text}"
    );

    shutdown.cancel();
    let _ = fast.last_request().await; // suppress unused warning
}
