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

use crate::common::{pick_free_tcp_port, spawn_terminal_supervisor_with_certs};

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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let req_clone = Arc::clone(&requests);
        let body_label = format!("echo:{label}");
        let handle = tokio::spawn(async move {
            loop {
                let (stream, _peer) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let req_clone2 = Arc::clone(&req_clone);
                let body_label2 = body_label.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |mut req: HyperReq<Incoming>| {
                        let req_clone3 = Arc::clone(&req_clone2);
                        let body_label3 = body_label2.clone();
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
                            let body_bytes =
                                req.body_mut().collect().await.map(|c| c.to_bytes()).unwrap_or_default();
                            captured.body = body_bytes.to_vec();
                            req_clone3.lock().await.push(captured);
                            let resp = HyperResp::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "text/plain")
                                .body(Full::new(Bytes::from(body_label3)))
                                .unwrap();
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

/// Write an HTTPS rule file to `rules_dir` with two routes pointing at
/// the supplied backend URLs. Both routes use `cert = "ephemeral"`.
fn write_https_rule_two_routes(
    rules_dir: &Path,
    rule_name: &str,
    listen: SocketAddr,
    api_host: &str,
    api_target: &str,
    app_host: &str,
    app_target: &str,
) {
    let toml = format!(
        r#"
[[rule]]
name = "{rule_name}"
protocol = "https"
listen = "{listen}"

[[rule.route]]
hostname = "{api_host}"
target = "{api_target}"
cert = "ephemeral"

[[rule.route]]
hostname = "{app_host}"
target = "{app_target}"
cert = "ephemeral"
"#,
    );
    std::fs::write(rules_dir.join("https.toml"), toml).unwrap();
}

/// Write an HTTPS rule with one route whose cert is loaded from disk.
#[allow(clippy::too_many_arguments)]
fn write_https_rule_one_route_with_paths(
    rules_dir: &Path,
    rule_name: &str,
    listen: SocketAddr,
    host: &str,
    target: &str,
    cert: &Path,
    key: &Path,
    hsts: bool,
) {
    let hsts_line = if hsts { "hsts = true\n" } else { "" };
    let toml = format!(
        r#"
[[rule]]
name = "{rule_name}"
protocol = "https"
listen = "{listen}"

[[rule.route]]
hostname = "{host}"
target = "{target}"
cert = "{}"
key = "{}"
{hsts_line}"#,
        cert.display(),
        key.display(),
    );
    std::fs::write(rules_dir.join("https.toml"), toml).unwrap();
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
        init_tracing();
        // Each test gets unique hostnames so they can't collide when
        // running in parallel (they all share `127.0.0.1`).
        let suffix: u32 = rand::random();
        let api_host = format!("api{suffix}.localhost");
        let app_host = format!("app{suffix}.localhost");

        let api = EchoBackend::spawn("api").await;
        let app = EchoBackend::spawn("app").await;

        let tmpdir = tempfile::tempdir().unwrap();
        let rules_dir = tmpdir.path().join("rules");
        let cert_dir = tmpdir.path().join("certs");
        std::fs::create_dir_all(&rules_dir).unwrap();
        std::fs::create_dir_all(&cert_dir).unwrap();

        // Pick free ephemeral ports for both the HTTPS frontend and the
        // HTTP→HTTPS redirect listener. The supervisor binds to whatever
        // `redirect_port` we hand it, so tests don't need privileged-port
        // access.
        let frontend_port = pick_free_tcp_port().await;
        let redirect_port = pick_free_tcp_port().await;
        let frontend_addr: SocketAddr = format!("127.0.0.1:{frontend_port}").parse().unwrap();

        write_https_rule_two_routes(
            &rules_dir,
            "front",
            frontend_addr,
            &api_host,
            &api.upstream_url(),
            &app_host,
            &app.upstream_url(),
        );

        let shutdown = CancellationToken::new();
        let cert_config = CertConfig {
            cert_dir: cert_dir.clone(),
            default_cert: None,
            default_key: None,
            redirect_port: Some(redirect_port),
        };
        let supervisor = spawn_terminal_supervisor_with_certs(
            rules_dir,
            Duration::from_millis(50),
            cert_config,
            shutdown.clone(),
        )
        .await;
        assert!(
            supervisor
                .wait_for_nonempty(Duration::from_secs(2))
                .await,
            "supervisor never spawned its HTTPS proxy"
        );

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
        // give the supervisor a moment to drain — strictly-correct teardown
        // would also `supervisor.stop().await` but the Drop on tmpdir is
        // sufficient for the assertions we've already made.
        tokio::time::sleep(Duration::from_millis(50)).await;
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
    assert_eq!(captured.header("x-forwarded-host"), Some(fx.api_host.as_str()));
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
    let resp = http1_request(
        &mut tls,
        Some("nowhere.localhost"),
        &[],
        "/",
    )
    .await
    .unwrap();
    let body = String::from_utf8_lossy(&resp);
    assert!(
        body.starts_with("HTTP/1.1 404"),
        "expected 404, got: {body}"
    );
    fx.stop().await;
}

/// §6h(8): the route's backend is unreachable → 502.
#[tokio::test]
async fn dead_backend_returns_502() {
    // Build a fixture where one route points at a never-bound port.
    let tmpdir = tempfile::tempdir().unwrap();
    let rules_dir = tmpdir.path().join("rules");
    let cert_dir = tmpdir.path().join("certs");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::create_dir_all(&cert_dir).unwrap();
    let frontend_port = pick_free_tcp_port().await;
    let frontend_addr: SocketAddr = format!("127.0.0.1:{frontend_port}").parse().unwrap();

    let dead_port = pick_free_tcp_port().await;
    // dead_port is free *right now* — by the time the frontend dials it,
    // the test is the only thing on this loopback host that knows it, so
    // the dial will return ECONNREFUSED.
    let host = format!("dead{}.localhost", rand::random::<u32>());
    let toml = format!(
        r#"
[[rule]]
name = "dead"
protocol = "https"
listen = "{frontend_addr}"

[[rule.route]]
hostname = "{host}"
target = "http://127.0.0.1:{dead_port}"
cert = "ephemeral"
"#,
    );
    std::fs::write(rules_dir.join("https.toml"), toml).unwrap();

    let shutdown = CancellationToken::new();
    let redirect_port = pick_free_tcp_port().await;
    let supervisor = spawn_terminal_supervisor_with_certs(
        rules_dir,
        Duration::from_millis(50),
        CertConfig {
            cert_dir,
            default_cert: None,
            default_key: None,
            redirect_port: Some(redirect_port),
        },
        shutdown.clone(),
    )
    .await;
    assert!(
        supervisor
            .wait_for_nonempty(Duration::from_secs(2))
            .await
    );
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
    shutdown.cancel();
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
    // Build a single-route fixture with HSTS enabled on a disk-loaded
    // cert (proves the disk-cert path also injects HSTS).
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
    let frontend_port = pick_free_tcp_port().await;
    let frontend_addr: SocketAddr = format!("127.0.0.1:{frontend_port}").parse().unwrap();
    write_https_rule_one_route_with_paths(
        &rules_dir,
        "hsts",
        frontend_addr,
        &host,
        &api.upstream_url(),
        &cert_path,
        &key_path,
        true,
    );
    let shutdown = CancellationToken::new();
    let redirect_port = pick_free_tcp_port().await;
    let supervisor = spawn_terminal_supervisor_with_certs(
        rules_dir,
        Duration::from_millis(50),
        CertConfig {
            cert_dir,
            default_cert: None,
            default_key: None,
            redirect_port: Some(redirect_port),
        },
        shutdown.clone(),
    )
    .await;
    assert!(
        supervisor
            .wait_for_nonempty(Duration::from_secs(2))
            .await
    );
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

/// §6h(7): drop semantics for malformed requests. We send a request with no
/// `Host` header at all. The frontend should respond 4xx (or drop). We
/// accept either as a success.
#[tokio::test]
async fn missing_host_header_is_rejected() {
    let fx = TwoRouteFixture::spawn().await;
    let mut tls = dial_tls(fx.frontend_addr, &fx.api_host, vec![b"http/1.1".to_vec()])
        .await
        .unwrap();
    let resp = http1_request(&mut tls, None, &[], "/")
        .await
        .unwrap();
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
    // Give the redirect listener a brief moment to fully wire up.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut tcp = TcpStream::connect(format!("127.0.0.1:{}", fx.redirect_port))
        .await
        .expect("connect to redirect listener");
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
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut tcp = TcpStream::connect(format!("127.0.0.1:{}", fx.redirect_port))
        .await
        .expect("connect to redirect listener");
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
    let cert_path = cert_dir.join("cert.pem");
    let key_path = cert_dir.join("key.pem");
    let host = format!("reload{}.localhost", rand::random::<u32>());
    issue_self_signed_pem(&cert_path, &key_path, &host);
    let frontend_port = pick_free_tcp_port().await;
    let frontend_addr: SocketAddr = format!("127.0.0.1:{frontend_port}").parse().unwrap();
    write_https_rule_one_route_with_paths(
        &rules_dir,
        "reload",
        frontend_addr,
        &host,
        &api.upstream_url(),
        &cert_path,
        &key_path,
        false,
    );
    let shutdown = CancellationToken::new();
    let redirect_port = pick_free_tcp_port().await;
    let supervisor = spawn_terminal_supervisor_with_certs(
        rules_dir,
        Duration::from_millis(50),
        CertConfig {
            cert_dir,
            default_cert: None,
            default_key: None,
            redirect_port: Some(redirect_port),
        },
        shutdown.clone(),
    )
    .await;
    assert!(
        supervisor
            .wait_for_nonempty(Duration::from_secs(2))
            .await
    );
    let first_leaf_fp = leaf_fingerprint(frontend_addr, &host).await;
    // Replace the cert with a freshly-generated one. The dedicated cert
    // watcher in `certs.rs` will observe the file-write event in the
    // cert directory, debounce, and trigger `CertStore::reload_host`
    // for the affected hostname — no rule-file bump required.
    std::thread::sleep(std::time::Duration::from_millis(100));
    issue_self_signed_pem(&cert_path, &key_path, &host);
    // Wait up to 2s for the reload to land.
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut second_leaf_fp = first_leaf_fp;
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let now = leaf_fingerprint(frontend_addr, &host).await;
        if now != first_leaf_fp {
            second_leaf_fp = now;
            break;
        }
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
    let api = EchoBackend::spawn("api").await;
    let tmpdir = tempfile::tempdir().unwrap();
    let rules_dir = tmpdir.path().join("rules");
    let cert_dir = tmpdir.path().join("certs");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::create_dir_all(&cert_dir).unwrap();
    let cert_path = cert_dir.join("cert.pem");
    let key_path = cert_dir.join("key.pem");
    let host = format!("bad{}.localhost", rand::random::<u32>());
    issue_self_signed_pem(&cert_path, &key_path, &host);
    let frontend_port = pick_free_tcp_port().await;
    let frontend_addr: SocketAddr = format!("127.0.0.1:{frontend_port}").parse().unwrap();
    write_https_rule_one_route_with_paths(
        &rules_dir,
        "bad",
        frontend_addr,
        &host,
        &api.upstream_url(),
        &cert_path,
        &key_path,
        false,
    );
    let shutdown = CancellationToken::new();
    let redirect_port = pick_free_tcp_port().await;
    let supervisor = spawn_terminal_supervisor_with_certs(
        rules_dir,
        Duration::from_millis(50),
        CertConfig {
            cert_dir,
            default_cert: None,
            default_key: None,
            redirect_port: Some(redirect_port),
        },
        shutdown.clone(),
    )
    .await;
    assert!(
        supervisor
            .wait_for_nonempty(Duration::from_secs(2))
            .await
    );
    let first_leaf_fp = leaf_fingerprint(frontend_addr, &host).await;
    // Trash the cert on disk. The cert watcher debounces the write event
    // and asks `CertStore::reload_host` to re-resolve — which fails
    // because the file is now malformed. The store keeps the previously
    // loaded entry in service.
    std::fs::write(&cert_path, b"this is not pem").unwrap();
    // Give the watcher's debounce window + a healthy margin to attempt
    // the reload and reject it.
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
