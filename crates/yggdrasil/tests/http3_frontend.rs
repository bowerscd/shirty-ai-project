//! End-to-end HTTP/3 integration tests.
//!
//! Drives `H3Frontend` with a real `quinn` + `h3` client. Covers:
//!  - h3 GET round-trip (200 OK with backend body).
//!  - SNI/host-based route dispatch (404 on unknown host).
//!  - X-Forwarded-For / X-Real-IP / X-Forwarded-Host injection.
//!  - HSTS injection on responses.
//!  - WebSocket-over-h3-style CONNECT returns 501 with Sec-WebSocket-Version.

mod common;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request as HRequest, Response as HResponse, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, SignatureScheme};
use tokio::net::TcpListener;

use yggdrasil::proxy::certs::{load_routes_into_store, CertStore};
use yggdrasil::proxy::h3_frontend::H3Frontend;

/// Test-only `ServerCertVerifier` that accepts any chain. The H3 frontend's
/// ephemeral leaf is self-signed, so this client opts out of validation.
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
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

async fn spawn_backend() -> SocketAddr {
    spawn_backend_with(false, &[]).await
}

async fn spawn_echo_length_backend() -> SocketAddr {
    spawn_backend_with(true, &[]).await
}

async fn spawn_backend_emitting_headers(
    extra_headers: &'static [(&'static str, &'static str)],
) -> SocketAddr {
    spawn_backend_with(false, extra_headers).await
}

async fn spawn_backend_with(
    echo_body_length: bool,
    extra_response_headers: &'static [(&'static str, &'static str)],
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _accept_loop = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let io = TokioIo::new(stream);
            let _conn = tokio::spawn(async move {
                let svc = service_fn(move |req: HRequest<Incoming>| async move {
                    if echo_body_length {
                        let collected = req.into_body().collect().await.expect("collect body");
                        let bytes = collected.to_bytes();
                        let body = format!("body_len={}\n", bytes.len());
                        return Ok::<_, Infallible>(
                            HResponse::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "text/plain")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        );
                    }
                    let header = |name: &str| {
                        req.headers()
                            .get(name)
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or("")
                    };
                    let body = format!(
                        "ok xff={} xri={} xfh={} xfp={} xfpsyn={}\n",
                        header("x-forwarded-for"),
                        header("x-real-ip"),
                        header("x-forwarded-host"),
                        header("x-forwarded-proto"),
                        header("x-forwarded-protocol"),
                    );
                    let mut builder = HResponse::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "text/plain");
                    for (name, value) in extra_response_headers {
                        builder = builder.header(*name, *value);
                    }
                    Ok::<_, Infallible>(builder.body(Full::new(Bytes::from(body))).unwrap())
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    addr
}

fn build_h3_client_endpoint() -> quinn::Endpoint {
    let mut crypto = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let quic_crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quinn client config");
    let client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);
    endpoint
}

async fn build_frontend(backend: SocketAddr) -> H3Frontend {
    build_frontend_with(backend, 16 * 1024 * 1024, std::collections::BTreeMap::new()).await
}

async fn build_frontend_with_body_limit(backend: SocketAddr, body_limit: usize) -> H3Frontend {
    build_frontend_with(backend, body_limit, std::collections::BTreeMap::new()).await
}

async fn build_frontend_with_static_headers(
    backend: SocketAddr,
    static_headers: std::collections::BTreeMap<String, String>,
) -> H3Frontend {
    build_frontend_with(backend, 16 * 1024 * 1024, static_headers).await
}

async fn build_frontend_with(
    backend: SocketAddr,
    body_limit: usize,
    static_headers: std::collections::BTreeMap<String, String>,
) -> H3Frontend {
    // Build a one-route HttpRoute pointing at `backend` and a per-host
    // cert via the cert convention. The H3 frontend will pick this up
    // through the shared cert store at startup.
    let tmp = tempfile::tempdir().expect("tmpdir");
    let cert_dir = tmp.path().to_path_buf();
    let host = "localhost";
    let host_dir = cert_dir.join(host);
    std::fs::create_dir_all(&host_dir).expect("mkdir host");
    let mut params = rcgen::CertificateParams::new(vec![host.to_string()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    std::fs::write(host_dir.join("fullchain.pem"), cert.pem()).unwrap();
    std::fs::write(host_dir.join("privkey.pem"), key.serialize_pem()).unwrap();

    let target = url::Url::parse(&format!("http://{backend}/")).unwrap();
    let routes = vec![ratatoskr::rule::HttpRoute {
        hostname: host.to_string(),
        target,
        hsts: Some(ratatoskr::rule::HstsConfig::default()),
        headers: static_headers,
    }];

    let store = Arc::new(CertStore::new());
    let _cert_less = load_routes_into_store("h3-int", &routes, store.as_ref(), &cert_dir, None)
        .expect("load route certs");

    // Tmpdir is kept alive for the test duration via `std::mem::forget`.
    // The cert paths sit inside it; once the test exits the OS cleans up.
    std::mem::forget(tmp);

    H3Frontend::spawn(
        "h3-int".to_string(),
        "127.0.0.1:0".parse().unwrap(),
        &routes,
        store,
        body_limit,
    )
    .await
    .expect("spawn h3")
}

async fn h3_request(
    server_addr: SocketAddr,
    uri: &str,
    method: http::Method,
) -> (http::Response<()>, String) {
    h3_request_with_body(server_addr, uri, method, Vec::new()).await
}

async fn h3_request_with_body(
    server_addr: SocketAddr,
    uri: &str,
    method: http::Method,
    body: Vec<u8>,
) -> (http::Response<()>, String) {
    tokio::time::timeout(Duration::from_secs(10), async move {
        let endpoint = build_h3_client_endpoint();
        let conn = endpoint
            .connect(server_addr, "localhost")
            .expect("dial setup")
            .await
            .expect("h3 handshake");

        let h3_quinn_conn = h3_quinn::Connection::new(conn);
        let (mut h3_conn, mut send) = h3::client::new(h3_quinn_conn).await.expect("h3 client new");
        let driver = tokio::spawn(async move {
            let _ = futures::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
        });

        let mut builder = http::Request::builder().method(method).uri(uri);
        if !body.is_empty() {
            builder = builder.header("content-length", body.len().to_string());
        }
        let req = builder.body(()).unwrap();
        let mut stream = send.send_request(req).await.expect("send_request");
        if !body.is_empty() {
            stream
                .send_data(Bytes::from(body))
                .await
                .expect("send_data");
        }
        stream.finish().await.expect("finish");

        let resp = stream.recv_response().await.expect("recv_response");
        let mut buf = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.expect("recv_data") {
            while chunk.has_remaining() {
                buf.push(chunk.get_u8());
            }
        }

        drop(stream);
        drop(send);
        endpoint.close(quinn::VarInt::from_u32(0), b"done");
        let _ = tokio::time::timeout(Duration::from_secs(1), driver).await;

        (resp, String::from_utf8(buf).expect("utf8 body"))
    })
    .await
    .expect("h3 request timed out")
}

#[tokio::test(flavor = "multi_thread")]
async fn h3_get_round_trip() {
    let backend = spawn_backend().await;
    let frontend = build_frontend(backend).await;

    let (resp, body) = h3_request(
        frontend.local_addr(),
        "https://localhost/",
        http::Method::GET,
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("strict-transport-security")
            .and_then(|value| value.to_str().ok()),
        Some("max-age=31536000"),
    );
    assert!(body.starts_with("ok xff="), "got body: {body}");
    assert!(body.contains("xff=127.0.0.1"), "body missing xff: {body}");
    assert!(body.contains("xri=127.0.0.1"), "body missing xri: {body}");
    assert!(body.contains("xfh=localhost"), "body missing xfh: {body}");
    assert!(body.contains("xfp=https"), "body missing xfp: {body}");
    assert!(
        body.contains("xfpsyn=https"),
        "body missing X-Forwarded-Protocol synonym: {body}"
    );

    frontend.stop(None).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn h3_unknown_host_returns_404() {
    let backend = spawn_backend().await;
    let frontend = build_frontend(backend).await;

    let (resp, body) = h3_request(
        frontend.local_addr(),
        "https://nonexistent.example/",
        http::Method::GET,
    )
    .await;

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(body, "no route\n");

    frontend.stop(None).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn h3_connect_returns_websocket_fallback_501() {
    let backend = spawn_backend().await;
    let frontend = build_frontend(backend).await;

    let (resp, body) = h3_request(
        frontend.local_addr(),
        "https://localhost/",
        http::Method::CONNECT,
    )
    .await;

    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(
        resp.headers()
            .get("sec-websocket-version")
            .and_then(|value| value.to_str().ok()),
        Some("13"),
    );
    assert!(body.contains("fall back"), "got body: {body}");

    frontend.stop(None).await;
}

/// End-to-end PROXY-v2 client-IP propagation for HTTP/3 chain traffic.
///
/// We bind a UDP socket on `127.0.0.1` standing in for the chain relay's
/// outbound flow socket, write a PROXY-v2 datagram from it to the
/// terminal claiming `(client = 203.0.113.45:54321 → server =
/// terminal_addr)`, then hand the same socket to a `quinn::Endpoint` so
/// the QUIC handshake datagrams arrive at the terminal with the *same*
/// source 5-tuple. The terminal's interpose socket strips the PROXY
/// datagram, records `synthetic_relay_addr → 203.0.113.45:54321`, and
/// the h3 accept loop reflects `203.0.113.45` as `X-Forwarded-For` /
/// `X-Real-IP` on the backend request.
///
/// This is the keystone test for the UDP/HTTP-3 leg of the chain
/// client-IP propagation work: it exercises encode → kernel transport
/// → interpose decode → map upsert → quinn accept lookup → request
/// header injection in a single in-process pipeline.
#[tokio::test(flavor = "multi_thread")]
async fn h3_chain_proxy_v2_propagates_real_client_ip_to_xff() {
    let backend = spawn_backend().await;
    let frontend = build_frontend(backend).await;
    let terminal_addr = frontend.local_addr();

    // Synthetic relay outbound socket. Bound *before* we hand it to
    // quinn so we can sneak a PROXY-v2 datagram out in front of the
    // handshake on the same 5-tuple.
    let synthetic_relay_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    synthetic_relay_sock.set_nonblocking(true).unwrap();
    let synthetic_relay_addr = synthetic_relay_sock.local_addr().unwrap();

    // Forge a "real client" address that's distinctly NOT 127.0.0.1, so
    // the assertion below can tell apart "interpose ran" from "kernel
    // peer fallback ran" — both would yield 127.0.0.1 on pure loopback.
    let fake_client: SocketAddr = "203.0.113.45:54321".parse().unwrap();
    let proxy_header = yggdrasil::proxy::proxy_protocol::encode_header(
        ratatoskr::rule::ProxyProto::V2,
        fake_client,
        terminal_addr,
    );
    synthetic_relay_sock
        .send_to(&proxy_header, terminal_addr)
        .expect("send PROXY v2 datagram");

    // Give the terminal's interpose socket a beat to recv + upsert.
    // The interpose's poll_recv runs whenever quinn polls the socket;
    // here we want the PROXY datagram to land before quinn's client-
    // side handshake fires its Initial, otherwise quinn would see an
    // Initial first and stamp X-Forwarded-For from the kernel peer
    // before the interpose ever sees the PROXY datagram.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Hand the now-quiesced socket to a client-side quinn endpoint.
    let runtime = quinn::default_runtime().unwrap();
    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        synthetic_relay_sock,
        runtime,
    )
    .expect("build chain-emulation client endpoint");
    endpoint.set_default_client_config({
        let mut crypto = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let quic_crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quinn ccfg");
        quinn::ClientConfig::new(Arc::new(quic_crypto))
    });

    let (resp, body) = tokio::time::timeout(Duration::from_secs(5), async move {
        let conn = endpoint
            .connect(terminal_addr, "localhost")
            .expect("dial setup")
            .await
            .expect("h3 handshake");

        let h3q = h3_quinn::Connection::new(conn);
        let (mut h3c, mut send) = h3::client::new(h3q).await.expect("h3 client new");
        let driver = tokio::spawn(async move {
            let _ = futures::future::poll_fn(|cx| h3c.poll_close(cx)).await;
        });

        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://localhost/")
            .body(())
            .unwrap();
        let mut stream = send.send_request(req).await.expect("send_request");
        stream.finish().await.expect("finish");

        let resp = stream.recv_response().await.expect("recv_response");
        let mut buf = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.expect("recv_data") {
            while chunk.has_remaining() {
                buf.push(chunk.get_u8());
            }
        }
        drop(stream);
        drop(send);
        endpoint.close(quinn::VarInt::from_u32(0), b"done");
        let _ = tokio::time::timeout(Duration::from_secs(1), driver).await;
        (resp, String::from_utf8(buf).expect("utf8 body"))
    })
    .await
    .expect("h3 request timed out");

    assert_eq!(resp.status(), StatusCode::OK);
    // The synthetic relay forwarded the PROXY-v2 datagram declaring
    // client = 203.0.113.45. The terminal's interpose recovered that,
    // and the h3 frontend stamped it into the backend request.
    assert!(
        body.contains("xff=203.0.113.45"),
        "expected xff=203.0.113.45 (real client from PROXY v2), got body: {body}; \
         synthetic_relay_addr was {synthetic_relay_addr}"
    );
    assert!(
        body.contains("xri=203.0.113.45"),
        "expected xri=203.0.113.45 (real client from PROXY v2), got body: {body}"
    );
    assert!(
        !body.contains("xff=127.0.0.1"),
        "X-Forwarded-For leaked the kernel-observed peer (127.0.0.1) \
         instead of the PROXY-v2-recovered real client; interpose did \
         not fire. body: {body}"
    );

    frontend.stop(None).await;
}

/// Operator raises `[server].https_request_body_limit` above the default;
/// a POST that previously would have been rejected by the old hard 16 MiB
/// cap now succeeds and the full body reaches the backend. Uses a tiny
/// custom limit (32 KiB) and a body just under it to keep the test cheap
/// while still exercising the knob.
#[tokio::test(flavor = "multi_thread")]
async fn h3_post_within_custom_body_limit_succeeds() {
    let backend = spawn_echo_length_backend().await;
    let body_limit = 32 * 1024;
    let frontend = build_frontend_with_body_limit(backend, body_limit).await;

    let payload = vec![b'x'; 16 * 1024];
    let payload_len = payload.len();
    let (resp, body) = h3_request_with_body(
        frontend.local_addr(),
        "https://localhost/upload",
        http::Method::POST,
        payload,
    )
    .await;

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "expected 200 for body under configured limit ({body_limit} bytes); body: {body}"
    );
    assert!(
        body.contains(&format!("body_len={payload_len}")),
        "backend did not receive the full body; got body: {body}"
    );

    frontend.stop(None).await;
}

/// Per-route `[[route]].headers` stamps the configured names + values
/// onto every h3 response, and operator-set values OVERRIDE backend-set
/// values of the same name (mirrors the h1/h2 behaviour). The backend
/// here returns its own `X-Frame-Options` that the route config
/// overrides, plus an unrelated `X-Backend-Tag` that passes through.
#[tokio::test(flavor = "multi_thread")]
async fn h3_static_response_headers_reach_client_and_override_backend() {
    let backend = spawn_backend_emitting_headers(&[
        ("x-frame-options", "ALLOW-FROM https://evil.example"),
        ("x-backend-tag", "kept"),
    ])
    .await;
    let mut static_headers = std::collections::BTreeMap::new();
    static_headers.insert(
        "X-Robots-Tag".to_string(),
        "noindex, nofollow, nosnippet, noarchive".to_string(),
    );
    static_headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
    static_headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
    static_headers.insert(
        "Content-Security-Policy".to_string(),
        "default-src 'self'".to_string(),
    );
    let frontend = build_frontend_with_static_headers(backend, static_headers).await;

    let (resp, _body) = h3_request(
        frontend.local_addr(),
        "https://localhost/",
        http::Method::GET,
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);

    // All four configured static headers reached the client.
    assert_eq!(
        resp.headers()
            .get("x-robots-tag")
            .and_then(|v| v.to_str().ok()),
        Some("noindex, nofollow, nosnippet, noarchive"),
    );
    assert_eq!(
        resp.headers()
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff"),
    );
    assert_eq!(
        resp.headers()
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok()),
        Some("default-src 'self'"),
    );

    // Operator's X-Frame-Options overrode the backend's: exactly one
    // value, and it's DENY.
    let xfo_values: Vec<_> = resp
        .headers()
        .get_all("x-frame-options")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert_eq!(
        xfo_values,
        vec!["DENY"],
        "operator X-Frame-Options should override backend"
    );

    // Unrelated backend header still flows through.
    assert_eq!(
        resp.headers()
            .get("x-backend-tag")
            .and_then(|v| v.to_str().ok()),
        Some("kept"),
    );

    frontend.stop(None).await;
}

/// Operator-configured body limit is enforced: a POST exceeding the
/// configured cap returns 413 Payload Too Large and is NOT forwarded to
/// the backend.
#[tokio::test(flavor = "multi_thread")]
async fn h3_post_over_custom_body_limit_returns_413() {
    let backend = spawn_echo_length_backend().await;
    let body_limit = 8 * 1024;
    let frontend = build_frontend_with_body_limit(backend, body_limit).await;

    let payload = vec![b'x'; 16 * 1024];
    let (resp, _body) = h3_request_with_body(
        frontend.local_addr(),
        "https://localhost/upload",
        http::Method::POST,
        payload,
    )
    .await;

    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "expected 413 for body over configured limit ({body_limit} bytes)"
    );

    frontend.stop(None).await;
}
