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
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request as HRequest, Response as HResponse, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, SignatureScheme};
use tokio::net::TcpListener;

use yggdrasil::proxy::certs::{load_rule_into_store, CertStore};
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
                let svc = service_fn(|req: HRequest<Incoming>| async move {
                    let header = |name: &str| {
                        req.headers()
                            .get(name)
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or("")
                    };
                    let body = format!(
                        "ok xff={} xri={} xfh={}\n",
                        header("x-forwarded-for"),
                        header("x-real-ip"),
                        header("x-forwarded-host"),
                    );
                    Ok::<_, Infallible>(
                        HResponse::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/plain")
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    )
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
    let store = Arc::new(CertStore::new());
    let rule_toml = format!(
        r#"
        [[rule]]
        name = "h3-int"
        listen = "127.0.0.1:0"
        protocol = "https"

        [[rule.route]]
        hostname = "localhost"
        target = "http://{backend}"
        cert = "ephemeral"
        hsts = true
        "#,
    );
    let f = ratatoskr::rule::RuleFile::from_toml("int.toml", &rule_toml).unwrap();
    let rule = f.rule.into_iter().next().unwrap();
    load_rule_into_store(&rule, store.as_ref(), Path::new("."), None).unwrap();
    H3Frontend::spawn(rule, store).await.expect("spawn h3")
}

async fn h3_request(
    server_addr: SocketAddr,
    uri: &str,
    method: http::Method,
) -> (http::Response<()>, String) {
    tokio::time::timeout(Duration::from_secs(5), async move {
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

        let req = http::Request::builder()
            .method(method)
            .uri(uri)
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

    frontend.stop().await;
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

    frontend.stop().await;
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

    frontend.stop().await;
}
