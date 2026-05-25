//! HTTP / HTTPS load generator (request-rate scenario).
//!
//! Drives a closed-loop ping-pong of HTTP requests across N persistent
//! connections to measure requests/sec + per-request latency. Used by
//! `bench/http-rps.sh` to put yggdrasil's L7 HTTPS frontend
//! head-to-head against nginx / traefik on the same workload.
//!
//! ## Protocol shape
//!
//! Each connection issues HTTP/1.1 `GET <path>` keep-alive requests
//! sequentially (`Connection: keep-alive`, default in HTTP/1.1). The
//! request body is empty; the response body is whatever the backend
//! returns (typically a fixed-size byte string from `bench-echo
//! http`). We measure wall-clock from "started writing the request"
//! to "finished reading the response body" for each request.
//!
//! HTTPS uses `tokio-rustls` with a **permissive** `ServerCertVerifier`
//! (`AcceptAnyCert`) — bench scenarios use self-signed ephemeral
//! certs, and the goal is to measure TLS-termination cost, not
//! certificate validation. **Do not reuse this module outside the
//! bench harness.**
//!
//! ## What we do NOT cover here (yet)
//!
//! * HTTP/2 multiplexing on the client side — every connection is
//!   HTTP/1.1. Easy to add via `hyper::client::conn::http2` if a
//!   scenario calls for it; the bench harness drives keep-alive
//!   single-stream RPS first because that is the workload yggdrasil's
//!   forward path optimises for.
//! * Streaming bodies. The whole response body is collected before
//!   the latency sample is recorded. For body-throughput scenarios
//!   we'd add a separate `http-throughput` mode that sums bytes/sec.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use hdrhistogram::Histogram;
use http::Request;
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, SignatureScheme};
use serde_json::json;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;

use crate::report::{build_report, finalize_stats, unix_ms_now, LatencySummary, Report, Stats};
use crate::HttpRpsArgs;

/// Test-only `ServerCertVerifier` that accepts any chain. Bench scenarios
/// use self-signed ephemeral certs; the goal is to measure
/// TLS-termination cost in the proxy under test, not certificate
/// validation. Mirrors the same shape used by yggdrasil's HTTPS
/// integration tests.
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
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

fn permissive_client_config() -> Arc<ClientConfig> {
    let mut cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

/// Parsed target URL. We don't link the `url` crate just for this one
/// scenario; the minimal parse here handles the shapes the bench
/// harness uses (`http://h:p/p`, `https://h:p/p`).
struct Target {
    tls: bool,
    host: String,
    port: u16,
    authority: String,
    path: String,
}

fn parse_target(s: &str) -> Result<Target> {
    let (scheme, rest) = match s.split_once("://") {
        Some(("http", r)) => (false, r),
        Some(("https", r)) => (true, r),
        _ => bail!("target must start with http:// or https://: {s}"),
    };
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a.to_string(), format!("/{p}")),
        None => (rest.to_string(), "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse()
                .with_context(|| format!("parse port from {authority}"))?,
        ),
        None => (authority.clone(), if scheme { 443 } else { 80 }),
    };
    Ok(Target {
        tls: scheme,
        host,
        port,
        authority,
        path,
    })
}

/// Driver for the `http-rps` scenario.
pub async fn run_http_rps(subject: &str, args: HttpRpsArgs) -> Result<Report> {
    // Install the rustls default crypto provider once. The
    // `with_no_client_auth` builder picks it up implicitly.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let target = parse_target(&args.target)?;
    let HttpRpsArgs {
        target: _,
        concurrency,
        duration,
        warmup,
    } = args;

    let total_duration = warmup + duration;
    let hist: Arc<Mutex<Histogram<u64>>> = Arc::new(Mutex::new(
        Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap(),
    ));
    let tx_requests = Arc::new(AtomicU64::new(0));
    let rx_responses = Arc::new(AtomicU64::new(0));
    let rx_bytes = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));

    let ts_start = unix_ms_now();
    let started = Instant::now();
    let measure_start = started + warmup;
    let deadline = started + total_duration;

    let target = Arc::new(target);
    let tls_config = if target.tls {
        Some(permissive_client_config())
    } else {
        None
    };

    let mut handles = Vec::with_capacity(concurrency as usize);
    for _ in 0..concurrency {
        let hist = Arc::clone(&hist);
        let tx_requests = Arc::clone(&tx_requests);
        let rx_responses = Arc::clone(&rx_responses);
        let rx_bytes = Arc::clone(&rx_bytes);
        let errors = Arc::clone(&errors);
        let target = Arc::clone(&target);
        let tls_config = tls_config.clone();
        handles.push(tokio::spawn(async move {
            // One persistent connection per task. On hard error we
            // bump the error counter and try again until deadline.
            while Instant::now() < deadline {
                let sender = match open_connection(&target, tls_config.as_ref()).await {
                    Ok(s) => s,
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        continue;
                    }
                };
                if drive_connection(
                    sender,
                    &target,
                    deadline,
                    measure_start,
                    &hist,
                    &tx_requests,
                    &rx_responses,
                    &rx_bytes,
                    &errors,
                )
                .await
                .is_err()
                {
                    // connection dropped (server closed keep-alive,
                    // TLS error, etc.); loop and reconnect.
                    continue;
                }
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }

    let ts_end = unix_ms_now();
    let elapsed = started.elapsed().saturating_sub(warmup);

    let tx = tx_requests.load(Ordering::Relaxed);
    let rx = rx_responses.load(Ordering::Relaxed);
    let bytes = rx_bytes.load(Ordering::Relaxed);
    let errs = errors.load(Ordering::Relaxed);

    let hist = Arc::try_unwrap(hist)
        .ok()
        .map(|m| m.into_inner())
        .unwrap_or_else(|| Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap());

    let mut stats = Stats {
        tx_packets: tx,
        rx_packets: rx,
        tx_bytes: 0,
        rx_bytes: bytes,
        errors: errs,
        latency_us: Some(LatencySummary::from_hist(&hist)),
        ..Default::default()
    };
    finalize_stats(&mut stats, elapsed);

    let mut params = serde_json::Map::new();
    params.insert("concurrency".into(), json!(concurrency));
    params.insert("duration_s".into(), json!(duration.as_secs_f64()));
    params.insert("warmup_s".into(), json!(warmup.as_secs_f64()));
    params.insert("tls".into(), json!(target.tls));

    Ok(build_report(
        "http-rps",
        subject,
        &args_to_target(&target),
        params,
        stats,
        ts_start,
        ts_end,
    ))
}

fn args_to_target(target: &Target) -> String {
    let scheme = if target.tls { "https" } else { "http" };
    format!("{scheme}://{}{}", target.authority, target.path)
}

/// Drive a single keep-alive HTTP/1.1 connection until `deadline` or
/// the connection breaks. Returns `Ok(())` on graceful termination
/// (deadline reached) and `Err` on connection failure so the caller
/// can reconnect.
#[allow(clippy::too_many_arguments)]
async fn drive_connection<B>(
    mut sender: SendRequest<B>,
    target: &Target,
    deadline: Instant,
    measure_start: Instant,
    hist: &Mutex<Histogram<u64>>,
    tx_requests: &AtomicU64,
    rx_responses: &AtomicU64,
    rx_bytes: &AtomicU64,
    errors: &AtomicU64,
) -> Result<()>
where
    B: hyper::body::Body + From<Empty<Bytes>> + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + std::fmt::Debug,
{
    while Instant::now() < deadline {
        let req = Request::builder()
            .method(http::Method::GET)
            .uri(&target.path)
            .header(http::header::HOST, &target.authority)
            .header(http::header::USER_AGENT, "loadgen/http-rps")
            .body(B::from(Empty::<Bytes>::new()))
            .expect("build request");
        let started = Instant::now();
        tx_requests.fetch_add(1, Ordering::Relaxed);
        let resp = match sender.send_request(req).await {
            Ok(r) => r,
            Err(e) => {
                errors.fetch_add(1, Ordering::Relaxed);
                return Err(e.into());
            }
        };
        let bytes = match resp.into_body().collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => {
                errors.fetch_add(1, Ordering::Relaxed);
                return Err(anyhow::anyhow!("collect body failed"));
            }
        };
        if Instant::now() >= measure_start {
            let micros = started.elapsed().as_micros() as u64;
            let _ = hist.lock().await.record(micros.max(1));
            rx_responses.fetch_add(1, Ordering::Relaxed);
            rx_bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
        }
    }
    Ok(())
}

/// Open one HTTP/1.1 connection to the target, performing the TLS
/// handshake if the URL scheme requested it. Returns a `SendRequest`
/// handle ready to issue requests.
async fn open_connection(
    target: &Target,
    tls_config: Option<&Arc<ClientConfig>>,
) -> Result<SendRequest<Empty<Bytes>>> {
    // Use tokio's `ToSocketAddrs` impl on `(host, port)` so hostnames
    // (`localhost`, `api.example.com`) resolve via getaddrinfo instead
    // of failing the `SocketAddr` parse path. IPs work too — the impl
    // short-circuits when the host is already a literal address.
    let tcp = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .with_context(|| format!("connect tcp to {}:{}", target.host, target.port))?;
    let _ = tcp.set_nodelay(true);
    if let Some(cfg) = tls_config {
        let server_name = ServerName::try_from(target.host.clone())
            .map_err(|e| anyhow::anyhow!("invalid SNI {}: {e}", target.host))?;
        let connector = TlsConnector::from(Arc::clone(cfg));
        let tls = connector.connect(server_name, tcp).await?;
        let io = TokioIo::new(tls);
        let (sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sender)
    } else {
        let io = TokioIo::new(tcp);
        let (sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sender)
    }
}
