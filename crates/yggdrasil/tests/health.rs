//! `/metrics`, `/healthz`, `/readyz` smoke test.
//!
//! Exercises the HTTP listener spawned by [`yggdrasil::metrics::init`] —
//! verifying:
//!
//! - `/healthz` returns 200 unconditionally (liveness)
//! - `/readyz` returns 503 *before* [`yggdrasil::health::mark_ready`] is
//!   called, and 200 after (the kubelet/LB ready-flip pattern)
//! - `/metrics` returns 200 with the prometheus exposition containing the
//!   `yggdrasil_build_info` gauge installed by `init`
//! - Unknown paths return 404
//!
//! This is a single `#[tokio::test]` because the global prometheus
//! recorder can only be installed once per process; integration test
//! binaries are per-file so we can keep one focused test here. Multiple
//! probes against the same listener happen within this one test.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use ratatoskr::control::Mode;

/// Helper: open a fresh TCP connection, send a minimal HTTP/1.1 GET
/// request with `Connection: close`, and return the raw response bytes as
/// a String. Per-request connection so each probe is isolated.
async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
    let mut tcp = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("connect {addr}: {e}"));
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    );
    tcp.write_all(req.as_bytes()).await.expect("write request");
    let mut buf = Vec::new();
    // Read with a timeout in case the server hangs; smoke test should be quick.
    let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut buf))
        .await
        .expect("read timeout");
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_listener_serves_health_and_metrics() {
    // 127.0.0.1:0 -> kernel picks a free port. init() returns the bound addr.
    let addr = yggdrasil::metrics::init(
        "127.0.0.1:0".parse().unwrap(),
        Mode::Terminal,
        None,
    )
    .await
    .expect("metrics init");

    // /healthz is unconditional — process is responding, so 200 ok.
    let resp = http_get(addr, "/healthz").await;
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "expected 200 on /healthz, got:\n{resp}"
    );
    assert!(resp.ends_with("ok\n"), "/healthz body mismatch:\n{resp}");

    // /readyz is gated on health::mark_ready — before it's called, expect 503.
    let resp = http_get(addr, "/readyz").await;
    assert!(
        resp.starts_with("HTTP/1.1 503"),
        "expected 503 on /readyz before mark_ready, got:\n{resp}"
    );
    assert!(
        resp.ends_with("not ready\n"),
        "/readyz body mismatch (before): {resp}"
    );

    // /metrics — recorder is installed, exposition includes the build_info
    // gauge we emitted at init time.
    let resp = http_get(addr, "/metrics").await;
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "expected 200 on /metrics, got:\n{resp}"
    );
    assert!(
        resp.contains("yggdrasil_build_info"),
        "/metrics missing build_info gauge:\n{resp}"
    );

    // Unknown path -> 404.
    let resp = http_get(addr, "/nope").await;
    assert!(
        resp.starts_with("HTTP/1.1 404"),
        "expected 404 on /nope, got:\n{resp}"
    );

    // Flip readiness; /readyz should now return 200 "ready\n".
    yggdrasil::health::mark_ready();
    let resp = http_get(addr, "/readyz").await;
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "expected 200 on /readyz after mark_ready, got:\n{resp}"
    );
    assert!(
        resp.ends_with("ready\n"),
        "/readyz body mismatch (after): {resp}"
    );
}
