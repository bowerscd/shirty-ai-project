//! Phase 5D integration tests: `yggdrasilctl chain diff` end-to-end.
//!
//! The CLI binary is exercised verbatim via `CARGO_BIN_EXE_yggdrasilctl`.
//! On the daemon side we stand up:
//!
//! * A **fake metrics listener** — a one-shot TCP server that responds
//!   to a single `GET /internal/derived-rules` with a canned JSON
//!   body. The CLI's `fetch_local_introspection` connects to this on
//!   `127.0.0.1:<picked_port>`.
//!
//! * For multi-hop tests, a **fake UDS daemon** — a one-shot Unix
//!   socket server that (a) reads a single `Request::OpenChainTunnel`
//!   line, (b) replies with `Response::ChainTunnelOpened`, then (c)
//!   acts as the tunnel terminator: reads the CLI's HTTP GET and
//!   writes a canned HTTP response. This is enough to drive the
//!   CLI's tunnel-splice path without spinning up a real two-process
//!   chain.
//!
//! Tests in this file:
//!
//! 1. `diff_single_hop_local_only_in_sync` — terminal-only chain
//!    (no upstream). CLI walks just hop 0 and reports "in sync".
//! 2. `diff_two_hops_in_sync` — terminal + one upstream relay,
//!    same predicates / version / origin on both. CLI prints both
//!    hops and reports in sync.
//! 3. `diff_two_hops_drift_detected` — terminal + upstream with a
//!    missing predicate. CLI exits non-zero with the missing predicate
//!    surfaced in the drift output.
//! 4. `diff_json_output_round_trips` — `--json` flag produces a
//!    machine-parseable report whose structure matches the human
//!    rendering.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Pick a free loopback TCP port by binding, querying, dropping.
fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    l.local_addr().expect("local_addr").port()
}

/// Spawn a one-shot TCP server on `addr` that accepts exactly one
/// connection, drains its HTTP request, and writes `body` framed in
/// a minimal HTTP/1.1 200 response. Returns a `JoinHandle` so the
/// caller can ensure the thread joined before tearing down.
fn spawn_oneshot_http(addr: SocketAddr, body: String) -> thread::JoinHandle<()> {
    let listener = TcpListener::bind(addr).expect("bind metrics listener");
    thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept");
        // Drain the request — read until we see the CRLF/CRLF sentinel.
        let mut buf = [0u8; 4096];
        let mut acc = Vec::new();
        loop {
            let n = stream.read(&mut buf).expect("read request");
            if n == 0 {
                break;
            }
            acc.extend_from_slice(&buf[..n]);
            if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(resp.as_bytes())
            .expect("write HTTP response");
        // Half-close write so the client sees EOF and proceeds.
        let _ = stream.shutdown(Shutdown::Write);
        // Optionally read until peer closes so we don't drop the socket
        // prematurely under TCP RST semantics.
        let _ = stream.read_to_end(&mut Vec::new());
    })
}

/// Spawn a one-shot UDS server at `socket_path` that:
/// 1. accepts one connection,
/// 2. reads exactly one newline-delimited JSON request (expected to
///    be `Request::OpenChainTunnel`),
/// 3. writes back a `Response::ChainTunnelOpened { stream_id: 1 }`
///    JSON line,
/// 4. then acts as the tunnel terminator: drains the CLI's HTTP GET
///    and writes the canned `body` framed as HTTP/1.1 200.
fn spawn_oneshot_uds_tunnel(
    socket_path: PathBuf,
    body: String,
) -> (thread::JoinHandle<()>, mpsc::Receiver<String>) {
    let (tx, rx) = mpsc::channel::<String>();
    let listener =
        UnixListener::bind(&socket_path).expect("bind UDS listener");
    let handle = thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept UDS");
        // Read the OpenChainTunnel line.
        let mut req_line = String::new();
        let mut byte = [0u8; 1];
        loop {
            let n = stream.read(&mut byte).expect("read request byte");
            if n == 0 {
                panic!("UDS client closed without sending a request");
            }
            if byte[0] == b'\n' {
                break;
            }
            req_line.push(byte[0] as char);
        }
        tx.send(req_line.clone()).ok();

        // Write ChainTunnelOpened.
        let resp = r#"{"kind":"chain_tunnel_opened","stream_id":1}"#;
        stream
            .write_all(resp.as_bytes())
            .expect("write tunnel opened response");
        stream.write_all(b"\n").expect("newline");

        // Now act as tunnel terminator — drain HTTP GET, write canned
        // HTTP response.
        let mut http_req = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream
                .read(&mut buf)
                .expect("read HTTP request through tunnel");
            if n == 0 {
                break;
            }
            http_req.extend_from_slice(&buf[..n]);
            if http_req.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(resp.as_bytes())
            .expect("write HTTP/200 through tunnel");
        let _ = stream.shutdown(Shutdown::Write);
        // Allow the CLI to read the response before we drop.
        let _ = stream.read_to_end(&mut Vec::new());
    });
    (handle, rx)
}

/// Construct a minimal `/internal/derived-rules` JSON snapshot.
fn snapshot_json(
    local: &str,
    upstream: Option<&str>,
    predicates: &[(&str, u16, &str)],
    version: Option<u64>,
    origin: Option<&str>,
) -> String {
    let preds: Vec<serde_json::Value> = predicates
        .iter()
        .map(|(name, port, proto)| {
            serde_json::json!({
                "name": name,
                "listen_port": port,
                "protocol": proto,
                "idle_timeout_ms": null,
            })
        })
        .collect();
    let chain = serde_json::json!({
        "local": local,
        "upstream": upstream,
        "downstream": null,
        "predicate_origin": origin,
        "predicate_version": version,
        "last_apply_unix": null,
    });
    serde_json::json!({
        "predicates": preds,
        "derived_rules": [],
        "chain": chain,
    })
    .to_string()
}

/// Run the yggdrasilctl binary with the given args. Captures stdout
/// + stderr. Caller asserts on the result.
fn run_cli(socket: &PathBuf, args: &[&str]) -> Output {
    let bin = env!("CARGO_BIN_EXE_yggdrasilctl");
    let mut cmd = Command::new(bin);
    cmd.arg("--socket")
        .arg(socket)
        .arg("chain")
        .arg("diff");
    for a in args {
        cmd.arg(a);
    }
    cmd.output().expect("spawn yggdrasilctl")
}

const PK_LOCAL: &str = "x25519:0101010101010101010101010101010101010101010101010101010101010101";
const PK_UPSTREAM: &str = "x25519:0202020202020202020202020202020202020202020202020202020202020202";

#[test]
fn diff_single_hop_local_only_in_sync() {
    let metrics_port = pick_free_port();
    let metrics_addr: SocketAddr = format!("127.0.0.1:{metrics_port}").parse().unwrap();
    let body = snapshot_json(
        PK_LOCAL,
        None, // no upstream → walk stops at hop 0
        &[("alpha", 9001, "tcp")],
        Some(7),
        Some(PK_LOCAL),
    );
    let metrics_join = spawn_oneshot_http(metrics_addr, body);

    // socket is unused for a single-hop diff because there's no
    // upstream to tunnel to, but the CLI still needs a path arg.
    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("unused.sock");
    let out = run_cli(
        &socket_path,
        &["--metrics-port", &metrics_port.to_string()],
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "CLI exit status was {:?}\nstdout: {stdout}\nstderr: {stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains("hop 0 (local "),
        "expected 'hop 0 (local ...)', got:\n{stdout}"
    );
    assert!(
        stdout.contains("predicates=1"),
        "expected predicates=1, got:\n{stdout}"
    );
    assert!(
        stdout.contains("in sync across 1 hop"),
        "expected 'in sync across 1 hop(s).', got:\n{stdout}"
    );

    metrics_join.join().expect("metrics thread joined");
}

#[test]
fn diff_two_hops_in_sync() {
    let metrics_port = pick_free_port();
    let metrics_addr: SocketAddr = format!("127.0.0.1:{metrics_port}").parse().unwrap();
    let local_body = snapshot_json(
        PK_LOCAL,
        Some(PK_UPSTREAM),
        &[("alpha", 9001, "tcp"), ("beta", 9002, "udp")],
        Some(7),
        Some(PK_LOCAL),
    );
    let metrics_join = spawn_oneshot_http(metrics_addr, local_body);

    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("control.sock");
    // Upstream hop carries the SAME predicates / version / origin.
    let upstream_body = snapshot_json(
        PK_UPSTREAM,
        None,
        &[("alpha", 9001, "tcp"), ("beta", 9002, "udp")],
        Some(7),
        Some(PK_LOCAL),
    );
    let (uds_join, _req_rx) = spawn_oneshot_uds_tunnel(socket_path.clone(), upstream_body);

    let out = run_cli(
        &socket_path,
        &["--metrics-port", &metrics_port.to_string()],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        out.status.success(),
        "expected exit 0, got {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains("hop 0 (local "),
        "expected 'hop 0 (local ...)' in:\n{stdout}"
    );
    assert!(
        stdout.contains("hop 1 (upstream "),
        "expected 'hop 1 (upstream ...)' in:\n{stdout}"
    );
    assert!(
        stdout.contains("in sync with hop 0"),
        "expected 'in sync with hop 0' in:\n{stdout}"
    );
    assert!(
        stdout.contains("in sync across 2 hop"),
        "expected 'in sync across 2 hop(s).' in:\n{stdout}"
    );

    metrics_join.join().expect("metrics thread joined");
    uds_join.join().expect("uds thread joined");
}

#[test]
fn diff_two_hops_drift_detected() {
    let metrics_port = pick_free_port();
    let metrics_addr: SocketAddr = format!("127.0.0.1:{metrics_port}").parse().unwrap();
    let local_body = snapshot_json(
        PK_LOCAL,
        Some(PK_UPSTREAM),
        &[("alpha", 9001, "tcp"), ("beta", 9002, "udp")],
        Some(7),
        Some(PK_LOCAL),
    );
    let metrics_join = spawn_oneshot_http(metrics_addr, local_body);

    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("control.sock");
    // Upstream is MISSING "beta" — drift!
    let upstream_body = snapshot_json(
        PK_UPSTREAM,
        None,
        &[("alpha", 9001, "tcp")],
        Some(7),
        Some(PK_LOCAL),
    );
    let (uds_join, _req_rx) = spawn_oneshot_uds_tunnel(socket_path.clone(), upstream_body);

    let out = run_cli(
        &socket_path,
        &["--metrics-port", &metrics_port.to_string()],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit 1 on drift, got {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains("DRIFT vs hop 0"),
        "expected 'DRIFT vs hop 0' in:\n{stdout}"
    );
    assert!(
        stdout.contains("beta") && stdout.contains("missing upstream"),
        "expected beta to be flagged as missing upstream, got:\n{stdout}"
    );
    assert!(
        stdout.contains("DRIFT detected"),
        "expected closing 'DRIFT detected' summary in:\n{stdout}"
    );

    metrics_join.join().expect("metrics thread joined");
    uds_join.join().expect("uds thread joined");
}

#[test]
fn diff_json_output_round_trips() {
    let metrics_port = pick_free_port();
    let metrics_addr: SocketAddr = format!("127.0.0.1:{metrics_port}").parse().unwrap();
    let body = snapshot_json(
        PK_LOCAL,
        None,
        &[("alpha", 9001, "tcp")],
        Some(7),
        Some(PK_LOCAL),
    );
    let metrics_join = spawn_oneshot_http(metrics_addr, body);

    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("unused.sock");
    // `--json` is a global flag; it must come before the `chain` subcommand
    // in clap argument order.
    let bin = env!("CARGO_BIN_EXE_yggdrasilctl");
    let out = Command::new(bin)
        .arg("--socket")
        .arg(&socket_path)
        .arg("--json")
        .arg("chain")
        .arg("diff")
        .arg("--metrics-port")
        .arg(metrics_port.to_string())
        .output()
        .expect("spawn yggdrasilctl");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "CLI exit status was {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status.code()
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!("stdout was not valid JSON: {e}\nstdout was:\n{stdout}")
        });
    assert_eq!(parsed["drift_detected"], serde_json::Value::Bool(false));
    let hops = parsed["hops"].as_array().expect("hops is array");
    assert_eq!(hops.len(), 1, "expected one hop, got {}", hops.len());
    assert_eq!(hops[0]["index"], 0);
    assert_eq!(hops[0]["view"]["chain"]["local"], PK_LOCAL);

    metrics_join.join().expect("metrics thread joined");
}

// `_` to mark TcpStream / UnixStream unused so the file still compiles
// with these imports when a test below references neither. Suppresses
// an unused-import warning if someone refactors later.
#[allow(dead_code)]
fn _unused_imports(_: TcpStream, _: UnixStream, _: Duration) {}
