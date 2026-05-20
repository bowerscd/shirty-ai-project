//! Phase 5D integration tests: `yggdrasilctl chain diff` end-to-end.
//!
//! The CLI binary is exercised verbatim via `CARGO_BIN_EXE_yggdrasilctl`.
//! On the daemon side we stand up a one-shot Unix domain socket that
//! impersonates the daemon's control surface:
//!
//! 1. **Local hop** (always served): the CLI sends
//!    `Request::DerivedRules` and we reply with a canned
//!    `Response::DerivedRules` carrying the snapshot.
//! 2. **Upstream hop** (when the local snapshot's `chain.upstream`
//!    is `Some`): the CLI opens a fresh UDS connection and sends
//!    `Request::OpenChainTunnel`. We reply with
//!    `Response::ChainTunnelOpened`, then act as the tunnel
//!    terminator: read the CLI's HTTP `GET /internal/derived-rules`
//!    and write a canned HTTP/1.1 200 response carrying the
//!    upstream snapshot. (Stage B3 will collapse this onto the same
//!    `Request::DerivedRules` shape; until then the tunnel still
//!    speaks HTTP.)
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
use std::net::Shutdown;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::thread;

/// Construct the JSON body for `Response::DerivedRules { ... }`.
/// Adds the `kind` discriminant the wire enum uses.
fn derived_rules_response_json(
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
        "kind": "derived_rules",
        "predicates": preds,
        "derived_rules": [],
        "chain": chain,
    })
    .to_string()
}

/// Snapshot body without the wire discriminant — used as the HTTP
/// payload for the upstream-hop fetch (which still goes over the
/// chain tunnel as HTTP until stage B3).
fn snapshot_body_json(
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

/// Read one newline-delimited line from a UDS connection. Panics on
/// EOF before newline (the test binary should never see a half-open).
fn read_uds_line<R: Read>(stream: &mut R) -> String {
    let mut line = String::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).expect("read uds byte");
        if n == 0 {
            panic!("UDS client closed without sending a request line");
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0] as char);
    }
    line
}

/// Spawn a one-shot UDS server that impersonates the daemon for
/// `chain diff`. Always serves a `Request::DerivedRules` on the first
/// connection. When `upstream_http_body` is `Some`, additionally
/// serves a second connection carrying `Request::OpenChainTunnel` ->
/// `Response::ChainTunnelOpened` -> tunneled HTTP response with the
/// given body.
fn spawn_oneshot_uds_diff(
    socket_path: PathBuf,
    local_response_json: String,
    upstream_http_body: Option<String>,
) -> thread::JoinHandle<()> {
    let listener = UnixListener::bind(&socket_path).expect("bind UDS listener");
    thread::spawn(move || {
        // ---- Connection 1: DerivedRules ----
        let (mut stream, _peer) = listener.accept().expect("accept #1");
        let req_line = read_uds_line(&mut stream);
        assert!(
            req_line.contains("\"kind\":\"derived_rules\""),
            "expected derived_rules request on conn #1, got {req_line:?}"
        );
        let mut payload = local_response_json.into_bytes();
        payload.push(b'\n');
        stream
            .write_all(&payload)
            .expect("write DerivedRules response");
        let _ = stream.shutdown(Shutdown::Write);
        // Drain anything else the client might have sent before close.
        let _ = stream.read_to_end(&mut Vec::new());

        // ---- Connection 2: OpenChainTunnel + tunneled HTTP (if requested) ----
        if let Some(body) = upstream_http_body {
            let (mut stream, _peer) = listener.accept().expect("accept #2");
            let req_line = read_uds_line(&mut stream);
            assert!(
                req_line.contains("\"kind\":\"open_chain_tunnel\""),
                "expected open_chain_tunnel on conn #2, got {req_line:?}"
            );
            let opened = r#"{"kind":"chain_tunnel_opened","stream_id":1}"#;
            stream.write_all(opened.as_bytes()).expect("write opened");
            stream.write_all(b"\n").expect("opened newline");

            // Drain the CLI's HTTP GET sent through the tunnel.
            let mut http_req = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = stream.read(&mut buf).expect("read tunneled HTTP");
                if n == 0 {
                    break;
                }
                http_req.extend_from_slice(&buf[..n]);
                if http_req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(resp.as_bytes())
                .expect("write HTTP response through tunnel");
            let _ = stream.shutdown(Shutdown::Write);
            let _ = stream.read_to_end(&mut Vec::new());
        }
    })
}

/// Run the yggdrasilctl binary with the given args. Captures stdout
/// + stderr.
fn run_cli(socket: &PathBuf, extra_args: &[&str]) -> Output {
    let bin = env!("CARGO_BIN_EXE_yggdrasilctl");
    let mut cmd = Command::new(bin);
    cmd.arg("--socket")
        .arg(socket)
        .arg("chain")
        .arg("diff");
    for a in extra_args {
        cmd.arg(a);
    }
    cmd.output().expect("spawn yggdrasilctl")
}

const PK_LOCAL: &str = "x25519:0101010101010101010101010101010101010101010101010101010101010101";
const PK_UPSTREAM: &str = "x25519:0202020202020202020202020202020202020202020202020202020202020202";

#[test]
fn diff_single_hop_local_only_in_sync() {
    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("control.sock");
    let local_resp = derived_rules_response_json(
        PK_LOCAL,
        None, // no upstream → walk stops at hop 0
        &[("alpha", 9001, "tcp")],
        Some(7),
        Some(PK_LOCAL),
    );
    let join = spawn_oneshot_uds_diff(socket_path.clone(), local_resp, None);

    let out = run_cli(&socket_path, &[]);
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

    join.join().expect("uds thread joined");
}

#[test]
fn diff_two_hops_in_sync() {
    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("control.sock");

    let local_resp = derived_rules_response_json(
        PK_LOCAL,
        Some(PK_UPSTREAM),
        &[("alpha", 9001, "tcp"), ("beta", 9002, "udp")],
        Some(7),
        Some(PK_LOCAL),
    );
    // Upstream hop carries the SAME predicates / version / origin.
    let upstream_body = snapshot_body_json(
        PK_UPSTREAM,
        None,
        &[("alpha", 9001, "tcp"), ("beta", 9002, "udp")],
        Some(7),
        Some(PK_LOCAL),
    );
    let join = spawn_oneshot_uds_diff(
        socket_path.clone(),
        local_resp,
        Some(upstream_body),
    );

    // metrics_port is still required (used for upstream tunnel dest);
    // any port works because the test UDS forwards verbatim.
    let out = run_cli(&socket_path, &["--metrics-port", "9090"]);
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

    join.join().expect("uds thread joined");
}

#[test]
fn diff_two_hops_drift_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("control.sock");

    let local_resp = derived_rules_response_json(
        PK_LOCAL,
        Some(PK_UPSTREAM),
        &[("alpha", 9001, "tcp"), ("beta", 9002, "udp")],
        Some(7),
        Some(PK_LOCAL),
    );
    // Upstream is MISSING "beta" — drift!
    let upstream_body = snapshot_body_json(
        PK_UPSTREAM,
        None,
        &[("alpha", 9001, "tcp")],
        Some(7),
        Some(PK_LOCAL),
    );
    let join = spawn_oneshot_uds_diff(
        socket_path.clone(),
        local_resp,
        Some(upstream_body),
    );

    let out = run_cli(&socket_path, &["--metrics-port", "9090"]);
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

    join.join().expect("uds thread joined");
}

#[test]
fn diff_json_output_round_trips() {
    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("control.sock");
    let local_resp = derived_rules_response_json(
        PK_LOCAL,
        None,
        &[("alpha", 9001, "tcp")],
        Some(7),
        Some(PK_LOCAL),
    );
    let join = spawn_oneshot_uds_diff(socket_path.clone(), local_resp, None);

    // `--json` is a global flag; it must come before the `chain` subcommand
    // in clap argument order.
    let bin = env!("CARGO_BIN_EXE_yggdrasilctl");
    let out = Command::new(bin)
        .arg("--socket")
        .arg(&socket_path)
        .arg("--json")
        .arg("chain")
        .arg("diff")
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

    join.join().expect("uds thread joined");
}
