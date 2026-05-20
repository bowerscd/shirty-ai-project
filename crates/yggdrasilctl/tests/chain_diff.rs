//! Integration tests: `yggdrasilctl chain diff` end-to-end.
//!
//! The CLI binary is exercised verbatim via `CARGO_BIN_EXE_yggdrasilctl`.
//! On the daemon side we stand up a one-shot Unix domain socket that
//! impersonates the daemon's control surface:
//!
//! - The CLI sends a single `Request::ChainSummary` over UDS.
//! - The test thread accepts one connection, reads the request line,
//!   and replies with a canned `Response::ChainSummary` carrying one
//!   or more `ChainHop`s (one per chain node we want the CLI to see).
//!
//! Tests:
//!
//! 1. `diff_single_hop_local_only_in_sync` — terminal-only chain
//!    (single hop). CLI prints "in sync across 1 hop".
//! 2. `diff_two_hops_in_sync` — terminal + one upstream relay; both
//!    hops carry the same predicates / version / origin.
//! 3. `diff_two_hops_drift_detected` — upstream is missing a
//!    predicate; CLI exits non-zero with the missing predicate
//!    surfaced.
//! 4. `diff_json_output_round_trips` — `--json` flag produces a
//!    machine-parseable report.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::thread;

/// Build a single hop (the value of `Response::ChainSummary { hops: [...] }`).
fn chain_hop_json(
    hop_index: u32,
    local: &str,
    upstream: Option<&str>,
    predicates: &[(&str, u16, &str)],
    version: Option<u64>,
    origin: Option<&str>,
) -> serde_json::Value {
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
    let view = serde_json::json!({
        "predicates": preds,
        "derived_rules": [],
        "chain": chain,
    });
    serde_json::json!({
        "hop_index": hop_index,
        "mode": "relay",
        "uptime_secs": 1,
        "view": view,
    })
}

/// Construct the JSON body for `Response::ChainSummary { ... }`.
fn chain_summary_response_json(hops: Vec<serde_json::Value>, partial: bool) -> String {
    serde_json::json!({
        "kind": "chain_summary",
        "hops": hops,
        "partial": partial,
    })
    .to_string()
}

/// Read one newline-delimited line from a UDS connection.
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

/// Spawn a one-shot UDS server that impersonates the daemon: accepts
/// a single connection, asserts the CLI sent a `chain_summary`
/// request, and replies with `response_json` (newline-terminated).
fn spawn_oneshot_uds_chain_summary(
    socket_path: PathBuf,
    response_json: String,
) -> thread::JoinHandle<()> {
    let listener = UnixListener::bind(&socket_path).expect("bind UDS listener");
    thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept");
        let req_line = read_uds_line(&mut stream);
        assert!(
            req_line.contains("\"kind\":\"chain_summary\""),
            "expected chain_summary request, got {req_line:?}"
        );
        let mut payload = response_json.into_bytes();
        payload.push(b'\n');
        stream
            .write_all(&payload)
            .expect("write ChainSummary response");
        let _ = stream.shutdown(Shutdown::Write);
        let _ = stream.read_to_end(&mut Vec::new());
    })
}

/// Run the yggdrasilctl binary with the given args. Captures stdout
/// + stderr.
fn run_cli(socket: &PathBuf, extra_args: &[&str]) -> Output {
    let bin = env!("CARGO_BIN_EXE_yggdrasilctl");
    let mut cmd = Command::new(bin);
    cmd.arg("chain")
        .arg("--socket")
        .arg(socket)
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
    let resp = chain_summary_response_json(
        vec![chain_hop_json(
            0,
            PK_LOCAL,
            None,
            &[("alpha", 9001, "tcp")],
            Some(7),
            Some(PK_LOCAL),
        )],
        false,
    );
    let join = spawn_oneshot_uds_chain_summary(socket_path.clone(), resp);

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

    let resp = chain_summary_response_json(
        vec![
            chain_hop_json(
                0,
                PK_LOCAL,
                Some(PK_UPSTREAM),
                &[("alpha", 9001, "tcp"), ("beta", 9002, "udp")],
                Some(7),
                Some(PK_LOCAL),
            ),
            chain_hop_json(
                1,
                PK_UPSTREAM,
                None,
                &[("alpha", 9001, "tcp"), ("beta", 9002, "udp")],
                Some(7),
                Some(PK_LOCAL),
            ),
        ],
        false,
    );
    let join = spawn_oneshot_uds_chain_summary(socket_path.clone(), resp);

    let out = run_cli(&socket_path, &[]);
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

    let resp = chain_summary_response_json(
        vec![
            chain_hop_json(
                0,
                PK_LOCAL,
                Some(PK_UPSTREAM),
                &[("alpha", 9001, "tcp"), ("beta", 9002, "udp")],
                Some(7),
                Some(PK_LOCAL),
            ),
            // Upstream is MISSING "beta" — drift!
            chain_hop_json(
                1,
                PK_UPSTREAM,
                None,
                &[("alpha", 9001, "tcp")],
                Some(7),
                Some(PK_LOCAL),
            ),
        ],
        false,
    );
    let join = spawn_oneshot_uds_chain_summary(socket_path.clone(), resp);

    let out = run_cli(&socket_path, &[]);
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
    let resp = chain_summary_response_json(
        vec![chain_hop_json(
            0,
            PK_LOCAL,
            None,
            &[("alpha", 9001, "tcp")],
            Some(7),
            Some(PK_LOCAL),
        )],
        false,
    );
    let join = spawn_oneshot_uds_chain_summary(socket_path.clone(), resp);

    // `--json` is a global flag; `--socket` is per-scope on `chain`/`local`.
    let bin = env!("CARGO_BIN_EXE_yggdrasilctl");
    let out = Command::new(bin)
        .arg("--json")
        .arg("chain")
        .arg("--socket")
        .arg(&socket_path)
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
    assert_eq!(parsed["partial"], serde_json::Value::Bool(false));
    let hops = parsed["hops"].as_array().expect("hops is array");
    assert_eq!(hops.len(), 1, "expected one hop, got {}", hops.len());
    assert_eq!(hops[0]["index"], 0);
    assert_eq!(hops[0]["view"]["chain"]["local"], PK_LOCAL);

    join.join().expect("uds thread joined");
}
