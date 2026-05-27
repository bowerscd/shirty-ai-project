//! End-to-end integration tests for `Request::ChainCanary`.
//!
//! Spins up a terminal-mode supervisor with a TCP and a UDP rule whose
//! `target` deliberately points at an unreachable backend, then
//! invokes `Request::ChainCanary` over the UDS. With the canary
//! arm-table shared between the supervisor and the control server,
//! the probe traffic prefixed with the random arming token is
//! intercepted at the rule's listener and echoed in-process — so the
//! probe succeeds even though the configured backend is unreachable.
//!
//! Coverage:
//! * Happy path TCP — `CanaryStatus::Ok`, non-zero `c_to_s.sent`.
//! * Happy path UDP — `CanaryStatus::Ok`, non-zero `c_to_s.sent` and
//!   `c_to_s.received`.
//! * `NO_SUCH_RULE` with close-match suggestions.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio_util::sync::CancellationToken;

use ratatoskr::control::{CanaryStatus, Mode, Request, Response};
use ratatoskr::rule::{Protocol, Rule};

use yggdrasil::control::ControlServer;
use yggdrasil::proxy::canary::CanaryArmTable;
use yggdrasil::proxy::certs::CertStore;
use yggdrasil::proxy::resolver::ResolverFactory;
use yggdrasil::proxy::supervisor::{CertConfig, ProxySupervisor};

use crate::common::pick_free_tcp_port;

/// Spawn a terminal-mode supervisor sharing the same `Arc<CanaryArmTable>`
/// that we hand to the control server, so arms installed by the canary
/// handler reach the rule listeners.
async fn spawn_terminal_with_arm_table(
    rules_dir: PathBuf,
    arm_table: Arc<CanaryArmTable>,
    shutdown: CancellationToken,
) -> ProxySupervisor {
    ProxySupervisor::spawn_with_cert_store(
        rules_dir,
        Duration::from_millis(50),
        ResolverFactory::new_terminal(),
        None,
        None,
        CertConfig::default(),
        Arc::new(CertStore::new()),
        None,
        arm_table,
        shutdown,
    )
    .await
    .unwrap()
}

/// Bind a UDS control server with the supplied arm-table shared with
/// the supervisor.
async fn bind_control(
    socket_path: PathBuf,
    supervisor: &ProxySupervisor,
    arm_table: Arc<CanaryArmTable>,
    config_path: PathBuf,
    shutdown: CancellationToken,
) -> ControlServer {
    ControlServer::bind(
        socket_path,
        Mode::Terminal,
        "terminal-node".to_string(),
        None,
        supervisor,
        None,
        config_path,
        false,
        yggdrasil::metrics::detached_handle_for_tests(),
        None,
        None,
        None,
        None,
        arm_table,
        Arc::new(yggdrasil::lan_cidrs::LanCidrs::resolve(None).expect("default lan_cidrs")),
        shutdown,
    )
    .await
    .unwrap()
}

async fn send_request(socket_path: &Path, req: &Request) -> Response {
    let mut stream = UnixStream::connect(socket_path).await.unwrap();
    let mut buf = serde_json::to_vec(req).unwrap();
    buf.push(b'\n');
    stream.write_all(&buf).await.unwrap();
    let (reader, _w) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    let line = tokio::time::timeout(Duration::from_secs(15), lines.next_line())
        .await
        .expect("response timed out")
        .unwrap()
        .unwrap();
    serde_json::from_str(&line).unwrap()
}

fn terminal_tcp_rule(name: &str, listen_port: u16, target: &str) -> Rule {
    Rule {
        name: name.into(),
        listen: format!("127.0.0.1:{listen_port}").parse().unwrap(),
        protocol: Protocol::Tcp,
        target_port: None,
        target: Some(target.to_string()),
        idle_timeout: None,
        proxy_protocol: None,
    }
}

fn terminal_udp_rule(name: &str, listen_port: u16, target: &str) -> Rule {
    Rule {
        name: name.into(),
        listen: format!("127.0.0.1:{listen_port}").parse().unwrap(),
        protocol: Protocol::Udp,
        target_port: None,
        target: Some(target.to_string()),
        idle_timeout: None,
        proxy_protocol: None,
    }
}

/// `chain canary` over a TCP rule pointing at an unreachable backend
/// still succeeds, because the canary's arming-token-prefixed probe
/// is short-circuited to an in-process echo at the rule's listener.
/// Exercises the full UDS → handler → arm-fanout → probe-driver path.
#[tokio::test]
async fn tcp_canary_ok_against_unreachable_backend() {
    let shutdown = CancellationToken::new();
    let rules_tmp = tempfile::tempdir().unwrap();
    let rules_dir = rules_tmp.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();

    let arm_table = Arc::new(CanaryArmTable::new());
    let supervisor =
        spawn_terminal_with_arm_table(rules_dir.clone(), Arc::clone(&arm_table), shutdown.clone())
            .await;

    // Push a TCP rule via the supervisor's external apply channel
    // (avoids needing a hot-reload trigger). target is
    // 127.0.0.1:1 (privileged unreachable port).
    let listen_port = pick_free_tcp_port().await;
    let rule = terminal_tcp_rule("tcp-canary", listen_port, "127.0.0.1:1");
    let ruleset = ratatoskr::rule::RuleSet::from_rules(vec![rule.clone()]).unwrap();
    supervisor.handle().apply_ruleset(ruleset).await.unwrap();
    // Wait briefly for the supervisor to bind the listener.
    let mut tries = 0;
    while supervisor.snapshot_receiver().borrow().is_empty() && tries < 50 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        tries += 1;
    }
    assert!(
        !supervisor.snapshot_receiver().borrow().is_empty(),
        "supervisor never bound the test rule"
    );

    let socket_dir = tempfile::tempdir().unwrap();
    let socket_path = socket_dir.path().join("control.sock");
    let config_path = socket_dir.path().join("yggdrasil.toml");
    std::fs::write(&config_path, "[server]\n").unwrap();
    let server = bind_control(
        socket_path.clone(),
        &supervisor,
        Arc::clone(&arm_table),
        config_path,
        shutdown.clone(),
    )
    .await;

    let resp = send_request(
        &socket_path,
        &Request::ChainCanary {
            rule_listen: rule.listen,
            rule_protocol: Protocol::Tcp,
            duration_ms: 500,
            rate: 0,
            payload_bytes: 0,
            timeout_ms: Some(2_000),
        },
    )
    .await;

    match resp {
        Response::ChainCanary(c) => {
            assert_eq!(c.status, CanaryStatus::Ok, "canary status: {c:?}");
            assert_eq!(c.rule_name.as_deref(), Some("tcp-canary"));
            assert_eq!(c.chain.len(), 1);
            assert!(c.chain[0].rule_present);
            assert!(c.chain[0].echo_armed);
            let p = c.probe_results.expect("probe results");
            assert!(p.c_to_s.sent > 0, "expected non-zero send count: {p:?}");
            assert!(p.connection_rtt_micros.is_some());
        }
        other => panic!("unexpected response: {other:?}"),
    }

    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

/// Same shape for a UDP rule. Validates the UDP intercept path
/// (token-prefixed datagram echo back to source).
#[tokio::test]
async fn udp_canary_ok_against_unreachable_backend() {
    let shutdown = CancellationToken::new();
    let rules_tmp = tempfile::tempdir().unwrap();
    let rules_dir = rules_tmp.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();

    let arm_table = Arc::new(CanaryArmTable::new());
    let supervisor =
        spawn_terminal_with_arm_table(rules_dir.clone(), Arc::clone(&arm_table), shutdown.clone())
            .await;

    let listen_port = pick_free_tcp_port().await; // any free port works for UDP too
    let rule = terminal_udp_rule("udp-canary", listen_port, "127.0.0.1:1");
    let ruleset = ratatoskr::rule::RuleSet::from_rules(vec![rule.clone()]).unwrap();
    supervisor.handle().apply_ruleset(ruleset).await.unwrap();
    let mut tries = 0;
    while supervisor.snapshot_receiver().borrow().is_empty() && tries < 50 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        tries += 1;
    }
    assert!(!supervisor.snapshot_receiver().borrow().is_empty());

    let socket_dir = tempfile::tempdir().unwrap();
    let socket_path = socket_dir.path().join("control.sock");
    let config_path = socket_dir.path().join("yggdrasil.toml");
    std::fs::write(&config_path, "[server]\n").unwrap();
    let server = bind_control(
        socket_path.clone(),
        &supervisor,
        Arc::clone(&arm_table),
        config_path,
        shutdown.clone(),
    )
    .await;

    let resp = send_request(
        &socket_path,
        &Request::ChainCanary {
            rule_listen: rule.listen,
            rule_protocol: Protocol::Udp,
            duration_ms: 500,
            rate: 0,
            payload_bytes: 0,
            timeout_ms: Some(2_000),
        },
    )
    .await;

    match resp {
        Response::ChainCanary(c) => {
            assert_eq!(c.status, CanaryStatus::Ok, "canary status: {c:?}");
            assert_eq!(c.rule_name.as_deref(), Some("udp-canary"));
            let p = c.probe_results.expect("probe results");
            assert!(p.c_to_s.sent > 0, "expected non-zero send: {p:?}");
            assert!(p.c_to_s.received > 0, "expected non-zero echo: {p:?}");
            assert!(p.connection_rtt_micros.is_none(), "UDP has no connect RTT");
        }
        other => panic!("unexpected response: {other:?}"),
    }

    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

/// Canary against a port no rule binds returns `NoSuchRule` plus a
/// `close_matches` list ordered by relevance: same-port-different-proto
/// > different-port-same-proto > everything else.
#[tokio::test]
async fn canary_no_such_rule_reports_close_matches() {
    let shutdown = CancellationToken::new();
    let rules_tmp = tempfile::tempdir().unwrap();
    let rules_dir = rules_tmp.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();

    let arm_table = Arc::new(CanaryArmTable::new());
    let supervisor =
        spawn_terminal_with_arm_table(rules_dir.clone(), Arc::clone(&arm_table), shutdown.clone())
            .await;

    // Install three rules:
    //   tcp-other-port: TCP, port X (different port, same proto)
    //   udp-same-port:  UDP, port Y (same port as query, different proto)
    //   tcp-unrelated:  TCP, port Z (different port, same proto)
    let port_x = pick_free_tcp_port().await;
    let port_y = pick_free_tcp_port().await;
    let port_z = pick_free_tcp_port().await;
    let rules = vec![
        terminal_tcp_rule("tcp-other-port", port_x, "127.0.0.1:1"),
        terminal_udp_rule("udp-same-port", port_y, "127.0.0.1:1"),
        terminal_tcp_rule("tcp-unrelated", port_z, "127.0.0.1:1"),
    ];
    let ruleset = ratatoskr::rule::RuleSet::from_rules(rules).unwrap();
    supervisor.handle().apply_ruleset(ruleset).await.unwrap();
    let mut tries = 0;
    while supervisor.snapshot_receiver().borrow().len() < 3 && tries < 50 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        tries += 1;
    }
    assert_eq!(supervisor.snapshot_receiver().borrow().len(), 3);

    let socket_dir = tempfile::tempdir().unwrap();
    let socket_path = socket_dir.path().join("control.sock");
    let config_path = socket_dir.path().join("yggdrasil.toml");
    std::fs::write(&config_path, "[server]\n").unwrap();
    let server = bind_control(
        socket_path.clone(),
        &supervisor,
        Arc::clone(&arm_table),
        config_path,
        shutdown.clone(),
    )
    .await;

    // Query for TCP on port_y — no rule binds (port_y, TCP) but a UDP
    // rule does. close_matches should rank the UDP rule on the same
    // port first.
    let target_listen: std::net::SocketAddr = format!("127.0.0.1:{port_y}").parse().unwrap();
    let resp = send_request(
        &socket_path,
        &Request::ChainCanary {
            rule_listen: target_listen,
            rule_protocol: Protocol::Tcp,
            duration_ms: 100,
            rate: 0,
            payload_bytes: 0,
            timeout_ms: Some(1_000),
        },
    )
    .await;

    match resp {
        Response::ChainCanary(c) => {
            assert_eq!(c.status, CanaryStatus::NoSuchRule);
            assert!(c.rule_name.is_none());
            assert!(c.probe_results.is_none());
            assert!(!c.close_matches.is_empty(), "expected close-matches: {c:?}");
            // First match must be the UDP rule on the same port.
            let first = &c.close_matches[0];
            assert_eq!(first.protocol, Protocol::Udp);
            assert_eq!(first.listen.port(), port_y);
            assert_eq!(first.rule_name, "udp-same-port");
        }
        other => panic!("unexpected response: {other:?}"),
    }

    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}
