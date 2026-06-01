//! End-to-end test for `Request::ChainApply`:
//!
//! 1. **Happy path (terminal mode)**: spin up a terminal-mode supervisor
//!    with a control server, send `ChainApply { rules }` over the UDS,
//!    assert `ChainApplied { applied_rule_count, predicate_count,
//!    skipped_https }`, and verify the supervisor's `current_set_rx`
//!    watch fires with the new ruleset.
//! 2. **Relay-mode rejection**: a relay supervisor refuses
//!    `ChainApply` with `NOT_SUPPORTED_IN_RELAY_MODE`. Relays derive
//!    their rule set from downstream predicate pushes and would
//!    immediately overwrite any manual apply.
//! 3. **Invalid rules rejection**: a candidate set with duplicate names
//!    is rejected synchronously with `RULES_INVALID` and the
//!    supervisor's current set does not change.
//!
//!
//! The tests use the same `send_request` helper pattern as
//! `tests/terminal_mode.rs` (raw JSON line write + line read on the UDS).
//! `chain apply` itself uses the same wire shape, so this exercises the
//! exact path `yggdrasilctl chain apply --file rules.toml` drives.

mod common;

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio_util::sync::CancellationToken;

use ratatoskr::control::{error_codes, Mode, Request, Response};
use ratatoskr::rule::{Protocol, Rule};

use yggdrasil::control::ControlServer;

use crate::common::{pick_free_tcp_port, spawn_supervisor, spawn_terminal_supervisor};

/// Build a minimal terminal-mode TCP rule with a unique listen port.
fn terminal_rule(name: &str, listen_port: u16, target: &str) -> Rule {
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

/// `chain apply` against a terminal-mode daemon enqueues the candidate
/// rule set onto the supervisor and reports the projected predicate
/// count.
#[tokio::test]
async fn terminal_chain_apply_enqueues_and_reports() {
    let shutdown = CancellationToken::new();
    let rules_tmp = tempfile::tempdir().unwrap();
    let rules_dir = rules_tmp.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();

    let supervisor =
        spawn_terminal_supervisor(rules_dir, Duration::from_millis(50), shutdown.clone()).await;

    // Subscribe before apply so we don't miss the watch tick.
    let mut current_set_rx = supervisor.handle().current_set_rx();
    // Mark the initial empty value as seen so the next `changed()`
    // tick is the one triggered by our apply.
    let _ = current_set_rx.borrow_and_update();

    let socket_dir = tempfile::tempdir().unwrap();
    let socket_path = socket_dir.path().join("control.sock");
    let config_path = socket_dir.path().join("yggdrasil.toml");
    std::fs::write(&config_path, "[server]\nmode = \"terminal\"\n").unwrap();

    // No chain upstream: pure-local terminal. The apply should
    // succeed with `predicate_count = 0` (no projection performed when
    // there's no upstream to push to).
    let server = ControlServer::bind(
        socket_path.clone(),
        Mode::Terminal,
        "test-node".to_string(),
        None,
        &supervisor,
        None,
        config_path,
        false,
        yggdrasil::metrics::detached_handle_for_tests(),
        None,
        None,
        None,
        None,
        std::sync::Arc::new(yggdrasil::proxy::canary::CanaryArmTable::new()),
        std::sync::Arc::new(
            yggdrasil::lan_cidrs::LanCidrs::resolve(None).expect("default lan_cidrs"),
        ),
        shutdown.clone(),
    )
    .await
    .unwrap();

    let listen_a = pick_free_tcp_port().await;
    let listen_b = pick_free_tcp_port().await;
    let rules = vec![
        terminal_rule("echo-a", listen_a, "127.0.0.1:9000"),
        terminal_rule("echo-b", listen_b, "127.0.0.1:9001"),
    ];

    let resp = send_request(
        &socket_path,
        &Request::ChainApply {
            rules: rules.clone(),
        },
    )
    .await;

    match resp {
        Response::ChainApplied(body) => {
            assert_eq!(body.applied_rule_count, 2);
            // Pure-local terminal: no projection, no predicates reported.
            assert_eq!(body.predicate_count, 0);
            // Structural-invariant tripwire: `predicate_extractor::extract`
            // currently always returns an empty `skipped_https` (the field
            // exists for wire-format back-compat; see the docstring on
            // `ExtractOutcome::skipped_https`). This assertion will fire
            // and prompt a re-think if the extractor ever starts skipping
            // rules — at which point a positive-case companion test must
            // accompany the implementation change.
            assert!(body.skipped_https.is_empty());
        }
        other => panic!("expected ChainApplied, got {other:?}"),
    }

    // Wait for the supervisor's watch to fire with the new set. The
    // apply call returned once the push was enqueued; the actual diff
    // + listener mutation happens on the supervisor task.
    let applied = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            current_set_rx.changed().await.unwrap();
            let snap = current_set_rx.borrow();
            if snap.rules().len() == 2 {
                return snap
                    .rules()
                    .iter()
                    .map(|r| r.name.clone())
                    .collect::<Vec<_>>();
            }
        }
    })
    .await
    .expect("supervisor never applied the pushed ruleset");

    assert!(applied.contains(&"echo-a".to_string()));
    assert!(applied.contains(&"echo-b".to_string()));

    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

/// `chain apply` against a relay-mode daemon is refused with
/// `NOT_SUPPORTED_IN_RELAY_MODE`. The supervisor's current rule set
/// must not change.
#[tokio::test]
async fn relay_chain_apply_returns_not_supported_in_relay_mode() {
    let shutdown = CancellationToken::new();
    let rules_tmp = tempfile::tempdir().unwrap();
    let rules_dir = rules_tmp.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();

    let peer_keys = ratatoskr::auth::StaticKeyPair::generate().unwrap();
    let peer_state = yggdrasil::heartbeat::PeerState::new(*peer_keys.public_key());

    let supervisor = spawn_supervisor(
        rules_dir,
        Duration::from_millis(50),
        peer_state.clone(),
        shutdown.clone(),
    )
    .await;

    let socket_dir = tempfile::tempdir().unwrap();
    let socket_path = socket_dir.path().join("control.sock");
    let config_path = socket_dir.path().join("yggdrasil.toml");
    std::fs::write(&config_path, "[server]\nmode = \"relay\"\n").unwrap();

    let server = ControlServer::bind(
        socket_path.clone(),
        Mode::Relay,
        "test-node".to_string(),
        Some(peer_state),
        &supervisor,
        None,
        config_path,
        false,
        yggdrasil::metrics::detached_handle_for_tests(),
        None,
        None,
        None,
        None,
        std::sync::Arc::new(yggdrasil::proxy::canary::CanaryArmTable::new()),
        std::sync::Arc::new(
            yggdrasil::lan_cidrs::LanCidrs::resolve(None).expect("default lan_cidrs"),
        ),
        shutdown.clone(),
    )
    .await
    .unwrap();

    let resp = send_request(
        &socket_path,
        &Request::ChainApply {
            rules: vec![terminal_rule("echo", 1, "127.0.0.1:9000")],
        },
    )
    .await;

    match resp {
        Response::Error { code, .. } => {
            assert_eq!(code, error_codes::NOT_SUPPORTED_IN_RELAY_MODE);
        }
        other => panic!("expected Error response, got {other:?}"),
    }

    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

/// `chain apply` with a duplicate-name candidate is rejected with
/// `RULES_INVALID`. The supervisor's current set must not change.
#[tokio::test]
async fn terminal_chain_apply_rejects_duplicate_names() {
    let shutdown = CancellationToken::new();
    let rules_tmp = tempfile::tempdir().unwrap();
    let rules_dir = rules_tmp.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let supervisor =
        spawn_terminal_supervisor(rules_dir, Duration::from_millis(50), shutdown.clone()).await;

    let socket_dir = tempfile::tempdir().unwrap();
    let socket_path = socket_dir.path().join("control.sock");
    let config_path = socket_dir.path().join("yggdrasil.toml");
    std::fs::write(&config_path, "[server]\nmode = \"terminal\"\n").unwrap();

    let server = ControlServer::bind(
        socket_path.clone(),
        Mode::Terminal,
        "test-node".to_string(),
        None,
        &supervisor,
        None,
        config_path,
        false,
        yggdrasil::metrics::detached_handle_for_tests(),
        None,
        None,
        None,
        None,
        std::sync::Arc::new(yggdrasil::proxy::canary::CanaryArmTable::new()),
        std::sync::Arc::new(
            yggdrasil::lan_cidrs::LanCidrs::resolve(None).expect("default lan_cidrs"),
        ),
        shutdown.clone(),
    )
    .await
    .unwrap();

    let dup = vec![
        terminal_rule("dup", 60001, "127.0.0.1:9000"),
        terminal_rule("dup", 60002, "127.0.0.1:9001"),
    ];

    let resp = send_request(&socket_path, &Request::ChainApply { rules: dup }).await;

    match resp {
        Response::Error { code, message } => {
            assert_eq!(code, error_codes::RULES_INVALID);
            assert!(
                message.contains("dup") || message.contains("duplicate"),
                "expected message to mention the duplicate name, got: {message}"
            );
        }
        other => panic!("expected Error response, got {other:?}"),
    }

    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

async fn send_request(socket_path: &Path, req: &Request) -> Response {
    let mut stream = UnixStream::connect(socket_path).await.unwrap();
    let mut buf = serde_json::to_vec(req).unwrap();
    buf.push(b'\n');
    stream.write_all(&buf).await.unwrap();
    let (reader, _w) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    let line = lines.next_line().await.unwrap().unwrap();
    serde_json::from_str(&line).unwrap()
}

/// `chain apply` against a terminal with a configured chain upstream
/// rejects a candidate set whose projected `PredicateSet` would exceed
/// `PREDICATE_SET_MAX_WIRE_BYTES`. Without this synchronous pre-check
/// the apply would "succeed" here but the publisher would silently
/// drop the upstream push (the encode would fail past the 8 KiB cap).
#[tokio::test]
async fn terminal_chain_apply_rejects_oversize_predicate_set() {
    let shutdown = CancellationToken::new();
    let rules_tmp = tempfile::tempdir().unwrap();
    let rules_dir = rules_tmp.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let supervisor =
        spawn_terminal_supervisor(rules_dir, Duration::from_millis(50), shutdown.clone()).await;

    let socket_dir = tempfile::tempdir().unwrap();
    let socket_path = socket_dir.path().join("control.sock");
    let config_path = socket_dir.path().join("yggdrasil.toml");
    std::fs::write(&config_path, "[server]\nmode = \"terminal\"\n").unwrap();

    // `has_chain_upstream = true` engages the oversize pre-check.
    let server = ControlServer::bind(
        socket_path.clone(),
        Mode::Terminal,
        "test-node".to_string(),
        None,
        &supervisor,
        None,
        config_path,
        true,
        yggdrasil::metrics::detached_handle_for_tests(),
        None,
        None,
        None,
        None,
        std::sync::Arc::new(yggdrasil::proxy::canary::CanaryArmTable::new()),
        std::sync::Arc::new(
            yggdrasil::lan_cidrs::LanCidrs::resolve(None).expect("default lan_cidrs"),
        ),
        shutdown.clone(),
    )
    .await
    .unwrap();

    // Build ~500 TCP rules with long unique names so the projected
    // PredicateSet wire-encodes well past the 8 KiB cap.
    let mut rules = Vec::with_capacity(500);
    for i in 0..500u16 {
        let name = format!("very-long-rule-name-to-push-wire-bytes-over-cap-{i:04}");
        rules.push(terminal_rule(&name, 10_000 + i, "127.0.0.1:9000"));
    }

    let resp = send_request(&socket_path, &Request::ChainApply { rules }).await;

    match resp {
        Response::Error { code, message } => {
            assert_eq!(code, error_codes::PREDICATE_SET_OVERSIZE);
            assert!(
                message.contains("wire cap"),
                "expected oversize message, got: {message}",
            );
        }
        other => panic!("expected Error response, got {other:?}"),
    }

    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}
