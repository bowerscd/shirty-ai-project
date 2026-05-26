//! Integration tests for the UDS control surface.
//!
//! Split out from the original monolithic `control.rs` (Phase B2).

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio_util::sync::CancellationToken;

use ratatoskr::control::{error_codes, Mode, Request, Response};

use crate::heartbeat::PeerState;
use crate::pending_peers::PendingPeerStore;
use crate::proxy::resolver::ResolverFactory;
use crate::proxy::supervisor::{CertConfig, ProxySupervisor};

use super::ControlServer;

async fn make_supervisor(dir: &Path) -> (ProxySupervisor, Arc<PeerState>, CancellationToken) {
    make_supervisor_with_enrolled(dir, false).await
}

/// `enrolled = true` uses a random non-zero key so
/// `peer_state.is_peer_enrolled()` returns true.
async fn make_supervisor_with_enrolled(
    dir: &Path,
    enrolled: bool,
) -> (ProxySupervisor, Arc<PeerState>, CancellationToken) {
    std::fs::create_dir_all(dir).unwrap();
    let key = if enrolled { [7u8; 32] } else { [0u8; 32] };
    let peer_state = PeerState::new(key);
    let shutdown = CancellationToken::new();
    let supervisor = ProxySupervisor::spawn(
        dir,
        Duration::from_millis(50),
        ResolverFactory::new_relay(peer_state.clone()),
        None,
        None,
        CertConfig::default(),
        None,
        shutdown.clone(),
    )
    .await
    .unwrap();
    (supervisor, peer_state, shutdown)
}

/// Build the supporting state needed by `ControlServer::bind`: a pending
/// store rooted in `dir/state` and a writable placeholder config path
/// rooted in `dir/yggdrasil.toml`.
fn aux_state(dir: &Path) -> (Arc<PendingPeerStore>, PathBuf) {
    let state_dir = dir.join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let store = Arc::new(PendingPeerStore::load(&state_dir).unwrap());
    let config_path = dir.join("yggdrasil.toml");
    // Minimal valid TOML so `update_downstream_pubkey` has something
    // to round-trip if a test ends up approving.
    std::fs::write(&config_path, "[server]\nidentity_file = \"/tmp/id.key\"\n").unwrap();
    (store, config_path)
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

/// Bind a relay-mode `ControlServer` for tests. Wraps the
/// peer-state/pending-store args in `Some(...)` so individual tests stay
/// terse. Terminal-mode tests (which want `None` for both) bind
/// directly.
async fn bind_relay_control(
    socket: PathBuf,
    peer_state: Arc<PeerState>,
    supervisor: &ProxySupervisor,
    pending: Arc<PendingPeerStore>,
    cfg: PathBuf,
    shutdown: CancellationToken,
) -> ControlServer {
    ControlServer::bind(
        socket,
        Mode::Relay,
        "test-node".to_string(),
        Some(peer_state),
        supervisor,
        Some(pending),
        cfg,
        false,
        crate::metrics::detached_handle_for_tests(),
        None,
        None,
        None,
        None,
        std::sync::Arc::new(crate::proxy::canary::CanaryArmTable::new()),
        shutdown,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn status_reports_initial_state() {
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
    let socket = tmp.path().join("control.sock");
    let (pending, cfg) = aux_state(tmp.path());

    let server = bind_relay_control(
        socket.clone(),
        peer_state.clone(),
        &supervisor,
        pending,
        cfg,
        shutdown.clone(),
    )
    .await;

    let resp = send_request(&socket, &Request::Status).await;
    match resp {
        Response::Status(s) => {
            assert_eq!(s.downstream_ip, None);
            assert_eq!(s.rule_count, 0);
            assert!(!s.downstream_enrolled);
        }
        other => panic!("unexpected response: {other:?}"),
    }
    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

#[tokio::test]
async fn status_reflects_heartbeat() {
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    let (supervisor, peer_state, shutdown) = make_supervisor_with_enrolled(&rules, true).await;
    let socket = tmp.path().join("control.sock");
    let (pending, cfg) = aux_state(tmp.path());
    let server = bind_relay_control(
        socket.clone(),
        peer_state.clone(),
        &supervisor,
        pending,
        cfg,
        shutdown.clone(),
    )
    .await;

    let ip: IpAddr = "192.0.2.5".parse().unwrap();
    peer_state.record_heartbeat(std::net::SocketAddr::new(ip, 7117));

    let resp = send_request(&socket, &Request::Status).await;
    match resp {
        Response::Status(s) => {
            assert_eq!(s.downstream_ip, Some(ip));
            assert!(s.downstream_enrolled);
            assert!(s.last_heartbeat_age_ms.is_some());
        }
        other => panic!("unexpected response: {other:?}"),
    }
    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

#[tokio::test]
async fn downstream_show_returns_pubkey_when_enrolled() {
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    let (supervisor, peer_state, shutdown) = make_supervisor_with_enrolled(&rules, true).await;
    let socket = tmp.path().join("control.sock");
    let (pending, cfg) = aux_state(tmp.path());
    let server = bind_relay_control(
        socket.clone(),
        peer_state.clone(),
        &supervisor,
        pending,
        cfg,
        shutdown.clone(),
    )
    .await;

    let resp = send_request(&socket, &Request::DownstreamShow).await;
    match resp {
        Response::Downstream(p) => {
            assert!(p.enrolled);
            // tagged form: "x25519:" + 64 hex chars = 71 chars
            assert_eq!(p.pubkey.len(), 71);
            assert!(p.pubkey.starts_with("x25519:"));
            assert_eq!(p.fingerprint.len(), 32);
        }
        other => panic!("unexpected response: {other:?}"),
    }
    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

#[tokio::test]
async fn downstream_show_returns_empty_when_not_enrolled() {
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
    let socket = tmp.path().join("control.sock");
    let (pending, cfg) = aux_state(tmp.path());
    let server = bind_relay_control(
        socket.clone(),
        peer_state.clone(),
        &supervisor,
        pending,
        cfg,
        shutdown.clone(),
    )
    .await;

    let resp = send_request(&socket, &Request::DownstreamShow).await;
    match resp {
        Response::Downstream(p) => {
            assert!(!p.enrolled);
            assert!(p.pubkey.is_empty());
            assert!(p.fingerprint.is_empty());
        }
        other => panic!("unexpected response: {other:?}"),
    }
    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

#[tokio::test]
async fn rules_reload_returns_current_count() {
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
    let socket = tmp.path().join("control.sock");
    let (pending, cfg) = aux_state(tmp.path());
    let server = bind_relay_control(
        socket.clone(),
        peer_state.clone(),
        &supervisor,
        pending,
        cfg,
        shutdown.clone(),
    )
    .await;

    let resp = send_request(&socket, &Request::RulesReload).await;
    match resp {
        Response::RulesReloaded {
            reloaded_rule_count,
        } => {
            assert_eq!(reloaded_rule_count, 0);
        }
        other => panic!("unexpected response: {other:?}"),
    }
    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

#[tokio::test]
async fn invalid_json_returns_error_response() {
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
    let socket = tmp.path().join("control.sock");
    let (pending, cfg) = aux_state(tmp.path());
    let server = bind_relay_control(
        socket.clone(),
        peer_state.clone(),
        &supervisor,
        pending,
        cfg,
        shutdown.clone(),
    )
    .await;

    let mut stream = UnixStream::connect(&socket).await.unwrap();
    stream.write_all(b"not json at all\n").await.unwrap();
    let (reader, _w) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    let line = lines.next_line().await.unwrap().unwrap();
    let resp: Response = serde_json::from_str(&line).unwrap();
    match resp {
        Response::Error { code, .. } => assert_eq!(code, error_codes::INVALID_REQUEST),
        other => panic!("unexpected response: {other:?}"),
    }
    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

#[tokio::test]
async fn peer_pending_lists_staged_candidates() {
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
    let socket = tmp.path().join("control.sock");
    let (pending, cfg) = aux_state(tmp.path());
    pending.record_candidate([0xAAu8; 32]).unwrap();
    pending.record_candidate([0xBBu8; 32]).unwrap();
    let server = bind_relay_control(
        socket.clone(),
        peer_state.clone(),
        &supervisor,
        pending,
        cfg,
        shutdown.clone(),
    )
    .await;

    let resp = send_request(&socket, &Request::DownstreamPending).await;
    match resp {
        Response::DownstreamPending(p) => {
            assert_eq!(p.candidates.len(), 2);
        }
        other => panic!("unexpected response: {other:?}"),
    }
    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

#[tokio::test]
async fn downstream_approve_writes_config_and_swaps_live_key() {
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
    let socket = tmp.path().join("control.sock");
    let (pending, cfg) = aux_state(tmp.path());

    let candidate = [0x42u8; 32];
    pending.record_candidate(candidate).unwrap();
    let fp = ratatoskr::auth::public_key_fingerprint(&candidate);

    assert!(!peer_state.is_peer_enrolled());

    let server = bind_relay_control(
        socket.clone(),
        peer_state.clone(),
        &supervisor,
        pending,
        cfg.clone(),
        shutdown.clone(),
    )
    .await;

    let resp = send_request(
        &socket,
        &Request::DownstreamApprove {
            fingerprint: fp.clone(),
        },
    )
    .await;
    match resp {
        Response::DownstreamApproved { fingerprint } => assert_eq!(fingerprint, fp),
        other => panic!("unexpected response: {other:?}"),
    }
    // Live key was swapped in.
    assert!(peer_state.is_peer_enrolled());
    assert_eq!(peer_state.peer_static_key(), candidate);
    // Config file was rewritten with the approved key in tagged form.
    let rewritten = std::fs::read_to_string(&cfg).unwrap();
    let tagged = format!("x25519:{}", hex::encode(candidate));
    assert!(
        rewritten.contains(&tagged),
        "config not rewritten with tagged pubkey: {rewritten}"
    );
    assert!(
        rewritten.contains("[accept]"),
        "config missing [accept]: {rewritten}"
    );

    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

#[tokio::test]
async fn downstream_approve_unknown_fingerprint_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
    let socket = tmp.path().join("control.sock");
    let (pending, cfg) = aux_state(tmp.path());
    let server = bind_relay_control(
        socket.clone(),
        peer_state.clone(),
        &supervisor,
        pending,
        cfg,
        shutdown.clone(),
    )
    .await;

    let resp = send_request(
        &socket,
        &Request::DownstreamApprove {
            fingerprint: "not-a-real-fingerprint".to_string(),
        },
    )
    .await;
    match resp {
        Response::Error { code, .. } => {
            assert_eq!(code, error_codes::NO_SUCH_FINGERPRINT)
        }
        other => panic!("unexpected response: {other:?}"),
    }
    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

#[tokio::test]
async fn status_reports_zero_certs_when_no_https_rules_loaded() {
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
    let socket = tmp.path().join("control.sock");
    let (pending, cfg) = aux_state(tmp.path());
    let server = bind_relay_control(
        socket.clone(),
        peer_state.clone(),
        &supervisor,
        pending,
        cfg,
        shutdown.clone(),
    )
    .await;

    let resp = send_request(&socket, &Request::Status).await;
    match resp {
        Response::Status(s) => {
            assert_eq!(s.ephemeral_cert_count, 0);
            assert!(s.default_cert_path.is_none());
            assert!(s.default_cert_loaded_age_secs.is_none());
        }
        other => panic!("unexpected response: {other:?}"),
    }

    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

/// `Request::Metrics` renders the Prometheus text exposition from the
/// installed handle. `detached_handle_for_tests` produces an empty
/// body (no recorder installed in tests); we're verifying the
/// dispatch path renders without panicking and the response shape
/// is well-formed.
#[tokio::test]
async fn metrics_endpoint_renders_prometheus_text() {
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
    let socket = tmp.path().join("control.sock");
    let (pending, cfg) = aux_state(tmp.path());
    let server = bind_relay_control(
        socket.clone(),
        peer_state.clone(),
        &supervisor,
        pending,
        cfg,
        shutdown.clone(),
    )
    .await;

    let resp = send_request(&socket, &Request::Metrics).await;
    match resp {
        Response::Metrics(m) => {
            assert!(
                m.body.is_empty() || m.body.ends_with('\n'),
                "expected empty or newline-terminated body, got: {:?}",
                m.body
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }
    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

/// `Request::Health` reports `ready = true` after `mark_ready` has
/// been called. The flag is process-global and one-way; previous
/// tests in this binary may already have flipped it, but after our
/// `mark_ready` call the contract holds unconditionally.
#[tokio::test]
async fn health_endpoint_reports_ready_after_mark_ready() {
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
    let socket = tmp.path().join("control.sock");
    let (pending, cfg) = aux_state(tmp.path());
    let server = bind_relay_control(
        socket.clone(),
        peer_state.clone(),
        &supervisor,
        pending,
        cfg,
        shutdown.clone(),
    )
    .await;

    crate::health::mark_ready();

    let resp = send_request(&socket, &Request::Health).await;
    match resp {
        Response::Health(h) => {
            assert!(h.ready, "health endpoint should report ready=true");
            // Sanity: uptime should be small; we just bound the server.
            assert!(h.uptime_secs < 3600);
        }
        other => panic!("unexpected response: {other:?}"),
    }
    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

/// `Request::DerivedRules` returns the introspection snapshot when
/// the control server has one wired. The wire path here is the
/// counterpart to `chain_introspection_e2e.rs`, which exercises
/// `IntrospectionState::snapshot()` directly without going through
/// the UDS dispatcher.
#[tokio::test]
async fn derived_rules_endpoint_returns_snapshot_when_introspection_wired() {
    use ratatoskr::pubkey::PubKey;

    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
    let socket = tmp.path().join("control.sock");
    let (pending, cfg) = aux_state(tmp.path());

    let local = PubKey::x25519([0x11; 32]);
    let introspection = crate::chain::IntrospectionState::new(
        local,
        Some(PubKey::x25519([0x22; 32])),
        None,
        supervisor.handle(),
    );

    let server = ControlServer::bind(
        socket.clone(),
        Mode::Relay,
        "test-node".to_string(),
        Some(peer_state.clone()),
        &supervisor,
        Some(pending),
        cfg,
        false,
        crate::metrics::detached_handle_for_tests(),
        Some(introspection),
        None,
        None,
        None,
        std::sync::Arc::new(crate::proxy::canary::CanaryArmTable::new()),
        shutdown.clone(),
    )
    .await
    .unwrap();

    let resp = send_request(&socket, &Request::DerivedRules).await;
    match resp {
        Response::DerivedRules(d) => {
            assert!(d.predicates.is_empty(), "no apply yet");
            assert!(d.derived_rules.is_empty(), "no rules loaded");
            assert_eq!(d.chain.local, local);
            assert!(d.chain.predicate_origin.is_none());
            assert!(d.chain.predicate_version.is_none());
            assert!(d.chain.last_apply_unix.is_none());
        }
        other => panic!("unexpected response: {other:?}"),
    }
    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

/// `Request::DerivedRules` on a server with no introspection state
/// reports `INTERNAL_ERROR` via the dispatcher's defensive arm.
/// `bind_relay_control` passes `None` for introspection, which is
/// the configuration tests want here.
#[tokio::test]
async fn derived_rules_endpoint_errors_when_introspection_absent() {
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
    let socket = tmp.path().join("control.sock");
    let (pending, cfg) = aux_state(tmp.path());
    let server = bind_relay_control(
        socket.clone(),
        peer_state.clone(),
        &supervisor,
        pending,
        cfg,
        shutdown.clone(),
    )
    .await;

    let resp = send_request(&socket, &Request::DerivedRules).await;
    match resp {
        Response::Error { code, .. } => {
            assert_eq!(code, error_codes::INTERNAL_ERROR);
        }
        other => panic!("unexpected response: {other:?}"),
    }
    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

/// `Request::TraceSet` with an invalid directive returns
/// `INVALID_REQUEST`. The dispatcher's two failure modes
/// (`EnvFilter::try_new` parse error and "tracing not initialised")
/// both land on the same error code, so this test is robust to
/// whether a sibling test has already installed the global
/// subscriber.
#[tokio::test]
async fn trace_set_with_invalid_directive_returns_invalid_request() {
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
    let socket = tmp.path().join("control.sock");
    let (pending, cfg) = aux_state(tmp.path());
    let server = bind_relay_control(
        socket.clone(),
        peer_state.clone(),
        &supervisor,
        pending,
        cfg,
        shutdown.clone(),
    )
    .await;

    // Best-effort init so `EnvFilter::try_new` is the error source.
    // If a sibling test already installed a subscriber, this call
    // returns Err but `TRACE_CONTROLLER` is already set by that
    // test — the dispatcher lands on the same INVALID_REQUEST code
    // either way.
    let _ = crate::log::init_tracing(crate::cli::LogFormat::Pretty);

    let resp = send_request(
        &socket,
        &Request::TraceSet {
            directive: Some("= not a valid filter =".to_string()),
        },
    )
    .await;
    match resp {
        Response::Error { code, message } => {
            assert_eq!(code, error_codes::INVALID_REQUEST);
            assert!(
                message.contains("tracing directive"),
                "expected directive error message, got: {message}"
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }
    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}
