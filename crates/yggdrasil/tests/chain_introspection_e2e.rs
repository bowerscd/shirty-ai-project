//! Phase 5B end-to-end test: a `PredicateSetUpdate` accepted by the
//! relay surfaces in the `/internal/derived-rules` HTTP snapshot.
//!
//! Wire path exercised:
//!
//! 1. Driver (acting as terminal) Noise_IK handshakes with a real
//!    `HeartbeatServer` backed by a `ChainAcceptor` + `ProxySupervisor`.
//! 2. Driver sends a `PredicateSetUpdate` envelope; server acks `Ok`.
//! 3. The introspection sink wired into the acceptor records the
//!    apply (predicates, origin, version, last_apply_unix).
//! 4. Test opens an HTTP/1.1 connection to the metrics listener and
//!    `GET`s `/internal/derived-rules`. The response body parses as
//!    JSON and contains the just-applied predicate set, the relay's
//!    chain identity, and a derived rule from the proxy supervisor.
//!
//! Also covers the non-loopback gate: a non-loopback-source request
//! cannot reach `127.0.0.1`-bound listeners in tests, so the gate is
//! exercised indirectly by the absence of a non-loopback path. The
//! gate's unit behaviour is asserted in the metrics-module tests via
//! `route(...)` with a synthetic peer.

mod common;

use std::sync::Arc;
use std::time::Duration;

use ratatoskr::auth::StaticKeyPair;
use ratatoskr::control::Mode;
use ratatoskr::control_frame::{AckStatus, ControlBodyType, ControlEnvelope};
use ratatoskr::predicate::{Predicate, PredicateSet};
use ratatoskr::pubkey::PubKey;
use ratatoskr::rule::Protocol;
use ratatoskr::wire;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use yggdrasil::chain::introspection::IntrospectionState;
use yggdrasil::chain::{ChainAcceptor, DeriveConfig};
use yggdrasil::heartbeat::{HeartbeatServer, PeerState};
use yggdrasil::pending_peers::PendingPeerStore;
use yggdrasil::proxy::resolver::ResolverFactory;
use yggdrasil::proxy::supervisor::{CertConfig, ProxySupervisor};

use common::{clone_kp, drive_handshake, pick_free_tcp_port};

/// One-shot helper that fires a single `Control` envelope and returns
/// the (decoded) `ControlAck`.
async fn send_control_and_await_ack(
    session: &mut ratatoskr::auth::Session,
    sock: &UdpSocket,
    envelope: &ControlEnvelope,
) -> ratatoskr::control_frame::ControlAck {
    let (_c, packet) = session.encode_control(envelope).expect("encode control");
    sock.send(&packet).await.expect("send control");
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf))
        .await
        .expect("ControlAck timeout")
        .expect("recv ControlAck");
    let view = wire::parse(&buf[..n]).expect("parse ControlAck");
    session
        .decode_control_ack(&view)
        .expect("decode ControlAck")
}

/// Open a fresh HTTP/1.1 connection, send `GET path`, return the raw
/// response bytes as a String. Mirrors the pattern in `tests/health.rs`.
async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
    let mut tcp = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("connect {addr}: {e}"));
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    );
    tcp.write_all(req.as_bytes()).await.expect("write request");
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut buf))
        .await
        .expect("read timeout");
    String::from_utf8_lossy(&buf).into_owned()
}

/// Split an HTTP/1.1 response into (status_line, body). Crude but
/// sufficient — we only need the status line and the body for JSON
/// parsing.
fn split_http_response(resp: &str) -> (&str, &str) {
    let status_end = resp.find("\r\n").expect("no CRLF in response");
    let status_line = &resp[..status_end];
    let body_start = resp.find("\r\n\r\n").expect("no body separator") + 4;
    (status_line, &resp[body_start..])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn predicate_set_update_surfaces_in_internal_derived_rules() {
    // 1. Crypto identities + downstream enrollment.
    let server_keys = StaticKeyPair::generate().unwrap();
    let client_keys = StaticKeyPair::generate().unwrap();
    let peer_state = PeerState::new(*client_keys.public_key());

    let pending_dir = tempfile::tempdir().unwrap();
    let pending_store =
        Arc::new(PendingPeerStore::load(pending_dir.path()).unwrap());

    // 2. Real proxy supervisor over an empty rules dir.
    let rules_dir = tempfile::tempdir().unwrap();
    let cancel = CancellationToken::new();
    let supervisor = ProxySupervisor::spawn(
        rules_dir.path().to_path_buf(),
        Duration::from_millis(50),
        ResolverFactory::new_relay(peer_state.clone()),
        Some("127.0.0.1".parse().unwrap()),
        CertConfig::default(),
        cancel.clone(),
    )
    .await
    .expect("spawn supervisor");

    // 3. Acceptor.
    let state_dir = tempfile::tempdir().unwrap();
    let derive_cfg = DeriveConfig {
        bind_addr: "127.0.0.1".parse().unwrap(),
        proxy_protocol: None,
    };
    let local_pubkey = PubKey::x25519(*server_keys.public_key());
    let upstream_pubkey = PubKey::x25519([0xAA; 32]);
    let downstream_pubkey = PubKey::x25519(*client_keys.public_key());
    let acceptor = ChainAcceptor::load(
        supervisor.handle(),
        derive_cfg,
        state_dir.path(),
        local_pubkey,
    )
    .expect("load acceptor");

    // 4. Introspection state + slot. Attach to the acceptor and to the
    //    metrics listener.
    let introspection = IntrospectionState::new(
        local_pubkey,
        Some(upstream_pubkey),
        Some(downstream_pubkey),
        supervisor.handle(),
    );
    acceptor
        .set_introspection(introspection.clone())
        .expect("set_introspection");
    let slot = yggdrasil::metrics::new_introspection_slot();
    if slot.set(introspection.clone()).is_err() {
        panic!("slot set twice");
    }
    let (metrics_addr, _handle) = yggdrasil::metrics::init(
        "127.0.0.1:0".parse().unwrap(),
        Mode::Relay,
        Some(slot.clone()),
    )
    .await
    .expect("metrics init");

    // 5. HeartbeatServer bound to a random loopback port with the acceptor.
    let hb_cancel = cancel.clone();
    let (hb, _outbound) = HeartbeatServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        clone_kp(&server_keys),
        peer_state.clone(),
        pending_store,
        Some(acceptor),
        hb_cancel,
    )
    .await
    .expect("bind server");
    let server_addr = hb.local_addr().unwrap();
    let hb_join = tokio::spawn(hb.run());

    // 6. Driver-side handshake + predicate push.
    let (mut session, sock) =
        drive_handshake(server_keys.public_key(), &client_keys, server_addr).await;

    let listen_port = pick_free_tcp_port().await;
    let origin = downstream_pubkey;
    let set = PredicateSet {
        predicates: vec![Predicate {
            name: "alpha".into(),
            listen_port,
            protocol: Protocol::Tcp,
            idle_timeout_ms: None,
        }],
        version: 1,
        origin,
    };
    let envelope = ControlEnvelope {
        seq: 1,
        body_type: ControlBodyType::PredicateSetUpdate.as_byte(),
        body: postcard::to_allocvec(&set).unwrap(),
    };
    let ack = send_control_and_await_ack(&mut session, &sock, &envelope).await;
    assert_eq!(ack.status, AckStatus::Ok);

    // 7. Wait until the supervisor has applied the derived rule. This is
    //    the same wait point as `chain_predicate_e2e.rs`; once that
    //    completes, the supervisor's `current_set` watch has fired and
    //    a future snapshot will see the new rule.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if supervisor
            .snapshot()
            .iter()
            .any(|p| p.listen.port() == listen_port)
        {
            break;
        }
        if Instant::now() >= deadline {
            panic!("supervisor never picked up the derived rule");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // 8. Fire the HTTP GET. With record_apply wired on the success
    //    branch in the acceptor, the snapshot must already reflect v=1
    //    and the predicate list.
    let raw = http_get(metrics_addr, "/internal/derived-rules").await;
    let (status, body) = split_http_response(&raw);
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "expected 200, got status line {status:?} body {body:?}"
    );
    let parsed: serde_json::Value =
        serde_json::from_str(body).expect("snapshot body parses as JSON");

    // Predicate list shape.
    let predicates = parsed["predicates"]
        .as_array()
        .expect("predicates is array");
    assert_eq!(predicates.len(), 1, "exactly one predicate applied");
    assert_eq!(predicates[0]["name"], "alpha");
    assert_eq!(predicates[0]["listen_port"], listen_port);
    assert_eq!(predicates[0]["protocol"], "tcp");

    // Derived rules surface the supervisor's current_set.
    let derived = parsed["derived_rules"]
        .as_array()
        .expect("derived_rules is array");
    assert!(
        derived.iter().any(|r| r["name"] == "alpha"),
        "derived_rules should contain the alpha rule, got: {derived:?}"
    );

    // Chain identity surfaces the configured pubkeys + applied version.
    let chain = &parsed["chain"];
    assert_eq!(chain["local"], local_pubkey.to_string());
    assert_eq!(chain["upstream"], upstream_pubkey.to_string());
    assert_eq!(chain["downstream"], downstream_pubkey.to_string());
    assert_eq!(chain["predicate_origin"], origin.to_string());
    assert_eq!(chain["predicate_version"], 1);
    assert!(
        chain["last_apply_unix"].as_i64().unwrap_or(0) > 0,
        "last_apply_unix should be a wall-clock value, got {:?}",
        chain["last_apply_unix"]
    );

    // 9. Content-Type sanity.
    assert!(
        raw.to_lowercase().contains("content-type: application/json"),
        "expected application/json content-type, got headers in: {raw}"
    );

    // 10. The index endpoint advertises the route.
    let index = http_get(metrics_addr, "/").await;
    assert!(
        index.starts_with("HTTP/1.1 200"),
        "expected 200 on /, got:\n{index}"
    );
    assert!(
        index.contains("/internal/derived-rules"),
        "index missing /internal/derived-rules listing:\n{index}"
    );

    cancel.cancel();
    supervisor.stop().await;
    let _ = hb_join.await;
    drop(rules_dir);
    drop(state_dir);
    drop(pending_dir);
}
