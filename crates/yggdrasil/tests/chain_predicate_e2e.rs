//! Phase 3C end-to-end test: terminal → relay PredicateSet push lands as
//! a derived RuleSet in the relay's proxy supervisor.
//!
//! Wire path exercised:
//!
//! 1. Driver (acting as terminal) Noise_IK handshakes with a real
//!    `HeartbeatServer` configured with a `ChainAcceptor` backed by a
//!    real `ProxySupervisor`.
//! 2. Driver postcard-encodes a `PredicateSet { version=1, … }` into a
//!    `ControlEnvelope { body_type = PredicateSetUpdate, … }` and sends
//!    the resulting `Control` packet.
//! 3. Server decrypts, dedup-classifies, decodes the body, runs the
//!    derive projection, hands the derived `RuleSet` to the supervisor,
//!    persists the per-origin version, and acks `Ok` over `ControlAck`.
//! 4. Test asserts:
//!    * Ack is `Ok`.
//!    * Supervisor's snapshot now contains a proxy bound on the
//!      predicate's `listen_port`.
//!    * `chain-predicates.toml` on disk records the accepted version.
//!    * A second push at a stale version is rejected with
//!      `VERSION_STALE`.

mod common;

use std::sync::Arc;
use std::time::Duration;

use ratatoskr::auth::StaticKeyPair;
use ratatoskr::control_frame::{AckStatus, ControlBodyType, ControlEnvelope};
use ratatoskr::predicate::{predicate_reject, Predicate, PredicateSet};
use ratatoskr::pubkey::PubKey;
use ratatoskr::rule::Protocol;
use ratatoskr::wire;
use tokio::net::UdpSocket;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

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

#[tokio::test]
async fn predicate_set_update_e2e_applies_to_supervisor() {
    // 1. Crypto identities + downstream enrollment.
    let server_keys = StaticKeyPair::generate().unwrap();
    let client_keys = StaticKeyPair::generate().unwrap();
    let peer_state = PeerState::new(*client_keys.public_key());

    let pending_dir = tempfile::tempdir().unwrap();
    let pending_store = Arc::new(PendingPeerStore::load(pending_dir.path()).unwrap());

    // 2. Real proxy supervisor over an empty rules dir.
    let rules_dir = tempfile::tempdir().unwrap();
    let cancel = CancellationToken::new();
    let supervisor = ProxySupervisor::spawn(
        rules_dir.path().to_path_buf(),
        Duration::from_millis(50),
        ResolverFactory::new_relay(peer_state.clone()),
        Some("127.0.0.1".parse().unwrap()),
        None,
        CertConfig::default(),
        cancel.clone(),
    )
    .await
    .expect("spawn supervisor");

    // 3. ChainAcceptor backed by the supervisor + an empty state dir.
    let state_dir = tempfile::tempdir().unwrap();
    let derive_cfg = DeriveConfig {
        bind_addr: "127.0.0.1".parse().unwrap(),
        proxy_protocol: None,
    };
    let acceptor = ChainAcceptor::load(supervisor.handle(), derive_cfg, state_dir.path())
        .expect("load acceptor");

    // 4. HeartbeatServer bound to a random loopback port with the acceptor.
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

    // 5. Driver-side handshake.
    let (mut session, sock) =
        drive_handshake(server_keys.public_key(), &client_keys, server_addr).await;

    // 6. Pick a free port for the (derived) listener and send the push.
    let listen_port = pick_free_tcp_port().await;
    let origin = PubKey::x25519(*client_keys.public_key());
    let set = PredicateSet {
        predicates: vec![Predicate {
            name: "alpha".into(),
            listen_port,
            protocol: Protocol::Tcp,
            idle_timeout_ms: None,
            https_http3: false,
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
    assert_eq!(ack.seq, 1);
    assert_eq!(ack.status, AckStatus::Ok, "expected ack Ok");

    // 7. The supervisor should pick up the derived rule and bind a proxy
    //    on `listen_port`. We poll the snapshot.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let snap = supervisor.snapshot();
        if let Some(p) = snap.iter().find(|p| p.listen.port() == listen_port) {
            assert_eq!(
                p.listen.ip().to_string(),
                "127.0.0.1",
                "derived listener bound on configured derive bind_addr"
            );
            break;
        }
        if Instant::now() >= deadline {
            panic!(
                "supervisor never picked up the derived listener on port {listen_port}; \
                 snapshot has {} proxies",
                snap.len()
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // 8. Stale push at version 1 should be rejected. Re-handshake to get
    //    a fresh seq space, then send.
    let stale = PredicateSet {
        predicates: vec![Predicate {
            name: "alpha".into(),
            listen_port,
            protocol: Protocol::Tcp,
            idle_timeout_ms: None,
            https_http3: false,
        }],
        version: 1,
        origin,
    };
    let envelope = ControlEnvelope {
        seq: 2,
        body_type: ControlBodyType::PredicateSetUpdate.as_byte(),
        body: postcard::to_allocvec(&stale).unwrap(),
    };
    let ack = send_control_and_await_ack(&mut session, &sock, &envelope).await;
    assert_eq!(ack.seq, 2);
    assert_eq!(
        ack.status,
        AckStatus::Reject(predicate_reject::VERSION_STALE),
        "second push at v=1 should be stale"
    );

    // 9. State file on disk reflects the accepted version.
    let persisted = std::fs::read_to_string(state_dir.path().join("chain-predicates.toml"))
        .expect("state file");
    assert!(
        persisted.contains("version = 1"),
        "persisted state should record v=1, got: {persisted}"
    );
    assert!(
        persisted.contains(&origin.to_string()),
        "persisted state should record origin pubkey, got: {persisted}"
    );

    cancel.cancel();
    supervisor.stop().await;
    let _ = hb_join.await;
    drop(rules_dir);
    drop(state_dir);
    drop(pending_dir);
}

#[tokio::test]
async fn unknown_body_type_acks_unknown_over_wire() {
    // Same setup as the e2e test but with a bogus body type. Tests the
    // dispatch path returns `AckStatus::Unknown` end-to-end.
    let server_keys = StaticKeyPair::generate().unwrap();
    let client_keys = StaticKeyPair::generate().unwrap();
    let peer_state = PeerState::new(*client_keys.public_key());
    let pending_dir = tempfile::tempdir().unwrap();
    let pending_store = Arc::new(PendingPeerStore::load(pending_dir.path()).unwrap());

    let rules_dir = tempfile::tempdir().unwrap();
    let cancel = CancellationToken::new();
    let supervisor = ProxySupervisor::spawn(
        rules_dir.path().to_path_buf(),
        Duration::from_millis(50),
        ResolverFactory::new_relay(peer_state.clone()),
        Some("127.0.0.1".parse().unwrap()),
        None,
        CertConfig::default(),
        cancel.clone(),
    )
    .await
    .unwrap();
    let state_dir = tempfile::tempdir().unwrap();
    let derive_cfg = DeriveConfig {
        bind_addr: "127.0.0.1".parse().unwrap(),
        proxy_protocol: None,
    };
    let acceptor = ChainAcceptor::load(supervisor.handle(), derive_cfg, state_dir.path()).unwrap();
    let (hb, _outbound) = HeartbeatServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        clone_kp(&server_keys),
        peer_state.clone(),
        pending_store,
        Some(acceptor),
        cancel.clone(),
    )
    .await
    .unwrap();
    let server_addr = hb.local_addr().unwrap();
    let hb_join = tokio::spawn(hb.run());
    let (mut session, sock) =
        drive_handshake(server_keys.public_key(), &client_keys, server_addr).await;

    // Body type 0x7F is unassigned in the registry.
    let envelope = ControlEnvelope {
        seq: 1,
        body_type: 0x7F,
        body: vec![],
    };
    let ack = send_control_and_await_ack(&mut session, &sock, &envelope).await;
    assert_eq!(ack.seq, 1);
    assert_eq!(ack.status, AckStatus::Unknown);

    cancel.cancel();
    supervisor.stop().await;
    let _ = hb_join.await;
}
