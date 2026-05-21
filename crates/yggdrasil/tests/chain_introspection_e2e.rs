//! Phase 5B end-to-end test: a `PredicateSetUpdate` accepted by the
//! relay surfaces in the introspection snapshot read by
//! `Request::DerivedRules` over UDS.
//!
//! Wire path exercised:
//!
//! 1. Driver (acting as terminal) Noise_IK handshakes with a real
//!    `HeartbeatServer` backed by a `ChainAcceptor` + `ProxySupervisor`.
//! 2. Driver sends a `PredicateSetUpdate` envelope; server acks `Ok`.
//! 3. The introspection sink wired into the acceptor records the
//!    apply (predicates, origin, version, last_apply_unix).
//! 4. Test calls `IntrospectionState::snapshot()` directly — same
//!    `DerivedRulesResponse` shape the UDS handler serves.

mod common;

use std::sync::Arc;
use std::time::Duration;

use ratatoskr::auth::StaticKeyPair;
use ratatoskr::control_frame::{AckStatus, ControlBodyType, ControlEnvelope};
use ratatoskr::predicate::{Predicate, PredicateSet};
use ratatoskr::pubkey::PubKey;
use ratatoskr::rule::Protocol;
use ratatoskr::wire;
use tokio::net::UdpSocket;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn predicate_set_update_surfaces_in_introspection_snapshot() {
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
    let acceptor = ChainAcceptor::load(supervisor.handle(), derive_cfg, state_dir.path())
        .expect("load acceptor");

    // 4. Introspection state wired into the acceptor.
    let introspection = IntrospectionState::new(
        local_pubkey,
        Some(upstream_pubkey),
        Some(downstream_pubkey),
        supervisor.handle(),
    );
    acceptor
        .set_introspection(introspection.clone())
        .expect("set_introspection");

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

    // 7. Wait until the supervisor has applied the derived rule. Once
    //    that completes, the introspection snapshot must reflect v=1
    //    and the predicate list.
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

    // 8. Read the introspection snapshot directly — same
    //    `DerivedRulesResponse` shape the UDS `Request::DerivedRules`
    //    handler serves.
    let snap = introspection.snapshot();

    // Predicate list shape.
    assert_eq!(snap.predicates.len(), 1, "exactly one predicate applied");
    assert_eq!(snap.predicates[0].name, "alpha");
    assert_eq!(snap.predicates[0].listen_port, listen_port);
    assert_eq!(snap.predicates[0].protocol, Protocol::Tcp);

    // Derived rules surface the supervisor's current_set.
    assert!(
        snap.derived_rules.iter().any(|r| r.name == "alpha"),
        "derived_rules should contain the alpha rule, got: {:?}",
        snap.derived_rules
    );

    // Chain identity surfaces the configured pubkeys + applied version.
    assert_eq!(snap.chain.local, local_pubkey);
    assert_eq!(snap.chain.upstream, Some(upstream_pubkey));
    assert_eq!(snap.chain.downstream, Some(downstream_pubkey));
    assert_eq!(snap.chain.predicate_origin, Some(origin));
    assert_eq!(snap.chain.predicate_version, Some(1));
    assert!(
        snap.chain.last_apply_unix.unwrap_or(0) > 0,
        "last_apply_unix should be a wall-clock value, got {:?}",
        snap.chain.last_apply_unix
    );

    cancel.cancel();
    supervisor.stop().await;
    let _ = hb_join.await;
    drop(rules_dir);
    drop(state_dir);
    drop(pending_dir);
}
