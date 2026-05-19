//! Phase 4B end-to-end test: TunnelOpen → echo backend → TunnelData
//! round-trip → TunnelClose, exercised over the real wire.
//!
//! Wire path:
//!
//! 1. A TCP echo server listens on `127.0.0.1:<rand>`.
//! 2. The driver (acting as terminal/initiator) Noise_IK handshakes with
//!    a real `HeartbeatServer` configured with a `ChainAcceptor` that
//!    has a [`TunnelManager`] attached. The manager's allow-list is
//!    loopback-only.
//! 3. The driver sends `TunnelOpen { stream_id, target_pubkey=self,
//!    dest=<echo addr> }`. The terminator dials, registers the stream,
//!    and acks `Ok`.
//! 4. The driver sends `TunnelData { stream_id, payload=b"hello" }`.
//!    The terminator pushes the bytes into the dialed socket; the echo
//!    server bounces them back; the splice task wraps the response in
//!    a fresh `Control` envelope and emits it on the relay's outbound
//!    channel. The driver receives the inbound `Control` and asserts
//!    the echoed bytes match.
//! 5. The driver sends `TunnelClose { stream_id }`. The terminator
//!    removes the stream from its registry; the splice task is aborted.
//!
//! Notes:
//! * The driver does not ack inbound `Control` from the relay. Phase
//!   4B's outbound path is fire-and-forget, so the server has no
//!   retransmit machinery that would care.
//! * Loopback TCP delivery is in-order, which keeps the strict-monotone
//!   Noise replay window from rejecting any frame. Out-of-order
//!   localhost UDP is theoretically possible but vanishingly rare; if
//!   the test ever flakes for that reason, switch to bind on a single
//!   loopback alias.
//!
//! [`TunnelManager`]: yggdrasil::chain::TunnelManager

mod common;

use std::sync::Arc;
use std::time::Duration;

use ratatoskr::auth::StaticKeyPair;
use ratatoskr::control_frame::{AckStatus, ControlBodyType, ControlEnvelope};
use ratatoskr::pubkey::PubKey;
use ratatoskr::tunnel::{TunnelClose, TunnelData, TunnelOpen};
use ratatoskr::wire::{self, PacketType};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use yggdrasil::chain::{ChainAcceptor, DeriveConfig, TunnelAllowList, TunnelManager};
use yggdrasil::heartbeat::{HeartbeatServer, PeerState};
use yggdrasil::pending_peers::PendingPeerStore;
use yggdrasil::proxy::resolver::ResolverFactory;
use yggdrasil::proxy::supervisor::{CertConfig, ProxySupervisor};

use common::{clone_kp, drive_handshake, echo_tcp_listener, spawn_tcp_echo};

/// One UDP frame, parsed and classified by packet type.
enum Inbound {
    Ack(ratatoskr::control_frame::ControlAck),
    Envelope(ControlEnvelope),
}

/// Receive a single UDP datagram from `sock`, decrypt it on `session`,
/// and return a typed [`Inbound`]. Panics on timeout / non-Control
/// packets so test failures point at the right line.
async fn recv_typed(
    session: &mut ratatoskr::auth::Session,
    sock: &UdpSocket,
    timeout: Duration,
) -> Inbound {
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .expect("UDP recv timeout")
        .expect("UDP recv error");
    let view = wire::parse(&buf[..n]).expect("parse packet");
    match view.packet_type {
        PacketType::Control => {
            let env = session.decode_control(&view).expect("decode control");
            Inbound::Envelope(env)
        }
        PacketType::ControlAck => {
            let ack = session
                .decode_control_ack(&view)
                .expect("decode control_ack");
            Inbound::Ack(ack)
        }
        other => panic!("unexpected packet type {other:?}"),
    }
}

/// Receive frames until a `ControlAck` for `expected_seq` arrives.
/// Collects every `Inbound::Envelope` seen along the way and returns
/// (envelopes_in_order, the_ack).
async fn drain_until_ack(
    session: &mut ratatoskr::auth::Session,
    sock: &UdpSocket,
    expected_seq: u32,
    timeout: Duration,
) -> (Vec<ControlEnvelope>, ratatoskr::control_frame::ControlAck) {
    let mut envs = Vec::new();
    let start = tokio::time::Instant::now();
    loop {
        let remaining = timeout.checked_sub(start.elapsed()).unwrap_or_default();
        match recv_typed(session, sock, remaining.max(Duration::from_millis(10))).await {
            Inbound::Ack(ack) if ack.seq == expected_seq => return (envs, ack),
            Inbound::Ack(ack) => panic!(
                "got ack for seq={} while waiting for seq={}",
                ack.seq, expected_seq
            ),
            Inbound::Envelope(env) => envs.push(env),
        }
    }
}

async fn send_envelope(
    session: &mut ratatoskr::auth::Session,
    sock: &UdpSocket,
    env: &ControlEnvelope,
) {
    let (_, packet) = session.encode_control(env).expect("encode control");
    sock.send(&packet).await.expect("send control");
}

/// Set up a `HeartbeatServer` + `ChainAcceptor` + `TunnelManager` with
/// loopback-only allow-list. Returns the (server_addr, server_keys,
/// client_keys, cancel-token).
async fn spawn_terminator(
    client_static_pub: [u8; 32],
) -> (
    std::net::SocketAddr,
    StaticKeyPair,
    CancellationToken,
    tokio::task::JoinHandle<anyhow::Result<()>>,
    Arc<TunnelManager>,
) {
    let server_keys = StaticKeyPair::generate().unwrap();
    let peer_state = PeerState::new(client_static_pub);
    let pending_dir = tempfile::tempdir().unwrap();
    let pending_store =
        Arc::new(PendingPeerStore::load(pending_dir.path()).unwrap());
    std::mem::forget(pending_dir);

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
    std::mem::forget(rules_dir);

    let state_dir = tempfile::tempdir().unwrap();
    let derive_cfg = DeriveConfig {
        bind_addr: "127.0.0.1".parse().unwrap(),
        proxy_protocol: None,
    };
    let acceptor =
        ChainAcceptor::load(supervisor.handle(), derive_cfg, state_dir.path())
            .expect("load acceptor");
    std::mem::forget(state_dir);

    let (hb, outbound) = HeartbeatServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        clone_kp(&server_keys),
        peer_state.clone(),
        pending_store,
        Some(acceptor.clone()),
        cancel.clone(),
    )
    .await
    .expect("bind heartbeat");
    let server_addr = hb.local_addr().unwrap();

    let mgr = TunnelManager::new(
        TunnelAllowList::loopback_only(),
        PubKey::x25519(*server_keys.public_key()),
        outbound.sender(),
    );
    acceptor
        .set_tunnel_manager(mgr.clone())
        .expect("attach tunnel manager");

    let hb_join = tokio::spawn(hb.run());

    (server_addr, server_keys, cancel, hb_join, mgr)
}

#[tokio::test]
async fn tunnel_open_data_close_round_trip_via_loopback_echo() {
    let client_keys = StaticKeyPair::generate().unwrap();
    let (server_addr, server_keys, cancel, hb_join, mgr) =
        spawn_terminator(*client_keys.public_key()).await;

    // Stand up a loopback TCP echo backend.
    let (listener, echo_addr) = echo_tcp_listener().await;
    let _echo_task = spawn_tcp_echo(listener);

    // Drive handshake.
    let (mut session, sock) =
        drive_handshake(server_keys.public_key(), &client_keys, server_addr).await;

    let target_pubkey = PubKey::x25519(*server_keys.public_key());
    let stream_id: u32 = 0xC0DE_C0DE;

    // 1. Open.
    let open = TunnelOpen {
        stream_id,
        target_pubkey,
        dest: echo_addr,
    };
    let open_env = ControlEnvelope {
        seq: 1,
        body_type: ControlBodyType::TunnelOpen.as_byte(),
        body: postcard::to_allocvec(&open).unwrap(),
    };
    send_envelope(&mut session, &sock, &open_env).await;
    let (envs, ack) =
        drain_until_ack(&mut session, &sock, 1, Duration::from_secs(2)).await;
    assert_eq!(ack.status, AckStatus::Ok, "tunnel open should ack Ok");
    assert!(envs.is_empty(), "no inbound envelopes expected before data");
    assert_eq!(mgr.open_stream_ids().await, vec![stream_id]);

    // 2. Data round-trip. Send "hello" and expect "hello" back inside a
    //    TunnelData envelope from the relay.
    let payload = b"hello, tunnel!".to_vec();
    let data = TunnelData {
        stream_id,
        payload: payload.clone(),
    };
    let data_env = ControlEnvelope {
        seq: 2,
        body_type: ControlBodyType::TunnelData.as_byte(),
        body: postcard::to_allocvec(&data).unwrap(),
    };
    send_envelope(&mut session, &sock, &data_env).await;
    let (envs, ack) =
        drain_until_ack(&mut session, &sock, 2, Duration::from_secs(2)).await;
    assert_eq!(ack.status, AckStatus::Ok, "tunnel data should ack Ok");
    // The echo might land before or after the ack. If after, drain a
    // single extra frame; the echo will reach us under one second on
    // loopback.
    let mut echoed = envs
        .into_iter()
        .find(|e| e.body_type == ControlBodyType::TunnelData.as_byte());
    if echoed.is_none() {
        // Wait briefly for the echo to arrive after the ack.
        if let Inbound::Envelope(env) =
            recv_typed(&mut session, &sock, Duration::from_secs(2)).await
        {
            echoed = Some(env);
        }
    }
    let echoed = echoed.expect("expected echoed TunnelData envelope");
    let echoed_data: TunnelData = postcard::from_bytes(&echoed.body).unwrap();
    assert_eq!(echoed_data.stream_id, stream_id);
    assert_eq!(echoed_data.payload, payload);

    // 3. Close.
    let close = TunnelClose { stream_id, reason: 0 };
    let close_env = ControlEnvelope {
        seq: 3,
        body_type: ControlBodyType::TunnelClose.as_byte(),
        body: postcard::to_allocvec(&close).unwrap(),
    };
    send_envelope(&mut session, &sock, &close_env).await;
    let (_envs, ack) =
        drain_until_ack(&mut session, &sock, 3, Duration::from_secs(2)).await;
    assert_eq!(ack.status, AckStatus::Ok);
    assert!(
        mgr.open_stream_ids().await.is_empty(),
        "stream should be removed after close"
    );

    cancel.cancel();
    let _ = hb_join.await;
}

#[tokio::test]
async fn tunnel_open_rejected_when_dest_not_in_allow_list() {
    let client_keys = StaticKeyPair::generate().unwrap();
    let (server_addr, server_keys, cancel, hb_join, mgr) =
        spawn_terminator(*client_keys.public_key()).await;

    let (mut session, sock) =
        drive_handshake(server_keys.public_key(), &client_keys, server_addr).await;

    // 10.x is RFC1918, not loopback, and not in the allow-list.
    let bad_dest: std::net::SocketAddr = "10.255.255.1:65535".parse().unwrap();
    let open = TunnelOpen {
        stream_id: 1,
        target_pubkey: PubKey::x25519(*server_keys.public_key()),
        dest: bad_dest,
    };
    let env = ControlEnvelope {
        seq: 1,
        body_type: ControlBodyType::TunnelOpen.as_byte(),
        body: postcard::to_allocvec(&open).unwrap(),
    };
    send_envelope(&mut session, &sock, &env).await;
    let (_, ack) =
        drain_until_ack(&mut session, &sock, 1, Duration::from_secs(2)).await;
    assert_eq!(
        ack.status,
        AckStatus::Reject(ratatoskr::tunnel::tunnel_reject::TARGET_NOT_ALLOWED)
    );
    assert!(mgr.open_stream_ids().await.is_empty());

    cancel.cancel();
    let _ = hb_join.await;
}
