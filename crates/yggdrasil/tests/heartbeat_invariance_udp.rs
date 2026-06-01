//! End-to-end heartbeat-invariance integration test (UDP).
//!
//! Spins up the whole server-side stack (heartbeat listener + proxy
//! supervisor + a single UDP rule + a backing echo socket) and proves the
//! data plane survives a heartbeat storm from the same residential IP:
//!
//! - One UDP flow opened through the proxy retains the same upstream source
//!   port across N heartbeats.
//! - `peer_state.watch()` fires **once** for the initial None→Some(IP)
//!   transition and zero more times across the whole storm.
//! - The supervisor's rule snapshot stays unchanged.
//!
//! This is the integration-level analogue of
//! `proxy::udp::tests::same_ip_heartbeats_do_not_drain_flow_table` plus
//! `heartbeat::server::tests::many_heartbeats_from_same_addr_fire_watch_once`.

mod common;

use std::time::Duration;

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use ratatoskr::auth::StaticKeyPair;
use ratatoskr::rule::Protocol;
use ratatoskr::wire;

use yggdrasil::heartbeat::PeerState;

use crate::common::{
    drive_handshake, echo_udp_socket, pick_free_udp_port, spawn_supervisor, spawn_udp_echo,
    write_rule, HeartbeatHarness,
};

#[tokio::test]
async fn full_stack_heartbeat_storm_does_not_disturb_udp_data_plane() {
    // 1. Set up identities and the heartbeat server.
    let server_keys = StaticKeyPair::generate().unwrap();
    let client_keys = StaticKeyPair::generate().unwrap();
    let peer_state = PeerState::new(Some(client_keys.public_key()));
    let shutdown = CancellationToken::new();

    let server_pub = server_keys.public_key();
    let hb = HeartbeatHarness::spawn(server_keys, peer_state.clone(), shutdown.clone()).await;

    // 2. Backing echo socket — stands in for whatever runs on the residential box.
    let (echo_sock, echo_addr) = echo_udp_socket().await;
    let echo_handle = spawn_udp_echo(echo_sock);

    // 3. Write a single UDP rule file pointing at `echo_addr.port()`.
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let listen_port = pick_free_udp_port().await;
    write_rule(
        &rules_dir,
        "echo.toml",
        "echo",
        "udp",
        listen_port,
        echo_addr.port(),
    );

    // 4. Spawn the proxy supervisor and wait for the proxy to come up.
    let supervisor = spawn_supervisor(
        rules_dir.clone(),
        Duration::from_millis(50),
        peer_state.clone(),
        shutdown.clone(),
    )
    .await;
    assert!(supervisor.wait_for_nonempty(Duration::from_secs(2)).await);
    let initial_snapshot = supervisor.snapshot();
    assert_eq!(initial_snapshot.len(), 1);
    let proxy_listen = initial_snapshot[0].listen;
    assert_eq!(initial_snapshot[0].protocol, Protocol::Udp);

    // 5. Drive the handshake and the first heartbeats.
    let (mut session, hb_sock) = drive_handshake(&server_pub, &client_keys, hb.addr).await;
    let mut watch_rx = peer_state.watch();
    let mut watch_fires = 0u32;
    if watch_rx.borrow_and_update().is_some() {
        watch_fires += 1;
    }

    let mut hb_buf = [0u8; 2048];
    for counter in 0..5u64 {
        let (_c, hb_pkt) = session.encode_heartbeat(counter, 0).unwrap();
        hb_sock.send(&hb_pkt).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(1), hb_sock.recv(&mut hb_buf))
            .await
            .expect("HeartbeatAck timeout")
            .unwrap();
        let view = wire::parse(&hb_buf[..n]).unwrap();
        let _ack = session.decode_heartbeat_ack(&view).unwrap();
        if watch_rx.has_changed().unwrap_or(false) {
            let _ = watch_rx.borrow_and_update();
            watch_fires += 1;
        }
    }
    assert!(
        peer_state.current_ip().is_some(),
        "peer_state should have a current IP after the first heartbeat"
    );
    assert_eq!(
        watch_fires, 1,
        "watch should fire exactly once (None→Some(127.0.0.1)) before the storm"
    );

    // 6. Open a UDP flow through the proxy frontend.
    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_sock.connect(proxy_listen).await.unwrap();
    client_sock.send(b"ping-0").await.unwrap();
    let mut reply = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut reply))
        .await
        .expect("expected echo reply")
        .unwrap();
    assert_eq!(&reply[..n], b"ping-0");

    // 7. The heartbeat storm. 100 same-IP heartbeats interleaved with data
    //    plane traffic. The invariant we assert: every datagram makes the
    //    round-trip, and the watch channel fires zero additional times.
    for i in 1..=100u64 {
        let (_c, hb_pkt) = session.encode_heartbeat(5 + i, 0).unwrap();
        hb_sock.send(&hb_pkt).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(1), hb_sock.recv(&mut hb_buf))
            .await
            .expect("HeartbeatAck timeout")
            .unwrap();
        let _ = wire::parse(&hb_buf[..n]).unwrap();

        if i % 10 == 0 {
            let payload = format!("ping-{i}");
            client_sock.send(payload.as_bytes()).await.unwrap();
            let n = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut reply))
                .await
                .unwrap_or_else(|_| panic!("data plane stalled at heartbeat #{i}"))
                .unwrap();
            assert_eq!(
                &reply[..n],
                payload.as_bytes(),
                "data plane corruption at heartbeat #{i}"
            );
        }
    }

    // 8. After the storm: the watch channel must NOT have fired again.
    if watch_rx.has_changed().unwrap_or(false) {
        let new_ip = *watch_rx.borrow_and_update();
        panic!("peer_state watch fired during same-IP heartbeat storm: new value = {new_ip:?}");
    }
    assert_eq!(
        supervisor.snapshot(),
        initial_snapshot,
        "rule supervisor snapshot must remain identical across the storm"
    );

    // 9. Tear down cleanly.
    shutdown.cancel();
    supervisor.stop().await;
    let _ = hb.handle.await;
    echo_handle.abort();
}
