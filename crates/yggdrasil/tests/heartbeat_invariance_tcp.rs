//! End-to-end heartbeat-invariance for TCP rules.
//!
//! TCP analogue of `heartbeat_invariance_udp.rs`. Asserts that a same-IP
//! heartbeat storm does not break an inflight TCP connection through a TCP
//! rule. Each storm tick we send a payload bidirectionally and re-read it,
//! verifying the TCP session is alive and byte-stable.

mod common;

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use ratatoskr::auth::StaticKeyPair;
use ratatoskr::rule::Protocol;

use yggdrasil::heartbeat::PeerState;

use crate::common::{
    drive_handshake, echo_tcp_listener, pick_free_tcp_port, send_heartbeat, spawn_supervisor,
    spawn_tcp_echo, write_rule, HeartbeatHarness,
};

#[tokio::test]
async fn full_stack_heartbeat_storm_does_not_disturb_tcp_connection() {
    let server_keys = StaticKeyPair::generate().unwrap();
    let client_keys = StaticKeyPair::generate().unwrap();
    let peer_state = PeerState::new(*client_keys.public_key());
    let shutdown = CancellationToken::new();
    let server_pub = *server_keys.public_key();

    let hb = HeartbeatHarness::spawn(server_keys, peer_state.clone(), shutdown.clone()).await;

    let (echo_listener, echo_addr) = echo_tcp_listener().await;
    let echo_handle = spawn_tcp_echo(echo_listener);

    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let listen_port = pick_free_tcp_port().await;
    write_rule(
        &rules_dir,
        "echo.toml",
        "echo",
        "tcp",
        listen_port,
        echo_addr.port(),
    );

    let supervisor = spawn_supervisor(
        rules_dir,
        Duration::from_millis(50),
        peer_state.clone(),
        shutdown.clone(),
    )
    .await;
    assert!(supervisor.wait_for_nonempty(Duration::from_secs(2)).await);
    let initial_snapshot = supervisor.snapshot();
    assert_eq!(initial_snapshot.len(), 1);
    let proxy_listen = initial_snapshot[0].listen;
    assert_eq!(initial_snapshot[0].protocol, Protocol::Tcp);

    // Drive the handshake and a few initial heartbeats to populate peer_ip.
    let (mut session, hb_sock) = drive_handshake(&server_pub, &client_keys, hb.addr).await;
    for counter in 0..5u64 {
        send_heartbeat(&mut session, &hb_sock, counter).await.unwrap();
    }
    assert!(peer_state.current_ip().is_some());

    let mut watch_rx = peer_state.watch();
    let _ = watch_rx.borrow_and_update(); // consume the initial None→Some change.

    // Open the TCP connection through the proxy.
    let mut stream = tokio::time::timeout(
        Duration::from_secs(2),
        TcpStream::connect(proxy_listen),
    )
    .await
    .expect("TcpStream connect timeout")
    .expect("TcpStream connect failed");

    // Verify round-trip works.
    stream.write_all(b"hello\n").await.unwrap();
    let mut buf = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut buf))
        .await
        .expect("initial TCP echo timeout")
        .unwrap();
    assert_eq!(&buf, b"hello\n");

    // Heartbeat storm interleaved with TCP echo round-trips.
    for i in 1..=100u64 {
        send_heartbeat(&mut session, &hb_sock, 5 + i).await.unwrap();

        if i % 10 == 0 {
            let payload = format!("ping-{i:03}\n");
            stream.write_all(payload.as_bytes()).await.unwrap();
            let mut buf = vec![0u8; payload.len()];
            tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("TCP stalled at heartbeat #{i}"))
                .unwrap();
            assert_eq!(buf, payload.as_bytes());
        }
    }

    // Watch channel must NOT have fired during the storm.
    assert!(
        !watch_rx.has_changed().unwrap_or(false),
        "peer_state watch fired during same-IP TCP heartbeat storm"
    );
    assert_eq!(
        supervisor.snapshot(),
        initial_snapshot,
        "rule supervisor snapshot must remain identical across the storm"
    );

    shutdown.cancel();
    supervisor.stop().await;
    let _ = hb.handle.await;
    echo_handle.abort();
}
