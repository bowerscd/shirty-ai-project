//! End-to-end hot-reload test.
//!
//! Verifies that dropping a new `*.toml` rule file into the rules
//! directory causes the supervisor to add a new listener within
//! debounce + a small safety margin, and that existing rules are not
//! disturbed by the reload.

mod common;

use std::time::Duration;

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use ratatoskr::auth::StaticKeyPair;

use yggdrasil::heartbeat::PeerState;

use crate::common::{
    drive_handshake, echo_udp_socket, pick_free_udp_port, send_heartbeat, spawn_supervisor,
    spawn_udp_echo, write_rule, HeartbeatHarness,
};

#[tokio::test]
async fn dropping_a_new_rule_file_adds_a_listener_live() {
    let server_keys = StaticKeyPair::generate().unwrap();
    let client_keys = StaticKeyPair::generate().unwrap();
    let peer_state = PeerState::new(Some(client_keys.public_key()));
    let shutdown = CancellationToken::new();
    let server_pub = server_keys.public_key();

    let hb = HeartbeatHarness::spawn(server_keys, peer_state.clone(), shutdown.clone()).await;

    let (echo_a, addr_a) = echo_udp_socket().await;
    let echo_a_handle = spawn_udp_echo(echo_a);
    let (echo_b, addr_b) = echo_udp_socket().await;
    let echo_b_handle = spawn_udp_echo(echo_b);

    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();

    // Initial rule: just rule A.
    let listen_a = pick_free_udp_port().await;
    write_rule(
        &rules_dir,
        "a.toml",
        "rule-a",
        "udp",
        listen_a,
        addr_a.port(),
    );

    let debounce = Duration::from_millis(100);
    let supervisor = spawn_supervisor(
        rules_dir.clone(),
        debounce,
        peer_state.clone(),
        shutdown.clone(),
    )
    .await;
    assert!(supervisor.wait_for_nonempty(Duration::from_secs(2)).await);
    let initial = supervisor.snapshot();
    assert_eq!(initial.len(), 1);
    let listen_a_addr = initial[0].listen;
    assert_eq!(initial[0].name, "rule-a");

    // Drive heartbeats to bind peer IP.
    let (mut session, hb_sock) = drive_handshake(&server_pub, &client_keys, hb.addr).await;
    for c in 0..3u64 {
        send_heartbeat(&mut session, &hb_sock, c).await.unwrap();
    }
    assert!(peer_state.current_ip().is_some());

    // Send through rule A to confirm it's working pre-reload.
    let client_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_a.connect(listen_a_addr).await.unwrap();
    client_a.send(b"a-pre").await.unwrap();
    let mut reply = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(2), client_a.recv(&mut reply))
        .await
        .expect("rule-a pre-reload echo timeout")
        .unwrap();
    assert_eq!(&reply[..n], b"a-pre");

    // Drop a new rule file: rule B.
    let listen_b = pick_free_udp_port().await;
    write_rule(
        &rules_dir,
        "b.toml",
        "rule-b",
        "udp",
        listen_b,
        addr_b.port(),
    );

    // The supervisor must pick this up within debounce + a small slack.
    let reload_deadline = Duration::from_secs(2);
    let started = std::time::Instant::now();
    let mut new_snap;
    loop {
        new_snap = supervisor.snapshot();
        if new_snap.len() == 2 {
            break;
        }
        if started.elapsed() > reload_deadline {
            panic!(
                "supervisor did not pick up rule-b within {reload_deadline:?}; \
                 snapshot = {new_snap:?}"
            );
        }
        // Bounded poll on the supervisor snapshot (the rule-watcher
        // debounce gates this; the deadline above is the safety net).
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Sanity: rule-a survived unchanged.
    let rule_a_post = new_snap.iter().find(|r| r.name == "rule-a").unwrap();
    let rule_a_initial = initial.iter().find(|r| r.name == "rule-a").unwrap();
    assert_eq!(
        rule_a_post, rule_a_initial,
        "rule-a must not be touched by reload"
    );

    // Rule A still serves traffic.
    client_a.send(b"a-post").await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(2), client_a.recv(&mut reply))
        .await
        .expect("rule-a post-reload echo timeout")
        .unwrap();
    assert_eq!(&reply[..n], b"a-post");

    // Rule B serves traffic too.
    let rule_b = new_snap.iter().find(|r| r.name == "rule-b").unwrap();
    let client_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_b.connect(rule_b.listen).await.unwrap();
    client_b.send(b"b-hello").await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(2), client_b.recv(&mut reply))
        .await
        .expect("rule-b echo timeout")
        .unwrap();
    assert_eq!(&reply[..n], b"b-hello");

    shutdown.cancel();
    supervisor.stop().await;
    let _ = hb.handle.await;
    echo_a_handle.abort();
    echo_b_handle.abort();
}
