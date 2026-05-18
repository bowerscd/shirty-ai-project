//! End-to-end IP-change handover test.
//!
//! Drives the full server stack with two heartbeat sockets bound to
//! different loopback addresses (127.0.0.1 vs 127.0.0.2 — both inside
//! 127.0.0.0/8) and asserts:
//!
//! - The `PeerState` watch channel fires for the first heartbeat
//!   (None→Some(127.0.0.1)) **and** for the IP change (Some(127.0.0.1)→
//!   Some(127.0.0.2)) — twice total.
//! - `peer_state.current_ip()` reflects the new IP after the change.
//! - An in-flight UDP flow uses a different upstream source port after
//!   the change (the flow table was drained and a fresh upstream socket
//!   was created).
//!
//! This is the integration-level analogue of
//! `proxy::udp::tests::ip_change_drains_flow_table` plus
//! `heartbeat::peer_state::tests::ip_change_fires_watch`.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use ratatoskr::auth::StaticKeyPair;
use ratatoskr::rule::Protocol;
use ratatoskr::wire::{self, SessionId};

use yggdrasil::heartbeat::PeerState;

use crate::common::{
    pick_free_udp_port, spawn_supervisor, write_rule, HeartbeatHarness,
};

#[tokio::test]
async fn ip_change_drains_inflight_udp_flow() {
    let server_keys = StaticKeyPair::generate().unwrap();
    let client_keys = StaticKeyPair::generate().unwrap();
    let peer_state = PeerState::new(*client_keys.public_key());
    let shutdown = CancellationToken::new();
    let server_pub = *server_keys.public_key();

    let hb = HeartbeatHarness::spawn(server_keys, peer_state.clone(), shutdown.clone()).await;

    // Echo socket bound to 127.0.0.1 — but we also need a *different* upstream
    // address corresponding to the "new" peer IP 127.0.0.2. The proxy
    // connects upstream to `peer_ip:upstream_port`. We bind the same echo
    // service on both 127.0.0.1:PORT and 127.0.0.2:PORT (loopback handles
    // both via the lo interface).
    let echo_port = pick_free_udp_port().await;
    let sock_a = UdpSocket::bind(format!("127.0.0.1:{echo_port}"))
        .await
        .expect("bind echo on 127.0.0.1");
    let sock_b = UdpSocket::bind(format!("127.0.0.2:{echo_port}"))
        .await
        .expect("bind echo on 127.0.0.2 (this requires 127.0.0.0/8 to be loopback)");

    // Track upstream source addresses seen by each echo socket. The proxy's
    // per-flow upstream ports are what we care about — they reveal whether
    // the flow table got rebuilt on the IP change.
    let seen_a: Arc<Mutex<Vec<SocketAddr>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<SocketAddr>>> = Arc::new(Mutex::new(Vec::new()));

    let echo_a = {
        let seen = seen_a.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = sock_a.recv_from(&mut buf).await {
                seen.lock().await.push(from);
                let _ = sock_a.send_to(&buf[..n], from).await;
            }
        })
    };
    let echo_b = {
        let seen = seen_b.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = sock_b.recv_from(&mut buf).await {
                seen.lock().await.push(from);
                let _ = sock_b.send_to(&buf[..n], from).await;
            }
        })
    };

    // Write the UDP rule.
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
        echo_port,
    );

    let supervisor = spawn_supervisor(
        rules_dir,
        Duration::from_millis(50),
        peer_state.clone(),
        shutdown.clone(),
    )
    .await;
    assert!(supervisor.wait_for_nonempty(Duration::from_secs(2)).await);
    let snap = supervisor.snapshot();
    assert_eq!(snap.len(), 1);
    let proxy_listen = snap[0].listen;
    assert_eq!(snap[0].protocol, Protocol::Udp);

    // Drive handshake from 127.0.0.1.
    let mut watch_rx = peer_state.watch();
    let _ = watch_rx.borrow_and_update();

    let sock_hb_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock_hb_a.connect(hb.addr).await.unwrap();
    let sid = SessionId::random();
    let (init, hs1) = ratatoskr::auth::Initiator::start(&client_keys, &server_pub, sid)
        .unwrap();
    sock_hb_a.send(&hs1).await.unwrap();
    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(2), sock_hb_a.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let view = wire::parse(&buf[..n]).unwrap();
    let mut session = init.complete(&view).unwrap();

    // First heartbeat batch from 127.0.0.1.
    for c in 0..3u64 {
        let (_c, pkt) = session.encode_heartbeat(c, 0).unwrap();
        sock_hb_a.send(&pkt).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(1), sock_hb_a.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let _ = wire::parse(&buf[..n]).unwrap();
    }
    assert_eq!(peer_state.current_ip(), Some([127, 0, 0, 1].into()));

    // Open a UDP flow through the proxy.
    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_sock.connect(proxy_listen).await.unwrap();
    client_sock.send(b"before-change").await.unwrap();
    let mut reply = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut reply))
        .await
        .expect("first echo timeout")
        .unwrap();
    assert_eq!(&reply[..n], b"before-change");

    // The echo on 127.0.0.1 should have seen exactly one source addr so far
    // (the proxy's per-flow upstream port).
    let upstream_pre = {
        let v = seen_a.lock().await;
        assert!(!v.is_empty(), "echo @ 127.0.0.1 did not receive any datagrams");
        v[0]
    };

    // Consume the initial None→Some watch fire.
    assert!(watch_rx.has_changed().unwrap_or(false));
    let _ = watch_rx.borrow_and_update();

    // Now rebind heartbeat socket to 127.0.0.2 and send heartbeats from there.
    let sock_hb_b = UdpSocket::bind("127.0.0.2:0").await.unwrap();
    sock_hb_b.connect(hb.addr).await.unwrap();
    for c in 3..6u64 {
        let (_c, pkt) = session.encode_heartbeat(c, 0).unwrap();
        sock_hb_b.send(&pkt).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(1), sock_hb_b.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let _ = wire::parse(&buf[..n]).unwrap();
    }
    assert_eq!(peer_state.current_ip(), Some([127, 0, 0, 2].into()));
    assert!(
        watch_rx.has_changed().unwrap_or(false),
        "watch must fire on IP change"
    );
    let _ = watch_rx.borrow_and_update();

    // Give the proxy a moment to react to the watch (drain flows, ready for
    // new upstream sockets pointed at 127.0.0.2).
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Send a new datagram through the proxy. It should be forwarded to the
    // 127.0.0.2 echo (new upstream), with a *different* upstream port than
    // before because the flow table was rebuilt.
    client_sock.send(b"after-change").await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut reply))
        .await
        .expect("post-change echo timeout")
        .unwrap();
    assert_eq!(&reply[..n], b"after-change");

    let upstream_post = {
        let v = seen_b.lock().await;
        assert!(
            !v.is_empty(),
            "echo @ 127.0.0.2 should have received the post-change datagram"
        );
        v[0]
    };
    assert_ne!(
        upstream_pre.port(),
        upstream_post.port(),
        "upstream source port must change after the flow table drain"
    );

    shutdown.cancel();
    supervisor.stop().await;
    let _ = hb.handle.await;
    echo_a.abort();
    echo_b.abort();
}
