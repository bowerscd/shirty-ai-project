//! Phase 4C end-to-end test: the originator-side tunnel pipeline.
//!
//! Wire shape exercised (full path, not mocked):
//!
//! ```text
//! [test driver] --UDS--> [terminal daemon]
//!                            |
//!                            | spawn_chain_client wired with
//!                            | TunnelInitiator as body_handler
//!                            v
//!                        ChainClient
//!                            |
//!                            | Noise_IK over UDP
//!                            v
//!                        HeartbeatServer + ChainAcceptor + TunnelManager
//!                            |
//!                            | TCP
//!                            v
//!                        loopback echo backend
//! ```
//!
//! The test:
//! 1. Spawns a loopback TCP echo server.
//! 2. Spawns a relay-style HeartbeatServer + ChainAcceptor + TunnelManager
//!    (allow-list: loopback only).
//! 3. Constructs a [`ChainClient`] with a [`TunnelInitiator`] installed
//!    as its body handler; spawns the client task. (No UDS daemon: we
//!    drive the initiator directly because the surrounding wiring is
//!    the unit under test.)
//! 4. Calls `initiator.open(...)`, writes "hello, tunnel!", and waits
//!    for the same bytes to come back through the inbound mpsc.
//! 5. Closes the stream.

mod common;

use std::sync::Arc;
use std::time::Duration;

use ratatoskr::auth::StaticKeyPair;
use ratatoskr::pubkey::PubKey;
use tokio_util::sync::CancellationToken;

use yggdrasil::chain::{
    ChainAcceptor, ChainClient, ChainClientConfig, DeriveConfig, TunnelAllowList,
    TunnelInitiator, TunnelManager,
};
use yggdrasil::heartbeat::{HeartbeatServer, PeerState};
use yggdrasil::pending_peers::PendingPeerStore;
use yggdrasil::proxy::resolver::ResolverFactory;
use yggdrasil::proxy::supervisor::{CertConfig, ProxySupervisor};

use common::{clone_kp, echo_tcp_listener, spawn_tcp_echo};

/// Spin up a relay-style terminator (HeartbeatServer + ChainAcceptor +
/// TunnelManager with loopback-only allow-list) authorising
/// `client_static_pub` as its downstream. Returns the listener address
/// plus the static keys we need on the initiator side, alongside the
/// cancel token and join handle for shutdown.
async fn spawn_terminator(
    client_static_pub: [u8; 32],
) -> (
    std::net::SocketAddr,
    StaticKeyPair,
    CancellationToken,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let server_keys = StaticKeyPair::generate().unwrap();
    let peer_state = PeerState::new(client_static_pub);
    let pending_dir = tempfile::tempdir().unwrap();
    let pending_store = Arc::new(PendingPeerStore::load(pending_dir.path()).unwrap());
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
    let acceptor = ChainAcceptor::load(supervisor.handle(), derive_cfg, state_dir.path())
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
        .set_tunnel_manager(mgr)
        .expect("attach tunnel manager");

    let hb_join = tokio::spawn(hb.run());
    (server_addr, server_keys, cancel, hb_join)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn initiator_round_trips_data_through_real_chain_client_and_terminator() {
    // 1. Loopback TCP echo backend.
    let (listener, echo_addr) = echo_tcp_listener().await;
    let _echo_task = spawn_tcp_echo(listener);

    // 2. Spawn the upstream relay (terminator side).
    let client_keys = StaticKeyPair::generate().unwrap();
    let (server_addr, server_keys, cancel, hb_join) =
        spawn_terminator(*client_keys.public_key()).await;

    // 3. Build a real ChainClient with a TunnelInitiator installed as
    //    its body_handler. This mirrors the production `spawn_chain_client`
    //    setup verbatim except that we keep the join handle so the test
    //    can drop it explicitly on teardown.
    let upstream_pubkey = *server_keys.public_key();
    let client_cancel = cancel.clone();
    let cfg = ChainClientConfig {
        endpoint: server_addr.to_string(),
        upstream_pubkey,
        local_keys: client_keys,
        heartbeat_interval: Duration::from_millis(200),
        rekey_interval: Duration::from_secs(120),
        body_handler: None,
    };
    let mut client = ChainClient::new(cfg, client_cancel.clone());
    let handle = client.handle();
    let initiator =
        TunnelInitiator::new(handle.clone(), PubKey::x25519(upstream_pubkey));
    client.set_body_handler(initiator.body_handler());
    let client_join = tokio::spawn(async move {
        let _ = client.run().await;
    });

    // Give the chain client time to complete its handshake.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // 4. Open a tunnel to the echo backend.
    let upstream = PubKey::x25519(upstream_pubkey);
    let stream = tokio::time::timeout(
        Duration::from_secs(3),
        initiator.open(upstream, echo_addr),
    )
    .await
    .expect("open() resolved within deadline")
    .expect("open() succeeded");
    let stream_id = stream.stream_id;
    let mut inbound_rx = stream.inbound_rx;
    let close_rx = stream.close_rx;

    // 5. Send payload and read it back.
    let payload = b"hello, initiator e2e!".to_vec();
    tokio::time::timeout(
        Duration::from_secs(3),
        initiator.send_data(stream_id, payload.clone()),
    )
    .await
    .expect("send_data resolved within deadline")
    .expect("send_data succeeded");

    let echoed = tokio::time::timeout(Duration::from_secs(3), async {
        // The echo backend may or may not coalesce the payload into a
        // single frame; collect bytes until we have enough.
        let mut got = Vec::new();
        while got.len() < payload.len() {
            let chunk = inbound_rx
                .recv()
                .await
                .expect("inbox should produce echoed bytes");
            got.extend_from_slice(&chunk);
        }
        got
    })
    .await
    .expect("echo bytes arrived within deadline");
    assert_eq!(
        echoed, payload,
        "echoed bytes should match the sent payload"
    );

    // 6. Close the stream cleanly. After close the registry entry is
    //    dropped and close_rx must resolve with `Err` (we initiated, so
    //    no peer-side reason landed first).
    initiator.close(stream_id, 0).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(500), close_rx)
            .await
            .map(|r| r.is_err())
            .unwrap_or(true),
        "close_rx should not deliver a peer-supplied reason after \
         a locally-initiated close"
    );
    assert!(
        initiator.open_stream_ids().await.is_empty(),
        "registry should be empty after close"
    );

    // Teardown.
    cancel.cancel();
    client_cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), client_join).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), hb_join).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn initiator_open_rejected_when_dest_outside_terminator_allow_list() {
    let client_keys = StaticKeyPair::generate().unwrap();
    let (server_addr, server_keys, cancel, hb_join) =
        spawn_terminator(*client_keys.public_key()).await;

    let upstream_pubkey = *server_keys.public_key();
    let client_cancel = cancel.clone();
    let cfg = ChainClientConfig {
        endpoint: server_addr.to_string(),
        upstream_pubkey,
        local_keys: client_keys,
        heartbeat_interval: Duration::from_millis(200),
        rekey_interval: Duration::from_secs(120),
        body_handler: None,
    };
    let mut client = ChainClient::new(cfg, client_cancel.clone());
    let handle = client.handle();
    let initiator =
        TunnelInitiator::new(handle.clone(), PubKey::x25519(upstream_pubkey));
    client.set_body_handler(initiator.body_handler());
    let client_join = tokio::spawn(async move {
        let _ = client.run().await;
    });

    tokio::time::sleep(Duration::from_millis(800)).await;

    // 10.x is RFC1918, not loopback. TunnelManager's loopback-only
    // allow-list rejects it with TARGET_NOT_ALLOWED.
    let bad_dest: std::net::SocketAddr = "10.255.255.1:65535".parse().unwrap();
    let upstream = PubKey::x25519(upstream_pubkey);
    let err = initiator
        .open(upstream, bad_dest)
        .await
        .expect_err("open of non-loopback should be rejected by terminator");
    match err {
        yggdrasil::chain::OpenError::Rejected(code) => {
            use ratatoskr::tunnel::tunnel_reject;
            assert_eq!(
                code,
                tunnel_reject::TARGET_NOT_ALLOWED,
                "expected TARGET_NOT_ALLOWED, got 0x{code:04x}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(
        initiator.open_stream_ids().await.is_empty(),
        "registry must roll back after reject"
    );

    cancel.cancel();
    client_cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), client_join).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), hb_join).await;
}
