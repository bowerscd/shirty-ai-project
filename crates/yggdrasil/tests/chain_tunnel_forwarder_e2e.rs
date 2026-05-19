//! Phase 5 end-to-end test: multi-hop tunnel forwarding.
//!
//! Wire shape exercised (full path, not mocked):
//!
//! ```text
//! [test driver]                                                    
//!      |                                                            
//!      | drives `initiator.open(target = vps_pk, dest = echo_addr)` 
//!      v                                                            
//! [terminal]──Noise_IK/UDP──▶[midbox]──Noise_IK/UDP──▶[vps]──TCP──▶[echo]
//!  initiator      chain client         chain client    terminator    backend
//!                 +acceptor            +acceptor                     
//!                 +forwarder           +tunnel mgr                   
//! ```
//!
//! The midbox is the unit under test. It receives `TunnelOpen` from
//! the terminal with `target_pubkey == vps_pk`, sees that it is *not*
//! its own pubkey, mints a fresh upstream `stream_id`, re-serialises
//! the open, sends it to the vps, and registers the bidirectional
//! mapping. Subsequent `TunnelData` envelopes in both directions are
//! re-written between the two stream-id spaces. The test asserts that
//! a "hello, tunnel!" round-trip lands on the loopback echo backend
//! and comes back unmodified.
//!
//! Test mechanics:
//! 1. Spawn a loopback TCP echo backend on the vps.
//! 2. Spawn the vps as a pure terminator (HeartbeatServer +
//!    ChainAcceptor + TunnelManager). It authorises the midbox's
//!    static pubkey as its downstream.
//! 3. Spawn the midbox: HeartbeatServer + ChainAcceptor (no
//!    TunnelManager — its own loopback is not the target) +
//!    ChainClient (upstream = vps) + TunnelForwarder wiring the two
//!    together. The midbox authorises the terminal's static pubkey
//!    as its downstream.
//! 4. Build a ChainClient on the terminal side with a TunnelInitiator
//!    body handler; drive `initiator.open(target = vps_pk, dest =
//!    echo_addr)`. Wait for the open to land via the midbox at the
//!    vps's terminator and the echo backend to dial successfully.
//! 5. Round-trip a payload through the forwarder and assert the bytes
//!    come back unmodified.

mod common;

use std::sync::Arc;
use std::time::Duration;

use ratatoskr::auth::StaticKeyPair;
use ratatoskr::pubkey::PubKey;
use tokio_util::sync::CancellationToken;

use yggdrasil::chain::{
    combined_tunnel_body_handler, ChainAcceptor, ChainClient, ChainClientConfig,
    DeriveConfig, TunnelAllowList, TunnelForwarder, TunnelInitiator, TunnelManager,
};
use yggdrasil::heartbeat::{HeartbeatServer, PeerState};
use yggdrasil::pending_peers::PendingPeerStore;
use yggdrasil::proxy::resolver::ResolverFactory;
use yggdrasil::proxy::supervisor::{CertConfig, ProxySupervisor};

use common::{clone_kp, echo_tcp_listener, spawn_tcp_echo};

/// Spawn a terminal-style "vps" node: HeartbeatServer + ChainAcceptor +
/// TunnelManager with loopback-only allow-list. Authorises
/// `downstream_pub` (the midbox's static pubkey) as the downstream.
///
/// The vps has no chain upstream of its own — it is a leaf-terminator.
/// Returns its listen address and static keys so the midbox can dial
/// it.
async fn spawn_vps_terminator(
    downstream_pub: [u8; 32],
) -> (
    std::net::SocketAddr,
    StaticKeyPair,
    CancellationToken,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let vps_keys = StaticKeyPair::generate().unwrap();
    let peer_state = PeerState::new(downstream_pub);
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
    .expect("spawn vps supervisor");
    std::mem::forget(rules_dir);

    let state_dir = tempfile::tempdir().unwrap();
    let derive_cfg = DeriveConfig {
        bind_addr: "127.0.0.1".parse().unwrap(),
        proxy_protocol: None,
    };
    let acceptor = ChainAcceptor::load(
        supervisor.handle(),
        derive_cfg,
        state_dir.path(),
        PubKey::x25519(*vps_keys.public_key()),
    )
    .expect("load vps acceptor");
    std::mem::forget(state_dir);

    let (hb, outbound) = HeartbeatServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        clone_kp(&vps_keys),
        peer_state.clone(),
        pending_store,
        Some(acceptor.clone()),
        cancel.clone(),
    )
    .await
    .expect("bind vps heartbeat");
    let vps_addr = hb.local_addr().unwrap();

    let mgr = TunnelManager::new(
        TunnelAllowList::loopback_only(),
        PubKey::x25519(*vps_keys.public_key()),
        outbound.sender(),
    );
    acceptor
        .set_tunnel_manager(mgr)
        .expect("attach vps tunnel manager");

    let hb_join = tokio::spawn(hb.run());
    (vps_addr, vps_keys, cancel, hb_join)
}

/// Spawn a "midbox" relay that has both a downstream chain listener
/// (accepting from `downstream_pub`) AND an outbound chain client
/// pointing at the vps (`vps_addr` + `vps_pubkey`). The midbox does
/// NOT terminate tunnels locally — its acceptor only attaches a
/// [`TunnelForwarder`], so any `TunnelOpen` it receives must be
/// routed upstream.
///
/// Caller supplies `midbox_keys` so the same pubkey is authorised
/// downstream at the vps and bound on the midbox's listener.
///
/// Returns:
/// * Midbox listen address.
/// * Cancel + join handles for both the heartbeat server and the
///   chain client tasks.
#[allow(clippy::too_many_arguments)]
async fn spawn_midbox_forwarder(
    midbox_keys: StaticKeyPair,
    downstream_pub: [u8; 32],
    vps_addr: std::net::SocketAddr,
    vps_pubkey: [u8; 32],
) -> (
    std::net::SocketAddr,
    CancellationToken,
    tokio::task::JoinHandle<anyhow::Result<()>>,
    tokio::task::JoinHandle<()>,
) {
    let peer_state = PeerState::new(downstream_pub);
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
    .expect("spawn midbox supervisor");
    std::mem::forget(rules_dir);

    let state_dir = tempfile::tempdir().unwrap();
    let derive_cfg = DeriveConfig {
        bind_addr: "127.0.0.1".parse().unwrap(),
        proxy_protocol: None,
    };
    let acceptor = ChainAcceptor::load(
        supervisor.handle(),
        derive_cfg,
        state_dir.path(),
        PubKey::x25519(*midbox_keys.public_key()),
    )
    .expect("load midbox acceptor");
    std::mem::forget(state_dir);

    let (hb, outbound) = HeartbeatServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        clone_kp(&midbox_keys),
        peer_state.clone(),
        pending_store,
        Some(acceptor.clone()),
        cancel.clone(),
    )
    .await
    .expect("bind midbox heartbeat");
    let midbox_addr = hb.local_addr().unwrap();

    // Build the upstream chain client (midbox → vps) without spawning;
    // the forwarder needs the live handle before the chain client's
    // run loop begins.
    let chain_cfg = ChainClientConfig {
        endpoint: vps_addr.to_string(),
        upstream_pubkey: vps_pubkey,
        local_keys: clone_kp(&midbox_keys),
        heartbeat_interval: Duration::from_millis(200),
        rekey_interval: Duration::from_secs(120),
        body_handler: None,
    };
    let mut chain_client = ChainClient::new(chain_cfg, cancel.clone());
    let chain_handle = chain_client.handle();
    let chain_initiator =
        TunnelInitiator::new(chain_handle.clone(), PubKey::x25519(vps_pubkey));

    // Attach the forwarder: midbox's downstream is the terminal, its
    // upstream is the vps.
    let forwarder = TunnelForwarder::new(
        chain_handle.clone(),
        outbound.sender(),
        PubKey::x25519(*midbox_keys.public_key()),
        chain_initiator.stream_id_allocator(),
    );
    acceptor
        .set_tunnel_forwarder(forwarder.clone())
        .expect("attach midbox forwarder");

    // Combined body handler so the upstream → midbox direction routes
    // back through the forwarder. Initiator is included for symmetry
    // (the midbox has no locally-originated tunnels in this test, but
    // production midboxes can have both).
    chain_client.set_body_handler(combined_tunnel_body_handler(
        chain_initiator.clone(),
        Some(forwarder),
    ));

    let hb_join = tokio::spawn(hb.run());
    let chain_join = tokio::spawn(async move {
        let _ = chain_client.run().await;
    });

    (midbox_addr, cancel, hb_join, chain_join)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forwarder_round_trips_data_through_three_node_chain() {
    // 1. Loopback echo backend (on the "vps").
    let (listener, echo_addr) = echo_tcp_listener().await;
    let _echo_task = spawn_tcp_echo(listener);

    // 2. Spawn the vps terminator. Its downstream is the midbox; we
    //    pre-generate the midbox keypair so the vps's PeerState can
    //    authorise the same pubkey the midbox will actually present.
    let midbox_keys = StaticKeyPair::generate().unwrap();
    let midbox_pubkey_bytes = *midbox_keys.public_key();
    let (vps_addr, vps_keys, vps_cancel, vps_hb_join) =
        spawn_vps_terminator(midbox_pubkey_bytes).await;

    // 3. Spawn the midbox forwarder. Its downstream is the terminal,
    //    its upstream is the vps. Hands its keys in so the same
    //    pubkey the vps authorised lands on the midbox's listener.
    let terminal_keys = StaticKeyPair::generate().unwrap();
    let (midbox_addr, midbox_cancel, midbox_hb_join, midbox_chain_join) =
        spawn_midbox_forwarder(
            clone_kp(&midbox_keys),
            *terminal_keys.public_key(),
            vps_addr,
            *vps_keys.public_key(),
        )
        .await;

    // 4. Terminal-side ChainClient + TunnelInitiator pointing at the
    //    midbox. We target the *vps* pubkey, not the midbox's, so the
    //    midbox is forced into the forwarder code path. Phase 5
    //    removed the v1 single-hop guard from
    //    `TunnelInitiator::open`, so the initiator emits whatever
    //    `target_pubkey` we pass onto the wire verbatim.
    let terminal_cancel = CancellationToken::new();
    let cfg = ChainClientConfig {
        endpoint: midbox_addr.to_string(),
        upstream_pubkey: midbox_pubkey_bytes,
        local_keys: terminal_keys,
        heartbeat_interval: Duration::from_millis(200),
        rekey_interval: Duration::from_secs(120),
        body_handler: None,
    };
    let mut terminal_client = ChainClient::new(cfg, terminal_cancel.clone());
    let terminal_handle = terminal_client.handle();
    // The initiator's *configured* upstream is the midbox, but we will
    // override `target_pubkey` per-envelope to point at the vps.
    let initiator = TunnelInitiator::new(
        terminal_handle.clone(),
        PubKey::x25519(midbox_pubkey_bytes),
    );
    terminal_client.set_body_handler(initiator.body_handler());
    let terminal_join = tokio::spawn(async move {
        let _ = terminal_client.run().await;
    });

    // Allow both chain client handshakes to complete (terminal→midbox
    // and midbox→vps). 1.5s is generous; production handshakes are
    // sub-100ms on loopback.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // 5. Open a tunnel targeting the *vps* (multi-hop).
    let vps_pubkey = PubKey::x25519(*vps_keys.public_key());
    let stream = tokio::time::timeout(
        Duration::from_secs(5),
        initiator.open(vps_pubkey, echo_addr),
    )
    .await
    .expect("open() resolved within deadline")
    .expect("open() succeeded across the forwarded chain");
    let stream_id = stream.stream_id;
    let mut inbound_rx = stream.inbound_rx;

    // 6. Round-trip a payload.
    let payload = b"hello, forwarder e2e!".to_vec();
    tokio::time::timeout(
        Duration::from_secs(5),
        initiator.send_data(stream_id, payload.clone()),
    )
    .await
    .expect("send_data resolved within deadline")
    .expect("send_data succeeded across the forwarded chain");

    let echoed = tokio::time::timeout(Duration::from_secs(5), async {
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

    // 7. Clean close.
    initiator.close(stream_id, 0).await;

    // Teardown.
    terminal_cancel.cancel();
    midbox_cancel.cancel();
    vps_cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), terminal_join).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), midbox_chain_join).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), midbox_hb_join).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), vps_hb_join).await;
    let _ = midbox_keys; // touch unused binding in the happy path
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forwarder_rejects_open_when_dest_outside_terminator_allow_list() {
    // Same topology as above but target a non-loopback dest so the vps
    // rejects with TARGET_NOT_ALLOWED; the midbox should propagate
    // that reject reason verbatim back to the terminal so the
    // operator's error message is faithful to the actual cause.

    let midbox_keys = StaticKeyPair::generate().unwrap();
    let midbox_pubkey_bytes = *midbox_keys.public_key();
    let (vps_addr, vps_keys, vps_cancel, vps_hb_join) =
        spawn_vps_terminator(midbox_pubkey_bytes).await;

    let terminal_keys = StaticKeyPair::generate().unwrap();
    let (midbox_addr, midbox_cancel, midbox_hb_join, midbox_chain_join) =
        spawn_midbox_forwarder(
            clone_kp(&midbox_keys),
            *terminal_keys.public_key(),
            vps_addr,
            *vps_keys.public_key(),
        )
        .await;

    let terminal_cancel = CancellationToken::new();
    let cfg = ChainClientConfig {
        endpoint: midbox_addr.to_string(),
        upstream_pubkey: midbox_pubkey_bytes,
        local_keys: terminal_keys,
        heartbeat_interval: Duration::from_millis(200),
        rekey_interval: Duration::from_secs(120),
        body_handler: None,
    };
    let mut terminal_client = ChainClient::new(cfg, terminal_cancel.clone());
    let terminal_handle = terminal_client.handle();
    let initiator = TunnelInitiator::new(
        terminal_handle.clone(),
        PubKey::x25519(midbox_pubkey_bytes),
    );
    terminal_client.set_body_handler(initiator.body_handler());
    let terminal_join = tokio::spawn(async move {
        let _ = terminal_client.run().await;
    });

    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Non-loopback dest: RFC1918 10.x is rejected by the vps's
    // loopback-only allow-list.
    let bad_dest: std::net::SocketAddr = "10.255.255.1:65535".parse().unwrap();
    let vps_pubkey = PubKey::x25519(*vps_keys.public_key());
    let err = initiator
        .open(vps_pubkey, bad_dest)
        .await
        .expect_err("open of non-loopback should be rejected by terminator (via forwarder)");
    use ratatoskr::tunnel::tunnel_reject;
    match err {
        yggdrasil::chain::OpenError::Rejected(code) => {
            assert_eq!(
                code,
                tunnel_reject::TARGET_NOT_ALLOWED,
                "expected TARGET_NOT_ALLOWED propagated from vps through midbox; \
                 got 0x{code:04x}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }

    // Teardown.
    terminal_cancel.cancel();
    midbox_cancel.cancel();
    vps_cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), terminal_join).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), midbox_chain_join).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), midbox_hb_join).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), vps_hb_join).await;
    let _ = midbox_keys;
}
