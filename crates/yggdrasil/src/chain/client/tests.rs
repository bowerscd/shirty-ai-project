//! Integration tests for [`ChainClient`].
//!

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use ratatoskr::auth::{Responder, Session, StaticKeyPair};
use ratatoskr::control_frame::{AckStatus, ControlAck};
use ratatoskr::pubkey::PubKey;
use ratatoskr::wire::{self, PacketType};

use crate::chain::reliability::InboundDisposition;

use super::{ChainClient, ChainClientConfig};

/// Minimal echo-style upstream responder for testing. Accepts any
/// caller, answers Handshake1 with Handshake2 (verifying remote static
/// key), then ACKs every heartbeat.
struct TestServer {
    addr: SocketAddr,
    handle: tokio::task::JoinHandle<()>,
    heartbeats_seen: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl TestServer {
    async fn start(server_keys: StaticKeyPair) -> Self {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let heartbeats_seen = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let heartbeats_seen_task = heartbeats_seen.clone();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut session: Option<Session> = None;
            loop {
                let (n, from) = match sock.recv_from(&mut buf).await {
                    Ok(r) => r,
                    Err(_) => return,
                };
                let view = match wire::parse(&buf[..n]) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                match view.packet_type {
                    PacketType::Handshake1 => {
                        let half = Responder::process_handshake_1(&server_keys, &view).unwrap();
                        let (s, reply) = half.complete().unwrap();
                        sock.send_to(&reply, from).await.unwrap();
                        session = Some(s);
                    }
                    PacketType::Heartbeat => {
                        if let Some(s) = session.as_mut() {
                            let hb = s.decode_heartbeat(&view).unwrap();
                            heartbeats_seen_task.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let (_, ack) = s.encode_heartbeat_ack(hb.counter, 12345).unwrap();
                            sock.send_to(&ack, from).await.unwrap();
                        }
                    }
                    _ => {}
                }
            }
        });
        Self {
            addr,
            handle,
            heartbeats_seen,
        }
    }

    async fn stop(self) {
        self.handle.abort();
        let _ = self.handle.await;
    }
}

#[tokio::test]
async fn handshake_then_heartbeat_ack_roundtrip() {
    let server_keys = StaticKeyPair::generate().unwrap();
    let client_keys = StaticKeyPair::generate().unwrap();
    let server_pub = server_keys.public_key();

    let server = TestServer::start(server_keys).await;
    let endpoint = server.addr.to_string();

    let cancel = CancellationToken::new();
    let cfg = ChainClientConfig {
        endpoint,
        upstream_pubkey: server_pub,
        local_keys: client_keys,
        heartbeat_interval: Duration::from_millis(50),
        rekey_interval: Duration::from_secs(60),
        body_handler: None,
        local_bind: None,
    };
    let client = ChainClient::new(cfg, cancel.clone());
    let client_handle = tokio::spawn(async move { client.run().await });

    let deadline = Instant::now() + Duration::from_secs(3);
    while server
        .heartbeats_seen
        .load(std::sync::atomic::Ordering::Relaxed)
        < 3
    {
        if Instant::now() > deadline {
            panic!(
                "timeout; saw only {} heartbeats",
                server
                    .heartbeats_seen
                    .load(std::sync::atomic::Ordering::Relaxed)
            );
        }
        // Bounded poll on an atomic counter; no notify channel.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), client_handle).await;
    server.stop().await;
}

#[tokio::test]
async fn rekey_triggers_a_second_handshake() {
    let server_keys = StaticKeyPair::generate().unwrap();
    let client_keys = StaticKeyPair::generate().unwrap();
    let server_pub = server_keys.public_key();

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let handshakes = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let handshakes_task = handshakes.clone();
    let server_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut session: Option<Session> = None;
        loop {
            let (n, from) = match sock.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => return,
            };
            let view = match wire::parse(&buf[..n]) {
                Ok(v) => v,
                Err(_) => continue,
            };
            match view.packet_type {
                PacketType::Handshake1 => {
                    handshakes_task.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let half = Responder::process_handshake_1(&server_keys, &view).unwrap();
                    let (s, reply) = half.complete().unwrap();
                    sock.send_to(&reply, from).await.unwrap();
                    session = Some(s);
                }
                PacketType::Heartbeat => {
                    if let Some(s) = session.as_mut() {
                        if let Ok(hb) = s.decode_heartbeat(&view) {
                            let (_, ack) = s.encode_heartbeat_ack(hb.counter, 0).unwrap();
                            sock.send_to(&ack, from).await.unwrap();
                        }
                    }
                }
                _ => {}
            }
        }
    });

    let cancel = CancellationToken::new();
    let cfg = ChainClientConfig {
        endpoint: addr.to_string(),
        upstream_pubkey: server_pub,
        local_keys: client_keys,
        heartbeat_interval: Duration::from_millis(20),
        rekey_interval: Duration::from_millis(200),
        body_handler: None,
        local_bind: None,
    };
    let client = ChainClient::new(cfg, cancel.clone());
    let client_handle = tokio::spawn(async move { client.run().await });

    let deadline = Instant::now() + Duration::from_secs(3);
    while handshakes.load(std::sync::atomic::Ordering::Relaxed) < 2 {
        if Instant::now() > deadline {
            panic!(
                "timeout; saw only {} handshakes",
                handshakes.load(std::sync::atomic::Ordering::Relaxed)
            );
        }
        // Bounded poll on an atomic counter; no notify channel.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), client_handle).await;
    server_task.abort();
}

#[tokio::test]
async fn cancel_token_stops_client_promptly() {
    let server_keys = StaticKeyPair::generate().unwrap();
    let client_keys = StaticKeyPair::generate().unwrap();
    let server_pub = server_keys.public_key();
    let server = TestServer::start(server_keys).await;

    let cancel = CancellationToken::new();
    let cfg = ChainClientConfig {
        endpoint: server.addr.to_string(),
        upstream_pubkey: server_pub,
        local_keys: client_keys,
        heartbeat_interval: Duration::from_millis(50),
        rekey_interval: Duration::from_secs(60),
        body_handler: None,
        local_bind: None,
    };
    let client = ChainClient::new(cfg, cancel.clone());
    let client_handle = tokio::spawn(async move { client.run().await });

    // Give the client task a window to drive its first handshake +
    // heartbeat before we cancel; without it we'd be testing cancel-on-
    // startup not cancel-mid-session. The assertion below bounds the
    // post-cancel exit latency at 1 s.
    tokio::time::sleep(Duration::from_millis(150)).await;
    cancel.cancel();

    let start = Instant::now();
    let res = tokio::time::timeout(Duration::from_secs(2), client_handle).await;
    assert!(res.is_ok(), "client did not exit within 2s of cancel");
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "client took {:?} to exit after cancel",
        start.elapsed()
    );
    server.stop().await;
}

#[tokio::test]
async fn reconnect_now_triggers_immediate_rehandshake() {
    // Reconnect signal must short-circuit the ack-deadline wait: a
    // call to `ChainClientHandle::reconnect_now()` should cause the
    // chain client to abandon its current session and re-handshake
    // within ~1s, not wait out the ack-deadline (which at the test's
    // 50ms heartbeat × default ACK_DEADLINE_MULTIPLIER=6 would still
    // be 300ms — but the *signal-path* assertion is "the next
    // handshake happens because we asked for it, not because
    // detection fired").
    let server_keys = StaticKeyPair::generate().unwrap();
    let client_keys = StaticKeyPair::generate().unwrap();
    let server_pub = server_keys.public_key();

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let handshakes = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let handshakes_task = handshakes.clone();
    let server_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut session: Option<Session> = None;
        loop {
            let (n, from) = match sock.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => return,
            };
            let view = match wire::parse(&buf[..n]) {
                Ok(v) => v,
                Err(_) => continue,
            };
            match view.packet_type {
                PacketType::Handshake1 => {
                    handshakes_task.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let half = Responder::process_handshake_1(&server_keys, &view).unwrap();
                    let (s, reply) = half.complete().unwrap();
                    sock.send_to(&reply, from).await.unwrap();
                    session = Some(s);
                }
                PacketType::Heartbeat => {
                    if let Some(s) = session.as_mut() {
                        if let Ok(hb) = s.decode_heartbeat(&view) {
                            let (_, ack) = s.encode_heartbeat_ack(hb.counter, 0).unwrap();
                            sock.send_to(&ack, from).await.unwrap();
                        }
                    }
                }
                _ => {}
            }
        }
    });

    let cancel = CancellationToken::new();
    let cfg = ChainClientConfig {
        endpoint: addr.to_string(),
        upstream_pubkey: server_pub,
        local_keys: client_keys,
        heartbeat_interval: Duration::from_millis(100),
        // Rekey far enough out that it doesn't race the test.
        rekey_interval: Duration::from_secs(60),
        body_handler: None,
        local_bind: None,
    };
    let client = ChainClient::new(cfg, cancel.clone());
    let handle = client.handle();
    let client_task = tokio::spawn(async move { client.run().await });

    // Wait for the first handshake to complete + a heartbeat ack to
    // come back; ensures the client is firmly in the steady-state
    // session loop before we nudge.
    let deadline = Instant::now() + Duration::from_secs(2);
    while handshakes.load(std::sync::atomic::Ordering::Relaxed) < 1 {
        if Instant::now() > deadline {
            panic!("first handshake never completed");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Let one heartbeat round-trip so the client has a live
    // `last_ack_at` (otherwise we're testing reconnect-mid-handshake,
    // which is a different path).
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        handshakes.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "session should still be on its first handshake"
    );

    // Fire the reconnect signal. Expectation: the client returns
    // SessionExit::ReconnectRequested from heartbeat_loop on its next
    // scheduler tick, the outer run() resets backoff to BACKOFF_MIN
    // (no sleep), and `run_session_once` issues handshake #2.
    let nudge_at = Instant::now();
    handle.reconnect_now();

    let deadline = nudge_at + Duration::from_secs(2);
    while handshakes.load(std::sync::atomic::Ordering::Relaxed) < 2 {
        if Instant::now() > deadline {
            panic!(
                "second handshake never fired (saw {} handshakes)",
                handshakes.load(std::sync::atomic::Ordering::Relaxed)
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let elapsed = nudge_at.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "second handshake took {elapsed:?} after nudge; \
         expected near-instant (<500ms) — reconnect signal isn't \
         short-circuiting the session loop"
    );

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), client_task).await;
    server_task.abort();
}

#[tokio::test]
async fn reconnect_now_during_backoff_loop_does_not_panic() {
    // The reconnect signal lives on the chain client, which means
    // `reconnect_now()` is safe to call regardless of whether the
    // client is mid-session, mid-handshake, or mid-backoff. Edge case:
    // calling it while the outer `run()` is parked in
    // `sleep_or_cancel(&cancel, backoff)` should not panic and should
    // not change behaviour (the signal is only consumed inside
    // `heartbeat_loop`'s select; the outer sleep ignores it).
    //
    // We can't directly observe "backoff is in progress" — the
    // existing `backoff_and_reconnect_when_endpoint_unresponsive`
    // test asserts "task is still alive after 300ms" against the
    // same setup. We piggyback on that pattern and assert that
    // firing `reconnect_now()` mid-backoff doesn't panic the task.
    let client_keys = StaticKeyPair::generate().unwrap();

    let cancel = CancellationToken::new();
    let cfg = ChainClientConfig {
        endpoint: "127.0.0.1:1".to_string(),
        upstream_pubkey: PubKey::x25519([0u8; 32]),
        local_keys: client_keys,
        heartbeat_interval: Duration::from_millis(50),
        rekey_interval: Duration::from_secs(60),
        body_handler: None,
        local_bind: None,
    };
    let client = ChainClient::new(cfg, cancel.clone());
    let handle = client.handle();
    let client_task = tokio::spawn(async move { client.run().await });

    // Let the client cycle through several failed handshake attempts
    // so we're confidently inside the backoff path.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        !client_task.is_finished(),
        "client should still be retrying"
    );

    // Fire the signal repeatedly; each call must be a no-op (the
    // outer sleep_or_cancel doesn't consume the signal, but the
    // signal is also edge-triggered so multiple calls collapse).
    for _ in 0..5 {
        handle.reconnect_now();
    }

    // Task is still alive and well; cancel as the test finalizer.
    assert!(
        !client_task.is_finished(),
        "client task crashed after reconnect_now during backoff"
    );

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(8), client_task).await;
}

#[tokio::test]
async fn fast_probe_bails_faster_than_backstop_when_upstream_goes_silent() {
    // After two healthy round-trips the upstream stops ACKing. The
    // fast-probe path (fires an extra heartbeat after
    // FAST_PROBE_AFTER_MULTIPLIER × heartbeat of silence, then bails
    // FAST_PROBE_DEADLINE_MULTIPLIER × heartbeat later if the probe
    // ACK doesn't arrive) should declare the session dead at
    // roughly (FAST_PROBE_AFTER + FAST_PROBE_DEADLINE) × heartbeat,
    // vs the backstop's ACK_DEADLINE_MULTIPLIER × heartbeat.
    //
    // We observe via the handshake count: a bailed session triggers
    // the outer `run()` to sleep `BACKOFF_MIN` then re-handshake,
    // bumping `handshakes` from 1 to 2.
    //
    // Heartbeat = 500ms, so the fast-probe path's deterministic
    // schedule (factoring in tick alignment ~1 tick of jitter) is:
    //   - last ack at ~t=0.55
    //   - probe fires at ~t=2.0  (since_ack=1.45 > fast_probe_after=1.0)
    //   - bail at      ~t=3.0    (probe_pending.elapsed=1.0 > fast_probe_deadline=0.5)
    //   - re-handshake at ~t=3.5 (BACKOFF_MIN = 500ms)
    // Backstop would bail at ~t=4.0 (since_ack > ACK_DEADLINE=3s),
    // re-handshake at ~t=4.5.
    // Budget: 4s from test start. Beats backstop's ~4.5s by enough
    // to distinguish even on a moderately loaded runner; if this
    // assertion starts failing on slow CI, widen the slack BUT
    // verify the FAST_PROBE_* multipliers haven't regressed first.
    let server_keys = StaticKeyPair::generate().unwrap();
    let client_keys = StaticKeyPair::generate().unwrap();
    let server_pub = server_keys.public_key();

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let handshakes = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let ack_heartbeats = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let heartbeats_received = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let handshakes_task = handshakes.clone();
    let heartbeats_task = heartbeats_received.clone();
    let ack_flag = ack_heartbeats.clone();
    let server_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut session: Option<Session> = None;
        loop {
            let (n, from) = match sock.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => return,
            };
            let view = match wire::parse(&buf[..n]) {
                Ok(v) => v,
                Err(_) => continue,
            };
            match view.packet_type {
                PacketType::Handshake1 => {
                    handshakes_task.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let half = Responder::process_handshake_1(&server_keys, &view).unwrap();
                    let (s, reply) = half.complete().unwrap();
                    sock.send_to(&reply, from).await.unwrap();
                    session = Some(s);
                    // Re-arm acks on each new session so the
                    // post-bail re-handshake doesn't tear back down
                    // before we can observe it.
                    ack_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                    heartbeats_task.store(0, std::sync::atomic::Ordering::Relaxed);
                }
                PacketType::Heartbeat => {
                    let count =
                        heartbeats_task.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                    // Ack the first two heartbeats; black-hole the
                    // rest (incl. the fast probe). Simulates an
                    // upstream that's silently dropped off the
                    // network.
                    if count > 2 {
                        ack_flag.store(false, std::sync::atomic::Ordering::Relaxed);
                    }
                    if ack_flag.load(std::sync::atomic::Ordering::Relaxed) {
                        if let Some(s) = session.as_mut() {
                            if let Ok(hb) = s.decode_heartbeat(&view) {
                                let (_, ack) = s.encode_heartbeat_ack(hb.counter, 0).unwrap();
                                sock.send_to(&ack, from).await.unwrap();
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    });

    let cancel = CancellationToken::new();
    let cfg = ChainClientConfig {
        endpoint: addr.to_string(),
        upstream_pubkey: server_pub,
        local_keys: client_keys,
        heartbeat_interval: Duration::from_millis(500),
        rekey_interval: Duration::from_secs(600),
        body_handler: None,
        local_bind: None,
    };
    let client = ChainClient::new(cfg, cancel.clone());
    let test_started = Instant::now();
    let client_task = tokio::spawn(async move { client.run().await });

    // Expect the second handshake within 4s of test start. See the
    // comment block above for the timing breakdown vs the backstop.
    let deadline = test_started + Duration::from_secs(4);
    while handshakes.load(std::sync::atomic::Ordering::Relaxed) < 2 {
        if Instant::now() > deadline {
            panic!(
                "fast-probe did not bail in time: {} handshakes after {:?} (backstop would need ~4.5s, \
                 so the fast-probe path may have regressed)",
                handshakes.load(std::sync::atomic::Ordering::Relaxed),
                test_started.elapsed(),
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let elapsed = test_started.elapsed();
    assert!(
        elapsed < Duration::from_secs(4),
        "fast-probe re-handshake took {elapsed:?}; expected < 4s"
    );

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), client_task).await;
    server_task.abort();
}

#[tokio::test]
async fn fast_probe_does_not_fire_when_upstream_is_healthy() {
    // No probe should fire on a healthy connection: each heartbeat
    // gets ACK'd well within FAST_PROBE_AFTER, so `last_ack_at`
    // refreshes and `probe_pending_since` stays None. Observe by
    // counting heartbeats received over a window and asserting it
    // equals N (not N + extra probes).
    //
    // Heartbeat = 100ms, observe for 1s = ~10 heartbeats expected.
    // Tolerate +2 jitter for tick alignment.
    let server_keys = StaticKeyPair::generate().unwrap();
    let client_keys = StaticKeyPair::generate().unwrap();
    let server_pub = server_keys.public_key();
    let server = TestServer::start(server_keys).await;

    let cancel = CancellationToken::new();
    let cfg = ChainClientConfig {
        endpoint: server.addr.to_string(),
        upstream_pubkey: server_pub,
        local_keys: client_keys,
        heartbeat_interval: Duration::from_millis(100),
        rekey_interval: Duration::from_secs(60),
        body_handler: None,
        local_bind: None,
    };
    let client = ChainClient::new(cfg, cancel.clone());
    let client_task = tokio::spawn(async move { client.run().await });

    tokio::time::sleep(Duration::from_millis(1_000)).await;
    let count = server
        .heartbeats_seen
        .load(std::sync::atomic::Ordering::Relaxed);
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), client_task).await;
    server.stop().await;

    // Healthy: ~10 ± 2. The sharper assertion: count must be < 13
    // (well under what we'd see if the probe fired every other
    // heartbeat — that would push to ~15-20).
    assert!(
        (8..=12).contains(&count),
        "expected ~10 heartbeats on healthy session, got {count}; \
         either timing is way off or fast-probe is firing spuriously"
    );
}

#[tokio::test]
async fn backoff_and_reconnect_when_endpoint_unresponsive() {
    let client_keys = StaticKeyPair::generate().unwrap();

    let cancel = CancellationToken::new();
    let cfg = ChainClientConfig {
        endpoint: "127.0.0.1:1".to_string(),
        upstream_pubkey: PubKey::x25519([0u8; 32]),
        local_keys: client_keys,
        heartbeat_interval: Duration::from_millis(50),
        rekey_interval: Duration::from_secs(60),
        body_handler: None,
        local_bind: None,
    };
    let client = ChainClient::new(cfg, cancel.clone());
    let client_handle = tokio::spawn(async move { client.run().await });

    // Tests the backoff path on an unresponsive endpoint: the client
    // must NOT exit during this window — it should retry per the
    // configured backoff. There's no observable signal for "i am
    // currently backing off," so the irreducible test is "wait past
    // at least one backoff cycle and confirm the task is still alive."
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !client_handle.is_finished(),
        "client should not have exited yet"
    );

    cancel.cancel();
    let res = tokio::time::timeout(Duration::from_secs(8), client_handle).await;
    assert!(res.is_ok(), "client did not stop within 8s of cancel");
}

/// Echo-style server that completes the chain handshake, acks every
/// heartbeat, decodes inbound `Control` envelopes, dispatches them
/// through a [`ControlChannel`] for dedup, and replies with a
/// `ControlAck` whose status reflects the body type. Lossy variants
/// drop a configurable fraction of inbound and outbound packets to
/// exercise the retransmit + dedup paths.
///
/// Loss decisions use a seeded [`StdRng`] so the drop pattern is
/// deterministic for a given `(loss_pct, seed)` pair — running the
/// lossy test twice yields the same dropped-packet sequence. This
/// matters because at 10% per-direction loss with the production
/// 5-attempt retransmit budget, the round-trip failure probability
/// per envelope is `(1 - 0.9 * 0.9)^5 ≈ 2.5e-4`; over 1000 envelopes,
/// `P(≥1 timeout) ≈ 22%`. Non-deterministic loss makes the test flake
/// roughly one run in five.
///
/// [`ControlChannel`]: crate::chain::reliability::ControlChannel
/// [`StdRng`]: rand::rngs::StdRng
struct ControlTestServer {
    addr: SocketAddr,
    handle: tokio::task::JoinHandle<()>,
}

impl ControlTestServer {
    async fn start_with_loss(server_keys: StaticKeyPair, loss_pct: u32, seed: u64) -> Self {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};
        use ratatoskr::control_frame::{ControlBodyType, ControlEnvelope};
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut session: Option<Session> = None;
            let mut channel = crate::chain::reliability::ControlChannel::new();
            let mut rng = StdRng::seed_from_u64(seed);
            loop {
                let (n, from) = match sock.recv_from(&mut buf).await {
                    Ok(r) => r,
                    Err(_) => return,
                };
                // Inbound loss injection.
                if loss_pct > 0 && rng.gen_range(0..100) < loss_pct {
                    continue;
                }
                let view = match wire::parse(&buf[..n]) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                match view.packet_type {
                    PacketType::Handshake1 => {
                        let half = match Responder::process_handshake_1(&server_keys, &view) {
                            Ok(h) => h,
                            Err(_) => continue,
                        };
                        if let Ok((s, reply)) = half.complete() {
                            let _ = sock.send_to(&reply, from).await;
                            session = Some(s);
                        }
                    }
                    PacketType::Heartbeat => {
                        if let Some(s) = session.as_mut() {
                            if let Ok(hb) = s.decode_heartbeat(&view) {
                                if let Ok((_, ack)) = s.encode_heartbeat_ack(hb.counter, 0) {
                                    // Outbound loss injection.
                                    if loss_pct > 0 && rng.gen_range(0..100) < loss_pct {
                                        continue;
                                    }
                                    let _ = sock.send_to(&ack, from).await;
                                }
                            }
                        }
                    }
                    PacketType::Control => {
                        let Some(s) = session.as_mut() else { continue };
                        let env: ControlEnvelope = match s.decode_control(&view) {
                            Ok(e) => e,
                            Err(_) => continue,
                        };
                        let seq = env.seq;
                        let status = match channel.on_inbound(env) {
                            InboundDisposition::Deliver(env) => {
                                match ControlBodyType::from_byte(env.body_type) {
                                    Some(ControlBodyType::Noop) => AckStatus::Ok,
                                    _ => AckStatus::Unknown,
                                }
                            }
                            InboundDisposition::Duplicate => AckStatus::Ok,
                        };
                        let ack = ControlAck { seq, status };
                        if let Ok((_, packet)) = s.encode_control_ack(&ack) {
                            if loss_pct > 0 && rng.gen_range(0..100) < loss_pct {
                                continue;
                            }
                            let _ = sock.send_to(&packet, from).await;
                        }
                    }
                    _ => {}
                }
            }
        });
        Self { addr, handle }
    }

    async fn stop(self) {
        self.handle.abort();
        let _ = self.handle.await;
    }
}

/// End-to-end happy path: enqueue 1000 `Noop` control envelopes via the
/// chain client handle, await all completion receivers, assert every
/// one resolved `Ok`. Exercises the full Noise + UDP + reliability path
/// with no loss injected.
///
/// Uses a 200ms heartbeat (→ 1.2s no-ack deadline) rather than the 50ms
/// of other tests, so concurrent test execution can't starve the
/// heartbeat-ack path long enough to bail the session mid-burst.
#[tokio::test]
async fn control_send_handle_resolves_one_thousand_noop_envelopes() {
    use ratatoskr::control_frame::ControlBodyType;
    let server_keys = StaticKeyPair::generate().unwrap();
    let client_keys = StaticKeyPair::generate().unwrap();
    let server_pub = server_keys.public_key();
    let server = ControlTestServer::start_with_loss(server_keys, 0, 0).await;

    let cancel = CancellationToken::new();
    let cfg = ChainClientConfig {
        endpoint: server.addr.to_string(),
        upstream_pubkey: server_pub,
        local_keys: client_keys,
        heartbeat_interval: Duration::from_millis(200),
        rekey_interval: Duration::from_secs(120),
        body_handler: None,
        local_bind: None,
    };
    let client = ChainClient::new(cfg, cancel.clone());
    let handle = client.handle();
    let client_handle = tokio::spawn(async move { client.run().await });

    // Wait for the handshake to complete: send_control before the
    // session exists fails with ChainClientShutDown. ChainClient
    // exposes no "handshake done" notification today, so 300 ms is
    // the irreducible lossless-handshake budget. (The lossy variant
    // below uses 500 ms for the same reason.)
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut receivers = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let rx = handle
            .send_control(ControlBodyType::Noop.as_byte(), vec![])
            .expect("client task alive");
        receivers.push(rx);
    }

    let deadline = Duration::from_secs(15);
    let mut ok_count = 0usize;
    let join_all = tokio::time::timeout(deadline, async {
        for rx in receivers {
            let r = rx.await.expect("oneshot delivered");
            assert!(r.is_ok(), "send resolved with {r:?}");
            ok_count += 1;
        }
        ok_count
    })
    .await
    .expect("all 1000 sends should resolve within deadline");
    assert_eq!(join_all, 1000);

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), client_handle).await;
    server.stop().await;
}

/// Lossy variant: 10% packet drop in both directions. Retransmit +
/// dedup must converge to "all 1000 sends report `Ok`" within the
/// deadline.
///
/// **Determinism.** Loss decisions use a seeded [`StdRng`] inside
/// the test server (see [`ControlTestServer::start_with_loss`]), so
/// the drop pattern is identical on every run for a given seed.
/// Without that, the math runs the other way: at 10% per-direction
/// loss with the production 5-attempt retransmit budget, the
/// round-trip failure probability per envelope is
/// `(1 - 0.9 * 0.9)^5 ≈ 2.5e-4`, so for 1000 envelopes
/// `P(≥1 timeout) ≈ 22%` — a roughly one-in-five flake rate.
///
/// If you bump `RETX_MAX_ATTEMPTS` or change the loss percentage,
/// re-verify the chosen seed still converges — or pick a new one.
/// Seed 1 has been verified to converge for `(loss_pct = 10,
/// N = 1000)` against the production reliability constants in this
/// tree.
///
/// [`StdRng`]: rand::rngs::StdRng
#[tokio::test]
async fn control_send_converges_under_10_percent_packet_loss() {
    use ratatoskr::control_frame::ControlBodyType;
    let server_keys = StaticKeyPair::generate().unwrap();
    let client_keys = StaticKeyPair::generate().unwrap();
    let server_pub = server_keys.public_key();
    // 10% loss in each direction, deterministic drop pattern.
    let server = ControlTestServer::start_with_loss(server_keys, 10, 1).await;

    let cancel = CancellationToken::new();
    let cfg = ChainClientConfig {
        endpoint: server.addr.to_string(),
        upstream_pubkey: server_pub,
        local_keys: client_keys,
        // Longer heartbeat interval so the ack-deadline (6× hb) outlasts
        // multi-packet drop bursts.
        heartbeat_interval: Duration::from_millis(200),
        rekey_interval: Duration::from_secs(120),
        body_handler: None,
        local_bind: None,
    };
    let client = ChainClient::new(cfg, cancel.clone());
    let handle = client.handle();
    let client_handle = tokio::spawn(async move { client.run().await });

    // Wait for handshake (which may itself need a retry on loss).
    // 500 ms is the lossy-handshake-with-one-retry budget; no
    // observable "handshake done" signal exists on ChainClient.
    tokio::time::sleep(Duration::from_millis(500)).await;

    const N: usize = 1000;
    let mut receivers = Vec::with_capacity(N);
    for _ in 0..N {
        let rx = handle
            .send_control(ControlBodyType::Noop.as_byte(), vec![])
            .expect("client task alive");
        receivers.push(rx);
    }

    let deadline = Duration::from_secs(30);
    let outcomes = tokio::time::timeout(deadline, async {
        let mut results = Vec::with_capacity(N);
        for rx in receivers {
            let r = rx.await.expect("oneshot delivered");
            results.push(r);
        }
        results
    })
    .await
    .expect("all 1000 sends should resolve within 30s under 10% loss");
    let ok = outcomes.iter().filter(|r| r.is_ok()).count();
    assert_eq!(ok, N, "every send should converge to Ok under bounded loss");

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), client_handle).await;
    server.stop().await;
}

/// `ControlClientHandle::send_control` resolves with `ChannelClosed`
/// when the client task exits (cancellation) before processing the op.
/// This is the production "graceful shutdown" path.
#[tokio::test]
async fn pending_sends_resolve_when_session_ends() {
    use ratatoskr::control_frame::ControlBodyType;
    let server_keys = StaticKeyPair::generate().unwrap();
    let client_keys = StaticKeyPair::generate().unwrap();
    let server_pub = server_keys.public_key();
    let server = ControlTestServer::start_with_loss(server_keys, 0, 0).await;

    let cancel = CancellationToken::new();
    let cfg = ChainClientConfig {
        endpoint: server.addr.to_string(),
        upstream_pubkey: server_pub,
        local_keys: client_keys,
        heartbeat_interval: Duration::from_millis(50),
        rekey_interval: Duration::from_secs(60),
        body_handler: None,
        local_bind: None,
    };
    let client = ChainClient::new(cfg, cancel.clone());
    let handle = client.handle();
    let client_handle = tokio::spawn(async move { client.run().await });

    // Wait for handshake (no observable signal; same pattern as the
    // other control-send tests above).
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Enqueue a send, then immediately cancel. The send's completion
    // either arrives Ok (race won) or ChannelClosed (race lost). Both
    // are acceptable; the contract is "never hangs".
    let rx = handle
        .send_control(ControlBodyType::Noop.as_byte(), vec![])
        .expect("client task alive");
    cancel.cancel();
    let res = tokio::time::timeout(Duration::from_secs(3), rx).await;
    assert!(res.is_ok(), "rx must resolve within 3s of cancel");

    let _ = tokio::time::timeout(Duration::from_secs(2), client_handle).await;
    server.stop().await;
}
