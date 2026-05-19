//! Heartbeat UDP server: owns the listening socket and the single Noise
//! session, drives handshakes, and processes inbound heartbeats.
//!
//! All authentication decisions are encapsulated here:
//!
//! * `Handshake1` is accepted only if the peer's static key matches the one
//!   stored in [`PeerState`]. Anything else is dropped at `warn` level. (TOFU
//!   staging via `yggdrasilctl peer approve` lands in Phase 8.)
//! * `Heartbeat` is decrypted with the active session's transport state,
//!   which enforces strict-monotonic replay protection. The cleartext
//!   counter authenticates via the AEAD tag.
//! * `Handshake2` / `HeartbeatAck` are server→client packets; receipt of
//!   either from the peer is a protocol error and the packet is dropped.
//! * `Rekey` from the peer is logged at `debug` and ignored — the peer
//!   should send a fresh `Handshake1` to actually rotate session keys.
//!
//! Re-handshakes are accepted at any time: a valid `Handshake1` replaces
//! the active session atomically. Stale replays of an old `Handshake1`
//! cause a session bounce but no security issue (the attacker cannot decrypt
//! `Handshake2` nor send valid heartbeats without the peer secret).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use ratatoskr::auth::{Responder, Session, StaticKeyPair};
use ratatoskr::wire::{self, PacketType, PacketView};

use super::peer_state::{HeartbeatEffect, PeerState};
use crate::pending_peers::PendingPeerStore;

/// Heartbeat UDP server. Construct with [`HeartbeatServer::bind`], then drive
/// with [`HeartbeatServer::run`] (typically on its own `tokio::spawn`).
pub struct HeartbeatServer {
    socket: UdpSocket,
    local_keys: StaticKeyPair,
    peer_state: Arc<PeerState>,
    pending_store: Arc<PendingPeerStore>,
    shutdown: CancellationToken,
    session: Option<SessionState>,
}

struct SessionState {
    session: Session,
    last_peer_addr: SocketAddr,
    started_at: Instant,
}

impl HeartbeatServer {
    /// Bind the heartbeat UDP socket. Returns immediately on success;
    /// call [`HeartbeatServer::run`] to actually start serving.
    pub async fn bind(
        listen: SocketAddr,
        local_keys: StaticKeyPair,
        peer_state: Arc<PeerState>,
        pending_store: Arc<PendingPeerStore>,
        shutdown: CancellationToken,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(listen)
            .await
            .with_context(|| format!("bind heartbeat UDP socket on {listen}"))?;
        tracing::info!(
            local = %socket.local_addr().map(|a| a.to_string()).unwrap_or_default(),
            peer  = %peer_state.fingerprint(),
            enrolled = peer_state.is_peer_enrolled(),
            "heartbeat server bound"
        );
        Ok(Self {
            socket,
            local_keys,
            peer_state,
            pending_store,
            shutdown,
            session: None,
        })
    }

    /// The actually-bound local address. Useful when `listen` had port 0.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Run the receive loop until the cancellation token fires.
    pub async fn run(mut self) -> Result<()> {
        // Heartbeat packets are tiny (a handful of bytes plus Noise/AEAD
        // overhead). 2 KiB leaves plenty of headroom for future packet
        // types without paying for the maximum UDP payload.
        let mut buf = [0u8; 2048];
        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => {
                    tracing::info!("heartbeat server received shutdown");
                    return Ok(());
                }
                res = self.socket.recv_from(&mut buf) => {
                    match res {
                        Ok((n, src)) => self.handle_packet(&buf[..n], src).await,
                        Err(e) => {
                            tracing::warn!(error = %e, "heartbeat recv_from failed");
                        }
                    }
                }
            }
        }
    }

    async fn handle_packet(&mut self, bytes: &[u8], src: SocketAddr) {
        let view = match wire::parse(bytes) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(src = %src, error = %e, "drop unparseable packet");
                return;
            }
        };

        match view.packet_type {
            PacketType::Handshake1 => self.handle_handshake1(&view, src).await,
            PacketType::Heartbeat => self.handle_heartbeat(&view, src).await,
            PacketType::Rekey => {
                tracing::debug!(
                    src = %src,
                    "received Rekey signal; peer must send a fresh Handshake1"
                );
            }
            PacketType::Control | PacketType::ControlAck => {
                // Control-channel dispatch lands in a follow-up commit in
                // this phase; for now, drop these so the parser does not
                // produce non-exhaustive warnings. Phase 2 tests run an
                // in-process loopback that exercises the reliability layer
                // directly without touching this server.
                tracing::debug!(
                    src = %src,
                    packet_type = ?view.packet_type,
                    "drop control packet: dispatch not yet wired into this server"
                );
            }
            PacketType::Handshake2 | PacketType::HeartbeatAck => {
                tracing::debug!(
                    src = %src,
                    packet_type = ?view.packet_type,
                    "drop server-only packet seen from peer"
                );
            }
        }
    }

    async fn handle_handshake1(&mut self, view: &PacketView<'_>, src: SocketAddr) {
        let half = match Responder::process_handshake_1(&self.local_keys, view) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(src = %src, error = %e, "drop invalid Handshake1");
                return;
            }
        };

        // Authenticate: the peer's offered static key must match the configured one.
        if *half.remote_public() != self.peer_state.peer_static_key() {
            if self.peer_state.is_peer_enrolled() {
                tracing::warn!(
                    src = %src,
                    offered = %half.remote_fingerprint(),
                    expected = %self.peer_state.fingerprint(),
                    "drop Handshake1 from peer with wrong key"
                );
            } else {
                // TOFU staging: record the candidate so the operator can
                // approve it via `yggdrasilctl peer approve <fingerprint>`.
                let offered = *half.remote_public();
                match self.pending_store.record_candidate(offered) {
                    Ok(()) => tracing::info!(
                        src = %src,
                        offered = %half.remote_fingerprint(),
                        "staged TOFU candidate; awaiting operator approval"
                    ),
                    Err(e) => tracing::warn!(
                        src = %src,
                        error = %e,
                        "failed to stage TOFU candidate"
                    ),
                }
            }
            metrics::counter!(
                "yggdrasil_heartbeats_received_total",
                "result" => "rejected"
            )
            .increment(1);
            return;
        }

        let session_id = half.session_id();
        let (session, reply) = match half.complete() {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(src = %src, error = %e, "Handshake2 generation failed");
                return;
            }
        };

        if let Err(e) = self.socket.send_to(&reply, src).await {
            tracing::warn!(src = %src, error = %e, "send Handshake2 failed");
            return;
        }

        let replacing = self.session.is_some();
        tracing::info!(
            src = %src,
            session_id = %session_id,
            peer = %self.peer_state.fingerprint(),
            replacing_existing = replacing,
            "new heartbeat session established"
        );
        metrics::counter!("yggdrasil_handshakes_completed_total").increment(1);
        self.session = Some(SessionState {
            session,
            last_peer_addr: src,
            started_at: Instant::now(),
        });
    }

    async fn handle_heartbeat(&mut self, view: &PacketView<'_>, src: SocketAddr) {
        let state = match self.session.as_mut() {
            Some(s) => s,
            None => {
                tracing::debug!(src = %src, "drop heartbeat: no active session");
                return;
            }
        };

        let decoded = match state.session.decode_heartbeat(view) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(
                    src = %src,
                    error = %e,
                    "drop heartbeat: decrypt or replay check failed"
                );
                metrics::counter!("yggdrasil_heartbeats_received_total", "result" => "rejected")
                    .increment(1);
                return;
            }
        };

        // Authenticated. Build and send the ACK *before* touching peer
        // state so a send failure doesn't leave us with stale `last_seen`.
        let ack = match state.session.encode_heartbeat_ack(decoded.counter, current_unix_millis()) {
            Ok((_, p)) => p,
            Err(e) => {
                tracing::warn!(src = %src, error = %e, "encode HeartbeatAck failed");
                return;
            }
        };
        if let Err(e) = self.socket.send_to(&ack, src).await {
            tracing::warn!(src = %src, error = %e, "send HeartbeatAck failed");
            return;
        }

        // ACK is on the wire; commit the peer-state update.
        let effect = self.peer_state.record_heartbeat(src);
        state.last_peer_addr = src;
        metrics::counter!("yggdrasil_heartbeats_received_total", "result" => "accepted")
            .increment(1);
        // Wall-clock seconds since UNIX_EPOCH. Standard Prometheus
        // convention is `_timestamp_seconds` for an epoch gauge; alert via
        // `time() - yggdrasil_last_heartbeat_timestamp_seconds > N`. The
        // value mirrors what `peer_state.last_heartbeat_ms()` just stored,
        // converted to seconds.
        if let Some(ms) = self.peer_state.last_heartbeat_ms() {
            metrics::gauge!("yggdrasil_last_heartbeat_timestamp_seconds")
                .set(ms as f64 / 1000.0);
        }

        match effect {
            HeartbeatEffect::SameIp(_) => {
                tracing::trace!(
                    src = %src,
                    counter = decoded.counter,
                    "heartbeat ok (same ip)"
                );
            }
            HeartbeatEffect::FirstHeartbeat(ip) => {
                tracing::info!(
                    src = %src,
                    first_ip = %ip,
                    session_id = %state.session.id(),
                    "first heartbeat received; peer IP locked in"
                );
                metrics::counter!("yggdrasil_peer_ip_changes_total").increment(1);
            }
            HeartbeatEffect::IpChanged { old, new } => {
                tracing::info!(
                    src = %src,
                    old_ip = %old,
                    new_ip = %new,
                    session_id = %state.session.id(),
                    "peer IP changed; data plane will drain affected flows"
                );
                metrics::counter!("yggdrasil_peer_ip_changes_total").increment(1);
            }
        }

        // Observability: log every N heartbeats at info to confirm liveness
        // without flooding the logs. Avoid an extra atomic — just key off
        // the counter. The first ~10 are noisy on purpose so new operators
        // get fast confirmation, then we settle into every-100.
        if decoded.counter < 10
            || (decoded.counter < 1000 && decoded.counter % 100 == 0)
            || decoded.counter % 1000 == 0
        {
            tracing::debug!(
                counter = decoded.counter,
                session_age_secs = state.started_at.elapsed().as_secs(),
                "heartbeat liveness"
            );
        }
    }
}

fn current_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use ratatoskr::auth::{Initiator, StaticKeyPair};
    use ratatoskr::wire::SessionId;

    /// Spawn a server bound to `127.0.0.1:0` and return the (server-pubkey,
    /// peer-state, server-addr, shutdown-token, client-keys) tuple, plus the
    /// JoinHandle.
    async fn spawn_server() -> (
        StaticKeyPair,
        StaticKeyPair,
        Arc<PeerState>,
        SocketAddr,
        CancellationToken,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let server_keys = StaticKeyPair::generate().unwrap();
        let client_keys = StaticKeyPair::generate().unwrap();
        let peer_state = PeerState::new(*client_keys.public_key());
        let pending_dir = tempfile::tempdir().unwrap();
        let pending_store =
            Arc::new(PendingPeerStore::load(pending_dir.path()).unwrap());
        // Leak the tempdir so it lives as long as the test (avoids relying
        // on drop order with the spawned server task).
        std::mem::forget(pending_dir);
        let cancel = CancellationToken::new();
        let server = HeartbeatServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            server_keys.clone_for_test(),
            peer_state.clone(),
            pending_store,
            cancel.clone(),
        )
        .await
        .expect("bind heartbeat server");
        let addr = server.local_addr().unwrap();
        let handle = tokio::spawn(server.run());
        (server_keys, client_keys, peer_state, addr, cancel, handle)
    }

    // StaticKeyPair has no public Clone (secret is zeroizing) — provide a
    // shallow test-only constructor that recovers the same key from raw bytes.
    trait CloneForTest {
        fn clone_for_test(&self) -> Self;
    }
    impl CloneForTest for StaticKeyPair {
        fn clone_for_test(&self) -> Self {
            StaticKeyPair::from_raw(*self.secret_bytes(), *self.public_key())
        }
    }

    /// Drive a full client-side handshake against the server. Returns the
    /// established Session plus the client UDP socket bound to a local port
    /// (so the test can keep sending heartbeats on the same source).
    async fn handshake_with_server(
        server_pub: &[u8; 32],
        client: &StaticKeyPair,
        server_addr: SocketAddr,
    ) -> (Session, UdpSocket) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.connect(server_addr).await.unwrap();
        let sid = SessionId::random();
        let (init, hs1) = Initiator::start(client, server_pub, sid).unwrap();
        sock.send(&hs1).await.unwrap();
        let mut buf = [0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf))
            .await
            .expect("timed out waiting for Handshake2")
            .expect("recv Handshake2");
        let view = wire::parse(&buf[..n]).unwrap();
        let session = init.complete(&view).expect("complete handshake");
        (session, sock)
    }

    #[tokio::test]
    async fn full_handshake_then_heartbeat_ack() {
        let (server_keys, client_keys, peer_state, server_addr, cancel, handle) =
            spawn_server().await;
        let (mut session, sock) = handshake_with_server(
            server_keys.public_key(),
            &client_keys,
            server_addr,
        )
        .await;

        // Send a heartbeat and expect an ACK.
        let (counter, hb) = session.encode_heartbeat(1234, 0).unwrap();
        sock.send(&hb).await.unwrap();

        let mut buf = [0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf))
            .await
            .expect("timed out waiting for HeartbeatAck")
            .unwrap();
        let view = wire::parse(&buf[..n]).unwrap();
        let ack = session.decode_heartbeat_ack(&view).expect("decode ack");
        assert_eq!(ack.echoed_counter, counter);
        assert!(ack.server_ts_ms > 0);

        // Wait briefly for the server's record_heartbeat side-effect to land.
        // The ACK is sent before record_heartbeat is called, but they happen
        // on the same task; a single yield is enough.
        for _ in 0..10 {
            if peer_state.current_ip().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(peer_state.current_ip().unwrap().to_string(), "127.0.0.1");
        assert!(peer_state.last_heartbeat_ms().is_some());

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn many_heartbeats_from_same_addr_fire_watch_once() {
        let (server_keys, client_keys, peer_state, server_addr, cancel, handle) =
            spawn_server().await;
        let mut rx = peer_state.watch();
        assert_eq!(*rx.borrow_and_update(), None);

        let (mut session, sock) = handshake_with_server(
            server_keys.public_key(),
            &client_keys,
            server_addr,
        )
        .await;

        // 25 heartbeats from the same client socket. We expect the watch
        // channel to fire exactly once (the initial None→Some(127.0.0.1)).
        let mut buf = [0u8; 2048];
        for i in 0..25u64 {
            let (_, hb) = session.encode_heartbeat(i, 0).unwrap();
            sock.send(&hb).await.unwrap();
            let n = tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf))
                .await
                .expect("ack timeout")
                .unwrap();
            let view = wire::parse(&buf[..n]).unwrap();
            session.decode_heartbeat_ack(&view).unwrap();
        }

        // We should observe exactly one change: the initial first heartbeat.
        assert!(rx.has_changed().unwrap(), "expected initial IP set");
        let val = *rx.borrow_and_update();
        assert_eq!(val.unwrap().to_string(), "127.0.0.1");
        assert!(
            !rx.has_changed().unwrap(),
            "watch must NOT fire again for same-IP heartbeats (heartbeat invariance)"
        );

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn rejects_handshake_from_wrong_peer_key() {
        let (server_keys, _client_keys, peer_state, server_addr, cancel, handle) =
            spawn_server().await;
        // Use a *different* client key than the one PeerState was constructed with.
        let intruder = StaticKeyPair::generate().unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.connect(server_addr).await.unwrap();
        let sid = SessionId::random();
        let (_init, hs1) = Initiator::start(&intruder, server_keys.public_key(), sid).unwrap();
        sock.send(&hs1).await.unwrap();

        // The server must NOT send Handshake2.
        let mut buf = [0u8; 2048];
        let res = tokio::time::timeout(Duration::from_millis(500), sock.recv(&mut buf)).await;
        assert!(
            res.is_err(),
            "expected timeout — server should silently drop wrong-key Handshake1"
        );
        assert_eq!(peer_state.current_ip(), None);

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn replayed_heartbeat_is_rejected_without_disturbing_state() {
        let (server_keys, client_keys, peer_state, server_addr, cancel, handle) =
            spawn_server().await;
        let (mut session, sock) = handshake_with_server(
            server_keys.public_key(),
            &client_keys,
            server_addr,
        )
        .await;

        // Send heartbeat 0, get ACK, then replay the exact same packet.
        let (_, hb0) = session.encode_heartbeat(100, 0).unwrap();
        sock.send(&hb0).await.unwrap();
        let mut buf = [0u8; 2048];
        let _ = tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf))
            .await
            .expect("ack timeout")
            .unwrap();

        let last_hb_before = peer_state.last_heartbeat_ms().unwrap();

        // Replay verbatim.
        sock.send(&hb0).await.unwrap();
        let res = tokio::time::timeout(Duration::from_millis(500), sock.recv(&mut buf)).await;
        assert!(res.is_err(), "expected timeout on replayed heartbeat");

        // last_heartbeat_ms should NOT have advanced from the replay.
        let last_hb_after = peer_state.last_heartbeat_ms().unwrap();
        assert_eq!(
            last_hb_before, last_hb_after,
            "replayed heartbeats must not bump last_heartbeat_ms"
        );

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn handshake1_replaces_existing_session() {
        let (server_keys, client_keys, _peer_state, server_addr, cancel, handle) =
            spawn_server().await;

        // First session.
        let (mut s1, sock1) = handshake_with_server(
            server_keys.public_key(),
            &client_keys,
            server_addr,
        )
        .await;
        let (_, hb) = s1.encode_heartbeat(1, 0).unwrap();
        sock1.send(&hb).await.unwrap();
        let mut buf = [0u8; 2048];
        let _ = tokio::time::timeout(Duration::from_secs(2), sock1.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();

        // Second handshake on a fresh client socket. The server should
        // accept and replace; the *new* session can send heartbeats.
        let (mut s2, sock2) = handshake_with_server(
            server_keys.public_key(),
            &client_keys,
            server_addr,
        )
        .await;
        let (counter, hb) = s2.encode_heartbeat(1, 0).unwrap();
        sock2.send(&hb).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(2), sock2.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let view = wire::parse(&buf[..n]).unwrap();
        let ack = s2.decode_heartbeat_ack(&view).unwrap();
        assert_eq!(ack.echoed_counter, counter);

        cancel.cancel();
        let _ = handle.await;
    }
}
