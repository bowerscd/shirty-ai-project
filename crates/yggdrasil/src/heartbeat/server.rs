//! Heartbeat UDP server: owns the listening socket and the single Noise
//! session, drives handshakes, and processes inbound heartbeats.
//!
//! All authentication decisions are encapsulated here:
//!
//! * `Handshake1` is accepted only if the peer's static key matches the one
//!   stored in [`PeerState`]. Anything else is dropped at `warn` level.
//!   (Pending-peer TOFU staging happens via `yggdrasilctl local accept
//!   approve`; see [`crate::pending_peers`].)
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
use ratatoskr::control_frame::{AckStatus, ControlAck, ControlEnvelope};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use ratatoskr::auth::{Responder, Session, StaticKeyPair};
use ratatoskr::wire::{self, PacketType, PacketView};

use super::peer_state::{HeartbeatEffect, PeerState};
use crate::chain::reliability::{ControlChannel, InboundDisposition};
use crate::chain::ChainAcceptor;
use crate::pending_peers::PendingPeerStore;

/// Heartbeat UDP server. Construct with [`HeartbeatServer::bind`], then drive
/// with [`HeartbeatServer::run`] (typically on its own `tokio::spawn`).
pub struct HeartbeatServer {
    socket: UdpSocket,
    local_keys: StaticKeyPair,
    peer_state: Arc<PeerState>,
    pending_store: Arc<PendingPeerStore>,
    shutdown: CancellationToken,
    /// Chain-control receive dispatcher. `None` skips control envelope
    /// dispatch (terminals + test drivers that don't supply a
    /// supervisor); when `Some`, inbound `Control` packets are decoded,
    /// dedup-classified, routed by body type, and acked.
    acceptor: Option<Arc<ChainAcceptor>>,
    /// Relay-initiated `Control` envelopes (e.g. `ChainHopReply`
    /// frames the acceptor pushes back down the chain in response to
    /// recursive `ChainHopQuery` walks).
    /// Drained by the run loop, encoded on the active session, and
    /// emitted on the socket. The keepalive sender lives as long as the
    /// server so the receiver never short-circuits with `None` when no
    /// upstream-bound producer is configured.
    outbound_rx: mpsc::UnboundedReceiver<ControlEnvelope>,
    _outbound_keepalive: mpsc::UnboundedSender<ControlEnvelope>,
    session: Option<SessionState>,
}

struct SessionState {
    session: Session,
    last_peer_addr: SocketAddr,
    started_at: Instant,
    /// Per-session inbound reliability layer. Sequence numbers reset
    /// when the underlying Noise session is replaced, matching the
    /// control-frame protocol's session-local seq space.
    control_channel: ControlChannel,
    /// Per-session monotonic outbound `ControlEnvelope.seq` counter.
    /// Today's relay-initiated frames are fire-and-forget; reliability
    /// (retransmit / ack-tracking) would layer on top without changing
    /// the wire shape.
    next_outbound_seq: u32,
}

impl HeartbeatServer {
    /// Bind the heartbeat UDP socket. Returns immediately on success;
    /// call [`HeartbeatServer::run`] to actually start serving.
    ///
    /// `acceptor` is the chain-control dispatcher. Pass `None` to drop
    /// inbound control packets (used by tests that do not exercise the
    /// relay-side dispatcher).
    ///
    /// The returned [`OutboundHandle`] is the **sender** side of the
    /// relay-initiated `Control` envelope channel (currently used by
    /// the chain acceptor to push `ChainHopReply` frames downstream).
    /// Drop it if the daemon never originates control envelopes — the
    /// server holds a keepalive sender internally so the channel won't
    /// close.
    pub async fn bind(
        listen: SocketAddr,
        local_keys: StaticKeyPair,
        peer_state: Arc<PeerState>,
        pending_store: Arc<PendingPeerStore>,
        acceptor: Option<Arc<ChainAcceptor>>,
        shutdown: CancellationToken,
    ) -> Result<(Self, OutboundHandle)> {
        let socket = UdpSocket::bind(listen)
            .await
            .with_context(|| format!("bind heartbeat UDP socket on {listen}"))?;
        tracing::info!(
            local = %socket.local_addr().map(|a| a.to_string()).unwrap_or_default(),
            peer  = %peer_state.fingerprint(),
            enrolled = peer_state.is_peer_enrolled(),
            chain_acceptor = acceptor.is_some(),
            "heartbeat server bound"
        );
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        let server = Self {
            socket,
            local_keys,
            peer_state,
            pending_store,
            shutdown,
            acceptor,
            outbound_rx,
            _outbound_keepalive: outbound_tx.clone(),
            session: None,
        };
        Ok((server, OutboundHandle(outbound_tx)))
    }

    /// The actually-bound local address. Useful when `listen` had port 0.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Run the receive loop until the cancellation token fires.
    pub async fn run(mut self) -> Result<()> {
        // Sized to fit the largest single Noise packet we accept on the
        // wire — currently a `ChainHopReply` body capped at
        // `chain_query::CHAIN_HOP_REPLY_MAX_WIRE_BYTES` (16 KiB) plus
        // envelope and AEAD overhead. See `ratatoskr::wire::MAX_PACKET_LEN`.
        let mut buf = [0u8; ratatoskr::wire::MAX_PACKET_LEN];
        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => {
                    tracing::info!("heartbeat server received shutdown");
                    return Ok(());
                }
                Some(env) = self.outbound_rx.recv() => {
                    self.handle_outbound(env).await;
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
            PacketType::Control => self.handle_control(&view, src).await,
            PacketType::ControlAck => {
                // The relay-side server is a Control *receiver*: it never
                // initiates a Control envelope, so it never expects a
                // peer-originated ControlAck. Drop quietly; the chain
                // client running on a terminal handles ControlAck on its
                // own outbound socket.
                tracing::debug!(
                    src = %src,
                    "drop ControlAck: relay-side server is receive-only on the control channel"
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

        // Authenticate: the peer's offered static key must match the
        // configured one. Both sides are compared as tagged `PubKey`s so a
        // future algorithm slots in without changing this comparison.
        let offered_pubkey = *half.remote_public();
        if Some(offered_pubkey) != self.peer_state.peer_static_key() {
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
                self.pending_store.record_candidate(offered_pubkey);
                tracing::info!(
                    src = %src,
                    offered = %half.remote_fingerprint(),
                    "staged TOFU candidate; awaiting operator approval"
                );
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
            control_channel: ControlChannel::new(),
            next_outbound_seq: 0,
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
        let ack = match state
            .session
            .encode_heartbeat_ack(decoded.counter, current_unix_millis())
        {
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
            metrics::gauge!("yggdrasil_last_heartbeat_timestamp_seconds").set(ms as f64 / 1000.0);
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

    async fn handle_control(&mut self, view: &PacketView<'_>, src: SocketAddr) {
        let state = match self.session.as_mut() {
            Some(s) => s,
            None => {
                tracing::debug!(src = %src, "drop Control: no active session");
                return;
            }
        };

        // Decrypt + replay-protect. Strict-monotone counter enforcement
        // lives inside the Session; a duplicate AEAD-level packet is
        // rejected here before reaching the channel dedup.
        let env = match state.session.decode_control(view) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    src = %src,
                    error = %e,
                    "drop Control: decrypt or replay check failed"
                );
                return;
            }
        };
        let seq = env.seq;

        // Channel-level dedup: a retransmitted (seq, body) pair that
        // already won the race is treated as if it succeeded — we re-ack
        // Ok so the sender's reliability layer clears its outbound entry.
        let status = match state.control_channel.on_inbound(env) {
            InboundDisposition::Deliver(env) => match self.acceptor.as_ref() {
                Some(acc) => acc.dispatch(env.body_type, &env.body).await,
                None => {
                    tracing::debug!(
                        src = %src,
                        body_type = env.body_type,
                        "drop Control body: no chain acceptor configured"
                    );
                    AckStatus::Unknown
                }
            },
            InboundDisposition::Duplicate => {
                tracing::debug!(
                    src = %src,
                    seq,
                    "Control duplicate; re-acking Ok"
                );
                AckStatus::Ok
            }
        };

        // Build + encrypt the ack on the SAME session.
        let ack = ControlAck { seq, status };
        let packet = match state.session.encode_control_ack(&ack) {
            Ok((_, p)) => p,
            Err(e) => {
                tracing::warn!(
                    src = %src,
                    seq,
                    error = %e,
                    "encode ControlAck failed"
                );
                return;
            }
        };
        if let Err(e) = self.socket.send_to(&packet, src).await {
            tracing::warn!(
                src = %src,
                seq,
                error = %e,
                "send ControlAck failed"
            );
        }
    }

    /// Encode + send a relay-initiated [`ControlEnvelope`] on the active
    /// session. Fire-and-forget: if there is no session (handshake hasn't
    /// happened yet, or it expired) the envelope is dropped with a debug
    /// log.
    async fn handle_outbound(&mut self, mut env: ControlEnvelope) {
        let state = match self.session.as_mut() {
            Some(s) => s,
            None => {
                tracing::debug!(
                    body_type = env.body_type,
                    "drop outbound Control: no active session"
                );
                return;
            }
        };
        let seq = state.next_outbound_seq;
        state.next_outbound_seq = seq.wrapping_add(1);
        env.seq = seq;

        let body_len = env.body.len();
        let packet = match state.session.encode_control(&env) {
            Ok((_, p)) => p,
            Err(e) => {
                tracing::warn!(
                    seq,
                    body_type = env.body_type,
                    error = %e,
                    "encode outbound Control failed"
                );
                return;
            }
        };
        let dest = state.last_peer_addr;
        let packet_len = packet.len();
        if let Err(e) = self.socket.send_to(&packet, dest).await {
            tracing::warn!(
                seq,
                body_type = env.body_type,
                dest = %dest,
                error = %e,
                "send outbound Control failed"
            );
        } else {
            tracing::debug!(
                seq,
                body_type = env.body_type,
                body_len,
                packet_len,
                dest = %dest,
                "heartbeat server: outbound Control sent"
            );
        }
    }
}

/// Sender side of the relay-initiated `Control` envelope channel. Hand
/// this to subsystems that need to push frames upstream (the chain
/// acceptor uses it to emit `ChainHopReply` frames). Cloneable; the
/// server holds a keepalive sender internally so droppers don't close
/// the channel.
#[derive(Debug, Clone)]
pub struct OutboundHandle(mpsc::UnboundedSender<ControlEnvelope>);

impl OutboundHandle {
    /// Underlying sender, suitable for passing into the chain acceptor
    /// (or any other subsystem that originates control envelopes).
    pub fn sender(&self) -> mpsc::UnboundedSender<ControlEnvelope> {
        self.0.clone()
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
    use ratatoskr::auth::{Initiator, StaticKeyPair};
    use ratatoskr::pubkey::PubKey;
    use ratatoskr::wire::SessionId;
    use std::time::Duration;

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
        let peer_state = PeerState::new(Some(client_keys.public_key()));
        let pending_store = Arc::new(PendingPeerStore::new());
        let cancel = CancellationToken::new();
        let (server, _outbound) = HeartbeatServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            server_keys.clone_for_test(),
            peer_state.clone(),
            pending_store,
            None,
            cancel.clone(),
        )
        .await
        .expect("bind heartbeat server");
        let addr = server.local_addr().unwrap();
        let handle = tokio::spawn(server.run());
        (server_keys, client_keys, peer_state, addr, cancel, handle)
    }

    // StaticKeyPair's derived Clone is fine; this helper exists so the
    // call site reads as "clone for test setup" rather than re-loading
    // bytes from disk.
    trait CloneForTest {
        fn clone_for_test(&self) -> Self;
    }
    impl CloneForTest for StaticKeyPair {
        fn clone_for_test(&self) -> Self {
            self.clone()
        }
    }

    /// Drive a full client-side handshake against the server. Returns the
    /// established Session plus the client UDP socket bound to a local port
    /// (so the test can keep sending heartbeats on the same source).
    async fn handshake_with_server(
        server_pub: &PubKey,
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
        let (mut session, sock) =
            handshake_with_server(&server_keys.public_key(), &client_keys, server_addr).await;

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

        let (mut session, sock) =
            handshake_with_server(&server_keys.public_key(), &client_keys, server_addr).await;

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
        let (_init, hs1) = Initiator::start(&intruder, &server_keys.public_key(), sid).unwrap();
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
        let (mut session, sock) =
            handshake_with_server(&server_keys.public_key(), &client_keys, server_addr).await;

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
        let (mut s1, sock1) =
            handshake_with_server(&server_keys.public_key(), &client_keys, server_addr).await;
        let (_, hb) = s1.encode_heartbeat(1, 0).unwrap();
        sock1.send(&hb).await.unwrap();
        let mut buf = [0u8; 2048];
        let _ = tokio::time::timeout(Duration::from_secs(2), sock1.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();

        // Second handshake on a fresh client socket. The server should
        // accept and replace; the *new* session can send heartbeats.
        let (mut s2, sock2) =
            handshake_with_server(&server_keys.public_key(), &client_keys, server_addr).await;
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
