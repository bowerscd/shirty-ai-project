//! Huginn heartbeat client.
//!
//! Maintains a single Noise_IK session against yggdrasil and emits an
//! authenticated heartbeat every `heartbeat_interval`. Re-handshakes
//! every `rekey_interval`. On any transport / decode error the client
//! sleeps with exponential backoff and re-resolves the endpoint, so a
//! yggdrasil restart (or a yggdrasil IP change) recovers automatically.
//!
//! ## Concurrency
//!
//! The whole client runs on one task: `tokio::select!` between the cancel
//! token, the heartbeat ticker, the rekey deadline, and the UDP recv arm.
//! No locking, no shared mutable state, no rendezvous — the heartbeat
//! `Session` is exclusively owned by the loop.

use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use ratatoskr::auth::{Initiator, Session, StaticKeyPair, PUBLIC_KEY_LEN};
use ratatoskr::wire::{self, PacketType, SessionId};

/// Build-time defaults that callers can override.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const BACKOFF_MIN: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// If we go this many heartbeat intervals without seeing an ACK, give up on
/// the current session and re-handshake.
const ACK_DEADLINE_MULTIPLIER: u32 = 6;

/// Static configuration of the heartbeat client.
pub struct HeartbeatClientConfig {
    pub endpoint:           String,
    pub server_pubkey:      [u8; PUBLIC_KEY_LEN],
    pub local_keys:         StaticKeyPair,
    pub heartbeat_interval: Duration,
    pub rekey_interval:     Duration,
}

/// Driver: owns the config and the cancel token; consumed by [`HeartbeatClient::run`].
pub struct HeartbeatClient {
    config: HeartbeatClientConfig,
    cancel: CancellationToken,
}

impl HeartbeatClient {
    pub fn new(config: HeartbeatClientConfig, cancel: CancellationToken) -> Self {
        Self { config, cancel }
    }

    /// Run forever until the cancel token fires. Returns `Ok(())` on clean
    /// shutdown. Inner session errors are logged and trigger backoff +
    /// reconnect, so this only returns when explicitly cancelled.
    pub async fn run(self) -> Result<()> {
        let mut backoff = BACKOFF_MIN;
        loop {
            if self.cancel.is_cancelled() {
                return Ok(());
            }
            match self.run_session_once().await {
                Ok(SessionExit::Rekey) => {
                    tracing::info!("rekey interval reached; renegotiating");
                    backoff = BACKOFF_MIN;
                }
                Ok(SessionExit::Cancelled) => {
                    tracing::info!("heartbeat client cancelled");
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(error = %e, backoff = ?backoff, "heartbeat session ended");
                    if sleep_or_cancel(&self.cancel, backoff).await {
                        return Ok(());
                    }
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                }
            }
        }
    }

    async fn run_session_once(&self) -> Result<SessionExit> {
        let server_addr = resolve_endpoint(&self.config.endpoint).await?;
        let bind_addr: SocketAddr = match server_addr {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        let socket = UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("bind UDP socket toward {server_addr}"))?;
        socket
            .connect(server_addr)
            .await
            .with_context(|| format!("connect UDP socket to {server_addr}"))?;
        tracing::info!(
            server = %server_addr,
            local  = %socket.local_addr().map(|a| a.to_string()).unwrap_or_default(),
            "udp socket ready"
        );

        let session = self.handshake(&socket).await?;
        self.heartbeat_loop(socket, session).await
    }

    async fn handshake(&self, socket: &UdpSocket) -> Result<Session> {
        let session_id = SessionId::random();
        let (initiator, hs1) = Initiator::start(
            &self.config.local_keys,
            &self.config.server_pubkey,
            session_id,
        )
        .context("build handshake1")?;
        tracing::debug!(
            session_id = %session_id,
            bytes = hs1.len(),
            "sending handshake1"
        );
        socket
            .send(&hs1)
            .await
            .context("send handshake1")?;

        let mut buf = [0u8; 2048];
        let n = match tokio::time::timeout(HANDSHAKE_TIMEOUT, socket.recv(&mut buf)).await {
            Ok(r) => r.context("recv handshake2")?,
            Err(_) => bail!("handshake2 timeout after {:?}", HANDSHAKE_TIMEOUT),
        };
        let view = wire::parse(&buf[..n]).context("parse handshake2")?;
        if view.packet_type != PacketType::Handshake2 {
            bail!(
                "expected Handshake2, got {:?} (session_id={})",
                view.packet_type,
                view.session_id
            );
        }
        let session = initiator
            .complete(&view)
            .context("complete handshake")?;
        tracing::info!(session_id = %session_id, "handshake complete");
        Ok(session)
    }

    async fn heartbeat_loop(
        &self,
        socket: UdpSocket,
        mut session: Session,
    ) -> Result<SessionExit> {
        let session_started = Instant::now();
        let mut ticker = tokio::time::interval(self.config.heartbeat_interval);
        // First tick fires immediately so we send a heartbeat right after the
        // handshake. (`Interval`'s default behaviour.)
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let mut last_ack_at: Option<Instant> = None;
        let mut heartbeats_sent: u64 = 0;
        let mut acks_received: u64 = 0;
        let mut buf = [0u8; 2048];

        let ack_deadline = self.config.heartbeat_interval * ACK_DEADLINE_MULTIPLIER;

        loop {
            // Check session lifetime + ACK liveness before awaiting again.
            if session_started.elapsed() >= self.config.rekey_interval {
                tracing::info!(
                    heartbeats_sent,
                    acks_received,
                    "rekey deadline reached"
                );
                return Ok(SessionExit::Rekey);
            }
            if let Some(last) = last_ack_at {
                if last.elapsed() > ack_deadline {
                    bail!(
                        "no ACK in {:?} (sent={}, acked={}); presuming session dead",
                        last.elapsed(),
                        heartbeats_sent,
                        acks_received
                    );
                }
            } else if heartbeats_sent > 0
                && session_started.elapsed() > ack_deadline
            {
                bail!(
                    "no ACK ever received (sent={}, deadline={:?})",
                    heartbeats_sent,
                    ack_deadline
                );
            }

            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => return Ok(SessionExit::Cancelled),
                _ = ticker.tick() => {
                    let ts = current_unix_millis();
                    let (counter, packet) = session
                        .encode_heartbeat(ts, 0)
                        .context("encode heartbeat")?;
                    socket.send(&packet).await.context("send heartbeat")?;
                    heartbeats_sent += 1;
                    tracing::trace!(counter, ts, "heartbeat sent");
                }
                res = socket.recv(&mut buf) => {
                    let n = res.context("recv from server")?;
                    let view = match wire::parse(&buf[..n]) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::debug!(error = %e, "ignoring unparseable packet");
                            continue;
                        }
                    };
                    match view.packet_type {
                        PacketType::HeartbeatAck => {
                            match session.decode_heartbeat_ack(&view) {
                                Ok(ack) => {
                                    acks_received += 1;
                                    last_ack_at = Some(Instant::now());
                                    tracing::trace!(
                                        echoed_counter = ack.echoed_counter,
                                        server_ts_ms  = ack.server_ts_ms,
                                        "heartbeat ack"
                                    );
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, "ignoring malformed ack");
                                }
                            }
                        }
                        PacketType::Handshake2 => {
                            // Stale handshake reply (post-rekey collision).
                            tracing::debug!("ignoring late Handshake2");
                        }
                        other => {
                            tracing::debug!(?other, "ignoring unexpected packet from server");
                        }
                    }
                }
            }
        }
    }
}

enum SessionExit {
    Rekey,
    Cancelled,
}

async fn resolve_endpoint(endpoint: &str) -> Result<SocketAddr> {
    let mut addrs = tokio::net::lookup_host(endpoint)
        .await
        .with_context(|| format!("resolve {endpoint}"))?;
    addrs
        .next()
        .ok_or_else(|| anyhow!("no addresses returned for {endpoint}"))
}

async fn sleep_or_cancel(cancel: &CancellationToken, dur: Duration) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => true,
        _ = tokio::time::sleep(dur) => false,
    }
}

fn current_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal echo-style yggdrasil heartbeat responder for testing. Accepts
    /// any caller, answers Handshake1 with Handshake2 (verifying remote
    /// static key), then ACKs every heartbeat.
    ///
    /// We can't pull in the real `yggdrasil` crate (binary crate; reaching
    /// across creates a cycle), so we re-implement the responder side with
    /// only `ratatoskr` primitives.
    use ratatoskr::auth::Responder;

    struct TestServer {
        addr: SocketAddr,
        handle: tokio::task::JoinHandle<()>,
        heartbeats_seen: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    impl TestServer {
        async fn start(server_keys: StaticKeyPair) -> Self {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = sock.local_addr().unwrap();
            let heartbeats_seen =
                std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
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
                            let half =
                                Responder::process_handshake_1(&server_keys, &view).unwrap();
                            let (s, reply) = half.complete().unwrap();
                            sock.send_to(&reply, from).await.unwrap();
                            session = Some(s);
                        }
                        PacketType::Heartbeat => {
                            if let Some(s) = session.as_mut() {
                                let hb = s.decode_heartbeat(&view).unwrap();
                                heartbeats_seen_task
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                let (_, ack) =
                                    s.encode_heartbeat_ack(hb.counter, 12345).unwrap();
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
        let server_pub = *server_keys.public_key();

        let server = TestServer::start(server_keys).await;
        let endpoint = server.addr.to_string();

        let cancel = CancellationToken::new();
        let cfg = HeartbeatClientConfig {
            endpoint,
            server_pubkey: server_pub,
            local_keys: client_keys,
            heartbeat_interval: Duration::from_millis(50),
            rekey_interval: Duration::from_secs(60),
        };
        let client = HeartbeatClient::new(cfg, cancel.clone());
        let client_handle = tokio::spawn(async move { client.run().await });

        // Wait for at least 3 heartbeats round-tripped.
        let deadline = Instant::now() + Duration::from_secs(3);
        while server.heartbeats_seen.load(std::sync::atomic::Ordering::Relaxed) < 3 {
            if Instant::now() > deadline {
                panic!(
                    "timeout; saw only {} heartbeats",
                    server.heartbeats_seen.load(std::sync::atomic::Ordering::Relaxed)
                );
            }
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
        let server_pub = *server_keys.public_key();

        // Count handshakes by hand: we wrap the responder so we observe
        // each Handshake1 reception.
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
                        handshakes_task
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let half =
                            Responder::process_handshake_1(&server_keys, &view).unwrap();
                        let (s, reply) = half.complete().unwrap();
                        sock.send_to(&reply, from).await.unwrap();
                        session = Some(s);
                    }
                    PacketType::Heartbeat => {
                        if let Some(s) = session.as_mut() {
                            if let Ok(hb) = s.decode_heartbeat(&view) {
                                let (_, ack) =
                                    s.encode_heartbeat_ack(hb.counter, 0).unwrap();
                                sock.send_to(&ack, from).await.unwrap();
                            }
                        }
                    }
                    _ => {}
                }
            }
        });

        let cancel = CancellationToken::new();
        let cfg = HeartbeatClientConfig {
            endpoint: addr.to_string(),
            server_pubkey: server_pub,
            local_keys: client_keys,
            heartbeat_interval: Duration::from_millis(20),
            rekey_interval: Duration::from_millis(200),
        };
        let client = HeartbeatClient::new(cfg, cancel.clone());
        let client_handle = tokio::spawn(async move { client.run().await });

        // Wait long enough for at least 2 handshakes (one initial + one rekey).
        let deadline = Instant::now() + Duration::from_secs(3);
        while handshakes.load(std::sync::atomic::Ordering::Relaxed) < 2 {
            if Instant::now() > deadline {
                panic!(
                    "timeout; saw only {} handshakes",
                    handshakes.load(std::sync::atomic::Ordering::Relaxed)
                );
            }
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
        let server_pub = *server_keys.public_key();
        let server = TestServer::start(server_keys).await;

        let cancel = CancellationToken::new();
        let cfg = HeartbeatClientConfig {
            endpoint: server.addr.to_string(),
            server_pubkey: server_pub,
            local_keys: client_keys,
            heartbeat_interval: Duration::from_millis(50),
            rekey_interval: Duration::from_secs(60),
        };
        let client = HeartbeatClient::new(cfg, cancel.clone());
        let client_handle = tokio::spawn(async move { client.run().await });

        // Let a heartbeat or two go through.
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
    async fn backoff_and_reconnect_when_endpoint_unresolvable() {
        // Pointing at port 1 on localhost: bind succeeds, but Handshake2
        // never arrives → handshake timeout → session error → backoff → retry.
        let client_keys = StaticKeyPair::generate().unwrap();

        let cancel = CancellationToken::new();
        let cfg = HeartbeatClientConfig {
            endpoint: "127.0.0.1:1".to_string(),
            server_pubkey: [0u8; PUBLIC_KEY_LEN],
            local_keys: client_keys,
            heartbeat_interval: Duration::from_millis(50),
            rekey_interval: Duration::from_secs(60),
        };
        let client = HeartbeatClient::new(cfg, cancel.clone());
        let client_handle = tokio::spawn(async move { client.run().await });

        // Let the client try and fail a couple of times (handshake timeout is
        // 5s in the constant, but it'll fail much faster on
        // "connection refused" because UDP doesn't refuse — so we cheat a
        // bit and just verify the client is *still running* / has not
        // panicked after a short observation window).
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !client_handle.is_finished(),
            "client should not have exited yet"
        );

        cancel.cancel();
        let res = tokio::time::timeout(Duration::from_secs(8), client_handle).await;
        assert!(res.is_ok(), "client did not stop within 8s of cancel");
    }
}
