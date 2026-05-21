//! Outbound chain control client.
//!
//! Every node — relay or terminal — that declares `[dial]` in its
//! config dials that upstream over UDP and maintains a single Noise_IK
//! session, emitting an authenticated heartbeat every `heartbeat_interval`.
//! Re-handshakes every `rekey_interval`. On any transport / decode error
//! the client sleeps with exponential backoff and re-resolves the
//! endpoint, so an upstream restart (or upstream IP change) recovers
//! automatically.
//!
//! ## Concurrency
//!
//! The whole client runs on one task: `tokio::select!` between the cancel
//! token, the heartbeat ticker, the control-channel retransmit timer, the
//! caller-side control-send queue, and the UDP recv arm. No locking, no
//! shared mutable state, no rendezvous — the heartbeat [`Session`] and
//! [`ControlChannel`] are exclusively owned by the loop.
//!
//! ## Control channel
//!
//! Phase 2 plumbing: the loop owns a per-session [`ControlChannel`] that
//! sequences, retransmits, and dedups `Control` / `ControlAck` packets. The
//! client task pulls outbound sends from an `mpsc` fed by callers holding a
//! [`ChainClientHandle`], and dispatches inbound envelopes through an
//! optional [`BodyHandler`] (production default: ack everything `Unknown`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use ratatoskr::auth::{Initiator, Session, StaticKeyPair, PUBLIC_KEY_LEN};
use ratatoskr::chain_query::{ChainHopQuery, ChainHopReply};
use ratatoskr::control_frame::{AckStatus, ControlAck, ControlBodyType};
use ratatoskr::wire::{self, PacketType, SessionId};

use super::query_router::QueryRouter;
use super::reliability::{ControlChannel, InboundDisposition, SendError};

/// Build-time defaults that callers can override.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const BACKOFF_MIN: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// If we go this many heartbeat intervals without seeing an ACK, give up
/// on the current session and re-handshake.
const ACK_DEADLINE_MULTIPLIER: u32 = 6;

/// Body-type dispatcher invoked when an inbound control envelope is
/// classified as `Deliver` by the [`ControlChannel`]. The handler returns
/// the [`AckStatus`] to send back to the peer.
///
/// In production builds the default is `None`, which acks every inbound
/// envelope as [`AckStatus::Unknown`] — Phase 2 ships no real body types
/// yet, so any non-`Reserved` body must come from a peer running a newer
/// version of the protocol that this node has not yet been upgraded to.
pub type BodyHandler = Arc<dyn Fn(u8, &[u8]) -> AckStatus + Send + Sync>;

/// Static configuration of the chain client.
pub struct ChainClientConfig {
    /// `host:port` (or `[ipv6]:port`) of the upstream node.
    pub endpoint: String,
    /// X25519 pubkey of the upstream — what Noise_IK pins.
    pub upstream_pubkey: [u8; PUBLIC_KEY_LEN],
    /// This node's static identity.
    pub local_keys: StaticKeyPair,
    pub heartbeat_interval: Duration,
    pub rekey_interval: Duration,
    /// Optional dispatcher for delivered control envelopes. `None` →
    /// every inbound envelope acks [`AckStatus::Unknown`].
    pub body_handler: Option<BodyHandler>,
}

impl std::fmt::Debug for ChainClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainClientConfig")
            .field("endpoint", &self.endpoint)
            .field("upstream_pubkey", &hex::encode(self.upstream_pubkey))
            .field("local_keys", &"<redacted>")
            .field("heartbeat_interval", &self.heartbeat_interval)
            .field("rekey_interval", &self.rekey_interval)
            .field("body_handler", &self.body_handler.as_ref().map(|_| "<fn>"))
            .finish()
    }
}

/// Request issued by a [`ChainClientHandle`] consumer; consumed by the
/// chain client task and folded into the per-session [`ControlChannel`].
#[derive(Debug)]
pub struct ControlOp {
    pub body_type: u8,
    pub body: Vec<u8>,
    pub completion: oneshot::Sender<Result<(), SendError>>,
}

/// Clone-able handle that lets external code enqueue control envelopes on
/// the chain client. Sending on a handle whose client task has exited
/// fails with [`ChainClientShutDown`].
#[derive(Debug, Clone)]
pub struct ChainClientHandle {
    tx: mpsc::UnboundedSender<ControlOp>,
    /// Shared per-session query/reply router used by
    /// [`ChainClientHandle::query_upstream`]. The chain client's
    /// body-handler closure resolves [`ChainHopReply`] envelopes
    /// through this same router.
    router: Arc<QueryRouter>,
}

#[derive(Debug, thiserror::Error)]
#[error("chain client is shut down")]
pub struct ChainClientShutDown;

impl ChainClientHandle {
    /// Enqueue a control envelope for the upstream. Returns the per-send
    /// `Receiver`; its value is `Ok(())` on `AckStatus::Ok`, or a
    /// [`SendError`] for any other outcome. The receiver itself may resolve
    /// with `Err(oneshot::error::RecvError)` if the client task drops the
    /// completion sender before producing a result (e.g. session ended
    /// during shutdown without a clean ack).
    pub fn send_control(
        &self,
        body_type: u8,
        body: Vec<u8>,
    ) -> Result<oneshot::Receiver<Result<(), SendError>>, ChainClientShutDown> {
        let (completion, rx) = oneshot::channel();
        self.tx
            .send(ControlOp {
                body_type,
                body,
                completion,
            })
            .map_err(|_| ChainClientShutDown)?;
        Ok(rx)
    }

    /// Test-only constructor: wrap a pre-built sender so unit tests can
    /// observe enqueued ops without running a full chain session. Not
    /// part of the public API.
    #[cfg(test)]
    #[doc(hidden)]
    pub(crate) fn __test_new(tx: mpsc::UnboundedSender<ControlOp>) -> Self {
        Self {
            tx,
            router: QueryRouter::new(),
        }
    }

    /// Shared per-session query router. The body handler installed on
    /// the chain client must be wired to resolve [`ChainHopReply`]
    /// envelopes through this same router (see
    /// [`QueryRouter::install_into_body_handler`]).
    pub fn query_router(&self) -> Arc<QueryRouter> {
        Arc::clone(&self.router)
    }

    /// Issue a [`ChainHopQuery`] upstream and await the matching
    /// [`ChainHopReply`]. The receiver acks the query immediately;
    /// the reply arrives as a separate `ChainHopReply` envelope routed
    /// through [`QueryRouter`].
    ///
    /// On timeout the router registration is cancelled so a late
    /// reply doesn't leak the oneshot slot; the caller receives
    /// [`QueryError::Timeout`]. On any underlying `send_control`
    /// failure (channel closed, retransmits exhausted, peer rejected)
    /// the error variant carries the underlying [`SendError`].
    pub async fn query_upstream(
        &self,
        depth_budget: u32,
        deadline: Duration,
    ) -> Result<ChainHopReply, QueryError> {
        let (query_id, rx) = self.router.register();
        let deadline_ms = u32::try_from(deadline.as_millis()).unwrap_or(u32::MAX);
        let query = ChainHopQuery {
            query_id,
            depth_budget,
            deadline_ms,
        };
        let body = postcard::to_allocvec(&query).map_err(QueryError::Encode)?;
        let ack_rx = self
            .send_control(ControlBodyType::ChainHopQuery.as_byte(), body)
            .map_err(|_| {
                self.router.cancel(query_id);
                QueryError::ClientDown
            })?;

        // First, await the ACK so we know the query was actually
        // delivered. If the peer can't even ack we won't get a reply
        // either, so propagate.
        let ack_outcome = tokio::time::timeout(deadline, ack_rx).await;
        match ack_outcome {
            Err(_) => {
                self.router.cancel(query_id);
                return Err(QueryError::Timeout);
            }
            Ok(Err(_)) => {
                self.router.cancel(query_id);
                return Err(QueryError::ClientDown);
            }
            Ok(Ok(Err(e))) => {
                self.router.cancel(query_id);
                return Err(QueryError::Send(e));
            }
            Ok(Ok(Ok(()))) => {}
        }

        // Then await the actual reply.
        match tokio::time::timeout(deadline, rx).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(_)) => Err(QueryError::ClientDown),
            Err(_) => {
                self.router.cancel(query_id);
                Err(QueryError::Timeout)
            }
        }
    }
}

/// Failure modes for [`ChainClientHandle::query_upstream`].
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    /// The deadline expired before a reply arrived. The local hop is
    /// still usable; the CLI surfaces this as `partial = true`.
    #[error("chain hop query timed out")]
    Timeout,
    /// The chain client task is no longer running (cancellation or
    /// fatal session error).
    #[error("chain client is shut down")]
    ClientDown,
    /// The send layer reported a delivery failure (retransmits
    /// exhausted, peer rejected the body type, etc.).
    #[error("chain hop query send failed: {0}")]
    Send(#[from] SendError),
    /// Postcard refused to encode the query body. Pure internal bug;
    /// surfaces here so tests catch it.
    #[error("failed to encode ChainHopQuery body: {0}")]
    Encode(postcard::Error),
}

/// Driver: owns the config, the cancel token, and the control-send queue;
/// consumed by [`ChainClient::run`].
pub struct ChainClient {
    config: ChainClientConfig,
    cancel: CancellationToken,
    control_tx: mpsc::UnboundedSender<ControlOp>,
    control_rx: mpsc::UnboundedReceiver<ControlOp>,
    router: Arc<QueryRouter>,
}

impl std::fmt::Debug for ChainClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainClient")
            .field("config", &self.config)
            .field("cancel", &"<token>")
            .finish()
    }
}

impl ChainClient {
    pub fn new(config: ChainClientConfig, cancel: CancellationToken) -> Self {
        let (control_tx, control_rx) = mpsc::unbounded_channel();
        Self {
            config,
            cancel,
            control_tx,
            control_rx,
            router: QueryRouter::new(),
        }
    }

    /// Clone the control-send handle. Multiple callers may hold handles
    /// concurrently; each enqueued op is processed in FIFO order by the
    /// client task.
    pub fn handle(&self) -> ChainClientHandle {
        ChainClientHandle {
            tx: self.control_tx.clone(),
            router: Arc::clone(&self.router),
        }
    }

    /// The query-router shared with [`ChainClientHandle`]s. Callers
    /// constructing the body-handler must install a router-aware
    /// dispatcher (see
    /// [`QueryRouter::install_into_body_handler`]) so inbound
    /// `ChainHopReply` envelopes reach their awaiting oneshots.
    pub fn query_router(&self) -> Arc<QueryRouter> {
        Arc::clone(&self.router)
    }

    /// Install (or replace) the per-envelope body handler.
    ///
    /// `ChainClientConfig::body_handler` is normally set at construction
    /// time, but the chain-tunnel initiator needs the [`ChainClientHandle`]
    /// (only available *after* `ChainClient::new`) in order to build its
    /// dispatcher closure. This setter lets the caller construct the
    /// initiator with the live handle and then register its body handler
    /// before [`ChainClient::run`] is called. Idempotent; callers must
    /// finish wiring before `run()` begins consuming the chain socket.
    pub fn set_body_handler(&mut self, handler: BodyHandler) {
        self.config.body_handler = Some(handler);
    }

    /// Run forever until the cancel token fires. Returns `Ok(())` on clean
    /// shutdown. Inner session errors are logged and trigger backoff +
    /// reconnect, so this only returns when explicitly cancelled.
    pub async fn run(mut self) -> Result<()> {
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
                    tracing::info!("chain client cancelled");
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(error = %e, backoff = ?backoff, "chain session ended");
                    if sleep_or_cancel(&self.cancel, backoff).await {
                        return Ok(());
                    }
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                }
            }
        }
    }

    async fn run_session_once(&mut self) -> Result<SessionExit> {
        let target_addr = resolve_endpoint(&self.config.endpoint).await?;
        let bind_addr: SocketAddr = match target_addr {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        let socket = UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("bind UDP socket toward {target_addr}"))?;
        socket
            .connect(target_addr)
            .await
            .with_context(|| format!("connect UDP socket to {target_addr}"))?;
        tracing::info!(
            upstream = %target_addr,
            local    = %socket.local_addr().map(|a| a.to_string()).unwrap_or_default(),
            "udp socket ready"
        );

        let session = self.handshake(&socket).await?;
        self.heartbeat_loop(socket, session).await
    }

    async fn handshake(&self, socket: &UdpSocket) -> Result<Session> {
        let session_id = SessionId::random();
        let (initiator, hs1) = Initiator::start(
            &self.config.local_keys,
            &self.config.upstream_pubkey,
            session_id,
        )
        .context("build handshake1")?;
        tracing::debug!(
            session_id = %session_id,
            bytes = hs1.len(),
            "sending handshake1"
        );
        socket.send(&hs1).await.context("send handshake1")?;

        let mut buf = [0u8; ratatoskr::wire::MAX_PACKET_LEN];
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
        let session = initiator.complete(&view).context("complete handshake")?;
        tracing::info!(session_id = %session_id, "handshake complete");
        Ok(session)
    }

    async fn heartbeat_loop(
        &mut self,
        socket: UdpSocket,
        mut session: Session,
    ) -> Result<SessionExit> {
        let session_started = Instant::now();
        let mut ticker = tokio::time::interval(self.config.heartbeat_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let mut last_ack_at: Option<Instant> = None;
        let mut heartbeats_sent: u64 = 0;
        let mut acks_received: u64 = 0;
        let mut buf = [0u8; ratatoskr::wire::MAX_PACKET_LEN];

        let ack_deadline = self.config.heartbeat_interval * ACK_DEADLINE_MULTIPLIER;

        // Per-session control reliability state. Drop-aborts every pending
        // send with `SendError::ChannelClosed` when this function returns
        // (rekey, cancel, or fatal session error), so callers awaiting on a
        // completion receiver always make progress.
        let mut channel = ControlChannel::new();

        loop {
            if session_started.elapsed() >= self.config.rekey_interval {
                tracing::info!(heartbeats_sent, acks_received, "rekey deadline reached");
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
            } else if heartbeats_sent > 0 && session_started.elapsed() > ack_deadline {
                bail!(
                    "no ACK ever received (sent={}, deadline={:?})",
                    heartbeats_sent,
                    ack_deadline
                );
            }

            // Compute the next control-channel retransmit deadline. If the
            // outbound queue is empty, sleep for a long interval (we'll be
            // woken by any of the other select arms first).
            let retx_at = channel
                .next_tick_at()
                .map(tokio::time::Instant::from_std)
                .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(3600));

            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => return Ok(SessionExit::Cancelled),
                // Drain inbound before anything else: heartbeat acks must
                // arrive promptly, and an unbounded outbound `control_rx`
                // burst would otherwise starve this arm and bail the
                // session on the no-ack deadline.
                res = socket.recv(&mut buf) => {
                    let n = res.context("recv from upstream")?;
                    tracing::trace!(n, "chain client: recv UDP packet");
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
                        PacketType::Control => {
                            match session.decode_control(&view) {
                                Ok(env) => {
                                    let seq = env.seq;
                                    let status = match channel.on_inbound(env) {
                                        InboundDisposition::Deliver(env) => {
                                            dispatch_body(
                                                self.config.body_handler.as_ref(),
                                                env.body_type,
                                                &env.body,
                                            )
                                        }
                                        InboundDisposition::Duplicate => AckStatus::Ok,
                                    };
                                    let ack = ControlAck { seq, status };
                                    match session.encode_control_ack(&ack) {
                                        Ok((_, packet)) => {
                                            if let Err(e) = socket.send(&packet).await {
                                                tracing::warn!(seq, error = %e, "send ControlAck failed");
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(seq, error = %e, "encode ControlAck failed");
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, "ignoring malformed Control");
                                }
                            }
                        }
                        PacketType::ControlAck => {
                            match session.decode_control_ack(&view) {
                                Ok(ack) => {
                                    let seq = ack.seq;
                                    let resolved = channel.on_ack(&ack);
                                    if resolved {
                                        tracing::trace!(seq, "control ack resolved waiter");
                                    } else {
                                        tracing::debug!(seq, "control ack for unknown seq");
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, "ignoring malformed ControlAck");
                                }
                            }
                        }
                        PacketType::Handshake2 => {
                            tracing::debug!("ignoring late Handshake2");
                        }
                        other => {
                            tracing::debug!(?other, "ignoring unexpected packet from upstream");
                        }
                    }
                }
                _ = ticker.tick() => {
                    let ts = current_unix_millis();
                    let (counter, packet) = session
                        .encode_heartbeat(ts, 0)
                        .context("encode heartbeat")?;
                    socket.send(&packet).await.context("send heartbeat")?;
                    heartbeats_sent += 1;
                    tracing::trace!(counter, ts, "heartbeat sent");
                }
                Some(op) = self.control_rx.recv() => {
                    let env = channel.enqueue(
                        op.body_type,
                        op.body,
                        op.completion,
                        Instant::now(),
                    );
                    let seq = env.seq;
                    match session.encode_control(&env) {
                        Ok((counter, packet)) => {
                            if let Err(e) = socket.send(&packet).await {
                                tracing::warn!(seq, counter, error = %e, "send control failed");
                            } else {
                                tracing::trace!(seq, counter, "control envelope sent");
                            }
                        }
                        Err(e) => {
                            tracing::warn!(seq, error = %e, "encode control failed");
                        }
                    }
                }
                _ = tokio::time::sleep_until(retx_at) => {
                    let due = channel.next_due(Instant::now());
                    for env in due {
                        let seq = env.seq;
                        match session.encode_control(&env) {
                            Ok((counter, packet)) => {
                                if let Err(e) = socket.send(&packet).await {
                                    tracing::warn!(seq, counter, error = %e, "retransmit control failed");
                                } else {
                                    tracing::trace!(seq, counter, "control envelope retransmitted");
                                }
                            }
                            Err(e) => {
                                tracing::warn!(seq, error = %e, "encode control retransmit failed");
                            }
                        }
                    }
                }
            }
        }
    }
}

fn dispatch_body(handler: Option<&BodyHandler>, body_type: u8, body: &[u8]) -> AckStatus {
    let res = match handler {
        Some(h) => h(body_type, body),
        None => AckStatus::Unknown,
    };
    tracing::trace!(
        body_type,
        body_len = body.len(),
        ?res,
        "chain client: dispatch_body"
    );
    res
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
    use ratatoskr::auth::Responder;

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
                                heartbeats_seen_task
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
        let server_pub = *server_keys.public_key();

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
        let cfg = ChainClientConfig {
            endpoint: server.addr.to_string(),
            upstream_pubkey: server_pub,
            local_keys: client_keys,
            heartbeat_interval: Duration::from_millis(50),
            rekey_interval: Duration::from_secs(60),
            body_handler: None,
        };
        let client = ChainClient::new(cfg, cancel.clone());
        let client_handle = tokio::spawn(async move { client.run().await });

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
    async fn backoff_and_reconnect_when_endpoint_unresponsive() {
        let client_keys = StaticKeyPair::generate().unwrap();

        let cancel = CancellationToken::new();
        let cfg = ChainClientConfig {
            endpoint: "127.0.0.1:1".to_string(),
            upstream_pubkey: [0u8; PUBLIC_KEY_LEN],
            local_keys: client_keys,
            heartbeat_interval: Duration::from_millis(50),
            rekey_interval: Duration::from_secs(60),
            body_handler: None,
        };
        let client = ChainClient::new(cfg, cancel.clone());
        let client_handle = tokio::spawn(async move { client.run().await });

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
        let server_pub = *server_keys.public_key();
        let server = ControlTestServer::start_with_loss(server_keys, 0, 0).await;

        let cancel = CancellationToken::new();
        let cfg = ChainClientConfig {
            endpoint: server.addr.to_string(),
            upstream_pubkey: server_pub,
            local_keys: client_keys,
            heartbeat_interval: Duration::from_millis(200),
            rekey_interval: Duration::from_secs(120),
            body_handler: None,
        };
        let client = ChainClient::new(cfg, cancel.clone());
        let handle = client.handle();
        let client_handle = tokio::spawn(async move { client.run().await });

        // Wait for the handshake to complete: the very first send would
        // race the handshake otherwise. A brief sleep is sufficient
        // because `start_with_loss(_, 0)` never drops anything.
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
    /// If you bump [`RETX_MAX_ATTEMPTS`] or change the loss percentage,
    /// re-verify the chosen seed still converges — or pick a new one.
    /// Seed 1 has been verified to converge for `(loss_pct = 10,
    /// N = 1000)` against the production reliability constants in this
    /// tree.
    #[tokio::test]
    async fn control_send_converges_under_10_percent_packet_loss() {
        use ratatoskr::control_frame::ControlBodyType;
        let server_keys = StaticKeyPair::generate().unwrap();
        let client_keys = StaticKeyPair::generate().unwrap();
        let server_pub = *server_keys.public_key();
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
        };
        let client = ChainClient::new(cfg, cancel.clone());
        let handle = client.handle();
        let client_handle = tokio::spawn(async move { client.run().await });

        // Wait for handshake (which may itself need a retry on loss).
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
        let server_pub = *server_keys.public_key();
        let server = ControlTestServer::start_with_loss(server_keys, 0, 0).await;

        let cancel = CancellationToken::new();
        let cfg = ChainClientConfig {
            endpoint: server.addr.to_string(),
            upstream_pubkey: server_pub,
            local_keys: client_keys,
            heartbeat_interval: Duration::from_millis(50),
            rekey_interval: Duration::from_secs(60),
            body_handler: None,
        };
        let client = ChainClient::new(cfg, cancel.clone());
        let handle = client.handle();
        let client_handle = tokio::spawn(async move { client.run().await });

        // Wait for handshake.
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
}
