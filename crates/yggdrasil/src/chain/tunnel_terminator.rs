//! Relay-side tunnel terminator.
//!
//! Phase 4B wires the `target_pubkey == self` half of the tunnel
//! topology: a relay receives [`TunnelOpen`] from its downstream, dials
//! the requested local destination after allow-list enforcement,
//! splices bytes both ways while the stream is open, and tears down on
//! [`TunnelClose`] or transport EOF.
//!
//! Multi-hop forwarding (`target_pubkey != self`) is a Phase 5 concern;
//! Phase 4B answers [`tunnel_reject::TUNNEL_NOT_PERMITTED`] in that case
//! so a forward-rolled peer learns the feature is not active yet.
//!
//! ## Wire interactions
//!
//! Inbound side (peer → relay):
//! * [`TunnelOpen`] — decode, check allow-list, check stream id is free,
//!   `tokio::net::TcpStream::connect` against `dest` with a short
//!   timeout, spawn the splice task, return `Ok`. Errors map to
//!   [`tunnel_reject::TARGET_NOT_ALLOWED`],
//!   [`tunnel_reject::TARGET_UNREACHABLE`],
//!   [`tunnel_reject::DUPLICATE_STREAM_ID`], or
//!   [`tunnel_reject::TUNNEL_NOT_PERMITTED`].
//! * [`TunnelData`] — decode, validate payload cap, push payload into
//!   the splice task's inbound queue. Unknown stream id returns
//!   [`tunnel_reject::STREAM_NOT_FOUND`].
//! * [`TunnelClose`] — decode, signal the splice task to drain and exit.
//!   Unknown stream id returns [`tunnel_reject::STREAM_NOT_FOUND`]
//!   so the acceptor's dispatch can fall through to the forwarder.
//!
//! Outbound side (relay → peer):
//! The splice task reads from the upstream TCP socket, chunks at
//! [`TUNNEL_DATA_MAX_PAYLOAD`], and pushes
//! [`ControlBodyType::TunnelData`] envelopes through the shared
//! `outbound` channel. On TCP EOF or error it pushes a
//! [`ControlBodyType::TunnelClose`] envelope with the appropriate
//! reason code and removes itself from the stream registry.
//!
//! ## Reliability
//!
//! Phase 4B emits relay-outbound envelopes **fire-and-forget**: the
//! [`HeartbeatServer`] drainer assigns a session-local seq and sends
//! once; there is no relay-side retransmit yet. Phase 4C/5 can layer a
//! second [`ControlChannel`] for outbound reliability without touching
//! the wire shape.
//!
//! [`TunnelOpen`]: ratatoskr::tunnel::TunnelOpen
//! [`TunnelData`]: ratatoskr::tunnel::TunnelData
//! [`TunnelClose`]: ratatoskr::tunnel::TunnelClose
//! [`TUNNEL_DATA_MAX_PAYLOAD`]: ratatoskr::tunnel::TUNNEL_DATA_MAX_PAYLOAD
//! [`ControlBodyType::TunnelData`]: ratatoskr::control_frame::ControlBodyType::TunnelData
//! [`ControlBodyType::TunnelClose`]: ratatoskr::control_frame::ControlBodyType::TunnelClose
//! [`tunnel_reject`]: ratatoskr::tunnel::tunnel_reject
//! [`HeartbeatServer`]: crate::heartbeat::HeartbeatServer
//! [`ControlChannel`]: crate::chain::reliability::ControlChannel

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ratatoskr::control_frame::{AckStatus, ControlBodyType, ControlEnvelope};
use ratatoskr::pubkey::PubKey;
use ratatoskr::tunnel::{
    tunnel_reject, TunnelClose, TunnelData, TunnelOpen, TUNNEL_DATA_MAX_PAYLOAD,
    TUNNEL_OPEN_MAX_WIRE_BYTES,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// Default TCP dial timeout. Short on purpose: tunnel targets are
/// loopback or directly-attached operator endpoints, not the open
/// internet.
pub const DEFAULT_DIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// Allow-list policy enforced by the terminator before dialling.
#[derive(Debug, Clone)]
pub struct TunnelAllowList {
    /// Permit destinations on `127.0.0.0/8` and `::1` regardless of port.
    pub allow_loopback: bool,
    /// Additional exact-match `ip:port` destinations the terminator may
    /// dial.
    pub allowed_targets: HashSet<SocketAddr>,
}

impl TunnelAllowList {
    /// Default policy: loopback only.
    pub fn loopback_only() -> Self {
        Self {
            allow_loopback: true,
            allowed_targets: HashSet::new(),
        }
    }

    fn permits(&self, dest: &SocketAddr) -> bool {
        if self.allow_loopback {
            let ip = dest.ip();
            let is_loopback = match ip {
                IpAddr::V4(v4) => v4.is_loopback(),
                IpAddr::V6(v6) => v6.is_loopback(),
            };
            if is_loopback {
                return true;
            }
        }
        self.allowed_targets.contains(dest)
    }
}

/// Relay-side terminator. Construct with [`TunnelManager::new`] and
/// hand a clone to [`ChainAcceptor`] (Phase 4B routes the three tunnel
/// body types into [`TunnelManager::handle_open`] / `handle_data` /
/// `handle_close`).
///
/// `outbound` is a fire-and-forget channel of [`ControlEnvelope`]s that
/// the [`HeartbeatServer`] drains, encodes on the active Noise session,
/// and emits on the socket. The terminator leaves `seq = 0` as a
/// placeholder; the drainer fills it in.
///
/// [`HeartbeatServer`]: crate::heartbeat::HeartbeatServer
/// [`ChainAcceptor`]: crate::chain::ChainAcceptor
#[derive(Debug)]
pub struct TunnelManager {
    allow: TunnelAllowList,
    dial_timeout: Duration,
    /// Pubkey of the local node. Tunnel opens whose
    /// `target_pubkey != local_pubkey` are rejected with
    /// `TUNNEL_NOT_PERMITTED` (Phase 4B is terminate-only).
    local_pubkey: PubKey,
    outbound: mpsc::UnboundedSender<ControlEnvelope>,
    streams: Mutex<HashMap<u32, StreamHandle>>,
}

/// Per-stream handle held by the manager while a stream is open.
#[derive(Debug)]
struct StreamHandle {
    /// Push inbound `TunnelData.payload` chunks to the splice task.
    inbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Splice task join handle (held so we can abort on shutdown).
    task: JoinHandle<()>,
}

impl TunnelManager {
    pub fn new(
        allow: TunnelAllowList,
        local_pubkey: PubKey,
        outbound: mpsc::UnboundedSender<ControlEnvelope>,
    ) -> Arc<Self> {
        Arc::new(Self {
            allow,
            dial_timeout: DEFAULT_DIAL_TIMEOUT,
            local_pubkey,
            outbound,
            streams: Mutex::new(HashMap::new()),
        })
    }

    #[cfg(test)]
    pub fn with_dial_timeout(self: Arc<Self>, _to: Duration) -> Arc<Self> {
        // Arc is intentional: tests construct with `Arc::new` already.
        // This helper exists to make the dial timeout overridable
        // without exposing the field. Phase 4B tests use the default.
        self
    }

    /// Decode + dispatch a `TunnelOpen` body. Returns the ack status the
    /// receiver should encode into the outbound `ControlAck`.
    pub async fn handle_open(&self, body: &[u8]) -> AckStatus {
        if body.len() > TUNNEL_OPEN_MAX_WIRE_BYTES {
            tracing::warn!(
                bytes = body.len(),
                cap = TUNNEL_OPEN_MAX_WIRE_BYTES,
                "tunnel open exceeds wire cap; rejecting"
            );
            metric_outcome("decode_error");
            return AckStatus::Reject(tunnel_reject::TUNNEL_NOT_PERMITTED);
        }
        let open: TunnelOpen = match postcard::from_bytes(body) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(error = %e, "tunnel open decode failed");
                metric_outcome("decode_error");
                return AckStatus::Reject(tunnel_reject::TUNNEL_NOT_PERMITTED);
            }
        };

        // Phase 4B is terminate-only: refuse anything that isn't aimed
        // at us. Multi-hop forwarding lands in Phase 5.
        if open.target_pubkey != self.local_pubkey {
            tracing::debug!(
                target = %open.target_pubkey,
                local = %self.local_pubkey,
                "tunnel open: target is not this node; refusing (forwarding deferred)"
            );
            metric_outcome("forward_not_implemented");
            return AckStatus::Reject(tunnel_reject::TUNNEL_NOT_PERMITTED);
        }

        if !self.allow.permits(&open.dest) {
            tracing::warn!(
                dest = %open.dest,
                "tunnel open: dest not in allow-list"
            );
            metric_outcome("target_not_allowed");
            return AckStatus::Reject(tunnel_reject::TARGET_NOT_ALLOWED);
        }

        // Reserve the stream id under lock so two concurrent opens
        // cannot both succeed.
        let mut streams = self.streams.lock().await;
        if streams.contains_key(&open.stream_id) {
            tracing::warn!(
                stream_id = open.stream_id,
                "tunnel open: duplicate stream id"
            );
            metric_outcome("duplicate_stream_id");
            return AckStatus::Reject(tunnel_reject::DUPLICATE_STREAM_ID);
        }

        let tcp = match timeout(self.dial_timeout, TcpStream::connect(open.dest)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::warn!(
                    dest = %open.dest,
                    error = %e,
                    "tunnel open: dial failed"
                );
                metric_outcome("target_unreachable");
                return AckStatus::Reject(tunnel_reject::TARGET_UNREACHABLE);
            }
            Err(_) => {
                tracing::warn!(
                    dest = %open.dest,
                    "tunnel open: dial timed out"
                );
                metric_outcome("target_unreachable");
                return AckStatus::Reject(tunnel_reject::TARGET_UNREACHABLE);
            }
        };

        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let outbound = self.outbound.clone();
        let stream_id = open.stream_id;
        let task = tokio::spawn(run_stream(stream_id, tcp, inbound_rx, outbound));
        streams.insert(stream_id, StreamHandle { inbound_tx, task });
        drop(streams);

        metric_outcome("open_ok");
        tracing::info!(
            stream_id,
            dest = %open.dest,
            "tunnel open: registered"
        );
        AckStatus::Ok
    }

    /// Decode + dispatch a `TunnelData` body.
    pub async fn handle_data(&self, body: &[u8]) -> AckStatus {
        let data: TunnelData = match postcard::from_bytes(body) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %e, "tunnel data decode failed");
                metric_outcome("decode_error");
                return AckStatus::Reject(tunnel_reject::PAYLOAD_TOO_LARGE);
            }
        };
        if data.payload.len() > TUNNEL_DATA_MAX_PAYLOAD {
            tracing::warn!(
                stream_id = data.stream_id,
                bytes = data.payload.len(),
                cap = TUNNEL_DATA_MAX_PAYLOAD,
                "tunnel data exceeds per-chunk cap"
            );
            metric_outcome("payload_too_large");
            return AckStatus::Reject(tunnel_reject::PAYLOAD_TOO_LARGE);
        }

        let streams = self.streams.lock().await;
        match streams.get(&data.stream_id) {
            Some(h) => {
                if h.inbound_tx.send(data.payload).is_err() {
                    // Splice task has already exited (TCP closed); the
                    // registry hasn't been pruned yet. Treat as missing.
                    tracing::debug!(
                        stream_id = data.stream_id,
                        "tunnel data: splice task gone; dropping"
                    );
                    metric_outcome("stream_not_found");
                    return AckStatus::Reject(tunnel_reject::STREAM_NOT_FOUND);
                }
                metric_outcome("data_ok");
                AckStatus::Ok
            }
            None => {
                tracing::debug!(
                    stream_id = data.stream_id,
                    "tunnel data: unknown stream id"
                );
                metric_outcome("stream_not_found");
                AckStatus::Reject(tunnel_reject::STREAM_NOT_FOUND)
            }
        }
    }

    /// Decode + dispatch a `TunnelClose` body. Returns
    /// `Reject(STREAM_NOT_FOUND)` for unknown stream ids so the
    /// acceptor's dispatch can fall through to the forwarder (which
    /// owns proxied streams). Mirrors [`handle_data`]'s behaviour.
    pub async fn handle_close(&self, body: &[u8]) -> AckStatus {
        let close: TunnelClose = match postcard::from_bytes(body) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "tunnel close decode failed");
                metric_outcome("decode_error");
                // A malformed close is still treated as a request to
                // close; we have no id to act on so just ack Ok and
                // move on.
                return AckStatus::Ok;
            }
        };
        let mut streams = self.streams.lock().await;
        if let Some(handle) = streams.remove(&close.stream_id) {
            tracing::info!(
                stream_id = close.stream_id,
                reason = close.reason,
                "tunnel close: peer-initiated"
            );
            // Drop the inbound sender so the splice's writer-pump
            // drains its queue, shuts down the local TCP write half
            // (sending FIN to the dialled server), and exits. Do NOT
            // abort the splice task here: the reader-pump may still
            // be reading the server's response (e.g. HTTP/1.1 with
            // `Connection: close`, where the server sends the response
            // *after* seeing FIN). The splice task will exit on its
            // own when both halves are done, and emit a
            // `TunnelClose` envelope back to the initiator at that
            // point. See [`run_stream`] for the half-close mechanics.
            drop(handle.inbound_tx);
            // We deliberately drop the JoinHandle without aborting;
            // the task continues running until both pumps complete.
            drop(handle.task);
            metric_outcome("close_ok");
            AckStatus::Ok
        } else {
            tracing::debug!(
                stream_id = close.stream_id,
                "tunnel close: unknown stream id (falling through to forwarder if attached)"
            );
            metric_outcome("stream_not_found");
            AckStatus::Reject(tunnel_reject::STREAM_NOT_FOUND)
        }
    }

    /// Snapshot of currently-open stream ids. Used by tests + diagnostic
    /// endpoints; production code does not depend on the exact set.
    pub async fn open_stream_ids(&self) -> Vec<u32> {
        let s = self.streams.lock().await;
        s.keys().copied().collect()
    }
}

fn metric_outcome(outcome: &'static str) {
    metrics::counter!(
        "yggdrasil_chain_tunnel_terminator_total",
        "outcome" => outcome,
    )
    .increment(1);
}

/// Per-stream splice task. Runs until either side EOFs, the inbound
/// channel closes (peer sent TunnelClose), or the task is aborted.
///
/// On exit emits a [`TunnelClose`] envelope upstream (reason `0` for
/// clean shutdowns; non-zero is currently unused since the only
/// terminator-detectable failure is a TCP write error which still
/// signals a clean stream end to the peer's HTTP layer).
async fn run_stream(
    stream_id: u32,
    tcp: TcpStream,
    mut inbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    outbound: mpsc::UnboundedSender<ControlEnvelope>,
) {
    let (mut read_half, mut write_half) = tcp.into_split();

    // Pump TCP-read → outbound TunnelData envelopes.
    let outbound_for_reader = outbound.clone();
    let reader_task = tokio::spawn(async move {
        let mut buf = vec![0u8; TUNNEL_DATA_MAX_PAYLOAD];
        let mut bytes_read_total: usize = 0;
        let mut chunks_sent: usize = 0;
        loop {
            let n = match read_half.read(&mut buf).await {
                Ok(0) => {
                    tracing::debug!(
                        stream_id,
                        bytes_read_total,
                        chunks_sent,
                        "tunnel splice: reader EOF from local TCP"
                    );
                    break;
                }
                Ok(n) => {
                    bytes_read_total += n;
                    n
                }
                Err(e) => {
                    tracing::warn!(
                        stream_id,
                        error = %e,
                        bytes_read_total,
                        chunks_sent,
                        "tunnel splice: tcp read error"
                    );
                    break;
                }
            };
            let data = TunnelData {
                stream_id,
                payload: buf[..n].to_vec(),
            };
            let body = match postcard::to_allocvec(&data) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        stream_id,
                        error = %e,
                        "tunnel splice: postcard encode failed"
                    );
                    break;
                }
            };
            let env = ControlEnvelope {
                seq: 0, // HeartbeatServer drainer assigns the real seq
                body_type: ControlBodyType::TunnelData.as_byte(),
                body,
            };
            if outbound_for_reader.send(env).is_err() {
                tracing::warn!(
                    stream_id,
                    "tunnel splice: outbound channel closed; ending"
                );
                break;
            }
            chunks_sent += 1;
        }
    });

    // Pump inbound TunnelData payloads → TCP-write.
    let writer_task = tokio::spawn(async move {
        let mut bytes_written_total: usize = 0;
        let mut chunks_received: usize = 0;
        while let Some(payload) = inbound_rx.recv().await {
            chunks_received += 1;
            bytes_written_total += payload.len();
            if let Err(e) = write_half.write_all(&payload).await {
                tracing::warn!(
                    stream_id,
                    error = %e,
                    bytes_written_total,
                    chunks_received,
                    "tunnel splice: tcp write error"
                );
                break;
            }
        }
        tracing::debug!(
            stream_id,
            bytes_written_total,
            chunks_received,
            "tunnel splice: writer inbound_rx closed; shutting TCP write half"
        );
        // Caller (handle_close or reader EOF) drops inbound_tx; signal
        // half-close to the upstream TCP peer so HTTP can flush.
        let _ = write_half.shutdown().await;
    });

    // Wait for *both* pumps to finish. TCP-style half-close means each
    // direction is independent: writer_task ends when the peer drops
    // its write half (`handle_close` runs and drops `inbound_tx`),
    // reader_task ends when the local TCP server closes its write half
    // (e.g. HTTP/1.1 `Connection: close` after the response is fully
    // written). Aborting one when the other completes would truncate
    // the response on request/response patterns like
    // `yggdrasilctl chain diff`, so we deliberately wait for both.
    let (_r, _w) = tokio::join!(reader_task, writer_task);

    // Best-effort close-notification to the peer. Phase 4B is
    // fire-and-forget: if the channel is closed (session torn down),
    // dropping the envelope is fine.
    let close = TunnelClose { stream_id, reason: 0 };
    if let Ok(body) = postcard::to_allocvec(&close) {
        let env = ControlEnvelope {
            seq: 0,
            body_type: ControlBodyType::TunnelClose.as_byte(),
            body,
        };
        let _ = outbound.send(env);
    }
    tracing::debug!(stream_id, "tunnel splice task exited");
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatoskr::auth::PUBLIC_KEY_LEN;
    use tokio::net::TcpListener;

    fn sample_pubkey(seed: u8) -> PubKey {
        PubKey::x25519([seed; PUBLIC_KEY_LEN])
    }

    fn loopback_manager() -> (Arc<TunnelManager>, mpsc::UnboundedReceiver<ControlEnvelope>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let mgr = TunnelManager::new(TunnelAllowList::loopback_only(), sample_pubkey(1), tx);
        (mgr, rx)
    }

    fn open_envelope(stream_id: u32, target: PubKey, dest: SocketAddr) -> Vec<u8> {
        let open = TunnelOpen {
            stream_id,
            target_pubkey: target,
            dest,
        };
        postcard::to_allocvec(&open).unwrap()
    }

    fn data_envelope(stream_id: u32, payload: Vec<u8>) -> Vec<u8> {
        let data = TunnelData { stream_id, payload };
        postcard::to_allocvec(&data).unwrap()
    }

    fn close_envelope(stream_id: u32, reason: u16) -> Vec<u8> {
        let close = TunnelClose { stream_id, reason };
        postcard::to_allocvec(&close).unwrap()
    }

    /// Start a tiny TCP echo server on 127.0.0.1; returns its bound
    /// address. The server accepts exactly one connection and echoes
    /// bytes back until the client half-closes.
    async fn spawn_loopback_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn rejects_target_not_in_allow_list() {
        let (mgr, _rx) = loopback_manager();
        let body = open_envelope(
            1,
            sample_pubkey(1),
            "10.0.0.1:80".parse().unwrap(),
        );
        let status = mgr.handle_open(&body).await;
        assert_eq!(
            status,
            AckStatus::Reject(tunnel_reject::TARGET_NOT_ALLOWED)
        );
        assert!(mgr.open_stream_ids().await.is_empty());
    }

    #[tokio::test]
    async fn rejects_forward_to_non_self_target() {
        let (mgr, _rx) = loopback_manager();
        // local_pubkey was sample_pubkey(1); aim at a different key.
        let body = open_envelope(
            7,
            sample_pubkey(2),
            "127.0.0.1:1".parse().unwrap(),
        );
        let status = mgr.handle_open(&body).await;
        assert_eq!(
            status,
            AckStatus::Reject(tunnel_reject::TUNNEL_NOT_PERMITTED)
        );
    }

    #[tokio::test]
    async fn rejects_dial_failure_as_target_unreachable() {
        let (mgr, _rx) = loopback_manager();
        // 127.0.0.1:1 is virtually guaranteed to be closed.
        let body = open_envelope(
            1,
            sample_pubkey(1),
            "127.0.0.1:1".parse().unwrap(),
        );
        let status = mgr.handle_open(&body).await;
        assert_eq!(
            status,
            AckStatus::Reject(tunnel_reject::TARGET_UNREACHABLE)
        );
    }

    #[tokio::test]
    async fn open_dial_success_registers_stream() {
        let (mgr, _rx) = loopback_manager();
        let dest = spawn_loopback_echo().await;
        let body = open_envelope(42, sample_pubkey(1), dest);
        let status = mgr.handle_open(&body).await;
        assert_eq!(status, AckStatus::Ok);
        assert_eq!(mgr.open_stream_ids().await, vec![42]);
    }

    #[tokio::test]
    async fn duplicate_stream_id_rejects() {
        let (mgr, _rx) = loopback_manager();
        let dest = spawn_loopback_echo().await;
        let body = open_envelope(99, sample_pubkey(1), dest);
        assert_eq!(mgr.handle_open(&body).await, AckStatus::Ok);
        // Second open with same id; even with a fresh dest the manager
        // must refuse because the id is taken.
        let dest2 = spawn_loopback_echo().await;
        let body2 = open_envelope(99, sample_pubkey(1), dest2);
        assert_eq!(
            mgr.handle_open(&body2).await,
            AckStatus::Reject(tunnel_reject::DUPLICATE_STREAM_ID)
        );
    }

    #[tokio::test]
    async fn data_for_unknown_stream_rejects() {
        let (mgr, _rx) = loopback_manager();
        let body = data_envelope(404, vec![1, 2, 3]);
        let status = mgr.handle_data(&body).await;
        assert_eq!(
            status,
            AckStatus::Reject(tunnel_reject::STREAM_NOT_FOUND)
        );
    }

    #[tokio::test]
    async fn data_payload_exceeding_cap_rejects() {
        let (mgr, _rx) = loopback_manager();
        // We don't need a live stream — the cap check fires before the
        // registry lookup.
        let oversize = vec![0u8; TUNNEL_DATA_MAX_PAYLOAD + 1];
        let body = data_envelope(7, oversize);
        let status = mgr.handle_data(&body).await;
        assert_eq!(
            status,
            AckStatus::Reject(tunnel_reject::PAYLOAD_TOO_LARGE)
        );
    }

    #[tokio::test]
    async fn close_unknown_stream_returns_stream_not_found() {
        let (mgr, _rx) = loopback_manager();
        let body = close_envelope(123, 0);
        assert_eq!(
            mgr.handle_close(&body).await,
            AckStatus::Reject(tunnel_reject::STREAM_NOT_FOUND)
        );
    }

    #[tokio::test]
    async fn close_removes_open_stream() {
        let (mgr, _rx) = loopback_manager();
        let dest = spawn_loopback_echo().await;
        assert_eq!(
            mgr.handle_open(&open_envelope(5, sample_pubkey(1), dest))
                .await,
            AckStatus::Ok
        );
        assert_eq!(mgr.open_stream_ids().await, vec![5]);
        assert_eq!(
            mgr.handle_close(&close_envelope(5, 0)).await,
            AckStatus::Ok
        );
        assert!(mgr.open_stream_ids().await.is_empty());
    }

    #[tokio::test]
    async fn data_round_trip_through_loopback_echo() {
        let (mgr, mut rx) = loopback_manager();
        let dest = spawn_loopback_echo().await;
        assert_eq!(
            mgr.handle_open(&open_envelope(11, sample_pubkey(1), dest))
                .await,
            AckStatus::Ok
        );

        // Push bytes inbound; echo will bounce them back.
        let body = data_envelope(11, b"hello".to_vec());
        assert_eq!(mgr.handle_data(&body).await, AckStatus::Ok);

        // The splice task should emit a TunnelData envelope back with
        // the echoed bytes.
        let env = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("outbound envelope arrived")
            .expect("channel still open");
        assert_eq!(env.body_type, ControlBodyType::TunnelData.as_byte());
        let echoed: TunnelData = postcard::from_bytes(&env.body).unwrap();
        assert_eq!(echoed.stream_id, 11);
        assert_eq!(echoed.payload, b"hello");
    }

    #[tokio::test]
    async fn allow_list_with_explicit_entry_permits_dest() {
        let echo = spawn_loopback_echo().await;
        // Build an allow-list with loopback DISABLED but the echo
        // address explicitly listed, then verify open succeeds.
        let mut allowed = HashSet::new();
        allowed.insert(echo);
        let allow = TunnelAllowList {
            allow_loopback: false,
            allowed_targets: allowed,
        };
        let (tx, _rx) = mpsc::unbounded_channel();
        let mgr = TunnelManager::new(allow, sample_pubkey(1), tx);
        let body = open_envelope(33, sample_pubkey(1), echo);
        assert_eq!(mgr.handle_open(&body).await, AckStatus::Ok);
    }
}
