//! Originator-side tunnel state machine.
//!
//! The relay-side terminator in [`tunnel_terminator`] handles the
//! `target_pubkey == self` half of the protocol: dial a TCP backend,
//! splice bytes, ack everything. Phase 4C ships the *other* half: the
//! originator that opens a tunnel from the local node toward an upstream
//! relay and shovels bytes through it on behalf of an operator (today
//! `yggdrasilctl chain tunnel open`, tomorrow `huginn` dashboard).
//!
//! ## Architecture
//!
//! * [`TunnelInitiator`] owns a [`ChainClientHandle`] (so it can enqueue
//!   `TunnelOpen` / `TunnelData` / `TunnelClose` envelopes on the
//!   outbound control channel) and a registry of currently-open
//!   streams. The registry is keyed by the originator-chosen
//!   `stream_id`; ids are allocated monotonically via an `AtomicU32`
//!   starting at `1`. The id wraps after `u32::MAX`, but the registry's
//!   uniqueness check rejects any collision so a wraparound that hit a
//!   still-live stream fails fast.
//! * Each open stream has an [`InitiatorStream`] handle on the UDS-bridge
//!   side: an unbounded `mpsc::Sender<Vec<u8>>` that delivers inbound
//!   payloads (from the relay → us) and an `oneshot::Sender<u16>` that
//!   delivers the close reason. Backpressure is intentionally absent in
//!   v1; the chain client's per-ack reliability flow already gates how
//!   fast bytes can move.
//! * The chain client's [`BodyHandler`] is plumbed through
//!   [`TunnelInitiator::body_handler`]: inbound [`TunnelData`] envelopes
//!   are routed to the matching stream's mpsc; [`TunnelClose`] resolves
//!   the close oneshot and removes the entry. Anything else acks
//!   [`AckStatus::Unknown`].
//!
//! ## Reliability
//!
//! Initiator → relay reliability is *free*: the chain client owns a
//! [`ControlChannel`] that retransmits unacked envelopes with
//! exponential backoff and resolves a `oneshot::Receiver` when the ack
//! arrives. [`TunnelInitiator::open`], `send_data`, and `close` all
//! await that receiver and propagate `AckStatus::Reject(reason)` /
//! transport errors to the caller.
//!
//! Relay → initiator reliability is still fire-and-forget as of Phase 4B
//! (see [`tunnel_terminator`]). The bridge tolerates this by treating
//! the UDS connection as the only source of truth for stream lifetime;
//! a dropped inbound chunk surfaces as a short read on the operator
//! end, which is consistent with TCP-over-lossy-WAN behaviour.
//!
//! ## What this module is NOT
//!
//! * Not a multi-hop forwarder. `target_pubkey != self` on inbound is the
//!   *terminator's* concern; the initiator only ever sends with
//!   `target_pubkey = <our upstream>` in v1 and trusts the upstream to
//!   forward when Phase 5 lands.
//! * Not a UDS bridge. [`crate::control::dispatch_open_chain_tunnel`]
//!   handles the connection-hijack dance; this module exposes
//!   stream-level primitives the bridge composes.
//!
//! [`tunnel_terminator`]: crate::chain::tunnel_terminator
//! [`ChainClientHandle`]: crate::chain::client::ChainClientHandle
//! [`BodyHandler`]: crate::chain::client::BodyHandler
//! [`ControlChannel`]: crate::chain::reliability::ControlChannel
//! [`TunnelData`]: ratatoskr::tunnel::TunnelData
//! [`TunnelClose`]: ratatoskr::tunnel::TunnelClose

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ratatoskr::control_frame::{AckStatus, ControlBodyType};
use ratatoskr::pubkey::PubKey;
use ratatoskr::tunnel::{
    tunnel_reject, TunnelClose, TunnelData, TunnelOpen, TUNNEL_DATA_MAX_PAYLOAD,
};
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::chain::client::{BodyHandler, ChainClientHandle, ChainClientShutDown};
use crate::chain::reliability::SendError;

/// Default per-send ack deadline. Capped well above the chain client's
/// own retransmit budget (`RETX_MAX_ATTEMPTS × RETX_MAX = 5 × 2s`) so a
/// stuck client task is the only thing that trips it; ordinary packet
/// loss is handled by the reliability layer transparently.
pub const DEFAULT_ACK_DEADLINE: Duration = Duration::from_secs(15);

/// Internal stream registry entry. Held by the initiator while the
/// stream is open; dropped + removed on close (local or peer-initiated).
#[derive(Debug)]
struct StreamEntry {
    /// Push inbound payload bytes (from the chain peer) toward the
    /// bridge. The bridge holds the matching `Receiver` and pumps the
    /// bytes onto the UDS write half.
    inbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Resolved when the peer sends a [`TunnelClose`]; carries the
    /// `reason` code (`0` = clean). The bridge holds the matching
    /// `Receiver` and uses it to short-circuit the UDS read loop.
    close_tx: Option<oneshot::Sender<u16>>,
}

/// Handle returned by [`TunnelInitiator::open`] for the UDS-bridge to
/// receive inbound bytes + the peer's close signal, and to issue
/// outbound `send_data` / `close` on the stream id.
///
/// Dropping the handle does **not** automatically close the stream —
/// the caller must invoke [`TunnelInitiator::close`] to send a
/// [`TunnelClose`] envelope on the wire. (Drop-only close would race
/// with the bridge teardown order; explicit close keeps the wire-
/// observable lifetime obvious.)
#[derive(Debug)]
pub struct InitiatorStream {
    /// Originator-chosen stream id; stable for the lifetime of the
    /// stream.
    pub stream_id: u32,
    /// Inbound bytes from the chain peer. The mpsc closes when the
    /// initiator removes the entry (peer close or local close).
    pub inbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Fires once with the peer's `reason` code on a peer-initiated
    /// close. Resolves to `Err(oneshot::Canceled)` if the initiator
    /// removes the entry locally first.
    pub close_rx: oneshot::Receiver<u16>,
}

/// Error returned by [`TunnelInitiator::open`].
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The chain client task has exited; no envelopes can be sent.
    #[error("chain client is shut down")]
    ChainClientShutDown,
    /// The chain client's reliability layer dropped or failed the
    /// outbound send (peer ack timeout, rejected with a non-`Ok`
    /// status, channel close while waiting).
    #[error("chain control send failed: {0}")]
    SendFailed(#[source] SendError),
    /// The upstream relay returned `AckStatus::Reject(reason)` for the
    /// `TunnelOpen` envelope. The `reason` code is one of the values in
    /// [`tunnel_reject`](ratatoskr::tunnel::tunnel_reject).
    #[error("upstream rejected tunnel open: reason={0}")]
    Rejected(u16),
    /// The reliability layer's `oneshot::Receiver` was dropped before
    /// it produced a value. In practice this means the client task was
    /// cancelled mid-send; treat it as a transport failure and retry.
    #[error("ack receiver dropped before producing a value")]
    AckChannelClosed,
}

impl From<ChainClientShutDown> for OpenError {
    fn from(_: ChainClientShutDown) -> Self {
        Self::ChainClientShutDown
    }
}

/// Error returned by [`TunnelInitiator::send_data`].
#[derive(Debug, thiserror::Error)]
pub enum SendDataError {
    /// `payload.len() > TUNNEL_DATA_MAX_PAYLOAD`; the caller must chunk.
    #[error(
        "payload {bytes} exceeds per-chunk cap {cap}; caller must chunk before send"
    )]
    PayloadTooLarge { bytes: usize, cap: usize },
    /// `stream_id` is not a live stream on this initiator. The caller
    /// either passed a bogus id or the stream was already closed locally
    /// or remotely.
    #[error("stream id {0} is not currently open on this initiator")]
    UnknownStream(u32),
    /// The chain client task is gone.
    #[error("chain client is shut down")]
    ChainClientShutDown,
    /// Reliability layer reported an outbound failure.
    #[error("chain control send failed: {0}")]
    SendFailed(#[source] SendError),
    /// Upstream rejected the data envelope (e.g. `STREAM_NOT_FOUND`
    /// because the terminator already tore down).
    #[error("upstream rejected tunnel data: reason={0}")]
    Rejected(u16),
    /// `oneshot::Receiver` dropped before producing a value.
    #[error("ack receiver dropped before producing a value")]
    AckChannelClosed,
}

impl From<ChainClientShutDown> for SendDataError {
    fn from(_: ChainClientShutDown) -> Self {
        Self::ChainClientShutDown
    }
}

/// Originator-side tunnel state machine. Construct with
/// [`TunnelInitiator::new`] in a daemon that has a chain upstream
/// configured; the same instance lives for the lifetime of the chain
/// client and serves multiple concurrent UDS bridges.
#[derive(Debug)]
pub struct TunnelInitiator {
    chain: ChainClientHandle,
    /// Pubkey of this node's chain upstream. Initiators record this so
    /// they can populate diagnostics; the protocol layer no longer
    /// constrains `TunnelOpen.target_pubkey` to equal it — Phase 5
    /// multi-hop forwarding lets the originator target any pubkey on
    /// the chain.
    #[allow(dead_code)]
    upstream_pubkey: PubKey,
    /// Monotone allocator for upstream-side stream IDs. Held by `Arc` so
    /// a [`TunnelForwarder`] running alongside this initiator (on a
    /// relay that both originates and forwards tunnels through the
    /// same upstream chain) can share the same ID space — preventing
    /// any chance of a forwarded stream colliding with a
    /// locally-originated one.
    ///
    /// [`TunnelForwarder`]: crate::chain::tunnel_forwarder::TunnelForwarder
    next_stream_id: Arc<AtomicU32>,
    streams: Mutex<HashMap<u32, StreamEntry>>,
}

impl TunnelInitiator {
    /// Construct an initiator bound to the given chain client and
    /// upstream pubkey. The upstream pubkey is the chain peer that will
    /// terminate the tunnel (or forward it in a future multi-hop world).
    pub fn new(chain: ChainClientHandle, upstream_pubkey: PubKey) -> Arc<Self> {
        Arc::new(Self {
            chain,
            upstream_pubkey,
            // Start at 1 so a fresh initiator never emits `stream_id =
            // 0`, which keeps the wire-trace easy to read (test vectors
            // and the terminator both pick low non-zero ids by
            // convention).
            next_stream_id: Arc::new(AtomicU32::new(1)),
            streams: Mutex::new(HashMap::new()),
        })
    }

    /// Hand out a clone of the upstream-side stream-id allocator. The
    /// chain-side [`TunnelForwarder`] uses this to mint upstream stream
    /// IDs for forwarded tunnels that share the same upstream chain as
    /// this initiator, ensuring no two subsystems ever emit the same
    /// id on the same outbound chain client.
    ///
    /// [`TunnelForwarder`]: crate::chain::tunnel_forwarder::TunnelForwarder
    pub fn stream_id_allocator(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.next_stream_id)
    }

    /// Open a fresh stream toward `dest` on `target_pubkey`. Sends a
    /// `TunnelOpen` envelope, awaits its ack, and returns an
    /// [`InitiatorStream`] that the caller (UDS bridge) uses for
    /// subsequent IO. On `Ok` the registry holds the stream until
    /// either [`TunnelInitiator::close`] or an inbound `TunnelClose`
    /// removes it; on `Err` the registry is unmodified.
    ///
    /// `target_pubkey` is the pubkey of the chain node that should
    /// terminate the tunnel. When it equals this initiator's direct
    /// upstream, the upstream terminates locally. When it points
    /// further into the chain, the upstream's
    /// [`TunnelForwarder`](crate::chain::tunnel_forwarder::TunnelForwarder)
    /// rewrites the stream id and relays the envelope onward.
    pub async fn open(
        self: &Arc<Self>,
        target_pubkey: PubKey,
        dest: SocketAddr,
    ) -> Result<InitiatorStream, OpenError> {
        let stream_id = self.alloc_stream_id();
        let body = TunnelOpen {
            stream_id,
            target_pubkey,
            dest,
        };
        let body_bytes = postcard::to_allocvec(&body)
            .expect("TunnelOpen postcard encode is infallible for fixed-size fields");

        // Register the entry *before* sending so an unusually fast ack
        // path that arrives before this future yields cannot trip the
        // "unknown stream id" branch.
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (close_tx, close_rx) = oneshot::channel();
        {
            let mut streams = self.streams.lock().await;
            // Wraparound + collision is vanishingly unlikely but checked
            // to keep the invariant tight.
            if streams.contains_key(&stream_id) {
                metric_outcome("open_id_collision");
                return Err(OpenError::SendFailed(SendError::ChannelClosed));
            }
            streams.insert(
                stream_id,
                StreamEntry {
                    inbound_tx,
                    close_tx: Some(close_tx),
                },
            );
        }

        let rx = match self.chain.send_control(
            ControlBodyType::TunnelOpen.as_byte(),
            body_bytes,
        ) {
            Ok(rx) => rx,
            Err(e) => {
                // Roll back the registry entry: the open envelope was
                // never enqueued, so callers should see "open failed"
                // not "stream open but unusable".
                self.remove_stream(stream_id).await;
                metric_outcome("open_client_shutdown");
                return Err(OpenError::from(e));
            }
        };

        // `rx` resolves when the chain client either gets an `Ok` ack,
        // gets a `Reject(reason)` ack, or gives up (timeout / channel
        // closed). All three are handled here.
        match rx.await {
            Ok(Ok(())) => {
                metric_outcome("open_ok");
                Ok(InitiatorStream {
                    stream_id,
                    inbound_rx,
                    close_rx,
                })
            }
            Ok(Err(SendError::Rejected(reason))) => {
                self.remove_stream(stream_id).await;
                metric_outcome("open_rejected");
                Err(OpenError::Rejected(reason))
            }
            Ok(Err(e)) => {
                self.remove_stream(stream_id).await;
                metric_outcome("open_send_failed");
                Err(OpenError::SendFailed(e))
            }
            Err(_recv_err) => {
                // The client task dropped the completion sender without
                // producing a result. The reliability layer guarantees
                // this only happens on shutdown.
                self.remove_stream(stream_id).await;
                metric_outcome("open_ack_channel_closed");
                Err(OpenError::AckChannelClosed)
            }
        }
    }

    /// Send one chunk of bytes on an open stream and await its ack.
    ///
    /// `payload.len()` must be `<= TUNNEL_DATA_MAX_PAYLOAD`; oversize
    /// chunks return [`SendDataError::PayloadTooLarge`] without
    /// touching the wire. Caller is responsible for chunking.
    pub async fn send_data(
        &self,
        stream_id: u32,
        payload: Vec<u8>,
    ) -> Result<(), SendDataError> {
        if payload.len() > TUNNEL_DATA_MAX_PAYLOAD {
            metric_outcome("send_payload_too_large");
            return Err(SendDataError::PayloadTooLarge {
                bytes: payload.len(),
                cap: TUNNEL_DATA_MAX_PAYLOAD,
            });
        }
        // Cheap presence check without holding the lock across the
        // send/await: streams cannot be re-created with the same id
        // (monotone allocator), so a "live now, gone later" race only
        // converts our success into an upstream `STREAM_NOT_FOUND`
        // reject — which we surface as `Rejected` rather than as
        // `UnknownStream`. The local pre-check is defence in depth.
        {
            let streams = self.streams.lock().await;
            if !streams.contains_key(&stream_id) {
                metric_outcome("send_unknown_stream");
                return Err(SendDataError::UnknownStream(stream_id));
            }
        }

        let body = TunnelData { stream_id, payload };
        let body_bytes = postcard::to_allocvec(&body)
            .expect("TunnelData postcard encode is infallible");
        let rx = self
            .chain
            .send_control(ControlBodyType::TunnelData.as_byte(), body_bytes)?;
        match rx.await {
            Ok(Ok(())) => {
                metric_outcome("send_ok");
                Ok(())
            }
            Ok(Err(SendError::Rejected(reason))) => {
                metric_outcome("send_rejected");
                Err(SendDataError::Rejected(reason))
            }
            Ok(Err(e)) => {
                metric_outcome("send_failed");
                Err(SendDataError::SendFailed(e))
            }
            Err(_recv_err) => {
                metric_outcome("send_ack_channel_closed");
                Err(SendDataError::AckChannelClosed)
            }
        }
    }

    /// Send a `TunnelClose` envelope for `stream_id`, remove the entry
    /// from the local registry, and await the upstream ack. Idempotent:
    /// closing a stream that is not in the registry does nothing and
    /// returns `Ok(())` (callers race with peer-initiated close all
    /// the time).
    ///
    /// Errors from the reliability layer or a `Reject(reason)` ack are
    /// best-effort logs only — by the time we're closing the stream is
    /// already gone locally, so there's nothing useful to do with the
    /// failure. The function returns `Ok(())` in those cases too and
    /// emits a `close_*` metric so an operator can see how often acks
    /// dropped.
    pub async fn close(&self, stream_id: u32, reason: u16) {
        let removed = self.remove_stream(stream_id).await;
        if !removed {
            // No-op: already closed (peer-initiated or duplicate local
            // close). The wire-level `TunnelClose` was already sent (or
            // received) the first time around.
            metric_outcome("close_noop");
            return;
        }
        let body = TunnelClose { stream_id, reason };
        let body_bytes = postcard::to_allocvec(&body)
            .expect("TunnelClose postcard encode is infallible");
        let rx = match self.chain.send_control(
            ControlBodyType::TunnelClose.as_byte(),
            body_bytes,
        ) {
            Ok(rx) => rx,
            Err(_) => {
                metric_outcome("close_client_shutdown");
                return;
            }
        };
        match rx.await {
            Ok(Ok(())) => metric_outcome("close_ok"),
            Ok(Err(SendError::Rejected(_))) => metric_outcome("close_rejected"),
            Ok(Err(_)) => metric_outcome("close_send_failed"),
            Err(_) => metric_outcome("close_ack_channel_closed"),
        }
    }

    /// Snapshot of currently-open stream ids. Test + diagnostic only.
    #[doc(hidden)]
    pub async fn open_stream_ids(&self) -> Vec<u32> {
        let streams = self.streams.lock().await;
        streams.keys().copied().collect()
    }

    /// Build a [`BodyHandler`] closure suitable for plumbing into the
    /// [`ChainClientConfig::body_handler`] slot. The closure routes
    /// `TunnelData` envelopes into the matching stream's inbound mpsc
    /// and `TunnelClose` envelopes into the matching stream's close
    /// oneshot. Anything else acks [`AckStatus::Unknown`].
    ///
    /// [`ChainClientConfig::body_handler`]: crate::chain::client::ChainClientConfig::body_handler
    pub fn body_handler(self: &Arc<Self>) -> BodyHandler {
        let me = Arc::clone(self);
        Arc::new(move |body_type: u8, body: &[u8]| -> AckStatus {
            me.dispatch_inbound(body_type, body)
        })
    }

    /// Synchronous inbound dispatch. Called from the chain client's
    /// `run` loop, so it must not `.await`; we use `try_lock` on the
    /// mutex and treat contention as `STREAM_NOT_FOUND` rather than
    /// blocking the heartbeat loop.
    ///
    /// Visible to `pub(crate)` so the chain-tunnel router can chain
    /// this dispatch with a fall-through to a [`TunnelForwarder`] for
    /// stream ids that don't belong to this initiator.
    ///
    /// [`TunnelForwarder`]: crate::chain::tunnel_forwarder::TunnelForwarder
    pub(crate) fn dispatch_inbound(&self, body_type: u8, body: &[u8]) -> AckStatus {
        let kind = match ControlBodyType::from_byte(body_type) {
            Some(k) => k,
            None => return AckStatus::Unknown,
        };
        match kind {
            ControlBodyType::TunnelData => self.handle_data(body),
            ControlBodyType::TunnelClose => self.handle_close(body),
            _ => AckStatus::Unknown,
        }
    }

    fn handle_data(&self, body: &[u8]) -> AckStatus {
        let data: TunnelData = match postcard::from_bytes(body) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %e, "initiator: TunnelData decode failed");
                metric_outcome("inbound_decode_error");
                return AckStatus::Reject(tunnel_reject::PAYLOAD_TOO_LARGE);
            }
        };
        if data.payload.len() > TUNNEL_DATA_MAX_PAYLOAD {
            tracing::warn!(
                stream_id = data.stream_id,
                bytes = data.payload.len(),
                cap = TUNNEL_DATA_MAX_PAYLOAD,
                "initiator: TunnelData over cap"
            );
            metric_outcome("inbound_payload_too_large");
            return AckStatus::Reject(tunnel_reject::PAYLOAD_TOO_LARGE);
        }
        // `try_lock` keeps the chain client loop strictly non-blocking.
        // Contention on this lock is bounded by `open` / `close` / the
        // peer-close arm of `dispatch_inbound` itself, all of which
        // hold the lock for microseconds. Tunnel data delivery is the
        // hot path and must not stall on an `await`.
        let streams = match self.streams.try_lock() {
            Ok(g) => g,
            Err(_) => {
                metric_outcome("inbound_lock_contention");
                // Asking the peer to retransmit costs nothing — the
                // reliability layer will redeliver this envelope on
                // its next retx tick. Telling the peer the stream is
                // missing would tear down a perfectly-good tunnel.
                return AckStatus::Reject(tunnel_reject::PAYLOAD_TOO_LARGE);
            }
        };
        match streams.get(&data.stream_id) {
            Some(entry) => {
                if entry.inbound_tx.send(data.payload).is_err() {
                    tracing::debug!(
                        stream_id = data.stream_id,
                        "initiator: inbound mpsc closed; bridge has exited"
                    );
                    metric_outcome("inbound_bridge_gone");
                    AckStatus::Reject(tunnel_reject::STREAM_NOT_FOUND)
                } else {
                    metric_outcome("inbound_data_ok");
                    AckStatus::Ok
                }
            }
            None => {
                tracing::debug!(
                    stream_id = data.stream_id,
                    "initiator: TunnelData for unknown stream id"
                );
                metric_outcome("inbound_stream_not_found");
                AckStatus::Reject(tunnel_reject::STREAM_NOT_FOUND)
            }
        }
    }

    fn handle_close(&self, body: &[u8]) -> AckStatus {
        let close: TunnelClose = match postcard::from_bytes(body) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "initiator: TunnelClose decode failed");
                metric_outcome("inbound_decode_error");
                // The peer wants the stream closed; we have nothing to
                // do (no id to act on) so just ack `Ok` and move on.
                return AckStatus::Ok;
            }
        };
        // Same try_lock posture as `handle_data` — close is idempotent
        // and will be retransmitted by the peer's reliability layer if
        // we contend; nothing to lose by deferring.
        let mut streams = match self.streams.try_lock() {
            Ok(g) => g,
            Err(_) => {
                metric_outcome("inbound_lock_contention");
                return AckStatus::Ok;
            }
        };
        if let Some(mut entry) = streams.remove(&close.stream_id) {
            // Signal the bridge: peer-initiated close with this reason.
            if let Some(tx) = entry.close_tx.take() {
                let _ = tx.send(close.reason);
            }
            // Dropping `entry.inbound_tx` closes the inbound mpsc so
            // the bridge's read-from-tunnel loop sees `None` and unwinds.
            drop(entry);
            tracing::info!(
                stream_id = close.stream_id,
                reason = close.reason,
                "initiator: peer-initiated close"
            );
            metric_outcome("inbound_close_ok");
        } else {
            tracing::debug!(
                stream_id = close.stream_id,
                "initiator: TunnelClose for unknown stream id (idempotent)"
            );
            metric_outcome("inbound_close_unknown");
        }
        AckStatus::Ok
    }

    /// Pubkey of this node's chain upstream. Surfaced so a UDS bridge
    /// can verify the operator-supplied `target_pubkey` matches before
    /// reaching for [`TunnelInitiator::open`]. (The same check fires
    /// inside `open` as defence in depth.)
    pub fn upstream_pubkey(&self) -> PubKey {
        self.upstream_pubkey
    }

    fn alloc_stream_id(&self) -> u32 {
        // `Ordering::Relaxed` is fine: the registry insert under the
        // mutex is the actual uniqueness check; the atomic is only a
        // hint.
        let mut id = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
        if id == 0 {
            // Skip `0` — see `TunnelInitiator::new` for the rationale.
            id = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
        }
        id
    }

    /// Remove the registry entry for `stream_id`. Returns `true` if an
    /// entry was actually removed (the caller is the one initiating the
    /// close); `false` if it was already gone.
    async fn remove_stream(&self, stream_id: u32) -> bool {
        let mut streams = self.streams.lock().await;
        streams.remove(&stream_id).is_some()
    }
}

fn metric_outcome(outcome: &'static str) {
    metrics::counter!(
        "yggdrasil_chain_tunnel_initiator_total",
        "outcome" => outcome,
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::chain::client::{ChainClientHandle, ControlOp};
    use ratatoskr::control_frame::AckStatus;
    use ratatoskr::tunnel::{TunnelClose, TunnelData, TunnelOpen};
    use tokio::sync::mpsc;

    fn fake_pubkey(byte: u8) -> PubKey {
        PubKey::x25519([byte; 32])
    }

    /// Spawn a tiny background "reliability layer": consume `ControlOp`s
    /// from the chain client mpsc, decode the body, hand it to the
    /// supplied responder, and resolve the completion oneshot with the
    /// responder's verdict. Lets us drive `open` / `send_data` / `close`
    /// in unit tests without a real chain client.
    fn fake_chain_client<F>(mut responder: F) -> (ChainClientHandle, tokio::task::JoinHandle<()>)
    where
        F: FnMut(u8, &[u8]) -> Result<(), SendError> + Send + 'static,
    {
        let (tx, mut rx) = mpsc::unbounded_channel::<ControlOp>();
        let join = tokio::spawn(async move {
            while let Some(op) = rx.recv().await {
                let verdict = responder(op.body_type, &op.body);
                let _ = op.completion.send(verdict);
            }
        });
        (ChainClientHandle::__test_new(tx), join)
    }

    #[tokio::test]
    async fn open_round_trips_through_chain_client_and_registers_stream() {
        let (handle, _join) = fake_chain_client(|body_type, body| {
            assert_eq!(body_type, ControlBodyType::TunnelOpen.as_byte());
            let open: TunnelOpen = postcard::from_bytes(body).unwrap();
            assert_eq!(open.dest.port(), 8080);
            Ok(())
        });
        let upstream = fake_pubkey(0x11);
        let initiator = TunnelInitiator::new(handle, upstream);
        let stream = initiator
            .open(upstream, "127.0.0.1:8080".parse().unwrap())
            .await
            .expect("open should succeed");
        assert!(stream.stream_id >= 1);
        let live = initiator.open_stream_ids().await;
        assert!(live.contains(&stream.stream_id));
    }

    #[tokio::test]
    async fn open_emits_target_pubkey_verbatim_for_multi_hop() {
        // Phase 5: the initiator no longer constrains `target_pubkey`
        // to equal `upstream_pubkey`; it puts whatever the caller
        // passed onto the wire so an upstream forwarder can route it
        // onward. This test pins that contract.
        use std::sync::Mutex;
        let captured: Arc<Mutex<Option<TunnelOpen>>> = Arc::new(Mutex::new(None));
        let captured_cl = Arc::clone(&captured);
        let (handle, _join) = fake_chain_client(move |body_type, body| {
            assert_eq!(body_type, ControlBodyType::TunnelOpen.as_byte());
            let open: TunnelOpen = postcard::from_bytes(body).unwrap();
            *captured_cl.lock().unwrap() = Some(open);
            Ok(())
        });
        let upstream = fake_pubkey(0x11);
        let downstream_terminator = fake_pubkey(0xEE);
        let initiator = TunnelInitiator::new(handle, upstream);
        let stream = initiator
            .open(downstream_terminator, "127.0.0.1:1".parse().unwrap())
            .await
            .expect("multi-hop open should succeed");
        let got = captured.lock().unwrap().clone().expect("open went to wire");
        assert_eq!(
            got.target_pubkey, downstream_terminator,
            "initiator must put the caller-provided target on the wire verbatim"
        );
        assert_eq!(got.stream_id, stream.stream_id);
    }

    #[tokio::test]
    async fn open_propagates_reject_and_rolls_back_registry() {
        let (handle, _join) = fake_chain_client(|_, _| {
            Err(SendError::Rejected(tunnel_reject::TARGET_NOT_ALLOWED))
        });
        let upstream = fake_pubkey(0x22);
        let initiator = TunnelInitiator::new(handle, upstream);
        let err = initiator
            .open(upstream, "10.0.0.1:443".parse().unwrap())
            .await
            .expect_err("expected reject");
        match err {
            OpenError::Rejected(r) => {
                assert_eq!(r, tunnel_reject::TARGET_NOT_ALLOWED)
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(
            initiator.open_stream_ids().await.is_empty(),
            "rejected open must not leave a registry entry behind"
        );
    }

    #[tokio::test]
    async fn open_propagates_send_failed_and_rolls_back_registry() {
        let (handle, _join) = fake_chain_client(|_, _| Err(SendError::ChannelClosed));
        let upstream = fake_pubkey(0x33);
        let initiator = TunnelInitiator::new(handle, upstream);
        let err = initiator
            .open(upstream, "127.0.0.1:9999".parse().unwrap())
            .await
            .expect_err("expected send failure");
        assert!(matches!(err, OpenError::SendFailed(_)));
        assert!(initiator.open_stream_ids().await.is_empty());
    }

    #[tokio::test]
    async fn send_data_rejects_oversize_without_touching_the_wire() {
        let (handle, _join) = fake_chain_client(|_, _| {
            panic!("oversize payload must short-circuit before the wire")
        });
        let initiator = TunnelInitiator::new(handle, fake_pubkey(0x44));
        let huge = vec![0u8; TUNNEL_DATA_MAX_PAYLOAD + 1];
        let err = initiator
            .send_data(1, huge)
            .await
            .expect_err("oversize must fail");
        match err {
            SendDataError::PayloadTooLarge { bytes, cap } => {
                assert_eq!(bytes, TUNNEL_DATA_MAX_PAYLOAD + 1);
                assert_eq!(cap, TUNNEL_DATA_MAX_PAYLOAD);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_data_unknown_stream_short_circuits() {
        let (handle, _join) = fake_chain_client(|_, _| {
            panic!("unknown-stream send must short-circuit before the wire")
        });
        let initiator = TunnelInitiator::new(handle, fake_pubkey(0x55));
        let err = initiator
            .send_data(0xDEAD_BEEF, b"x".to_vec())
            .await
            .expect_err("unknown stream id must fail");
        match err {
            SendDataError::UnknownStream(id) => assert_eq!(id, 0xDEAD_BEEF),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_data_round_trip_acks_ok() {
        let (handle, _join) = fake_chain_client(|body_type, body| {
            if body_type == ControlBodyType::TunnelOpen.as_byte() {
                return Ok(());
            }
            if body_type == ControlBodyType::TunnelData.as_byte() {
                let data: TunnelData = postcard::from_bytes(body).unwrap();
                assert_eq!(data.payload, b"hello");
                return Ok(());
            }
            panic!("unexpected body type {body_type}");
        });
        let upstream = fake_pubkey(0x66);
        let initiator = TunnelInitiator::new(handle, upstream);
        let stream = initiator
            .open(upstream, "127.0.0.1:1".parse().unwrap())
            .await
            .unwrap();
        initiator
            .send_data(stream.stream_id, b"hello".to_vec())
            .await
            .expect("send_data should succeed");
    }

    #[tokio::test]
    async fn close_removes_registry_entry_and_emits_close_envelope() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let saw_close = Arc::new(AtomicBool::new(false));
        let saw_close_clone = saw_close.clone();
        let (handle, _join) = fake_chain_client(move |body_type, body| {
            if body_type == ControlBodyType::TunnelClose.as_byte() {
                let _close: TunnelClose = postcard::from_bytes(body).unwrap();
                saw_close_clone.store(true, Ordering::SeqCst);
            }
            Ok(())
        });
        let upstream = fake_pubkey(0x77);
        let initiator = TunnelInitiator::new(handle, upstream);
        let stream = initiator
            .open(upstream, "127.0.0.1:2".parse().unwrap())
            .await
            .unwrap();
        initiator.close(stream.stream_id, 0).await;
        assert!(initiator.open_stream_ids().await.is_empty());
        assert!(saw_close.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn close_on_unknown_stream_is_noop_and_does_not_touch_the_wire() {
        let (handle, _join) = fake_chain_client(|_, _| {
            panic!("close on unknown stream must short-circuit before the wire")
        });
        let initiator = TunnelInitiator::new(handle, fake_pubkey(0x88));
        initiator.close(0xDEAD_BEEF, 0).await;
    }

    #[tokio::test]
    async fn body_handler_routes_inbound_tunnel_data_into_stream_mpsc() {
        let (handle, _join) = fake_chain_client(|_, _| Ok(()));
        let upstream = fake_pubkey(0x99);
        let initiator = TunnelInitiator::new(handle, upstream);
        let mut stream = initiator
            .open(upstream, "127.0.0.1:3".parse().unwrap())
            .await
            .unwrap();
        let dispatcher = initiator.body_handler();
        let data = TunnelData {
            stream_id: stream.stream_id,
            payload: b"inbound!".to_vec(),
        };
        let body = postcard::to_allocvec(&data).unwrap();
        let ack = dispatcher(ControlBodyType::TunnelData.as_byte(), &body);
        assert_eq!(ack, AckStatus::Ok);
        let received = stream
            .inbound_rx
            .recv()
            .await
            .expect("payload should be delivered");
        assert_eq!(received, b"inbound!");
    }

    #[tokio::test]
    async fn body_handler_returns_stream_not_found_for_unknown_id() {
        let (handle, _join) = fake_chain_client(|_, _| Ok(()));
        let initiator = TunnelInitiator::new(handle, fake_pubkey(0xAA));
        let dispatcher = initiator.body_handler();
        let data = TunnelData {
            stream_id: 0xFEED_FACE,
            payload: b"x".to_vec(),
        };
        let body = postcard::to_allocvec(&data).unwrap();
        let ack = dispatcher(ControlBodyType::TunnelData.as_byte(), &body);
        assert_eq!(ack, AckStatus::Reject(tunnel_reject::STREAM_NOT_FOUND));
    }

    #[tokio::test]
    async fn body_handler_close_resolves_close_rx_and_removes_entry() {
        let (handle, _join) = fake_chain_client(|_, _| Ok(()));
        let upstream = fake_pubkey(0xBB);
        let initiator = TunnelInitiator::new(handle, upstream);
        let stream = initiator
            .open(upstream, "127.0.0.1:4".parse().unwrap())
            .await
            .unwrap();
        let dispatcher = initiator.body_handler();
        let close = TunnelClose {
            stream_id: stream.stream_id,
            reason: 42,
        };
        let body = postcard::to_allocvec(&close).unwrap();
        let ack = dispatcher(ControlBodyType::TunnelClose.as_byte(), &body);
        assert_eq!(ack, AckStatus::Ok);
        let reason = stream.close_rx.await.expect("close_rx should resolve");
        assert_eq!(reason, 42);
        assert!(initiator.open_stream_ids().await.is_empty());
    }

    #[tokio::test]
    async fn body_handler_returns_unknown_for_non_tunnel_body_types() {
        let (handle, _join) = fake_chain_client(|_, _| Ok(()));
        let initiator = TunnelInitiator::new(handle, fake_pubkey(0xCC));
        let dispatcher = initiator.body_handler();
        let ack = dispatcher(0xFE, &[1, 2, 3]);
        assert_eq!(ack, AckStatus::Unknown);
    }

    #[tokio::test]
    async fn alloc_stream_id_skips_zero_after_wrap() {
        let (handle, _join) = fake_chain_client(|_, _| Ok(()));
        let initiator = TunnelInitiator::new(handle, fake_pubkey(0xDD));
        // Manually drive the allocator close to wrap-around so we can
        // see the `0 → skip` branch fire.
        initiator
            .next_stream_id
            .store(u32::MAX, Ordering::Relaxed);
        let first = initiator.alloc_stream_id();
        let second = initiator.alloc_stream_id();
        assert_eq!(first, u32::MAX);
        assert_ne!(second, 0, "must not hand out stream_id 0 even on wrap");
        assert_eq!(second, 1);
    }
}
