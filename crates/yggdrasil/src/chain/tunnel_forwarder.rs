//! Mid-chain tunnel forwarder.
//!
//! Phase 4B shipped the *terminator* (relay-side, `target_pubkey == self`
//! → splice to a TCP backend) and Phase 4C shipped the *initiator*
//! (leaf-side, originate a tunnel toward our own upstream). Phase 5
//! fills in the middle: when a mid-chain relay receives a `TunnelOpen`
//! whose `target_pubkey` is **not** ours, we now relay it one hop up
//! the chain and proxy bytes both ways for the lifetime of the stream.
//!
//! ## Position in the chain
//!
//! ```text
//!     downstream peer            (this relay)              upstream peer
//!     ───────────────            ─────────────              ─────────────
//!     ChainAcceptor   ◀── TunnelOpen ──▶  routing on
//!                                         target_pubkey:
//!                                          == local → terminator
//!                                          != local → forwarder ────▶ ChainClient ──▶
//!                                                                                      
//!     downstream_outbound  ◀── TunnelData ◀──── relay re-write upstream stream_id
//!     (heartbeat server)        downstream id      to downstream id
//!                                                  ▲
//!                                                  │
//!                                                  upstream ChainClient body_handler
//!                                                  (combined initiator + forwarder)
//! ```
//!
//! ## State per forwarded stream
//!
//! The forwarder maintains a bidirectional pair of `HashMap`s keyed by
//! the two **independent** stream-id spaces it has to bridge:
//!
//! * `by_downstream: HashMap<u32, ForwardedStream>` — keyed by the
//!   downstream-chosen `stream_id` we saw on the inbound `TunnelOpen`.
//!   Carries the upstream-side `stream_id` we minted and the
//!   `target_pubkey` (kept for diagnostics).
//! * `by_upstream: HashMap<u32, u32>` — reverse lookup, keyed by the
//!   upstream-chosen `stream_id` we emitted on the outbound `TunnelOpen`,
//!   mapping back to the downstream-chosen `stream_id`. Used when an
//!   upstream `TunnelData` / `TunnelClose` comes back and we have to
//!   re-write the id before pushing it onto `downstream_outbound`.
//!
//! ## Stream-id allocation: shared with the initiator
//!
//! On a relay that *both* forwards tunnels *and* runs `yggdrasilctl
//! chain tunnel open` for local operators, two subsystems compete for
//! the upstream chain's stream-id space:
//!
//! * [`TunnelInitiator`] for locally-originated tunnels.
//! * `TunnelForwarder` for proxied (downstream-originated) tunnels.
//!
//! Letting each subsystem keep its own atomic risks collisions on the
//! upstream side; the terminator would reject the second with
//! `DUPLICATE_STREAM_ID` and tear down a healthy stream. We side-step
//! the problem entirely by having the forwarder *clone* the initiator's
//! `Arc<AtomicU32>` (see [`TunnelInitiator::stream_id_allocator`]) so
//! both subsystems mint ids from a single monotone counter. This costs
//! one extra `Arc` and zero contention beyond `fetch_add(Relaxed)`.
//!
//! ## Reliability posture
//!
//! Forwarder → upstream sends are *reliable* (we await the upstream's
//! ack via the chain client's [`ControlChannel`]) so the downstream's
//! ack accurately reflects whether the next hop accepted the envelope.
//! Upstream → downstream forwarding is *fire-and-forget* over the
//! heartbeat server's `outbound` channel — same posture as the
//! [`TunnelManager`] terminator path. Loss of an upstream → downstream
//! data envelope surfaces as a short read on the originator's UDS,
//! which is consistent with TCP-over-lossy-WAN behaviour.
//!
//! ## What this module is NOT
//!
//! * Not a re-implementation of the terminator. The terminator stays in
//!   [`crate::chain::tunnel_terminator`] and handles `target_pubkey ==
//!   self`; the forwarder handles `target_pubkey != self`. The
//!   [`ChainAcceptor`] is the only place that knows which is which.
//! * Not multi-source. Like the rest of the v1 chain control plane,
//!   the forwarder assumes the relay has *one* upstream and *one*
//!   downstream session (CP24); a relay with no upstream cannot
//!   forward and the forwarder is simply not constructed.
//! * Not a TCP proxy. The forwarder never touches sockets; it only
//!   re-writes stream ids and shuffles already-encrypted control
//!   envelopes between two chain peers.
//!
//! [`TunnelInitiator`]: crate::chain::tunnel_initiator::TunnelInitiator
//! [`TunnelInitiator::stream_id_allocator`]: crate::chain::tunnel_initiator::TunnelInitiator::stream_id_allocator
//! [`TunnelManager`]: crate::chain::tunnel_terminator::TunnelManager
//! [`ChainAcceptor`]: crate::chain::acceptor::ChainAcceptor
//! [`ControlChannel`]: crate::chain::reliability::ControlChannel

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use ratatoskr::control_frame::{AckStatus, ControlBodyType, ControlEnvelope};
use ratatoskr::pubkey::PubKey;
use ratatoskr::tunnel::{
    tunnel_reject, TunnelClose, TunnelData, TunnelOpen, TUNNEL_DATA_MAX_PAYLOAD,
    TUNNEL_OPEN_MAX_WIRE_BYTES,
};
use tokio::sync::{mpsc, Mutex};

use crate::chain::client::ChainClientHandle;
use crate::chain::reliability::SendError;

/// Per-stream registry entry. Lives in `by_downstream`; the reverse
/// map (`by_upstream`) just stores the downstream id so we can find
/// this entry on inbound upstream envelopes.
#[derive(Debug, Clone, Copy)]
struct ForwardedStream {
    /// Stream id we emitted on the outbound `TunnelOpen` to the
    /// upstream peer. Minted via the shared allocator, independent of
    /// the downstream-chosen id.
    upstream_stream_id: u32,
    /// Stored for diagnostics + future Phase 5+ loop-detection
    /// elaborations. Not consulted on the data path.
    #[allow(dead_code)]
    target_pubkey: PubKey,
}

/// Mid-chain tunnel relay. Constructed only on relays that have both a
/// downstream chain listener and a chain upstream — pure leaves
/// (terminal mode) and root relays (no upstream) never instantiate one.
pub struct TunnelForwarder {
    /// Upstream chain client handle. We `send_control` on this to
    /// reliably push forwarded envelopes one hop further.
    upstream: ChainClientHandle,
    /// Outbound channel back to the *downstream* peer's chain session.
    /// Same handle the heartbeat server hands to the terminator; sends
    /// are fire-and-forget (matches the terminator's posture).
    downstream_outbound: mpsc::UnboundedSender<ControlEnvelope>,
    /// This relay's own pubkey. Used only for the defensive
    /// self-target check in `handle_open_from_downstream`: a
    /// downstream that crafts `target_pubkey == ours` should have been
    /// caught one router up (`ChainAcceptor` routes by target_pubkey
    /// and would have gone to the terminator), but we double-check so
    /// a routing bug surfaces as `LOOP_DETECTED` rather than a stuck
    /// stream.
    local_pubkey: PubKey,
    /// Shared with the [`TunnelInitiator`] on the same node so the two
    /// subsystems never emit colliding `stream_id`s on the upstream
    /// chain. See module docs.
    ///
    /// [`TunnelInitiator`]: crate::chain::tunnel_initiator::TunnelInitiator
    upstream_id_alloc: Arc<AtomicU32>,
    /// Downstream id → forwarded-stream entry. Source of truth for
    /// "is this stream open?".
    by_downstream: Mutex<HashMap<u32, ForwardedStream>>,
    /// Upstream id → downstream id. Reverse lookup for inbound traffic
    /// from the upstream.
    by_upstream: Mutex<HashMap<u32, u32>>,
}

impl std::fmt::Debug for TunnelForwarder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelForwarder")
            .field("local_pubkey", &self.local_pubkey)
            .field(
                "next_upstream_id_hint",
                &self.upstream_id_alloc.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl TunnelForwarder {
    /// Construct a forwarder bound to this relay's upstream chain
    /// client and downstream outbound channel. The `upstream_id_alloc`
    /// must be the same `Arc<AtomicU32>` used by the [`TunnelInitiator`]
    /// running alongside us, obtained via
    /// [`TunnelInitiator::stream_id_allocator`]. See module docs.
    ///
    /// [`TunnelInitiator`]: crate::chain::tunnel_initiator::TunnelInitiator
    /// [`TunnelInitiator::stream_id_allocator`]: crate::chain::tunnel_initiator::TunnelInitiator::stream_id_allocator
    pub fn new(
        upstream: ChainClientHandle,
        downstream_outbound: mpsc::UnboundedSender<ControlEnvelope>,
        local_pubkey: PubKey,
        upstream_id_alloc: Arc<AtomicU32>,
    ) -> Arc<Self> {
        Arc::new(Self {
            upstream,
            downstream_outbound,
            local_pubkey,
            upstream_id_alloc,
            by_downstream: Mutex::new(HashMap::new()),
            by_upstream: Mutex::new(HashMap::new()),
        })
    }

    /// Handle a `TunnelOpen` from the *downstream* peer that targets a
    /// node beyond us. Decodes the envelope, mints a fresh upstream
    /// `stream_id`, re-emits the `TunnelOpen` upstream, awaits the ack,
    /// and on `Ok` registers the bidirectional mapping. On any other
    /// outcome the registry is left untouched and the downstream ack
    /// mirrors the upstream rejection reason so the originator gets a
    /// faithful end-to-end status code.
    pub async fn handle_open_from_downstream(&self, body: &[u8]) -> AckStatus {
        if body.len() > TUNNEL_OPEN_MAX_WIRE_BYTES {
            tracing::warn!(
                bytes = body.len(),
                cap = TUNNEL_OPEN_MAX_WIRE_BYTES,
                "forwarder: TunnelOpen exceeds wire cap; rejecting"
            );
            metric_outcome("open_decode_error");
            return AckStatus::Reject(tunnel_reject::TUNNEL_NOT_PERMITTED);
        }
        let open: TunnelOpen = match postcard::from_bytes(body) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(error = %e, "forwarder: TunnelOpen decode failed");
                metric_outcome("open_decode_error");
                return AckStatus::Reject(tunnel_reject::TUNNEL_NOT_PERMITTED);
            }
        };

        // Defence-in-depth: the acceptor already routes by
        // target_pubkey, but a routing bug landing self-targeted opens
        // here would otherwise loop forever back to us. Fail fast.
        if open.target_pubkey == self.local_pubkey {
            tracing::warn!(
                target = %open.target_pubkey,
                "forwarder: TunnelOpen with target == local; rejecting LOOP_DETECTED"
            );
            metric_outcome("open_self_target");
            return AckStatus::Reject(tunnel_reject::LOOP_DETECTED);
        }

        let downstream_stream_id = open.stream_id;

        // Hold the downstream-id mutex *before* allocating the upstream
        // id so a duplicate downstream id is caught without consuming
        // a counter slot.
        {
            let by_ds = self.by_downstream.lock().await;
            if by_ds.contains_key(&downstream_stream_id) {
                tracing::warn!(
                    stream_id = downstream_stream_id,
                    "forwarder: duplicate downstream stream id"
                );
                metric_outcome("open_duplicate_downstream");
                return AckStatus::Reject(tunnel_reject::DUPLICATE_STREAM_ID);
            }
        }

        let upstream_stream_id = alloc_upstream_id(&self.upstream_id_alloc);

        // Re-serialise with the upstream-chosen stream id. `dest` and
        // `target_pubkey` pass through unmodified — the upstream peer
        // is the one that decides whether to terminate (target ==
        // them) or forward again (target != them).
        let upstream_open = TunnelOpen {
            stream_id: upstream_stream_id,
            target_pubkey: open.target_pubkey,
            dest: open.dest,
        };
        let upstream_body = match postcard::to_allocvec(&upstream_open) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "forwarder: TunnelOpen re-encode failed");
                metric_outcome("open_reencode_error");
                return AckStatus::Reject(tunnel_reject::TUNNEL_NOT_PERMITTED);
            }
        };

        let rx = match self.upstream.send_control(
            ControlBodyType::TunnelOpen.as_byte(),
            upstream_body,
        ) {
            Ok(rx) => rx,
            Err(_) => {
                tracing::warn!("forwarder: upstream chain client is shut down");
                metric_outcome("open_upstream_down");
                return AckStatus::Reject(tunnel_reject::TARGET_UNREACHABLE);
            }
        };

        match rx.await {
            Ok(Ok(())) => {
                // Upstream accepted the open; register the mapping.
                let entry = ForwardedStream {
                    upstream_stream_id,
                    target_pubkey: open.target_pubkey,
                };
                let mut by_ds = self.by_downstream.lock().await;
                let mut by_us = self.by_upstream.lock().await;
                // Re-check the downstream map under lock; an in-flight
                // duplicate open would surface here. Bail without
                // touching the upstream — the upstream stream stays
                // open until the originator times out, which matches
                // the existing terminator's failure mode.
                if by_ds.contains_key(&downstream_stream_id) {
                    tracing::warn!(
                        stream_id = downstream_stream_id,
                        "forwarder: race on duplicate downstream id after upstream ack"
                    );
                    metric_outcome("open_duplicate_downstream_race");
                    return AckStatus::Reject(tunnel_reject::DUPLICATE_STREAM_ID);
                }
                by_ds.insert(downstream_stream_id, entry);
                by_us.insert(upstream_stream_id, downstream_stream_id);
                tracing::info!(
                    downstream_stream_id,
                    upstream_stream_id,
                    target = %open.target_pubkey,
                    "forwarder: TunnelOpen relayed and registered"
                );
                metric_outcome("open_ok");
                AckStatus::Ok
            }
            Ok(Err(SendError::Rejected(reason))) => {
                tracing::debug!(
                    downstream_stream_id,
                    upstream_stream_id,
                    reason,
                    "forwarder: upstream rejected TunnelOpen"
                );
                metric_outcome("open_upstream_rejected");
                AckStatus::Reject(reason)
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    downstream_stream_id,
                    upstream_stream_id,
                    error = %e,
                    "forwarder: upstream TunnelOpen failed"
                );
                metric_outcome("open_upstream_send_failed");
                AckStatus::Reject(tunnel_reject::TARGET_UNREACHABLE)
            }
            Err(_) => {
                tracing::warn!(
                    downstream_stream_id,
                    upstream_stream_id,
                    "forwarder: upstream ack channel closed mid-open"
                );
                metric_outcome("open_ack_channel_closed");
                AckStatus::Reject(tunnel_reject::TARGET_UNREACHABLE)
            }
        }
    }

    /// Handle a `TunnelData` from the *downstream* peer. Looks up the
    /// downstream stream id, re-writes the envelope with the matching
    /// upstream id, and forwards reliably. The downstream ack mirrors
    /// the upstream ack outcome.
    pub async fn handle_data_from_downstream(&self, body: &[u8]) -> AckStatus {
        let data: TunnelData = match postcard::from_bytes(body) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %e, "forwarder: TunnelData decode failed");
                metric_outcome("data_decode_error");
                return AckStatus::Reject(tunnel_reject::PAYLOAD_TOO_LARGE);
            }
        };
        if data.payload.len() > TUNNEL_DATA_MAX_PAYLOAD {
            tracing::warn!(
                stream_id = data.stream_id,
                bytes = data.payload.len(),
                cap = TUNNEL_DATA_MAX_PAYLOAD,
                "forwarder: TunnelData over cap"
            );
            metric_outcome("data_payload_too_large");
            return AckStatus::Reject(tunnel_reject::PAYLOAD_TOO_LARGE);
        }

        let upstream_id = {
            let by_ds = self.by_downstream.lock().await;
            match by_ds.get(&data.stream_id) {
                Some(entry) => entry.upstream_stream_id,
                None => {
                    metric_outcome("data_downstream_unknown");
                    return AckStatus::Reject(tunnel_reject::STREAM_NOT_FOUND);
                }
            }
        };

        let upstream_data = TunnelData {
            stream_id: upstream_id,
            payload: data.payload,
        };
        let upstream_body = match postcard::to_allocvec(&upstream_data) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "forwarder: TunnelData re-encode failed");
                metric_outcome("data_reencode_error");
                return AckStatus::Reject(tunnel_reject::PAYLOAD_TOO_LARGE);
            }
        };
        let rx = match self.upstream.send_control(
            ControlBodyType::TunnelData.as_byte(),
            upstream_body,
        ) {
            Ok(rx) => rx,
            Err(_) => {
                metric_outcome("data_upstream_down");
                return AckStatus::Reject(tunnel_reject::TARGET_UNREACHABLE);
            }
        };
        match rx.await {
            Ok(Ok(())) => {
                metric_outcome("data_ok");
                AckStatus::Ok
            }
            Ok(Err(SendError::Rejected(reason))) => {
                metric_outcome("data_upstream_rejected");
                AckStatus::Reject(reason)
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    downstream_stream_id = data.stream_id,
                    upstream_stream_id = upstream_id,
                    error = %e,
                    "forwarder: upstream TunnelData failed"
                );
                metric_outcome("data_upstream_send_failed");
                AckStatus::Reject(tunnel_reject::TARGET_UNREACHABLE)
            }
            Err(_) => {
                metric_outcome("data_ack_channel_closed");
                AckStatus::Reject(tunnel_reject::TARGET_UNREACHABLE)
            }
        }
    }

    /// Handle a `TunnelClose` from the *downstream* peer. Forwards
    /// the close upstream best-effort but **keeps both registry
    /// entries alive** so the upstream terminator can still flush
    /// response bytes back through this forwarder before its own
    /// `TunnelClose` arrives.
    ///
    /// This mirrors the TCP-style half-close semantics that
    /// [`TunnelInitiator::signal_close`] relies on: a close from
    /// downstream is "I am done writing" — the upstream may still
    /// have bytes to send back. Entries are removed when the upstream
    /// side's reciprocal `TunnelClose` lands in
    /// [`TunnelForwarder::dispatch_close_from_upstream`].
    ///
    /// The downstream ack is always `Ok` (a close from the downstream
    /// is authoritative — there is nothing to reject).
    ///
    /// [`TunnelInitiator::signal_close`]: crate::chain::tunnel_initiator::TunnelInitiator::signal_close
    pub async fn handle_close_from_downstream(&self, body: &[u8]) -> AckStatus {
        let close: TunnelClose = match postcard::from_bytes(body) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "forwarder: TunnelClose decode failed");
                metric_outcome("close_decode_error");
                // Ack Ok — a close that we can't decode still carries
                // the operator's intent to terminate; we have nothing
                // to do because we couldn't identify the stream.
                return AckStatus::Ok;
            }
        };

        // Look up — DO NOT remove. The upstream terminator may still
        // be flushing response bytes; entries are removed only when
        // the upstream side closes back. See type-level docs.
        let upstream_id_opt = {
            let by_ds = self.by_downstream.lock().await;
            by_ds.get(&close.stream_id).map(|e| e.upstream_stream_id)
        };

        let upstream_id = match upstream_id_opt {
            Some(id) => id,
            None => {
                // Already gone — upstream-initiated close raced ahead
                // of us and removed both entries, or this stream id
                // never existed. Ack Ok so the originator stops
                // retrying.
                metric_outcome("close_downstream_already_gone");
                return AckStatus::Ok;
            }
        };

        // Best-effort upstream propagation; we do not block the
        // downstream ack on the upstream ack landing because the
        // operator is done writing regardless.
        let upstream_close = TunnelClose {
            stream_id: upstream_id,
            reason: close.reason,
        };
        if let Ok(buf) = postcard::to_allocvec(&upstream_close) {
            match self
                .upstream
                .send_control(ControlBodyType::TunnelClose.as_byte(), buf)
            {
                Ok(rx) => {
                    tokio::spawn(async move {
                        match rx.await {
                            Ok(Ok(())) => metric_outcome("close_upstream_ok"),
                            Ok(Err(SendError::Rejected(_))) => {
                                metric_outcome("close_upstream_rejected")
                            }
                            Ok(Err(_)) => metric_outcome("close_upstream_send_failed"),
                            Err(_) => metric_outcome("close_upstream_ack_channel_closed"),
                        }
                    });
                }
                Err(_) => {
                    metric_outcome("close_upstream_down");
                }
            }
        } else {
            metric_outcome("close_reencode_error");
        }

        metric_outcome("close_ok");
        AckStatus::Ok
    }

    /// Synchronous inbound dispatch from the upstream chain client's
    /// body_handler. Called for stream ids that the [`TunnelInitiator`]
    /// did not recognise (the combined body handler in
    /// [`combined_tunnel_body_handler`] tries the initiator first and
    /// falls through to us on `STREAM_NOT_FOUND`).
    ///
    /// Re-writes the upstream stream id back to the downstream id and
    /// pushes the envelope onto the downstream outbound channel. The
    /// upstream side acks `Ok` even if the downstream side has gone
    /// away — we have nothing useful to tell the upstream and the
    /// originator's own UDS dropping will surface as a closed stream
    /// in the other direction.
    ///
    /// Like [`TunnelInitiator::dispatch_inbound`], this function must
    /// not `.await`: it runs in the chain client's per-envelope hot
    /// path. We `try_lock` on the registry and treat contention as
    /// `STREAM_NOT_FOUND` so the reliability layer redelivers when the
    /// hot lock is free again.
    ///
    /// [`TunnelInitiator`]: crate::chain::tunnel_initiator::TunnelInitiator
    /// [`TunnelInitiator::dispatch_inbound`]: crate::chain::tunnel_initiator::TunnelInitiator
    pub fn dispatch_inbound_from_upstream(
        self: &Arc<Self>,
        body_type: u8,
        body: &[u8],
    ) -> AckStatus {
        let kind = match ControlBodyType::from_byte(body_type) {
            Some(k) => k,
            None => return AckStatus::Unknown,
        };
        match kind {
            ControlBodyType::TunnelData => self.dispatch_data_from_upstream(body),
            ControlBodyType::TunnelClose => self.dispatch_close_from_upstream(body),
            // `TunnelOpen` from upstream is not part of the v1 wire
            // protocol (opens only flow away from the originator).
            // Surface as `Unknown` so the upstream sees it didn't land.
            _ => AckStatus::Unknown,
        }
    }

    fn dispatch_data_from_upstream(&self, body: &[u8]) -> AckStatus {
        let data: TunnelData = match postcard::from_bytes(body) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %e, "forwarder: inbound TunnelData decode failed");
                metric_outcome("inbound_data_decode_error");
                return AckStatus::Reject(tunnel_reject::PAYLOAD_TOO_LARGE);
            }
        };
        if data.payload.len() > TUNNEL_DATA_MAX_PAYLOAD {
            metric_outcome("inbound_data_payload_too_large");
            return AckStatus::Reject(tunnel_reject::PAYLOAD_TOO_LARGE);
        }
        let by_us = match self.by_upstream.try_lock() {
            Ok(g) => g,
            Err(_) => {
                metric_outcome("inbound_data_lock_contention");
                // Same posture as the initiator: ask peer to retx
                // rather than tearing down on transient contention.
                return AckStatus::Reject(tunnel_reject::PAYLOAD_TOO_LARGE);
            }
        };
        let downstream_id = match by_us.get(&data.stream_id) {
            Some(ds) => *ds,
            None => {
                // Unknown to us — let the combined dispatcher's caller
                // see `STREAM_NOT_FOUND` so monitoring matches the
                // initiator-only deployment.
                metric_outcome("inbound_data_unknown_upstream");
                return AckStatus::Reject(tunnel_reject::STREAM_NOT_FOUND);
            }
        };
        drop(by_us);

        let downstream_data = TunnelData {
            stream_id: downstream_id,
            payload: data.payload,
        };
        let buf = match postcard::to_allocvec(&downstream_data) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "forwarder: downstream TunnelData re-encode failed");
                metric_outcome("inbound_data_reencode_error");
                return AckStatus::Reject(tunnel_reject::PAYLOAD_TOO_LARGE);
            }
        };
        let envelope = ControlEnvelope {
            // The heartbeat server's outbound drainer assigns the
            // real per-session seq; we ship a placeholder.
            seq: 0,
            body_type: ControlBodyType::TunnelData.as_byte(),
            body: buf,
        };
        if self.downstream_outbound.send(envelope).is_err() {
            metric_outcome("inbound_data_downstream_gone");
            // The downstream session is gone; the originator will see
            // a closed stream eventually. We ack `Ok` to the upstream
            // because retrying would not help.
            return AckStatus::Ok;
        }
        metric_outcome("inbound_data_ok");
        AckStatus::Ok
    }

    fn dispatch_close_from_upstream(&self, body: &[u8]) -> AckStatus {
        let close: TunnelClose = match postcard::from_bytes(body) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "forwarder: inbound TunnelClose decode failed");
                metric_outcome("inbound_close_decode_error");
                // We can't identify the stream — ack Ok so upstream
                // stops retransmitting.
                return AckStatus::Ok;
            }
        };
        let (mut by_us, mut by_ds) = match (
            self.by_upstream.try_lock(),
            self.by_downstream.try_lock(),
        ) {
            (Ok(u), Ok(d)) => (u, d),
            _ => {
                metric_outcome("inbound_close_lock_contention");
                return AckStatus::Reject(tunnel_reject::PAYLOAD_TOO_LARGE);
            }
        };
        let downstream_id = match by_us.remove(&close.stream_id) {
            Some(ds) => ds,
            None => {
                // Already gone — peer-initiated close raced with our
                // own close; ack Ok and move on.
                metric_outcome("inbound_close_unknown_upstream");
                return AckStatus::Ok;
            }
        };
        by_ds.remove(&downstream_id);
        drop(by_us);
        drop(by_ds);

        let downstream_close = TunnelClose {
            stream_id: downstream_id,
            reason: close.reason,
        };
        let buf = match postcard::to_allocvec(&downstream_close) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "forwarder: downstream TunnelClose re-encode failed");
                metric_outcome("inbound_close_reencode_error");
                return AckStatus::Ok;
            }
        };
        let envelope = ControlEnvelope {
            seq: 0,
            body_type: ControlBodyType::TunnelClose.as_byte(),
            body: buf,
        };
        let _ = self.downstream_outbound.send(envelope);
        metric_outcome("inbound_close_ok");
        AckStatus::Ok
    }

    /// Snapshot of currently-open downstream stream ids. Test +
    /// diagnostic only.
    #[doc(hidden)]
    pub async fn open_stream_ids(&self) -> Vec<u32> {
        let by_ds = self.by_downstream.lock().await;
        by_ds.keys().copied().collect()
    }
}

/// Hand out the next upstream-side `stream_id`, skipping `0`. Logic
/// mirrors [`TunnelInitiator::alloc_stream_id`] so the two subsystems
/// stay in lock-step; the same `Arc<AtomicU32>` backs both.
///
/// [`TunnelInitiator::alloc_stream_id`]: crate::chain::tunnel_initiator::TunnelInitiator
fn alloc_upstream_id(alloc: &AtomicU32) -> u32 {
    let mut id = alloc.fetch_add(1, Ordering::Relaxed);
    if id == 0 {
        id = alloc.fetch_add(1, Ordering::Relaxed);
    }
    id
}

fn metric_outcome(outcome: &'static str) {
    metrics::counter!(
        "yggdrasil_chain_tunnel_forwarder_total",
        "outcome" => outcome,
    )
    .increment(1);
}

/// Build a [`BodyHandler`] closure that chains an inbound envelope
/// through the [`TunnelInitiator`] first and, on
/// `Reject(STREAM_NOT_FOUND)`, falls through to an optional
/// [`TunnelForwarder`]. Outcome propagation rules:
///
/// * `AckStatus::Ok` from initiator → return `Ok` (locally-originated
///   stream handled).
/// * `AckStatus::Unknown` from initiator → return `Unknown` (body type
///   not a tunnel envelope; do not consult forwarder).
/// * `AckStatus::Reject(STREAM_NOT_FOUND)` from initiator + forwarder
///   set → delegate to forwarder, propagate its outcome.
/// * Any other `AckStatus::Reject(...)` → propagate verbatim; the
///   forwarder cannot rescue a payload-too-large or similar terminal
///   error.
///
/// When `forwarder` is `None` the closure behaves exactly like
/// [`TunnelInitiator::body_handler`]: useful for terminal nodes
/// (no downstream chain session, nothing to forward).
///
/// [`BodyHandler`]: crate::chain::client::BodyHandler
/// [`TunnelInitiator`]: crate::chain::tunnel_initiator::TunnelInitiator
/// [`TunnelInitiator::body_handler`]: crate::chain::tunnel_initiator::TunnelInitiator
pub fn combined_tunnel_body_handler(
    initiator: Arc<crate::chain::tunnel_initiator::TunnelInitiator>,
    forwarder: Option<Arc<TunnelForwarder>>,
) -> crate::chain::client::BodyHandler {
    Arc::new(move |body_type: u8, body: &[u8]| -> AckStatus {
        let first = initiator.dispatch_inbound(body_type, body);
        match (&first, &forwarder) {
            (AckStatus::Reject(reason), Some(fwd))
                if *reason == tunnel_reject::STREAM_NOT_FOUND =>
            {
                fwd.dispatch_inbound_from_upstream(body_type, body)
            }
            _ => first,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::client::{ChainClientHandle, ControlOp};
    use ratatoskr::tunnel::TUNNEL_DATA_MAX_PAYLOAD;
    use std::net::SocketAddr;
    use tokio::sync::mpsc;

    fn pk(byte: u8) -> PubKey {
        PubKey::x25519([byte; 32])
    }

    /// Build a fake chain client handle backed by an mpsc the test can
    /// drain. The fn is given the body and decides what `SendError` /
    /// `Ok(())` to emit; the completion oneshot is resolved with that.
    fn fake_chain_client(
        responder: impl Fn(u8, &[u8]) -> Result<(), SendError> + Send + 'static,
    ) -> (ChainClientHandle, tokio::task::JoinHandle<()>) {
        let (tx, mut rx) = mpsc::unbounded_channel::<ControlOp>();
        let handle = ChainClientHandle::__test_new(tx);
        let join = tokio::spawn(async move {
            while let Some(op) = rx.recv().await {
                let res = responder(op.body_type, &op.body);
                let _ = op.completion.send(res);
            }
        });
        (handle, join)
    }

    fn dest() -> SocketAddr {
        "127.0.0.1:9".parse().unwrap()
    }

    #[tokio::test]
    async fn open_relays_with_fresh_upstream_id() {
        let (upstream, _join) = fake_chain_client(|body_type, body| {
            assert_eq!(body_type, ControlBodyType::TunnelOpen.as_byte());
            let open: TunnelOpen = postcard::from_bytes(body).unwrap();
            // The forwarder must rewrite the stream id to a fresh
            // upstream-side id (not the downstream's 42).
            assert_ne!(open.stream_id, 42);
            Ok(())
        });
        let (ds_tx, mut _ds_rx) = mpsc::unbounded_channel();
        let alloc = Arc::new(AtomicU32::new(7));
        let fwd =
            TunnelForwarder::new(upstream, ds_tx, pk(0x11), Arc::clone(&alloc));

        let open = TunnelOpen {
            stream_id: 42,
            target_pubkey: pk(0x22), // not us
            dest: dest(),
        };
        let body = postcard::to_allocvec(&open).unwrap();
        let ack = fwd.handle_open_from_downstream(&body).await;
        assert_eq!(ack, AckStatus::Ok);
        // Allocator should have advanced.
        assert!(alloc.load(Ordering::Relaxed) > 7);
        assert_eq!(fwd.open_stream_ids().await, vec![42]);
    }

    #[tokio::test]
    async fn open_self_target_rejects_loop_detected() {
        let (upstream, _join) = fake_chain_client(|_, _| Ok(()));
        let (ds_tx, _ds_rx) = mpsc::unbounded_channel();
        let fwd = TunnelForwarder::new(
            upstream,
            ds_tx,
            pk(0xAA),
            Arc::new(AtomicU32::new(1)),
        );
        let open = TunnelOpen {
            stream_id: 1,
            target_pubkey: pk(0xAA), // same as local — should never happen
            dest: dest(),
        };
        let body = postcard::to_allocvec(&open).unwrap();
        let ack = fwd.handle_open_from_downstream(&body).await;
        assert_eq!(ack, AckStatus::Reject(tunnel_reject::LOOP_DETECTED));
    }

    #[tokio::test]
    async fn open_propagates_upstream_reject() {
        let (upstream, _join) = fake_chain_client(|_, _| {
            Err(SendError::Rejected(tunnel_reject::TARGET_NOT_ALLOWED))
        });
        let (ds_tx, _ds_rx) = mpsc::unbounded_channel();
        let fwd = TunnelForwarder::new(
            upstream,
            ds_tx,
            pk(0x11),
            Arc::new(AtomicU32::new(1)),
        );
        let open = TunnelOpen {
            stream_id: 1,
            target_pubkey: pk(0x22),
            dest: dest(),
        };
        let body = postcard::to_allocvec(&open).unwrap();
        let ack = fwd.handle_open_from_downstream(&body).await;
        assert_eq!(ack, AckStatus::Reject(tunnel_reject::TARGET_NOT_ALLOWED));
        // No mapping should have been recorded.
        assert!(fwd.open_stream_ids().await.is_empty());
    }

    #[tokio::test]
    async fn data_round_trip_rewrites_stream_id_both_ways() {
        // Capture what the upstream sees so we know the rewritten id.
        let captured_upstream_id = Arc::new(std::sync::Mutex::new(0u32));
        let cap = Arc::clone(&captured_upstream_id);
        let (upstream, _join) = fake_chain_client(move |body_type, body| {
            if body_type == ControlBodyType::TunnelOpen.as_byte() {
                let open: TunnelOpen = postcard::from_bytes(body).unwrap();
                *cap.lock().unwrap() = open.stream_id;
            }
            Ok(())
        });
        let (ds_tx, mut ds_rx) = mpsc::unbounded_channel();
        let fwd = TunnelForwarder::new(
            upstream,
            ds_tx,
            pk(0x11),
            Arc::new(AtomicU32::new(100)),
        );

        // Downstream opens stream_id=5 -> upstream id allocated.
        let open = TunnelOpen {
            stream_id: 5,
            target_pubkey: pk(0x22),
            dest: dest(),
        };
        let body = postcard::to_allocvec(&open).unwrap();
        assert_eq!(
            fwd.handle_open_from_downstream(&body).await,
            AckStatus::Ok
        );
        let upstream_id = *captured_upstream_id.lock().unwrap();
        assert_ne!(upstream_id, 5, "upstream id must be freshly minted");

        // Downstream → upstream data: forwarder must rewrite 5 → upstream_id.
        let ds_data = TunnelData {
            stream_id: 5,
            payload: vec![1, 2, 3],
        };
        let ds_body = postcard::to_allocvec(&ds_data).unwrap();
        assert_eq!(
            fwd.handle_data_from_downstream(&ds_body).await,
            AckStatus::Ok
        );

        // Upstream → downstream data: forwarder must rewrite
        // upstream_id → 5 and push onto ds_outbound.
        let us_data = TunnelData {
            stream_id: upstream_id,
            payload: vec![9, 8, 7],
        };
        let us_body = postcard::to_allocvec(&us_data).unwrap();
        let fwd_arc = Arc::clone(&fwd);
        let ack = fwd_arc
            .dispatch_inbound_from_upstream(ControlBodyType::TunnelData.as_byte(), &us_body);
        assert_eq!(ack, AckStatus::Ok);
        let envelope = ds_rx.recv().await.expect("downstream envelope");
        assert_eq!(envelope.body_type, ControlBodyType::TunnelData.as_byte());
        let echoed: TunnelData = postcard::from_bytes(&envelope.body).unwrap();
        assert_eq!(echoed.stream_id, 5);
        assert_eq!(echoed.payload, vec![9, 8, 7]);
    }

    #[tokio::test]
    async fn close_from_downstream_preserves_entries_until_upstream_reciprocal() {
        // Capture the upstream id so we can simulate the upstream's
        // reciprocal `TunnelClose`.
        let captured_upstream_id = Arc::new(std::sync::Mutex::new(0u32));
        let cap = Arc::clone(&captured_upstream_id);
        let (upstream, _join) = fake_chain_client(move |body_type, body| {
            if body_type == ControlBodyType::TunnelOpen.as_byte() {
                let open: TunnelOpen = postcard::from_bytes(body).unwrap();
                *cap.lock().unwrap() = open.stream_id;
            }
            Ok(())
        });
        let (ds_tx, _ds_rx) = mpsc::unbounded_channel();
        let fwd = TunnelForwarder::new(
            upstream,
            ds_tx,
            pk(0x11),
            Arc::new(AtomicU32::new(1)),
        );
        let open = TunnelOpen {
            stream_id: 9,
            target_pubkey: pk(0x22),
            dest: dest(),
        };
        let open_body = postcard::to_allocvec(&open).unwrap();
        assert_eq!(
            fwd.handle_open_from_downstream(&open_body).await,
            AckStatus::Ok
        );
        assert_eq!(fwd.open_stream_ids().await, vec![9]);
        let upstream_id = *captured_upstream_id.lock().unwrap();
        assert_ne!(upstream_id, 9);

        // TCP-style half-close: downstream sending `TunnelClose` does
        // not remove the registry entries. The upstream terminator
        // may still be flushing response bytes back; entries persist
        // until the upstream-side `TunnelClose` arrives.
        let close = TunnelClose { stream_id: 9, reason: 0 };
        let close_body = postcard::to_allocvec(&close).unwrap();
        assert_eq!(
            fwd.handle_close_from_downstream(&close_body).await,
            AckStatus::Ok
        );
        // Let the spawned best-effort upstream close ack drain.
        tokio::task::yield_now().await;
        assert_eq!(
            fwd.open_stream_ids().await,
            vec![9],
            "downstream close must not remove entries"
        );

        // Upstream's reciprocal `TunnelClose` (re-using the upstream
        // id) removes both sides.
        let upstream_close = TunnelClose {
            stream_id: upstream_id,
            reason: 0,
        };
        let upstream_close_body = postcard::to_allocvec(&upstream_close).unwrap();
        assert_eq!(
            fwd.dispatch_inbound_from_upstream(
                ControlBodyType::TunnelClose.as_byte(),
                &upstream_close_body,
            ),
            AckStatus::Ok
        );
        assert!(fwd.open_stream_ids().await.is_empty());

        // A subsequent downstream data on the now-removed id should
        // be STREAM_NOT_FOUND.
        let ds_data = TunnelData {
            stream_id: 9,
            payload: vec![1],
        };
        let ds_body = postcard::to_allocvec(&ds_data).unwrap();
        assert_eq!(
            fwd.handle_data_from_downstream(&ds_body).await,
            AckStatus::Reject(tunnel_reject::STREAM_NOT_FOUND)
        );
    }

    #[tokio::test]
    async fn data_payload_too_large_rejects() {
        let (upstream, _join) = fake_chain_client(|_, _| Ok(()));
        let (ds_tx, _ds_rx) = mpsc::unbounded_channel();
        let fwd = TunnelForwarder::new(
            upstream,
            ds_tx,
            pk(0x11),
            Arc::new(AtomicU32::new(1)),
        );
        let data = TunnelData {
            stream_id: 1,
            payload: vec![0u8; TUNNEL_DATA_MAX_PAYLOAD + 1],
        };
        let body = postcard::to_allocvec(&data).unwrap();
        let ack = fwd.handle_data_from_downstream(&body).await;
        assert_eq!(ack, AckStatus::Reject(tunnel_reject::PAYLOAD_TOO_LARGE));
    }

    #[tokio::test]
    async fn duplicate_downstream_open_rejected() {
        let (upstream, _join) = fake_chain_client(|_, _| Ok(()));
        let (ds_tx, _ds_rx) = mpsc::unbounded_channel();
        let fwd = TunnelForwarder::new(
            upstream,
            ds_tx,
            pk(0x11),
            Arc::new(AtomicU32::new(1)),
        );
        let open = TunnelOpen {
            stream_id: 7,
            target_pubkey: pk(0x22),
            dest: dest(),
        };
        let body = postcard::to_allocvec(&open).unwrap();
        assert_eq!(
            fwd.handle_open_from_downstream(&body).await,
            AckStatus::Ok
        );
        assert_eq!(
            fwd.handle_open_from_downstream(&body).await,
            AckStatus::Reject(tunnel_reject::DUPLICATE_STREAM_ID)
        );
    }

    #[tokio::test]
    async fn unknown_upstream_id_returns_stream_not_found() {
        let (upstream, _join) = fake_chain_client(|_, _| Ok(()));
        let (ds_tx, _ds_rx) = mpsc::unbounded_channel();
        let fwd = TunnelForwarder::new(
            upstream,
            ds_tx,
            pk(0x11),
            Arc::new(AtomicU32::new(1)),
        );
        let us_data = TunnelData {
            stream_id: 123,
            payload: vec![0u8; 4],
        };
        let body = postcard::to_allocvec(&us_data).unwrap();
        let fwd_arc = Arc::clone(&fwd);
        let ack = fwd_arc
            .dispatch_inbound_from_upstream(ControlBodyType::TunnelData.as_byte(), &body);
        assert_eq!(ack, AckStatus::Reject(tunnel_reject::STREAM_NOT_FOUND));
    }
}
