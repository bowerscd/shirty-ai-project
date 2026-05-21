//! Per-session reliability layer for the chain control channel.
//!
//! Sits between [`ratatoskr::auth::Session`] (Noise transport) and the
//! caller-supplied dispatcher (body-type handler). The channel owns:
//!
//! * A monotonically increasing send sequence (`u32`).
//! * An outbound queue keyed by `seq`, with an exponential-backoff retransmit
//!   schedule and a configurable max-attempts cap.
//! * An inbound dedup window of the last `DEDUP_WINDOW` accepted seqs.
//! * A [`tokio::sync::oneshot::Sender`] per outstanding outbound send, fired
//!   when the matching ack arrives (or with an error on timeout / shutdown).
//!
//! Lifetime: bound to a single Noise session. Rekey / reconnect reset
//! everything (callers that need cross-session delivery resubmit at the
//! upper layer in a later phase).
//!
//! The module is intentionally I/O-free: it consumes [`Instant`] from the
//! caller and produces [`ControlEnvelope`] / decisions, so it can be
//! exhaustively unit-tested without any UDP socket or tokio runtime.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use ratatoskr::control_frame::{AckStatus, ControlAck, ControlEnvelope};
use tokio::sync::oneshot;

/// Initial retransmit interval (also = ack-deadline for the first attempt).
pub const RETX_INITIAL: Duration = Duration::from_millis(200);
/// Upper bound on the per-attempt interval after exponential growth.
pub const RETX_MAX: Duration = Duration::from_secs(2);
/// Maximum total sends per envelope (the initial send plus retransmits).
pub const RETX_MAX_ATTEMPTS: u32 = 5;
/// Number of recently-accepted inbound seqs to remember for dedup.
pub const DEDUP_WINDOW: usize = 256;

/// Outcome reported to the caller via the per-send oneshot.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SendError {
    /// Exhausted all retransmits without receiving an ack.
    #[error("control envelope timed out after {0} attempts")]
    Timeout(u32),
    /// Peer recognised the body type but refused the envelope.
    #[error("control envelope rejected by peer: code 0x{0:04x}")]
    Rejected(u16),
    /// Peer did not recognise the body type.
    #[error("control envelope reported as unknown body type by peer")]
    UnknownBodyType,
    /// Channel was aborted (session ended, daemon shutting down, etc.)
    /// before the ack arrived.
    #[error("control channel shut down before ack")]
    ChannelClosed,
}

/// Per-session reliability state for the chain control channel.
#[derive(Debug)]
pub struct ControlChannel {
    next_seq: u32,
    outbound: BTreeMap<u32, OutboundEntry>,
    dedup: DedupWindow,
}

#[derive(Debug)]
struct OutboundEntry {
    envelope: ControlEnvelope,
    /// Number of times this envelope has been emitted (including the initial
    /// send). Caps at [`RETX_MAX_ATTEMPTS`].
    attempts: u32,
    /// When the next emission becomes due. `<= Instant::now()` means ready.
    next_send_at: Instant,
    /// Caller-supplied notification channel for the eventual ack outcome.
    /// Wrapped in `Option` so [`oneshot::Sender::send`] (which consumes self)
    /// can be called by-value when we finally resolve the entry.
    completion: Option<oneshot::Sender<Result<(), SendError>>>,
}

/// Decision returned by [`ControlChannel::on_inbound`].
#[derive(Debug, PartialEq, Eq)]
pub enum InboundDisposition {
    /// First time we've seen this seq. Caller should run the body-type
    /// dispatcher and ack with the resulting status.
    Deliver(ControlEnvelope),
    /// Seq is in the dedup window. Caller should re-ack `Ok` (the peer's
    /// prior ack was presumably lost in transit).
    Duplicate,
}

#[derive(Debug)]
struct DedupWindow {
    seen: VecDeque<u32>,
    cap: usize,
}

impl DedupWindow {
    fn new(cap: usize) -> Self {
        Self {
            seen: VecDeque::with_capacity(cap),
            cap,
        }
    }
    fn contains(&self, seq: u32) -> bool {
        self.seen.iter().any(|&s| s == seq)
    }
    fn insert(&mut self, seq: u32) {
        if self.contains(seq) {
            return;
        }
        if self.seen.len() == self.cap {
            self.seen.pop_front();
        }
        self.seen.push_back(seq);
    }
}

impl Default for ControlChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlChannel {
    pub fn new() -> Self {
        Self {
            // Start at 1 so `0` can be reserved as a sentinel by upper
            // layers if they ever need one.
            next_seq: 1,
            outbound: BTreeMap::new(),
            dedup: DedupWindow::new(DEDUP_WINDOW),
        }
    }

    /// Allocate the next seq, push an outbound entry, and return the
    /// envelope the caller must transmit immediately.
    ///
    /// The first emission counts as `attempts == 1`. The first retransmit
    /// (if no ack within [`RETX_INITIAL`]) is scheduled by setting
    /// `next_send_at = now + RETX_INITIAL`.
    ///
    /// Panics on `u32::MAX` overflow — a single session is not expected to
    /// emit four billion control envelopes; if that limit is approached the
    /// upper layer should force a rekey.
    pub fn enqueue(
        &mut self,
        body_type: u8,
        body: Vec<u8>,
        completion: oneshot::Sender<Result<(), SendError>>,
        now: Instant,
    ) -> ControlEnvelope {
        let seq = self.next_seq;
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .expect("control channel seq exhausted; rekey before this");
        let envelope = ControlEnvelope {
            seq,
            body_type,
            body,
        };
        self.outbound.insert(
            seq,
            OutboundEntry {
                envelope: envelope.clone(),
                attempts: 1,
                next_send_at: now + RETX_INITIAL,
                completion: Some(completion),
            },
        );
        envelope
    }

    /// Walk the outbound queue and return every envelope whose deadline has
    /// passed. Each returned envelope has its `attempts` incremented and its
    /// next deadline rescheduled. Entries that have already used their full
    /// [`RETX_MAX_ATTEMPTS`] budget at the time `next_due` is called are
    /// removed and reported to their waiters as [`SendError::Timeout`].
    pub fn next_due(&mut self, now: Instant) -> Vec<ControlEnvelope> {
        let mut out = Vec::new();
        let mut timed_out = Vec::new();
        for (&seq, entry) in &mut self.outbound {
            if entry.next_send_at > now {
                continue;
            }
            if entry.attempts >= RETX_MAX_ATTEMPTS {
                timed_out.push(seq);
                continue;
            }
            entry.attempts += 1;
            entry.next_send_at = now + backoff_for(entry.attempts);
            out.push(entry.envelope.clone());
        }
        for seq in timed_out {
            if let Some(mut entry) = self.outbound.remove(&seq) {
                if let Some(tx) = entry.completion.take() {
                    let _ = tx.send(Err(SendError::Timeout(RETX_MAX_ATTEMPTS)));
                }
            }
        }
        out
    }

    /// Earliest deadline of any pending outbound entry, or `None` if the
    /// queue is empty. Callers use this to compute the next `select!`
    /// timer arm.
    pub fn next_tick_at(&self) -> Option<Instant> {
        self.outbound.values().map(|e| e.next_send_at).min()
    }

    /// Resolve a pending send with the supplied ack. Returns `true` if a
    /// matching outbound entry was found and notified, `false` if the seq
    /// was unknown (e.g. an ack we've already processed, or noise).
    pub fn on_ack(&mut self, ack: &ControlAck) -> bool {
        let Some(mut entry) = self.outbound.remove(&ack.seq) else {
            return false;
        };
        let result = match ack.status {
            AckStatus::Ok => Ok(()),
            AckStatus::Reject(code) => Err(SendError::Rejected(code)),
            AckStatus::Unknown => Err(SendError::UnknownBodyType),
        };
        if let Some(tx) = entry.completion.take() {
            let _ = tx.send(result);
        }
        true
    }

    /// Classify an inbound envelope and update the dedup window.
    pub fn on_inbound(&mut self, env: ControlEnvelope) -> InboundDisposition {
        if self.dedup.contains(env.seq) {
            return InboundDisposition::Duplicate;
        }
        self.dedup.insert(env.seq);
        InboundDisposition::Deliver(env)
    }

    /// Count of envelopes awaiting an ack.
    pub fn pending(&self) -> usize {
        self.outbound.len()
    }

    /// Notify every pending waiter with [`SendError::ChannelClosed`] and
    /// drop the outbound queue. Used on session shutdown / rekey.
    pub fn abort_all(&mut self) {
        for (_, mut entry) in std::mem::take(&mut self.outbound) {
            if let Some(tx) = entry.completion.take() {
                let _ = tx.send(Err(SendError::ChannelClosed));
            }
        }
    }
}

impl Drop for ControlChannel {
    fn drop(&mut self) {
        // Notify any leftover waiters so they unblock with a clear error
        // rather than hanging on a closed sender.
        self.abort_all();
    }
}

fn backoff_for(attempts: u32) -> Duration {
    // attempts == 1 → wait RETX_INITIAL before the *first* retransmit.
    // attempts == 2 → 2× RETX_INITIAL, etc., capped at RETX_MAX.
    let shift = attempts.saturating_sub(1).min(8);
    let computed = RETX_INITIAL.saturating_mul(1u32 << shift);
    computed.min(RETX_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatoskr::control_frame::{AckStatus, ControlAck, ControlEnvelope};

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn enqueue_assigns_monotonic_seqs() {
        let mut ch = ControlChannel::new();
        let (tx1, _r1) = oneshot::channel();
        let (tx2, _r2) = oneshot::channel();
        let e1 = ch.enqueue(0x01, vec![], tx1, t0());
        let e2 = ch.enqueue(0x01, vec![], tx2, t0());
        assert!(e2.seq > e1.seq);
        assert_eq!(ch.pending(), 2);
    }

    #[tokio::test]
    async fn ack_resolves_waiter_with_ok() {
        let mut ch = ControlChannel::new();
        let (tx, rx) = oneshot::channel();
        let env = ch.enqueue(0x01, b"x".to_vec(), tx, t0());
        let acked = ch.on_ack(&ControlAck {
            seq: env.seq,
            status: AckStatus::Ok,
        });
        assert!(acked);
        assert_eq!(ch.pending(), 0);
        assert_eq!(rx.await.unwrap(), Ok(()));
    }

    #[tokio::test]
    async fn ack_resolves_waiter_with_reject() {
        let mut ch = ControlChannel::new();
        let (tx, rx) = oneshot::channel();
        let env = ch.enqueue(0x01, b"x".to_vec(), tx, t0());
        ch.on_ack(&ControlAck {
            seq: env.seq,
            status: AckStatus::Reject(0xBEEF),
        });
        assert_eq!(rx.await.unwrap(), Err(SendError::Rejected(0xBEEF)));
    }

    #[tokio::test]
    async fn ack_resolves_waiter_with_unknown() {
        let mut ch = ControlChannel::new();
        let (tx, rx) = oneshot::channel();
        let env = ch.enqueue(0x01, b"x".to_vec(), tx, t0());
        ch.on_ack(&ControlAck {
            seq: env.seq,
            status: AckStatus::Unknown,
        });
        assert_eq!(rx.await.unwrap(), Err(SendError::UnknownBodyType));
    }

    #[test]
    fn unknown_ack_seq_is_silently_dropped() {
        let mut ch = ControlChannel::new();
        let acked = ch.on_ack(&ControlAck {
            seq: 9999,
            status: AckStatus::Ok,
        });
        assert!(!acked);
    }

    #[test]
    fn retransmit_fires_after_initial_backoff() {
        let mut ch = ControlChannel::new();
        let (tx, _rx) = oneshot::channel();
        let start = t0();
        let _ = ch.enqueue(0x01, b"x".to_vec(), tx, start);
        // Before the deadline, nothing is due.
        assert!(ch.next_due(start + RETX_INITIAL / 2).is_empty());
        // At the deadline, the first retransmit fires.
        let due = ch.next_due(start + RETX_INITIAL);
        assert_eq!(due.len(), 1);
        // Next deadline now uses exponential backoff (attempts=2 → 2× initial).
        assert!(ch.next_tick_at().unwrap() > start + RETX_INITIAL);
    }

    #[tokio::test]
    async fn retransmits_eventually_time_out() {
        let mut ch = ControlChannel::new();
        let (tx, rx) = oneshot::channel();
        let start = t0();
        let _ = ch.enqueue(0x01, b"x".to_vec(), tx, start);
        // Walk far past the last possible deadline; drive next_due until the
        // queue empties or attempts hit the cap.
        let mut now = start;
        for _ in 0..RETX_MAX_ATTEMPTS + 2 {
            now += RETX_MAX * 2;
            let _ = ch.next_due(now);
        }
        assert_eq!(ch.pending(), 0);
        assert_eq!(
            rx.await.unwrap(),
            Err(SendError::Timeout(RETX_MAX_ATTEMPTS))
        );
    }

    #[test]
    fn dedup_window_marks_repeated_seqs_as_duplicate() {
        let mut ch = ControlChannel::new();
        let env = ControlEnvelope {
            seq: 7,
            body_type: 0x01,
            body: vec![],
        };
        match ch.on_inbound(env.clone()) {
            InboundDisposition::Deliver(e) => assert_eq!(e, env),
            InboundDisposition::Duplicate => panic!("first delivery should not be duplicate"),
        }
        // Re-deliver the same seq.
        assert_eq!(ch.on_inbound(env), InboundDisposition::Duplicate);
    }

    #[test]
    fn dedup_window_evicts_oldest_entries() {
        let mut ch = ControlChannel::new();
        // Fill the dedup window plus one extra so seq=0 ages out.
        for i in 0..=DEDUP_WINDOW as u32 {
            let env = ControlEnvelope {
                seq: i,
                body_type: 0x01,
                body: vec![],
            };
            let _ = ch.on_inbound(env);
        }
        // seq=0 was the oldest; with the window full + one extra it should
        // now be evicted, so re-presenting it counts as a fresh Deliver.
        let env0 = ControlEnvelope {
            seq: 0,
            body_type: 0x01,
            body: vec![],
        };
        match ch.on_inbound(env0.clone()) {
            InboundDisposition::Deliver(e) => assert_eq!(e, env0),
            InboundDisposition::Duplicate => panic!("seq 0 should have aged out"),
        }
    }

    #[tokio::test]
    async fn abort_all_notifies_waiters() {
        let mut ch = ControlChannel::new();
        let (tx, rx) = oneshot::channel();
        let _ = ch.enqueue(0x01, b"x".to_vec(), tx, t0());
        ch.abort_all();
        assert_eq!(ch.pending(), 0);
        assert_eq!(rx.await.unwrap(), Err(SendError::ChannelClosed));
    }

    #[tokio::test]
    async fn drop_notifies_waiters() {
        let (tx, rx) = oneshot::channel();
        {
            let mut ch = ControlChannel::new();
            let _ = ch.enqueue(0x01, b"x".to_vec(), tx, t0());
        }
        assert_eq!(rx.await.unwrap(), Err(SendError::ChannelClosed));
    }

    #[test]
    fn backoff_caps_at_retx_max() {
        // attempts=1 → 200ms, doubling, capped at 2s.
        assert_eq!(backoff_for(1), Duration::from_millis(200));
        assert_eq!(backoff_for(2), Duration::from_millis(400));
        assert_eq!(backoff_for(3), Duration::from_millis(800));
        assert_eq!(backoff_for(4), Duration::from_millis(1600));
        // attempts=5 would naively give 3.2s → capped.
        assert_eq!(backoff_for(5), RETX_MAX);
        assert_eq!(backoff_for(99), RETX_MAX);
    }
}
