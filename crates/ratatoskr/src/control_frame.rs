//! Encrypted control-plane frames carried inside `Control` / `ControlAck`
//! packets.
//!
//! The chain protocol divides the post-handshake tag space into two axes:
//!
//! * **Heartbeat** (`Heartbeat` / `HeartbeatAck`) — fixed-shape fitness keepalive.
//! * **Control**   (`Control` / `ControlAck`)    — variable-shape, sequenced,
//!   acked, body-typed payload that future phases use for branch announcements,
//!   TLS material distribution, allowlist sync, etc.
//!
//! This module defines only the **transport envelope**. Body-type semantics
//! and the body-type registry of actual variants live in `predicate.rs`,
//! `canary.rs`, and `chain_query.rs`. The envelope itself carries an
//! internal-only `Noop` body gated behind `#[cfg(test)]` for round-tripping
//! the reliability layer, plus a `Reserved` sentinel so the registry's
//! discriminator wire format is fixed.
//!
//! Wire shape (inside Noise AEAD ciphertext):
//!
//! ```text
//! ControlEnvelope = postcard({ seq: u32, body_type: u8, body: Vec<u8> })
//! ControlAck      = postcard({ seq: u32, status: AckStatus })
//! AckStatus       = Ok | Reject(u16) | Unknown
//! ```
//!
//! `seq` is a monotonically increasing channel-local sequence number assigned
//! by the sender. The receiver echoes it verbatim in `ControlAck.seq`. The
//! per-channel sequence space resets when the underlying Noise session is
//! renegotiated (rekey or reconnect); cross-session redelivery is out of
//! scope.

use serde::{Deserialize, Serialize};

/// Envelope carried inside every `Control` packet's ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlEnvelope {
    /// Channel-local monotone sequence number, assigned by the sender.
    pub seq: u32,
    /// Discriminator from the body-type registry. See [`ControlBodyType`].
    pub body_type: u8,
    /// Postcard-encoded body. Interpretation depends on `body_type`.
    pub body: Vec<u8>,
}

/// Envelope carried inside every `ControlAck` packet's ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlAck {
    /// Echoes `ControlEnvelope.seq` so the sender can resolve the matching
    /// outstanding send.
    pub seq: u32,
    pub status: AckStatus,
}

/// Outcome of delivering a control envelope to the receiver's dispatcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AckStatus {
    /// The receiver successfully consumed the envelope.
    Ok,
    /// The receiver recognised the body type but refused it; the `u16`
    /// is a body-type-defined reason code.
    Reject(u16),
    /// The receiver did not recognise the body type (forward-compat slot
    /// for a peer that hasn't been upgraded yet).
    Unknown,
}

/// Body-type registry. The repr is the on-the-wire `ControlEnvelope.body_type`
/// byte. New variants append; existing values never shift.
///
/// [`PredicateSetUpdate`] is the downstream → upstream push of a
/// terminal's [`PredicateSet`]; the wire body for that variant is a
/// postcard-encoded set, and reject reason codes live in
/// [`predicate_reject`](crate::predicate::predicate_reject).
///
/// [`Reserved`]: ControlBodyType::Reserved
/// [`Noop`]: ControlBodyType::Noop
/// [`PredicateSetUpdate`]: ControlBodyType::PredicateSetUpdate
/// [`PredicateSet`]: crate::predicate::PredicateSet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ControlBodyType {
    /// Sentinel; never sent on the wire. Reserves the `0x00` discriminator
    /// so future variants can claim it explicitly if useful.
    Reserved = 0x00,
    /// Internal no-op body used by the reliability-layer round-trip tests
    /// in `yggdrasil::chain`. Body is the empty `()` tuple postcard-encoded
    /// as zero bytes; receivers ack `Ok`. Production code paths never
    /// enqueue this body.
    Noop = 0x01,
    /// Downstream → upstream push of the downstream's current
    /// [`PredicateSet`]. Body is the postcard-encoded set. Receivers ack
    /// `Ok` on accept, `Reject(code)` with a
    /// [`predicate_reject`](crate::predicate::predicate_reject) code on
    /// validation/version/policy failure, or `Unknown` if they don't yet
    /// support predicate pushes.
    ///
    /// [`PredicateSet`]: crate::predicate::PredicateSet
    PredicateSetUpdate = 0x02,
    /// Downstream→upstream `ChainHopQuery` for the recursive
    /// `ChainSummary` RPC. Body is a postcard-encoded
    /// [`crate::chain_query::ChainHopQuery`]. The receiver acks `Ok`
    /// immediately, then asynchronously assembles its local hop (and
    /// any upstream hops it can reach within the deadline) and emits a
    /// reciprocal `ChainHopReply` envelope back to the querier on the
    /// same chain session.
    ChainHopQuery = 0x03,
    /// Upstream→downstream `ChainHopReply` carrying one or more
    /// [`crate::control::ChainHop`] entries. Body is a postcard-encoded
    /// [`crate::chain_query::ChainHopReply`]. The `query_id` field
    /// correlates the reply with the originating
    /// [`ChainHopQuery`](Self::ChainHopQuery).
    ChainHopReply = 0x04,
    /// Downstream→upstream `CanaryArm` for the recursive
    /// `chain canary` arming phase. Body is a postcard-encoded
    /// [`crate::canary::CanaryArm`]. Receivers acknowledge `Ok`
    /// synchronously and asynchronously install (terminal hops)
    /// or simply record (intermediate hops) the arm entry, then
    /// forward to their upstream when one exists. The originator
    /// of the canary command then drives the data phase against
    /// the rule's listener; matching probe traffic short-circuits
    /// to an in-process echo at the terminal.
    CanaryArm = 0x05,
    /// Upstream→downstream `CanaryReply` carrying the per-hop
    /// arming-phase result. Body is a postcard-encoded
    /// [`crate::canary::CanaryReply`]. The `query_id` field
    /// correlates the reply with the originating
    /// [`CanaryArm`](Self::CanaryArm).
    CanaryReply = 0x06,
}

impl ControlBodyType {
    /// Map a discriminator byte back to a known body type.
    /// Returns `None` for any byte the local registry does not recognise.
    pub fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0x00 => Self::Reserved,
            0x01 => Self::Noop,
            0x02 => Self::PredicateSetUpdate,
            0x03 => Self::ChainHopQuery,
            0x04 => Self::ChainHopReply,
            0x05 => Self::CanaryArm,
            0x06 => Self::CanaryReply,
            _ => return None,
        })
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_postcard_roundtrip() {
        let env = ControlEnvelope {
            seq: 17,
            body_type: ControlBodyType::Noop.as_byte(),
            body: vec![],
        };
        let bytes = postcard::to_allocvec(&env).unwrap();
        let back: ControlEnvelope = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn envelope_with_body_postcard_roundtrip() {
        let env = ControlEnvelope {
            seq: u32::MAX,
            body_type: 0xAB,
            body: (0u8..=255).collect(),
        };
        let bytes = postcard::to_allocvec(&env).unwrap();
        let back: ControlEnvelope = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn ack_postcard_roundtrip_ok() {
        let ack = ControlAck {
            seq: 42,
            status: AckStatus::Ok,
        };
        let bytes = postcard::to_allocvec(&ack).unwrap();
        let back: ControlAck = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ack, back);
    }

    #[test]
    fn ack_postcard_roundtrip_reject() {
        let ack = ControlAck {
            seq: 7,
            status: AckStatus::Reject(0xDEAD),
        };
        let bytes = postcard::to_allocvec(&ack).unwrap();
        let back: ControlAck = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ack, back);
    }

    #[test]
    fn ack_postcard_roundtrip_unknown() {
        let ack = ControlAck {
            seq: 7,
            status: AckStatus::Unknown,
        };
        let bytes = postcard::to_allocvec(&ack).unwrap();
        let back: ControlAck = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ack, back);
    }

    #[test]
    fn body_type_byte_roundtrip() {
        assert_eq!(ControlBodyType::Reserved.as_byte(), 0x00);
        assert_eq!(
            ControlBodyType::from_byte(0x00),
            Some(ControlBodyType::Reserved),
        );
        assert_eq!(ControlBodyType::Noop.as_byte(), 0x01);
        assert_eq!(
            ControlBodyType::from_byte(0x01),
            Some(ControlBodyType::Noop),
        );
        assert_eq!(ControlBodyType::PredicateSetUpdate.as_byte(), 0x02);
        assert_eq!(
            ControlBodyType::from_byte(0x02),
            Some(ControlBodyType::PredicateSetUpdate),
        );
        assert_eq!(ControlBodyType::ChainHopQuery.as_byte(), 0x03);
        assert_eq!(
            ControlBodyType::from_byte(0x03),
            Some(ControlBodyType::ChainHopQuery),
        );
        assert_eq!(ControlBodyType::ChainHopReply.as_byte(), 0x04);
        assert_eq!(
            ControlBodyType::from_byte(0x04),
            Some(ControlBodyType::ChainHopReply),
        );
        assert_eq!(ControlBodyType::CanaryArm.as_byte(), 0x05);
        assert_eq!(
            ControlBodyType::from_byte(0x05),
            Some(ControlBodyType::CanaryArm),
        );
        assert_eq!(ControlBodyType::CanaryReply.as_byte(), 0x06);
        assert_eq!(
            ControlBodyType::from_byte(0x06),
            Some(ControlBodyType::CanaryReply),
        );
        assert!(ControlBodyType::from_byte(0xFF).is_none());
    }

    // ---- proptest roundtrip invariants ----

    use proptest::prelude::*;

    fn arb_ack_status() -> impl Strategy<Value = AckStatus> {
        prop_oneof![
            Just(AckStatus::Ok),
            any::<u16>().prop_map(AckStatus::Reject),
            Just(AckStatus::Unknown),
        ]
    }

    fn arb_envelope() -> impl Strategy<Value = ControlEnvelope> {
        (
            any::<u32>(),
            any::<u8>(),
            proptest::collection::vec(any::<u8>(), 0..256),
        )
            .prop_map(|(seq, body_type, body)| ControlEnvelope {
                seq,
                body_type,
                body,
            })
    }

    fn arb_ack() -> impl Strategy<Value = ControlAck> {
        (any::<u32>(), arb_ack_status()).prop_map(|(seq, status)| ControlAck { seq, status })
    }

    proptest! {
        #[test]
        fn proptest_envelope_postcard_roundtrip(env in arb_envelope()) {
            let bytes = postcard::to_allocvec(&env).unwrap();
            let back: ControlEnvelope = postcard::from_bytes(&bytes).unwrap();
            prop_assert_eq!(env, back);
        }

        #[test]
        fn proptest_ack_postcard_roundtrip(ack in arb_ack()) {
            let bytes = postcard::to_allocvec(&ack).unwrap();
            let back: ControlAck = postcard::from_bytes(&bytes).unwrap();
            prop_assert_eq!(ack, back);
        }
    }
}
