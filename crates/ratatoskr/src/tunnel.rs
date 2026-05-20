//! Chain-control tunnel wire schema.
//!
//! A **tunnel** is a credit-windowed, in-order byte stream carried inside
//! [`ControlEnvelope`] bodies. The operator CLI (`yggdrasilctl chain ...`)
//! opens a tunnel from the local terminal node to a chain-internal target
//! (an introspection endpoint on an upstream relay, listening on
//! `127.0.0.1`), pumps HTTP request/response bytes through it, and closes
//! it when done.
//!
//! This module ships **only the wire envelope types**. The relay-side
//! state machine, allow-list enforcement, and UDS bridge land in Phase 4B.
//! Phase 4A is intentionally limited to type definitions, the
//! [`ControlBodyType`] additions, postcard roundtrip coverage, and the
//! per-variant reject reason registry so the wire shape is locked in
//! before any code path consumes it.
//!
//! ## Wire shape
//!
//! Three body types claim three consecutive discriminator bytes:
//! * [`ControlBodyType::TunnelOpen`] (`0x03`) — body = postcard
//!   ([`TunnelOpen`]). The originator picks `stream_id` from a
//!   channel-local space; the receiver must reject (`Reject(
//!   tunnel_reject::DUPLICATE_STREAM_ID)`) if `stream_id` is already
//!   live on that channel.
//! * [`ControlBodyType::TunnelData`] (`0x04`) — body = postcard
//!   ([`TunnelData`]). Carries one chunk of stream bytes. The receiver
//!   must reject if `stream_id` does not name a live stream on that
//!   channel.
//! * [`ControlBodyType::TunnelClose`] (`0x05`) — body = postcard
//!   ([`TunnelClose`]). Idempotent: a close for an unknown
//!   `stream_id` acks `Ok` (the sender's reliability layer treats a
//!   re-ack of an old close as a no-op).
//!
//! ## Reason codes
//!
//! Tunnel reject reasons live in `200..300`, disjoint from the predicate
//! range (`100..200`) and the heartbeat/auth range (reserved low ints).
//! See [`tunnel_reject`].
//!
//! ## Allow-list
//!
//! The tunnel terminator (the node where `target_pubkey == self`) enforces
//! a destination allow-list hardcoded in the daemon for v1. Default
//! configuration is `127.0.0.1` only. Open requests outside the allow-list
//! are rejected with [`tunnel_reject::TARGET_NOT_ALLOWED`].
//!
//! ## Backpressure (Phase 4B)
//!
//! The state machine uses an initial 64 KiB receive window per stream and
//! advertises credit on ack. The wire format does not currently carry
//! credit; ack-side credit signalling is added at the same time as the
//! tunnel state machine. Phase 4A's envelope types are sized so that
//! adding optional credit fields is a non-breaking postcard append.
//!
//! [`ControlEnvelope`]: crate::control_frame::ControlEnvelope
//! [`ControlBodyType::TunnelOpen`]: crate::control_frame::ControlBodyType::TunnelOpen
//! [`ControlBodyType::TunnelData`]: crate::control_frame::ControlBodyType::TunnelData
//! [`ControlBodyType::TunnelClose`]: crate::control_frame::ControlBodyType::TunnelClose

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::pubkey::PubKey;

/// Open a new tunnel stream from the originator to `target_pubkey`'s
/// node, terminating at `dest` once the target is reached.
///
/// `stream_id` is chosen by the originator from the channel-local
/// (per-session) `u32` space. Receivers reject duplicate live ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelOpen {
    /// Originator-chosen stream identifier; unique among live streams on
    /// the same control channel.
    pub stream_id: u32,
    /// Pubkey of the node that should terminate the tunnel. Intermediate
    /// nodes forward; the matching node dials `dest`. In Phase 4B,
    /// `target_pubkey == self` is the only supported topology (single-hop
    /// terminate-at-this-node); multi-hop forward is added in Phase 5.
    pub target_pubkey: PubKey,
    /// Destination socket address on the terminating node. The terminator
    /// enforces an allow-list against this value; the default allow-list
    /// is `127.0.0.1` only.
    pub dest: SocketAddr,
}

/// One chunk of bytes on an open stream.
///
/// Receivers must validate that `stream_id` names a live stream before
/// delivering `payload`; an unknown id is rejected with
/// [`tunnel_reject::STREAM_NOT_FOUND`].
///
/// Each chunk is bounded by [`TUNNEL_DATA_MAX_PAYLOAD`]; oversize chunks
/// are rejected with [`tunnel_reject::PAYLOAD_TOO_LARGE`]. The sender's
/// reliability layer must split larger transfers into multiple chunks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelData {
    /// Identifies the stream this chunk belongs to.
    pub stream_id: u32,
    /// Payload bytes. Empty payloads are legal and may be used for keep-
    /// alives, but the v1 state machine never emits them on its own.
    pub payload: Vec<u8>,
}

/// Half-close + half-close-with-error indication for an open stream.
///
/// `reason == 0` means "clean shutdown initiated by the local side";
/// non-zero values are drawn from [`tunnel_reject`] when a node refuses
/// to continue the stream (for example, an upstream dial failure observed
/// after the tunnel was open).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelClose {
    /// Identifies the stream being closed.
    pub stream_id: u32,
    /// Close reason. `0` = clean shutdown; non-zero values come from
    /// [`tunnel_reject`] and indicate the close was forced by a failure
    /// somewhere on the path.
    pub reason: u16,
}

/// Reject reason codes carried by `AckStatus::Reject(u16)` in response to
/// a tunnel body. All codes live in the range `200..300`.
pub mod tunnel_reject {
    /// `TunnelData` or `TunnelClose` referenced a `stream_id` that the
    /// receiver does not know about. (For `TunnelClose`, this is the only
    /// situation where the receiver acks `Reject` — a duplicate close on
    /// a stream that has already been closed acks `Ok`.)
    pub const STREAM_NOT_FOUND: u16 = 200;
    /// `TunnelOpen.dest` is outside the terminating node's allow-list.
    /// The terminator enforces the allow-list before dialling.
    pub const TARGET_NOT_ALLOWED: u16 = 201;
    /// The terminator failed to dial `TunnelOpen.dest`. Returned
    /// synchronously when the OS-level connect fails fast (refused,
    /// network unreachable). Slow failures (timeout) surface as a
    /// `TunnelClose` with the same reason.
    pub const TARGET_UNREACHABLE: u16 = 202;
    /// `TunnelOpen` was sent with a `stream_id` that already names a
    /// live stream on the same control channel. The originator must
    /// pick a fresh id.
    pub const DUPLICATE_STREAM_ID: u16 = 203;
    /// `TunnelData.payload` exceeds [`super::TUNNEL_DATA_MAX_PAYLOAD`].
    pub const PAYLOAD_TOO_LARGE: u16 = 204;
    /// An intermediate node detected a forwarding loop (the originator's
    /// pubkey was already in the visited set). Forwarding is a Phase 5
    /// concern; the code is reserved here so the registry is stable.
    pub const LOOP_DETECTED: u16 = 205;
    /// The receiver does not permit tunnels from this originator
    /// (catch-all policy bucket: future per-tenant restrictions land
    /// here without claiming new codes).
    pub const TUNNEL_NOT_PERMITTED: u16 = 206;
}

/// Per-chunk payload cap for a single [`TunnelData`] body.
///
/// 16 KiB leaves comfortable headroom under the typical 64 KiB UDP /
/// Noise frame ceiling after envelope, postcard, and AEAD overhead, and
/// matches the natural HTTP body chunk size most operator CLIs emit. The
/// terminator's receive window (Phase 4B) is 64 KiB, so a sender can have
/// up to four [`TUNNEL_DATA_MAX_PAYLOAD`]-sized chunks in flight before
/// blocking on credit.
pub const TUNNEL_DATA_MAX_PAYLOAD: usize = 16 * 1024;

/// Soft cap on the postcard-encoded size of a [`TunnelOpen`] body. The
/// open-side body carries no operator-supplied bytes; the cap exists so
/// a malformed peer cannot stuff a giant pubkey/addr buffer through the
/// dispatcher.
pub const TUNNEL_OPEN_MAX_WIRE_BYTES: usize = 256;

/// Soft cap on the postcard-encoded size of a [`TunnelClose`] body.
pub const TUNNEL_CLOSE_MAX_WIRE_BYTES: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::PUBLIC_KEY_LEN;

    fn sample_pubkey() -> PubKey {
        PubKey::x25519([7u8; PUBLIC_KEY_LEN])
    }

    #[test]
    fn tunnel_open_postcard_roundtrip_v4() {
        let open = TunnelOpen {
            stream_id: 0x0102_0304,
            target_pubkey: sample_pubkey(),
            dest: "127.0.0.1:9100".parse().unwrap(),
        };
        let bytes = postcard::to_allocvec(&open).unwrap();
        let back: TunnelOpen = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(open, back);
    }

    #[test]
    fn tunnel_open_postcard_roundtrip_v6() {
        let open = TunnelOpen {
            stream_id: 1,
            target_pubkey: sample_pubkey(),
            dest: "[::1]:443".parse().unwrap(),
        };
        let bytes = postcard::to_allocvec(&open).unwrap();
        let back: TunnelOpen = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(open, back);
    }

    #[test]
    fn tunnel_open_fits_under_soft_cap() {
        let open = TunnelOpen {
            stream_id: u32::MAX,
            target_pubkey: sample_pubkey(),
            // IPv6 + non-default port is the worst encoding for the IP.
            dest: "[fe80::dead:beef:dead:beef]:65535".parse().unwrap(),
        };
        let bytes = postcard::to_allocvec(&open).unwrap();
        assert!(
            bytes.len() <= TUNNEL_OPEN_MAX_WIRE_BYTES,
            "TunnelOpen wire size {} exceeds cap {}",
            bytes.len(),
            TUNNEL_OPEN_MAX_WIRE_BYTES
        );
    }

    #[test]
    fn tunnel_data_postcard_roundtrip_empty() {
        let data = TunnelData {
            stream_id: 99,
            payload: vec![],
        };
        let bytes = postcard::to_allocvec(&data).unwrap();
        let back: TunnelData = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(data, back);
    }

    #[test]
    fn tunnel_data_postcard_roundtrip_full() {
        let data = TunnelData {
            stream_id: 0xCAFEBABE,
            payload: (0..TUNNEL_DATA_MAX_PAYLOAD).map(|i| i as u8).collect(),
        };
        let bytes = postcard::to_allocvec(&data).unwrap();
        let back: TunnelData = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(data, back);
    }

    #[test]
    fn tunnel_close_postcard_roundtrip_clean() {
        let close = TunnelClose { stream_id: 7, reason: 0 };
        let bytes = postcard::to_allocvec(&close).unwrap();
        let back: TunnelClose = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(close, back);
    }

    #[test]
    fn tunnel_close_postcard_roundtrip_error() {
        let close = TunnelClose {
            stream_id: 7,
            reason: tunnel_reject::TARGET_UNREACHABLE,
        };
        let bytes = postcard::to_allocvec(&close).unwrap();
        let back: TunnelClose = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(close, back);
        assert!(bytes.len() <= TUNNEL_CLOSE_MAX_WIRE_BYTES);
    }

    #[test]
    fn reject_codes_are_in_the_200_range() {
        // Hardcoded so a typo here trips the test rather than silently
        // colliding with the predicate range.
        assert_eq!(tunnel_reject::STREAM_NOT_FOUND, 200);
        assert_eq!(tunnel_reject::TARGET_NOT_ALLOWED, 201);
        assert_eq!(tunnel_reject::TARGET_UNREACHABLE, 202);
        assert_eq!(tunnel_reject::DUPLICATE_STREAM_ID, 203);
        assert_eq!(tunnel_reject::PAYLOAD_TOO_LARGE, 204);
        assert_eq!(tunnel_reject::LOOP_DETECTED, 205);
        assert_eq!(tunnel_reject::TUNNEL_NOT_PERMITTED, 206);
    }
}
