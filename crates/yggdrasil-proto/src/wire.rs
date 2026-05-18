//! Wire format for the control-plane channel between ratatoskr and yggdrasil.
//!
//! Every packet starts with a 5-byte preamble:
//!
//! ```text
//! +------+-------------+
//! | tag  | session_id  |
//! | 1 B  | 4 B         |
//! +------+-------------+
//! ```
//!
//! Handshake packets (`Handshake1`, `Handshake2`) follow the preamble immediately
//! with the raw Noise message bytes.
//!
//! Post-handshake packets (`Heartbeat`, `HeartbeatAck`, `Rekey`) carry an 8-byte
//! big-endian counter (the Noise AEAD nonce, in cleartext) before the ciphertext:
//!
//! ```text
//! +------+-------------+----------+------------------+
//! | tag  | session_id  | counter  | ciphertext + tag |
//! | 1 B  | 4 B         | 8 B BE   | variable         |
//! +------+-------------+----------+------------------+
//! ```
//!
//! Plaintext payload formats (inside the AEAD ciphertext) are:
//!
//! * `Heartbeat`     — `timestamp_ms` (u64 BE) ++ `flags` (u8) — total 9 bytes
//! * `HeartbeatAck`  — `echoed_counter` (u64 BE) ++ `server_ts_ms` (u64 BE) — 16 bytes
//! * `Rekey`         — empty
//!
//! The counter is in cleartext so the receiver can call
//! [`snow::TransportState::set_receiving_nonce`] before attempting to decrypt
//! and so the layer above can perform a cheap monotonic replay check without
//! touching crypto state. The cleartext value is implicitly authenticated by
//! the AEAD: if an attacker mutates the counter, the nonce used to verify the
//! tag differs and decryption fails.

use crate::error::{Error, Result};

// ---- Packet-type discriminators ----

pub const TAG_HANDSHAKE_1: u8 = 0x01;
pub const TAG_HANDSHAKE_2: u8 = 0x02;
pub const TAG_HEARTBEAT: u8 = 0x03;
pub const TAG_HEARTBEAT_ACK: u8 = 0x04;
pub const TAG_REKEY: u8 = 0x05;

// ---- Constants ----

/// Length of the common preamble (tag + session id).
pub const PREAMBLE_LEN: usize = 1 + 4;
/// Length of the cleartext counter that prefixes post-handshake packets.
pub const COUNTER_LEN: usize = 8;
/// Length of the encrypted heartbeat plaintext (`timestamp_ms` + `flags`).
pub const HEARTBEAT_PT_LEN: usize = 8 + 1;
/// Length of the encrypted heartbeat-ack plaintext.
pub const HEARTBEAT_ACK_PT_LEN: usize = 8 + 8;
/// AEAD tag length (ChaCha20-Poly1305).
pub const AEAD_TAG_LEN: usize = 16;

/// A 4-byte session identifier, picked by the initiator and echoed by the responder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SessionId(pub [u8; 4]);

impl SessionId {
    /// Generate a random session ID using [`rand::thread_rng`].
    pub fn random() -> Self {
        use rand::RngCore;
        let mut b = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut b);
        Self(b)
    }

    /// Render the ID as 8 lowercase hex characters (useful for log fields).
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// All packet types defined for the control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Handshake1   = TAG_HANDSHAKE_1,
    Handshake2   = TAG_HANDSHAKE_2,
    Heartbeat    = TAG_HEARTBEAT,
    HeartbeatAck = TAG_HEARTBEAT_ACK,
    Rekey        = TAG_REKEY,
}

impl PacketType {
    pub fn from_tag(tag: u8) -> Result<Self> {
        Ok(match tag {
            TAG_HANDSHAKE_1    => Self::Handshake1,
            TAG_HANDSHAKE_2    => Self::Handshake2,
            TAG_HEARTBEAT      => Self::Heartbeat,
            TAG_HEARTBEAT_ACK  => Self::HeartbeatAck,
            TAG_REKEY          => Self::Rekey,
            other              => return Err(Error::UnknownPacketType(other)),
        })
    }

    /// `true` for `Heartbeat`, `HeartbeatAck`, `Rekey` — the cleartext counter
    /// field follows the preamble for these.
    pub fn has_counter(self) -> bool {
        matches!(self, Self::Heartbeat | Self::HeartbeatAck | Self::Rekey)
    }
}

/// A parsed view of an inbound packet — owns no allocation beyond the input slice.
#[derive(Debug)]
pub struct PacketView<'a> {
    pub packet_type: PacketType,
    pub session_id:  SessionId,
    /// Only set for `Heartbeat`/`HeartbeatAck`/`Rekey`; `None` for handshake packets.
    pub counter:     Option<u64>,
    /// Remaining bytes: for handshake packets, the raw Noise message; for
    /// post-handshake packets, the ciphertext + AEAD tag.
    pub body:        &'a [u8],
}

/// Parse the preamble (and counter, when present) from an inbound packet.
///
/// Returns an error if the buffer is shorter than the minimum required for the
/// detected packet type or carries an unknown tag.
pub fn parse(buf: &[u8]) -> Result<PacketView<'_>> {
    if buf.len() < PREAMBLE_LEN {
        return Err(Error::MalformedPacket("packet shorter than preamble"));
    }
    let packet_type = PacketType::from_tag(buf[0])?;
    let mut sid = [0u8; 4];
    sid.copy_from_slice(&buf[1..5]);
    let session_id = SessionId(sid);

    if packet_type.has_counter() {
        if buf.len() < PREAMBLE_LEN + COUNTER_LEN {
            return Err(Error::MalformedPacket("packet shorter than preamble + counter"));
        }
        let counter = u64::from_be_bytes(
            buf[PREAMBLE_LEN..PREAMBLE_LEN + COUNTER_LEN]
                .try_into()
                .expect("8-byte slice"),
        );
        Ok(PacketView {
            packet_type,
            session_id,
            counter: Some(counter),
            body: &buf[PREAMBLE_LEN + COUNTER_LEN..],
        })
    } else {
        Ok(PacketView {
            packet_type,
            session_id,
            counter: None,
            body: &buf[PREAMBLE_LEN..],
        })
    }
}

/// Write the preamble bytes (tag + session id) into `out`.
pub fn write_preamble(out: &mut Vec<u8>, pt: PacketType, sid: SessionId) {
    out.push(pt as u8);
    out.extend_from_slice(&sid.0);
}

/// Write the cleartext counter into `out` (big-endian u64).
pub fn write_counter(out: &mut Vec<u8>, counter: u64) {
    out.extend_from_slice(&counter.to_be_bytes());
}

// ---- Plaintext payload encoders / decoders ----

/// Encode a heartbeat plaintext (before AEAD).
pub fn encode_heartbeat_plaintext(timestamp_ms: u64, flags: u8) -> [u8; HEARTBEAT_PT_LEN] {
    let mut buf = [0u8; HEARTBEAT_PT_LEN];
    buf[..8].copy_from_slice(&timestamp_ms.to_be_bytes());
    buf[8] = flags;
    buf
}

pub fn decode_heartbeat_plaintext(buf: &[u8]) -> Result<(u64, u8)> {
    if buf.len() != HEARTBEAT_PT_LEN {
        return Err(Error::MalformedPacket("heartbeat plaintext wrong length"));
    }
    let ts = u64::from_be_bytes(buf[..8].try_into().expect("8 bytes"));
    Ok((ts, buf[8]))
}

pub fn encode_heartbeat_ack_plaintext(
    echoed_counter: u64,
    server_ts_ms: u64,
) -> [u8; HEARTBEAT_ACK_PT_LEN] {
    let mut buf = [0u8; HEARTBEAT_ACK_PT_LEN];
    buf[..8].copy_from_slice(&echoed_counter.to_be_bytes());
    buf[8..].copy_from_slice(&server_ts_ms.to_be_bytes());
    buf
}

pub fn decode_heartbeat_ack_plaintext(buf: &[u8]) -> Result<(u64, u64)> {
    if buf.len() != HEARTBEAT_ACK_PT_LEN {
        return Err(Error::MalformedPacket("heartbeat-ack plaintext wrong length"));
    }
    let ec = u64::from_be_bytes(buf[..8].try_into().expect("8 bytes"));
    let ts = u64::from_be_bytes(buf[8..].try_into().expect("8 bytes"));
    Ok((ec, ts))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_short_packet() {
        assert!(matches!(parse(&[]), Err(Error::MalformedPacket(_))));
        assert!(matches!(parse(&[0x01, 0, 0, 0]), Err(Error::MalformedPacket(_))));
    }

    #[test]
    fn parse_rejects_unknown_tag() {
        let buf = [0xFF, 0, 0, 0, 0];
        assert!(matches!(parse(&buf), Err(Error::UnknownPacketType(0xFF))));
    }

    #[test]
    fn parse_handshake_1_no_counter() {
        let sid = SessionId([1, 2, 3, 4]);
        let mut buf = Vec::new();
        write_preamble(&mut buf, PacketType::Handshake1, sid);
        buf.extend_from_slice(b"NOISE_MSG_1");
        let view = parse(&buf).unwrap();
        assert_eq!(view.packet_type, PacketType::Handshake1);
        assert_eq!(view.session_id, sid);
        assert!(view.counter.is_none());
        assert_eq!(view.body, b"NOISE_MSG_1");
    }

    #[test]
    fn parse_heartbeat_with_counter() {
        let sid = SessionId([0xDE, 0xAD, 0xBE, 0xEF]);
        let mut buf = Vec::new();
        write_preamble(&mut buf, PacketType::Heartbeat, sid);
        write_counter(&mut buf, 0x0102_0304_0506_0708);
        buf.extend_from_slice(b"CIPHERTEXT");
        let view = parse(&buf).unwrap();
        assert_eq!(view.packet_type, PacketType::Heartbeat);
        assert_eq!(view.session_id, sid);
        assert_eq!(view.counter, Some(0x0102_0304_0506_0708));
        assert_eq!(view.body, b"CIPHERTEXT");
    }

    #[test]
    fn parse_heartbeat_rejects_when_truncated_in_counter() {
        // Preamble + only 4 bytes of counter — should fail.
        let mut buf = Vec::new();
        write_preamble(&mut buf, PacketType::Heartbeat, SessionId([0; 4]));
        buf.extend_from_slice(&[0, 0, 0, 0]);
        assert!(matches!(parse(&buf), Err(Error::MalformedPacket(_))));
    }

    #[test]
    fn heartbeat_plaintext_roundtrip() {
        let buf = encode_heartbeat_plaintext(1_700_000_000_123, 0x42);
        let (ts, flags) = decode_heartbeat_plaintext(&buf).unwrap();
        assert_eq!(ts, 1_700_000_000_123);
        assert_eq!(flags, 0x42);
    }

    #[test]
    fn heartbeat_ack_plaintext_roundtrip() {
        let buf = encode_heartbeat_ack_plaintext(42, 1_700_000_000_555);
        let (echoed, ts) = decode_heartbeat_ack_plaintext(&buf).unwrap();
        assert_eq!(echoed, 42);
        assert_eq!(ts, 1_700_000_000_555);
    }

    #[test]
    fn session_id_renders_as_hex() {
        assert_eq!(SessionId([0xDE, 0xAD, 0xBE, 0xEF]).to_string(), "deadbeef");
    }
}
