//! Out-of-band enrollment token format.
//!
//! ## Operator flow
//!
//! 1. Ratatoskr operator runs `ratatoskr keygen` and `ratatoskr pubkey` to
//!    obtain the residential side's static X25519 keypair and publishes the
//!    public half to the yggdrasil operator.
//! 2. The yggdrasil operator runs `yggdrasil enroll-token --peer-pubkey <hex>
//!    --endpoint vps.example.com:7117 -o token.txt`, which writes the trusted
//!    peer pubkey into yggdrasil's config (with operator confirmation) and
//!    emits the token below.
//! 3. The token is transferred to the residential box over a trusted channel
//!    (scp, USB, etc.). Because the token contains only public material it is
//!    not itself a secret, but operators should still avoid handing it to
//!    untrusted parties — the `peer_public` it carries is the entry on
//!    yggdrasil's allow-list.
//! 4. `ratatoskr enroll token.txt` parses the token, verifies that
//!    `peer_public` matches the locally generated identity, and writes
//!    `yggdrasil_public` + `endpoint_hint` into `/etc/ratatoskr/config.toml`.
//!
//! A wrong-token-by-mistake fails fast at the next handshake attempt (Noise_IK
//! key mismatch produces `Error::Noise`).
//!
//! ## Wire format
//!
//! ```text
//! +-----------+---------+--------------------------+
//! | "YGG1"    | version | postcard(EnrollmentBody) |
//! | 4 bytes   | 1 byte  | variable                 |
//! +-----------+---------+--------------------------+
//! ```
//!
//! The whole blob is then [Base64 (URL-safe, no padding)] encoded and
//! prefixed with `YGG1-v1.` so misuse like pasting a non-token string fails
//! fast on the first character.

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::auth::PUBLIC_KEY_LEN;
use crate::error::{Error, Result};

/// 4-byte magic prefix on every enrollment token binary blob.
pub const MAGIC: &[u8; 4] = b"YGG1";
/// Current on-the-wire token version.
pub const TOKEN_VERSION: u8 = 1;
/// Human-visible prefix on the base64-encoded form.
pub const TEXT_PREFIX: &str = "YGG1-v1.";

/// Body of an enrollment token, serialised with `postcard`.
///
/// Contains only public material. The peer secret never leaves the residential
/// host where `ratatoskr keygen` ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentBody {
    /// Long-term public key of the yggdrasil server. Ratatoskr pins this.
    pub yggdrasil_public: [u8; PUBLIC_KEY_LEN],
    /// Public key of the peer (ratatoskr) — used as a sanity-check on enrollment.
    pub peer_public: [u8; PUBLIC_KEY_LEN],
    /// `host:port` (or `[ipv6]:port`) hint for ratatoskr to dial first.
    pub endpoint_hint: String,
    /// Unix epoch seconds when the operator minted the token.
    pub issued_at: i64,
}

impl EnrollmentBody {
    /// Construct a token body. Caller (yggdrasil operator) supplies the
    /// peer's pubkey received out-of-band from the ratatoskr operator.
    pub fn new(
        yggdrasil_public: [u8; PUBLIC_KEY_LEN],
        peer_public: [u8; PUBLIC_KEY_LEN],
        endpoint_hint: impl Into<String>,
        issued_at: i64,
    ) -> Self {
        Self {
            yggdrasil_public,
            peer_public,
            endpoint_hint: endpoint_hint.into(),
            issued_at,
        }
    }

    /// Encode to the binary blob: `MAGIC ++ TOKEN_VERSION ++ postcard(body)`.
    pub fn encode_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(64 + self.endpoint_hint.len());
        buf.extend_from_slice(MAGIC);
        buf.push(TOKEN_VERSION);
        let body = postcard::to_stdvec(self).map_err(Error::Postcard)?;
        buf.extend_from_slice(&body);
        Ok(buf)
    }

    /// Decode a binary blob produced by [`Self::encode_bytes`].
    pub fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < MAGIC.len() + 1 {
            return Err(Error::InvalidEnrollmentToken(
                "token too short for header".into(),
            ));
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(Error::InvalidEnrollmentToken("missing magic prefix".into()));
        }
        let version = bytes[MAGIC.len()];
        if version != TOKEN_VERSION {
            return Err(Error::InvalidEnrollmentToken(format!(
                "unsupported token version {version}"
            )));
        }
        let body_bytes = &bytes[MAGIC.len() + 1..];
        postcard::from_bytes(body_bytes).map_err(Error::Postcard)
    }

    /// Encode to the human-distributable text form (`YGG1-v1.<base64-url>`).
    pub fn encode_string(&self) -> Result<String> {
        let bytes = self.encode_bytes()?;
        let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
        Ok(format!("{TEXT_PREFIX}{body}"))
    }

    /// Decode the human-distributable text form.
    ///
    /// Accepts the canonical `YGG1-v1.<b64>` form. Leading/trailing whitespace
    /// is stripped so pasting from a terminal with a stray newline works.
    pub fn decode_string(s: &str) -> Result<Self> {
        let s = s.trim();
        let body = s.strip_prefix(TEXT_PREFIX).ok_or_else(|| {
            Error::InvalidEnrollmentToken(format!(
                "token must start with `{TEXT_PREFIX}`"
            ))
        })?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body.as_bytes())
            .map_err(Error::Base64)?;
        Self::decode_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::StaticKeyPair;

    fn make_body() -> (EnrollmentBody, StaticKeyPair, StaticKeyPair) {
        let server = StaticKeyPair::generate().unwrap();
        let peer = StaticKeyPair::generate().unwrap();
        let body = EnrollmentBody::new(
            *server.public_key(),
            *peer.public_key(),
            "vps.example.com:7117",
            1_700_000_000,
        );
        (body, server, peer)
    }

    #[test]
    fn text_roundtrip_carries_public_material_only() {
        let (body, _server, peer) = make_body();
        let s = body.encode_string().unwrap();
        assert!(s.starts_with(TEXT_PREFIX));

        let decoded = EnrollmentBody::decode_string(&s).unwrap();
        assert_eq!(decoded, body);
        assert_eq!(decoded.peer_public, *peer.public_key());
    }

    #[test]
    fn binary_roundtrip() {
        let (body, _, _) = make_body();
        let bytes = body.encode_bytes().unwrap();
        assert_eq!(&bytes[..4], MAGIC);
        assert_eq!(bytes[4], TOKEN_VERSION);
        let decoded = EnrollmentBody::decode_bytes(&bytes).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn rejects_missing_magic() {
        let err = EnrollmentBody::decode_bytes(b"NOPE\x01garbage").err();
        assert!(matches!(err, Some(Error::InvalidEnrollmentToken(_))));
    }

    #[test]
    fn rejects_wrong_version() {
        let mut bytes = MAGIC.to_vec();
        bytes.push(0xFF);
        bytes.extend_from_slice(b"junk");
        let err = EnrollmentBody::decode_bytes(&bytes).err();
        assert!(matches!(err, Some(Error::InvalidEnrollmentToken(_))));
    }

    #[test]
    fn rejects_short_blob() {
        let err = EnrollmentBody::decode_bytes(b"YG").err();
        assert!(matches!(err, Some(Error::InvalidEnrollmentToken(_))));
    }

    #[test]
    fn rejects_text_without_prefix() {
        let err = EnrollmentBody::decode_string("not-a-token").err();
        assert!(matches!(err, Some(Error::InvalidEnrollmentToken(_))));
    }

    #[test]
    fn whitespace_is_tolerated_on_decode() {
        let (body, _, _) = make_body();
        let s = body.encode_string().unwrap();
        let with_ws = format!("\n  {s}\n");
        let decoded = EnrollmentBody::decode_string(&with_ws).unwrap();
        assert_eq!(decoded, body);
    }
}
