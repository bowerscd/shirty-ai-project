//! Tagged public-key wire/text form.
//!
//! Every public key carries an explicit algorithm tag so a future
//! post-quantum migration can append variants without breaking older
//! parsers. Text form is `<algo>:<hex>`; the only `<algo>` value in v1 is
//! `x25519`.
//!
//! The enum is `#[non_exhaustive]` so adding variants in a future version is
//! a non-breaking change for downstream crates that match on it.
//!
//! Fingerprints are also tagged (`<algo>:<hex hash>`). The hash family used
//! for a given variant is fixed at the variant level: X25519 uses
//! BLAKE2s-128. Future variants may pick a different hash family without
//! colliding because the algorithm tag prefix disambiguates the renderings.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::auth::X25519_PUBLIC_LEN;
use crate::error::Error;

/// Public key, tagged by algorithm. Wire serialisation uses a 1-byte
/// postcard discriminator; text serialisation uses `<algo>:<hex>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PubKey {
    /// X25519 — the only algorithm in v1.
    X25519([u8; X25519_PUBLIC_LEN]),
}

impl PubKey {
    /// Construct from raw X25519 bytes. Convenience constructor for the
    /// common case.
    ///
    /// # Examples
    ///
    /// ```
    /// use ratatoskr::pubkey::PubKey;
    /// let pk = PubKey::x25519([0x42; 32]);
    /// assert_eq!(pk.algorithm(), "x25519");
    /// assert_eq!(pk.raw_bytes().len(), 32);
    /// assert_eq!(pk.as_x25519(), Some(&[0x42; 32]));
    /// ```
    pub fn x25519(bytes: [u8; X25519_PUBLIC_LEN]) -> Self {
        Self::X25519(bytes)
    }

    /// Algorithm tag string (`"x25519"`, etc.).
    pub fn algorithm(&self) -> &'static str {
        match self {
            Self::X25519(_) => "x25519",
        }
    }

    /// Raw key bytes. For X25519 this is the 32-byte u-coordinate.
    pub fn raw_bytes(&self) -> &[u8] {
        match self {
            Self::X25519(b) => b.as_slice(),
        }
    }

    /// Return the X25519 bytes if this is an X25519 key. Returns `None` for
    /// any future variants.
    pub fn as_x25519(&self) -> Option<&[u8; X25519_PUBLIC_LEN]> {
        match self {
            Self::X25519(b) => Some(b),
        }
    }

    /// Short fingerprint, hex-encoded, suitable for voice/log display.
    /// Tagged with the algorithm prefix (`<algo>:<hex>`) so fingerprints
    /// across algorithms cannot collide and so the hash family used for
    /// each algorithm can vary without ambiguity.
    ///
    /// X25519 uses BLAKE2s-128 (16-byte hash, 32 hex chars).
    ///
    /// # Examples
    ///
    /// ```
    /// use ratatoskr::pubkey::PubKey;
    /// let fp = PubKey::x25519([0u8; 32]).fingerprint();
    /// // tagged form is "<algo>:<32 hex chars>" for X25519
    /// assert!(fp.starts_with("x25519:"));
    /// assert_eq!(fp.len(), "x25519:".len() + 32);
    /// ```
    pub fn fingerprint(&self) -> String {
        match self {
            Self::X25519(b) => format!("x25519:{}", x25519_fingerprint_hex(b)),
        }
    }
}

/// BLAKE2s-128 of an X25519 public key, rendered as 32 hex characters.
/// The hash-family choice is part of the X25519 variant's fingerprint
/// contract; new variants may pick a different hash family.
pub(crate) fn x25519_fingerprint_hex(public: &[u8; X25519_PUBLIC_LEN]) -> String {
    use blake2::digest::{consts::U16, Digest};
    type Blake2s128 = blake2::Blake2s<U16>;
    let mut hasher = Blake2s128::new();
    hasher.update(public);
    let out = hasher.finalize();
    hex::encode(out)
}

impl fmt::Display for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X25519(b) => write!(f, "x25519:{}", hex::encode(b)),
        }
    }
}

impl FromStr for PubKey {
    type Err = Error;

    /// Parse the tagged text form `<algo>:<hex>`. The only `<algo>`
    /// recognised in v1 is `x25519`; bare hex is rejected so operators
    /// cannot accidentally paste a key whose algorithm has changed.
    ///
    /// # Examples
    ///
    /// Roundtrip through `Display`:
    ///
    /// ```
    /// use ratatoskr::pubkey::PubKey;
    /// let original = PubKey::x25519([0xAB; 32]);
    /// let parsed: PubKey = original.to_string().parse().unwrap();
    /// assert_eq!(original, parsed);
    /// ```
    ///
    /// Untagged hex is rejected:
    ///
    /// ```
    /// use ratatoskr::pubkey::PubKey;
    /// let bare = "ab".repeat(32);
    /// assert!(bare.parse::<PubKey>().is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let (algo, hex_str) = s.split_once(':').ok_or_else(|| {
            Error::InvalidPubKey(format!("pubkey must be `<algorithm>:<hex>`, got {:?}", s))
        })?;
        match algo {
            "x25519" => {
                let bytes = hex::decode(hex_str)
                    .map_err(|e| Error::InvalidPubKey(format!("x25519 pubkey hex decode: {e}")))?;
                let arr: [u8; X25519_PUBLIC_LEN] = bytes.as_slice().try_into().map_err(|_| {
                    Error::InvalidPubKey(format!(
                        "x25519 pubkey must decode to {} bytes, got {}",
                        X25519_PUBLIC_LEN,
                        bytes.len()
                    ))
                })?;
                Ok(Self::X25519(arr))
            }
            other => Err(Error::InvalidPubKey(format!(
                "unknown pubkey algorithm {:?} (supported: x25519)",
                other
            ))),
        }
    }
}

impl Serialize for PubKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            // Binary form: postcard discriminator + raw bytes.
            // Use a derive-shaped enum via an internal helper so postcard
            // emits a stable 1-byte tag.
            #[derive(Serialize)]
            enum Binary<'a> {
                X25519(&'a [u8; X25519_PUBLIC_LEN]),
            }
            match self {
                Self::X25519(b) => Binary::X25519(b).serialize(serializer),
            }
        }
    }
}

impl<'de> Deserialize<'de> for PubKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            s.parse().map_err(serde::de::Error::custom)
        } else {
            #[derive(Deserialize)]
            enum Binary {
                X25519([u8; X25519_PUBLIC_LEN]),
            }
            match Binary::deserialize(deserializer)? {
                Binary::X25519(b) => Ok(Self::X25519(b)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_round_trip_text() {
        let key = PubKey::X25519([0x11; X25519_PUBLIC_LEN]);
        let s = key.to_string();
        assert!(s.starts_with("x25519:"));
        let parsed: PubKey = s.parse().unwrap();
        assert_eq!(parsed, key);
    }

    #[test]
    fn rejects_untagged_hex() {
        let raw = hex::encode([0x22; X25519_PUBLIC_LEN]);
        let err = raw.parse::<PubKey>().unwrap_err();
        assert!(matches!(err, Error::InvalidPubKey(s) if s.contains("<algorithm>:<hex>")));
    }

    #[test]
    fn rejects_unknown_algorithm() {
        let s = format!("blake3:{}", hex::encode([0x33; 32]));
        let err = s.parse::<PubKey>().unwrap_err();
        assert!(matches!(err, Error::InvalidPubKey(s) if s.contains("unknown pubkey algorithm")));
    }

    #[test]
    fn rejects_wrong_length_x25519() {
        let s = format!("x25519:{}", hex::encode([0x44; 16]));
        let err = s.parse::<PubKey>().unwrap_err();
        assert!(matches!(err, Error::InvalidPubKey(s) if s.contains("must decode to 32 bytes")));
    }

    #[test]
    fn trims_whitespace_on_parse() {
        let key = PubKey::X25519([0x55; X25519_PUBLIC_LEN]);
        let s = format!("\n  {key}  \n");
        assert_eq!(s.parse::<PubKey>().unwrap(), key);
    }

    #[test]
    fn fingerprint_includes_algorithm_prefix() {
        let key = PubKey::X25519([0x66; X25519_PUBLIC_LEN]);
        let fp = key.fingerprint();
        assert!(fp.starts_with("x25519:"));
        assert_eq!(fp.len(), "x25519:".len() + 32); // 16-byte hash = 32 hex chars
    }

    #[test]
    fn postcard_round_trip() {
        let key = PubKey::X25519([0x77; X25519_PUBLIC_LEN]);
        let bytes = postcard::to_stdvec(&key).unwrap();
        // 1-byte discriminator + 32 bytes raw = 33 bytes total.
        assert_eq!(bytes.len(), 33);
        assert_eq!(bytes[0], 0, "discriminator for X25519 must be 0");
        let decoded: PubKey = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, key);
    }

    #[test]
    fn json_round_trip() {
        let key = PubKey::X25519([0x88; X25519_PUBLIC_LEN]);
        let json = serde_json::to_string(&key).unwrap();
        assert!(json.contains("x25519:"));
        let decoded: PubKey = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, key);
    }

    #[test]
    fn raw_bytes_round_trip() {
        let key = PubKey::X25519([0x99; X25519_PUBLIC_LEN]);
        assert_eq!(key.raw_bytes(), &[0x99; X25519_PUBLIC_LEN]);
        assert_eq!(key.as_x25519().unwrap(), &[0x99; X25519_PUBLIC_LEN]);
        assert_eq!(key.algorithm(), "x25519");
    }
}
