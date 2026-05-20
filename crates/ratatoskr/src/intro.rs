//! File-exclusive enrollment format.
//!
//! Two file types govern the bilateral enrollment handshake between an
//! upstream operator (U) and a downstream operator (D):
//!
//! 1. **intro.txt** — produced by D's `yggdrasilctl identity export-intro`.
//!    Contains D's pubkey, fingerprint, an optional human note, and the
//!    creation timestamp. Carries no secret material. Transferred
//!    out-of-band to U.
//!
//! 2. **invite.txt** — produced by U's
//!    `yggdrasilctl identity add-downstream --from intro.txt`. Echoes D's
//!    pubkey, declares U's own pubkey + endpoint, plus matching note +
//!    timestamp. U's own config is updated with `[accept]` as a
//!    side effect. Transferred back to D.
//!
//! On D's box, `yggdrasilctl identity add-upstream invite.txt` parses the
//! invite, verifies that `downstream_pubkey` matches D's local identity
//! (sanity check against a swapped file), and writes `[dial]`
//! into D's config.
//!
//! Both files are TOML; pubkeys are tagged (`x25519:<hex>`). No hex
//! transcription, no base64 paste-in. Operators verify fingerprints
//! out-of-band (voice, signal, etc.) before applying either file.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::pubkey::PubKey;

/// Current schema version for both intro and invite files. Bumped on
/// breaking format changes (e.g. adding required fields).
pub const FORMAT_VERSION: u32 = 1;

/// Contents of an `intro.txt` file. Produced by the downstream operator,
/// carries D's identity for the upstream operator to pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntroFile {
    pub intro: IntroBody,
}

/// Body of an intro.txt. Wrapped in `[intro]` so file consumers can grep
/// for the table name and humans can scan for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntroBody {
    /// Format version. Reject on mismatch.
    pub version: u32,
    /// Downstream node's pubkey. Tagged form (`x25519:<hex>`).
    pub pubkey: PubKey,
    /// Short fingerprint of the pubkey above. Always recomputed on parse;
    /// the field exists for human eyeball verification only and is checked
    /// for consistency on load.
    pub fingerprint: String,
    /// Unix epoch seconds when the intro was minted. Pure metadata.
    pub issued_at: i64,
    /// Optional human-readable note (e.g. "D box at 2026-05-18, signal contact").
    #[serde(default)]
    pub note: String,
}

/// Contents of an `invite.txt` file. Produced by the upstream operator
/// after consuming an intro, carries U's identity + endpoint plus an
/// echo of D's pubkey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteFile {
    pub invite: InviteBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteBody {
    /// Format version. Reject on mismatch.
    pub version: u32,
    /// Upstream node's pubkey. Tagged form.
    pub upstream_pubkey: PubKey,
    /// Upstream's short fingerprint. Sanity-checked on parse.
    pub upstream_fingerprint: String,
    /// Endpoint (host:port or [ipv6]:port) where downstream should dial
    /// the upstream's chain-control listener.
    pub upstream_endpoint: String,
    /// Echo of the downstream's pubkey from the consumed intro. Downstream
    /// MUST verify this matches its own local identity before applying.
    pub downstream_pubkey: PubKey,
    /// Echoed downstream fingerprint.
    pub downstream_fingerprint: String,
    /// Unix epoch seconds when the invite was minted.
    pub issued_at: i64,
    /// Optional human-readable note (e.g. "U operator, applied 2026-05-18").
    #[serde(default)]
    pub note: String,
}

impl IntroFile {
    /// Build a new intro file body from a pubkey, timestamp, and note.
    pub fn new(pubkey: PubKey, issued_at: i64, note: impl Into<String>) -> Self {
        let fingerprint = pubkey.fingerprint();
        Self {
            intro: IntroBody {
                version: FORMAT_VERSION,
                pubkey,
                fingerprint,
                issued_at,
                note: note.into(),
            },
        }
    }

    /// Serialize to TOML text.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| {
            Error::InvalidEnrollmentToken(format!("intro toml serialise: {e}"))
        })
    }

    /// Parse from TOML text, validating fingerprint consistency and version.
    pub fn from_toml(text: &str) -> Result<Self> {
        let f: IntroFile = toml::from_str(text).map_err(|e| Error::TomlParse {
            path: "<intro>".into(),
            source: e,
        })?;
        if f.intro.version != FORMAT_VERSION {
            return Err(Error::InvalidEnrollmentToken(format!(
                "intro version {} not supported (expected {FORMAT_VERSION})",
                f.intro.version
            )));
        }
        let expected = f.intro.pubkey.fingerprint();
        if expected != f.intro.fingerprint {
            return Err(Error::InvalidEnrollmentToken(format!(
                "intro fingerprint {} does not match pubkey (expected {})",
                f.intro.fingerprint, expected
            )));
        }
        Ok(f)
    }

    /// Read and parse an intro file from disk.
    pub fn read(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|source| Error::ReadFile {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml(&raw)
    }
}

impl InviteFile {
    /// Build a new invite from an intro and the upstream's own identity +
    /// endpoint.
    pub fn new(
        intro: &IntroFile,
        upstream_pubkey: PubKey,
        upstream_endpoint: impl Into<String>,
        issued_at: i64,
        note: impl Into<String>,
    ) -> Self {
        Self {
            invite: InviteBody {
                version: FORMAT_VERSION,
                upstream_pubkey,
                upstream_fingerprint: upstream_pubkey.fingerprint(),
                upstream_endpoint: upstream_endpoint.into(),
                downstream_pubkey: intro.intro.pubkey,
                downstream_fingerprint: intro.intro.pubkey.fingerprint(),
                issued_at,
                note: note.into(),
            },
        }
    }

    /// Serialize to TOML text.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| {
            Error::InvalidEnrollmentToken(format!("invite toml serialise: {e}"))
        })
    }

    /// Parse from TOML text. Validates both fingerprints and version.
    pub fn from_toml(text: &str) -> Result<Self> {
        let f: InviteFile = toml::from_str(text).map_err(|e| Error::TomlParse {
            path: "<invite>".into(),
            source: e,
        })?;
        if f.invite.version != FORMAT_VERSION {
            return Err(Error::InvalidEnrollmentToken(format!(
                "invite version {} not supported (expected {FORMAT_VERSION})",
                f.invite.version
            )));
        }
        let exp_u = f.invite.upstream_pubkey.fingerprint();
        if exp_u != f.invite.upstream_fingerprint {
            return Err(Error::InvalidEnrollmentToken(format!(
                "invite upstream_fingerprint {} does not match upstream_pubkey (expected {})",
                f.invite.upstream_fingerprint, exp_u
            )));
        }
        let exp_d = f.invite.downstream_pubkey.fingerprint();
        if exp_d != f.invite.downstream_fingerprint {
            return Err(Error::InvalidEnrollmentToken(format!(
                "invite downstream_fingerprint {} does not match downstream_pubkey (expected {})",
                f.invite.downstream_fingerprint, exp_d
            )));
        }
        if f.invite.upstream_endpoint.trim().is_empty() {
            return Err(Error::InvalidEnrollmentToken(
                "invite upstream_endpoint must not be empty".into(),
            ));
        }
        Ok(f)
    }

    /// Read and parse an invite from disk.
    pub fn read(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|source| Error::ReadFile {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml(&raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::PUBLIC_KEY_LEN;

    fn pk(byte: u8) -> PubKey {
        PubKey::X25519([byte; PUBLIC_KEY_LEN])
    }

    #[test]
    fn intro_round_trip() {
        let intro = IntroFile::new(pk(0x11), 1_700_000_000, "D operator");
        let toml = intro.to_toml().unwrap();
        assert!(toml.contains("[intro]"));
        assert!(toml.contains("x25519:"));
        let parsed = IntroFile::from_toml(&toml).unwrap();
        assert_eq!(parsed, intro);
    }

    #[test]
    fn intro_rejects_fingerprint_mismatch() {
        let intro = IntroFile::new(pk(0x22), 1, "");
        let mut bad = intro.to_toml().unwrap();
        bad = bad.replace(&intro.intro.fingerprint, "x25519:00112233445566778899aabbccddeeff");
        let err = IntroFile::from_toml(&bad).unwrap_err();
        assert!(matches!(err, Error::InvalidEnrollmentToken(s) if s.contains("does not match pubkey")));
    }

    #[test]
    fn intro_rejects_wrong_version() {
        let mut intro = IntroFile::new(pk(0x33), 1, "");
        intro.intro.version = 99;
        let toml = intro.to_toml().unwrap();
        let err = IntroFile::from_toml(&toml).unwrap_err();
        assert!(matches!(err, Error::InvalidEnrollmentToken(s) if s.contains("not supported")));
    }

    #[test]
    fn invite_round_trip() {
        let intro = IntroFile::new(pk(0x44), 1, "D");
        let invite = InviteFile::new(&intro, pk(0x55), "u.example.com:7117", 2, "U");
        let toml = invite.to_toml().unwrap();
        assert!(toml.contains("[invite]"));
        let parsed = InviteFile::from_toml(&toml).unwrap();
        assert_eq!(parsed, invite);
    }

    #[test]
    fn invite_carries_intro_pubkey() {
        let intro = IntroFile::new(pk(0x66), 1, "");
        let invite = InviteFile::new(&intro, pk(0x77), "host:1", 2, "");
        assert_eq!(invite.invite.downstream_pubkey, pk(0x66));
        assert_eq!(invite.invite.upstream_pubkey, pk(0x77));
    }

    #[test]
    fn invite_rejects_empty_endpoint() {
        let intro = IntroFile::new(pk(0x88), 1, "");
        let invite = InviteFile::new(&intro, pk(0x99), "", 2, "");
        let toml = invite.to_toml().unwrap();
        let err = InviteFile::from_toml(&toml).unwrap_err();
        assert!(matches!(err, Error::InvalidEnrollmentToken(s) if s.contains("upstream_endpoint must not be empty")));
    }

    #[test]
    fn invite_rejects_upstream_fingerprint_mismatch() {
        let intro = IntroFile::new(pk(0xAA), 1, "");
        let mut invite = InviteFile::new(&intro, pk(0xBB), "host:1", 2, "");
        invite.invite.upstream_fingerprint = "x25519:00".to_string();
        let toml = invite.to_toml().unwrap();
        let err = InviteFile::from_toml(&toml).unwrap_err();
        assert!(matches!(err, Error::InvalidEnrollmentToken(s) if s.contains("upstream_fingerprint")));
    }
}
