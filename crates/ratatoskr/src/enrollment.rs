//! File-exclusive enrollment format.
//!
//! Two file types govern the bilateral enrollment handshake between the
//! requesting (`dial`-side) operator and the accepting (`accept`-side)
//! operator:
//!
//! 1. **request.txt** — produced by the dial-side via
//!    `yggdrasilctl identity export-request`. Contains the requester's
//!    pubkey, fingerprint, an optional human note, and the creation
//!    timestamp. Carries no secret material. Transferred out-of-band to
//!    the accept-side operator.
//!
//! 2. **grant.txt** — produced by the accept-side via
//!    `yggdrasilctl identity add-accept --from request.txt`. Echoes the
//!    requester's pubkey, declares the granter's own pubkey + endpoint,
//!    plus matching note + timestamp. The granter's own config is
//!    updated with `[accept]` as a side effect. Transferred back to the
//!    requester.
//!
//! On the requester's box, `yggdrasilctl identity add-dial --from
//! grant.txt` parses the grant, verifies that `dial_pubkey` matches the
//! local identity (sanity check against a swapped file), and writes
//! `[dial]` into the requester's config.
//!
//! Both files are TOML; pubkeys are tagged (`x25519:<hex>`). No hex
//! transcription, no base64 paste-in. Operators verify fingerprints
//! out-of-band (voice, signal, etc.) before applying either file.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::pubkey::PubKey;

/// Current schema version for both request and grant files. Bumped on
/// breaking format changes (e.g. adding required fields).
pub const FORMAT_VERSION: u32 = 1;

/// Contents of a `request.txt` file. Produced by the dial-side operator,
/// carries the requester's identity for the accept-side operator to pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestFile {
    pub request: RequestBody,
}

/// Body of a request.txt. Wrapped in `[request]` so file consumers can
/// grep for the table name and humans can scan for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestBody {
    /// Format version. Reject on mismatch.
    pub version: u32,
    /// Requester's (dial-side) pubkey. Tagged form (`x25519:<hex>`).
    pub pubkey: PubKey,
    /// Short fingerprint of the pubkey above. Always recomputed on parse;
    /// the field exists for human eyeball verification only and is checked
    /// for consistency on load.
    pub fingerprint: String,
    /// Unix epoch seconds when the request was minted. Pure metadata.
    pub issued_at: i64,
    /// Optional human-readable note (e.g. "D box at 2026-05-18, signal contact").
    #[serde(default)]
    pub note: String,
}

/// Contents of a `grant.txt` file. Produced by the accept-side operator
/// after consuming a request, carries the granter's identity + endpoint
/// plus an echo of the requester's pubkey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantFile {
    pub grant: GrantBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantBody {
    /// Format version. Reject on mismatch.
    pub version: u32,
    /// Accept-side node's pubkey (the granter). Tagged form.
    pub accept_pubkey: PubKey,
    /// Accept-side short fingerprint. Sanity-checked on parse.
    pub accept_fingerprint: String,
    /// Endpoint (host:port or [ipv6]:port) where the requester should dial
    /// the granter's chain-control listener.
    pub accept_endpoint: String,
    /// Echo of the requester's pubkey from the consumed request. The
    /// requester MUST verify this matches its own local identity before
    /// applying.
    pub dial_pubkey: PubKey,
    /// Echoed requester fingerprint.
    pub dial_fingerprint: String,
    /// Unix epoch seconds when the grant was minted.
    pub issued_at: i64,
    /// Optional human-readable note (e.g. "U operator, applied 2026-05-18").
    #[serde(default)]
    pub note: String,
}

impl RequestFile {
    /// Build a new request file body from a pubkey, timestamp, and note.
    ///
    /// # Examples
    ///
    /// Round-trip through TOML (`to_toml` / `from_toml`):
    ///
    /// ```
    /// use ratatoskr::enrollment::RequestFile;
    /// use ratatoskr::pubkey::PubKey;
    /// let req = RequestFile::new(
    ///     PubKey::x25519([0x33; 32]),
    ///     1_700_000_000,
    ///     "home box",
    /// );
    /// let toml = req.to_toml().unwrap();
    /// let parsed = RequestFile::from_toml(&toml).unwrap();
    /// assert_eq!(parsed.request.pubkey, PubKey::x25519([0x33; 32]));
    /// assert_eq!(parsed.request.note, "home box");
    /// ```
    pub fn new(pubkey: PubKey, issued_at: i64, note: impl Into<String>) -> Self {
        let fingerprint = pubkey.fingerprint();
        Self {
            request: RequestBody {
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
        toml::to_string_pretty(self)
            .map_err(|e| Error::InvalidEnrollmentToken(format!("request toml serialise: {e}")))
    }

    /// Parse from TOML text, validating fingerprint consistency and version.
    pub fn from_toml(text: &str) -> Result<Self> {
        let f: RequestFile = toml::from_str(text).map_err(|e| Error::TomlParse {
            path: "<request>".into(),
            source: e,
        })?;
        if f.request.version != FORMAT_VERSION {
            return Err(Error::InvalidEnrollmentToken(format!(
                "request version {} not supported (expected {FORMAT_VERSION})",
                f.request.version
            )));
        }
        let expected = f.request.pubkey.fingerprint();
        if expected != f.request.fingerprint {
            return Err(Error::InvalidEnrollmentToken(format!(
                "request fingerprint {} does not match pubkey (expected {})",
                f.request.fingerprint, expected
            )));
        }
        Ok(f)
    }

    /// Read and parse a request file from disk.
    pub fn read(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|source| Error::ReadFile {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml(&raw)
    }
}

impl GrantFile {
    /// Build a new grant from a request and the accept-side's own
    /// identity + endpoint.
    ///
    /// # Examples
    ///
    /// Mint a grant for a freshly-issued request, then round-trip the
    /// grant through TOML:
    ///
    /// ```
    /// use ratatoskr::enrollment::{GrantFile, RequestFile};
    /// use ratatoskr::pubkey::PubKey;
    ///
    /// let request = RequestFile::new(
    ///     PubKey::x25519([0x11; 32]),
    ///     1_700_000_000,
    ///     "home box",
    /// );
    /// let grant = GrantFile::new(
    ///     &request,
    ///     PubKey::x25519([0x22; 32]),
    ///     "vps.example.com:443",
    ///     1_700_000_100,
    ///     "approved",
    /// );
    /// let toml = grant.to_toml().unwrap();
    /// let parsed = GrantFile::from_toml(&toml).unwrap();
    /// assert_eq!(parsed.grant.accept_endpoint, "vps.example.com:443");
    /// // The grant carries the original requester's pubkey too.
    /// assert_eq!(parsed.grant.dial_pubkey, PubKey::x25519([0x11; 32]));
    /// ```
    pub fn new(
        request: &RequestFile,
        accept_pubkey: PubKey,
        accept_endpoint: impl Into<String>,
        issued_at: i64,
        note: impl Into<String>,
    ) -> Self {
        Self {
            grant: GrantBody {
                version: FORMAT_VERSION,
                accept_pubkey,
                accept_fingerprint: accept_pubkey.fingerprint(),
                accept_endpoint: accept_endpoint.into(),
                dial_pubkey: request.request.pubkey,
                dial_fingerprint: request.request.pubkey.fingerprint(),
                issued_at,
                note: note.into(),
            },
        }
    }

    /// Serialize to TOML text.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self)
            .map_err(|e| Error::InvalidEnrollmentToken(format!("grant toml serialise: {e}")))
    }

    /// Parse from TOML text. Validates both fingerprints and version.
    pub fn from_toml(text: &str) -> Result<Self> {
        let f: GrantFile = toml::from_str(text).map_err(|e| Error::TomlParse {
            path: "<grant>".into(),
            source: e,
        })?;
        if f.grant.version != FORMAT_VERSION {
            return Err(Error::InvalidEnrollmentToken(format!(
                "grant version {} not supported (expected {FORMAT_VERSION})",
                f.grant.version
            )));
        }
        let exp_a = f.grant.accept_pubkey.fingerprint();
        if exp_a != f.grant.accept_fingerprint {
            return Err(Error::InvalidEnrollmentToken(format!(
                "grant accept_fingerprint {} does not match accept_pubkey (expected {})",
                f.grant.accept_fingerprint, exp_a
            )));
        }
        let exp_d = f.grant.dial_pubkey.fingerprint();
        if exp_d != f.grant.dial_fingerprint {
            return Err(Error::InvalidEnrollmentToken(format!(
                "grant dial_fingerprint {} does not match dial_pubkey (expected {})",
                f.grant.dial_fingerprint, exp_d
            )));
        }
        if f.grant.accept_endpoint.trim().is_empty() {
            return Err(Error::InvalidEnrollmentToken(
                "grant accept_endpoint must not be empty".into(),
            ));
        }
        Ok(f)
    }

    /// Read and parse a grant from disk.
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
    fn request_round_trip() {
        let req = RequestFile::new(pk(0x11), 1_700_000_000, "D operator");
        let toml = req.to_toml().unwrap();
        assert!(toml.contains("[request]"));
        assert!(toml.contains("x25519:"));
        let parsed = RequestFile::from_toml(&toml).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn request_rejects_fingerprint_mismatch() {
        let req = RequestFile::new(pk(0x22), 1, "");
        let mut bad = req.to_toml().unwrap();
        bad = bad.replace(
            &req.request.fingerprint,
            "x25519:00112233445566778899aabbccddeeff",
        );
        let err = RequestFile::from_toml(&bad).unwrap_err();
        assert!(
            matches!(err, Error::InvalidEnrollmentToken(s) if s.contains("does not match pubkey"))
        );
    }

    #[test]
    fn request_rejects_wrong_version() {
        let mut req = RequestFile::new(pk(0x33), 1, "");
        req.request.version = 99;
        let toml = req.to_toml().unwrap();
        let err = RequestFile::from_toml(&toml).unwrap_err();
        assert!(matches!(err, Error::InvalidEnrollmentToken(s) if s.contains("not supported")));
    }

    #[test]
    fn grant_round_trip() {
        let req = RequestFile::new(pk(0x44), 1, "D");
        let grant = GrantFile::new(&req, pk(0x55), "u.example.com:7117", 2, "U");
        let toml = grant.to_toml().unwrap();
        assert!(toml.contains("[grant]"));
        let parsed = GrantFile::from_toml(&toml).unwrap();
        assert_eq!(parsed, grant);
    }

    #[test]
    fn grant_carries_request_pubkey() {
        let req = RequestFile::new(pk(0x66), 1, "");
        let grant = GrantFile::new(&req, pk(0x77), "host:1", 2, "");
        assert_eq!(grant.grant.dial_pubkey, pk(0x66));
        assert_eq!(grant.grant.accept_pubkey, pk(0x77));
    }

    #[test]
    fn grant_rejects_empty_endpoint() {
        let req = RequestFile::new(pk(0x88), 1, "");
        let grant = GrantFile::new(&req, pk(0x99), "", 2, "");
        let toml = grant.to_toml().unwrap();
        let err = GrantFile::from_toml(&toml).unwrap_err();
        assert!(
            matches!(err, Error::InvalidEnrollmentToken(s) if s.contains("accept_endpoint must not be empty"))
        );
    }

    #[test]
    fn grant_rejects_accept_fingerprint_mismatch() {
        let req = RequestFile::new(pk(0xAA), 1, "");
        let mut grant = GrantFile::new(&req, pk(0xBB), "host:1", 2, "");
        grant.grant.accept_fingerprint = "x25519:00".to_string();
        let toml = grant.to_toml().unwrap();
        let err = GrantFile::from_toml(&toml).unwrap_err();
        assert!(
            matches!(err, Error::InvalidEnrollmentToken(s) if s.contains("accept_fingerprint"))
        );
    }
}
