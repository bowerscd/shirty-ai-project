//! Pending-peer staging store for TOFU enrollment.
//!
//! When yggdrasil is running without an enrolled peer (`peer.public_key_hex`
//! empty), incoming `Handshake1`s are *not* accepted — but instead of being
//! silently dropped, the offered peer pubkey is recorded into a small
//! on-disk file under `state_dir/pending_peers.toml`. The operator then
//! runs `yggdrasilctl peer pending` to inspect the queue and
//! `yggdrasilctl peer approve <fingerprint>` to lift one candidate into
//! the main config.
//!
//! The store is process-wide (held behind an `Arc<Mutex<…>>`) and serialises
//! writes through an atomic tmp+rename pattern. The on-disk format is a
//! single TOML document:
//!
//! ```toml
//! [[candidates]]
//! fingerprint = "abcd…"
//! public_key_hex = "0102…"
//! first_seen_unix_ms = 1700000000000
//! attempt_count = 3
//! ```
//!
//! Concurrency: the mutex guards the in-memory state and the file write.
//! TOFU is a control-plane event (rare), so contention is irrelevant; the
//! mutex keeps the file consistent without a more elaborate dance.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use yggdrasil_proto::auth::{public_key_fingerprint, PUBLIC_KEY_LEN};
use yggdrasil_proto::control::PendingCandidate;

/// On-disk record for one pending TOFU candidate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CandidateRecord {
    fingerprint: String,
    public_key_hex: String,
    first_seen_unix_ms: u64,
    attempt_count: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Document {
    #[serde(default)]
    candidates: Vec<CandidateRecord>,
}

/// Thread-safe TOFU staging store.
pub struct PendingPeerStore {
    path: PathBuf,
    inner: Mutex<Document>,
}

impl PendingPeerStore {
    /// Load (or initialise) the store at `<state_dir>/pending_peers.toml`.
    /// A missing file is treated as an empty store. A malformed file is a
    /// hard error (operator action required).
    pub fn load(state_dir: impl AsRef<Path>) -> Result<Self> {
        let path = state_dir.as_ref().join("pending_peers.toml");
        let doc = if path.exists() {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            toml::from_str::<Document>(&text)
                .with_context(|| format!("parse {}", path.display()))?
        } else {
            Document::default()
        };
        Ok(Self {
            path,
            inner: Mutex::new(doc),
        })
    }

    /// Record an unauthenticated `Handshake1` whose offered pubkey did not
    /// match the configured peer. If the same fingerprint is already
    /// staged the `attempt_count` is bumped; otherwise a fresh entry is
    /// appended.
    pub fn record_candidate(&self, pubkey: [u8; PUBLIC_KEY_LEN]) -> Result<()> {
        let fingerprint = public_key_fingerprint(&pubkey);
        let now_ms = current_unix_millis();
        let mut guard = self.inner.lock().unwrap();
        if let Some(existing) = guard
            .candidates
            .iter_mut()
            .find(|c| c.fingerprint == fingerprint)
        {
            existing.attempt_count = existing.attempt_count.saturating_add(1);
        } else {
            guard.candidates.push(CandidateRecord {
                fingerprint,
                public_key_hex: hex::encode(pubkey),
                first_seen_unix_ms: now_ms,
                attempt_count: 1,
            });
        }
        write_atomic(&self.path, &guard)
    }

    /// Snapshot of all staged candidates, in stable order.
    pub fn list(&self) -> Vec<PendingCandidate> {
        let guard = self.inner.lock().unwrap();
        guard
            .candidates
            .iter()
            .map(|c| PendingCandidate {
                fingerprint: c.fingerprint.clone(),
                public_key_hex: c.public_key_hex.clone(),
                first_seen_unix_ms: c.first_seen_unix_ms,
                attempt_count: c.attempt_count,
            })
            .collect()
    }

    /// Pop the candidate matching `fingerprint`. Returns the decoded 32-byte
    /// public key on success, or `None` if no such fingerprint is staged.
    /// On success the store is persisted with that entry removed.
    pub fn approve(&self, fingerprint: &str) -> Result<Option<[u8; PUBLIC_KEY_LEN]>> {
        let mut guard = self.inner.lock().unwrap();
        let idx = match guard
            .candidates
            .iter()
            .position(|c| c.fingerprint == fingerprint)
        {
            Some(i) => i,
            None => return Ok(None),
        };
        let removed = guard.candidates.remove(idx);
        let bytes = hex::decode(&removed.public_key_hex)
            .with_context(|| format!("decode staged pubkey for {fingerprint}"))?;
        if bytes.len() != PUBLIC_KEY_LEN {
            anyhow::bail!(
                "staged pubkey for {fingerprint} has wrong length {} (want {PUBLIC_KEY_LEN})",
                bytes.len()
            );
        }
        let mut key = [0u8; PUBLIC_KEY_LEN];
        key.copy_from_slice(&bytes);
        write_atomic(&self.path, &guard)?;
        Ok(Some(key))
    }
}

fn current_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn write_atomic(path: &Path, doc: &Document) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
    }
    let text = toml::to_string_pretty(doc).context("serialise pending peers TOML")?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = PendingPeerStore::load(dir.path()).unwrap();
        assert!(store.list().is_empty());
    }

    #[test]
    fn record_then_list_round_trip_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let key = [7u8; PUBLIC_KEY_LEN];
        {
            let store = PendingPeerStore::load(dir.path()).unwrap();
            store.record_candidate(key).unwrap();
        }
        let store = PendingPeerStore::load(dir.path()).unwrap();
        let list = store.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].public_key_hex, hex::encode(key));
        assert_eq!(list[0].attempt_count, 1);
        assert_eq!(list[0].fingerprint, public_key_fingerprint(&key));
    }

    #[test]
    fn repeated_record_bumps_attempt_count() {
        let dir = tempfile::tempdir().unwrap();
        let store = PendingPeerStore::load(dir.path()).unwrap();
        let key = [3u8; PUBLIC_KEY_LEN];
        store.record_candidate(key).unwrap();
        store.record_candidate(key).unwrap();
        store.record_candidate(key).unwrap();
        let list = store.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].attempt_count, 3);
    }

    #[test]
    fn approve_returns_key_and_removes_entry() {
        let dir = tempfile::tempdir().unwrap();
        let store = PendingPeerStore::load(dir.path()).unwrap();
        let k1 = [1u8; PUBLIC_KEY_LEN];
        let k2 = [2u8; PUBLIC_KEY_LEN];
        store.record_candidate(k1).unwrap();
        store.record_candidate(k2).unwrap();
        let fp1 = public_key_fingerprint(&k1);
        let approved = store.approve(&fp1).unwrap();
        assert_eq!(approved, Some(k1));
        let list = store.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].fingerprint, public_key_fingerprint(&k2));
        // Double approve of the same fingerprint now yields None.
        assert_eq!(store.approve(&fp1).unwrap(), None);
    }

    #[test]
    fn approve_unknown_fingerprint_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let store = PendingPeerStore::load(dir.path()).unwrap();
        assert_eq!(store.approve("nope").unwrap(), None);
    }
}
