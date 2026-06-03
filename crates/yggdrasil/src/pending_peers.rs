//! Pending-peer staging store for TOFU enrollment.
//!
//! When yggdrasil is running without an enrolled peer (`[accept]` not yet
//! configured), incoming `Handshake1`s are *not* accepted — but instead of
//! being silently dropped, the offered peer pubkey is recorded into a small
//! in-memory queue. The operator then runs `yggdrasilctl peer pending` to
//! inspect the queue and `yggdrasilctl peer approve <fingerprint>` to lift one
//! candidate into the main config.
//!
//! Pending candidates live in memory only; across daemon restart they are dropped and legitimate peers re-knock. This is the intended flow under the architectural vision — see `.github/copilot-instructions.md` "Terminal is authority, intermediaries are transport".
//!
//! The store is process-wide (held behind an `Arc<Mutex<…>>`). TOFU is a
//! control-plane event (rare), so contention is irrelevant.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use ratatoskr::control::PendingCandidate;
use ratatoskr::pubkey::PubKey;

/// In-memory record for one pending TOFU candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CandidateRecord {
    /// Tagged pubkey (`<algo>:<hex>`). Algorithm-agile.
    pubkey: PubKey,
    first_seen_unix_ms: u64,
    attempt_count: u64,
}

/// Thread-safe TOFU staging store.
pub struct PendingPeerStore {
    inner: Mutex<Vec<CandidateRecord>>,
}

impl PendingPeerStore {
    /// Initialise an empty in-memory pending-peer store.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Vec::new()),
        }
    }

    /// Record an unauthenticated `Handshake1` whose offered pubkey did not
    /// match the configured peer. If the same pubkey is already staged the
    /// `attempt_count` is bumped; otherwise a fresh entry is appended.
    pub fn record_candidate(&self, pubkey: PubKey) {
        let now_ms = current_unix_millis();
        let mut candidates = self.inner.lock().unwrap();
        if let Some(existing) = candidates.iter_mut().find(|c| c.pubkey == pubkey) {
            existing.attempt_count = existing.attempt_count.saturating_add(1);
        } else {
            candidates.push(CandidateRecord {
                pubkey,
                first_seen_unix_ms: now_ms,
                attempt_count: 1,
            });
        }
    }

    /// Snapshot of all staged candidates, in stable order. Fingerprints are
    /// recomputed from the stored pubkey on every call.
    pub fn list(&self) -> Vec<PendingCandidate> {
        let candidates = self.inner.lock().unwrap();
        candidates
            .iter()
            .map(|c| PendingCandidate {
                fingerprint: c.pubkey.fingerprint(),
                pubkey: c.pubkey,
                first_seen_unix_ms: c.first_seen_unix_ms,
                attempt_count: c.attempt_count,
            })
            .collect()
    }

    /// Pop the candidate matching `query`. The query may be a full
    /// fingerprint (with or without the `<algo>:` prefix) or any unique
    /// prefix of at least [`MIN_FINGERPRINT_PREFIX_LEN`] hex characters
    /// of the fingerprint's hex tail.
    ///
    /// Returns the resolved full fingerprint and decoded tagged
    /// [`PubKey`] on a unique match, [`ApproveOutcome::NotFound`] when no
    /// candidate's fingerprint starts with the query, or
    /// [`ApproveOutcome::Ambiguous`] with the list of full fingerprints
    /// that share it.
    pub fn approve(&self, query: &str) -> ApproveOutcome {
        let normalised = query.trim().to_ascii_lowercase();

        // Split into optional algorithm tag + hex tail.
        let (algo_filter, hex_tail) = match normalised.split_once(':') {
            Some((algo, hex)) => (Some(algo.to_string()), hex.to_string()),
            None => (None, normalised),
        };

        if hex_tail.len() < MIN_FINGERPRINT_PREFIX_LEN {
            return ApproveOutcome::PrefixTooShort {
                provided: hex_tail.len(),
                required: MIN_FINGERPRINT_PREFIX_LEN,
            };
        }
        if !hex_tail.chars().all(|c| c.is_ascii_hexdigit()) {
            return ApproveOutcome::NotFound;
        }

        let mut candidates = self.inner.lock().unwrap();
        let matches: Vec<usize> = candidates
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                let fp = c.pubkey.fingerprint();
                let (algo, tail) = fp
                    .split_once(':')
                    .expect("fingerprint always has algorithm prefix");
                if let Some(want_algo) = algo_filter.as_deref() {
                    if want_algo != algo {
                        return false;
                    }
                }
                tail.starts_with(&hex_tail)
            })
            .map(|(i, _)| i)
            .collect();

        match matches.as_slice() {
            [] => ApproveOutcome::NotFound,
            [idx] => {
                let removed = candidates.remove(*idx);
                let fingerprint = removed.pubkey.fingerprint();
                ApproveOutcome::Approved {
                    fingerprint,
                    key: removed.pubkey,
                }
            }
            many => ApproveOutcome::Ambiguous {
                matches: many
                    .iter()
                    .map(|i| candidates[*i].pubkey.fingerprint())
                    .collect(),
            },
        }
    }
}

impl Default for PendingPeerStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimum hex characters (in the fingerprint's hex tail, after any
/// `<algo>:` prefix) accepted by [`PendingPeerStore::approve`] when
/// resolving a fingerprint by prefix. Picked so that two random
/// fingerprints colliding on a prefix is implausible at any realistic
/// pending-queue size while still saving the operator from typing all
/// 32 hex characters of an X25519 BLAKE2s-128 fingerprint.
pub const MIN_FINGERPRINT_PREFIX_LEN: usize = 8;

/// Result of a fingerprint-prefix lookup against the pending store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApproveOutcome {
    /// Exactly one candidate matched the prefix; it has been popped from
    /// the queue. The full fingerprint and decoded tagged pubkey are
    /// returned for the caller to commit to config.
    Approved { fingerprint: String, key: PubKey },
    /// No staged candidate shares the prefix.
    NotFound,
    /// More than one candidate shares the prefix. The store is left
    /// untouched; the operator must re-run with a longer prefix.
    Ambiguous { matches: Vec<String> },
    /// The supplied prefix is shorter than [`MIN_FINGERPRINT_PREFIX_LEN`].
    PrefixTooShort { provided: usize, required: usize },
}

fn current_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(byte: u8) -> PubKey {
        PubKey::x25519([byte; 32])
    }

    #[test]
    fn new_store_is_empty() {
        let store = PendingPeerStore::new();
        assert!(store.list().is_empty());
    }

    #[test]
    fn recreated_store_is_empty_after_prior_candidate() {
        let store = PendingPeerStore::new();
        store.record_candidate(pk(7));
        assert_eq!(store.list().len(), 1);

        drop(store);

        let store = PendingPeerStore::new();
        assert!(store.list().is_empty());
    }

    #[test]
    fn record_then_list_round_trip_in_memory() {
        let store = PendingPeerStore::new();
        let key = pk(7);
        store.record_candidate(key);
        let list = store.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].pubkey, key);
        assert_eq!(list[0].attempt_count, 1);
        assert_eq!(list[0].fingerprint, key.fingerprint());
        assert!(list[0].fingerprint.starts_with("x25519:"));
    }

    #[test]
    fn repeated_record_bumps_attempt_count() {
        let store = PendingPeerStore::new();
        let key = pk(3);
        store.record_candidate(key);
        store.record_candidate(key);
        store.record_candidate(key);
        let list = store.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].attempt_count, 3);
    }

    #[test]
    fn approve_returns_key_and_removes_entry() {
        let store = PendingPeerStore::new();
        let k1 = pk(1);
        let k2 = pk(2);
        store.record_candidate(k1);
        store.record_candidate(k2);
        let fp1 = k1.fingerprint();
        match store.approve(&fp1) {
            ApproveOutcome::Approved { fingerprint, key } => {
                assert_eq!(fingerprint, fp1);
                assert_eq!(key, k1);
            }
            other => panic!("expected Approved, got {other:?}"),
        }
        let list = store.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].fingerprint, k2.fingerprint());
        // Double approve of the same fingerprint now yields NotFound.
        assert_eq!(store.approve(&fp1), ApproveOutcome::NotFound);
    }

    #[test]
    fn approve_unknown_fingerprint_returns_not_found() {
        let store = PendingPeerStore::new();
        assert_eq!(store.approve("deadbeef"), ApproveOutcome::NotFound);
    }

    #[test]
    fn approve_rejects_prefix_under_eight_chars() {
        let store = PendingPeerStore::new();
        store.record_candidate(pk(4));
        let fp = pk(4).fingerprint();
        // Take 7 hex chars of the tail (excluding the algorithm prefix).
        let tail = fp.split_once(':').unwrap().1;
        let short = &tail[..7];
        match store.approve(short) {
            ApproveOutcome::PrefixTooShort { provided, required } => {
                assert_eq!(provided, 7);
                assert_eq!(required, MIN_FINGERPRINT_PREFIX_LEN);
            }
            other => panic!("expected PrefixTooShort, got {other:?}"),
        }
        // Store is untouched.
        assert_eq!(store.list().len(), 1);
    }

    #[test]
    fn approve_resolves_unique_hex_tail_prefix() {
        let store = PendingPeerStore::new();
        let k = pk(9);
        store.record_candidate(k);
        let fp = k.fingerprint();
        let tail = fp.split_once(':').unwrap().1;
        let prefix = &tail[..MIN_FINGERPRINT_PREFIX_LEN];
        match store.approve(prefix) {
            ApproveOutcome::Approved { fingerprint, key } => {
                assert_eq!(fingerprint, fp);
                assert_eq!(key, k);
            }
            other => panic!("expected Approved, got {other:?}"),
        }
    }

    #[test]
    fn approve_resolves_unique_tagged_prefix() {
        let store = PendingPeerStore::new();
        let k = pk(0x10);
        store.record_candidate(k);
        let fp = k.fingerprint();
        let result = store.approve(&fp);
        match result {
            ApproveOutcome::Approved { fingerprint, key } => {
                assert_eq!(fingerprint, fp);
                assert_eq!(key, k);
            }
            other => panic!("expected Approved, got {other:?}"),
        }
    }

    #[test]
    fn approve_returns_ambiguous_when_two_candidates_share_prefix() {
        let store = PendingPeerStore::new();
        let k1 = PubKey::x25519([
            0x94, 0x44, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ]);
        let k2 = PubKey::x25519([
            0xc1, 0x83, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ]);
        let fp1 = k1.fingerprint();
        let fp2 = k2.fingerprint();
        let fp1_tail = fp1.split_once(':').unwrap().1;
        let fp2_tail = fp2.split_once(':').unwrap().1;
        let prefix = &fp1_tail[..MIN_FINGERPRINT_PREFIX_LEN];
        assert_eq!(prefix, &fp2_tail[..MIN_FINGERPRINT_PREFIX_LEN]);

        store.record_candidate(k1);
        store.record_candidate(k2);

        match store.approve(prefix) {
            ApproveOutcome::Ambiguous { matches } => {
                assert_eq!(matches, vec![fp1, fp2]);
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
        assert_eq!(store.list().len(), 2);
    }
}
