//! Per-rule arming table for `chain canary` probe traffic.
//!
//! When a canary command runs, every hop along the chain receives a
//! [`ratatoskr::canary::CanaryArm`] frame identifying the targeted rule
//! `(listen, protocol)` plus a random 32-byte token. Hops that own the
//! rule's terminating L4 listener (i.e. the terminal hop for that
//! rule) install an arm entry in their local [`CanaryArmTable`].
//!
//! The per-rule TCP/UDP listeners consult the table on each accept /
//! datagram and route probe traffic — distinguished from real client
//! traffic by the 32-byte token prefix — to an in-process echo
//! instead of the configured backend.
//!
//! ## Hot-path cost
//!
//! The cold path (no canary in flight, which is the steady state for
//! 99.999% of production traffic) is a single
//! [`dashmap::DashMap::get`] shard probe per accept / datagram. With
//! no entry for the rule's `(listen, protocol)`, `is_armed` returns
//! `false` and the listener proceeds straight to its normal
//! forwarding code. The cost is bounded by one atomic load and one
//! hash lookup; the table never accumulates entries because arming
//! is operator-triggered (`yggdrasilctl chain canary`) and self-evicts
//! by TTL.
//!
//! ## Lazy expiry
//!
//! Entries carry an absolute `Instant` deadline. Both `is_armed` and
//! `match_token` filter out expired entries during their read paths;
//! `arm` lazily purges expired entries for the inserted-into key.
//! [`purge_expired`](CanaryArmTable::purge_expired) sweeps the whole
//! map and is intended to be called by the daemon's periodic reaper
//! (the same task that already runs UDP flow-table eviction).
//!
//! ## Concurrency
//!
//! Multiple operators can run `chain canary` against the same rule
//! simultaneously: each command picks its own token and adds its own
//! entry. Token matching is exact-byte, so the listeners route each
//! probe to its respective in-process echo without interference.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use ratatoskr::canary::CANARY_TOKEN_LEN;
use ratatoskr::rule::Protocol;

/// One installed arm: a token + its absolute expiry.
#[derive(Debug, Clone, Copy)]
struct ArmEntry {
    token: [u8; CANARY_TOKEN_LEN],
    expires_at: Instant,
}

/// Per-rule arming table. Shared across the daemon as
/// `Arc<CanaryArmTable>` and consulted on every TCP accept and every
/// UDP frontend-worker recv.
///
/// Sharded by `(SocketAddr, Protocol)`. Each shard typically holds
/// zero entries (no canary in flight) or one (a single in-flight
/// canary against that rule); the `Vec` of entries accommodates rare
/// cases where multiple operators run `chain canary` against the
/// same rule simultaneously without one clobbering the other.
#[derive(Debug, Default)]
pub struct CanaryArmTable {
    arms: DashMap<(SocketAddr, Protocol), Vec<ArmEntry>>,
}

impl CanaryArmTable {
    /// Fresh empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// O(1) cold-path guard for hot listener code. Returns `true` iff
    /// at least one non-expired arm exists for `(listen, protocol)`.
    /// When this returns `false` the listener should skip the
    /// per-packet token check entirely.
    pub fn is_armed(&self, listen: SocketAddr, protocol: Protocol) -> bool {
        match self.arms.get(&(listen, protocol)) {
            Some(entries) => {
                let now = Instant::now();
                entries.iter().any(|e| e.expires_at > now)
            }
            None => false,
        }
    }

    /// Returns `true` iff `candidate` exactly matches a non-expired
    /// arm token for `(listen, protocol)`. Callers should gate this
    /// with [`is_armed`](Self::is_armed) so the byte comparison only
    /// runs when at least one arm is live.
    pub fn match_token(
        &self,
        listen: SocketAddr,
        protocol: Protocol,
        candidate: &[u8; CANARY_TOKEN_LEN],
    ) -> bool {
        match self.arms.get(&(listen, protocol)) {
            Some(entries) => {
                let now = Instant::now();
                entries
                    .iter()
                    .any(|e| e.expires_at > now && &e.token == candidate)
            }
            None => false,
        }
    }

    /// Install an arm for `(listen, protocol)` valid for `ttl`.
    /// Replacing an arm with the same token resets its expiry.
    pub fn arm(
        &self,
        listen: SocketAddr,
        protocol: Protocol,
        token: [u8; CANARY_TOKEN_LEN],
        ttl: Duration,
    ) {
        let expires_at = Instant::now() + ttl;
        let now = Instant::now();
        let mut entry = self.arms.entry((listen, protocol)).or_default();
        // Lazy-purge stale entries on each insertion. Bounds shard
        // memory without a dedicated reaper task, and keeps the
        // common "replace the existing arm with a new token" path
        // O(1) per shard.
        entry.retain(|e| e.expires_at > now);
        // Same-token replacement: refresh the expiry rather than
        // appending a duplicate entry.
        if let Some(slot) = entry.iter_mut().find(|e| e.token == token) {
            slot.expires_at = expires_at;
        } else {
            entry.push(ArmEntry { token, expires_at });
        }
    }

    /// Drop a specific token's arm if present. Used when the
    /// originator completes a canary cleanly so the entry doesn't
    /// linger until TTL.
    pub fn disarm(&self, listen: SocketAddr, protocol: Protocol, token: &[u8; CANARY_TOKEN_LEN]) {
        if let Some(mut entry) = self.arms.get_mut(&(listen, protocol)) {
            entry.retain(|e| &e.token != token);
            if entry.is_empty() {
                drop(entry);
                self.arms.remove(&(listen, protocol));
            }
        }
    }

    /// Sweep every shard, dropping expired arm entries and empty
    /// shard vectors. Idempotent. Cost is `O(total_arms)` and is
    /// expected to be called once per second or longer by the
    /// daemon's existing reaper task.
    pub fn purge_expired(&self) {
        let now = Instant::now();
        self.arms.retain(|_, entries| {
            entries.retain(|e| e.expires_at > now);
            !entries.is_empty()
        });
    }

    /// Total number of armed entries across all rules. Diagnostic /
    /// metric surface only — not used on the hot path.
    pub fn active_count(&self) -> usize {
        let now = Instant::now();
        self.arms
            .iter()
            .map(|shard| shard.iter().filter(|e| e.expires_at > now).count())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listen(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn token(seed: u8) -> [u8; CANARY_TOKEN_LEN] {
        [seed; CANARY_TOKEN_LEN]
    }

    #[test]
    fn cold_table_is_not_armed() {
        let table = CanaryArmTable::new();
        assert!(!table.is_armed(listen(2222), Protocol::Tcp));
        assert!(!table.match_token(listen(2222), Protocol::Tcp, &token(0)));
    }

    #[test]
    fn arm_then_match_succeeds() {
        let table = CanaryArmTable::new();
        let tok = token(0xAB);
        table.arm(listen(2222), Protocol::Tcp, tok, Duration::from_secs(5));
        assert!(table.is_armed(listen(2222), Protocol::Tcp));
        assert!(table.match_token(listen(2222), Protocol::Tcp, &tok));
    }

    #[test]
    fn unrelated_protocol_does_not_match() {
        let table = CanaryArmTable::new();
        table.arm(
            listen(2222),
            Protocol::Tcp,
            token(0xAB),
            Duration::from_secs(5),
        );
        assert!(!table.is_armed(listen(2222), Protocol::Udp));
    }

    #[test]
    fn unrelated_listen_does_not_match() {
        let table = CanaryArmTable::new();
        table.arm(
            listen(2222),
            Protocol::Tcp,
            token(0xAB),
            Duration::from_secs(5),
        );
        assert!(!table.is_armed(listen(3333), Protocol::Tcp));
    }

    #[test]
    fn wrong_token_does_not_match_but_is_armed_still_true() {
        let table = CanaryArmTable::new();
        table.arm(
            listen(2222),
            Protocol::Tcp,
            token(0xAB),
            Duration::from_secs(5),
        );
        assert!(table.is_armed(listen(2222), Protocol::Tcp));
        assert!(!table.match_token(listen(2222), Protocol::Tcp, &token(0xCD)));
    }

    #[test]
    fn expired_arm_is_no_longer_armed() {
        let table = CanaryArmTable::new();
        let tok = token(0xAB);
        table.arm(listen(2222), Protocol::Tcp, tok, Duration::from_millis(1));
        // Real-time TTL test: the table consults Instant::now() to
        // decide expiry; making this deterministic would require
        // injecting a Clock trait through CanaryArmTable. 10x slack
        // over the 1 ms TTL.
        std::thread::sleep(Duration::from_millis(10));
        assert!(!table.is_armed(listen(2222), Protocol::Tcp));
        assert!(!table.match_token(listen(2222), Protocol::Tcp, &tok));
    }

    #[test]
    fn multiple_concurrent_arms_on_same_rule_each_match() {
        let table = CanaryArmTable::new();
        let t1 = token(0x11);
        let t2 = token(0x22);
        table.arm(listen(2222), Protocol::Tcp, t1, Duration::from_secs(5));
        table.arm(listen(2222), Protocol::Tcp, t2, Duration::from_secs(5));
        assert!(table.match_token(listen(2222), Protocol::Tcp, &t1));
        assert!(table.match_token(listen(2222), Protocol::Tcp, &t2));
        // A third, unknown token must not match.
        assert!(!table.match_token(listen(2222), Protocol::Tcp, &token(0x33)));
    }

    #[test]
    fn same_token_reapplied_refreshes_ttl() {
        let table = CanaryArmTable::new();
        let tok = token(0xAB);
        table.arm(listen(2222), Protocol::Tcp, tok, Duration::from_millis(50));
        assert_eq!(table.active_count(), 1);
        // Re-arm with the same token; should NOT duplicate.
        table.arm(listen(2222), Protocol::Tcp, tok, Duration::from_secs(5));
        assert_eq!(table.active_count(), 1);
        // After the original short TTL would have expired, the
        // refreshed entry still matches. Real-time TTL test (see
        // expired_arm_is_no_longer_armed for why no Clock trait).
        std::thread::sleep(Duration::from_millis(100));
        assert!(table.match_token(listen(2222), Protocol::Tcp, &tok));
    }

    #[test]
    fn disarm_removes_specific_token_only() {
        let table = CanaryArmTable::new();
        let t1 = token(0x11);
        let t2 = token(0x22);
        table.arm(listen(2222), Protocol::Tcp, t1, Duration::from_secs(5));
        table.arm(listen(2222), Protocol::Tcp, t2, Duration::from_secs(5));
        table.disarm(listen(2222), Protocol::Tcp, &t1);
        assert!(!table.match_token(listen(2222), Protocol::Tcp, &t1));
        assert!(table.match_token(listen(2222), Protocol::Tcp, &t2));
        // Removing the last token clears the shard entry.
        table.disarm(listen(2222), Protocol::Tcp, &t2);
        assert!(!table.is_armed(listen(2222), Protocol::Tcp));
        assert_eq!(table.active_count(), 0);
    }

    #[test]
    fn purge_expired_clears_empty_shards() {
        let table = CanaryArmTable::new();
        table.arm(
            listen(2222),
            Protocol::Tcp,
            token(0x11),
            Duration::from_millis(1),
        );
        table.arm(
            listen(3333),
            Protocol::Udp,
            token(0x22),
            Duration::from_secs(5),
        );
        // Real-time TTL test; 10x slack on the 1 ms TTL of the first arm.
        std::thread::sleep(Duration::from_millis(10));
        table.purge_expired();
        assert!(!table.is_armed(listen(2222), Protocol::Tcp));
        assert!(table.is_armed(listen(3333), Protocol::Udp));
        assert_eq!(table.active_count(), 1);
    }

    #[test]
    fn arm_purges_stale_entries_on_insert() {
        let table = CanaryArmTable::new();
        // Install a soon-to-expire arm.
        table.arm(
            listen(2222),
            Protocol::Tcp,
            token(0x11),
            Duration::from_millis(1),
        );
        // Real-time TTL test; 10x slack on the 1 ms TTL.
        std::thread::sleep(Duration::from_millis(10));
        // Now install a fresh arm with a different token; the
        // existing stale entry must be cleaned up by the insert
        // path (no orphaned tokens piling up under a busy operator).
        table.arm(
            listen(2222),
            Protocol::Tcp,
            token(0x22),
            Duration::from_secs(5),
        );
        assert_eq!(table.active_count(), 1);
    }

    #[test]
    fn concurrent_arms_across_threads() {
        use std::sync::Arc;
        use std::thread;
        let table = Arc::new(CanaryArmTable::new());
        let mut handles = vec![];
        for i in 0u8..16 {
            let t = Arc::clone(&table);
            handles.push(thread::spawn(move || {
                t.arm(
                    listen(2222),
                    Protocol::Tcp,
                    token(i),
                    Duration::from_secs(5),
                );
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(table.active_count(), 16);
        for i in 0u8..16 {
            assert!(table.match_token(listen(2222), Protocol::Tcp, &token(i)));
        }
    }
}
