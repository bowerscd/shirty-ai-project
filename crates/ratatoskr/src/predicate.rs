//! Predicate-set wire schema.
//!
//! A **predicate** is the chain-invariant projection of a [`Rule`]: the
//! match-side fields a terminal advertises to its upstream so the upstream
//! can synthesise a derived rule that forwards toward the terminal. Target
//! fields (`upstream_port` / `upstream_addr` / `upstream_host`) are
//! deliberately absent — relays resolve those locally from the
//! heartbeat-discovered downstream peer address.
//!
//! A [`PredicateSet`] is a versioned, origin-stamped bundle of predicates
//! pushed inside a [`ControlEnvelope`] body. The envelope's body type is
//! [`ControlBodyType::PredicateSetUpdate`]. Reject reasons use the codes
//! in [`predicate_reject`].
//!
//! ## Field deliberations
//!
//! Phase 3 ships a deliberately small predicate shape:
//! * `name` is operator-facing; it must survive across the chain because
//!   `chain diff` and `chain trace` rely on stable identifiers.
//! * `listen_port` is chain-invariant; every node in the chain listens on
//!   the same port for traffic destined for this predicate.
//! * `protocol` matches the existing [`Rule::protocol`] field. Phase 3
//!   only emits `Tcp` and `Udp` predicates — `Https` is currently
//!   terminal-only and the extractor logs+drops `Https` rules.
//! * `idle_timeout_ms` is the per-rule UDP idle eviction window, captured
//!   as milliseconds so the wire format does not depend on
//!   `humantime_serde`. `None` means "use the daemon default".
//!
//! Additional predicate fields (SNI patterns, ALPN, source CIDRs, HTTPS
//! routes) are deliberately deferred — postcard's tagged-struct encoding
//! lets them be appended without breaking older parsers.
//!
//! [`Rule`]: crate::rule::Rule
//! [`Rule::protocol`]: crate::rule::Rule::protocol
//! [`ControlEnvelope`]: crate::control_frame::ControlEnvelope
//! [`ControlBodyType::PredicateSetUpdate`]: crate::control_frame::ControlBodyType::PredicateSetUpdate

use serde::{Deserialize, Serialize};

use crate::pubkey::PubKey;
use crate::rule::Protocol;

/// One predicate: the chain-invariant projection of a single [`Rule`].
///
/// [`Rule`]: crate::rule::Rule
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Predicate {
    /// Operator-facing name. Must be unique within a [`PredicateSet`].
    pub name: String,
    /// Non-zero TCP/UDP port on which every node in the chain listens for
    /// traffic destined for this predicate.
    pub listen_port: u16,
    /// Transport protocol. Phase 3 emits only [`Protocol::Tcp`] and
    /// [`Protocol::Udp`]; [`Protocol::Https`] is filtered out by the
    /// extractor.
    pub protocol: Protocol,
    /// UDP-only idle eviction window, in milliseconds. `None` means
    /// "use the daemon default". Ignored on TCP predicates.
    pub idle_timeout_ms: Option<u64>,
}

/// A versioned bundle of predicates pushed from a downstream toward its
/// upstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredicateSet {
    /// Predicates owned by [`origin`]. The list is ordered by `name` (the
    /// extractor sorts the input set so wire bytes are deterministic across
    /// rebuilds of the same logical rules.toml).
    ///
    /// [`origin`]: PredicateSet::origin
    pub predicates: Vec<Predicate>,
    /// Monotone version assigned by the origin node. Bumped on every push
    /// that follows a successful local rule reload. The receiver rejects
    /// pushes whose `version` is not strictly greater than the last
    /// accepted `version` from the same `origin`.
    pub version: u64,
    /// Pubkey of the node that authored this predicate set. Always a
    /// terminal in Phase 3 (relays cannot author predicates).
    pub origin: PubKey,
}

/// Reject reason codes carried by `AckStatus::Reject(u16)` in response to a
/// `PredicateSetUpdate`. Codes live in the range `100..200`; future body
/// types use disjoint ranges.
pub mod predicate_reject {
    /// The pushed `version` is not strictly greater than the receiver's
    /// last accepted `version` for the same `origin`. The receiver's state
    /// is already at-or-ahead.
    pub const VERSION_STALE: u16 = 100;
    /// The postcard-encoded `PredicateSet` exceeds the per-message size
    /// limit (the chain control plane runs over UDP; payloads larger than
    /// the limit cannot be carried by a single frame).
    pub const PREDICATE_SET_TOO_LARGE: u16 = 101;
    /// The predicate set fails relay-side validation: empty `name`,
    /// duplicate `name`, `listen_port == 0`, or `protocol = Https`
    /// (HTTPS predicates are deferred to a later phase).
    pub const INVALID_PREDICATE: u16 = 102;
    /// The predicate set violates the relay's `[chain.locked_predicates]`
    /// policy. Enforcement details are deferred; the reason code is
    /// reserved so the registry is stable from Phase 3 onward.
    pub const LOCKED_PREDICATES_VIOLATION: u16 = 103;
}

/// Soft cap on the postcard-encoded size of a [`PredicateSet`]. The chain
/// control plane carries each set inside a single Noise-protected UDP
/// frame; payloads larger than this are rejected with
/// [`predicate_reject::PREDICATE_SET_TOO_LARGE`].
///
/// 8 KiB comfortably fits a 50-predicate set with operator-friendly names
/// and stays well below typical link MTU after IPSec / Noise overhead.
/// Fragmentation is deferred — at the cap value, the extractor logs a
/// warning and the sender's reliability layer surfaces the reject to the
/// caller.
pub const PREDICATE_SET_MAX_WIRE_BYTES: usize = 8 * 1024;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::PUBLIC_KEY_LEN;

    fn sample_origin() -> PubKey {
        PubKey::x25519([0x42u8; PUBLIC_KEY_LEN])
    }

    fn sample_predicate(name: &str, port: u16, protocol: Protocol) -> Predicate {
        Predicate {
            name: name.to_string(),
            listen_port: port,
            protocol,
            idle_timeout_ms: match protocol {
                Protocol::Udp => Some(60_000),
                _ => None,
            },
        }
    }

    #[test]
    fn predicate_postcard_roundtrip_tcp() {
        let p = sample_predicate("ssh", 2222, Protocol::Tcp);
        let bytes = postcard::to_allocvec(&p).unwrap();
        let back: Predicate = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(p, back);
        assert_eq!(back.idle_timeout_ms, None);
    }

    #[test]
    fn predicate_postcard_roundtrip_udp_with_idle_timeout() {
        let p = sample_predicate("dns", 53, Protocol::Udp);
        let bytes = postcard::to_allocvec(&p).unwrap();
        let back: Predicate = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(p, back);
        assert_eq!(back.idle_timeout_ms, Some(60_000));
    }

    #[test]
    fn predicate_set_postcard_roundtrip() {
        let set = PredicateSet {
            predicates: vec![
                sample_predicate("dns", 53, Protocol::Udp),
                sample_predicate("ssh", 2222, Protocol::Tcp),
            ],
            version: 7,
            origin: sample_origin(),
        };
        let bytes = postcard::to_allocvec(&set).unwrap();
        let back: PredicateSet = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(set, back);
        assert_eq!(back.version, 7);
        assert_eq!(back.predicates.len(), 2);
    }

    #[test]
    fn empty_predicate_set_roundtrips() {
        let set = PredicateSet {
            predicates: vec![],
            version: 1,
            origin: sample_origin(),
        };
        let bytes = postcard::to_allocvec(&set).unwrap();
        let back: PredicateSet = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(set, back);
    }

    #[test]
    fn reject_codes_are_stable() {
        // Pin the values so a future refactor can't silently shift them.
        assert_eq!(predicate_reject::VERSION_STALE, 100);
        assert_eq!(predicate_reject::PREDICATE_SET_TOO_LARGE, 101);
        assert_eq!(predicate_reject::INVALID_PREDICATE, 102);
        assert_eq!(predicate_reject::LOCKED_PREDICATES_VIOLATION, 103);
    }

    #[test]
    fn predicate_set_max_wire_bytes_is_sane() {
        // A 50-predicate set with 24-char names + idle_timeout fits
        // comfortably under the cap. This guards against accidental
        // shrinkage that would break legitimate-sized terminals.
        let set = PredicateSet {
            predicates: (0..50)
                .map(|i| Predicate {
                    name: format!("predicate-with-a-quite-long-name-{i:03}"),
                    listen_port: 10_000 + i as u16,
                    protocol: Protocol::Udp,
                    idle_timeout_ms: Some(60_000),
                })
                .collect(),
            version: u64::MAX,
            origin: sample_origin(),
        };
        let bytes = postcard::to_allocvec(&set).unwrap();
        assert!(
            bytes.len() < PREDICATE_SET_MAX_WIRE_BYTES,
            "50-predicate set encoded to {} bytes; cap is {}",
            bytes.len(),
            PREDICATE_SET_MAX_WIRE_BYTES
        );
    }
}
