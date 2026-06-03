//! Predicate-set wire schema.
//!
//! A **predicate** is the chain-invariant projection of a [`Rule`]: the
//! match-side fields a terminal advertises to its upstream so the upstream
//! can synthesise a derived rule that forwards toward the terminal. Target
//! fields (`target_port`, `target`) are deliberately absent — relays
//! resolve those locally from the heartbeat-discovered downstream peer
//! address.
//!
//! A [`PredicateSet`] is an origin-stamped bundle of predicates
//! pushed inside a [`ControlEnvelope`] body. The envelope's body type is
//! [`ControlBodyType::PredicateSetUpdate`]. Reject reasons use the codes
//! in [`predicate_reject`].
//!
//! ## Field deliberations
//!
//! The predicate shape is deliberately small:
//! * `name` is operator-facing; it must survive across the chain because
//!   `chain diff` and `chain trace` rely on stable identifiers.
//! * `listen_port` is chain-invariant; every node in the chain listens on
//!   the same port for traffic destined for this predicate.
//! * `protocol` matches the existing [`Rule::protocol`] field. `Tcp`,
//!   `Udp`, and `Https` predicates are emitted; HTTPS route and certificate
//!   material stays terminal-local.
//! * `idle_timeout_ms` is the per-rule UDP idle eviction window, captured
//!   as milliseconds so the wire format does not depend on
//!   `humantime_serde`. `None` means "use the daemon default".
//! * `https_http3` is HTTPS-only. It marks HTTPS predicates whose origin
//!   rule has HTTP/3 enabled so a downstream derive step can synthesize both
//!   TCP and UDP listeners for the same `listen_port`.
//!
//! [`Rule`]: crate::rule::Rule
//! [`Rule::protocol`]: crate::rule::Rule::protocol
//! [`ControlEnvelope`]: crate::control_frame::ControlEnvelope
//! [`ControlBodyType::PredicateSetUpdate`]: crate::control_frame::ControlBodyType::PredicateSetUpdate

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
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
    /// Transport protocol projected from the origin rule. HTTPS predicates
    /// carry only chain-invariant listener metadata; route and certificate
    /// material remains terminal-local.
    pub protocol: Protocol,
    /// UDP-only idle eviction window, in milliseconds. `None` means
    /// "use the daemon default". Ignored on TCP predicates.
    #[serde(default)]
    pub idle_timeout_ms: Option<u64>,
    /// HTTPS-only: when `true`, the origin's HTTPS rule has HTTP/3 enabled,
    /// so the consuming relay must derive both a `(Tcp, listen_port)` and a
    /// `(Udp, listen_port)` listener (the UDP one carries QUIC traffic). When
    /// `false`, only the TCP listener is derived.
    ///
    /// For [`Protocol::Tcp`] and [`Protocol::Udp`] predicates this field is
    /// meaningless and must be `false`; otherwise the consumer rejects the
    /// predicate with [`predicate_reject::INVALID_PREDICATE`].
    ///
    /// Wire-format note: postcard encodes this as a single byte (0 or 1),
    /// adding ~1 byte per predicate. With the 8 KiB cap at
    /// [`PREDICATE_SET_MAX_WIRE_BYTES`] the worst-case impact on the
    /// 50-predicate budget is negligible.
    #[serde(default)]
    pub https_http3: bool,
}

impl Predicate {
    /// Validate predicate-level invariants that are independent of relay-local
    /// derivation policy.
    pub fn validate(&self) -> Result<()> {
        if self.https_http3 && self.protocol != Protocol::Https {
            return Err(Error::InvalidPredicate(format!(
                "predicate {:?}: https_http3 is only valid with protocol https (got {})",
                self.name,
                self.protocol.as_str()
            )));
        }
        Ok(())
    }
}

/// A bundle of predicates pushed from a downstream toward its upstream.
///
/// # Examples
///
/// Round-trip a [`PredicateSet`] through postcard (the on-the-wire
/// encoding used by the chain control plane):
///
/// ```
/// use ratatoskr::predicate::{Predicate, PredicateSet};
/// use ratatoskr::pubkey::PubKey;
/// use ratatoskr::rule::Protocol;
///
/// let set = PredicateSet {
///     predicates: vec![Predicate {
///         name: "minecraft".into(),
///         listen_port: 25565,
///         protocol: Protocol::Tcp,
///         idle_timeout_ms: None,
///         https_http3: false,
///     }],
///     origin: PubKey::x25519([0x44; 32]),
/// };
/// let bytes = postcard::to_allocvec(&set).unwrap();
/// let decoded: PredicateSet = postcard::from_bytes(&bytes).unwrap();
/// assert_eq!(decoded, set);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredicateSet {
    /// Predicates owned by [`origin`]. The list is ordered by `name` (the
    /// extractor sorts the input set so wire bytes are deterministic across
    /// rebuilds of the same logical rules.toml).
    ///
    /// [`origin`]: PredicateSet::origin
    pub predicates: Vec<Predicate>,
    /// Pubkey of the node that authored this predicate set. Always a
    /// terminal: relays cannot author predicates, they only forward or
    /// derive them.
    pub origin: PubKey,
}

#[derive(Debug, Deserialize)]
struct LegacyPredicate {
    name: String,
    listen_port: u16,
    protocol: Protocol,
    #[serde(default)]
    idle_timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct LegacyPredicateSet {
    predicates: Vec<LegacyPredicate>,
    origin: PubKey,
}

impl LegacyPredicateSet {
    fn into_current(self) -> PredicateSet {
        PredicateSet {
            predicates: self
                .predicates
                .into_iter()
                .map(|p| Predicate {
                    name: p.name,
                    listen_port: p.listen_port,
                    protocol: p.protocol,
                    idle_timeout_ms: p.idle_timeout_ms,
                    https_http3: false,
                })
                .collect(),
            origin: self.origin,
        }
    }
}

impl PredicateSet {
    /// Decode a postcard-encoded predicate set and validate schema-level
    /// invariants before returning it to the caller.
    ///
    /// Accepts both the current shape and the legacy shape that predates
    /// [`Predicate::https_http3`], defaulting the missing field to `false`.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        match postcard::from_bytes::<Self>(bytes) {
            Ok(set) => {
                set.validate()?;
                Ok(set)
            }
            Err(current_err) => {
                let legacy: LegacyPredicateSet =
                    postcard::from_bytes(bytes).map_err(|_| current_err)?;
                let set = legacy.into_current();
                set.validate()?;
                Ok(set)
            }
        }
    }

    /// Validate every predicate in the set against schema-level invariants.
    pub fn validate(&self) -> Result<()> {
        for predicate in &self.predicates {
            predicate.validate()?;
        }
        Ok(())
    }
}

/// Reject reason codes carried by `AckStatus::Reject(u16)` in response to a
/// `PredicateSetUpdate`. Codes live in the range `100..200`; future body
/// types use disjoint ranges.
pub mod predicate_reject {
    /// The postcard-encoded `PredicateSet` exceeds the per-message size
    /// limit (the chain control plane runs over UDP; payloads larger than
    /// the limit cannot be carried by a single frame).
    pub const PREDICATE_SET_TOO_LARGE: u16 = 101;
    /// The predicate set fails relay-side validation: empty `name`,
    /// duplicate `name`, `listen_port == 0`, an HTTPS-only flag on a
    /// non-HTTPS predicate, or a predicate the receiver cannot derive.
    pub const INVALID_PREDICATE: u16 = 102;
    /// The predicate set violates the relay's `[chain.locked_predicates]`
    /// policy. Enforcement details are deferred; the reason code is
    /// reserved so the registry is stable from initial release onward.
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
    use crate::auth::X25519_PUBLIC_LEN;

    fn sample_origin() -> PubKey {
        PubKey::x25519([0x42u8; X25519_PUBLIC_LEN])
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
            https_http3: false,
        }
    }

    #[test]
    fn predicate_json_missing_https_http3_defaults_false() {
        let p: Predicate =
            serde_json::from_str(r#"{ "name": "web", "listen_port": 443, "protocol": "tcp" }"#)
                .unwrap();
        assert_eq!(p.name, "web");
        assert_eq!(p.listen_port, 443);
        assert_eq!(p.protocol, Protocol::Tcp);
        assert_eq!(p.idle_timeout_ms, None);
        assert!(!p.https_http3);
    }

    #[test]
    fn predicate_postcard_roundtrip_https_with_http3() {
        let mut p = sample_predicate("web", 443, Protocol::Https);
        p.https_http3 = true;
        let bytes = postcard::to_allocvec(&p).unwrap();
        let back: Predicate = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(p, back);
        assert!(back.https_http3);
    }

    #[test]
    fn predicate_postcard_roundtrip_tcp_without_http3() {
        let p = sample_predicate("ssh", 2222, Protocol::Tcp);
        let bytes = postcard::to_allocvec(&p).unwrap();
        let back: Predicate = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(p, back);
        assert!(!back.https_http3);
    }

    #[test]
    fn predicate_validate_rejects_http3_on_tcp() {
        let mut p = sample_predicate("ssh", 2222, Protocol::Tcp);
        p.https_http3 = true;
        let err = p.validate().unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidPredicate(msg)
                if msg == "predicate \"ssh\": https_http3 is only valid with protocol https (got tcp)"
        ));
    }

    #[test]
    fn predicate_validate_rejects_http3_on_udp() {
        let mut p = sample_predicate("dns", 53, Protocol::Udp);
        p.https_http3 = true;
        let err = p.validate().unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidPredicate(msg)
                if msg == "predicate \"dns\": https_http3 is only valid with protocol https (got udp)"
        ));
    }

    #[test]
    fn predicate_validate_allows_http3_false_on_any_protocol() {
        for protocol in [Protocol::Tcp, Protocol::Udp, Protocol::Https] {
            sample_predicate("rule", 443, protocol).validate().unwrap();
        }
    }

    #[test]
    fn predicate_validate_allows_http3_true_on_https() {
        let mut p = sample_predicate("web", 443, Protocol::Https);
        p.https_http3 = true;
        p.validate().unwrap();
    }

    #[test]
    fn predicate_set_validate_rejects_http3_on_non_https() {
        let mut p = sample_predicate("ssh", 2222, Protocol::Tcp);
        p.https_http3 = true;
        let set = PredicateSet {
            predicates: vec![p],
            origin: sample_origin(),
        };
        assert!(matches!(set.validate(), Err(Error::InvalidPredicate(_))));
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
            origin: sample_origin(),
        };
        let bytes = postcard::to_allocvec(&set).unwrap();
        let back: PredicateSet = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(set, back);
        assert_eq!(back.predicates.len(), 2);
    }

    #[test]
    fn predicate_set_postcard_roundtrip_mixed_http3() {
        let mut https = sample_predicate("web", 443, Protocol::Https);
        https.https_http3 = true;
        let set = PredicateSet {
            predicates: vec![sample_predicate("ssh", 2222, Protocol::Tcp), https],
            origin: sample_origin(),
        };
        let bytes = postcard::to_allocvec(&set).unwrap();
        let back: PredicateSet = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(set, back);
        assert!(back.predicates[1].https_http3);
    }

    #[derive(Serialize)]
    struct LegacyPredicate {
        name: String,
        listen_port: u16,
        protocol: Protocol,
        idle_timeout_ms: Option<u64>,
    }

    #[derive(Serialize)]
    struct LegacyPredicateSet {
        predicates: Vec<LegacyPredicate>,
        origin: PubKey,
    }

    #[test]
    fn old_json_predicate_set_shape_defaults_https_http3_false() {
        let legacy = LegacyPredicateSet {
            predicates: vec![LegacyPredicate {
                name: "legacy".into(),
                listen_port: 443,
                protocol: Protocol::Https,
                idle_timeout_ms: None,
            }],
            origin: sample_origin(),
        };
        let bytes = serde_json::to_vec(&legacy).unwrap();
        let back: PredicateSet = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.predicates.len(), 1);
        assert_eq!(back.predicates[0].name, "legacy");
        assert!(!back.predicates[0].https_http3);
    }

    #[test]
    fn old_postcard_predicate_set_shape_defaults_https_http3_false() {
        let legacy = LegacyPredicateSet {
            predicates: vec![LegacyPredicate {
                name: "legacy".into(),
                listen_port: 443,
                protocol: Protocol::Https,
                idle_timeout_ms: None,
            }],
            origin: sample_origin(),
        };
        let bytes = postcard::to_allocvec(&legacy).unwrap();
        let back = PredicateSet::from_wire_bytes(&bytes).unwrap();
        assert_eq!(back.predicates.len(), 1);
        assert_eq!(back.predicates[0].name, "legacy");
        assert!(!back.predicates[0].https_http3);
    }

    #[test]
    fn direct_postcard_decode_of_old_shape_documents_serde_limit() {
        let legacy = LegacyPredicateSet {
            predicates: vec![LegacyPredicate {
                name: "legacy".into(),
                listen_port: 443,
                protocol: Protocol::Https,
                idle_timeout_ms: None,
            }],
            origin: sample_origin(),
        };
        let bytes = postcard::to_allocvec(&legacy).unwrap();
        assert!(postcard::from_bytes::<PredicateSet>(&bytes).is_err());
    }

    #[test]
    fn predicate_set_from_wire_bytes_validates_http3_flag() {
        let mut p = sample_predicate("ssh", 2222, Protocol::Tcp);
        p.https_http3 = true;
        let set = PredicateSet {
            predicates: vec![p],
            origin: sample_origin(),
        };
        let bytes = postcard::to_allocvec(&set).unwrap();
        assert!(matches!(
            PredicateSet::from_wire_bytes(&bytes),
            Err(Error::InvalidPredicate(_))
        ));
    }

    #[test]
    fn empty_predicate_set_roundtrips() {
        let set = PredicateSet {
            predicates: vec![],
            origin: sample_origin(),
        };
        let bytes = postcard::to_allocvec(&set).unwrap();
        let back: PredicateSet = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(set, back);
    }

    #[test]
    fn reject_codes_are_stable() {
        // Pin the values so a future refactor can't silently shift them.
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
                    protocol: Protocol::Https,
                    idle_timeout_ms: None,
                    https_http3: true,
                })
                .collect(),
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

    // ---- proptest roundtrip invariants ----

    use proptest::prelude::*;

    fn arb_protocol() -> impl Strategy<Value = Protocol> {
        prop_oneof![
            Just(Protocol::Tcp),
            Just(Protocol::Udp),
            Just(Protocol::Https),
        ]
    }

    fn arb_pubkey() -> impl Strategy<Value = PubKey> {
        any::<[u8; 32]>().prop_map(PubKey::x25519)
    }

    fn arb_predicate() -> impl Strategy<Value = Predicate> {
        (
            "[a-z][a-z0-9_-]{0,30}",
            1u16..=u16::MAX,
            arb_protocol(),
            proptest::option::of(any::<u64>()),
            any::<bool>(),
        )
            .prop_map(
                |(name, listen_port, protocol, idle_timeout_ms, h3)| Predicate {
                    name,
                    listen_port,
                    protocol,
                    idle_timeout_ms,
                    // Constrain to inputs that satisfy Predicate::validate():
                    // https_http3 is only meaningful when protocol == Https.
                    https_http3: protocol == Protocol::Https && h3,
                },
            )
    }

    fn arb_predicate_set() -> impl Strategy<Value = PredicateSet> {
        (
            proptest::collection::vec(arb_predicate(), 0..10),
            arb_pubkey(),
        )
            .prop_map(|(predicates, origin)| PredicateSet { predicates, origin })
    }

    proptest! {
        #[test]
        fn proptest_predicate_postcard_roundtrip(p in arb_predicate()) {
            let bytes = postcard::to_allocvec(&p).unwrap();
            let back: Predicate = postcard::from_bytes(&bytes).unwrap();
            prop_assert_eq!(p, back);
        }

        #[test]
        fn proptest_predicate_set_postcard_roundtrip(set in arb_predicate_set()) {
            let bytes = postcard::to_allocvec(&set).unwrap();
            let back: PredicateSet = postcard::from_bytes(&bytes).unwrap();
            prop_assert_eq!(set, back);
        }
    }
}
