//! Phase 5B: `/internal/derived-rules` introspection state.
//!
//! [`IntrospectionState`] is a small, cheap-to-clone view that captures
//! everything the `/internal/derived-rules` HTTP endpoint needs to
//! render:
//!
//! * The latest [`PredicateSet`] this node has either *received* (relay)
//!   or *projected and pushed* (terminal). Held under a
//!   [`parking_lot::RwLock`] so the HTTP handler can read without
//!   contending with the predicate-recv / predicate-publish tasks.
//! * The active [`RuleSet`] — pulled from the [`SupervisorHandle`]'s
//!   `current_set` watch on every snapshot. Always up to date and
//!   guaranteed to be the set this node is currently *driving* (whether
//!   that was loaded from rules.toml on a terminal or derived from
//!   upstream predicates on a relay).
//! * Chain identity: local pubkey plus optional upstream / downstream
//!   pubkeys, copied at construction from
//!   [`crate::config::ChainSection`].
//! * `last_apply_unix` — wall-clock seconds at which `record_apply`
//!   last fired. Held in an [`AtomicI64`] so reads are lock-free; the
//!   value `0` means "no apply yet" and surfaces as JSON `null` in the
//!   snapshot.
//!
//! ## Wiring overview
//!
//! | Field | Who writes | Who reads |
//! |-|-|-|
//! | `latest_predicates` | [`crate::chain::ChainAcceptor::handle_predicate_set_update`] on a relay, [`crate::chain::predicate_publisher`] on a terminal | `/internal/derived-rules` HTTP handler |
//! | `last_apply_unix` | Same writers as above | Same reader |
//! | `derived_rules` (live) | Proxy supervisor | HTTP handler via `current_set_rx().borrow()` |
//! | `local_pubkey`, `upstream_pubkey`, `downstream_pubkey` | Constructor | HTTP handler |
//!
//! ## JSON shape
//!
//! ```json
//! {
//!   "predicates": [ { "name": ..., "listen_port": ..., "protocol": ..., "idle_timeout_ms": ... }, ... ],
//!   "derived_rules": [ ...Rule... ],
//!   "chain": {
//!     "local": "x25519:...",
//!     "upstream": "x25519:..." | null,
//!     "downstream": "x25519:..." | null,
//!     "predicate_origin": "x25519:..." | null,
//!     "predicate_version": 42 | null,
//!     "last_apply_unix": 1737244800 | null
//!   }
//! }
//! ```
//!
//! The `predicates` list and `chain.predicate_*` fields are siblings on
//! purpose: that keeps the predicate-set version + origin attached to
//! every snapshot without nesting an entire [`PredicateSet`] wrapper
//! inside `predicates` (the plan called for a flat array there).
//!
//! ## Security
//!
//! The endpoint exposes the operator's effective rule set, which can
//! leak hostnames + ports. The HTTP listener gates `/internal/*` paths
//! to loopback peers; non-loopback connections receive
//! [`hyper::StatusCode::FORBIDDEN`]. Operators reach the endpoint
//! through `yggdrasilctl chain tunnel open` rather than exposing the
//! metrics listener publicly.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use ratatoskr::predicate::{Predicate, PredicateSet};
use ratatoskr::pubkey::PubKey;
use ratatoskr::rule::Rule;
use serde::Serialize;

use crate::proxy::supervisor::SupervisorHandle;

/// Shared, thread-safe handle to chain-introspection state. Cloneable
/// `Arc` so any subsystem that wants to call [`record_apply`] can hold
/// its own pointer.
///
/// [`record_apply`]: IntrospectionState::record_apply
#[derive(Debug)]
pub struct IntrospectionState {
    local_pubkey: PubKey,
    upstream_pubkey: Option<PubKey>,
    downstream_pubkey: Option<PubKey>,
    supervisor: SupervisorHandle,
    latest_predicates: RwLock<Option<PredicateSet>>,
    /// Wall-clock seconds of last `record_apply`. `0` means "never".
    last_apply_unix: AtomicI64,
}

impl IntrospectionState {
    /// Construct an empty state. `record_apply` has not been called
    /// yet, so the first snapshot will show empty `predicates`, no
    /// `predicate_origin` / `predicate_version`, and `last_apply_unix
    /// = null`.
    pub fn new(
        local_pubkey: PubKey,
        upstream_pubkey: Option<PubKey>,
        downstream_pubkey: Option<PubKey>,
        supervisor: SupervisorHandle,
    ) -> Arc<Self> {
        Arc::new(Self {
            local_pubkey,
            upstream_pubkey,
            downstream_pubkey,
            supervisor,
            latest_predicates: RwLock::new(None),
            last_apply_unix: AtomicI64::new(0),
        })
    }

    /// Record that a new [`PredicateSet`] has been accepted. Called by
    /// the relay-side acceptor after the supervisor `apply_ruleset`
    /// succeeds, and by the terminal-side publisher after the upstream
    /// acks `Ok`. Both paths represent "this is the set my behaviour
    /// is now driven by", so the two writers share one slot.
    ///
    /// Replaces any prior set unconditionally — versioning is the
    /// upstream chain's concern; introspection only ever shows the
    /// *most recently applied* set.
    pub fn record_apply(&self, set: &PredicateSet) {
        *self.latest_predicates.write() = Some(set.clone());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.last_apply_unix.store(now, Ordering::Relaxed);
    }

    /// Build a snapshot of the current state. Performs at most one
    /// short read-lock acquire on `latest_predicates` and one cheap
    /// `watch::Receiver::borrow` clone on the supervisor's current
    /// rule set.
    pub fn snapshot(&self) -> IntrospectionSnapshot {
        let predicates_holder = self.latest_predicates.read();
        let (predicates, predicate_origin, predicate_version) =
            match predicates_holder.as_ref() {
                Some(p) => (
                    p.predicates.clone(),
                    Some(p.origin),
                    Some(p.version),
                ),
                None => (Vec::new(), None, None),
            };
        drop(predicates_holder);
        let last_apply_raw = self.last_apply_unix.load(Ordering::Relaxed);
        let last_apply_unix = if last_apply_raw > 0 {
            Some(last_apply_raw)
        } else {
            None
        };
        let derived_rules: Vec<Rule> = self
            .supervisor
            .current_set_rx()
            .borrow()
            .rules()
            .to_vec();
        IntrospectionSnapshot {
            predicates,
            derived_rules,
            chain: ChainSnapshot {
                local: self.local_pubkey,
                upstream: self.upstream_pubkey,
                downstream: self.downstream_pubkey,
                predicate_origin,
                predicate_version,
                last_apply_unix,
            },
        }
    }

    /// Render the snapshot to a pretty-printed JSON string suitable
    /// for direct HTTP response. Operator-facing output, not parsed
    /// by daemons, so pretty-printing is the right default.
    ///
    /// Returns `serde_json::Error` only on the (unreachable) path where
    /// a [`Rule`] or [`Predicate`] fails to serialise — both types
    /// derive `Serialize` from `String` + plain enums, so this is
    /// defence in depth.
    pub fn render_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.snapshot())
    }
}

/// Wire shape returned by the `/internal/derived-rules` endpoint.
/// See the module docstring for the canonical JSON shape.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct IntrospectionSnapshot {
    /// Predicate list this node is currently driven by. Terminal: the
    /// projection from the local rule set last pushed upstream. Relay:
    /// the set last received from downstream and used to derive
    /// `derived_rules`.
    pub predicates: Vec<Predicate>,
    /// Active rule set on this node. Always reflects the
    /// proxy supervisor's `current_set` watch at snapshot time.
    pub derived_rules: Vec<Rule>,
    pub chain: ChainSnapshot,
}

/// Chain-identity facts and predicate-set metadata.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ChainSnapshot {
    /// This node's static x25519 pubkey, tagged. Lets the operator's
    /// `chain diff` tooling confirm which node it actually reached
    /// through the tunnel.
    pub local: PubKey,
    /// Upstream node pubkey when `[chain.upstream]` is configured.
    pub upstream: Option<PubKey>,
    /// Downstream node pubkey when `[chain.downstream]` is configured.
    pub downstream: Option<PubKey>,
    /// `PredicateSet.origin` of the most recently applied push. On a
    /// terminal this equals `local`; on a relay it equals the terminal
    /// further down the chain that authored the predicate.
    pub predicate_origin: Option<PubKey>,
    /// `PredicateSet.version` of the most recently applied push.
    pub predicate_version: Option<u64>,
    /// Wall-clock seconds since UNIX epoch of the most recent
    /// `record_apply`. Null until the first push has been applied.
    pub last_apply_unix: Option<i64>,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ratatoskr::predicate::Predicate;
    use ratatoskr::rule::{Protocol, RuleSet};

    /// Build a fake [`SupervisorHandle`] for unit testing. Returns the
    /// handle plus the `watch::Sender` so the test can push updates to
    /// the `current_set` channel if needed.
    fn fake_supervisor_handle(
        rules: RuleSet,
    ) -> (SupervisorHandle, tokio::sync::watch::Sender<RuleSet>) {
        SupervisorHandle::__test_new(rules)
    }

    fn fake_pubkey(seed: u8) -> PubKey {
        PubKey::x25519([seed; 32])
    }

    fn rules_with_one() -> RuleSet {
        let rule = Rule {
            name: "echo-tcp".into(),
            listen: "0.0.0.0:9001".parse().unwrap(),
            protocol: Protocol::Tcp,
            target_port: None,
            target_addr: Some("127.0.0.1:9100".parse().unwrap()),
            target_host: None,
            idle_timeout: None,
            proxy_protocol: None,
            routes: None,
            cert_dir: None,
        };
        RuleSet::from_rules(vec![rule]).expect("RuleSet build")
    }

    #[test]
    fn snapshot_with_no_apply_returns_empty_predicates_and_null_metadata() {
        let (supervisor, _tx) = fake_supervisor_handle(rules_with_one());
        let state = IntrospectionState::new(
            fake_pubkey(0xAA),
            Some(fake_pubkey(0xBB)),
            None,
            supervisor,
        );
        let snap = state.snapshot();
        assert!(snap.predicates.is_empty(), "no apply → empty predicates");
        assert_eq!(snap.chain.local, fake_pubkey(0xAA));
        assert_eq!(snap.chain.upstream, Some(fake_pubkey(0xBB)));
        assert_eq!(snap.chain.downstream, None);
        assert_eq!(snap.chain.predicate_origin, None);
        assert_eq!(snap.chain.predicate_version, None);
        assert_eq!(snap.chain.last_apply_unix, None);
        assert_eq!(
            snap.derived_rules.len(),
            1,
            "derived_rules reflects the supervisor's current_set"
        );
    }

    #[test]
    fn record_apply_populates_predicates_and_last_apply_unix() {
        let (supervisor, _tx) = fake_supervisor_handle(RuleSet::default());
        let state = IntrospectionState::new(
            fake_pubkey(0x11),
            None,
            Some(fake_pubkey(0x22)),
            supervisor,
        );
        let set = PredicateSet {
            predicates: vec![Predicate {
                name: "echo-tcp".into(),
                listen_port: 9001,
                protocol: Protocol::Tcp,
                idle_timeout_ms: None,
            }],
            version: 7,
            origin: fake_pubkey(0xEE),
        };
        state.record_apply(&set);
        let snap = state.snapshot();
        assert_eq!(snap.predicates.len(), 1);
        assert_eq!(snap.predicates[0].name, "echo-tcp");
        assert_eq!(snap.chain.predicate_origin, Some(fake_pubkey(0xEE)));
        assert_eq!(snap.chain.predicate_version, Some(7));
        assert!(
            snap.chain.last_apply_unix.unwrap() > 0,
            "last_apply_unix should be a real wall-clock value"
        );
    }

    #[test]
    fn record_apply_overwrites_previous_set() {
        let (supervisor, _tx) = fake_supervisor_handle(RuleSet::default());
        let state = IntrospectionState::new(
            fake_pubkey(0x33),
            None,
            None,
            supervisor,
        );
        let v1 = PredicateSet {
            predicates: vec![],
            version: 1,
            origin: fake_pubkey(0xCC),
        };
        let v2 = PredicateSet {
            predicates: vec![Predicate {
                name: "echo-tcp".into(),
                listen_port: 9001,
                protocol: Protocol::Tcp,
                idle_timeout_ms: None,
            }],
            version: 2,
            origin: fake_pubkey(0xCC),
        };
        state.record_apply(&v1);
        state.record_apply(&v2);
        let snap = state.snapshot();
        assert_eq!(snap.chain.predicate_version, Some(2));
        assert_eq!(snap.predicates.len(), 1);
    }

    #[test]
    fn render_json_round_trips_through_serde() {
        let (supervisor, _tx) = fake_supervisor_handle(rules_with_one());
        let state = IntrospectionState::new(
            fake_pubkey(0x44),
            Some(fake_pubkey(0x55)),
            None,
            supervisor,
        );
        state.record_apply(&PredicateSet {
            predicates: vec![Predicate {
                name: "echo-tcp".into(),
                listen_port: 9001,
                protocol: Protocol::Tcp,
                idle_timeout_ms: Some(60_000),
            }],
            version: 42,
            origin: fake_pubkey(0xDD),
        });
        let json = state.render_json().expect("render_json");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("parse back");
        let chain = &parsed["chain"];
        assert_eq!(chain["predicate_version"], 42);
        assert!(chain["last_apply_unix"].as_i64().unwrap_or(0) > 0);
        assert_eq!(parsed["predicates"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["derived_rules"].as_array().unwrap().len(), 1);
    }
}
