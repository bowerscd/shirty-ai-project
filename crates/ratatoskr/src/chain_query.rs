//! `ChainSummary` recursive RPC over the chain control plane.
//!
//! The chain-summary fanout is a request/response pair that rides on
//! top of the [`crate::control_frame::ControlEnvelope`] transport:
//!
//! * [`ChainHopQuery`] is shipped downstream→upstream with
//!   [`ControlBodyType::ChainHopQuery`]. The receiver acks `Ok`
//!   immediately and asynchronously assembles its own
//!   [`crate::control::ChainHop`] plus, if it has its own upstream,
//!   recursively forwards a fresh query further up the chain.
//! * [`ChainHopReply`] is shipped back upstream→downstream with
//!   [`ControlBodyType::ChainHopReply`] once the receiver has either
//!   collected every reachable hop or the deadline expired. The
//!   `query_id` field correlates the reply with the original query so
//!   multiple concurrent walks on the same session don't collide.
//!
//! Wire shape (postcard-encoded body inside the Noise AEAD ciphertext):
//!
//! ```text
//! ChainHopQuery = { query_id: u32, depth_budget: u32, deadline_ms: u32 }
//! ChainHopReply = { query_id: u32, hops: Vec<ChainHop>, partial: bool, error: Option<String> }
//! ```
//!
//! Recursive semantics:
//! * `depth_budget` is decremented on every hop. A receiver with
//!   `depth_budget == 0` returns only its own local hop.
//! * `deadline_ms` is the time the *querier* is willing to wait, end
//!   to end. Each receiver subtracts its own forwarding overhead and
//!   passes the remainder to the next hop. On timeout the partial
//!   reply has `partial = true`.
//! * `query_id`s are local to each chain session: a forwarding relay
//!   allocates a fresh `query_id` when it forwards upstream, then
//!   maps the upstream reply back onto the downstream-side `query_id`
//!   it originally received.
//!
//! [`ControlBodyType::ChainHopQuery`]: crate::control_frame::ControlBodyType::ChainHopQuery
//! [`ControlBodyType::ChainHopReply`]: crate::control_frame::ControlBodyType::ChainHopReply

use serde::{Deserialize, Serialize};

use crate::control::ChainHop;

/// Hard cap on the postcard-encoded body length of a single
/// [`ChainHopReply`]. Each hop's `view: DerivedRulesResponse` can be
/// several KB in pathological cases (large rule sets, long predicate
/// vectors); we cap the aggregate so a single oversized reply can't
/// overrun the chain's [`crate::wire::MAX_CONTROL_PLAINTEXT_LEN`]
/// budget. Replies that exceed the cap are truncated to the local hop
/// and flagged `partial = true`.
pub const CHAIN_HOP_REPLY_MAX_WIRE_BYTES: usize = 16 * 1024;

/// Default cap on chain depth that a single query will traverse. The
/// querier may shrink this but the receiver always min's it against
/// its own ceiling to bound recursion in misbehaving topologies.
pub const CHAIN_HOP_DEFAULT_DEPTH_BUDGET: u32 = 16;

/// Default end-to-end deadline for a `ChainSummary` walk, in
/// milliseconds. The UDS dispatcher can override.
pub const CHAIN_HOP_DEFAULT_DEADLINE_MS: u32 = 5_000;

/// Body of a [`crate::control_frame::ControlBodyType::ChainHopQuery`]
/// envelope. Postcard-encoded into the envelope's `body` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainHopQuery {
    /// Sender-assigned correlation id. The receiver echoes it back in
    /// the matching [`ChainHopReply`].
    pub query_id: u32,
    /// Maximum number of additional hops the receiver is allowed to
    /// traverse upstream. A receiver decrements by 1 before forwarding;
    /// a receiver with `depth_budget == 0` returns only its local hop.
    pub depth_budget: u32,
    /// Remaining end-to-end deadline in milliseconds at the moment the
    /// query was put on the wire. Receivers subtract their own
    /// forwarding overhead before passing the remainder upstream.
    pub deadline_ms: u32,
}

/// Body of a [`crate::control_frame::ControlBodyType::ChainHopReply`]
/// envelope. Postcard-encoded into the envelope's `body` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainHopReply {
    /// Echoes [`ChainHopQuery::query_id`].
    pub query_id: u32,
    /// One entry per chain hop, ordered local-first (the responding
    /// hop is element 0, its upstream is element 1, etc).
    pub hops: Vec<ChainHop>,
    /// `true` when the walk did not reach the head of the chain
    /// (deadline expired, upstream hop was unreachable, depth budget
    /// exhausted, or the aggregate body would have exceeded
    /// [`CHAIN_HOP_REPLY_MAX_WIRE_BYTES`]). The CLI surfaces this in
    /// `Response::ChainSummary.partial`.
    pub partial: bool,
    /// Optional human-readable reason populated when `partial = true`.
    /// Never used for control-flow decisions; pure diagnostics.
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{ChainHop, ChainIdentity, DerivedRulesResponse, Mode};
    use crate::pubkey::PubKey;

    fn sample_hop() -> ChainHop {
        ChainHop {
            hop_index: 0,
            mode: Mode::Terminal,
            uptime_secs: 42,
            name: None,
            query_rtt_ms: None,
            view: DerivedRulesResponse {
                predicates: vec![],
                derived_rules: vec![],
                chain: ChainIdentity {
                    local: PubKey::X25519([1u8; 32]),
                    upstream: None,
                    downstream: None,
                    predicate_origin: None,
                    last_apply_unix: None,
                },
            },
        }
    }

    #[test]
    fn query_postcard_roundtrip() {
        let q = ChainHopQuery {
            query_id: 0xCAFEBABE,
            depth_budget: 16,
            deadline_ms: 5_000,
        };
        let bytes = postcard::to_allocvec(&q).unwrap();
        let back: ChainHopQuery = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(q, back);
    }

    #[test]
    fn reply_postcard_roundtrip_ok() {
        let r = ChainHopReply {
            query_id: 7,
            hops: vec![sample_hop()],
            partial: false,
            error: None,
        };
        let bytes = postcard::to_allocvec(&r).unwrap();
        let back: ChainHopReply = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn reply_postcard_roundtrip_partial_with_error() {
        let r = ChainHopReply {
            query_id: 7,
            hops: vec![sample_hop()],
            partial: true,
            error: Some("upstream timed out".into()),
        };
        let bytes = postcard::to_allocvec(&r).unwrap();
        let back: ChainHopReply = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn reply_cap_is_below_control_plaintext_budget() {
        // The reply needs to fit alongside ControlEnvelope framing
        // overhead inside MAX_CONTROL_PLAINTEXT_LEN.
        const _: () =
            assert!(CHAIN_HOP_REPLY_MAX_WIRE_BYTES < crate::wire::MAX_CONTROL_PLAINTEXT_LEN);
    }

    // ---- proptest roundtrip invariants ----

    use proptest::prelude::*;

    fn arb_query() -> impl Strategy<Value = ChainHopQuery> {
        (any::<u32>(), any::<u32>(), any::<u32>()).prop_map(
            |(query_id, depth_budget, deadline_ms)| ChainHopQuery {
                query_id,
                depth_budget,
                deadline_ms,
            },
        )
    }

    proptest! {
        #[test]
        fn proptest_query_postcard_roundtrip(q in arb_query()) {
            let bytes = postcard::to_allocvec(&q).unwrap();
            let back: ChainHopQuery = postcard::from_bytes(&bytes).unwrap();
            prop_assert_eq!(q, back);
        }
    }
}
