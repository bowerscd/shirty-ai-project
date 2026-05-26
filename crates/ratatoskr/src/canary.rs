//! `chain canary` recursive arming RPC over the chain control plane.
//!
//! The canary fanout is a request/response pair that rides on top of the
//! [`crate::control_frame::ControlEnvelope`] transport, mirroring the
//! `ChainHopQuery` / `ChainHopReply` shape:
//!
//! * [`CanaryArm`] is shipped downstream→upstream with
//!   [`crate::control_frame::ControlBodyType::CanaryArm`]. The receiver
//!   acks `Ok` immediately and asynchronously:
//!   1. Looks up its local rule for `(rule_listen, rule_protocol)`. If a
//!      matching rule exists and this node terminates the chain for it
//!      (i.e. the rule's listener will accept the probe's L4
//!      connection), the receiver installs an arm entry in its
//!      [`crate::canary`]-table keyed by the 32-byte `token` so that
//!      token-prefixed traffic at the rule's listener is short-circuited
//!      to an in-process echo instead of being forwarded to the
//!      configured backend.
//!   2. If the receiver has its own upstream, recursively forwards a
//!      fresh [`CanaryArm`] further up the chain. The local hop's view
//!      plus the upstream's reply hops are concatenated and returned.
//! * [`CanaryReply`] is shipped back upstream→downstream with
//!   [`crate::control_frame::ControlBodyType::CanaryReply`] once the
//!   receiver has either collected every reachable hop or the deadline
//!   expired. The `query_id` field correlates the reply with the
//!   original arming query so multiple concurrent canary commands on
//!   the same chain session don't collide.
//!
//! Wire shape (postcard-encoded body inside the Noise AEAD ciphertext):
//!
//! ```text
//! CanaryArm   = { query_id: u32, depth_budget: u32, deadline_ms: u32,
//!                 rule_listen: SocketAddr, rule_protocol: Protocol,
//!                 token: [u8; 32], expires_unix_ms: u64 }
//! CanaryReply = { query_id: u32, hops: Vec<CanaryHop>, partial: bool,
//!                 error: Option<String> }
//! CanaryHop   = { hop_index: u32, pubkey: PubKey, name: Option<String>,
//!                 mode: Mode, rule_present: bool, echo_armed: bool,
//!                 query_rtt_ms: Option<u64> }
//! ```
//!
//! Recursive semantics:
//! * `depth_budget` is decremented on every hop. A receiver with
//!   `depth_budget == 0` returns only its own local hop.
//! * `deadline_ms` is the time the *querier* is willing to wait, end to
//!   end. Each receiver subtracts its own forwarding overhead and
//!   passes the remainder to the next hop. On timeout the partial
//!   reply has `partial = true`.
//! * `query_id`s are local to each chain session: a forwarding relay
//!   allocates a fresh `query_id` when it forwards upstream, then maps
//!   the upstream reply back onto the downstream-side `query_id` it
//!   originally received.
//! * `expires_unix_ms` is the wall-clock deadline at which arm-table
//!   entries self-evict. Set by the originator to `now +
//!   probe_duration + grace`. Receivers may clamp to a local maximum
//!   to bound resource exposure.
//!
//! The token is 32 bytes of cryptographic randomness from the
//! originator's OS RNG. With 256 bits of entropy the false-positive
//! probability of an unrelated client connection accidentally matching
//! an active arm is negligible (2⁻²⁵⁶), and the arm-table cold path
//! (no active arm for a given `(listen, protocol)`) skips the prefix
//! check entirely so non-canary traffic pays no per-packet cost when
//! no canary is in flight.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::control::Mode;
use crate::pubkey::PubKey;
use crate::rule::Protocol;

/// Length in bytes of the arming token prefix.
pub const CANARY_TOKEN_LEN: usize = 32;

/// Hard cap on the postcard-encoded body length of a single
/// [`CanaryReply`]. Per-hop entries are small (a few hundred bytes
/// each — pubkey + name + booleans + small ints), so 4 KiB
/// comfortably accommodates a chain depth budget of 16 hops without
/// touching [`crate::wire::MAX_CONTROL_PLAINTEXT_LEN`]'s 17 KiB ceiling.
pub const CANARY_REPLY_MAX_WIRE_BYTES: usize = 4 * 1024;

/// Default cap on chain depth that a single canary arm will traverse.
pub const CANARY_ARM_DEFAULT_DEPTH_BUDGET: u32 = 16;

/// Default end-to-end deadline for a `CanaryArm` walk, in milliseconds.
/// The UDS dispatcher can override per command invocation.
pub const CANARY_ARM_DEFAULT_DEADLINE_MS: u32 = 5_000;

/// Body of a [`crate::control_frame::ControlBodyType::CanaryArm`]
/// envelope. Postcard-encoded into the envelope's `body` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryArm {
    /// Sender-assigned correlation id. The receiver echoes it back in
    /// the matching [`CanaryReply`].
    pub query_id: u32,
    /// Maximum number of additional hops the receiver is allowed to
    /// traverse upstream. A receiver decrements by 1 before forwarding;
    /// a receiver with `depth_budget == 0` returns only its local hop.
    pub depth_budget: u32,
    /// Remaining end-to-end deadline in milliseconds at the moment the
    /// query was put on the wire. Receivers subtract their own
    /// forwarding overhead before passing the remainder upstream.
    pub deadline_ms: u32,
    /// The rule's `(bind_addr, port)` to arm. Each hop matches this
    /// against its own rule set; if the receiver has a rule with a
    /// matching `listen`, it records `rule_present = true` in its hop
    /// entry. The terminal hop (rule owner) additionally installs the
    /// in-process echo intercept so token-prefixed probe traffic
    /// short-circuits.
    pub rule_listen: SocketAddr,
    /// L4 protocol of the rule to arm. HTTPS rules are not directly
    /// armed by this body — the CLI emits two separate canary commands
    /// (one for TCP/443, one for UDP/443) when targeting an HTTPS rule
    /// without an explicit `--proto`.
    pub rule_protocol: Protocol,
    /// 32 bytes of cryptographic randomness identifying this canary
    /// run. Probe traffic at the rule's listener that begins with these
    /// bytes is matched against the local arm table; matching traffic
    /// is echoed in-process at the terminal hop. Non-matching traffic
    /// is forwarded to the rule's configured backend.
    pub token: [u8; CANARY_TOKEN_LEN],
    /// Wall-clock deadline (Unix epoch milliseconds) at which arm
    /// entries on every hop must self-evict. Originators set this to
    /// `now + probe_duration_ms + grace_ms`. Receivers may clamp to
    /// a local maximum.
    pub expires_unix_ms: u64,
}

/// Body of a [`crate::control_frame::ControlBodyType::CanaryReply`]
/// envelope. Postcard-encoded into the envelope's `body` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryReply {
    /// Echoes [`CanaryArm::query_id`].
    pub query_id: u32,
    /// One entry per chain hop, ordered local-first (the responding
    /// hop is element 0, its upstream is element 1, …).
    pub hops: Vec<CanaryHop>,
    /// `true` when the walk did not reach the head of the chain
    /// (deadline expired, upstream hop was unreachable, depth budget
    /// exhausted, or the aggregate body would have exceeded
    /// [`CANARY_REPLY_MAX_WIRE_BYTES`]). The CLI surfaces this as the
    /// `CHAIN_DEAD` outcome.
    pub partial: bool,
    /// Optional human-readable reason populated when `partial = true`.
    /// Never used for control-flow decisions; pure diagnostics.
    pub error: Option<String>,
}

/// One hop's view of itself during a canary arm fanout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryHop {
    /// `0 = local`, `1 = local's upstream`, `2 = grandparent`, …
    pub hop_index: u32,
    /// Hop's X25519 pubkey. Always present so the renderer has a
    /// stable identifier even when no name is set.
    pub pubkey: PubKey,
    /// Hop's resolved `[server].name` (or hostname fallback). `None`
    /// when the hop omitted the field on its end (e.g. tests, or a
    /// future opt-out flag); renderers fall back to a short pubkey
    /// form in that case.
    #[serde(default)]
    pub name: Option<String>,
    /// Runtime mode (`gateway` / `relay` / `terminal`).
    pub mode: Mode,
    /// `true` when this hop's rule set contains a rule with `listen ==
    /// [CanaryArm::rule_listen]` and `protocol ==
    /// [CanaryArm::rule_protocol]`. False on hops where the rule has
    /// not been derived (e.g. a deeper relay whose downstream hasn't
    /// pushed a matching predicate set, or a hop with no matching
    /// rule at all).
    pub rule_present: bool,
    /// `true` only on the hop that installed the in-process echo
    /// intercept — the chain terminus for the targeted rule. The
    /// canary originator uses this to confirm that probe traffic
    /// will actually be looped back instead of forwarded to the
    /// rule's backend.
    pub echo_armed: bool,
    /// Wall-clock round-trip time, in milliseconds, that the *parent*
    /// hop measured for the upstream `CanaryArm` that produced this
    /// entry. `None` on the local hop (index 0 in any reply) and on
    /// hops further upstream not RTT-stamped by their parent.
    #[serde(default)]
    pub query_rtt_ms: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hop() -> CanaryHop {
        CanaryHop {
            hop_index: 0,
            pubkey: PubKey::X25519([0x11; 32]),
            name: Some("vps".into()),
            mode: Mode::Relay,
            rule_present: true,
            echo_armed: false,
            query_rtt_ms: None,
        }
    }

    #[test]
    fn arm_postcard_roundtrip() {
        let a = CanaryArm {
            query_id: 0xCAFE_BABE,
            depth_budget: 8,
            deadline_ms: 4_000,
            rule_listen: "0.0.0.0:2222".parse().unwrap(),
            rule_protocol: Protocol::Tcp,
            token: [0xAB; CANARY_TOKEN_LEN],
            expires_unix_ms: 1_700_000_000_000,
        };
        let bytes = postcard::to_allocvec(&a).unwrap();
        let back: CanaryArm = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn reply_postcard_roundtrip_ok() {
        let r = CanaryReply {
            query_id: 7,
            hops: vec![sample_hop()],
            partial: false,
            error: None,
        };
        let bytes = postcard::to_allocvec(&r).unwrap();
        let back: CanaryReply = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn reply_postcard_roundtrip_partial_with_error() {
        let r = CanaryReply {
            query_id: 9,
            hops: vec![sample_hop()],
            partial: true,
            error: Some("upstream timed out".into()),
        };
        let bytes = postcard::to_allocvec(&r).unwrap();
        let back: CanaryReply = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn hop_postcard_roundtrip_with_and_without_name() {
        let with = sample_hop();
        let without = CanaryHop {
            name: None,
            ..sample_hop()
        };
        for h in [with, without] {
            let bytes = postcard::to_allocvec(&h).unwrap();
            let back: CanaryHop = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(h, back);
        }
    }

    #[test]
    fn token_constant_matches_array_length() {
        // Guards against drift between the array size in `CanaryArm`
        // and the documented constant.
        let a = CanaryArm {
            query_id: 0,
            depth_budget: 0,
            deadline_ms: 0,
            rule_listen: "127.0.0.1:1".parse().unwrap(),
            rule_protocol: Protocol::Udp,
            token: [0; CANARY_TOKEN_LEN],
            expires_unix_ms: 0,
        };
        assert_eq!(a.token.len(), CANARY_TOKEN_LEN);
    }

    #[test]
    fn reply_cap_is_below_control_plaintext_budget() {
        const _: () = assert!(CANARY_REPLY_MAX_WIRE_BYTES < crate::wire::MAX_CONTROL_PLAINTEXT_LEN);
    }

    #[test]
    fn full_depth_reply_fits_under_cap() {
        // Pessimistic per-hop entry: maximum-length name (32 bytes),
        // worst-case pubkey serialisation, both Option<...> populated,
        // mode tag, three booleans, hop_index, query_rtt_ms.
        // Encoding 16 such entries plus the outer reply envelope must
        // fit under CANARY_REPLY_MAX_WIRE_BYTES.
        let max_name = "x".repeat(32);
        let hop = CanaryHop {
            hop_index: u32::MAX,
            pubkey: PubKey::X25519([0xFF; 32]),
            name: Some(max_name),
            mode: Mode::Relay,
            rule_present: true,
            echo_armed: true,
            query_rtt_ms: Some(u64::MAX),
        };
        let reply = CanaryReply {
            query_id: u32::MAX,
            hops: vec![hop; CANARY_ARM_DEFAULT_DEPTH_BUDGET as usize],
            partial: true,
            error: Some("x".repeat(128)),
        };
        let bytes = postcard::to_allocvec(&reply).unwrap();
        assert!(
            bytes.len() <= CANARY_REPLY_MAX_WIRE_BYTES,
            "encoded reply at full depth = {} bytes, exceeds cap {}",
            bytes.len(),
            CANARY_REPLY_MAX_WIRE_BYTES,
        );
    }
}
