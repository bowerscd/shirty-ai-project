//! Chain control plane.
//!
//! The chain is the directional spine of yggdrasil's deployment topology:
//! every node has at most one upstream (whom it dials and sends
//! heartbeats to) and at most one downstream (whom it accepts inbound
//! chain traffic from) in v1. Terminal nodes are chain leaves with only
//! an upstream; mid-chain relays have both; the root relay has only a
//! downstream.
//!
//! Module layout:
//! * [`client`] — outbound side: dial upstream, run Noise_IK, send heartbeats
//!   and control frames.
//! * [`reliability`] — per-session retransmit + dedup state machine that sits
//!   between the Noise transport and the body-type dispatcher.
//! * [`predicate_extractor`] — pure projection from a local [`RuleSet`] to a
//!   [`PredicateSet`] suitable for pushing upstream.
//! * [`predicate_publisher`] — terminal-side task: watches the supervisor's
//!   `current_set` channel and pushes successive [`PredicateSet`]s to the
//!   upstream via the chain client.
//! * [`derive`] — pure projection from a received [`PredicateSet`] back to a
//!   local [`RuleSet`] the relay can apply to its proxy supervisor.
//!
//! The inbound (server) side of chain traffic currently lives under
//! [`crate::heartbeat`] and will be wrapped/moved here in a later phase;
//! that move was deliberately deferred so this phase only adds the new
//! `TAG_CONTROL` / `TAG_CONTROL_ACK` dispatch arms without restructuring
//! the existing single-downstream session machinery.
//!
//! [`RuleSet`]: ratatoskr::rule::RuleSet
//! [`PredicateSet`]: ratatoskr::predicate::PredicateSet

pub mod client;
pub mod derive;
pub mod predicate_extractor;
pub mod predicate_publisher;
pub mod reliability;

pub use client::{
    BodyHandler, ChainClient, ChainClientConfig, ChainClientHandle, ChainClientShutDown,
    ControlOp,
};
pub use derive::{derive, DeriveConfig, DeriveError};
pub use predicate_extractor::{extract, ExtractOutcome};
pub use reliability::{ControlChannel, InboundDisposition, SendError};
