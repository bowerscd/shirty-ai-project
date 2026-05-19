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
//!
//! The inbound (server) side of chain traffic currently lives under
//! [`crate::heartbeat`] and will be wrapped/moved here in a later phase;
//! that move was deliberately deferred so this phase only adds the new
//! `TAG_CONTROL` / `TAG_CONTROL_ACK` dispatch arms without restructuring
//! the existing single-downstream session machinery.

pub mod client;
pub mod reliability;

pub use client::{
    BodyHandler, ChainClient, ChainClientConfig, ChainClientHandle, ChainClientShutDown,
    ControlOp,
};
pub use reliability::{ControlChannel, InboundDisposition, SendError};
