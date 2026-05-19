//! Chain control plane.
//!
//! The chain is the directional spine of yggdrasil's deployment topology:
//! every node has at most one upstream (whom it dials and sends
//! heartbeats to) and at most one downstream (whom it accepts inbound
//! chain traffic from) in v1. Terminal nodes are chain leaves with only
//! an upstream; mid-chain relays have both; the root relay has only a
//! downstream.
//!
//! In Phase 1 the chain protocol on the wire is identical to the
//! pre-existing Noise_IK heartbeat protocol. Future phases extend the
//! tag space (TAG_CONTROL, TAG_CONTROL_ACK) for branch announcements,
//! TLS material distribution, and other control-plane traffic.
//!
//! Module layout:
//! * [`client`] — outbound side: dial upstream, run Noise_IK, send heartbeats.
//! * The inbound side (server) currently lives under [`crate::heartbeat`]
//!   and will be wrapped/moved here in a later phase. The migration is
//!   gated on the new tag space landing.

pub mod client;

pub use client::{ChainClient, ChainClientConfig};
