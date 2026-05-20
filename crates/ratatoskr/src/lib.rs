//! Shared protocol types and crypto for the yggdrasil chain control plane.
//!
//! This crate is the single source of truth for:
//! * rule (proxy-rule) configuration schema and parser
//! * the wire format and framing of control-plane packets (handshake,
//!   heartbeat, ack, rekey, control envelope, control ack)
//! * the authenticated session layer (Noise_IK over UDP) with replay protection
//! * the offline introduction / invite document format used for chain
//!   enrollment (see [`intro`])
//! * shared error types

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod auth;
pub mod chain_query;
pub mod control;
pub mod control_frame;
pub mod error;
pub mod intro;
pub mod predicate;
pub mod pubkey;
pub mod rule;
pub mod wire;

pub use error::{Error, Result};
