//! Shared protocol types and crypto for yggdrasil + huginn.
//!
//! This crate is the single source of truth for:
//! * rule (proxy-rule) configuration schema and parser
//! * the wire format and framing of control-plane packets (handshake, heartbeat, ack, rekey)
//! * the authenticated session layer (Noise_IK over UDP) with replay protection
//! * the out-of-band enrollment token format
//! * shared error types

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod auth;
pub mod control;
pub mod enrollment;
pub mod error;
pub mod intro;
pub mod pubkey;
pub mod rule;
pub mod wire;

pub use error::{Error, Result};
