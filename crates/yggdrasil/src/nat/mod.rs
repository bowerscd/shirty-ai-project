//! NAT traversal subsystem.
//!
//! Hand-rolled PCP (RFC 6887) and NAT-PMP (RFC 6886) client used by
//! home-hosted yggdrasil deployments (standalone-terminal, gateway-at-
//! home, relay-at-home) to ask the residential router to forward inbound
//! traffic to the operator-declared rule listeners, the chain
//! `[accept].listen` socket, the HTTP→HTTPS redirect listener, and HTTP/3
//! UDP endpoints.
//!
//! UPnP-IGD is intentionally not implemented: SSDP multicast + SOAP/XML
//! is a values mismatch with the project's `#![forbid(unsafe_code)]`
//! and minimum-attack-surface posture. PCP is a fixed-size binary
//! protocol with mutual fate-sharing with the gateway via the `epoch`
//! field; NAT-PMP is even smaller and most consumer routers speak one or
//! the other. Auto mode tries PCP first and falls back to NAT-PMP per
//! RFC 6887 §9.
//!
//! The subsystem is opt-in via `[server].nat_traversal` (default
//! `"off"`). When off, no code in this module runs and no resources are
//! held.

pub mod discovery;
pub mod mapper;
pub mod wire;

pub use mapper::{
    compute_targets, ActiveMapping, MappingOrigin, MappingTarget, NatMapper, NatMapperHandle,
    NatMapperParams, NatProtocol, NatSnapshot, NatState,
};

use serde::{Deserialize, Serialize};

/// Selects the NAT-traversal protocol the daemon will try. Wired
/// from `[server].nat_traversal`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NatTraversalMode {
    /// No NAT traversal — the mapper is not spawned. Default.
    #[default]
    Off,
    /// PCP (RFC 6887) only. No fallback. Use when you know your
    /// gateway speaks PCP and don't want to leak fallback NAT-PMP
    /// requests on networks that don't.
    Pcp,
    /// NAT-PMP (RFC 6886) only. Use for older gateways that
    /// implement NAT-PMP but not PCP.
    NatPmp,
    /// PCP first, fall back to NAT-PMP on `UnsuppVersion` or socket
    /// timeout per RFC 6887 §9. Recommended default for unknown
    /// networks.
    Auto,
}

impl NatTraversalMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Pcp => "pcp",
            Self::NatPmp => "natpmp",
            Self::Auto => "auto",
        }
    }

    pub const fn is_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }
}
