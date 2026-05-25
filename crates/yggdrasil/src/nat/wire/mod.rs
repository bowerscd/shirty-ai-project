//! Wire-format primitives shared by the PCP and NAT-PMP codecs.
//!
//! Both protocols listen on UDP port 5351 on the gateway. PCP messages
//! are 60 bytes (request) / 60+ bytes (response, ignoring options),
//! NAT-PMP messages are 12 bytes (request) / 12 or 16 bytes (response).
//! Everything is fixed-layout big-endian binary; no allocations, no
//! XML, no DOM.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

pub mod natpmp;
pub mod pcp;

/// UDP port both PCP and NAT-PMP gateways listen on.
pub const GATEWAY_PORT: u16 = 5351;

/// IANA protocol number for TCP, as used in PCP MAP requests.
pub const IP_PROTO_TCP: u8 = 6;

/// IANA protocol number for UDP, as used in PCP MAP requests.
pub const IP_PROTO_UDP: u8 = 17;

/// The kind of traffic to map. Translates to PCP's IANA protocol
/// number and to one of NAT-PMP's two map opcodes internally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MapProtocol {
    Tcp,
    Udp,
}

impl MapProtocol {
    pub const fn ip_proto(self) -> u8 {
        match self {
            MapProtocol::Tcp => IP_PROTO_TCP,
            MapProtocol::Udp => IP_PROTO_UDP,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            MapProtocol::Tcp => "tcp",
            MapProtocol::Udp => "udp",
        }
    }
}

/// Mapping lifetime sent on the wire. Clamped to a sane range so a
/// misconfiguration cannot ask the gateway to hold a port for years
/// (which most routers either silently truncate or reject).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifetime(u32);

impl Lifetime {
    /// Smallest lifetime we'll ever request. Below this, the renewal
    /// cadence would dominate the wire chatter for no benefit.
    pub const MIN_SECS: u32 = 120;
    /// Largest lifetime we'll ever request. RFC 6887 recommends not
    /// going beyond `60 * 60 * 24` (one day); larger values are
    /// commonly rejected with `MalformedRequest` on consumer routers.
    pub const MAX_SECS: u32 = 24 * 60 * 60;
    /// Sentinel for the "release the mapping" wire shape, defined by
    /// both protocols as a lifetime of zero.
    pub const RELEASE: Lifetime = Lifetime(0);

    /// Construct a lifetime clamped into the allowed range.
    pub fn bounded(secs: u32) -> Self {
        let clamped = secs.clamp(Self::MIN_SECS, Self::MAX_SECS);
        Self(clamped)
    }

    /// Build a release-sentinel lifetime (zero on the wire).
    pub const fn release() -> Self {
        Self::RELEASE
    }

    /// Raw seconds value as it will appear on the wire.
    pub const fn as_secs(self) -> u32 {
        self.0
    }

    /// As a `Duration`. Convenient for arithmetic against `Instant`s.
    pub fn as_duration(self) -> Duration {
        Duration::from_secs(self.0 as u64)
    }
}

impl From<Lifetime> for u32 {
    fn from(v: Lifetime) -> u32 {
        v.0
    }
}

/// Errors returned by either codec when parsing or constructing a
/// frame. The mapper translates these into metric labels and into the
/// `last_error` string surfaced in `Status`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    #[error("buffer too short: needed {needed} bytes, got {got}")]
    Truncated { needed: usize, got: usize },
    #[error("unexpected version on wire: {version}")]
    BadVersion { version: u8 },
    #[error("unexpected opcode on wire: {opcode:#04x}")]
    BadOpcode { opcode: u8 },
    #[error("response opcode high bit not set (expected response, got request)")]
    NotAResponse,
    #[error("nonce mismatch between request and response")]
    NonceMismatch,
    #[error("unrecognized result code: {0}")]
    UnknownResultCode(u16),
    #[error("PCP protocol error: {0:?}")]
    PcpError(pcp::PcpResultCode),
    #[error("NAT-PMP protocol error: {0:?}")]
    NatPmpError(natpmp::NatPmpResultCode),
    #[error("expected an IPv4-mapped IPv6 address, got {0}")]
    NotIpv4Mapped(Ipv6Addr),
}

/// Convert an `Ipv4Addr` into the IPv4-mapped-IPv6 form
/// (`::ffff:a.b.c.d`) that PCP uses for its address fields.
pub fn ipv4_to_mapped_v6(v4: Ipv4Addr) -> Ipv6Addr {
    v4.to_ipv6_mapped()
}

/// Inverse of [`ipv4_to_mapped_v6`]. Returns an error if the address
/// is not an IPv4-mapped IPv6 address (PCP allows native v6 in this
/// field but v1 is v4-only, so we treat that as a hard fail).
pub fn ipv6_mapped_to_v4(v6: Ipv6Addr) -> Result<Ipv4Addr, WireError> {
    v6.to_ipv4_mapped().ok_or(WireError::NotIpv4Mapped(v6))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifetime_clamps_into_range() {
        assert_eq!(Lifetime::bounded(0).as_secs(), Lifetime::MIN_SECS);
        assert_eq!(Lifetime::bounded(60).as_secs(), Lifetime::MIN_SECS);
        assert_eq!(Lifetime::bounded(7_200).as_secs(), 7_200);
        assert_eq!(Lifetime::bounded(u32::MAX).as_secs(), Lifetime::MAX_SECS);
    }

    #[test]
    fn release_lifetime_is_zero() {
        assert_eq!(Lifetime::release().as_secs(), 0);
    }

    #[test]
    fn ipv4_mapped_roundtrip() {
        let v4 = Ipv4Addr::new(192, 0, 2, 1);
        let v6 = ipv4_to_mapped_v6(v4);
        assert_eq!(ipv6_mapped_to_v4(v6).unwrap(), v4);
    }

    #[test]
    fn rejects_non_v4_mapped_address() {
        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert!(matches!(
            ipv6_mapped_to_v4(v6),
            Err(WireError::NotIpv4Mapped(_))
        ));
    }

    #[test]
    fn map_protocol_ip_proto_numbers() {
        assert_eq!(MapProtocol::Tcp.ip_proto(), 6);
        assert_eq!(MapProtocol::Udp.ip_proto(), 17);
    }
}
