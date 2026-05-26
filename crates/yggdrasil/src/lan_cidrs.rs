//! LAN-CIDR set used by the per-IP companion listener to gate cert-less
//! HTTPS route serving by peer IP.
//!
//! ## Why this exists
//!
//! Cert-less HTTPS routes (a `[[rule.route]]` with no resolvable cert
//! source) live only on the per-IP companion listener's `:80` plaintext
//! path. To prevent a WAN attacker who reaches `:80` directly from
//! forging a `Host` header and proxying to internal backends, the
//! plaintext branch checks the inbound TCP peer's IP against an
//! "is this a private/LAN address?" set.
//!
//! ## Default set
//!
//! The default set is the union of well-known private-addressing
//! ranges, each cited to an RFC:
//!
//! | CIDR              | Purpose                          | RFC                  |
//! | ----------------- | -------------------------------- | -------------------- |
//! | `127.0.0.0/8`     | IPv4 loopback                    | RFC 1122 §3.2.1.3    |
//! | `10.0.0.0/8`      | RFC 1918 private IPv4 (class A)  | RFC 1918             |
//! | `172.16.0.0/12`   | RFC 1918 private IPv4 (class B)  | RFC 1918             |
//! | `192.168.0.0/16`  | RFC 1918 private IPv4 (class C)  | RFC 1918             |
//! | `::1/128`         | IPv6 loopback                    | RFC 4291 §2.5.3      |
//! | `fc00::/7`        | IPv6 Unique Local Addresses      | RFC 4193             |
//!
//! Deliberately excluded by default (operator opt-in via
//! [`crate::config::ServerSection::lan_cidrs`]):
//!
//! * `169.254.0.0/16` / `fe80::/10` — link-local; interface-scoped, rarely
//!   what an operator wants to call "LAN".
//! * `100.64.0.0/10` — CGNAT (RFC 6598); used by residential ISPs for cell
//!   carriers and by Tailscale. Off by default to avoid surprising
//!   operators.
//!
//! ## Why a *static* set instead of interface introspection
//!
//! A previous design attempted to introspect the host's network interface
//! CIDRs at startup. That works on bare metal but breaks in containerised
//! deployments: a yggdrasil container on a user-defined bridge network
//! only sees the bridge subnet (e.g. `192.168.156.0/24`) as its interface
//! CIDR — the actual home LAN subnet (e.g. `192.168.1.0/24`) is *not*
//! visible to the container, so introspection would deny real LAN
//! clients.
//!
//! Linux's default Docker shape *does* preserve source IPs across the
//! bridge: inbound traffic to a published port hits the kernel's
//! `PREROUTING DOCKER` chain DNAT before docker-proxy gets involved, so
//! the container sees the real source IP. (See the iptables-rule analysis
//! at <https://blog.ipspace.net/kb/DockerSvc/30-nat-iptables/>.) The
//! peer-IP filter therefore works correctly with the static "is this a
//! private-range IP?" criterion regardless of the daemon's network
//! namespace.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use thiserror::Error;

/// One CIDR entry in a [`LanCidrs`] set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

#[derive(Debug, Error)]
pub enum CidrParseError {
    #[error("CIDR must contain a '/' (got {input:?})")]
    MissingSlash { input: String },
    #[error("invalid IP address in CIDR {input:?}: {detail}")]
    InvalidAddr { input: String, detail: String },
    #[error("invalid prefix length in CIDR {input:?}: {detail}")]
    InvalidPrefix { input: String, detail: String },
    #[error("prefix length {prefix} is too large for {family} address in CIDR {input:?}")]
    PrefixTooLarge {
        input: String,
        family: &'static str,
        prefix: u8,
    },
}

impl IpCidr {
    /// Parse a CIDR string of the form `address/prefix`. Examples:
    /// * `"10.0.0.0/8"`
    /// * `"::1/128"`
    /// * `"fc00::/7"`
    pub fn parse(s: &str) -> Result<Self, CidrParseError> {
        let (addr_str, prefix_str) =
            s.split_once('/')
                .ok_or_else(|| CidrParseError::MissingSlash {
                    input: s.to_string(),
                })?;
        let network: IpAddr = addr_str.parse().map_err(|e: std::net::AddrParseError| {
            CidrParseError::InvalidAddr {
                input: s.to_string(),
                detail: e.to_string(),
            }
        })?;
        let prefix: u8 = prefix_str.parse().map_err(|e: std::num::ParseIntError| {
            CidrParseError::InvalidPrefix {
                input: s.to_string(),
                detail: e.to_string(),
            }
        })?;
        match network {
            IpAddr::V4(_) if prefix > 32 => {
                return Err(CidrParseError::PrefixTooLarge {
                    input: s.to_string(),
                    family: "IPv4",
                    prefix,
                });
            }
            IpAddr::V6(_) if prefix > 128 => {
                return Err(CidrParseError::PrefixTooLarge {
                    input: s.to_string(),
                    family: "IPv6",
                    prefix,
                });
            }
            _ => {}
        }
        Ok(Self { network, prefix })
    }

    /// True iff `ip` is in this CIDR. Mixed-family checks always return
    /// false (an IPv6 peer never matches an IPv4 CIDR and vice versa).
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(peer)) => v4_prefix_match(net, peer, self.prefix),
            (IpAddr::V6(net), IpAddr::V6(peer)) => v6_prefix_match(net, peer, self.prefix),
            _ => false,
        }
    }
}

impl std::fmt::Display for IpCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

fn v4_prefix_match(a: Ipv4Addr, b: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(a) & mask) == (u32::from(b) & mask)
}

fn v6_prefix_match(a: Ipv6Addr, b: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 128 {
        return false;
    }
    let mask = if prefix == 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(a) & mask) == (u128::from(b) & mask)
}

/// Default CIDR strings, in the canonical order operators see them.
/// Compile-time constant rather than a `&[IpCidr]` literal because
/// `IpCidr::parse` is not `const fn` (parsing involves the standard-
/// library `IpAddr` parser which is not const-evaluable as of MSRV).
pub const DEFAULT_LAN_CIDR_STRINGS: &[&str] = &[
    "127.0.0.0/8",    // IPv4 loopback (RFC 1122 §3.2.1.3)
    "10.0.0.0/8",     // RFC 1918 class A
    "172.16.0.0/12",  // RFC 1918 class B
    "192.168.0.0/16", // RFC 1918 class C
    "::1/128",        // IPv6 loopback (RFC 4291 §2.5.3)
    "fc00::/7",       // RFC 4193 IPv6 Unique Local Addresses
];

/// Where the resolved [`LanCidrs`] came from. Surfaced in
/// `yggdrasilctl local status` and at startup-log time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanCidrsSource {
    /// Operator did not set `[server].lan_cidrs` — the default set is in use.
    Default,
    /// Operator set `[server].lan_cidrs` explicitly — that list overrides
    /// the default entirely.
    Override,
}

impl LanCidrsSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Override => "override",
        }
    }
}

/// Resolved LAN-CIDR set, ready for fast per-connection membership tests.
#[derive(Debug, Clone)]
pub struct LanCidrs {
    cidrs: Vec<IpCidr>,
    source: LanCidrsSource,
}

impl LanCidrs {
    /// Build from an operator-supplied list. If `override_cidrs` is
    /// `None`, falls back to the hard-coded default set. If
    /// `override_cidrs` is `Some([])` (empty array), the resolved set is
    /// empty — cert-less route serving is effectively disabled.
    ///
    /// Returns an error if any entry fails to parse.
    pub fn resolve(override_cidrs: Option<&[String]>) -> Result<Self, CidrParseError> {
        match override_cidrs {
            Some(operator_list) => {
                let cidrs: Vec<IpCidr> = operator_list
                    .iter()
                    .map(|s| IpCidr::parse(s))
                    .collect::<Result<_, _>>()?;
                Ok(Self {
                    cidrs,
                    source: LanCidrsSource::Override,
                })
            }
            None => {
                let cidrs: Vec<IpCidr> = DEFAULT_LAN_CIDR_STRINGS
                    .iter()
                    .map(|s| {
                        IpCidr::parse(s).expect("hard-coded DEFAULT_LAN_CIDR_STRINGS is parseable")
                    })
                    .collect();
                Ok(Self {
                    cidrs,
                    source: LanCidrsSource::Default,
                })
            }
        }
    }

    /// True iff `peer` is in any CIDR in the resolved set.
    pub fn contains(&self, peer: IpAddr) -> bool {
        self.cidrs.iter().any(|c| c.contains(peer))
    }

    /// View the resolved CIDR list, in the same order the operator
    /// supplied them (or default-order if no override).
    pub fn cidrs(&self) -> &[IpCidr] {
        &self.cidrs
    }

    /// Source label for diagnostics. See [`LanCidrsSource`].
    pub fn source(&self) -> LanCidrsSource {
        self.source
    }

    /// Render the resolved set as CIDR strings for serialisation /
    /// display (status response, startup log).
    pub fn as_strings(&self) -> Vec<String> {
        self.cidrs.iter().map(|c| c.to_string()).collect()
    }
}

/// Shared snapshot the supervisor hands to per-IP companion listeners.
/// Wrapped in `Arc` so a hot reload that changes `[server].lan_cidrs`
/// can swap the snapshot atomically without disturbing in-flight
/// requests.
pub type LanCidrsSnapshot = Arc<LanCidrs>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_cidr() {
        let c = IpCidr::parse("192.168.1.0/24").unwrap();
        assert_eq!(c.to_string(), "192.168.1.0/24");
    }

    #[test]
    fn parses_ipv6_cidr() {
        let c = IpCidr::parse("fc00::/7").unwrap();
        assert_eq!(c.to_string(), "fc00::/7");
    }

    #[test]
    fn parses_ipv4_loopback() {
        let c = IpCidr::parse("127.0.0.0/8").unwrap();
        assert!(c.contains("127.0.0.1".parse().unwrap()));
        assert!(c.contains("127.255.255.254".parse().unwrap()));
        assert!(!c.contains("128.0.0.1".parse().unwrap()));
    }

    #[test]
    fn parses_ipv6_loopback() {
        let c = IpCidr::parse("::1/128").unwrap();
        assert!(c.contains("::1".parse().unwrap()));
        assert!(!c.contains("::2".parse().unwrap()));
    }

    #[test]
    fn rejects_missing_slash() {
        assert!(matches!(
            IpCidr::parse("10.0.0.0"),
            Err(CidrParseError::MissingSlash { .. })
        ));
    }

    #[test]
    fn rejects_invalid_addr() {
        assert!(matches!(
            IpCidr::parse("not-an-ip/24"),
            Err(CidrParseError::InvalidAddr { .. })
        ));
    }

    #[test]
    fn rejects_invalid_prefix() {
        assert!(matches!(
            IpCidr::parse("10.0.0.0/abc"),
            Err(CidrParseError::InvalidPrefix { .. })
        ));
    }

    #[test]
    fn rejects_oversized_ipv4_prefix() {
        assert!(matches!(
            IpCidr::parse("10.0.0.0/33"),
            Err(CidrParseError::PrefixTooLarge { family: "IPv4", .. })
        ));
    }

    #[test]
    fn rejects_oversized_ipv6_prefix() {
        assert!(matches!(
            IpCidr::parse("::1/129"),
            Err(CidrParseError::PrefixTooLarge { family: "IPv6", .. })
        ));
    }

    #[test]
    fn mixed_family_contains_returns_false() {
        let v4 = IpCidr::parse("10.0.0.0/8").unwrap();
        assert!(!v4.contains("::1".parse().unwrap()));
        let v6 = IpCidr::parse("fc00::/7").unwrap();
        assert!(!v6.contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn zero_prefix_matches_anything_in_family() {
        let v4 = IpCidr::parse("0.0.0.0/0").unwrap();
        assert!(v4.contains("1.2.3.4".parse().unwrap()));
        assert!(v4.contains("255.255.255.255".parse().unwrap()));
        assert!(!v4.contains("::1".parse().unwrap()));
    }

    #[test]
    fn resolve_default_returns_six_ranges() {
        let lan = LanCidrs::resolve(None).unwrap();
        assert_eq!(lan.source(), LanCidrsSource::Default);
        assert_eq!(lan.cidrs().len(), DEFAULT_LAN_CIDR_STRINGS.len());
    }

    #[test]
    fn resolve_default_contains_loopback() {
        let lan = LanCidrs::resolve(None).unwrap();
        assert!(lan.contains("127.0.0.1".parse().unwrap()));
        assert!(lan.contains("::1".parse().unwrap()));
    }

    #[test]
    fn resolve_default_contains_rfc1918_ranges() {
        let lan = LanCidrs::resolve(None).unwrap();
        assert!(lan.contains("10.0.0.1".parse().unwrap()));
        assert!(lan.contains("172.16.0.1".parse().unwrap()));
        assert!(lan.contains("172.31.255.255".parse().unwrap()));
        assert!(lan.contains("192.168.1.100".parse().unwrap()));
        assert!(lan.contains("192.168.156.4".parse().unwrap())); // docker bridge
    }

    #[test]
    fn resolve_default_contains_rfc4193_ula() {
        let lan = LanCidrs::resolve(None).unwrap();
        assert!(lan.contains("fc00::1".parse().unwrap()));
        assert!(lan.contains("fd00::beef".parse().unwrap()));
    }

    #[test]
    fn resolve_default_rejects_public_ips() {
        let lan = LanCidrs::resolve(None).unwrap();
        assert!(!lan.contains("8.8.8.8".parse().unwrap()));
        assert!(!lan.contains("203.0.113.50".parse().unwrap())); // TEST-NET-3
        assert!(!lan.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn resolve_default_rejects_link_local() {
        let lan = LanCidrs::resolve(None).unwrap();
        assert!(!lan.contains("169.254.1.1".parse().unwrap()));
        assert!(!lan.contains("fe80::1".parse().unwrap()));
    }

    #[test]
    fn resolve_default_rejects_cgnat() {
        let lan = LanCidrs::resolve(None).unwrap();
        assert!(!lan.contains("100.64.0.1".parse().unwrap()));
        assert!(!lan.contains("100.127.255.255".parse().unwrap()));
    }

    #[test]
    fn resolve_override_replaces_default() {
        let override_list = vec!["192.168.1.0/24".to_string()];
        let lan = LanCidrs::resolve(Some(&override_list)).unwrap();
        assert_eq!(lan.source(), LanCidrsSource::Override);
        assert_eq!(lan.cidrs().len(), 1);
        assert!(lan.contains("192.168.1.100".parse().unwrap()));
        // No longer in the set:
        assert!(!lan.contains("10.0.0.1".parse().unwrap()));
        assert!(!lan.contains("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn resolve_override_empty_list_blocks_everything() {
        let override_list: Vec<String> = vec![];
        let lan = LanCidrs::resolve(Some(&override_list)).unwrap();
        assert_eq!(lan.source(), LanCidrsSource::Override);
        assert_eq!(lan.cidrs().len(), 0);
        assert!(!lan.contains("127.0.0.1".parse().unwrap()));
        assert!(!lan.contains("192.168.1.100".parse().unwrap()));
    }

    #[test]
    fn resolve_override_widen_with_cgnat() {
        // Operator opts into Tailscale's CGNAT range alongside private nets.
        let override_list = vec!["192.168.0.0/16".to_string(), "100.64.0.0/10".to_string()];
        let lan = LanCidrs::resolve(Some(&override_list)).unwrap();
        assert!(lan.contains("100.64.0.1".parse().unwrap()));
        assert!(lan.contains("192.168.1.100".parse().unwrap()));
        // Loopback is no longer in the set under an override.
        assert!(!lan.contains("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn resolve_override_propagates_parse_error() {
        let override_list = vec!["not-a-cidr".to_string()];
        let err = LanCidrs::resolve(Some(&override_list)).unwrap_err();
        assert!(matches!(err, CidrParseError::MissingSlash { .. }));
    }

    #[test]
    fn as_strings_round_trips_defaults() {
        let lan = LanCidrs::resolve(None).unwrap();
        let s = lan.as_strings();
        assert_eq!(s.len(), DEFAULT_LAN_CIDR_STRINGS.len());
        for (i, expected) in DEFAULT_LAN_CIDR_STRINGS.iter().enumerate() {
            assert_eq!(s[i], *expected);
        }
    }
}
