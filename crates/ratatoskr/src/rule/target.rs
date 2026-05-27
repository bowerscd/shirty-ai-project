//! Parsing for the L4 rule `target` field.
//!
//! The operator-facing schema carries a single `target = "host:port"`
//! string on terminal-mode L4 rules; this module turns that into a
//! structured form the daemon's resolver factory consumes. `host` may
//! be:
//!
//! * an IPv4 literal (`"192.0.2.10"`) — wired as a static [`Target::Static`]
//!   socket address, no re-resolution.
//! * an IPv6 literal in brackets (`"[2001:db8::1]"`) — same shape.
//! * a DNS name (`"printer.lan"`, `"palworld"`) — wired as
//!   [`Target::Dns`], re-resolved periodically by the daemon's resolver
//!   refresh task.
//!
//! `port` must be a non-zero u16.
//!
//! Operators do not need to distinguish the cases — the loader picks the
//! right resolver shape based on whether the host portion parses as an
//! IP literal. A literal that fails IP parsing falls through to the DNS
//! path; the host portion is then validated against the same RFC-1123
//! LDH rules as `[[rule.route]] hostname`.

use std::net::SocketAddr;

use super::validate::is_valid_dns_hostname;

/// Parsed form of `[[rule]].target`.
///
/// The variants line up directly with the daemon-side
/// `proxy::resolver::UpstreamResolver::{Static,Dns}` constructors; this
/// module is responsible only for the textual → structured conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// IP literal `host:port`. No re-resolution at runtime.
    Static(SocketAddr),
    /// DNS hostname `host:port`. Re-resolved periodically by the daemon.
    Dns { host: String, port: u16 },
}

impl Target {
    /// Parse a `host:port` string into a [`Target`]. Returns a
    /// human-readable error suitable for embedding in a
    /// [`crate::error::Error::InvalidRule`] message.
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Ok(addr) = s.parse::<SocketAddr>() {
            if addr.port() == 0 {
                return Err(format!("target {s:?}: port must be non-zero"));
            }
            return Ok(Self::Static(addr));
        }

        let (host, port_str) = s
            .rsplit_once(':')
            .ok_or_else(|| format!("target {s:?}: expected \"host:port\""))?;
        if host.is_empty() {
            return Err(format!("target {s:?}: empty host"));
        }
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("target {s:?}: port {port_str:?} is not a u16"))?;
        if port == 0 {
            return Err(format!("target {s:?}: port must be non-zero"));
        }
        if !is_valid_dns_hostname(host) {
            return Err(format!(
                "target {s:?}: host {host:?} is not a valid IP literal or DNS \
                 name (LDH labels, no wildcards, no underscores)"
            ));
        }
        Ok(Self::Dns {
            host: host.to_string(),
            port,
        })
    }

    /// The port portion of this target. Convenience accessor used by the
    /// supervisor and metrics.
    pub fn port(&self) -> u16 {
        match self {
            Self::Static(addr) => addr.port(),
            Self::Dns { port, .. } => *port,
        }
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static(addr) => write!(f, "{addr}"),
            Self::Dns { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_literal_as_static() {
        let t = Target::parse("192.0.2.10:22").unwrap();
        assert_eq!(t, Target::Static("192.0.2.10:22".parse().unwrap()));
        assert_eq!(t.port(), 22);
    }

    #[test]
    fn parses_ipv6_literal_as_static() {
        let t = Target::parse("[2001:db8::1]:443").unwrap();
        assert_eq!(t, Target::Static("[2001:db8::1]:443".parse().unwrap()));
    }

    #[test]
    fn parses_dns_hostname_as_dns() {
        let t = Target::parse("printer.lan:9100").unwrap();
        assert_eq!(
            t,
            Target::Dns {
                host: "printer.lan".to_string(),
                port: 9100,
            }
        );
    }

    #[test]
    fn parses_single_label_hostname() {
        // Container short names ("palworld", "jellyfin") are common
        // targets inside docker bridge networks — must round-trip.
        let t = Target::parse("palworld:8211").unwrap();
        assert_eq!(
            t,
            Target::Dns {
                host: "palworld".to_string(),
                port: 8211,
            }
        );
    }

    #[test]
    fn rejects_zero_port_ip() {
        let err = Target::parse("127.0.0.1:0").unwrap_err();
        assert!(err.contains("port must be non-zero"), "got: {err}");
    }

    #[test]
    fn rejects_zero_port_dns() {
        let err = Target::parse("host.example:0").unwrap_err();
        assert!(err.contains("port must be non-zero"), "got: {err}");
    }

    #[test]
    fn rejects_missing_port() {
        let err = Target::parse("hostnoport").unwrap_err();
        assert!(err.contains("expected"), "got: {err}");
    }

    #[test]
    fn rejects_empty_host() {
        let err = Target::parse(":22").unwrap_err();
        assert!(err.contains("empty host"), "got: {err}");
    }

    #[test]
    fn rejects_wildcard_hostname() {
        let err = Target::parse("*.example.com:443").unwrap_err();
        assert!(err.contains("not a valid"), "got: {err}");
    }

    #[test]
    fn rejects_underscore_hostname() {
        let err = Target::parse("bad_host.lan:80").unwrap_err();
        assert!(err.contains("not a valid"), "got: {err}");
    }

    #[test]
    fn rejects_non_numeric_port() {
        let err = Target::parse("host.example:notanumber").unwrap_err();
        assert!(err.contains("not a u16"), "got: {err}");
    }
}
