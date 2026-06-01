//! The `Rule` struct itself plus its per-rule validation.
//!

use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::target::Target;
use super::types::{Protocol, ProxyProto};

/// A single L4 proxy rule as deserialised from a `[[rule]]` table.
///
/// Exactly one of `target_port` / `target` is set:
/// * `target_port` — relay mode. The destination IP is supplied by the
///   heartbeat-discovered peer at runtime; this field selects the port.
/// * `target` — terminal mode. A `host:port` string where `host` is
///   either an IP literal (parsed once, no re-resolution) or a DNS name
///   (re-resolved periodically by the daemon). The loader picks the
///   resolver shape based on whether the host portion parses as an IP.
///
/// HTTPS routes live in top-level `[[route]]` blocks on the rule file,
/// not on rules — see [`super::HttpRoute`] and [`super::RuleSet::routes`].
/// `Rule` is L4-only; `protocol = "https"` is rejected at validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Human-friendly identifier. Must be globally unique across all rule files.
    pub name: String,
    /// Local socket on which yggdrasil listens for client connections / datagrams.
    pub listen: SocketAddr,
    /// `"tcp"` or `"udp"`. `"https"` is rejected — HTTPS routes are
    /// expressed via top-level `[[route]]` blocks.
    pub protocol: Protocol,
    /// Relay mode: destination port on the upstream peer (the residential host's
    /// IP comes from the heartbeat, not from this file). XOR with `target`.
    #[serde(default)]
    pub target_port: Option<u16>,
    /// Terminal mode: dial target as a `host:port` string. `host` may be
    /// an IPv4 literal, a bracketed IPv6 literal, or a DNS name. IP
    /// literals are wired as a static target; DNS names are re-resolved
    /// periodically. XOR with `target_port`.
    #[serde(default)]
    pub target: Option<String>,
    /// UDP only: time without activity before a flow is evicted from the flow table.
    /// Default applied at load time (see [`Rule::resolved_idle_timeout`]).
    #[serde(default, with = "humantime_serde::option")]
    pub idle_timeout: Option<Duration>,
    /// Relay-mode only: emit a PROXY-protocol header to the upstream before
    /// forwarding. Rejected when `target` is set (terminal rules must not
    /// synthesise PROXY-protocol headers; relay-written headers pass through
    /// verbatim). Valid on both TCP and UDP relay rules. For TCP, the header
    /// is prepended to the upstream byte stream before any application bytes;
    /// for UDP, a PROXY-v2 header is sent as a standalone datagram on each
    /// new flow before the first application datagram.
    #[serde(default)]
    pub proxy_protocol: Option<ProxyProto>,
}

/// Default UDP idle timeout if a rule does not specify one.
pub const DEFAULT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

impl Rule {
    /// Validate per-rule invariants. Returns `Error::InvalidRule` with a
    /// human-readable message on failure.
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(Error::InvalidRule("rule name is empty".into()));
        }
        if self
            .name
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(Error::InvalidRule(format!(
                "rule name {:?} contains whitespace or control characters",
                self.name
            )));
        }
        if self.listen.port() == 0 {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: listen port must be non-zero",
                self.name
            )));
        }
        match self.protocol {
            Protocol::Tcp | Protocol::Udp => self.validate_l4(),
            Protocol::Https => Err(Error::InvalidRule(format!(
                "rule {:?}: protocol = \"https\" is not valid on `[[rule]]`; \
                 use top-level `[[route]]` blocks to declare HTTPS routes",
                self.name
            ))),
        }
    }

    /// Per-protocol checks for TCP/UDP rules.
    fn validate_l4(&self) -> Result<()> {
        // 2-way XOR over (target_port, target).
        match (self.target_port, self.target.as_deref()) {
            (Some(_), Some(_)) => {
                return Err(Error::InvalidRule(format!(
                    "rule {:?}: set exactly one of target_port (relay) or \
                     target (terminal); not both",
                    self.name
                )));
            }
            (None, None) => {
                return Err(Error::InvalidRule(format!(
                    "rule {:?}: must set exactly one of target_port (relay) \
                     or target (terminal, \"host:port\")",
                    self.name
                )));
            }
            (Some(0), None) => {
                return Err(Error::InvalidRule(format!(
                    "rule {:?}: target_port must be non-zero",
                    self.name
                )));
            }
            (Some(_), None) => {
                // Relay mode: target_port already constrained above.
            }
            (None, Some(s)) => {
                // Terminal mode: parse the target to fail fast on a bad
                // value. The parsed form is thrown away here; the resolver
                // factory re-parses at build time. The cost is negligible
                // (one parse per rule per config reload).
                Target::parse(s).map_err(|detail| {
                    Error::InvalidRule(format!("rule {:?}: {detail}", self.name))
                })?;
            }
        }

        if self.target.is_some() && self.proxy_protocol.is_some() {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: proxy_protocol is invalid on terminal rules \
                 (target is set); relay-written headers pass through verbatim",
                self.name
            )));
        }
        match self.protocol {
            Protocol::Tcp => {
                if self.idle_timeout.is_some() {
                    return Err(Error::InvalidRule(format!(
                        "rule {:?}: idle_timeout is only valid for udp rules",
                        self.name
                    )));
                }
            }
            Protocol::Udp => {
                // `proxy_protocol` is allowed on relay-mode UDP rules so the
                // chain's HTTPS UDP/QUIC leg can carry the real client IP to
                // the terminal's h3 frontend. Only v2 is meaningful as a
                // standalone datagram; v1 is ASCII designed for TCP stream
                // prefix and not well-defined for datagrams. Terminal-mode
                // UDP rules (target set) are already rejected above by the
                // shared target+proxy_protocol check.
                if matches!(self.proxy_protocol, Some(ProxyProto::V1)) {
                    return Err(Error::InvalidRule(format!(
                        "rule {:?}: proxy_protocol = \"v1\" is invalid on udp \
                         rules; use \"v2\" (v1 is ASCII, designed for stream prefix)",
                        self.name
                    )));
                }
            }
            Protocol::Https => unreachable!("dispatched in validate()"),
        }
        Ok(())
    }

    /// Idle timeout to apply at runtime — supplied value or
    /// [`DEFAULT_UDP_IDLE_TIMEOUT`] for UDP, irrelevant for TCP.
    pub fn resolved_idle_timeout(&self) -> Duration {
        self.idle_timeout.unwrap_or(DEFAULT_UDP_IDLE_TIMEOUT)
    }

    /// Return a copy of this rule with the listen IP replaced by `bind_ip`
    /// if one is provided AND the rule's listen address is the wildcard
    /// (`0.0.0.0` or `::`). Rules with an explicit non-wildcard listen IP
    /// are returned unchanged — operator intent always wins over the
    /// server-wide default.
    ///
    /// Port is preserved. `bind_ip = None` is a no-op (rule returned
    /// unchanged). The override is a v4 vs v6 match: a v4 default does not
    /// rewrite a `::` listen and vice versa.
    pub fn with_bind_override(&self, bind_ip: Option<std::net::IpAddr>) -> Rule {
        let Some(ip) = bind_ip else {
            return self.clone();
        };
        let cur_ip = self.listen.ip();
        let is_wildcard = cur_ip.is_unspecified();
        let same_family = matches!(
            (cur_ip, ip),
            (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_))
                | (std::net::IpAddr::V6(_), std::net::IpAddr::V6(_))
        );
        if !is_wildcard || !same_family {
            return self.clone();
        }
        let mut out = self.clone();
        out.listen = std::net::SocketAddr::new(ip, self.listen.port());
        out
    }
}
