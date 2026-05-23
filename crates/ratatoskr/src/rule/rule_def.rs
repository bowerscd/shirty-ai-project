//! The `Rule` struct itself plus its per-rule validation.
//!
//! Split out from the original monolithic `rule.rs` (Phase B1).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::http_route::HttpRoute;
use super::types::{Protocol, ProxyProto, TargetHost};
use super::validate::validate_http_route;

/// A single proxy rule as deserialised from a `[[rule]]` table.
///
/// Exactly one of `target_port` / `target_addr` / `target_host` is
/// set for L4 (`protocol = "tcp" | "udp"`):
/// * `target_port` — relay mode. The destination IP is supplied by the
///   heartbeat-discovered peer at runtime; this field selects the port.
/// * `target_addr` — terminal mode. A fixed LAN socket dialed verbatim.
/// * `target_host` — terminal mode. A `host:port` resolved via the OS
///   resolver at startup and refreshed periodically. Useful when the LAN
///   device gets its address from DHCP or is reachable by an mDNS name.
///
/// For L7 (`protocol = "https"`) the dial targets live inside the per-rule
/// `routes` array; none of the L4 dial-target fields may be set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Human-friendly identifier. Must be globally unique across all rule files.
    pub name: String,
    /// Local socket on which yggdrasil listens for client connections / datagrams.
    pub listen: SocketAddr,
    /// `"tcp"`, `"udp"`, or `"https"`.
    pub protocol: Protocol,
    /// Relay mode: destination port on the upstream peer (the residential host's
    /// IP comes from the heartbeat, not from this file). XOR with `target_addr`
    /// and `target_host`. Forbidden when `protocol = "https"`.
    #[serde(default)]
    pub target_port: Option<u16>,
    /// Terminal mode: fixed LAN socket address dialed verbatim. XOR with
    /// `target_port` and `target_host`. Forbidden when
    /// `protocol = "https"`.
    #[serde(default)]
    pub target_addr: Option<SocketAddr>,
    /// Terminal mode: `"hostname:port"` resolved at runtime via the OS
    /// resolver and refreshed periodically. XOR with `target_port` and
    /// `target_addr`. Forbidden when `protocol = "https"`. The host
    /// portion must be a syntactically valid DNS label sequence (same rules
    /// as `[[rule.route]] hostname`).
    #[serde(default)]
    pub target_host: Option<TargetHost>,
    /// UDP only: time without activity before a flow is evicted from the flow table.
    /// Default applied at load time (see [`Rule::resolved_idle_timeout`]).
    #[serde(default, with = "humantime_serde::option")]
    pub idle_timeout: Option<Duration>,
    /// TCP only: emit a PROXY-protocol header to the upstream before forwarding.
    /// Rejected when `target_addr` or `target_host` is set (terminal rules
    /// must not synthesise PROXY-protocol headers; relay-written headers pass
    /// through verbatim).
    #[serde(default)]
    pub proxy_protocol: Option<ProxyProto>,
    /// HTTPS only: required, non-empty list of per-hostname routes. See
    /// [`HttpRoute`]. Forbidden when `protocol = "tcp" | "udp"`.
    #[serde(default, rename = "route")]
    pub routes: Option<Vec<HttpRoute>>,
    /// HTTPS only: override of the convention cert directory for this
    /// rule's routes. Absent → fall back to `[server].cert_dir`.
    #[serde(default)]
    pub cert_dir: Option<PathBuf>,

    // --- HTTPS L7 options ---
    /// HTTPS-only: when `Some(false)`, suppress the HTTP/3 listener for this
    /// rule. `None` and `Some(true)` are equivalent (HTTP/3 enabled).
    /// Setting this field on a non-HTTPS rule is rejected at validation.
    #[serde(default)]
    pub http3: Option<bool>,

    /// HTTPS-only: when `Some(false)`, suppress the `Alt-Svc: h3=...` header
    /// on TCP HTTPS responses for this rule. `None` and `Some(true)` are
    /// equivalent (header emitted). If this field is absent and `http3 = false`,
    /// the header is implicitly suppressed. Setting `alt_svc = true` together
    /// with `http3 = false` is rejected (an Alt-Svc header pointing nowhere is
    /// a footgun). Setting this field on a non-HTTPS rule is rejected.
    #[serde(default)]
    pub alt_svc: Option<bool>,
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
            Protocol::Https => self.validate_l7(),
        }
    }

    /// Per-protocol checks for TCP/UDP rules.
    fn validate_l4(&self) -> Result<()> {
        // HTTPS-only fields must be absent.
        if self.routes.is_some() {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: `route` blocks are only valid for protocol = \"https\"",
                self.name
            )));
        }
        if self.cert_dir.is_some() {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: `cert_dir` is only valid for protocol = \"https\"",
                self.name
            )));
        }
        if self.http3.is_some() {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: `http3` is only meaningful for `protocol = \"https\"` rules",
                self.name
            )));
        }
        if self.alt_svc.is_some() {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: `alt_svc` is only meaningful for `protocol = \"https\"` rules",
                self.name
            )));
        }

        // 3-way XOR over (target_port, target_addr, target_host).
        // The Deserialize impl for `TargetHost` already enforces a valid
        // hostname + non-zero port; here we only check inter-field
        // consistency.
        let set_count = [
            self.target_port.is_some(),
            self.target_addr.is_some(),
            self.target_host.is_some(),
        ]
        .into_iter()
        .filter(|b| *b)
        .count();
        match set_count {
            0 => {
                return Err(Error::InvalidRule(format!(
                    "rule {:?}: must set exactly one of target_port (relay), \
                     target_addr (terminal, static), or target_host \
                     (terminal, DNS-resolved)",
                    self.name
                )));
            }
            1 => {}
            _ => {
                return Err(Error::InvalidRule(format!(
                    "rule {:?}: set exactly one of target_port (relay), \
                     target_addr (terminal, static), or target_host \
                     (terminal, DNS-resolved); not multiple",
                    self.name
                )));
            }
        }
        if matches!(self.target_port, Some(0)) {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: target_port must be non-zero",
                self.name
            )));
        }
        if let Some(addr) = self.target_addr {
            if addr.port() == 0 {
                return Err(Error::InvalidRule(format!(
                    "rule {:?}: target_addr port must be non-zero",
                    self.name
                )));
            }
        }
        if (self.target_addr.is_some() || self.target_host.is_some())
            && self.proxy_protocol.is_some()
        {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: proxy_protocol is invalid on terminal rules \
                 (target_addr or target_host is set); relay-written \
                 headers pass through verbatim",
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
                if self.proxy_protocol.is_some() {
                    return Err(Error::InvalidRule(format!(
                        "rule {:?}: proxy_protocol is only valid for tcp rules",
                        self.name
                    )));
                }
            }
            Protocol::Https => unreachable!("dispatched in validate()"),
        }
        Ok(())
    }

    /// Per-protocol checks for HTTPS rules.
    fn validate_l7(&self) -> Result<()> {
        // L4 dial-target fields must all be absent.
        if self.target_port.is_some() {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: `target_port` is not valid for protocol = \
                 \"https\" (dial targets live in [[rule.route]])",
                self.name
            )));
        }
        if self.target_addr.is_some() {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: `target_addr` is not valid for protocol = \
                 \"https\" (dial targets live in [[rule.route]])",
                self.name
            )));
        }
        if self.target_host.is_some() {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: `target_host` is not valid for protocol = \
                 \"https\" (dial targets live in [[rule.route]])",
                self.name
            )));
        }
        if self.proxy_protocol.is_some() {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: `proxy_protocol` is not valid for protocol = \
                 \"https\" (terminal consumes inbound PROXY-protocol headers)",
                self.name
            )));
        }
        if self.idle_timeout.is_some() {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: `idle_timeout` is only valid for udp rules",
                self.name
            )));
        }
        if self.alt_svc == Some(true) && self.http3 == Some(false) {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: `alt_svc = true` is incompatible with `http3 = false` — an Alt-Svc header would advertise a non-existent listener",
                self.name
            )));
        }

        // `routes` required and non-empty.
        let routes = self.routes.as_deref().unwrap_or(&[]);
        if routes.is_empty() {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: protocol = \"https\" requires at least one \
                 [[rule.route]] block",
                self.name
            )));
        }

        // Per-route validation + within-rule duplicate-hostname detection.
        let mut seen_hostnames = std::collections::HashSet::<String>::new();
        for route in routes {
            validate_http_route(&self.name, route)?;
            let lc = route.hostname.to_ascii_lowercase();
            if !seen_hostnames.insert(lc) {
                return Err(Error::InvalidRule(format!(
                    "rule {:?}: duplicate route hostname {:?}",
                    self.name, route.hostname
                )));
            }
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
