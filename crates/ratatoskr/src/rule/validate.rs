//! Shared rule-validation helpers.
//!
//! Split out from the original monolithic `rule.rs` (Phase B1). All
//! items are crate-private; the only entry points that escape the rule
//! module subtree are `validate_http_route` (consumed by `Rule::validate_l7`)
//! and `is_valid_dns_hostname` (consumed by `super::target::Target::parse`).

use crate::error::{Error, Result};

use super::http_route::HttpRoute;

/// Validate a single [`HttpRoute`] block belonging to `rule_name`.
///
/// Checks:
/// * `hostname` non-empty and a syntactically valid DNS label sequence.
/// * `target` scheme is exactly `"http"`; host and explicit port present.
///
/// Cert resolution is node-wide; routes carry no cert source of their
/// own. A route whose hostname is not covered by any node-wide cert is
/// served as a cert-less LAN route (`:80` plaintext to `lan_cidrs`
/// peers only).
pub(super) fn validate_http_route(rule_name: &str, route: &HttpRoute) -> Result<()> {
    if route.hostname.is_empty() {
        return Err(Error::InvalidRule(format!(
            "rule {:?}: route hostname is empty",
            rule_name
        )));
    }
    if !is_valid_dns_hostname(&route.hostname) {
        return Err(Error::InvalidRule(format!(
            "rule {:?}: route hostname {:?} is not a valid DNS name",
            rule_name, route.hostname
        )));
    }

    if route.target.scheme() != "http" {
        return Err(Error::InvalidRule(format!(
            "rule {:?}: route {:?}: target URL scheme must be \"http\" \
             (got {:?})",
            rule_name,
            route.hostname,
            route.target.scheme()
        )));
    }
    if route.target.host_str().is_none() {
        return Err(Error::InvalidRule(format!(
            "rule {:?}: route {:?}: target URL is missing a host",
            rule_name, route.hostname
        )));
    }
    if route.target.port_or_known_default().is_none() {
        return Err(Error::InvalidRule(format!(
            "rule {:?}: route {:?}: target URL has no port and no known \
             default for its scheme",
            rule_name, route.hostname
        )));
    }

    Ok(())
}

/// Loose RFC-1123 DNS-name validator. Accepts:
/// * length 1..=253 octets total;
/// * labels of length 1..=63;
/// * labels matching `[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?`;
/// * a single optional trailing dot.
///
/// Wildcard (`*.example.com`) and underscore labels are rejected: a route
/// hostname must be a concrete DNS name, not a pattern. (Per-hostname
/// SNI/Host matching is exact at runtime.)
pub(super) fn is_valid_dns_hostname(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|label| {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        let bytes = label.as_bytes();
        if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
            return false;
        }
        bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'-')
    })
}
