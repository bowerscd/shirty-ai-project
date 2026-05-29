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

    for (name, value) in &route.headers {
        validate_static_header(rule_name, &route.hostname, name, value)?;
    }

    Ok(())
}

/// Reserved header names that the operator MUST NOT set via
/// `[[route]].headers`. Split between two concerns:
///  * **hop-by-hop** (RFC 7230 §6.1 + the proxy-specific names) — these
///    apply only to a single connection and would be misleading if set
///    on a forwarded response;
///  * **yggdrasil-owned** — names that the daemon stamps itself, so
///    a route-level override would silently lose to the daemon's late
///    write (and operators would chase phantom bugs). HSTS is the
///    headline example — use the `hsts` route field instead.
///
/// Names are compared case-insensitively (HTTP headers are
/// case-insensitive). Request-forwarding headers (`X-Forwarded-*`,
/// `X-Real-IP`, `Forwarded`) appear here too even though they're
/// nominally request-side: the field name implies request semantics, so
/// allowing them on a response would be confusing and we'd rather a
/// loud config-load error than a silent mis-interpretation downstream.
fn reserved_static_header(name: &str) -> bool {
    const RESERVED: &[&str] = &[
        // hop-by-hop
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        // yggdrasil-owned response headers
        "strict-transport-security",
        "alt-svc",
        // forwarding (request-side; never makes sense on a response)
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-protocol",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-real-ip",
        "forwarded",
    ];
    let lower = name.to_ascii_lowercase();
    RESERVED.iter().any(|r| *r == lower)
}

fn validate_static_header(rule_name: &str, hostname: &str, name: &str, value: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidRule(format!(
            "rule {:?}: route {:?}: static response header name is empty",
            rule_name, hostname
        )));
    }
    // RFC 7230 token: ALPHA / DIGIT / "!#$%&'*+-.^_`|~"
    if !name.bytes().all(is_token_byte) {
        return Err(Error::InvalidRule(format!(
            "rule {:?}: route {:?}: static response header name {:?} \
             contains characters not allowed in an HTTP field name",
            rule_name, hostname, name
        )));
    }
    if reserved_static_header(name) {
        return Err(Error::InvalidRule(format!(
            "rule {:?}: route {:?}: static response header {:?} is \
             reserved (hop-by-hop, yggdrasil-owned, or request-only); \
             use the dedicated field (e.g. `hsts`) or pick a different name",
            rule_name, hostname, name
        )));
    }
    // RFC 7230 field-value: visible ASCII (0x21..=0x7E), HTAB, SP.
    // No CR / LF (those would be header injection).
    if !value.bytes().all(is_field_value_byte) {
        return Err(Error::InvalidRule(format!(
            "rule {:?}: route {:?}: static response header {:?} has an \
             invalid value (must be visible ASCII, no CR / LF)",
            rule_name, hostname, name
        )));
    }
    Ok(())
}

fn is_token_byte(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
    )
}

fn is_field_value_byte(b: u8) -> bool {
    b == b'\t' || (0x20..=0x7E).contains(&b)
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
