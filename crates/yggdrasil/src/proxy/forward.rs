//! Header rewriting shared between the TCP HTTPS frontend (h2/h1) and
//! the HTTP/3 frontend. Both transports need byte-identical handling so
//! upstream backends see consistent X-Forwarded-* values regardless of
//! which protocol the client used.

use std::net::IpAddr;

use anyhow::Context;
use http::header::{
    HeaderMap, HeaderName, HeaderValue, CONNECTION, FORWARDED, PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::uri::{Authority, Scheme};
use http::Uri;
use url::Url;

use ratatoskr::rule::HstsConfig;

/// Hop-by-hop headers per RFC 7230 §6.1 plus the few proxy-specific
/// headers that should never propagate.
fn hop_by_hop_headers() -> &'static [HeaderName] {
    &[
        CONNECTION,
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
    ]
}

/// Strip the inbound client's pre-existing X-Forwarded-* / Forwarded /
/// X-Real-IP headers so we can set them ourselves. Mutates in place.
pub fn strip_untrusted_forwarding(headers: &mut HeaderMap) {
    let to_remove = [
        HeaderName::from_static("x-forwarded-for"),
        HeaderName::from_static("x-forwarded-proto"),
        HeaderName::from_static("x-forwarded-protocol"),
        HeaderName::from_static("x-forwarded-host"),
        HeaderName::from_static("x-forwarded-port"),
        HeaderName::from_static("x-real-ip"),
        FORWARDED,
    ];
    for h in to_remove {
        headers.remove(&h);
    }
}

/// Strip hop-by-hop headers per RFC 7230 §6.1.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    // RFC 7230 §6.1 allows `Connection: <token>` to nominate further
    // hop-by-hop headers. Collect those tokens first, before removing
    // `Connection` itself.
    let tokens: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .filter_map(|tok| {
            let t = tok.trim();
            if t.eq_ignore_ascii_case("close") || t.eq_ignore_ascii_case("keep-alive") {
                None
            } else {
                HeaderName::from_bytes(t.as_bytes()).ok()
            }
        })
        .collect();

    for t in tokens {
        headers.remove(t);
    }
    for h in hop_by_hop_headers() {
        headers.remove(h);
    }
}

/// Inject `X-Forwarded-For` + `X-Real-IP` + `X-Forwarded-Proto` +
/// `X-Forwarded-Protocol` + `X-Forwarded-Host` for a forwarded request.
/// `client_ip` is the original client's IP (from PROXY-protocol header
/// on TCP, or from the h3 interpose map on UDP / QUIC). `host` is the
/// inbound `Host` header value. `scheme` is the client-facing scheme
/// as seen on the wire — `"https"` for the TLS / QUIC frontend, `"http"`
/// for the companion listener's plaintext path on `:80`.
///
/// `X-Forwarded-Protocol` is emitted alongside the canonical
/// `X-Forwarded-Proto` because the Jellyfin recommended reverse-proxy
/// posture (and a long tail of older Microsoft-stack-derived backends)
/// reads the `Protocol`-spelt variant. The two values are always
/// identical; backends should prefer `Proto`.
pub fn inject_forwarded(
    headers: &mut HeaderMap,
    client_ip: IpAddr,
    host: Option<&str>,
    scheme: &str,
) {
    if let Ok(v) = HeaderValue::from_str(&client_ip.to_string()) {
        headers.insert(HeaderName::from_static("x-forwarded-for"), v.clone());
        headers.insert(HeaderName::from_static("x-real-ip"), v);
    }
    if let Ok(v) = HeaderValue::from_str(scheme) {
        headers.insert(HeaderName::from_static("x-forwarded-proto"), v.clone());
        headers.insert(HeaderName::from_static("x-forwarded-protocol"), v);
    }
    if let Some(h) = host {
        if let Ok(v) = HeaderValue::from_str(h) {
            headers.insert(HeaderName::from_static("x-forwarded-host"), v);
        }
    }
}

/// Inject Strict-Transport-Security on the outbound response per the
/// route's HstsConfig, when configured.
pub fn maybe_inject_hsts(headers: &mut HeaderMap, hsts: Option<&HstsConfig>) {
    let Some(cfg) = hsts else { return };
    if headers.contains_key("strict-transport-security") {
        return;
    }

    let mut value = format!("max-age={}", cfg.max_age);
    if cfg.include_subdomains {
        value.push_str("; includeSubDomains");
    }
    if cfg.preload {
        value.push_str("; preload");
    }
    if let Ok(v) = HeaderValue::from_str(&value) {
        headers.insert(HeaderName::from_static("strict-transport-security"), v);
    }
}

/// Rewrite the client-facing request URI to target the selected upstream.
pub fn build_upstream_uri(orig: &Uri, upstream: &Url) -> anyhow::Result<Uri> {
    let path_and_query = orig.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let authority = match (upstream.host_str(), upstream.port_or_known_default()) {
        (Some(h), Some(p)) => format!("{h}:{p}"),
        (Some(h), None) => h.to_string(),
        _ => anyhow::bail!("upstream URL has no host"),
    };
    let authority = Authority::try_from(authority.as_bytes()).context("authority parse")?;
    Ok(Uri::builder()
        .scheme(Scheme::HTTP)
        .authority(authority)
        .path_and_query(path_and_query)
        .build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_untrusted_forwarding_drops_claims_and_keeps_others() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        h.insert("x-forwarded-proto", HeaderValue::from_static("http"));
        h.insert("x-forwarded-protocol", HeaderValue::from_static("http"));
        h.insert("x-forwarded-host", HeaderValue::from_static("evil.example"));
        h.insert("x-forwarded-port", HeaderValue::from_static("1234"));
        h.insert("x-real-ip", HeaderValue::from_static("5.6.7.8"));
        h.insert("forwarded", HeaderValue::from_static("for=lies"));
        h.insert("x-keep", HeaderValue::from_static("yes"));

        strip_untrusted_forwarding(&mut h);

        assert!(!h.contains_key("x-forwarded-for"));
        assert!(!h.contains_key("x-forwarded-proto"));
        assert!(
            !h.contains_key("x-forwarded-protocol"),
            "the X-Forwarded-Protocol synonym must be stripped too — leaving a \
             client-supplied value would let a request spoof its origin scheme"
        );
        assert!(!h.contains_key("x-forwarded-host"));
        assert!(!h.contains_key("x-forwarded-port"));
        assert!(!h.contains_key("x-real-ip"));
        assert!(!h.contains_key("forwarded"));
        assert_eq!(h.get("x-keep").unwrap(), "yes");
    }

    #[test]
    fn strip_hop_by_hop_drops_standard_names() {
        let mut h = HeaderMap::new();
        h.insert(CONNECTION, HeaderValue::from_static("close"));
        h.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        h.insert(TE, HeaderValue::from_static("trailers"));
        h.insert(TRAILER, HeaderValue::from_static("expires"));
        h.insert(UPGRADE, HeaderValue::from_static("websocket"));
        h.insert(PROXY_AUTHENTICATE, HeaderValue::from_static("Basic"));
        h.insert(PROXY_AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        h.insert("x-keep", HeaderValue::from_static("yes"));

        strip_hop_by_hop(&mut h);

        assert!(!h.contains_key(CONNECTION));
        assert!(!h.contains_key(TRANSFER_ENCODING));
        assert!(!h.contains_key(TE));
        assert!(!h.contains_key(TRAILER));
        assert!(!h.contains_key(UPGRADE));
        assert!(!h.contains_key(PROXY_AUTHENTICATE));
        assert!(!h.contains_key(PROXY_AUTHORIZATION));
        assert_eq!(h.get("x-keep").unwrap(), "yes");
    }

    #[test]
    fn strip_hop_by_hop_honours_connection_listed_names() {
        let mut h = HeaderMap::new();
        h.insert(CONNECTION, HeaderValue::from_static("foo, bar"));
        h.insert("foo", HeaderValue::from_static("1"));
        h.insert("bar", HeaderValue::from_static("2"));
        h.insert("x-keep", HeaderValue::from_static("yes"));

        strip_hop_by_hop(&mut h);

        assert!(!h.contains_key(CONNECTION));
        assert!(!h.contains_key("foo"));
        assert!(!h.contains_key("bar"));
        assert_eq!(h.get("x-keep").unwrap(), "yes");
    }

    #[test]
    fn inject_forwarded_sets_ipv4_values() {
        let mut h = HeaderMap::new();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();

        inject_forwarded(&mut h, ip, Some("api.example.com"), "https");

        assert_eq!(h.get("x-forwarded-for").unwrap(), "203.0.113.7");
        assert_eq!(h.get("x-real-ip").unwrap(), "203.0.113.7");
        assert_eq!(h.get("x-forwarded-proto").unwrap(), "https");
        assert_eq!(
            h.get("x-forwarded-protocol").unwrap(),
            "https",
            "Jellyfin recommended config and older Microsoft-stack backends read \
             X-Forwarded-Protocol; must be emitted alongside the canonical Proto"
        );
        assert_eq!(h.get("x-forwarded-host").unwrap(), "api.example.com");
    }

    #[test]
    fn inject_forwarded_sets_ipv6_values_without_brackets() {
        let mut h = HeaderMap::new();
        let ip: IpAddr = "2001:db8::1".parse().unwrap();

        inject_forwarded(&mut h, ip, Some("api.example.com"), "https");

        assert_eq!(h.get("x-forwarded-for").unwrap(), "2001:db8::1");
        assert_eq!(h.get("x-real-ip").unwrap(), "2001:db8::1");
        assert_eq!(h.get("x-forwarded-proto").unwrap(), "https");
        assert_eq!(h.get("x-forwarded-protocol").unwrap(), "https");
        assert_eq!(h.get("x-forwarded-host").unwrap(), "api.example.com");
    }

    #[test]
    fn inject_forwarded_uses_http_scheme_for_plaintext_path() {
        let mut h = HeaderMap::new();
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        inject_forwarded(&mut h, ip, Some("jellyfin.janus.local"), "http");

        assert_eq!(h.get("x-forwarded-for").unwrap(), "192.168.1.100");
        assert_eq!(h.get("x-real-ip").unwrap(), "192.168.1.100");
        assert_eq!(
            h.get("x-forwarded-proto").unwrap(),
            "http",
            "companion listener must inject http, not https"
        );
        assert_eq!(
            h.get("x-forwarded-protocol").unwrap(),
            "http",
            "the X-Forwarded-Protocol synonym must track Proto on the plaintext \
             path too"
        );
        assert_eq!(h.get("x-forwarded-host").unwrap(), "jellyfin.janus.local");
    }

    #[test]
    fn maybe_inject_hsts_none_adds_no_header() {
        let mut h = HeaderMap::new();

        maybe_inject_hsts(&mut h, None);

        assert!(!h.contains_key("strict-transport-security"));
    }

    #[test]
    fn maybe_inject_hsts_default_config_sets_max_age_only() {
        let mut h = HeaderMap::new();
        let cfg = HstsConfig::default();

        maybe_inject_hsts(&mut h, Some(&cfg));

        assert_eq!(
            h.get("strict-transport-security").unwrap(),
            "max-age=31536000"
        );
    }

    #[test]
    fn maybe_inject_hsts_include_subdomains_and_preload() {
        let mut h = HeaderMap::new();
        let cfg = HstsConfig {
            include_subdomains: true,
            preload: true,
            ..HstsConfig::default()
        };

        maybe_inject_hsts(&mut h, Some(&cfg));

        assert_eq!(
            h.get("strict-transport-security").unwrap(),
            "max-age=31536000; includeSubDomains; preload"
        );
    }

    #[test]
    fn maybe_inject_hsts_preserves_upstream_header() {
        let mut h = HeaderMap::new();
        h.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=60"),
        );
        let cfg = HstsConfig::default();

        maybe_inject_hsts(&mut h, Some(&cfg));

        assert_eq!(h.get("strict-transport-security").unwrap(), "max-age=60");
    }
}
