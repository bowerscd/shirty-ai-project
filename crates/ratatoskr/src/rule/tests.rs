//! Integration tests for the rule schema, validation, file loading, and
//! diff. Split out from the original monolithic `rule.rs` (Phase B1).

use std::time::Duration;

use crate::error::{Error, Result};

use super::*;

fn parse(s: &str) -> Result<RuleFile> {
    RuleFile::from_toml("test.toml", s)
}

#[test]
fn parses_minimal_tcp_rule() {
    let f = parse(
        r#"
            [[rule]]
            name = "ssh"
            listen = "0.0.0.0:2222"
            protocol = "tcp"
            target_port = 22
            "#,
    )
    .unwrap();
    assert_eq!(f.rule.len(), 1);
    let r = &f.rule[0];
    assert_eq!(r.name, "ssh");
    assert_eq!(r.protocol, Protocol::Tcp);
    assert_eq!(r.target_port, Some(22));
    assert_eq!(r.target, None);
    assert_eq!(r.idle_timeout, None);
    assert_eq!(r.proxy_protocol, None);
    f.validate_each().unwrap();
}

#[test]
fn parses_terminal_style_tcp_rule_with_ip_literal() {
    let f = parse(
        r#"
            [[rule]]
            name = "home-ssh"
            listen = "0.0.0.0:2222"
            protocol = "tcp"
            target = "192.168.1.10:22"
            "#,
    )
    .unwrap();
    let r = &f.rule[0];
    assert_eq!(r.target_port, None);
    assert_eq!(r.target.as_deref(), Some("192.168.1.10:22"));
    f.validate_each().unwrap();
}

#[test]
fn parses_terminal_style_tcp_rule_with_dns_name() {
    let f = parse(
        r#"
            [[rule]]
            name = "dns-rule"
            listen = "0.0.0.0:9100"
            protocol = "tcp"
            target = "printer.lan:9100"
            "#,
    )
    .unwrap();
    f.validate_each().expect("should validate");
    assert_eq!(f.rule[0].target.as_deref(), Some("printer.lan:9100"));
}

#[test]
fn parses_terminal_style_udp_rule() {
    let f = parse(
        r#"
            [[rule]]
            name = "home-dns"
            listen = "0.0.0.0:53"
            protocol = "udp"
            target = "192.168.1.1:53"
            idle_timeout = "30s"
            "#,
    )
    .unwrap();
    let r = &f.rule[0];
    assert_eq!(r.protocol, Protocol::Udp);
    assert_eq!(r.target.as_deref(), Some("192.168.1.1:53"));
    assert_eq!(r.idle_timeout, Some(Duration::from_secs(30)));
    f.validate_each().unwrap();
}

#[test]
fn parses_udp_rule_with_idle_timeout() {
    let f = parse(
        r#"
            [[rule]]
            name = "minecraft-bedrock"
            listen = "0.0.0.0:19132"
            protocol = "udp"
            target_port = 19132
            idle_timeout = "30s"
            "#,
    )
    .unwrap();
    let r = &f.rule[0];
    assert_eq!(r.protocol, Protocol::Udp);
    assert_eq!(r.idle_timeout, Some(Duration::from_secs(30)));
    assert_eq!(r.resolved_idle_timeout(), Duration::from_secs(30));
    f.validate_each().unwrap();
}

#[test]
fn parses_tcp_rule_with_proxy_protocol() {
    let f = parse(
        r#"
            [[rule]]
            name = "http"
            listen = "0.0.0.0:80"
            protocol = "tcp"
            target_port = 8080
            proxy_protocol = "v2"
            "#,
    )
    .unwrap();
    assert_eq!(f.rule[0].proxy_protocol, Some(ProxyProto::V2));
    f.validate_each().unwrap();
}

#[test]
fn rejects_idle_timeout_on_tcp_rule() {
    let f = parse(
        r#"
            [[rule]]
            name = "ssh"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            target_port = 22
            idle_timeout = "30s"
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(err, Some(Error::InvalidRule(ref s)) if s.contains("idle_timeout")));
}

#[test]
fn accepts_proxy_protocol_on_relay_mode_udp_rule() {
    // Relay-mode UDP rules (target_port set, target absent) may carry
    // proxy_protocol = "v2" so the relay can emit a PROXY-v2 first
    // datagram for HTTPS UDP/QUIC chain traffic. Terminal-mode UDP rules
    // remain rejected by the shared `target + proxy_protocol` check; v1
    // is also rejected on UDP because it's a stream-prefix ASCII shape.
    let f = parse(
        r#"
            [[rule]]
            name = "h3"
            listen = "0.0.0.0:443"
            protocol = "udp"
            target_port = 443
            proxy_protocol = "v2"
            "#,
    )
    .unwrap();
    f.validate_each()
        .expect("relay-mode UDP + proxy_protocol v2 is valid");
    assert_eq!(f.rule[0].proxy_protocol, Some(ProxyProto::V2));
}

#[test]
fn rejects_proxy_protocol_v1_on_udp_rule() {
    // v1 is ASCII designed for TCP stream prefix; not meaningful as a
    // standalone datagram. Reject on UDP relay rules.
    let f = parse(
        r#"
            [[rule]]
            name = "h3-v1"
            listen = "0.0.0.0:443"
            protocol = "udp"
            target_port = 443
            proxy_protocol = "v1"
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(
        matches!(err, Some(Error::InvalidRule(ref s)) if s.contains("v1") && s.contains("udp"))
    );
}

#[test]
fn rejects_zero_listen_port() {
    let f = parse(
        r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:0"
            protocol = "tcp"
            target_port = 22
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(err, Some(Error::InvalidRule(ref s)) if s.contains("listen port")));
}

#[test]
fn rejects_zero_target_port() {
    let f = parse(
        r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            target_port = 0
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(err, Some(Error::InvalidRule(ref s)) if s.contains("target_port")));
}

#[test]
fn rejects_both_target_port_and_target() {
    let f = parse(
        r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            target_port = 22
            target = "192.168.1.1:22"
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(
        err,
        Some(Error::InvalidRule(s)) if s.contains("not both")
    ));
}

#[test]
fn rejects_neither_target_port_nor_target() {
    let f = parse(
        r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(
        err,
        Some(Error::InvalidRule(s)) if s.contains("must set exactly one")
    ));
}

#[test]
fn rejects_target_with_zero_port() {
    let f = parse(
        r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            target = "192.168.1.1:0"
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(
        err,
        Some(Error::InvalidRule(s)) if s.contains("port must be non-zero")
    ));
}

#[test]
fn rejects_proxy_protocol_with_target() {
    let f = parse(
        r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            target = "192.168.1.1:22"
            proxy_protocol = "v2"
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(
        err,
        Some(Error::InvalidRule(s)) if s.contains("proxy_protocol is invalid on terminal rules")
    ));
}

#[test]
fn rejects_target_with_invalid_hostname() {
    // Wildcards are not valid DNS hostnames, and they don't parse as IP
    // literals either, so the parse failure surfaces at validate time
    // (the field itself is just a String, not strongly parsed at deserialize).
    let f = parse(
        r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            target = "*.example.com:22"
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(
        err,
        Some(Error::InvalidRule(s)) if s.contains("not a valid")
    ));
}

#[test]
fn rejects_target_missing_port() {
    let f = parse(
        r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            target = "hostnoport"
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(
        err,
        Some(Error::InvalidRule(s)) if s.contains("expected \"host:port\"")
    ));
}

#[test]
fn rejects_empty_name() {
    let f = parse(
        r#"
            [[rule]]
            name = ""
            listen = "0.0.0.0:22"
            protocol = "tcp"
            target_port = 22
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(err, Some(Error::InvalidRule(ref s)) if s.contains("empty")));
}

#[test]
fn rejects_name_with_whitespace() {
    let f = parse(
        r#"
            [[rule]]
            name = "bad name"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            target_port = 22
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(err, Some(Error::InvalidRule(ref s)) if s.contains("whitespace")));
}

#[test]
fn rejects_malformed_toml() {
    let err = parse("[[rule\nname=oops").err();
    assert!(matches!(err, Some(Error::TomlParse { .. })));
}

#[test]
fn allows_empty_rule_file() {
    let f = parse("").unwrap();
    assert!(f.rule.is_empty());
    f.validate_each().unwrap();
}

#[test]
fn rule_set_aggregates_multiple_files() {
    let a = parse(
        r#"
            [[rule]]
            name = "a"
            listen = "0.0.0.0:1111"
            protocol = "tcp"
            target_port = 1
            "#,
    )
    .unwrap();
    let b = parse(
        r#"
            [[rule]]
            name = "b"
            listen = "0.0.0.0:2222"
            protocol = "udp"
            target_port = 2
            "#,
    )
    .unwrap();
    let set = RuleSet::from_files([a, b]).unwrap();
    assert_eq!(set.len(), 2);
    assert!(set.find("a").is_some());
    assert!(set.find("b").is_some());
    assert!(set.find("nope").is_none());
}

#[test]
fn rule_set_rejects_duplicate_names() {
    let a = parse(
        r#"
            [[rule]]
            name = "dup"
            listen = "0.0.0.0:1111"
            protocol = "tcp"
            target_port = 1
            "#,
    )
    .unwrap();
    let b = parse(
        r#"
            [[rule]]
            name = "dup"
            listen = "0.0.0.0:2222"
            protocol = "tcp"
            target_port = 2
            "#,
    )
    .unwrap();
    let err = RuleSet::from_files([a, b]).err();
    assert!(matches!(err, Some(Error::InvalidRule(ref s)) if s.contains("duplicate rule name")));
}

fn l4_rule_file(name: &str, listen: &str, protocol: Protocol) -> RuleFile {
    parse(&format!(
        r#"
            [[rule]]
            name = "{name}"
            listen = "{listen}"
            protocol = "{}"
            target_port = 53
            "#,
        protocol.as_str()
    ))
    .unwrap()
}

#[allow(dead_code)]
fn https_rule_file(_name: &str, _listen: &str) -> RuleFile {
    // After the L7 schema cleanup, HTTPS rules don't exist on `[[rule]]`.
    // This helper is kept (returning an empty file) so tests that reference
    // it compile until they're removed.
    RuleFile::default()
}

#[test]
fn rule_set_allows_tcp_and_udp_on_same_listen_addr() {
    let set = RuleSet::from_files([
        l4_rule_file("dns-tcp", "0.0.0.0:53", Protocol::Tcp),
        l4_rule_file("dns-udp", "0.0.0.0:53", Protocol::Udp),
    ])
    .unwrap();
    assert_eq!(set.len(), 2);
}

// The legacy `rule_set_allows_https_*` / `rule_set_rejects_https_*` /
// `rule_set_rejects_two_https_rules_*` tests were predicated on
// HTTPS rules existing in `[[rule]]`. With the L7 schema cleanup,
// HTTPS routes live in top-level `[[route]]` blocks; the duplicate-
// hostname check has its own coverage in
// `rule_set_rejects_duplicate_route_hostnames_case_insensitive`.

#[test]
fn rule_set_rejects_two_tcp_rules_on_same_listen_addr() {
    let err = RuleSet::from_files([
        l4_rule_file("tcp-a", "0.0.0.0:1111", Protocol::Tcp),
        l4_rule_file("tcp-b", "0.0.0.0:1111", Protocol::Tcp),
    ])
    .err();
    assert!(matches!(err, Some(Error::InvalidRule(s))
            if s.contains("duplicate listen address") && s.contains("protocol tcp")));
}

#[test]
fn unknown_protocol_string_fails_to_deserialise() {
    let err = parse(
        r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "sctp"
            target_port = 22
            "#,
    )
    .err();
    assert!(matches!(err, Some(Error::TomlParse { .. })));
}

#[test]
fn idle_timeout_default_for_udp() {
    let f = parse(
        r#"
            [[rule]]
            name = "udp"
            listen = "0.0.0.0:1234"
            protocol = "udp"
            target_port = 1234
            "#,
    )
    .unwrap();
    assert_eq!(f.rule[0].idle_timeout, None);
    assert_eq!(f.rule[0].resolved_idle_timeout(), DEFAULT_UDP_IDLE_TIMEOUT);
}

// ---- diff tests ----

fn rule(name: &str, port: u16, proto: Protocol, target: u16) -> Rule {
    let f = parse(&format!(
        r#"
            [[rule]]
            name = "{name}"
            listen = "0.0.0.0:{port}"
            protocol = "{}"
            target_port = {target}
            "#,
        proto.as_str()
    ))
    .unwrap();
    f.rule.into_iter().next().unwrap()
}

fn set(rules: Vec<Rule>) -> RuleSet {
    RuleSet::from_files([RuleFile {
        rule: rules,
        route: Vec::new(),
    }])
    .unwrap()
}

#[test]
fn diff_empty_to_empty_is_noop() {
    let d = RuleSet::default().diff(&RuleSet::default());
    assert!(d.is_noop());
    assert_eq!(d.touched(), 0);
}

#[test]
fn diff_initial_treats_everything_as_added() {
    let s = set(vec![rule("a", 1111, Protocol::Tcp, 22)]);
    let d = s.as_initial_diff();
    assert_eq!(d.added.len(), 1);
    assert_eq!(d.added[0].name, "a");
    assert!(d.removed.is_empty());
    assert!(d.changed.is_empty());
    assert!(d.unchanged.is_empty());
}

#[test]
fn diff_classifies_added_removed_changed_unchanged() {
    let old = set(vec![
        rule("keep", 1000, Protocol::Tcp, 22),
        rule("gone", 2000, Protocol::Tcp, 23),
        rule("mod", 3000, Protocol::Tcp, 24),
    ]);
    // "keep" unchanged, "gone" removed, "mod" target port changed, "new" added.
    let new = set(vec![
        rule("keep", 1000, Protocol::Tcp, 22),
        rule("mod", 3000, Protocol::Tcp, 99),
        rule("new", 4000, Protocol::Udp, 53),
    ]);
    let d = old.diff(&new);
    assert_eq!(d.added.len(), 1);
    assert_eq!(d.added[0].name, "new");
    assert_eq!(d.removed.len(), 1);
    assert_eq!(d.removed[0].name, "gone");
    assert_eq!(d.changed.len(), 1);
    assert_eq!(d.changed[0].old.name, "mod");
    assert_eq!(d.changed[0].old.target_port, Some(24));
    assert_eq!(d.changed[0].new.target_port, Some(99));
    assert_eq!(d.unchanged, vec!["keep".to_string()]);
    assert_eq!(d.touched(), 3);
    assert!(!d.is_noop());
}

#[test]
fn diff_same_set_is_noop_but_marks_unchanged() {
    let s = set(vec![
        rule("a", 1, Protocol::Tcp, 1),
        rule("b", 2, Protocol::Udp, 2),
    ]);
    let d = s.diff(&s);
    assert!(d.is_noop());
    assert_eq!(d.unchanged.len(), 2);
}

// ---- with_bind_override ----

fn relay_rule_with_listen(listen: &str) -> Rule {
    let mut r = rule("test", 0, Protocol::Tcp, 22);
    r.listen = listen.parse().unwrap();
    r
}

#[test]
fn with_bind_override_none_is_noop() {
    let r = relay_rule_with_listen("0.0.0.0:1234");
    let out = r.with_bind_override(None);
    assert_eq!(out.listen, r.listen);
}

#[test]
fn with_bind_override_rewrites_wildcard_v4_listen() {
    let r = relay_rule_with_listen("0.0.0.0:1234");
    let out = r.with_bind_override(Some("10.0.0.5".parse().unwrap()));
    assert_eq!(out.listen, "10.0.0.5:1234".parse().unwrap());
}

#[test]
fn with_bind_override_rewrites_wildcard_v6_listen() {
    let r = relay_rule_with_listen("[::]:1234");
    let out = r.with_bind_override(Some("fd00::1".parse().unwrap()));
    assert_eq!(out.listen, "[fd00::1]:1234".parse().unwrap());
}

#[test]
fn with_bind_override_preserves_explicit_v4_listen() {
    let r = relay_rule_with_listen("127.0.0.1:1234");
    let out = r.with_bind_override(Some("10.0.0.5".parse().unwrap()));
    assert_eq!(
        out.listen,
        "127.0.0.1:1234".parse().unwrap(),
        "explicit operator listen IP must win over default_bind"
    );
}

#[test]
fn with_bind_override_does_not_cross_address_families() {
    let r = relay_rule_with_listen("0.0.0.0:1234");
    let out = r.with_bind_override(Some("fd00::1".parse().unwrap()));
    assert_eq!(
        out.listen,
        "0.0.0.0:1234".parse().unwrap(),
        "v6 default_bind must not rewrite a v4 wildcard listen"
    );
}

// ===== L7 (HTTPS) schema tests =====
//
// HTTPS routes are top-level `[[route]]` blocks, not nested in
// `[[rule]]`. Rule rejects `protocol = "https"` outright.

#[test]
fn rule_rejects_https_protocol() {
    let f = parse(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(
        err,
        Some(Error::InvalidRule(s)) if s.contains("protocol = \"https\" is not valid on `[[rule]]`")
    ));
}

#[test]
fn parses_minimal_top_level_route() {
    let f = parse(
        r#"
            [[route]]
            hostname = "app.example.com"
            target = "http://192.168.1.10:8080"
            "#,
    )
    .unwrap();
    assert_eq!(f.route.len(), 1);
    assert_eq!(f.route[0].hostname, "app.example.com");
    assert_eq!(f.route[0].target.scheme(), "http");
    assert_eq!(f.route[0].target.port(), Some(8080));
    assert_eq!(f.route[0].hsts, None);
    f.validate_each().unwrap();
}

#[test]
fn route_rejects_invalid_hostname() {
    let f = parse(
        r#"
            [[route]]
            hostname = "*.example.com"
            target = "http://192.168.1.10:8080"
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(
        err,
        Some(Error::InvalidRule(s)) if s.contains("not a valid DNS name")
    ));
}

#[test]
fn route_rejects_non_http_target_scheme() {
    let f = parse(
        r#"
            [[route]]
            hostname = "app.example.com"
            target = "https://192.168.1.10:8080"
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(
        err,
        Some(Error::InvalidRule(s)) if s.contains("scheme must be \"http\"")
    ));
}

#[test]
fn route_accepts_default_http_port() {
    let f = parse(
        r#"
            [[route]]
            hostname = "app.example.com"
            target = "http://192.168.1.10"
            "#,
    )
    .unwrap();
    // `port_or_known_default()` returns 80 for an http: URL without an explicit port.
    f.validate_each().unwrap();
}

#[test]
fn route_hsts_shorthand_true_yields_defaults() {
    let f = parse(
        r#"
            [[route]]
            hostname = "app.example.com"
            target = "http://192.168.1.10:8080"
            hsts = true
            "#,
    )
    .unwrap();
    let hsts = f.route[0].hsts.unwrap();
    assert_eq!(hsts.max_age, DEFAULT_HSTS_MAX_AGE);
    assert!(!hsts.include_subdomains);
    assert!(!hsts.preload);
}

#[test]
fn route_hsts_shorthand_false_yields_none() {
    let f = parse(
        r#"
            [[route]]
            hostname = "app.example.com"
            target = "http://192.168.1.10:8080"
            hsts = false
            "#,
    )
    .unwrap();
    assert_eq!(f.route[0].hsts, None);
}

#[test]
fn route_hsts_explicit_table_overrides_defaults() {
    let f = parse(
        r#"
            [[route]]
            hostname = "app.example.com"
            target = "http://192.168.1.10:8080"

              [route.hsts]
              max_age = 600
              include_subdomains = true
              preload = true
            "#,
    )
    .unwrap();
    let hsts = f.route[0].hsts.unwrap();
    assert_eq!(hsts.max_age, 600);
    assert!(hsts.include_subdomains);
    assert!(hsts.preload);
}

#[test]
fn rule_set_aggregates_routes_across_files() {
    let f1 = parse(
        r#"
            [[route]]
            hostname = "a.example.com"
            target = "http://10.0.0.1:80"
            "#,
    )
    .unwrap();
    let f2 = parse(
        r#"
            [[route]]
            hostname = "b.example.com"
            target = "http://10.0.0.2:80"
            "#,
    )
    .unwrap();
    let rs = RuleSet::from_files([f1, f2]).unwrap();
    assert_eq!(rs.routes().len(), 2);
    let hosts: std::collections::HashSet<_> =
        rs.routes().iter().map(|r| r.hostname.as_str()).collect();
    assert!(hosts.contains("a.example.com"));
    assert!(hosts.contains("b.example.com"));
}

#[test]
fn rule_set_rejects_duplicate_route_hostnames_case_insensitive() {
    let f1 = parse(
        r#"
            [[route]]
            hostname = "App.Example.com"
            target = "http://10.0.0.1:80"
            "#,
    )
    .unwrap();
    let f2 = parse(
        r#"
            [[route]]
            hostname = "app.example.COM"
            target = "http://10.0.0.2:80"
            "#,
    )
    .unwrap();
    let err = RuleSet::from_files([f1, f2]).err();
    assert!(matches!(
        err,
        Some(Error::InvalidRule(s)) if s.contains("duplicate HTTPS route hostname")
    ));
}

#[test]
fn mixed_rule_and_route_in_same_file() {
    let f = parse(
        r#"
            [[rule]]
            name = "subnautica"
            listen = "0.0.0.0:34006"
            protocol = "udp"
            target = "127.0.0.1:11000"

            [[route]]
            hostname = "subnautica.janus.local"
            target = "http://192.168.156.7:8080"
            "#,
    )
    .unwrap();
    assert_eq!(f.rule.len(), 1);
    assert_eq!(f.route.len(), 1);
    f.validate_each().unwrap();
}

#[test]
fn https_protocol_serialises_as_lowercase() {
    // Protocol uses #[serde(rename_all = "lowercase")] so the
    // discriminator round-trips as a lowercase string. toml can't
    // serialise a top-level enum, so check via serde_json.
    let s = serde_json::to_string(&Protocol::Https).unwrap();
    assert_eq!(s, "\"https\"");
}

#[test]
fn http_route_static_headers_round_trip_and_validate() {
    let f = parse(
        r#"
            [[route]]
            hostname = "app.example.com"
            target = "http://192.168.1.10:8080"

            [route.headers]
            "X-Robots-Tag" = "noindex, nofollow, nosnippet, noarchive"
            "X-Frame-Options" = "DENY"
            "Content-Security-Policy" = "default-src 'self'"
            "#,
    )
    .unwrap();
    assert_eq!(f.route.len(), 1);
    let r = &f.route[0];
    assert_eq!(r.headers.len(), 3);
    assert_eq!(
        r.headers.get("X-Robots-Tag").map(String::as_str),
        Some("noindex, nofollow, nosnippet, noarchive"),
    );
    assert_eq!(
        r.headers.get("X-Frame-Options").map(String::as_str),
        Some("DENY"),
    );
    f.validate_each().unwrap();
}

#[test]
fn http_route_static_headers_default_to_empty() {
    let f = parse(
        r#"
            [[route]]
            hostname = "minimal.example.com"
            target = "http://10.0.0.1:80"
            "#,
    )
    .unwrap();
    assert!(f.route[0].headers.is_empty());
    f.validate_each().unwrap();
}

#[test]
fn http_route_rejects_hop_by_hop_static_header() {
    let f = parse(
        r#"
            [[route]]
            hostname = "bad.example.com"
            target = "http://10.0.0.1:80"

            [route.headers]
            "Connection" = "close"
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(
        matches!(err, Some(Error::InvalidRule(ref s)) if s.contains("reserved") && s.to_ascii_lowercase().contains("connection")),
        "expected hop-by-hop rejection, got {err:?}",
    );
}

#[test]
fn http_route_rejects_hsts_static_header() {
    let f = parse(
        r#"
            [[route]]
            hostname = "hsts.example.com"
            target = "http://10.0.0.1:80"

            [route.headers]
            "Strict-Transport-Security" = "max-age=63072000"
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(
        matches!(err, Some(Error::InvalidRule(ref s)) if s.contains("reserved") && s.to_ascii_lowercase().contains("strict-transport-security")),
        "expected HSTS rejection (use `hsts` field instead), got {err:?}",
    );
}

#[test]
fn http_route_rejects_forwarding_static_header() {
    let f = parse(
        r#"
            [[route]]
            hostname = "fwd.example.com"
            target = "http://10.0.0.1:80"

            [route.headers]
            "X-Forwarded-For" = "1.2.3.4"
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(
        matches!(err, Some(Error::InvalidRule(ref s)) if s.contains("reserved") && s.to_ascii_lowercase().contains("x-forwarded-for")),
        "expected forwarding-header rejection, got {err:?}",
    );
}

#[test]
fn http_route_rejects_invalid_header_name_character() {
    let f = parse(
        r#"
            [[route]]
            hostname = "x.example.com"
            target = "http://10.0.0.1:80"

            [route.headers]
            "Has Space" = "ok"
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(
        matches!(err, Some(Error::InvalidRule(ref s)) if s.contains("not allowed in an HTTP field name")),
        "expected invalid-name rejection, got {err:?}",
    );
}

#[test]
fn http_route_rejects_crlf_in_header_value() {
    // CRLF in a header value would be header-injection; reject loudly
    // at config load. Use a hand-built HttpRoute since TOML strips
    // some control characters at parse time.
    use super::HttpRoute;
    use std::collections::BTreeMap;
    let mut headers = BTreeMap::new();
    headers.insert(
        "X-Custom".to_string(),
        "ok\r\nInjected-Header: pwn".to_string(),
    );
    let route = HttpRoute {
        hostname: "x.example.com".to_string(),
        target: "http://10.0.0.1:80".parse().unwrap(),
        hsts: None,
        headers,
    };
    let err = super::validate::validate_http_route("<route>", &route).err();
    assert!(
        matches!(err, Some(Error::InvalidRule(ref s)) if s.contains("invalid value")),
        "expected CRLF-injection rejection, got {err:?}",
    );
}
