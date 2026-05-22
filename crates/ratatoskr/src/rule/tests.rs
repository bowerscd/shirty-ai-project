//! Integration tests for the rule schema, validation, file loading, and
//! diff. Split out from the original monolithic `rule.rs` (Phase B1).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use url::Url;

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
    assert_eq!(r.target_addr, None);
    assert_eq!(r.idle_timeout, None);
    assert_eq!(r.udp_workers, None);
    assert_eq!(r.proxy_protocol, None);
    f.validate_each().unwrap();
}

#[test]
fn parses_terminal_style_tcp_rule() {
    let f = parse(
        r#"
            [[rule]]
            name = "home-ssh"
            listen = "0.0.0.0:2222"
            protocol = "tcp"
            target_addr = "192.168.1.10:22"
            "#,
    )
    .unwrap();
    let r = &f.rule[0];
    assert_eq!(r.target_port, None);
    assert_eq!(
        r.target_addr,
        Some("192.168.1.10:22".parse::<SocketAddr>().unwrap())
    );
    f.validate_each().unwrap();
}

#[test]
fn parses_terminal_style_udp_rule() {
    let f = parse(
        r#"
            [[rule]]
            name = "home-dns"
            listen = "0.0.0.0:53"
            protocol = "udp"
            target_addr = "192.168.1.1:53"
            idle_timeout = "30s"
            "#,
    )
    .unwrap();
    let r = &f.rule[0];
    assert_eq!(r.protocol, Protocol::Udp);
    assert_eq!(
        r.target_addr,
        Some("192.168.1.1:53".parse::<SocketAddr>().unwrap())
    );
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
fn parses_udp_rule_with_udp_workers() {
    let f = parse(
        r#"
            [[rule]]
            name = "dns"
            listen = "0.0.0.0:53"
            protocol = "udp"
            target_port = 53
            udp_workers = 4
            "#,
    )
    .unwrap();
    f.validate_each().unwrap();
    assert_eq!(f.rule[0].udp_workers, Some(4));

    let toml = toml::to_string(&f).unwrap();
    let back = parse(&toml).unwrap();
    back.validate_each().unwrap();
    assert_eq!(back.rule[0].udp_workers, Some(4));
}

#[test]
fn rejects_zero_udp_workers() {
    let f = parse(
        r#"
            [[rule]]
            name = "dns"
            listen = "0.0.0.0:53"
            protocol = "udp"
            target_port = 53
            udp_workers = 0
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(err, Some(Error::InvalidRule(s))
            if s.contains("udp_workers must be >= 1 when set")));
}

#[test]
fn rejects_udp_workers_on_tcp_rule() {
    let f = parse(
        r#"
            [[rule]]
            name = "ssh"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            target_port = 22
            udp_workers = 4
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(err, Some(Error::InvalidRule(s))
            if s.contains("udp_workers is only meaningful for UDP rules")));
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
    assert!(matches!(err, Some(Error::InvalidRule(s)) if s.contains("idle_timeout")));
}

#[test]
fn rejects_proxy_protocol_on_udp_rule() {
    let f = parse(
        r#"
            [[rule]]
            name = "dns"
            listen = "0.0.0.0:53"
            protocol = "udp"
            target_port = 53
            proxy_protocol = "v1"
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(err, Some(Error::InvalidRule(s)) if s.contains("proxy_protocol")));
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
    assert!(matches!(err, Some(Error::InvalidRule(s)) if s.contains("listen port")));
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
    assert!(matches!(err, Some(Error::InvalidRule(s)) if s.contains("target_port")));
}

#[test]
fn rejects_both_target_port_and_target_addr() {
    let f = parse(
        r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            target_port = 22
            target_addr = "192.168.1.1:22"
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(
        err,
        Some(Error::InvalidRule(s)) if s.contains("exactly one of target_port")
    ));
}

#[test]
fn rejects_neither_target_port_nor_target_addr() {
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
fn rejects_target_addr_with_zero_port() {
    let f = parse(
        r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            target_addr = "192.168.1.1:0"
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(
        err,
        Some(Error::InvalidRule(s)) if s.contains("target_addr port")
    ));
}

#[test]
fn rejects_proxy_protocol_with_target_addr() {
    let f = parse(
        r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            target_addr = "192.168.1.1:22"
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
fn parses_target_host_as_terminal_rule() {
    let f = parse(
        r#"
            [[rule]]
            name = "dns-rule"
            listen = "0.0.0.0:9100"
            protocol = "tcp"
            target_host = "printer.lan:9100"
            "#,
    )
    .unwrap();
    f.validate_each().expect("should validate");
    let h = f.rule[0].target_host.as_ref().expect("target_host set");
    assert_eq!(h.host, "printer.lan");
    assert_eq!(h.port, 9100);
}

#[test]
fn rejects_target_host_with_invalid_hostname() {
    // Wildcards are not valid DNS hostnames in `is_valid_dns_hostname`.
    let f = parse(
        r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            target_host = "*.example.com:22"
            "#,
    );
    // The Deserialize impl rejects this at TOML-parse time, so we expect
    // a TomlParse error rather than a validate error.
    assert!(f.is_err(), "*.example.com should be rejected at parse time");
    let msg = format!("{}", f.unwrap_err());
    assert!(msg.contains("not a valid DNS name"), "got: {msg}");
}

#[test]
fn rejects_target_host_with_zero_port() {
    let f = parse(
        r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            target_host = "host.example:0"
            "#,
    );
    assert!(f.is_err(), "zero port should be rejected at parse time");
    let msg = format!("{}", f.unwrap_err());
    assert!(msg.contains("non-zero"), "got: {msg}");
}

#[test]
fn rejects_target_host_missing_port() {
    let f = parse(
        r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            target_host = "hostnoport"
            "#,
    );
    assert!(f.is_err(), "missing port should be rejected at parse time");
    let msg = format!("{}", f.unwrap_err());
    assert!(
        msg.contains("expected \"hostname:port\"") || msg.contains("port"),
        "got: {msg}"
    );
}

#[test]
fn rejects_target_host_combined_with_target_addr() {
    let f = parse(
        r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            target_addr = "192.168.1.1:22"
            target_host = "example.lan:22"
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(
        err,
        Some(Error::InvalidRule(s)) if s.contains("not multiple")
    ));
}

#[test]
fn rejects_target_host_combined_with_target_port() {
    let f = parse(
        r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            target_port = 22
            target_host = "example.lan:22"
            "#,
    )
    .unwrap();
    let err = f.validate_each().err();
    assert!(matches!(
        err,
        Some(Error::InvalidRule(s)) if s.contains("not multiple")
    ));
}

#[test]
fn rejects_proxy_protocol_with_target_host() {
    let f = parse(
        r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            target_host = "example.lan:22"
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
    assert!(matches!(err, Some(Error::InvalidRule(s)) if s.contains("empty")));
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
    assert!(matches!(err, Some(Error::InvalidRule(s)) if s.contains("whitespace")));
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
    assert!(matches!(err, Some(Error::InvalidRule(s)) if s.contains("duplicate rule name")));
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

fn https_rule_file(name: &str, listen: &str) -> RuleFile {
    let hostname = name.replace('_', "-");
    parse(&format!(
        r#"
            [[rule]]
            name = "{name}"
            listen = "{listen}"
            protocol = "https"

              [[rule.route]]
              hostname = "{hostname}.local"
              target = "http://127.0.0.1:8080"
              cert     = "ephemeral"
            "#,
    ))
    .unwrap()
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

#[test]
fn rule_set_allows_https_rules_on_different_ports() {
    let set = RuleSet::from_files([
        https_rule_file("https-443", "0.0.0.0:443"),
        https_rule_file("https-8443", "0.0.0.0:8443"),
    ])
    .unwrap();
    assert_eq!(set.len(), 2);
}

#[test]
fn rule_set_allows_https_and_udp_on_different_ips_same_port() {
    let set = RuleSet::from_files([
        https_rule_file("https-a", "192.0.2.1:443"),
        l4_rule_file("udp-b", "192.0.2.2:443", Protocol::Udp),
    ])
    .unwrap();
    assert_eq!(set.len(), 2);
}

#[test]
fn rule_set_rejects_https_and_tcp_on_same_listen_addr() {
    let err = RuleSet::from_files([
        https_rule_file("https-web", "0.0.0.0:443"),
        l4_rule_file("tcp-web", "0.0.0.0:443", Protocol::Tcp),
    ])
    .unwrap_err();
    let Error::InvalidRule(msg) = err else {
        panic!("expected InvalidRule");
    };
    assert!(msg.contains("\"https-web\""), "got: {msg}");
    assert!(msg.contains("\"tcp-web\""), "got: {msg}");
    assert!(msg.contains("(https)"), "got: {msg}");
    assert!(msg.contains("(tcp)"), "got: {msg}");
    assert!(
        msg.contains("HTTPS rules implicitly claim both TCP and UDP"),
        "got: {msg}"
    );
}

#[test]
fn rule_set_rejects_https_and_udp_on_same_listen_addr() {
    let err = RuleSet::from_files([
        l4_rule_file("udp-web", "0.0.0.0:443", Protocol::Udp),
        https_rule_file("https-web", "0.0.0.0:443"),
    ])
    .err();
    assert!(matches!(err, Some(Error::InvalidRule(s))
            if s.contains("HTTPS rules implicitly claim both TCP and UDP")));
}

#[test]
fn rule_set_rejects_two_https_rules_on_same_listen_addr() {
    let err = RuleSet::from_files([
        https_rule_file("https-a", "0.0.0.0:443"),
        https_rule_file("https-b", "0.0.0.0:443"),
    ])
    .err();
    assert!(matches!(err, Some(Error::InvalidRule(s))
            if s.contains("duplicate listen address") && s.contains("protocol https")));
}

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
    assert_eq!(f.rule[0].udp_workers, None);
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
    RuleSet::from_files([RuleFile { rule: rules }]).unwrap()
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

fn parse_one(s: &str) -> Result<Rule> {
    let f = parse(s)?;
    assert_eq!(f.rule.len(), 1);
    Ok(f.rule.into_iter().next().unwrap())
}

#[test]
fn parses_minimal_https_rule_with_ephemeral_cert() {
    let r = parse_one(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "app.localhost"
              target = "http://127.0.0.1:8080"
              cert     = "ephemeral"
            "#,
    )
    .unwrap();
    assert_eq!(r.protocol, Protocol::Https);
    let routes = r.routes.as_ref().expect("routes present");
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].hostname, "app.localhost");
    assert_eq!(routes[0].target.scheme(), "http");
    assert_eq!(routes[0].target.port(), Some(8080));
    assert_eq!(routes[0].cert, Some(CertSource::Ephemeral));
    assert_eq!(routes[0].key, None);
    assert_eq!(routes[0].hsts, None);
    r.validate().expect("schema-valid");
}

#[test]
fn parses_https_rule_with_path_cert_and_key() {
    let r = parse_one(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "api.home.example"
              target = "http://192.168.1.10:8080"
              cert     = "/tls/api/fullchain.pem"
              key      = "/tls/api/privkey.pem"
            "#,
    )
    .unwrap();
    let route = &r.routes.as_ref().unwrap()[0];
    assert_eq!(
        route.cert,
        Some(CertSource::Path(PathBuf::from("/tls/api/fullchain.pem")))
    );
    assert_eq!(route.key, Some(PathBuf::from("/tls/api/privkey.pem")));
    r.validate().unwrap();
}

#[test]
fn https_rule_accepts_multiple_routes_and_distinct_hosts() {
    let r = parse_one(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "a.local"
              target = "http://10.0.0.1:80"
              cert     = "ephemeral"

              [[rule.route]]
              hostname = "b.local"
              target = "http://10.0.0.2:80"
              cert     = "ephemeral"
            "#,
    )
    .unwrap();
    assert_eq!(r.routes.as_ref().unwrap().len(), 2);
    r.validate().unwrap();
}

#[test]
fn https_rule_rejects_duplicate_route_hostnames_case_insensitive() {
    let err = parse_one(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "App.local"
              target = "http://10.0.0.1:80"
              cert     = "ephemeral"

              [[rule.route]]
              hostname = "app.LOCAL"
              target = "http://10.0.0.2:80"
              cert     = "ephemeral"
            "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();
    assert!(matches!(err, Error::InvalidRule(s) if s.contains("duplicate route hostname")));
}

#[test]
fn https_rule_requires_non_empty_routes() {
    let err = parse_one(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"
            "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();
    assert!(
        matches!(err, Error::InvalidRule(s) if s.contains("requires at least one")),
        "expected 'requires at least one' error"
    );
}

#[test]
fn https_rule_rejects_target_port() {
    let err = parse_one(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"
            target_port = 80

              [[rule.route]]
              hostname = "x.local"
              target = "http://127.0.0.1:80"
              cert     = "ephemeral"
            "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();
    assert!(matches!(err, Error::InvalidRule(s) if s.contains("`target_port` is not valid")),);
}

#[test]
fn https_rule_rejects_target_addr() {
    let err = parse_one(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"
            target_addr = "127.0.0.1:80"

              [[rule.route]]
              hostname = "x.local"
              target = "http://127.0.0.1:80"
              cert     = "ephemeral"
            "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();
    assert!(matches!(err, Error::InvalidRule(s) if s.contains("`target_addr` is not valid")),);
}

#[test]
fn https_rule_rejects_target_host() {
    let err = parse_one(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"
            target_host = "backend.lan:80"

              [[rule.route]]
              hostname = "x.local"
              target = "http://127.0.0.1:80"
              cert     = "ephemeral"
            "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();
    assert!(matches!(err, Error::InvalidRule(s) if s.contains("`target_host` is not valid")),);
}

#[test]
fn https_rule_rejects_proxy_protocol() {
    let err = parse_one(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"
            proxy_protocol = "v2"

              [[rule.route]]
              hostname = "x.local"
              target = "http://127.0.0.1:80"
              cert     = "ephemeral"
            "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();
    assert!(matches!(err, Error::InvalidRule(s) if s.contains("`proxy_protocol` is not valid")),);
}

#[test]
fn https_rule_rejects_idle_timeout() {
    let err = parse_one(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"
            idle_timeout = "30s"

              [[rule.route]]
              hostname = "x.local"
              target = "http://127.0.0.1:80"
              cert     = "ephemeral"
            "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();
    assert!(matches!(err, Error::InvalidRule(s) if s.contains("`idle_timeout`")));
}

#[test]
fn tcp_rule_rejects_route_blocks() {
    let err = parse(
        r#"
            [[rule]]
            name = "x"
            listen = "0.0.0.0:1234"
            protocol = "tcp"
            target_port = 22

              [[rule.route]]
              hostname = "x.local"
              target = "http://127.0.0.1:80"
              cert     = "ephemeral"
            "#,
    )
    .unwrap()
    .validate_each()
    .unwrap_err();
    assert!(matches!(err, Error::InvalidRule(s) if s.contains("`route` blocks are only valid")));
}

#[test]
fn tcp_rule_rejects_cert_dir() {
    let err = parse(
        r#"
            [[rule]]
            name = "x"
            listen = "0.0.0.0:1234"
            protocol = "tcp"
            target_port = 22
            cert_dir = "/tls"
            "#,
    )
    .unwrap()
    .validate_each()
    .unwrap_err();
    assert!(matches!(err, Error::InvalidRule(s) if s.contains("`cert_dir` is only valid")));
}

#[test]
fn https_rule_rejects_non_http_target_scheme() {
    let err = parse_one(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "x.local"
              target = "https://10.0.0.1:443"
              cert     = "ephemeral"
            "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();
    assert!(matches!(err, Error::InvalidRule(s) if s.contains("target URL scheme")),);
}

#[test]
fn https_rule_accepts_target_with_default_http_port() {
    // http://10.0.0.1 (no explicit port) → url crate sets known default
    // port 80; we accept it. Adopting the URL semantics avoids forcing
    // operators to write `:80` redundantly.
    let r = parse_one(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "x.local"
              target = "http://10.0.0.1"
              cert     = "ephemeral"
            "#,
    )
    .unwrap();
    r.validate().unwrap();
    assert_eq!(
        r.routes.as_ref().unwrap()[0].target.port_or_known_default(),
        Some(80)
    );
}

#[test]
fn https_rule_rejects_path_cert_without_key() {
    let err = parse_one(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "api.home.example"
              target = "http://10.0.0.1:80"
              cert     = "/tls/cert.pem"
            "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();
    assert!(matches!(err, Error::InvalidRule(s) if s.contains("`key` must also")));
}

#[test]
fn https_rule_rejects_ephemeral_cert_with_key() {
    let err = parse_one(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "x.local"
              target = "http://10.0.0.1:80"
              cert     = "ephemeral"
              key      = "/tls/k.pem"
            "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();
    assert!(matches!(err, Error::InvalidRule(s) if s.contains("does not take a separate")));
}

#[test]
fn https_rule_rejects_key_without_cert() {
    let err = parse_one(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "x.local"
              target = "http://10.0.0.1:80"
              key      = "/tls/k.pem"
            "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();
    assert!(matches!(err, Error::InvalidRule(s) if s.contains("but no `cert` is provided")));
}

#[test]
fn https_rule_ephemeral_allows_localhost_pattern_hostnames() {
    for host in [
        "localhost",
        "app.localhost",
        "deep.nested.localhost",
        "thing.local",
        "raspberrypi.local",
    ] {
        let r = parse_one(&format!(
            r#"
                [[rule]]
                name = "h"
                listen = "0.0.0.0:443"
                protocol = "https"

                  [[rule.route]]
                  hostname = "{host}"
                  target = "http://127.0.0.1:8080"
                  cert     = "ephemeral"
                "#
        ))
        .unwrap();
        r.validate()
            .unwrap_or_else(|e| panic!("hostname {host:?} unexpectedly rejected: {e:?}"));
    }
}

#[test]
fn https_rule_ephemeral_rejects_public_hostnames() {
    let err = parse_one(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "api.example.com"
              target = "http://127.0.0.1:8080"
              cert     = "ephemeral"
            "#,
    )
    .unwrap()
    .validate()
    .unwrap_err();
    assert!(matches!(err, Error::InvalidRule(s) if s.contains("only allowed for")));
}

#[test]
fn https_rule_rejects_invalid_dns_hostname() {
    for bad in [
        "-leading-dash.local",
        "trailing-dash-.local",
        "label..double-dot.local",
        "white space.local",
    ] {
        let err = parse_one(&format!(
            r#"
                [[rule]]
                name = "h"
                listen = "0.0.0.0:443"
                protocol = "https"

                  [[rule.route]]
                  hostname = "{bad}"
                  target = "http://127.0.0.1:8080"
                  cert     = "ephemeral"
                "#
        ))
        .unwrap()
        .validate()
        .unwrap_err();
        assert!(
            matches!(err, Error::InvalidRule(s) if s.contains("not a valid DNS name")),
            "hostname {bad:?} should have been rejected as malformed"
        );
    }
}

#[test]
fn https_rule_hsts_shorthand_true_yields_defaults() {
    let r = parse_one(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "x.local"
              target = "http://10.0.0.1:80"
              cert     = "ephemeral"
              hsts     = true
            "#,
    )
    .unwrap();
    let hsts = r.routes.as_ref().unwrap()[0]
        .hsts
        .expect("hsts shorthand parsed");
    assert_eq!(hsts.max_age, DEFAULT_HSTS_MAX_AGE);
    assert!(!hsts.include_subdomains);
    assert!(!hsts.preload);
}

#[test]
fn https_rule_hsts_shorthand_false_yields_none() {
    let r = parse_one(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "x.local"
              target = "http://10.0.0.1:80"
              cert     = "ephemeral"
              hsts     = false
            "#,
    )
    .unwrap();
    assert_eq!(r.routes.as_ref().unwrap()[0].hsts, None);
}

#[test]
fn https_rule_hsts_explicit_table_overrides_defaults() {
    let r = parse_one(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "x.local"
              target = "http://10.0.0.1:80"
              cert     = "ephemeral"

              [rule.route.hsts]
              max_age = 600
              include_subdomains = true
              preload = true
            "#,
    )
    .unwrap();
    let hsts = r.routes.as_ref().unwrap()[0].hsts.unwrap();
    assert_eq!(hsts.max_age, 600);
    assert!(hsts.include_subdomains);
    assert!(hsts.preload);
}

#[test]
fn cert_source_deserialises_ephemeral_string() {
    let cs: CertSource = toml::from_str("v = \"ephemeral\"\n")
        .map(|t: toml::Table| t["v"].clone().try_into::<CertSource>().unwrap())
        .unwrap();
    assert_eq!(cs, CertSource::Ephemeral);
}

#[test]
fn cert_source_deserialises_path_string() {
    let cs: CertSource = toml::from_str("v = \"/tls/x.pem\"\n")
        .map(|t: toml::Table| t["v"].clone().try_into::<CertSource>().unwrap())
        .unwrap();
    assert_eq!(cs, CertSource::Path(PathBuf::from("/tls/x.pem")));
}

#[test]
fn cert_source_rejects_empty_string() {
    let err: Result<CertSource> = toml::from_str("v = \"\"\n")
        .map(|t: toml::Table| {
            t["v"].clone().try_into::<CertSource>().map_err(|e| {
                // Box the toml::de::Error into Error::InvalidRule for
                // uniform handling in the assertion below.
                Error::InvalidRule(e.to_string())
            })
        })
        .unwrap();
    assert!(err.is_err());
}

#[test]
fn https_protocol_serialises_as_lowercase() {
    let p = Protocol::Https;
    let v = serde_json::to_string(&p).unwrap();
    assert_eq!(v, "\"https\"");
    assert_eq!(p.as_str(), "https");
}

fn https_rule_with_options(extra: &str) -> String {
    format!(
        r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"
            {extra}

              [[rule.route]]
              hostname = "app.local"
              target = "http://127.0.0.1:8080"
              cert     = "ephemeral"
            "#,
    )
}

#[test]
fn https_rule_parses_http3_true() {
    let r = parse_one(&https_rule_with_options("http3 = true")).unwrap();
    r.validate().unwrap();
    assert_eq!(r.http3, Some(true));
    assert_eq!(r.alt_svc, None);
}

#[test]
fn https_rule_parses_http3_false() {
    let r = parse_one(&https_rule_with_options("http3 = false")).unwrap();
    r.validate().unwrap();
    assert_eq!(r.http3, Some(false));
    assert_eq!(r.alt_svc, None);
}

#[test]
fn https_rule_defaults_h3_options_to_absent() {
    let r = parse_one(&https_rule_with_options("")).unwrap();
    r.validate().unwrap();
    assert_eq!(r.http3, None);
    assert_eq!(r.alt_svc, None);
}

#[test]
fn https_rule_accepts_http3_false_and_alt_svc_false() {
    let r = parse_one(&https_rule_with_options(
        "http3 = false\n            alt_svc = false",
    ))
    .unwrap();
    r.validate().unwrap();
    assert_eq!(r.http3, Some(false));
    assert_eq!(r.alt_svc, Some(false));
}

#[test]
fn https_rule_accepts_alt_svc_true_alone() {
    let r = parse_one(&https_rule_with_options("alt_svc = true")).unwrap();
    r.validate().unwrap();
    assert_eq!(r.http3, None);
    assert_eq!(r.alt_svc, Some(true));
}

#[test]
fn https_rule_rejects_alt_svc_true_when_http3_disabled() {
    let err = parse_one(&https_rule_with_options(
        "http3 = false\n            alt_svc = true",
    ))
    .unwrap()
    .validate()
    .unwrap_err();
    assert!(matches!(err, Error::InvalidRule(s)
            if s.contains("`alt_svc = true` is incompatible with `http3 = false`")));
}

#[test]
fn tcp_rule_rejects_http3() {
    let err = parse(
        r#"
            [[rule]]
            name = "ssh"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            target_port = 22
            http3 = true
            "#,
    )
    .unwrap()
    .validate_each()
    .unwrap_err();
    assert!(matches!(err, Error::InvalidRule(s)
            if s.contains("`http3` is only meaningful for `protocol = \"https\"` rules")));
}

#[test]
fn udp_rule_rejects_alt_svc() {
    let err = parse(
        r#"
            [[rule]]
            name = "dns"
            listen = "0.0.0.0:53"
            protocol = "udp"
            target_port = 53
            alt_svc = true
            "#,
    )
    .unwrap()
    .validate_each()
    .unwrap_err();
    assert!(matches!(err, Error::InvalidRule(s)
            if s.contains("`alt_svc` is only meaningful for `protocol = \"https\"` rules")));
}

#[test]
fn https_h3_options_toml_round_trip() {
    let rule = Rule {
        name: "h".to_string(),
        listen: "0.0.0.0:443".parse().unwrap(),
        protocol: Protocol::Https,
        target_port: None,
        target_addr: None,
        target_host: None,
        idle_timeout: None,
        udp_workers: None,
        proxy_protocol: None,
        routes: Some(vec![HttpRoute {
            hostname: "app.local".to_string(),
            target: Url::parse("http://127.0.0.1:8080").unwrap(),
            cert: Some(CertSource::Ephemeral),
            key: None,
            hsts: None,
        }]),
        cert_dir: None,
        http3: Some(false),
        alt_svc: Some(false),
    };
    rule.validate().unwrap();
    let f = RuleFile {
        rule: vec![rule.clone()],
    };
    let toml = toml::to_string(&f).unwrap();
    assert!(toml.contains("http3 = false"), "toml was: {toml}");
    assert!(toml.contains("alt_svc = false"), "toml was: {toml}");
    let back = parse(&toml).unwrap();
    back.validate_each().unwrap();
    assert_eq!(back.rule[0], rule);
}
