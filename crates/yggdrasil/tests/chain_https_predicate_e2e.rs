//! End-to-end test for HTTPS-predicate derivation across the chain.
//!
//! Terminal-mode supervisor publishes an HTTPS rule. The extractor emits
//! a `Protocol::Https` predicate with `https_http3 = true` (default). The
//! predicate is pushed to a relay-mode supervisor; the relay derives two
//! rules: a TCP listener and a UDP listener (for HTTP/3 traffic) both on
//! the predicate's port.
//!
//! This test exercises the rule-set bring-up only — no actual TLS or QUIC
//! traffic. Full HTTP/3 traffic-through-chain coverage lives in
//! `h3-tests-integration`.

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use ratatoskr::pubkey::PubKey;
use ratatoskr::rule::{Protocol, RuleFile, RuleSet};
use yggdrasil::chain::derive::{derive, DeriveConfig};
use yggdrasil::chain::predicate_extractor;

use crate::common::pick_free_tcp_port;

fn https_ruleset(listen_port: u16, rule_options: &str) -> RuleSet {
    let toml = format!(
        r#"
[[rule]]
name = "web"
listen = "127.0.0.1:{listen_port}"
protocol = "https"
{rule_options}
[[rule.route]]
hostname = "localhost"
target = "http://127.0.0.1:65535"
cert = "ephemeral"
"#,
    );
    let rule_file = RuleFile::from_toml("web.toml", &toml).expect("parse https rule");
    RuleSet::from_files([rule_file]).expect("validate https rule set")
}

fn derive_cfg() -> DeriveConfig {
    DeriveConfig {
        bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        proxy_protocol: None,
    }
}

fn origin() -> PubKey {
    PubKey::x25519([0x77; 32])
}

#[tokio::test(flavor = "multi_thread")]
async fn https_predicate_with_http3_derives_tcp_and_udp_on_relay() {
    let listen_port = pick_free_tcp_port().await;
    let rules = https_ruleset(listen_port, "");

    let outcome = predicate_extractor::extract(&rules, origin(), 1);
    assert!(outcome.skipped_https.is_empty());

    let predicates = outcome.set;
    assert_eq!(predicates.predicates.len(), 1);
    let p = &predicates.predicates[0];
    assert_eq!(p.name, "web");
    assert_eq!(p.listen_port, listen_port);
    assert_eq!(p.protocol, Protocol::Https);
    assert!(p.https_http3, "default http3 should be enabled");

    let derived = derive(&predicates, &derive_cfg()).expect("derive succeeds");

    assert_eq!(
        derived.rules().len(),
        2,
        "expected TCP and UDP rules from HTTPS+http3"
    );
    let tcp = derived.find("web-tcp").expect("web-tcp rule");
    assert_eq!(tcp.protocol, Protocol::Tcp);
    assert_eq!(tcp.listen.port(), p.listen_port);
    assert_eq!(tcp.target_port, Some(p.listen_port));

    let udp = derived.find("web-udp").expect("web-udp rule");
    assert_eq!(udp.protocol, Protocol::Udp);
    assert_eq!(udp.listen.port(), p.listen_port);
    assert_eq!(udp.target_port, Some(p.listen_port));
    assert_eq!(udp.idle_timeout, Some(Duration::from_secs(30)));
}

#[tokio::test(flavor = "multi_thread")]
async fn https_predicate_with_http3_disabled_derives_tcp_only() {
    let listen_port = pick_free_tcp_port().await;
    let rules = https_ruleset(listen_port, "http3 = false\n");

    let outcome = predicate_extractor::extract(&rules, origin(), 1);
    assert!(outcome.skipped_https.is_empty());

    let predicates = outcome.set;
    assert_eq!(predicates.predicates.len(), 1);
    let p = &predicates.predicates[0];
    assert_eq!(p.name, "web");
    assert_eq!(p.listen_port, listen_port);
    assert_eq!(p.protocol, Protocol::Https);
    assert!(!p.https_http3, "explicit http3 = false should be preserved");

    let derived = derive(&predicates, &derive_cfg()).expect("derive succeeds");

    assert_eq!(
        derived.rules().len(),
        1,
        "expected only TCP rule when http3 is off"
    );
    let tcp = derived.find("web-tcp").expect("web-tcp rule");
    assert_eq!(tcp.protocol, Protocol::Tcp);
    assert_eq!(tcp.listen.port(), p.listen_port);
    assert_eq!(tcp.target_port, Some(p.listen_port));
    assert!(derived.find("web-udp").is_none());
}
