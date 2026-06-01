//! End-to-end test for HTTPS-predicate derivation across the chain.
//!
//! Terminal-mode supervisor publishes a top-level `[[route]]`. The
//! extractor emits a single `Protocol::Https` predicate carrying the
//! node-wide `https_http3` flag from `[server]`. The predicate is then
//! fed into `derive()` to spawn relay-side L4 listeners: one TCP (for
//! HTTP/2 over TLS) plus one UDP (for HTTP/3) when http3 is enabled.

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use ratatoskr::pubkey::PubKey;
use ratatoskr::rule::{Protocol, RuleFile, RuleSet};
use yggdrasil::chain::derive::{derive, DeriveConfig};
use yggdrasil::chain::predicate_extractor;

use crate::common::pick_free_tcp_port;

fn routes_ruleset() -> RuleSet {
    let toml = r#"
[[route]]
hostname = "localhost"
target = "http://127.0.0.1:65535"
"#;
    let rule_file = RuleFile::from_toml("routes.toml", toml).expect("parse routes file");
    RuleSet::from_files([rule_file]).expect("validate routes set")
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
    let rules = routes_ruleset();

    let meta = predicate_extractor::HttpsPredicateMeta {
        listen_port,
        http3: true,
    };
    let outcome = predicate_extractor::extract(&rules, meta, origin(), 1);

    let predicates = outcome.set;
    assert_eq!(predicates.predicates.len(), 1);
    let p = &predicates.predicates[0];
    assert_eq!(p.listen_port, listen_port);
    assert_eq!(p.protocol, Protocol::Https);
    assert!(p.https_http3, "http3 flag from meta should pass through");

    let derived = derive(&predicates, &derive_cfg()).expect("derive succeeds");

    assert_eq!(
        derived.rules().len(),
        2,
        "expected TCP and UDP rules from HTTPS+http3"
    );
    let tcp = derived
        .rules()
        .iter()
        .find(|r| r.protocol == Protocol::Tcp)
        .expect("tcp rule");
    assert_eq!(tcp.listen.port(), p.listen_port);
    assert_eq!(tcp.target_port, Some(p.listen_port));
    assert_eq!(
        tcp.proxy_protocol,
        Some(ratatoskr::rule::ProxyProto::V2),
        "HTTPS-derived TCP rule must carry PROXY v2 so the terminal's \
         HTTPS frontend can recover the real client IP for X-Forwarded-For"
    );

    let udp = derived
        .rules()
        .iter()
        .find(|r| r.protocol == Protocol::Udp)
        .expect("udp rule");
    assert_eq!(udp.listen.port(), p.listen_port);
    assert_eq!(udp.target_port, Some(p.listen_port));
    assert_eq!(udp.idle_timeout, Some(Duration::from_secs(30)));
    assert_eq!(
        udp.proxy_protocol,
        Some(ratatoskr::rule::ProxyProto::V2),
        "HTTPS-derived UDP rule must carry PROXY v2 so the relay can emit \
         the standalone first-datagram for the terminal's h3 interpose to \
         pick up the real client IP"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn https_predicate_with_http3_disabled_derives_tcp_only() {
    let listen_port = pick_free_tcp_port().await;
    let rules = routes_ruleset();

    let meta = predicate_extractor::HttpsPredicateMeta {
        listen_port,
        http3: false,
    };
    let outcome = predicate_extractor::extract(&rules, meta, origin(), 1);

    let predicates = outcome.set;
    assert_eq!(predicates.predicates.len(), 1);
    let p = &predicates.predicates[0];
    assert_eq!(p.listen_port, listen_port);
    assert_eq!(p.protocol, Protocol::Https);
    assert!(!p.https_http3, "explicit http3 = false should be preserved");

    let derived = derive(&predicates, &derive_cfg()).expect("derive succeeds");

    assert_eq!(
        derived.rules().len(),
        1,
        "expected only TCP rule when http3 is off"
    );
    let tcp = derived
        .rules()
        .iter()
        .find(|r| r.protocol == Protocol::Tcp)
        .expect("tcp rule");
    assert_eq!(tcp.listen.port(), p.listen_port);
    assert_eq!(tcp.target_port, Some(p.listen_port));
    assert_eq!(
        tcp.proxy_protocol,
        Some(ratatoskr::rule::ProxyProto::V2),
        "HTTPS-derived TCP rule must carry PROXY v2 even when http3 is off"
    );
    assert!(!derived.rules().iter().any(|r| r.protocol == Protocol::Udp));
}
