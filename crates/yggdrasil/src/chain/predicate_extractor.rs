//! Projection from a local [`RuleSet`] to a [`PredicateSet`].
//!
//! Every terminal in the chain owns a `RuleSet` parsed from its
//! `conf.d/*.toml`. To synchronise rules along the chain, the terminal
//! projects its rule set down to its **chain-invariant** fields and pushes
//! that projection to its upstream as a [`PredicateSet`]. The upstream
//! relay then derives a `RuleSet` from the predicate set
//! (see [`super::derive`]) to forward traffic toward the terminal.
//!
//! ## What is projected away
//!
//! * **Target fields** (`target_port`, `target_addr`, `target_host`)
//!   are stripped — every node in the chain resolves its own target
//!   locally (from heartbeat-discovered peer for relays, from the rule
//!   file for terminals).
//! * **PROXY-protocol toggle** is stripped — relays decide independently
//!   whether to emit PROXY headers based on their local
//!   `[accept]` configuration. The terminal cannot dictate that.
//! * **HTTPS routes / cert directories** are stripped. HTTPS rules are
//!   still projected as predicates, carrying only their listen port and
//!   whether HTTP/3 is enabled.
//!
//! ## Determinism
//!
//! The output `predicates` list is sorted by `name`. Combined with the
//! `version` counter, this gives byte-stable wire output for a given
//! logical rule set so the push side can suppress redundant retransmits
//! by comparing postcard digests.

use ratatoskr::predicate::{Predicate, PredicateSet};
use ratatoskr::pubkey::PubKey;
use ratatoskr::rule::{Protocol, Rule, RuleSet};

/// Project a [`RuleSet`] into a [`PredicateSet`] stamped with `origin`
/// and `version`.
///
/// HTTPS rules are projected as HTTPS predicates. Their route and
/// certificate fields remain terminal-local; only the chain-invariant
/// listen port and HTTP/3 enablement are carried upstream.
pub fn extract(ruleset: &RuleSet, origin: PubKey, version: u64) -> ExtractOutcome {
    let mut predicates = Vec::with_capacity(ruleset.rules().len());

    for rule in ruleset.rules() {
        match rule.protocol {
            Protocol::Tcp | Protocol::Udp => predicates.push(project_rule(rule)),
            Protocol::Https => predicates.push(project_https_rule(rule)),
        }
    }

    // Sort by name so postcard output is deterministic for any given
    // logical rule set.
    predicates.sort_by(|a, b| a.name.cmp(&b.name));

    ExtractOutcome {
        set: PredicateSet {
            predicates,
            version,
            origin,
        },
        skipped_https: Vec::new(),
    }
}

/// Output of [`extract`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractOutcome {
    /// The projected predicate set, ready to be postcard-encoded into a
    /// [`ControlEnvelope`] body.
    ///
    /// [`ControlEnvelope`]: ratatoskr::control_frame::ControlEnvelope
    pub set: PredicateSet,
    /// Compatibility field for control responses that used to report HTTPS
    /// rules skipped by projection. New extraction keeps HTTPS rules, so this
    /// is always empty.
    pub skipped_https: Vec<String>,
}

fn project_rule(rule: &Rule) -> Predicate {
    Predicate {
        name: rule.name.clone(),
        listen_port: rule.listen.port(),
        protocol: rule.protocol,
        idle_timeout_ms: match rule.protocol {
            Protocol::Udp => rule.idle_timeout.map(|d| {
                u64::try_from(d.as_millis())
                    // RuleSet validation caps idle_timeout well under
                    // u64::MAX milliseconds, but saturate defensively so
                    // a future schema change can't silently truncate.
                    .unwrap_or(u64::MAX)
            }),
            _ => None,
        },
        https_http3: false,
    }
}

fn project_https_rule(rule: &Rule) -> Predicate {
    Predicate {
        name: rule.name.clone(),
        listen_port: rule.listen.port(),
        protocol: Protocol::Https,
        // HTTPS predicates carry no UDP idle_timeout at the predicate level.
        // The derived UDP rule on the relay uses a hardcoded default.
        idle_timeout_ms: None,
        https_http3: rule.http3 != Some(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatoskr::auth::PUBLIC_KEY_LEN;
    use ratatoskr::pubkey::PubKey;
    use ratatoskr::rule::{HttpRoute, Rule};
    use std::net::SocketAddr;
    use std::time::Duration;
    use url::Url;

    fn ruleset_from(rules: Vec<Rule>) -> RuleSet {
        RuleSet::from_rules(rules).expect("test rule set must validate")
    }

    fn origin() -> PubKey {
        PubKey::x25519([0x11u8; PUBLIC_KEY_LEN])
    }

    fn tcp_rule(name: &str, port: u16, target_port: u16) -> Rule {
        Rule {
            name: name.to_string(),
            listen: SocketAddr::from(([0, 0, 0, 0], port)),
            protocol: Protocol::Tcp,
            target_port: Some(target_port),
            target_addr: None,
            target_host: None,
            idle_timeout: None,
            proxy_protocol: None,
            routes: None,
            cert_dir: None,
            http3: None,
            alt_svc: None,
        }
    }

    fn udp_rule(name: &str, port: u16, idle: Option<Duration>) -> Rule {
        Rule {
            name: name.to_string(),
            listen: SocketAddr::from(([0, 0, 0, 0], port)),
            protocol: Protocol::Udp,
            target_port: Some(port),
            target_addr: None,
            target_host: None,
            idle_timeout: idle,
            proxy_protocol: None,
            routes: None,
            cert_dir: None,
            http3: None,
            alt_svc: None,
        }
    }

    fn https_rule(name: &str, port: u16, http3: Option<bool>) -> Rule {
        Rule {
            name: name.to_string(),
            listen: SocketAddr::from(([0, 0, 0, 0], port)),
            protocol: Protocol::Https,
            target_port: None,
            target_addr: None,
            target_host: None,
            idle_timeout: None,
            proxy_protocol: None,
            routes: Some(vec![HttpRoute {
                hostname: format!("{name}.localhost"),
                target: Url::parse("http://127.0.0.1:8080").unwrap(),
                cert: None,
                key: None,
                hsts: None,
            }]),
            cert_dir: None,
            http3,
            alt_svc: None,
        }
    }

    #[test]
    fn extracts_tcp_and_udp_predicates() {
        let ruleset = ruleset_from(vec![
            tcp_rule("ssh", 2222, 22),
            udp_rule("dns", 53, Some(Duration::from_secs(30))),
        ]);
        let out = extract(&ruleset, origin(), 1);
        assert_eq!(out.set.version, 1);
        assert_eq!(out.set.origin, origin());
        assert_eq!(out.set.predicates.len(), 2);
        assert!(out.skipped_https.is_empty());
        // Sorted by name: dns < ssh.
        assert_eq!(out.set.predicates[0].name, "dns");
        assert_eq!(out.set.predicates[0].protocol, Protocol::Udp);
        assert_eq!(out.set.predicates[0].listen_port, 53);
        assert_eq!(out.set.predicates[0].idle_timeout_ms, Some(30_000));
        assert!(!out.set.predicates[0].https_http3);
        assert_eq!(out.set.predicates[1].name, "ssh");
        assert_eq!(out.set.predicates[1].protocol, Protocol::Tcp);
        assert_eq!(out.set.predicates[1].listen_port, 2222);
        assert_eq!(out.set.predicates[1].idle_timeout_ms, None);
        assert!(!out.set.predicates[1].https_http3);
    }

    #[test]
    fn extracts_https_default_http3_enabled() {
        let rule = https_rule("web-default", 8443, None);
        let listen_port = rule.listen.port();
        let out = extract(&ruleset_from(vec![rule]), origin(), 2);

        assert_eq!(out.set.predicates.len(), 1);
        assert!(out.skipped_https.is_empty());
        let predicate = &out.set.predicates[0];
        assert_eq!(predicate.name, "web-default");
        assert_eq!(predicate.protocol, Protocol::Https);
        assert_eq!(predicate.listen_port, listen_port);
        assert_eq!(predicate.idle_timeout_ms, None);
        assert!(predicate.https_http3);
    }

    #[test]
    fn extracts_https_explicit_http3_true() {
        let out = extract(
            &ruleset_from(vec![https_rule("web-h3", 9443, Some(true))]),
            origin(),
            3,
        );

        assert_eq!(out.set.predicates.len(), 1);
        assert_eq!(out.set.predicates[0].protocol, Protocol::Https);
        assert!(out.set.predicates[0].https_http3);
    }

    #[test]
    fn extracts_https_explicit_http3_false() {
        let out = extract(
            &ruleset_from(vec![https_rule("web-h2", 10443, Some(false))]),
            origin(),
            4,
        );

        assert_eq!(out.set.predicates.len(), 1);
        assert_eq!(out.set.predicates[0].protocol, Protocol::Https);
        assert!(!out.set.predicates[0].https_http3);
    }

    #[test]
    fn extracts_mixed_rules_in_name_order() {
        let ruleset = ruleset_from(vec![
            tcp_rule("ssh", 2222, 22),
            udp_rule("dns", 53, Some(Duration::from_secs(30))),
            https_rule("web", 8443, Some(false)),
        ]);
        let out = extract(&ruleset, origin(), 5);

        assert!(out.skipped_https.is_empty());
        assert_eq!(out.set.predicates.len(), 3);
        assert_eq!(out.set.predicates[0].name, "dns");
        assert_eq!(out.set.predicates[1].name, "ssh");
        assert_eq!(out.set.predicates[2].name, "web");

        let dns = &out.set.predicates[0];
        assert_eq!(dns.protocol, Protocol::Udp);
        assert_eq!(dns.listen_port, 53);
        assert_eq!(dns.idle_timeout_ms, Some(30_000));
        assert!(!dns.https_http3);

        let ssh = &out.set.predicates[1];
        assert_eq!(ssh.protocol, Protocol::Tcp);
        assert_eq!(ssh.listen_port, 2222);
        assert_eq!(ssh.idle_timeout_ms, None);
        assert!(!ssh.https_http3);

        let web = &out.set.predicates[2];
        assert_eq!(web.protocol, Protocol::Https);
        assert_eq!(web.listen_port, 8443);
        assert_eq!(web.idle_timeout_ms, None);
        assert!(!web.https_http3);
    }

    #[test]
    fn output_is_deterministic_across_input_order() {
        let a = ruleset_from(vec![
            tcp_rule("ssh", 2222, 22),
            https_rule("web", 8443, Some(true)),
            udp_rule("dns", 53, None),
        ]);
        let b = ruleset_from(vec![
            udp_rule("dns", 53, None),
            tcp_rule("ssh", 2222, 22),
            https_rule("web", 8443, Some(true)),
        ]);
        let out_a = extract(&a, origin(), 1);
        let out_b = extract(&b, origin(), 1);
        // Comparing the PredicateSet values directly is equivalent to
        // comparing their postcard encodings, because `PredicateSet`'s
        // Eq impl is field-wise and `Vec`'s ordering is preserved by
        // postcard. We avoid pulling postcard as a yggdrasil dev-dep.
        assert_eq!(out_a.set, out_b.set);
    }

    #[test]
    fn tcp_predicate_has_no_idle_timeout_even_if_rule_does() {
        // Defensive: TCP rules can't carry idle_timeout per validation, but
        // if some future bug lets one slip through, the extractor must
        // still produce a TCP predicate with idle_timeout_ms = None so
        // wire-form invariants hold.
        let mut rule = tcp_rule("ssh", 2222, 22);
        rule.idle_timeout = Some(Duration::from_secs(99));
        // Skip `from_rules` validation: we're testing the extractor's
        // own defensiveness, not the rule validator.
        let out = extract_via_unsorted_rules(vec![rule], origin(), 1);
        assert_eq!(out.set.predicates[0].idle_timeout_ms, None);
    }

    /// Test-only helper that runs the projection logic against a list of
    /// rules without going through `RuleSet::from_rules`.
    fn extract_via_unsorted_rules(
        rules: Vec<Rule>,
        origin: PubKey,
        version: u64,
    ) -> ExtractOutcome {
        let mut predicates = Vec::with_capacity(rules.len());
        for rule in &rules {
            match rule.protocol {
                Protocol::Tcp | Protocol::Udp => predicates.push(super::project_rule(rule)),
                Protocol::Https => predicates.push(super::project_https_rule(rule)),
            }
        }
        predicates.sort_by(|a, b| a.name.cmp(&b.name));
        ExtractOutcome {
            set: PredicateSet {
                predicates,
                version,
                origin,
            },
            skipped_https: Vec::new(),
        }
    }
}
