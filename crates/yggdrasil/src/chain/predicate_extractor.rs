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
//! * **Target fields** (`target_port`, `target`) are stripped — every
//!   node in the chain resolves its own target locally (from heartbeat-
//!   discovered peer for relays, from the rule file for terminals).
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
use ratatoskr::rule::{HttpRoute, Protocol, Rule, RuleSet};

/// Node-wide HTTPS metadata sourced from `[server]`. Threaded through
/// the extractor so the single HTTPS predicate carries the right
/// listener address and HTTP/3 flag without the extractor having to
/// know about `ServerConfig`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpsPredicateMeta {
    /// Port to advertise in the HTTPS predicate. Matches
    /// `[server].https_listen.port()`.
    pub listen_port: u16,
    /// HTTP/3 enable flag. Matches `[server].https_http3`.
    pub http3: bool,
}

impl Default for HttpsPredicateMeta {
    fn default() -> Self {
        Self {
            listen_port: 443,
            http3: true,
        }
    }
}

/// Project a [`RuleSet`] into a [`PredicateSet`] stamped with `origin`
/// and `version`.
///
/// L4 rules become L4 predicates. The top-level [[route]] collection
/// emits a single HTTPS predicate (when non-empty) projecting the
/// node-wide HTTPS listener; route hostnames stay terminal-local.
pub fn extract(
    ruleset: &RuleSet,
    https_meta: HttpsPredicateMeta,
    origin: PubKey,
    version: u64,
) -> ExtractOutcome {
    let mut predicates = Vec::with_capacity(ruleset.rules().len());

    for rule in ruleset.rules() {
        match rule.protocol {
            Protocol::Tcp | Protocol::Udp => predicates.push(project_rule(rule)),
            Protocol::Https => unreachable!(
                "Rule::validate rejects protocol = Https; HTTPS routes live in RuleSet::routes"
            ),
        }
    }

    if !ruleset.routes().is_empty() {
        predicates.push(project_routes(ruleset.routes(), https_meta));
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

fn project_routes(_routes: &[HttpRoute], meta: HttpsPredicateMeta) -> Predicate {
    // One HTTPS predicate per terminal — projects the node-wide HTTPS
    // listener that the operator's [server].https_listen configures.
    Predicate {
        name: "public-https".to_string(),
        listen_port: meta.listen_port,
        protocol: Protocol::Https,
        idle_timeout_ms: None,
        https_http3: meta.http3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatoskr::auth::X25519_PUBLIC_LEN;
    use ratatoskr::pubkey::PubKey;
    use ratatoskr::rule::{HttpRoute, Rule};
    use std::net::SocketAddr;
    use std::time::Duration;
    use url::Url;

    fn ruleset_from(rules: Vec<Rule>) -> RuleSet {
        RuleSet::from_rules(rules).expect("test rule set must validate")
    }

    fn origin() -> PubKey {
        PubKey::x25519([0x11u8; X25519_PUBLIC_LEN])
    }

    fn tcp_rule(name: &str, port: u16, target_port: u16) -> Rule {
        Rule {
            name: name.to_string(),
            listen: SocketAddr::from(([0, 0, 0, 0], port)),
            protocol: Protocol::Tcp,
            target_port: Some(target_port),
            target: None,
            idle_timeout: None,
            proxy_protocol: None,
        }
    }

    fn udp_rule(name: &str, port: u16, idle: Option<Duration>) -> Rule {
        Rule {
            name: name.to_string(),
            listen: SocketAddr::from(([0, 0, 0, 0], port)),
            protocol: Protocol::Udp,
            target_port: Some(port),
            target: None,
            idle_timeout: idle,
            proxy_protocol: None,
        }
    }

    fn route(host: &str) -> HttpRoute {
        HttpRoute {
            hostname: host.to_string(),
            target: Url::parse("http://127.0.0.1:8080").unwrap(),
            hsts: None,
            headers: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn extracts_tcp_and_udp_predicates() {
        let ruleset = ruleset_from(vec![
            tcp_rule("ssh", 2222, 22),
            udp_rule("dns", 53, Some(Duration::from_secs(30))),
        ]);
        let out = extract(&ruleset, HttpsPredicateMeta::default(), origin(), 1);
        assert_eq!(out.set.predicates.len(), 2);
        // Sorted by name: dns < ssh.
        assert_eq!(out.set.predicates[0].name, "dns");
        assert_eq!(out.set.predicates[0].protocol, Protocol::Udp);
        assert_eq!(out.set.predicates[0].idle_timeout_ms, Some(30_000));
        assert_eq!(out.set.predicates[1].name, "ssh");
        assert_eq!(out.set.predicates[1].protocol, Protocol::Tcp);
    }

    #[test]
    fn routes_project_to_single_https_predicate() {
        let routes = vec![route("app1.example.com"), route("app2.example.com")];
        let ruleset = RuleSet::from_parts(Vec::new(), routes).unwrap();
        let out = extract(&ruleset, HttpsPredicateMeta::default(), origin(), 1);
        // One HTTPS predicate carrying the node-wide listener,
        // regardless of how many routes.
        assert_eq!(out.set.predicates.len(), 1);
        let p = &out.set.predicates[0];
        assert_eq!(p.protocol, Protocol::Https);
        assert_eq!(p.listen_port, 443);
        assert!(p.https_http3);
    }

    #[test]
    fn empty_routes_emit_no_https_predicate() {
        let ruleset = ruleset_from(vec![tcp_rule("ssh", 2222, 22)]);
        let out = extract(&ruleset, HttpsPredicateMeta::default(), origin(), 1);
        assert_eq!(out.set.predicates.len(), 1);
        assert_eq!(out.set.predicates[0].protocol, Protocol::Tcp);
    }

    #[test]
    fn https_predicate_carries_meta_overrides() {
        // Operator-set [server].https_listen + https_http3 = false flows
        // straight through to the projected predicate.
        let routes = vec![route("app.example.com")];
        let ruleset = RuleSet::from_parts(Vec::new(), routes).unwrap();
        let meta = HttpsPredicateMeta {
            listen_port: 8443,
            http3: false,
        };
        let out = extract(&ruleset, meta, origin(), 1);
        let p = out
            .set
            .predicates
            .iter()
            .find(|p| p.protocol == Protocol::Https)
            .expect("HTTPS predicate present");
        assert_eq!(p.listen_port, 8443);
        assert!(!p.https_http3);
    }

    #[test]
    fn predicates_sorted_by_name_for_deterministic_postcard() {
        let ruleset = ruleset_from(vec![
            tcp_rule("z", 9001, 22),
            tcp_rule("a", 9002, 22),
            tcp_rule("m", 9003, 22),
        ]);
        let out = extract(&ruleset, HttpsPredicateMeta::default(), origin(), 7);
        let names: Vec<&str> = out.set.predicates.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["a", "m", "z"]);
    }

    #[test]
    fn tcp_predicate_has_no_idle_timeout_even_if_rule_does() {
        // Per-rule idle_timeout is UDP-only; the TCP predicate should
        // not carry it across the chain.
        let mut tcp = tcp_rule("ssh", 2222, 22);
        tcp.idle_timeout = None; // explicit
        let ruleset = ruleset_from(vec![tcp]);
        let out = extract(&ruleset, HttpsPredicateMeta::default(), origin(), 1);
        assert_eq!(out.set.predicates[0].idle_timeout_ms, None);
    }
}
