//! Relay-side derivation: [`PredicateSet`] → [`RuleSet`].
//!
//! When a relay receives a [`PredicateSet`] from its downstream over the
//! chain control channel, it synthesises a local [`RuleSet`] that
//! forwards traffic for each predicate back down toward the downstream.
//! The derived rules are then handed to the proxy supervisor via
//! [`crate::proxy::supervisor::SupervisorHandle::apply_ruleset`]; this
//! module is the pure projection.
//!
//! ## What the relay supplies (per-node local)
//!
//! [`DeriveConfig`] carries the fields a predicate cannot specify on
//! behalf of the relay:
//!
//! * `bind_addr` — the local interface the derived listener binds to.
//!   Predicates only carry `listen_port`; choosing which IP to bind on
//!   is a local policy decision (e.g. `0.0.0.0`, a specific WAN IP, or a
//!   wireguard tunnel address).
//! * `proxy_protocol` — applied to derived **TCP** rules so the relay
//!   emits a PROXY-protocol header before forwarding. UDP and any other
//!   protocol ignore this field. Every chain-derived HTTPS rule has
//!   this set so the terminal sees the original client IP via the
//!   header rather than the relay's source IP.
//!
//! ## What the derive function fills in
//!
//! TCP/UDP predicates produce one [`Rule`]. HTTPS predicates reserve the
//! entire listen port: they always claim both TCP and UDP listen slots so a
//! separate TCP/UDP predicate cannot shadow the port. They produce a TCP rule
//! and, when HTTP/3 is enabled, a UDP rule for QUIC:
//!
//! * `listen = (bind_addr, predicate.listen_port)`.
//! * `target_port = Some(predicate.listen_port)` — relay mode: dial
//!   the heartbeat-discovered downstream peer on the same port the
//!   predicate listens on. The downstream IP lives in the heartbeat
//!   session state, not in the derived rule.
//! * For TCP/UDP predicates: `name`, `protocol`, `idle_timeout`, and
//!   TCP `proxy_protocol` are projected from the predicate/config.
//! * For HTTPS predicates: rule names are suffixed with `-tcp` and
//!   optional `-udp`; the UDP HTTP/3 rule uses a 30 s idle timeout.
//!
//! ## Errors
//!
//! [`derive`] returns [`DeriveError`] on any validation failure. The
//! caller maps these to `AckStatus::Reject(code)` using the reason codes
//! in [`predicate_reject`](ratatoskr::predicate::predicate_reject).
//!
//! [`PredicateSet`]: ratatoskr::predicate::PredicateSet

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ratatoskr::predicate::{predicate_reject, Predicate, PredicateSet};
use ratatoskr::rule::{Protocol, ProxyProto, Rule, RuleSet};

/// Local-only fields the relay supplies to fill in derivable rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeriveConfig {
    /// Local interface to bind the derived listener on. Combined with
    /// each predicate's `listen_port` to form the rule's `listen`
    /// SocketAddr.
    pub bind_addr: IpAddr,
    /// PROXY-protocol version to emit on derived TCP rules. `None`
    /// disables PROXY emission; UDP rules ignore this field unconditionally.
    pub proxy_protocol: Option<ProxyProto>,
}

/// Failure modes for [`derive`].
///
/// Each variant maps to a stable
/// [`predicate_reject`](ratatoskr::predicate::predicate_reject) code via
/// [`DeriveError::reject_code`]; the caller embeds that code in an
/// `AckStatus::Reject(u16)` on the wire.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeriveError {
    /// A predicate's `name` is empty or contains whitespace/control chars.
    #[error("predicate {0:?}: invalid name")]
    InvalidName(String),
    /// A predicate's `listen_port` is zero. Port 0 makes no sense for a
    /// fixed-listener proxy.
    #[error("predicate {0:?}: listen_port must be non-zero")]
    ZeroListenPort(String),
    /// Two predicates share the same `name`. Names must be unique across
    /// a single predicate set.
    #[error("duplicate predicate name {0:?}")]
    DuplicateName(String),
    /// Two predicates would derive rules with the same rule name.
    #[error("predicates {first:?} and {second:?} derive duplicate rule name {rule_name:?}")]
    DuplicateRuleName {
        rule_name: String,
        first: String,
        second: String,
    },
    /// Two predicates share the same `(protocol, listen_port)` pair; the
    /// derived rule set would not be bindable.
    #[error("predicates {first:?} and {second:?} share {protocol} listen_port {port}")]
    DuplicateListenPort {
        first: String,
        second: String,
        protocol: &'static str,
        port: u16,
    },
    /// A predicate shares a listen port with an HTTPS predicate. HTTPS
    /// reserves both TCP and UDP on its port even when HTTP/3 is disabled,
    /// so enabling HTTP/3 later cannot turn a valid set into a collision.
    #[error("predicate {other_name:?} shares {protocol} port {port} reserved by HTTPS predicate {https_name:?}")]
    HttpsListenCollision {
        https_name: String,
        other_name: String,
        protocol: &'static str,
        port: u16,
    },
}

impl DeriveError {
    /// Map this error to the stable wire reject code carried in
    /// `AckStatus::Reject(u16)`.
    pub fn reject_code(&self) -> u16 {
        match self {
            Self::InvalidName(_)
            | Self::ZeroListenPort(_)
            | Self::DuplicateName(_)
            | Self::DuplicateRuleName { .. }
            | Self::DuplicateListenPort { .. }
            | Self::HttpsListenCollision { .. } => predicate_reject::INVALID_PREDICATE,
        }
    }
}

/// Derive a local [`RuleSet`] from a received [`PredicateSet`].
///
/// The caller is responsible for sequencing: only invoke `derive` after
/// the predicate set has passed the version-monotonicity check
/// (otherwise the relay would happily reapply stale state).
pub fn derive(set: &PredicateSet, cfg: &DeriveConfig) -> Result<RuleSet, DeriveError> {
    let mut seen_names: HashSet<&str> = HashSet::with_capacity(set.predicates.len());
    let mut seen_rule_names: HashMap<String, String> =
        HashMap::with_capacity(set.predicates.len() * 2);
    let mut seen_listens: Vec<ListenClaim> = Vec::with_capacity(set.predicates.len() * 2);
    let mut rules = Vec::with_capacity(set.predicates.len() * 2);

    for predicate in &set.predicates {
        validate_predicate(predicate)?;

        if !seen_names.insert(predicate.name.as_str()) {
            return Err(DeriveError::DuplicateName(predicate.name.clone()));
        }

        match predicate.protocol {
            Protocol::Tcp | Protocol::Udp => {
                insert_rule_name_claim(
                    &mut seen_rule_names,
                    predicate.name.clone(),
                    &predicate.name,
                )?;
                insert_listen_claim(&mut seen_listens, ListenClaim::l4(predicate))?;
                rules.push(rule_from_predicate_l4(predicate, cfg));
            }
            Protocol::Https => {
                let tcp_name = derived_https_rule_name(predicate, Protocol::Tcp);
                insert_rule_name_claim(&mut seen_rule_names, tcp_name, &predicate.name)?;
                if predicate.https_http3 {
                    let udp_name = derived_https_rule_name(predicate, Protocol::Udp);
                    insert_rule_name_claim(&mut seen_rule_names, udp_name, &predicate.name)?;
                }

                // HTTPS reserves the whole port, including UDP when HTTP/3 is
                // currently disabled, so enabling HTTP/3 later cannot make a
                // previously valid predicate set collide.
                insert_listen_claim(
                    &mut seen_listens,
                    ListenClaim::https(predicate, Protocol::Tcp),
                )?;
                insert_listen_claim(
                    &mut seen_listens,
                    ListenClaim::https(predicate, Protocol::Udp),
                )?;

                rules.push(rule_from_https_predicate(predicate, cfg, Protocol::Tcp));
                if predicate.https_http3 {
                    rules.push(rule_from_https_predicate(predicate, cfg, Protocol::Udp));
                }
            }
        }
    }

    // Cross-rule validation (duplicate names, duplicate listen sockets)
    // is enforced inline above with predicate-flavoured error messages;
    // delegate per-rule + cross-rule validation to `RuleSet::from_rules`
    // as a defensive belt-and-braces (any unexpected validation gap
    // upstream surfaces as an invalid-predicate rejection).
    RuleSet::from_rules(rules).map_err(|e| {
        // RuleSet's error is operator-formatted; collapse to the
        // predicate-flavoured invalid-name variant so the wire reject
        // code path is unambiguous.
        DeriveError::InvalidName(e.to_string())
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ListenClaim {
    protocol: Protocol,
    port: u16,
    predicate_name: String,
    derived_from_https: bool,
}

impl ListenClaim {
    fn l4(p: &Predicate) -> Self {
        debug_assert!(matches!(p.protocol, Protocol::Tcp | Protocol::Udp));
        Self {
            protocol: p.protocol,
            port: p.listen_port,
            predicate_name: p.name.clone(),
            derived_from_https: false,
        }
    }

    fn https(p: &Predicate, derived_protocol: Protocol) -> Self {
        debug_assert!(matches!(derived_protocol, Protocol::Tcp | Protocol::Udp));
        Self {
            protocol: derived_protocol,
            port: p.listen_port,
            predicate_name: p.name.clone(),
            derived_from_https: true,
        }
    }
}

fn insert_rule_name_claim(
    seen: &mut HashMap<String, String>,
    rule_name: String,
    predicate_name: &str,
) -> Result<(), DeriveError> {
    if let Some(first) = seen.get(&rule_name).cloned() {
        return Err(DeriveError::DuplicateRuleName {
            rule_name,
            first,
            second: predicate_name.to_string(),
        });
    }
    seen.insert(rule_name, predicate_name.to_string());
    Ok(())
}

fn insert_listen_claim(seen: &mut Vec<ListenClaim>, claim: ListenClaim) -> Result<(), DeriveError> {
    if let Some(existing) = seen
        .iter()
        .find(|existing| existing.protocol == claim.protocol && existing.port == claim.port)
        .cloned()
    {
        return Err(listen_collision_error(&existing, &claim));
    }

    if let Some(existing) = seen
        .iter()
        .find(|existing| {
            existing.port == claim.port && (existing.derived_from_https != claim.derived_from_https)
        })
        .cloned()
    {
        return Err(listen_collision_error(&existing, &claim));
    }

    seen.push(claim);
    Ok(())
}

fn listen_collision_error(existing: &ListenClaim, incoming: &ListenClaim) -> DeriveError {
    if existing.derived_from_https && !incoming.derived_from_https {
        return DeriveError::HttpsListenCollision {
            https_name: existing.predicate_name.clone(),
            other_name: incoming.predicate_name.clone(),
            protocol: incoming.protocol.as_str(),
            port: existing.port,
        };
    }
    if incoming.derived_from_https && !existing.derived_from_https {
        return DeriveError::HttpsListenCollision {
            https_name: incoming.predicate_name.clone(),
            other_name: existing.predicate_name.clone(),
            protocol: existing.protocol.as_str(),
            port: incoming.port,
        };
    }
    DeriveError::DuplicateListenPort {
        first: existing.predicate_name.clone(),
        second: incoming.predicate_name.clone(),
        protocol: incoming.protocol.as_str(),
        port: incoming.port,
    }
}

fn validate_predicate(p: &Predicate) -> Result<(), DeriveError> {
    if p.name.is_empty() || p.name.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(DeriveError::InvalidName(p.name.clone()));
    }
    if p.listen_port == 0 {
        return Err(DeriveError::ZeroListenPort(p.name.clone()));
    }
    Ok(())
}

fn rule_from_predicate_l4(p: &Predicate, cfg: &DeriveConfig) -> Rule {
    debug_assert!(matches!(p.protocol, Protocol::Tcp | Protocol::Udp));
    let proxy_protocol = match p.protocol {
        Protocol::Tcp => cfg.proxy_protocol,
        _ => None,
    };
    let idle_timeout = match p.protocol {
        Protocol::Udp => p.idle_timeout_ms.map(Duration::from_millis),
        _ => None,
    };
    Rule {
        name: p.name.clone(),
        listen: SocketAddr::new(cfg.bind_addr, p.listen_port),
        protocol: p.protocol,
        target_port: Some(p.listen_port),
        target: None,
        idle_timeout,
        proxy_protocol,
    }
}

fn rule_from_https_predicate(
    p: &Predicate,
    cfg: &DeriveConfig,
    derived_protocol: Protocol,
) -> Rule {
    debug_assert!(matches!(derived_protocol, Protocol::Tcp | Protocol::Udp));
    let idle_timeout = match derived_protocol {
        Protocol::Tcp => None,
        // 30 s default matches quinn's max_idle_timeout — keepalive PINGs at
        // 15 s ensure live QUIC connections refresh well within the reaper window.
        Protocol::Udp => Some(Duration::from_secs(30)),
        Protocol::Https => unreachable!(),
    };
    Rule {
        name: derived_https_rule_name(p, derived_protocol),
        listen: SocketAddr::new(cfg.bind_addr, p.listen_port),
        protocol: derived_protocol,
        target_port: Some(p.listen_port),
        target: None,
        idle_timeout,
        // HTTPS chain traffic always carries PROXY v2 from relay to terminal
        // so the terminal's HTTPS frontend can recover the real client IP
        // and stamp it into X-Forwarded-For. Both ends are yggdrasil and
        // always agree on this; there is no opt-in. For TCP this is a
        // header prepended to the byte stream; for UDP (HTTP/3) it is a
        // standalone first datagram per new flow (see proxy::udp).
        proxy_protocol: Some(ProxyProto::V2),
    }
}

fn derived_https_rule_name(p: &Predicate, derived_protocol: Protocol) -> String {
    let suffix = match derived_protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Https => unreachable!(),
    };
    format!("{}-{suffix}", p.name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::predicate_extractor;
    use ratatoskr::auth::PUBLIC_KEY_LEN;
    use ratatoskr::pubkey::PubKey;
    use ratatoskr::rule::HttpRoute;
    use std::net::Ipv4Addr;
    use url::Url;

    fn origin() -> PubKey {
        PubKey::x25519([0x33u8; PUBLIC_KEY_LEN])
    }

    fn predicate(name: &str, port: u16, protocol: Protocol) -> Predicate {
        Predicate {
            name: name.to_string(),
            listen_port: port,
            protocol,
            idle_timeout_ms: match protocol {
                Protocol::Udp => Some(45_000),
                _ => None,
            },
            https_http3: false,
        }
    }

    fn tcp_predicate(name: &str, port: u16) -> Predicate {
        predicate(name, port, Protocol::Tcp)
    }

    fn udp_predicate(name: &str, port: u16) -> Predicate {
        predicate(name, port, Protocol::Udp)
    }

    fn https_predicate(name: &str, port: u16, https_http3: bool) -> Predicate {
        Predicate {
            name: name.to_string(),
            listen_port: port,
            protocol: Protocol::Https,
            idle_timeout_ms: None,
            https_http3,
        }
    }

    fn cfg() -> DeriveConfig {
        DeriveConfig {
            bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            proxy_protocol: Some(ProxyProto::V2),
        }
    }

    fn predicate_set(predicates: Vec<Predicate>) -> PredicateSet {
        PredicateSet {
            predicates,
            version: 1,
            origin: origin(),
        }
    }

    fn assert_rule_on_port<'a>(
        ruleset: &'a RuleSet,
        name: &str,
        protocol: Protocol,
        bind_addr: IpAddr,
        port: u16,
    ) -> &'a Rule {
        let rule = ruleset
            .find(name)
            .unwrap_or_else(|| panic!("missing {name} rule"));
        assert_eq!(rule.protocol, protocol);
        assert_eq!(rule.listen, SocketAddr::new(bind_addr, port));
        assert_eq!(rule.target_port, Some(port));
        rule
    }

    fn https_source_ruleset(name: &str, _port: u16, _http3: Option<bool>) -> RuleSet {
        // After the L7 schema cleanup, HTTPS comes from top-level
        // [[route]] blocks (RuleSet::routes), not [[rule]] with
        // protocol = "https". This helper now builds a RuleSet
        // with a single route. The `name` and `port` args are kept
        // for back-compat with the test-call sites; `port` and
        // `http3` are unused since both come from `[server]` config
        // after the cleanup.
        RuleSet::from_parts(
            Vec::new(),
            vec![HttpRoute {
                hostname: format!("{name}.localhost"),
                target: Url::parse("http://127.0.0.1:8080").unwrap(),
                hsts: None,
                headers: std::collections::BTreeMap::new(),
            }],
        )
        .expect("source HTTPS rule set must validate")
    }

    fn assert_https_collision(
        err: DeriveError,
        expected_https_name: &str,
        expected_other_name: &str,
        expected_protocol: &'static str,
        expected_port: u16,
    ) {
        assert!(matches!(
            &err,
            DeriveError::HttpsListenCollision { https_name, other_name, protocol, port }
                if https_name.as_str() == expected_https_name
                    && other_name.as_str() == expected_other_name
                    && *protocol == expected_protocol
                    && *port == expected_port
        ));
    }

    #[test]
    fn derives_tcp_with_proxy_protocol() {
        let set = predicate_set(vec![predicate("ssh", 2222, Protocol::Tcp)]);
        let ruleset = derive(&set, &cfg()).unwrap();
        assert_eq!(ruleset.rules().len(), 1);
        let rule = &ruleset.rules()[0];
        assert_eq!(rule.name, "ssh");
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert_eq!(rule.listen.port(), 2222);
        assert_eq!(rule.listen.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(rule.target_port, Some(2222));
        assert_eq!(rule.target, None);
        assert_eq!(rule.proxy_protocol, Some(ProxyProto::V2));
        assert_eq!(rule.idle_timeout, None);
    }

    #[test]
    fn derives_udp_with_idle_timeout_and_no_proxy_protocol() {
        let set = predicate_set(vec![predicate("dns", 53, Protocol::Udp)]);
        let ruleset = derive(&set, &cfg()).unwrap();
        assert_eq!(ruleset.rules().len(), 1);
        let rule = &ruleset.rules()[0];
        assert_eq!(rule.protocol, Protocol::Udp);
        assert_eq!(rule.target_port, Some(53));
        // UDP never gets PROXY-protocol even if the config carries one.
        assert_eq!(rule.proxy_protocol, None);
        assert_eq!(rule.idle_timeout, Some(Duration::from_millis(45_000)));
    }

    #[test]
    fn derives_https_with_http3_as_tcp_and_udp_rules() {
        let cfg = cfg();
        let set = predicate_set(vec![https_predicate("web", 443, true)]);
        let ruleset = derive(&set, &cfg).unwrap();
        assert_eq!(ruleset.rules().len(), 2);

        let tcp = ruleset.find("web-tcp").unwrap();
        assert_eq!(tcp.protocol, Protocol::Tcp);
        assert_eq!(tcp.listen, SocketAddr::new(cfg.bind_addr, 443));
        assert_eq!(tcp.target_port, Some(443));
        assert_eq!(tcp.target, None);
        assert_eq!(tcp.idle_timeout, None);
        assert_eq!(tcp.proxy_protocol, Some(ProxyProto::V2));

        let udp = ruleset.find("web-udp").unwrap();
        assert_eq!(udp.protocol, Protocol::Udp);
        assert_eq!(udp.listen, SocketAddr::new(cfg.bind_addr, 443));
        assert_eq!(udp.target_port, Some(443));
        assert_eq!(udp.target, None);
        assert_eq!(udp.idle_timeout, Some(Duration::from_secs(30)));
        assert_eq!(udp.proxy_protocol, Some(ProxyProto::V2));
    }

    #[test]
    fn derives_https_without_http3_as_tcp_only() {
        let cfg = cfg();
        let set = predicate_set(vec![https_predicate("web", 443, false)]);
        let ruleset = derive(&set, &cfg).unwrap();
        assert_eq!(ruleset.rules().len(), 1);

        let tcp = ruleset.find("web-tcp").unwrap();
        assert_eq!(tcp.protocol, Protocol::Tcp);
        assert_eq!(tcp.listen, SocketAddr::new(cfg.bind_addr, 443));
        assert_eq!(tcp.target_port, Some(443));
        assert!(ruleset.find("web-udp").is_none());
    }

    #[test]
    fn accepts_https_plus_tcp_on_different_ports() {
        let set = predicate_set(vec![
            https_predicate("web", 443, true),
            tcp_predicate("ssh", 2222),
        ]);
        let ruleset = derive(&set, &cfg()).unwrap();
        assert_eq!(ruleset.rules().len(), 3);
        assert!(ruleset.find("web-tcp").is_some());
        assert!(ruleset.find("web-udp").is_some());
        assert!(ruleset.find("ssh").is_some());
    }

    #[test]
    fn preserves_https_listen_port_for_non_default_port() {
        let cfg = cfg();
        let set = predicate_set(vec![https_predicate("web", 8443, true)]);
        let ruleset = derive(&set, &cfg).unwrap();

        assert_eq!(ruleset.rules().len(), 2);
        assert_rule_on_port(&ruleset, "web-tcp", Protocol::Tcp, cfg.bind_addr, 8443);
        assert_rule_on_port(&ruleset, "web-udp", Protocol::Udp, cfg.bind_addr, 8443);
    }

    #[test]
    fn derives_multiple_https_predicates_on_distinct_ports() {
        let cfg = cfg();
        let set = predicate_set(vec![
            https_predicate("web", 443, true),
            https_predicate("api", 8443, true),
        ]);
        let ruleset = derive(&set, &cfg).unwrap();

        assert_eq!(ruleset.rules().len(), 4);
        assert_rule_on_port(&ruleset, "web-tcp", Protocol::Tcp, cfg.bind_addr, 443);
        assert_rule_on_port(&ruleset, "web-udp", Protocol::Udp, cfg.bind_addr, 443);
        assert_rule_on_port(&ruleset, "api-tcp", Protocol::Tcp, cfg.bind_addr, 8443);
        assert_rule_on_port(&ruleset, "api-udp", Protocol::Udp, cfg.bind_addr, 8443);
    }

    #[test]
    fn derives_mixed_tcp_udp_and_https_predicates() {
        let cfg = cfg();
        let set = predicate_set(vec![
            tcp_predicate("ssh", 2222),
            udp_predicate("dns", 53),
            https_predicate("web", 443, true),
        ]);
        let ruleset = derive(&set, &cfg).unwrap();

        assert_eq!(ruleset.rules().len(), 4);
        let ssh = assert_rule_on_port(&ruleset, "ssh", Protocol::Tcp, cfg.bind_addr, 2222);
        assert_eq!(ssh.proxy_protocol, Some(ProxyProto::V2));
        assert_eq!(ssh.idle_timeout, None);

        let dns = assert_rule_on_port(&ruleset, "dns", Protocol::Udp, cfg.bind_addr, 53);
        assert_eq!(dns.proxy_protocol, None);
        assert_eq!(dns.idle_timeout, Some(Duration::from_millis(45_000)));

        assert_rule_on_port(&ruleset, "web-tcp", Protocol::Tcp, cfg.bind_addr, 443);
        let web_udp = assert_rule_on_port(&ruleset, "web-udp", Protocol::Udp, cfg.bind_addr, 443);
        assert_eq!(web_udp.idle_timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn derive_config_bind_addr_is_honored_for_same_predicates() {
        let set = predicate_set(vec![
            tcp_predicate("ssh", 2222),
            https_predicate("web", 443, true),
        ]);
        let cfg_a = DeriveConfig {
            bind_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            proxy_protocol: None,
        };
        let cfg_b = DeriveConfig {
            bind_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            proxy_protocol: None,
        };

        let rules_a = derive(&set, &cfg_a).unwrap();
        let rules_b = derive(&set, &cfg_b).unwrap();

        assert_eq!(rules_a.rules().len(), rules_b.rules().len());
        for rule_a in rules_a.rules() {
            let rule_b = rules_b.find(&rule_a.name).unwrap();
            assert_eq!(rule_a.listen.ip(), cfg_a.bind_addr);
            assert_eq!(rule_b.listen.ip(), cfg_b.bind_addr);
            assert_eq!(rule_a.listen.port(), rule_b.listen.port());
        }
    }

    #[test]
    fn accepts_non_initial_predicate_version() {
        let mut set = predicate_set(vec![https_predicate("web", 443, true)]);
        set.version = 42;

        let ruleset = derive(&set, &cfg()).unwrap();

        assert_eq!(set.version, 42);
        assert_eq!(ruleset.rules().len(), 2);
        assert!(ruleset.find("web-tcp").is_some());
        assert!(ruleset.find("web-udp").is_some());
    }

    #[test]
    fn postcard_round_trip_preserves_mixed_https_derivation_bytes() {
        let cfg = cfg();
        let set = predicate_set(vec![
            tcp_predicate("ssh", 2222),
            udp_predicate("dns", 53),
            https_predicate("web", 443, true),
        ]);
        let direct = derive(&set, &cfg).unwrap();

        let encoded = postcard::to_allocvec(&set).unwrap();
        let decoded: PredicateSet = postcard::from_bytes(&encoded).unwrap();
        let from_wire = derive(&decoded, &cfg).unwrap();

        assert_eq!(decoded, set);
        assert_eq!(from_wire.rules(), direct.rules());
        assert_eq!(
            postcard::to_allocvec(from_wire.rules()).unwrap(),
            postcard::to_allocvec(direct.rules()).unwrap()
        );
    }

    #[test]
    fn derives_same_rules_for_default_and_explicit_http3_true_source_rules() {
        let default_source = https_source_ruleset("web", 443, None);
        let explicit_source = https_source_ruleset("web", 443, Some(true));
        let meta = predicate_extractor::HttpsPredicateMeta::default();
        let default_predicates =
            predicate_extractor::extract(&default_source, meta, origin(), 7).set;
        let explicit_predicates =
            predicate_extractor::extract(&explicit_source, meta, origin(), 7).set;

        assert_eq!(default_predicates, explicit_predicates);
        assert!(default_predicates.predicates[0].https_http3);

        let default_derived = derive(&default_predicates, &cfg()).unwrap();
        let explicit_derived = derive(&explicit_predicates, &cfg()).unwrap();

        assert_eq!(explicit_derived.rules(), default_derived.rules());
    }

    #[test]
    fn derive_output_passes_rule_validation() {
        let set = predicate_set(vec![
            predicate("ssh", 2222, Protocol::Tcp),
            predicate("dns", 53, Protocol::Udp),
        ]);
        let ruleset = derive(&set, &cfg()).unwrap();
        for rule in ruleset.rules() {
            rule.validate().expect("derived rule must pass validation");
        }
    }

    #[test]
    fn rejects_zero_listen_port() {
        let mut p = predicate("bad", 0, Protocol::Tcp);
        p.listen_port = 0;
        let set = predicate_set(vec![p]);
        let err = derive(&set, &cfg()).unwrap_err();
        assert!(matches!(err, DeriveError::ZeroListenPort(_)));
    }

    #[test]
    fn rejects_empty_name() {
        let set = predicate_set(vec![predicate("", 22, Protocol::Tcp)]);
        let err = derive(&set, &cfg()).unwrap_err();
        assert!(matches!(err, DeriveError::InvalidName(_)));
    }

    #[test]
    fn rejects_whitespace_in_name() {
        let set = predicate_set(vec![predicate("bad name", 22, Protocol::Tcp)]);
        let err = derive(&set, &cfg()).unwrap_err();
        assert!(matches!(err, DeriveError::InvalidName(_)));
    }

    #[test]
    fn rejects_duplicate_name() {
        let set = predicate_set(vec![
            predicate("ssh", 22, Protocol::Tcp),
            predicate("ssh", 2222, Protocol::Tcp),
        ]);
        let err = derive(&set, &cfg()).unwrap_err();
        assert!(matches!(err, DeriveError::DuplicateName(name) if name == "ssh"));
    }

    #[test]
    fn rejects_duplicate_listen_port_same_protocol() {
        let set = predicate_set(vec![
            predicate("a", 22, Protocol::Tcp),
            predicate("b", 22, Protocol::Tcp),
        ]);
        let err = derive(&set, &cfg()).unwrap_err();
        assert!(matches!(err, DeriveError::DuplicateListenPort { .. }));
    }

    #[test]
    fn rejects_rule_name_collision_with_https_derived_tcp_name() {
        let set = predicate_set(vec![
            https_predicate("web", 443, false),
            predicate("web-tcp", 8443, Protocol::Tcp),
        ]);
        let err = derive(&set, &cfg()).unwrap_err();
        assert!(matches!(
            &err,
            DeriveError::DuplicateRuleName { rule_name, first, second }
                if rule_name.as_str() == "web-tcp"
                    && first.as_str() == "web"
                    && second.as_str() == "web-tcp"
        ));
        assert_eq!(
            err.to_string(),
            "predicates \"web\" and \"web-tcp\" derive duplicate rule name \"web-tcp\""
        );
    }

    #[test]
    fn rejects_duplicate_https_predicate_names_before_derived_names_collide() {
        let set = predicate_set(vec![
            https_predicate("web", 443, true),
            https_predicate("web", 8443, true),
        ]);

        let err = derive(&set, &cfg()).unwrap_err();

        assert!(matches!(err, DeriveError::DuplicateName(name) if name == "web"));
    }

    #[test]
    fn rejects_https_plus_tcp_on_same_port() {
        let set = predicate_set(vec![
            https_predicate("web", 443, true),
            tcp_predicate("tcp-shadow", 443),
        ]);
        let err = derive(&set, &cfg()).unwrap_err();
        assert_https_collision(err, "web", "tcp-shadow", "tcp", 443);
    }

    #[test]
    fn rejects_https_plus_udp_on_same_port_when_http3_on() {
        let set = predicate_set(vec![
            https_predicate("web", 443, true),
            udp_predicate("udp-shadow", 443),
        ]);
        let err = derive(&set, &cfg()).unwrap_err();
        assert_https_collision(err, "web", "udp-shadow", "udp", 443);
    }

    #[test]
    fn rejects_https_plus_udp_on_same_port_when_http3_off() {
        // HTTPS reserves UDP even when HTTP/3 is off so toggling it on later
        // cannot make a previously valid predicate set collide.
        let set = predicate_set(vec![
            https_predicate("web", 443, false),
            udp_predicate("udp-shadow", 443),
        ]);
        let err = derive(&set, &cfg()).unwrap_err();
        assert_https_collision(err, "web", "udp-shadow", "udp", 443);
    }

    #[test]
    fn allows_same_port_across_protocols() {
        // 53/tcp and 53/udp can coexist on the relay listener (e.g. DNS).
        let set = predicate_set(vec![
            predicate("dns-tcp", 53, Protocol::Tcp),
            predicate("dns-udp", 53, Protocol::Udp),
        ]);
        let ruleset = derive(&set, &cfg()).unwrap();
        assert_eq!(ruleset.rules().len(), 2);
    }

    #[test]
    fn empty_predicate_set_yields_empty_ruleset() {
        let set = predicate_set(vec![]);
        let ruleset = derive(&set, &cfg()).unwrap();
        assert!(ruleset.is_empty());
    }

    #[test]
    fn no_proxy_protocol_config_means_no_proxy_protocol_on_derived_rule() {
        let cfg = DeriveConfig {
            bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            proxy_protocol: None,
        };
        let set = predicate_set(vec![predicate("ssh", 2222, Protocol::Tcp)]);
        let ruleset = derive(&set, &cfg).unwrap();
        assert_eq!(ruleset.rules()[0].proxy_protocol, None);
    }

    #[test]
    fn binds_on_configured_addr() {
        let cfg = DeriveConfig {
            bind_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            proxy_protocol: None,
        };
        let set = predicate_set(vec![predicate("ssh", 2222, Protocol::Tcp)]);
        let ruleset = derive(&set, &cfg).unwrap();
        assert_eq!(
            ruleset.rules()[0].listen.ip(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
    }
}
