//! Relay-side derivation: [`PredicateSet`] → [`RuleSet`].
//!
//! When a relay receives a [`PredicateSet`] from its downstream over the
//! chain control channel, it synthesises a local [`RuleSet`] that
//! forwards traffic for each predicate back down toward the downstream.
//! The derived rules are then handed to the existing reload pipeline
//! (Phase 3B will wire that side); this module is the pure projection.
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
//!   protocol ignore this field. The plan envisions every relay-to-
//!   downstream TCP flow carrying a PROXY header so the terminal sees
//!   the original client IP.
//!
//! ## What the derive function fills in
//!
//! Each predicate produces one [`Rule`] with:
//!
//! * `name`, `listen_port`, `protocol`, `idle_timeout` from the predicate.
//! * `listen = (bind_addr, predicate.listen_port)`.
//! * `target_port = Some(predicate.listen_port)` — relay mode: dial
//!   the heartbeat-discovered downstream peer on the same port the
//!   predicate listens on. The downstream IP lives in the heartbeat
//!   session state, not in the derived rule.
//! * For TCP: `proxy_protocol = derive_config.proxy_protocol`.
//!
//! ## Errors
//!
//! [`derive`] returns [`DeriveError`] on any validation failure. The
//! caller maps these to `AckStatus::Reject(code)` using the reason codes
//! in [`predicate_reject`](ratatoskr::predicate::predicate_reject).
//!
//! [`PredicateSet`]: ratatoskr::predicate::PredicateSet

use std::collections::HashSet;
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
    /// Two TCP/UDP predicates share the same `(protocol, listen_port)`
    /// pair; the derived rule set would not be bindable.
    #[error("predicates {first:?} and {second:?} share {protocol} listen_port {port}")]
    DuplicateListenPort {
        first: String,
        second: String,
        protocol: &'static str,
        port: u16,
    },
    /// The predicate uses [`Protocol::Https`]. Phase 3 does not yet
    /// support deriving HTTPS rules: HTTPS needs cert configuration that
    /// is not carried in a predicate.
    #[error("predicate {0:?}: protocol https is not yet derivable")]
    HttpsNotDerivable(String),
}

impl DeriveError {
    /// Map this error to the stable wire reject code carried in
    /// `AckStatus::Reject(u16)`.
    pub fn reject_code(&self) -> u16 {
        match self {
            Self::InvalidName(_)
            | Self::ZeroListenPort(_)
            | Self::DuplicateName(_)
            | Self::DuplicateListenPort { .. }
            | Self::HttpsNotDerivable(_) => predicate_reject::INVALID_PREDICATE,
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
    let mut seen_listens: Vec<(Protocol, u16, &str)> = Vec::with_capacity(set.predicates.len());
    let mut rules = Vec::with_capacity(set.predicates.len());

    for predicate in &set.predicates {
        validate_predicate(predicate)?;

        if !seen_names.insert(predicate.name.as_str()) {
            return Err(DeriveError::DuplicateName(predicate.name.clone()));
        }
        if let Some((_, _, other)) = seen_listens
            .iter()
            .find(|(p, port, _)| *p == predicate.protocol && *port == predicate.listen_port)
        {
            return Err(DeriveError::DuplicateListenPort {
                first: (*other).to_string(),
                second: predicate.name.clone(),
                protocol: predicate.protocol.as_str(),
                port: predicate.listen_port,
            });
        }
        seen_listens.push((predicate.protocol, predicate.listen_port, &predicate.name));

        rules.push(rule_from_predicate(predicate, cfg));
    }

    // Cross-rule validation (duplicate names, duplicate listen sockets)
    // is enforced inline above with predicate-flavoured error messages;
    // delegate per-rule + cross-rule validation to `RuleSet::from_rules`
    // as a defensive belt-and-braces (any unexpected validation gap
    // upstream surfaces as `DeriveError::InvalidPredicate`).
    RuleSet::from_rules(rules).map_err(|e| {
        // RuleSet's error is operator-formatted; collapse to the
        // predicate-flavoured invalid-name variant so the wire reject
        // code path is unambiguous.
        DeriveError::InvalidName(e.to_string())
    })
}

fn validate_predicate(p: &Predicate) -> Result<(), DeriveError> {
    if matches!(p.protocol, Protocol::Https) {
        return Err(DeriveError::HttpsNotDerivable(p.name.clone()));
    }
    if p.name.is_empty() || p.name.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(DeriveError::InvalidName(p.name.clone()));
    }
    if p.listen_port == 0 {
        return Err(DeriveError::ZeroListenPort(p.name.clone()));
    }
    Ok(())
}

fn rule_from_predicate(p: &Predicate, cfg: &DeriveConfig) -> Rule {
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
        target_addr: None,
        target_host: None,
        idle_timeout,
        proxy_protocol,
        routes: None,
        cert_dir: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatoskr::auth::PUBLIC_KEY_LEN;
    use ratatoskr::pubkey::PubKey;
    use std::net::Ipv4Addr;

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
        assert_eq!(rule.target_addr, None);
        assert_eq!(rule.target_host, None);
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
    fn rejects_https_predicates() {
        let set = predicate_set(vec![predicate("home-https", 443, Protocol::Https)]);
        let err = derive(&set, &cfg()).unwrap_err();
        assert!(matches!(err, DeriveError::HttpsNotDerivable(_)));
        assert_eq!(err.reject_code(), predicate_reject::INVALID_PREDICATE);
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
