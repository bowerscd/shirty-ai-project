//! Branch (proxy-rule) schema and TOML deserialisation.
//!
//! A *branch file* lives at `/etc/yggdrasil/branches/<name>.toml` and contains
//! one or more `[[rule]]` blocks. Splitting rules across files is purely an
//! operator convenience — the runtime semantics are determined by the
//! aggregated rule set across the whole directory.
//!
//! Example:
//!
//! ```toml
//! [[rule]]
//! name           = "minecraft-survival"
//! listen         = "0.0.0.0:25565"
//! protocol       = "tcp"
//! upstream_port  = 25565
//! proxy_protocol = "v2"          # optional, off by default
//!
//! [[rule]]
//! name           = "minecraft-bedrock"
//! listen         = "0.0.0.0:19132"
//! protocol       = "udp"
//! upstream_port  = 19132
//! idle_timeout   = "30s"          # optional, defaults to 60s for udp
//! ```
//!
//! ## Validation
//!
//! Per-rule:
//! * `name` is non-empty and contains no whitespace or control characters.
//! * `idle_timeout` is only meaningful for UDP; setting it on a TCP rule is
//!   rejected.
//! * `proxy_protocol` is only meaningful for TCP; setting it on a UDP rule is
//!   rejected.
//! * `listen` port must be non-zero (binding to port 0 makes no sense for a
//!   fixed-listener proxy).
//! * `upstream_port` must be non-zero.
//!
//! Cross-file:
//! * `name` must be globally unique.
//! * `listen` socket address must be globally unique (no two rules can claim
//!   the same `(ip, port, protocol)` triple — different protocols *can* share
//!   `(ip, port)`).

use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Transport protocol selected per-rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// HAProxy PROXY-protocol version selector for TCP rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProto {
    V1,
    V2,
}

/// A single proxy rule as deserialised from a `[[rule]]` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Human-friendly identifier. Must be globally unique across all branch files.
    pub name: String,
    /// Local socket on which yggdrasil listens for client connections / datagrams.
    pub listen: SocketAddr,
    /// `"tcp"` or `"udp"`.
    pub protocol: Protocol,
    /// Destination port on the upstream peer (the residential host's IP comes from
    /// the heartbeat, not from this file).
    pub upstream_port: u16,
    /// UDP only: time without activity before a flow is evicted from the flow table.
    /// Default applied at load time (see [`Rule::resolved_idle_timeout`]).
    #[serde(default, with = "humantime_serde::option")]
    pub idle_timeout: Option<Duration>,
    /// TCP only: emit a PROXY-protocol header to the upstream before forwarding.
    #[serde(default)]
    pub proxy_protocol: Option<ProxyProto>,
}

/// Default UDP idle timeout if a rule does not specify one.
pub const DEFAULT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

impl Rule {
    /// Validate per-rule invariants. Returns `Error::InvalidBranch` with a
    /// human-readable message on failure.
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(Error::InvalidBranch("rule name is empty".into()));
        }
        if self.name.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(Error::InvalidBranch(format!(
                "rule name {:?} contains whitespace or control characters",
                self.name
            )));
        }
        if self.listen.port() == 0 {
            return Err(Error::InvalidBranch(format!(
                "rule {:?}: listen port must be non-zero",
                self.name
            )));
        }
        if self.upstream_port == 0 {
            return Err(Error::InvalidBranch(format!(
                "rule {:?}: upstream_port must be non-zero",
                self.name
            )));
        }
        match self.protocol {
            Protocol::Tcp => {
                if self.idle_timeout.is_some() {
                    return Err(Error::InvalidBranch(format!(
                        "rule {:?}: idle_timeout is only valid for udp rules",
                        self.name
                    )));
                }
            }
            Protocol::Udp => {
                if self.proxy_protocol.is_some() {
                    return Err(Error::InvalidBranch(format!(
                        "rule {:?}: proxy_protocol is only valid for tcp rules",
                        self.name
                    )));
                }
            }
        }
        Ok(())
    }

    /// Idle timeout to apply at runtime — supplied value or
    /// [`DEFAULT_UDP_IDLE_TIMEOUT`] for UDP, irrelevant for TCP.
    pub fn resolved_idle_timeout(&self) -> Duration {
        self.idle_timeout.unwrap_or(DEFAULT_UDP_IDLE_TIMEOUT)
    }
}

/// A single branch file (`/etc/yggdrasil/branches/*.toml`) deserialised from TOML.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchFile {
    #[serde(default)]
    pub rule: Vec<Rule>,
}

impl BranchFile {
    /// Parse a TOML string into a [`BranchFile`], attaching `path` to any parse
    /// error so the operator gets line context.
    pub fn from_toml(path: impl Into<std::path::PathBuf>, s: &str) -> Result<Self> {
        let path = path.into();
        toml::from_str(s).map_err(|source| Error::TomlParse {
            path,
            source,
        })
    }

    /// Validate every rule in the file. Cross-file uniqueness is enforced by
    /// [`BranchSet::from_files`].
    pub fn validate_each(&self) -> Result<()> {
        for r in &self.rule {
            r.validate()?;
        }
        Ok(())
    }
}

/// Aggregated, cross-file-validated set of rules ready for use by the runtime.
#[derive(Debug, Clone, Default)]
pub struct BranchSet {
    rules: Vec<Rule>,
}

impl BranchSet {
    /// Build a [`BranchSet`] from one or more parsed branch files, performing
    /// cross-file uniqueness validation. Per-rule validation runs first.
    pub fn from_files(files: impl IntoIterator<Item = BranchFile>) -> Result<Self> {
        let mut rules: Vec<Rule> = Vec::new();
        for f in files {
            f.validate_each()?;
            rules.extend(f.rule);
        }

        // Duplicate name check.
        {
            let mut seen = std::collections::HashSet::<&str>::new();
            for r in &rules {
                if !seen.insert(r.name.as_str()) {
                    return Err(Error::InvalidBranch(format!(
                        "duplicate rule name {:?} across branch files",
                        r.name
                    )));
                }
            }
        }

        // Duplicate listen-addr+protocol check.
        {
            let mut seen = std::collections::HashSet::<(SocketAddr, Protocol)>::new();
            for r in &rules {
                if !seen.insert((r.listen, r.protocol)) {
                    return Err(Error::InvalidBranch(format!(
                        "duplicate listen address {} for protocol {} (rule {:?})",
                        r.listen,
                        r.protocol.as_str(),
                        r.name
                    )));
                }
            }
        }

        Ok(Self { rules })
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn find(&self, name: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.name == name)
    }

    /// Compute a name-keyed diff against a new set. Used by the hot-reload
    /// watcher to figure out which listeners to add, remove, or restart.
    pub fn diff(&self, new: &BranchSet) -> BranchDiff {
        use std::collections::HashMap;

        let mut old_by_name: HashMap<&str, &Rule> =
            self.rules.iter().map(|r| (r.name.as_str(), r)).collect();
        let mut diff = BranchDiff::default();

        for new_rule in &new.rules {
            match old_by_name.remove(new_rule.name.as_str()) {
                Some(old) if old == new_rule => diff.unchanged.push(new_rule.name.clone()),
                Some(old) => diff.changed.push(RuleChange {
                    old: old.clone(),
                    new: new_rule.clone(),
                }),
                None => diff.added.push(new_rule.clone()),
            }
        }

        // Anything left in old_by_name was removed in the new set.
        for (_, r) in old_by_name {
            diff.removed.push(r.clone());
        }
        // Sort removed by name for determinism (HashMap iteration is randomised).
        diff.removed.sort_by(|a, b| a.name.cmp(&b.name));
        diff
    }

    /// Diff treating the previous set as empty — used to emit the initial
    /// "everything is new" event when the watcher first starts.
    pub fn as_initial_diff(&self) -> BranchDiff {
        BranchDiff {
            added: self.rules.clone(),
            ..Default::default()
        }
    }
}

/// A rule whose contents changed across a reload (same `name`, different fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleChange {
    pub old: Rule,
    pub new: Rule,
}

/// Result of [`BranchSet::diff`]: a partition of the new rule set into
/// added / removed / changed / unchanged, keyed by rule `name`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BranchDiff {
    pub added: Vec<Rule>,
    pub removed: Vec<Rule>,
    pub changed: Vec<RuleChange>,
    /// Rule names that exist with identical contents in both sets.
    pub unchanged: Vec<String>,
}

impl BranchDiff {
    /// `true` if the diff represents no actual change.
    pub fn is_noop(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }

    /// Number of rules touched (added + removed + changed).
    pub fn touched(&self) -> usize {
        self.added.len() + self.removed.len() + self.changed.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<BranchFile> {
        BranchFile::from_toml("test.toml", s)
    }

    #[test]
    fn parses_minimal_tcp_rule() {
        let f = parse(
            r#"
            [[rule]]
            name = "ssh"
            listen = "0.0.0.0:2222"
            protocol = "tcp"
            upstream_port = 22
            "#,
        )
        .unwrap();
        assert_eq!(f.rule.len(), 1);
        let r = &f.rule[0];
        assert_eq!(r.name, "ssh");
        assert_eq!(r.protocol, Protocol::Tcp);
        assert_eq!(r.upstream_port, 22);
        assert_eq!(r.idle_timeout, None);
        assert_eq!(r.proxy_protocol, None);
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
            upstream_port = 19132
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
            upstream_port = 8080
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
            upstream_port = 22
            idle_timeout = "30s"
            "#,
        )
        .unwrap();
        let err = f.validate_each().err();
        assert!(matches!(err, Some(Error::InvalidBranch(s)) if s.contains("idle_timeout")));
    }

    #[test]
    fn rejects_proxy_protocol_on_udp_rule() {
        let f = parse(
            r#"
            [[rule]]
            name = "dns"
            listen = "0.0.0.0:53"
            protocol = "udp"
            upstream_port = 53
            proxy_protocol = "v1"
            "#,
        )
        .unwrap();
        let err = f.validate_each().err();
        assert!(matches!(err, Some(Error::InvalidBranch(s)) if s.contains("proxy_protocol")));
    }

    #[test]
    fn rejects_zero_listen_port() {
        let f = parse(
            r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:0"
            protocol = "tcp"
            upstream_port = 22
            "#,
        )
        .unwrap();
        let err = f.validate_each().err();
        assert!(matches!(err, Some(Error::InvalidBranch(s)) if s.contains("listen port")));
    }

    #[test]
    fn rejects_zero_upstream_port() {
        let f = parse(
            r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            upstream_port = 0
            "#,
        )
        .unwrap();
        let err = f.validate_each().err();
        assert!(matches!(err, Some(Error::InvalidBranch(s)) if s.contains("upstream_port")));
    }

    #[test]
    fn rejects_empty_name() {
        let f = parse(
            r#"
            [[rule]]
            name = ""
            listen = "0.0.0.0:22"
            protocol = "tcp"
            upstream_port = 22
            "#,
        )
        .unwrap();
        let err = f.validate_each().err();
        assert!(matches!(err, Some(Error::InvalidBranch(s)) if s.contains("empty")));
    }

    #[test]
    fn rejects_name_with_whitespace() {
        let f = parse(
            r#"
            [[rule]]
            name = "bad name"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            upstream_port = 22
            "#,
        )
        .unwrap();
        let err = f.validate_each().err();
        assert!(matches!(err, Some(Error::InvalidBranch(s)) if s.contains("whitespace")));
    }

    #[test]
    fn rejects_malformed_toml() {
        let err = parse("[[rule\nname=oops").err();
        assert!(matches!(err, Some(Error::TomlParse { .. })));
    }

    #[test]
    fn allows_empty_branch_file() {
        let f = parse("").unwrap();
        assert!(f.rule.is_empty());
        f.validate_each().unwrap();
    }

    #[test]
    fn branch_set_aggregates_multiple_files() {
        let a = parse(
            r#"
            [[rule]]
            name = "a"
            listen = "0.0.0.0:1111"
            protocol = "tcp"
            upstream_port = 1
            "#,
        )
        .unwrap();
        let b = parse(
            r#"
            [[rule]]
            name = "b"
            listen = "0.0.0.0:2222"
            protocol = "udp"
            upstream_port = 2
            "#,
        )
        .unwrap();
        let set = BranchSet::from_files([a, b]).unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.find("a").is_some());
        assert!(set.find("b").is_some());
        assert!(set.find("nope").is_none());
    }

    #[test]
    fn branch_set_rejects_duplicate_names() {
        let a = parse(
            r#"
            [[rule]]
            name = "dup"
            listen = "0.0.0.0:1111"
            protocol = "tcp"
            upstream_port = 1
            "#,
        )
        .unwrap();
        let b = parse(
            r#"
            [[rule]]
            name = "dup"
            listen = "0.0.0.0:2222"
            protocol = "tcp"
            upstream_port = 2
            "#,
        )
        .unwrap();
        let err = BranchSet::from_files([a, b]).err();
        assert!(matches!(err, Some(Error::InvalidBranch(s)) if s.contains("duplicate rule name")));
    }

    #[test]
    fn branch_set_rejects_duplicate_listen_within_protocol() {
        let a = parse(
            r#"
            [[rule]]
            name = "x"
            listen = "0.0.0.0:1111"
            protocol = "tcp"
            upstream_port = 1
            "#,
        )
        .unwrap();
        let b = parse(
            r#"
            [[rule]]
            name = "y"
            listen = "0.0.0.0:1111"
            protocol = "tcp"
            upstream_port = 2
            "#,
        )
        .unwrap();
        let err = BranchSet::from_files([a, b]).err();
        assert!(matches!(err, Some(Error::InvalidBranch(s)) if s.contains("duplicate listen")));
    }

    #[test]
    fn branch_set_allows_same_listen_addr_across_different_protocols() {
        // tcp and udp can share `(ip, port)` — different sockets entirely.
        let a = parse(
            r#"
            [[rule]]
            name = "x-tcp"
            listen = "0.0.0.0:53"
            protocol = "tcp"
            upstream_port = 53
            "#,
        )
        .unwrap();
        let b = parse(
            r#"
            [[rule]]
            name = "x-udp"
            listen = "0.0.0.0:53"
            protocol = "udp"
            upstream_port = 53
            "#,
        )
        .unwrap();
        let set = BranchSet::from_files([a, b]).unwrap();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn unknown_protocol_string_fails_to_deserialise() {
        let err = parse(
            r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "sctp"
            upstream_port = 22
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
            upstream_port = 1234
            "#,
        )
        .unwrap();
        assert_eq!(f.rule[0].idle_timeout, None);
        assert_eq!(
            f.rule[0].resolved_idle_timeout(),
            DEFAULT_UDP_IDLE_TIMEOUT
        );
    }

    // ---- diff tests ----

    fn rule(name: &str, port: u16, proto: Protocol, upstream: u16) -> Rule {
        let f = parse(&format!(
            r#"
            [[rule]]
            name = "{name}"
            listen = "0.0.0.0:{port}"
            protocol = "{}"
            upstream_port = {upstream}
            "#,
            proto.as_str()
        ))
        .unwrap();
        f.rule.into_iter().next().unwrap()
    }

    fn set(rules: Vec<Rule>) -> BranchSet {
        BranchSet::from_files([BranchFile { rule: rules }]).unwrap()
    }

    #[test]
    fn diff_empty_to_empty_is_noop() {
        let d = BranchSet::default().diff(&BranchSet::default());
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
            rule("mod",  3000, Protocol::Tcp, 24),
        ]);
        // "keep" unchanged, "gone" removed, "mod" upstream port changed, "new" added.
        let new = set(vec![
            rule("keep", 1000, Protocol::Tcp, 22),
            rule("mod",  3000, Protocol::Tcp, 99),
            rule("new",  4000, Protocol::Udp, 53),
        ]);
        let d = old.diff(&new);
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].name, "new");
        assert_eq!(d.removed.len(), 1);
        assert_eq!(d.removed[0].name, "gone");
        assert_eq!(d.changed.len(), 1);
        assert_eq!(d.changed[0].old.name, "mod");
        assert_eq!(d.changed[0].old.upstream_port, 24);
        assert_eq!(d.changed[0].new.upstream_port, 99);
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
}
