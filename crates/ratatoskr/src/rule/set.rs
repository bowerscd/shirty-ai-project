//! `RuleSet`: cross-file-validated aggregate of rules + HTTPS routes plus
//! the reload-diff (`RuleChange`, `RuleDiff`).
//!
//! Split out from the original monolithic `rule.rs` (Phase B1).

use std::net::SocketAddr;

use crate::error::{Error, Result};

use super::file::RuleFile;
use super::http_route::HttpRoute;
use super::rule_def::Rule;
use super::types::Protocol;

/// Aggregated, cross-file-validated set of rules ready for use by the runtime.
///
/// Carries two independent collections:
/// * `rules` — L4 (TCP / UDP) `[[rule]]` blocks, each owning its own listener.
/// * `routes` — HTTPS routes contributed by top-level `[[route]]` blocks
///   across all files, attached to the node-wide HTTPS listener
///   (`[server].https_listen`).
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
    routes: Vec<HttpRoute>,
}

impl RuleSet {
    /// Build a [`RuleSet`] from one or more parsed rule files, performing
    /// cross-file uniqueness validation. Per-rule validation runs first.
    pub fn from_files(files: impl IntoIterator<Item = RuleFile>) -> Result<Self> {
        let mut rules: Vec<Rule> = Vec::new();
        let mut routes: Vec<HttpRoute> = Vec::new();
        for f in files {
            f.validate_each()?;
            rules.extend(f.rule);
            routes.extend(f.route);
        }
        Self::from_parts_unchecked_individuals(rules, routes)
    }

    /// Build a [`RuleSet`] from an already-constructed list of rules.
    /// Each rule is individually validated, then cross-rule duplicate
    /// detection runs. Used by the chain-control derive path, which
    /// synthesises rules from received predicates rather than reading
    /// them from `.toml` files.
    pub fn from_rules(rules: Vec<Rule>) -> Result<Self> {
        for r in &rules {
            r.validate()?;
        }
        Self::from_parts_unchecked_individuals(rules, Vec::new())
    }

    /// Build a [`RuleSet`] from already-constructed rule + route lists.
    /// Each is individually validated, then cross-collection uniqueness
    /// checks run.
    pub fn from_parts(rules: Vec<Rule>, routes: Vec<HttpRoute>) -> Result<Self> {
        for r in &rules {
            r.validate()?;
        }
        for route in &routes {
            super::validate::validate_http_route("<route>", route)?;
        }
        Self::from_parts_unchecked_individuals(rules, routes)
    }

    // Cross-collection duplicate detection only — assumes each rule and
    // route has already been individually validated.
    fn from_parts_unchecked_individuals(rules: Vec<Rule>, routes: Vec<HttpRoute>) -> Result<Self> {
        // Duplicate rule-name check.
        {
            let mut seen = std::collections::HashSet::<&str>::new();
            for r in &rules {
                if !seen.insert(r.name.as_str()) {
                    return Err(Error::InvalidRule(format!(
                        "duplicate rule name {:?} across rule files",
                        r.name
                    )));
                }
            }
        }

        // Duplicate L4 listen claim check. TCP and UDP can share an address.
        {
            let mut listens = std::collections::HashMap::<SocketAddr, Vec<(&str, Protocol)>>::new();
            for r in &rules {
                if let Some(existing) = listens.get(&r.listen) {
                    for (other_name, other_proto) in existing {
                        if r.protocol == *other_proto {
                            return Err(Error::InvalidRule(format!(
                                "duplicate listen address {} for protocol {} (rules {:?} and {:?})",
                                r.listen,
                                r.protocol.as_str(),
                                r.name,
                                other_name
                            )));
                        }
                    }
                }
                listens
                    .entry(r.listen)
                    .or_default()
                    .push((r.name.as_str(), r.protocol));
            }
        }

        // Duplicate-hostname check across HTTPS routes.
        {
            let mut seen_hosts = std::collections::HashSet::<String>::new();
            for r in &routes {
                let lc = r.hostname.to_ascii_lowercase();
                if !seen_hosts.insert(lc.clone()) {
                    return Err(Error::InvalidRule(format!(
                        "duplicate HTTPS route hostname {:?} across rule files",
                        r.hostname
                    )));
                }
            }
        }

        Ok(Self { rules, routes })
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn routes(&self) -> &[HttpRoute] {
        &self.routes
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.routes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn find(&self, name: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.name == name)
    }

    /// Compute a name-keyed diff against a new set. Used by the hot-reload
    /// watcher to figure out which listeners to add, remove, or restart.
    ///
    /// Currently only diffs the L4 `rules` collection. HTTPS routes are
    /// hot-reloaded as a single replacement set by the supervisor.
    pub fn diff(&self, new: &RuleSet) -> RuleDiff {
        use std::collections::HashMap;

        let mut old_by_name: HashMap<&str, &Rule> =
            self.rules.iter().map(|r| (r.name.as_str(), r)).collect();
        let mut diff = RuleDiff::default();

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
    pub fn as_initial_diff(&self) -> RuleDiff {
        RuleDiff {
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

/// Result of [`RuleSet::diff`]: a partition of the new rule set into
/// added / removed / changed / unchanged, keyed by rule `name`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleDiff {
    pub added: Vec<Rule>,
    pub removed: Vec<Rule>,
    pub changed: Vec<RuleChange>,
    /// Rule names that exist with identical contents in both sets.
    pub unchanged: Vec<String>,
}

impl RuleDiff {
    /// `true` if the diff represents no actual change.
    pub fn is_noop(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }

    /// Number of rules touched (added + removed + changed).
    pub fn touched(&self) -> usize {
        self.added.len() + self.removed.len() + self.changed.len()
    }
}
