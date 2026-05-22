//! `RuleSet`: cross-file-validated aggregate of rules plus the
//! reload-diff (`RuleChange`, `RuleDiff`).
//!
//! Split out from the original monolithic `rule.rs` (Phase B1).

use std::net::SocketAddr;

use crate::error::{Error, Result};

use super::file::RuleFile;
use super::rule_def::Rule;
use super::types::Protocol;

/// Aggregated, cross-file-validated set of rules ready for use by the runtime.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    /// Build a [`RuleSet`] from one or more parsed rule files, performing
    /// cross-file uniqueness validation. Per-rule validation runs first.
    pub fn from_files(files: impl IntoIterator<Item = RuleFile>) -> Result<Self> {
        let mut rules: Vec<Rule> = Vec::new();
        for f in files {
            f.validate_each()?;
            rules.extend(f.rule);
        }
        Self::from_rules_unchecked_individuals(rules)
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
        Self::from_rules_unchecked_individuals(rules)
    }

    // Cross-rule duplicate detection only — assumes each rule has already
    // been individually validated.
    fn from_rules_unchecked_individuals(rules: Vec<Rule>) -> Result<Self> {
        // Duplicate name check.
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

        // Duplicate listen claim check. TCP and UDP can share an address, but
        // HTTPS also claims UDP on the same port for HTTP/3.
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
                        if r.protocol == Protocol::Https || *other_proto == Protocol::Https {
                            return Err(Error::InvalidRule(format!(
                                "rules {:?} ({}) and {:?} ({}) share listen address {}; HTTPS rules implicitly claim both TCP and UDP on the port (HTTP/3 listens on UDP), so no other rule may share the same (ip, port)",
                                r.name,
                                r.protocol.as_str(),
                                other_name,
                                other_proto.as_str(),
                                r.listen
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
