//! Exact (case-insensitive) hostname → route mapping.
//!
//! Split out from the original monolithic `http_frontend.rs` (Phase B4).

use std::collections::HashMap;

use url::Url;

use ratatoskr::rule::{HstsConfig, HttpRoute};

pub struct RouteTable {
    by_host: HashMap<String, RouteEntry>,
}

pub(crate) struct RouteEntry {
    pub(crate) target: Url,
    pub(crate) hsts: Option<HstsConfig>,
    /// Name of the rule this route was authored under. Used for
    /// tracing / metrics labels so observability survives the
    /// companion-listener's cross-rule aggregation (the companion
    /// merges every cert-less route on a given `(ip, 80)` slot from
    /// every HTTPS rule that binds that IP).
    pub(crate) rule_name: String,
}

impl RouteTable {
    /// Build a fresh route table from a single rule's routes.
    pub(crate) fn build(routes: &[HttpRoute], rule_name: &str) -> Self {
        let mut t = Self {
            by_host: HashMap::with_capacity(routes.len()),
        };
        t.extend(routes, rule_name);
        t
    }

    /// Add additional routes to an existing table. Used by the
    /// companion listener to aggregate cert-less routes across
    /// multiple rules that share a `(ip, 80)` listen slot. Returns
    /// the list of hostnames that were *already* present and got
    /// replaced — operators wire this list onto a
    /// `tracing::warn!` so a same-host collision across rules is
    /// surfaced loud.
    pub(crate) fn extend(&mut self, routes: &[HttpRoute], rule_name: &str) -> Vec<String> {
        let mut replaced = Vec::new();
        for r in routes {
            let key = r.hostname.to_ascii_lowercase();
            let new = RouteEntry {
                target: r.target.clone(),
                hsts: r.hsts,
                rule_name: rule_name.to_string(),
            };
            if self.by_host.insert(key.clone(), new).is_some() {
                replaced.push(key);
            }
        }
        replaced
    }

    /// Remove every entry whose `rule_name` matches `rule_name`.
    /// Returns the hostnames that were removed. Used by the
    /// companion listener on hot reload to drop the cert-less routes
    /// contributed by a rule that has been removed or whose routes
    /// have changed shape.
    pub(crate) fn remove_by_rule(&mut self, rule_name: &str) -> Vec<String> {
        let to_remove: Vec<String> = self
            .by_host
            .iter()
            .filter(|(_, e)| e.rule_name == rule_name)
            .map(|(k, _)| k.clone())
            .collect();
        for k in &to_remove {
            self.by_host.remove(k);
        }
        to_remove
    }

    pub(crate) fn lookup(&self, host: &str) -> Option<&RouteEntry> {
        // Strip trailing dot ("foo.example.com.") and port if present.
        let host = host.trim_end_matches('.');
        let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
        self.by_host.get(&host.to_ascii_lowercase())
    }

    pub fn len(&self) -> usize {
        self.by_host.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_host.is_empty()
    }

    /// Iterate hostnames (for the `:80` redirect listener's knowledge of
    /// which hosts to accept).
    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.by_host.keys().map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_table_lookup_is_case_insensitive_and_strips_port() {
        let routes = vec![HttpRoute {
            hostname: "API.example.com".into(),
            target: "http://10.0.0.1:8080".parse().unwrap(),
            hsts: None,
        }];
        let t = RouteTable::build(&routes, "test-rule");
        assert!(t.lookup("api.example.com").is_some());
        assert!(t.lookup("API.example.com").is_some());
        assert!(t.lookup("api.example.com:443").is_some());
        assert!(t.lookup("api.example.com.").is_some());
        assert!(t.lookup("other.example.com").is_none());
        assert_eq!(t.lookup("api.example.com").unwrap().rule_name, "test-rule");
    }

    #[test]
    fn route_table_extend_aggregates_routes_from_multiple_rules() {
        let route_a = vec![HttpRoute {
            hostname: "a.example".into(),
            target: "http://10.0.0.1:80".parse().unwrap(),
            hsts: None,
        }];
        let route_b = vec![HttpRoute {
            hostname: "b.example".into(),
            target: "http://10.0.0.2:80".parse().unwrap(),
            hsts: None,
        }];
        let mut t = RouteTable::build(&route_a, "rule-a");
        let replaced = t.extend(&route_b, "rule-b");
        assert!(replaced.is_empty());
        assert_eq!(t.len(), 2);
        assert_eq!(t.lookup("a.example").unwrap().rule_name, "rule-a");
        assert_eq!(t.lookup("b.example").unwrap().rule_name, "rule-b");
    }

    #[test]
    fn route_table_extend_reports_cross_rule_host_collision() {
        let route_a = vec![HttpRoute {
            hostname: "shared.example".into(),
            target: "http://10.0.0.1:80".parse().unwrap(),
            hsts: None,
        }];
        let route_b = vec![HttpRoute {
            hostname: "shared.example".into(),
            target: "http://10.0.0.2:80".parse().unwrap(),
            hsts: None,
        }];
        let mut t = RouteTable::build(&route_a, "rule-a");
        let replaced = t.extend(&route_b, "rule-b");
        assert_eq!(replaced, vec!["shared.example".to_string()]);
        assert_eq!(t.lookup("shared.example").unwrap().rule_name, "rule-b");
    }

    #[test]
    fn route_table_remove_by_rule_drops_matching_entries() {
        let routes = vec![HttpRoute {
            hostname: "x.example".into(),
            target: "http://10.0.0.1:80".parse().unwrap(),
            hsts: None,
        }];
        let mut t = RouteTable::build(&routes, "rule-a");
        let extra = vec![HttpRoute {
            hostname: "y.example".into(),
            target: "http://10.0.0.2:80".parse().unwrap(),
            hsts: None,
        }];
        t.extend(&extra, "rule-b");
        assert_eq!(t.len(), 2);
        let removed = t.remove_by_rule("rule-a");
        assert_eq!(removed, vec!["x.example".to_string()]);
        assert_eq!(t.len(), 1);
        assert!(t.lookup("y.example").is_some());
    }
}
