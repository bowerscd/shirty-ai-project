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
}

impl RouteTable {
    pub(crate) fn build(routes: &[HttpRoute]) -> Self {
        let mut by_host = HashMap::with_capacity(routes.len());
        for r in routes {
            by_host.insert(
                r.hostname.to_ascii_lowercase(),
                RouteEntry {
                    target: r.target.clone(),
                    hsts: r.hsts,
                },
            );
        }
        Self { by_host }
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
            cert: None,
            key: None,
            hsts: None,
        }];
        let t = RouteTable::build(&routes);
        assert!(t.lookup("api.example.com").is_some());
        assert!(t.lookup("API.example.com").is_some());
        assert!(t.lookup("api.example.com:443").is_some());
        assert!(t.lookup("api.example.com.").is_some());
        assert!(t.lookup("other.example.com").is_none());
    }
}
