//! [`RuleFile`]: a single `conf.d/*.toml` deserialised from TOML.
//!
//! Split out from the original monolithic `rule.rs` (Phase B1).

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::http_route::HttpRoute;
use super::rule_def::Rule;
use super::validate::validate_http_route;

/// A single rule file (`/etc/yggdrasil/conf.d/*.toml`) deserialised from TOML.
///
/// Files may carry zero or more `[[rule]]` blocks (L4 — TCP / UDP) and
/// zero or more top-level `[[route]]` blocks (L7 — HTTPS routes
/// attached to the node-wide HTTPS listener).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleFile {
    #[serde(default)]
    pub rule: Vec<Rule>,
    #[serde(default)]
    pub route: Vec<HttpRoute>,
}

impl RuleFile {
    /// Parse a TOML string into a [`RuleFile`], attaching `path` to any parse
    /// error so the operator gets line context.
    ///
    /// # Examples
    ///
    /// Relay-mode rules (dial the heartbeat-discovered peer IP via
    /// `target_port`):
    ///
    /// ```
    /// use ratatoskr::rule::RuleFile;
    /// let toml = r#"
    ///     [[rule]]
    ///     name           = "minecraft-survival"
    ///     listen         = "0.0.0.0:25565"
    ///     protocol       = "tcp"
    ///     target_port    = 25565
    ///     proxy_protocol = "v2"
    ///
    ///     [[rule]]
    ///     name         = "minecraft-bedrock"
    ///     listen       = "0.0.0.0:19132"
    ///     protocol     = "udp"
    ///     target_port  = 19132
    ///     idle_timeout = "30s"
    /// "#;
    /// let file = RuleFile::from_toml("relay.toml", toml).unwrap();
    /// file.validate_each().unwrap();
    /// assert_eq!(file.rule.len(), 2);
    /// ```
    ///
    /// Terminal-mode L4 rule with a static IP literal target:
    ///
    /// ```
    /// use ratatoskr::rule::RuleFile;
    /// let toml = r#"
    ///     [[rule]]
    ///     name     = "home-ssh"
    ///     listen   = "0.0.0.0:2222"
    ///     protocol = "tcp"
    ///     target   = "192.168.1.10:22"
    /// "#;
    /// RuleFile::from_toml("terminal.toml", toml).unwrap()
    ///     .validate_each().unwrap();
    /// ```
    ///
    /// HTTPS routes (terminal-mode only; attach to the node-wide
    /// `[server].https_listen`):
    ///
    /// ```
    /// use ratatoskr::rule::RuleFile;
    /// let toml = r#"
    ///     [[route]]
    ///     hostname = "app.local"
    ///     target   = "http://192.168.1.11:3000"
    /// "#;
    /// RuleFile::from_toml("https.toml", toml).unwrap()
    ///     .validate_each().unwrap();
    /// ```
    pub fn from_toml(path: impl Into<std::path::PathBuf>, s: &str) -> Result<Self> {
        let path = path.into();
        toml::from_str(s).map_err(|source| Error::TomlParse { path, source })
    }

    /// Validate every rule and route in the file. Cross-file uniqueness is
    /// enforced by [`super::RuleSet::from_files`].
    pub fn validate_each(&self) -> Result<()> {
        for r in &self.rule {
            r.validate()?;
        }
        // Routes have no rule-level grouping; validate each with a
        // synthetic "<file-level>" tag in the error path. Cross-file
        // hostname uniqueness is enforced at RuleSet build time.
        for route in &self.route {
            validate_http_route("<route>", route)?;
        }
        Ok(())
    }
}
