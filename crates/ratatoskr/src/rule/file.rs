//! [`RuleFile`]: a single `conf.d/*.toml` deserialised from TOML.
//!
//! Split out from the original monolithic `rule.rs` (Phase B1).

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::rule_def::Rule;

/// A single rule file (`/etc/yggdrasil/conf.d/*.toml`) deserialised from TOML.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleFile {
    #[serde(default)]
    pub rule: Vec<Rule>,
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
    /// Terminal-mode rules with a static LAN address (`target_addr`):
    ///
    /// ```
    /// use ratatoskr::rule::RuleFile;
    /// let toml = r#"
    ///     [[rule]]
    ///     name        = "home-ssh"
    ///     listen      = "0.0.0.0:2222"
    ///     protocol    = "tcp"
    ///     target_addr = "192.168.1.10:22"
    /// "#;
    /// RuleFile::from_toml("terminal.toml", toml).unwrap()
    ///     .validate_each().unwrap();
    /// ```
    ///
    /// Terminal-mode rule with a DNS-resolved upstream (`target_host`),
    /// re-resolved every 30 s by the daemon:
    ///
    /// ```
    /// use ratatoskr::rule::RuleFile;
    /// let toml = r#"
    ///     [[rule]]
    ///     name        = "home-printer"
    ///     listen      = "0.0.0.0:9100"
    ///     protocol    = "tcp"
    ///     target_host = "printer.lan:9100"
    /// "#;
    /// RuleFile::from_toml("terminal-dns.toml", toml).unwrap()
    ///     .validate_each().unwrap();
    /// ```
    ///
    /// HTTPS L7 frontend (terminal-mode only; SNI-dispatches to multiple
    /// LAN backends):
    ///
    /// ```
    /// use ratatoskr::rule::RuleFile;
    /// let toml = r#"
    ///     [[rule]]
    ///     name     = "home-https"
    ///     listen   = "0.0.0.0:443"
    ///     protocol = "https"
    ///
    ///       [[rule.route]]
    ///       hostname = "app.local"
    ///       target   = "http://192.168.1.11:3000"
    ///       cert     = "ephemeral"
    /// "#;
    /// RuleFile::from_toml("https.toml", toml).unwrap()
    ///     .validate_each().unwrap();
    /// ```
    ///
    /// Picking exactly one of `target_port`, `target_addr`, or
    /// `target_host` is a per-rule validation requirement; rules that
    /// omit all three (or set more than one) are rejected by
    /// [`RuleFile::validate_each`].
    pub fn from_toml(path: impl Into<std::path::PathBuf>, s: &str) -> Result<Self> {
        let path = path.into();
        toml::from_str(s).map_err(|source| Error::TomlParse { path, source })
    }

    /// Validate every rule in the file. Cross-file uniqueness is enforced by
    /// [`super::RuleSet::from_files`].
    pub fn validate_each(&self) -> Result<()> {
        for r in &self.rule {
            r.validate()?;
        }
        Ok(())
    }
}
