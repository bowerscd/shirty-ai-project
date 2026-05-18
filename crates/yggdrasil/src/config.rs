//! Server configuration schema (`/etc/yggdrasil/config.toml`).

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use ratatoskr::Error as ProtoError;

/// Top-level server config file. Validated on load.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub server:  ServerSection,
    #[serde(default)]
    pub metrics: MetricsSection,
    #[serde(default)]
    pub control: ControlSection,
    /// The single enrolled huginn peer. Empty `public_key_hex` means
    /// no peer is enrolled yet — TOFU candidates may then be staged via `yggdrasilctl`.
    #[serde(default)]
    pub peer:    PeerSection,
}

/// Runtime mode selector. English-only operator surface (no serde aliases).
///
/// * `Relay` — cloud-side daemon. Dials the heartbeat-discovered peer IP.
/// * `Terminal` — home-side daemon. Dials a fixed `upstream_addr` per rule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Relay,
    Terminal,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::Terminal => "terminal",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    /// Runtime mode. Defaults to `relay`.
    #[serde(default)]
    pub mode: Mode,
    /// UDP socket to receive huginn heartbeats on. Required in `relay` mode;
    /// must be unset in `terminal` mode (validated on load).
    #[serde(default)]
    pub heartbeat_listen: Option<SocketAddr>,
    /// Directory containing `*.toml` rule files. Defaults to `/etc/yggdrasil/conf.d`.
    #[serde(default = "default_rules_dir")]
    pub rules_dir: PathBuf,
    /// Hard-override for every rule's `listen` IP. When set, each rule binds on
    /// `(default_bind, rule.listen.port())` regardless of what the rule's TOML
    /// `listen` field specifies (the port is preserved). Use to share one
    /// config across hosts with different network interfaces.
    #[serde(default)]
    pub default_bind: Option<IpAddr>,
    /// Per-host state directory (TOFU staging, runtime markers).
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    /// Path to the server's static X25519 identity (created by `yggdrasil keygen`).
    #[serde(default = "default_identity_file")]
    pub identity_file: PathBuf,
    /// Root directory under which per-rule TLS material lives by convention.
    /// Individual `[[rule.route]]` blocks may still reference cert/key files by
    /// absolute path; this directory is the recommended root for those paths
    /// and the location `yggdrasilctl certs list` enumerates.
    #[serde(default = "default_cert_dir")]
    pub cert_dir: PathBuf,
    /// Default TLS certificate (full chain, PEM) used by L7 `https` rules
    /// whose routes do not specify their own `cert`. Must be set together
    /// with `default_key` (XOR-validated on load).
    #[serde(default)]
    pub default_cert: Option<PathBuf>,
    /// Default TLS private key (PEM) paired with `default_cert`. Must be set
    /// together with `default_cert`.
    #[serde(default)]
    pub default_key:  Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsSection {
    /// Address to expose Prometheus `/metrics` on. Leave at the default `127.0.0.1:9090`
    /// and front it with whatever scraper you trust.
    pub listen: SocketAddr,
}

impl Default for MetricsSection {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:9090".parse().expect("static addr"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlSection {
    /// Unix domain socket for `yggdrasilctl`. Should be group-readable by the
    /// admin group only.
    pub socket: PathBuf,
}

impl Default for ControlSection {
    fn default() -> Self {
        Self {
            socket: PathBuf::from("/run/yggdrasil/control.sock"),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerSection {
    /// Hex-encoded X25519 public key of the enrolled huginn peer.
    /// Empty string means "not yet enrolled".
    #[serde(default)]
    pub public_key_hex: String,
    /// Re-handshake after at most this much time (default 1h).
    #[serde(default = "default_rekey_interval", with = "humantime_serde")]
    pub rekey_interval: Duration,
}

fn default_state_dir() -> PathBuf       { PathBuf::from("/var/lib/yggdrasil") }
fn default_identity_file() -> PathBuf   { PathBuf::from("/etc/yggdrasil/identity.key") }
fn default_rules_dir() -> PathBuf       { PathBuf::from("/etc/yggdrasil/conf.d") }
fn default_cert_dir() -> PathBuf        { PathBuf::from("/etc/yggdrasil/certs") }
fn default_rekey_interval() -> Duration { Duration::from_secs(3600) }

impl ServerConfig {
    /// Load and validate a config file from disk.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
            path: path.to_path_buf(),
            source: e,
        })?;
        let cfg: ServerConfig = toml::from_str(&raw).map_err(|e| ConfigError::Proto(ProtoError::TomlParse {
            path:   path.to_path_buf(),
            source: e,
        }))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate the in-memory config. Called automatically by [`Self::load`];
    /// expose publicly so consumers that mutate config after load (e.g.
    /// applying CLI overrides) can re-validate before use.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.peer.public_key_hex.is_empty() {
            let bytes = hex::decode(&self.peer.public_key_hex)
                .map_err(|_| ConfigError::Invalid("peer.public_key_hex is not valid hex".into()))?;
            if bytes.len() != ratatoskr::auth::PUBLIC_KEY_LEN {
                return Err(ConfigError::Invalid(
                    "peer.public_key_hex must decode to exactly 32 bytes".into(),
                ));
            }
        }
        match self.server.mode {
            Mode::Relay => {
                if self.server.heartbeat_listen.is_none() {
                    return Err(ConfigError::Invalid(
                        "server.heartbeat_listen is required in relay mode".into(),
                    ));
                }
            }
            Mode::Terminal => {
                if self.server.heartbeat_listen.is_some() {
                    return Err(ConfigError::Invalid(
                        "server.heartbeat_listen must not be set in terminal mode".into(),
                    ));
                }
                if !self.peer.public_key_hex.is_empty() {
                    return Err(ConfigError::Invalid(
                        "peer.public_key_hex must be empty in terminal mode".into(),
                    ));
                }
            }
        }
        match (&self.server.default_cert, &self.server.default_key) {
            (Some(_), None) => {
                return Err(ConfigError::Invalid(
                    "server.default_cert is set but server.default_key is not; \
                     both must be set together or both omitted"
                        .into(),
                ));
            }
            (None, Some(_)) => {
                return Err(ConfigError::Invalid(
                    "server.default_key is set but server.default_cert is not; \
                     both must be set together or both omitted"
                        .into(),
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read {path}: {source}")]
    Read { path: PathBuf, source: std::io::Error },
    #[error(transparent)]
    Proto(#[from] ProtoError),
    #[error("invalid config: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<ServerConfig, ConfigError> {
        let cfg: ServerConfig = toml::from_str(s).map_err(|e| ConfigError::Proto(ProtoError::TomlParse {
            path: PathBuf::from("test.toml"),
            source: e,
        }))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn relay_minimal_toml() -> &'static str {
        r#"
        [server]
        heartbeat_listen = "0.0.0.0:51820"
        "#
    }

    fn terminal_minimal_toml() -> &'static str {
        r#"
        [server]
        mode = "terminal"
        "#
    }

    #[test]
    fn default_mode_is_relay() {
        let cfg = parse(relay_minimal_toml()).unwrap();
        assert_eq!(cfg.server.mode, Mode::Relay);
    }

    #[test]
    fn parses_explicit_relay() {
        let cfg = parse(
            r#"
            [server]
            mode = "relay"
            heartbeat_listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.server.mode, Mode::Relay);
    }

    #[test]
    fn parses_explicit_terminal() {
        let cfg = parse(terminal_minimal_toml()).unwrap();
        assert_eq!(cfg.server.mode, Mode::Terminal);
        assert!(cfg.server.heartbeat_listen.is_none());
    }

    #[test]
    fn unknown_mode_is_rejected() {
        let err = parse(
            r#"
            [server]
            mode = "verdfolnir"
            heartbeat_listen = "0.0.0.0:51820"
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Proto(_)));
    }

    #[test]
    fn relay_without_heartbeat_listen_is_rejected() {
        let err = parse(
            r#"
            [server]
            mode = "relay"
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Invalid(s) if s.contains("heartbeat_listen is required")));
    }

    #[test]
    fn terminal_with_heartbeat_listen_is_rejected() {
        let err = parse(
            r#"
            [server]
            mode = "terminal"
            heartbeat_listen = "0.0.0.0:51820"
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Invalid(s) if s.contains("must not be set in terminal")));
    }

    #[test]
    fn terminal_with_peer_pubkey_is_rejected() {
        let err = parse(
            r#"
            [server]
            mode = "terminal"

            [peer]
            public_key_hex = "0000000000000000000000000000000000000000000000000000000000000000"
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Invalid(s) if s.contains("must be empty in terminal")));
    }

    #[test]
    fn rules_dir_defaults_to_conf_d() {
        let cfg = parse(relay_minimal_toml()).unwrap();
        assert_eq!(cfg.server.rules_dir, PathBuf::from("/etc/yggdrasil/conf.d"));
    }

    #[test]
    fn rules_dir_override_parses() {
        let cfg = parse(
            r#"
            [server]
            heartbeat_listen = "0.0.0.0:51820"
            rules_dir = "/srv/yggdrasil/rules"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.server.rules_dir, PathBuf::from("/srv/yggdrasil/rules"));
    }

    #[test]
    fn default_bind_parses() {
        let cfg = parse(
            r#"
            [server]
            heartbeat_listen = "0.0.0.0:51820"
            default_bind = "192.168.1.5"
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.server.default_bind,
            Some("192.168.1.5".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn default_bind_absent_is_none() {
        let cfg = parse(relay_minimal_toml()).unwrap();
        assert!(cfg.server.default_bind.is_none());
    }

    #[test]
    fn unknown_field_is_rejected() {
        let err = parse(
            r#"
            [server]
            heartbeat_listen = "0.0.0.0:51820"
            branches_dir = "/etc/yggdrasil/branches"
            "#,
        )
        .err()
        .unwrap();
        // Old field name no longer accepted (pre-release; clean break).
        assert!(matches!(err, ConfigError::Proto(_)));
    }

    #[test]
    fn cert_dir_defaults_to_etc_yggdrasil_certs() {
        let cfg = parse(relay_minimal_toml()).unwrap();
        assert_eq!(cfg.server.cert_dir, PathBuf::from("/etc/yggdrasil/certs"));
    }

    #[test]
    fn cert_dir_override_parses() {
        let cfg = parse(
            r#"
            [server]
            heartbeat_listen = "0.0.0.0:51820"
            cert_dir = "/srv/yggdrasil/tls"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.server.cert_dir, PathBuf::from("/srv/yggdrasil/tls"));
    }

    #[test]
    fn default_cert_and_key_set_together_parses() {
        let cfg = parse(
            r#"
            [server]
            heartbeat_listen = "0.0.0.0:51820"
            default_cert = "/etc/yggdrasil/certs/wildcard.pem"
            default_key  = "/etc/yggdrasil/certs/wildcard.key"
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.server.default_cert,
            Some(PathBuf::from("/etc/yggdrasil/certs/wildcard.pem"))
        );
        assert_eq!(
            cfg.server.default_key,
            Some(PathBuf::from("/etc/yggdrasil/certs/wildcard.key"))
        );
    }

    #[test]
    fn default_cert_without_key_is_rejected() {
        let err = parse(
            r#"
            [server]
            heartbeat_listen = "0.0.0.0:51820"
            default_cert = "/etc/yggdrasil/certs/wildcard.pem"
            "#,
        )
        .err()
        .unwrap();
        assert!(
            matches!(err, ConfigError::Invalid(s)
                if s.contains("default_cert is set but server.default_key is not"))
        );
    }

    #[test]
    fn default_key_without_cert_is_rejected() {
        let err = parse(
            r#"
            [server]
            heartbeat_listen = "0.0.0.0:51820"
            default_key = "/etc/yggdrasil/certs/wildcard.key"
            "#,
        )
        .err()
        .unwrap();
        assert!(
            matches!(err, ConfigError::Invalid(s)
                if s.contains("default_key is set but server.default_cert is not"))
        );
    }

    #[test]
    fn default_cert_and_key_absent_is_ok() {
        let cfg = parse(relay_minimal_toml()).unwrap();
        assert!(cfg.server.default_cert.is_none());
        assert!(cfg.server.default_key.is_none());
    }

    #[test]
    fn terminal_mode_accepts_cert_settings() {
        // Cert config is mode-agnostic for now (Phase 6b lays the groundwork;
        // the actual L7 frontend is gated to relay mode in a later phase).
        let cfg = parse(
            r#"
            [server]
            mode = "terminal"
            cert_dir = "/etc/yggdrasil/tls"
            default_cert = "/etc/yggdrasil/tls/wc.pem"
            default_key  = "/etc/yggdrasil/tls/wc.key"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.server.mode, Mode::Terminal);
        assert_eq!(cfg.server.cert_dir, PathBuf::from("/etc/yggdrasil/tls"));
        assert!(cfg.server.default_cert.is_some());
    }
}
