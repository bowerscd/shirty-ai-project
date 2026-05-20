//! Server configuration schema (`/etc/yggdrasil/config.toml`).
//!
//! The config is organised into a small number of named tables:
//!
//! * `[server]` — paths and defaults.
//! * `[metrics]` — Prometheus exporter listen address.
//! * `[control]` — `yggdrasilctl` Unix-domain socket path.
//! * `[dial]` (optional) — this node's outbound chain client: who to
//!   dial, what to pin, how often to heartbeat. Drives both relay- and
//!   terminal-mode nodes when set.
//! * `[accept]` (optional) — single enrolled inbound chain peer plus its
//!   listener socket. When present and `pubkey` is set, the node listens
//!   for inbound chain traffic on `listen` and accepts only from `pubkey`.
//!
//! All public keys use the tagged textual form `<algo>:<hex>`; bare hex is
//! rejected.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use ratatoskr::pubkey::PubKey;
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
    /// Outbound chain client. When set, this node dials the configured
    /// upstream and sends heartbeats. Terminal-mode nodes with no upstream
    /// link omit this entirely.
    #[serde(default)]
    pub dial:    Option<DialSection>,
    /// Inbound chain peer. When set, the node accepts inbound chain
    /// traffic on `listen` only from `pubkey`. v1 supports exactly one
    /// inbound peer per node.
    #[serde(default)]
    pub accept:  Option<AcceptSection>,
}

/// Effective runtime mode, derived from top-level chain sections.
///
/// * `Relay` — `[accept]` is present (with or without `[dial]`).
/// * `Terminal` — only `[dial]` is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
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
    /// Path to the node's static X25519 identity. Auto-generated on first
    /// start if the file does not exist.
    #[serde(default = "default_identity_file")]
    pub identity_file: PathBuf,
    /// Root directory under which per-rule TLS material lives by convention.
    #[serde(default = "default_cert_dir")]
    pub cert_dir: PathBuf,
    /// Default TLS certificate (full chain, PEM) used by L7 `https` rules
    /// whose routes do not specify their own `cert`. Must be set together
    /// with `default_key` (XOR-validated on load).
    #[serde(default)]
    pub default_cert: Option<PathBuf>,
    /// Default TLS private key (PEM) paired with `default_cert`.
    #[serde(default)]
    pub default_key:  Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsSection {
    /// Address to expose Prometheus `/metrics` on. Leave at the default
    /// `127.0.0.1:9090` and front it with whatever scraper you trust.
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

/// `[dial]` — outbound chain client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DialSection {
    /// Tagged pubkey (`x25519:<hex>`) of the upstream node we dial.
    pub pubkey: PubKey,
    /// Endpoint to dial: `host:port` or `[ipv6]:port`. Re-resolved on
    /// every reconnection attempt; DNS rebinds during the lifetime of the
    /// daemon are honoured.
    pub endpoint: String,
    /// How often to send heartbeats. Default 5 s.
    #[serde(default = "default_heartbeat_interval", with = "humantime_serde")]
    pub heartbeat_interval: Duration,
    /// Re-handshake after at most this much time (default 1h).
    #[serde(default = "default_rekey_interval", with = "humantime_serde")]
    pub rekey_interval: Duration,
}

/// `[accept]` — single enrolled inbound chain peer plus its listener socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptSection {
    /// Tagged pubkey (`x25519:<hex>`) of the enrolled inbound peer.
    pub pubkey: PubKey,
    /// UDP socket to bind on. Required.
    pub listen: SocketAddr,
    /// Re-handshake after at most this much time (default 1h).
    #[serde(default = "default_rekey_interval", with = "humantime_serde")]
    pub rekey_interval: Duration,
}

fn default_state_dir() -> PathBuf       { PathBuf::from("/var/lib/yggdrasil") }
fn default_identity_file() -> PathBuf   { PathBuf::from("/etc/yggdrasil/identity.key") }
fn default_rules_dir() -> PathBuf       { PathBuf::from("/etc/yggdrasil/conf.d") }
fn default_cert_dir() -> PathBuf        { PathBuf::from("/etc/yggdrasil/certs") }
fn default_rekey_interval() -> Duration { Duration::from_secs(3600) }
fn default_heartbeat_interval() -> Duration { Duration::from_secs(5) }

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

    /// Derive effective runtime mode from section presence.
    pub fn derived_mode(&self) -> Result<Mode, ConfigError> {
        match (self.dial.is_some(), self.accept.is_some()) {
            (true, false) => Ok(Mode::Terminal),
            (false, true) | (true, true) => Ok(Mode::Relay),
            (false, false) => Err(ConfigError::Invalid(
                "config must define at least one of [dial] or [accept]".into(),
            )),
        }
    }

    /// Validate the in-memory config.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // ---- Derived mode shape ----
        let _ = self.derived_mode()?;

        // ---- [dial] sanity ----
        if let Some(up) = &self.dial {
            if up.endpoint.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "[dial].endpoint must not be empty".into(),
                ));
            }
            if !up.endpoint.contains(':') {
                return Err(ConfigError::Invalid(format!(
                    "[dial].endpoint must be host:port (got {:?})",
                    up.endpoint
                )));
            }
            if up.heartbeat_interval.is_zero() {
                return Err(ConfigError::Invalid(
                    "[dial].heartbeat_interval must be > 0".into(),
                ));
            }
            if up.rekey_interval.is_zero() {
                return Err(ConfigError::Invalid(
                    "[dial].rekey_interval must be > 0".into(),
                ));
            }
        }

        // ---- [accept] sanity ----
        if let Some(acc) = &self.accept {
            if acc.rekey_interval.is_zero() {
                return Err(ConfigError::Invalid(
                    "[accept].rekey_interval must be > 0".into(),
                ));
            }
        }

        // ---- TLS default cert/key XOR ----
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

        [accept]
        pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        listen = "0.0.0.0:51820"
        "#
    }

    fn terminal_minimal_toml() -> &'static str {
        r#"
        [server]

        [dial]
        pubkey   = "x25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        endpoint = "u.example.com:7117"
        "#
    }

    #[test]
    fn derived_mode_is_relay_when_accept_only() {
        let cfg = parse(relay_minimal_toml()).unwrap();
        assert_eq!(cfg.derived_mode().unwrap(), Mode::Relay);
    }

    #[test]
    fn derived_mode_is_terminal_when_dial_only() {
        let cfg = parse(terminal_minimal_toml()).unwrap();
        assert_eq!(cfg.derived_mode().unwrap(), Mode::Terminal);
    }

    #[test]
    fn derived_mode_is_relay_when_dial_and_accept_present() {
        let cfg = parse(
            r#"
            [server]

            [dial]
            pubkey   = "x25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            endpoint = "u.example.com:7117"

            [accept]
            pubkey = "x25519:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.derived_mode().unwrap(), Mode::Relay);
    }

    #[test]
    fn missing_dial_and_accept_is_rejected() {
        let err = parse(
            r#"
            [server]
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Invalid(s) if s.contains("at least one of [dial] or [accept]")));
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
            rules_dir = "/srv/yggdrasil/rules"

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
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
            default_bind = "192.168.1.5"

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.server.default_bind,
            Some("192.168.1.5".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn unknown_field_is_rejected() {
        let err = parse(
            r#"
            [server]
            branches_dir = "/etc/yggdrasil/branches"
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Proto(_)));
    }

    #[test]
    fn cert_dir_defaults_to_etc_yggdrasil_certs() {
        let cfg = parse(relay_minimal_toml()).unwrap();
        assert_eq!(cfg.server.cert_dir, PathBuf::from("/etc/yggdrasil/certs"));
    }

    #[test]
    fn default_cert_and_key_set_together_parses() {
        let cfg = parse(
            r#"
            [server]
            default_cert = "/etc/yggdrasil/certs/wildcard.pem"
            default_key  = "/etc/yggdrasil/certs/wildcard.key"

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        assert!(cfg.server.default_cert.is_some());
        assert!(cfg.server.default_key.is_some());
    }

    #[test]
    fn default_cert_without_key_is_rejected() {
        let err = parse(
            r#"
            [server]
            default_cert = "/etc/yggdrasil/certs/wildcard.pem"

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
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
            default_key = "/etc/yggdrasil/certs/wildcard.key"

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .err()
        .unwrap();
        assert!(
            matches!(err, ConfigError::Invalid(s)
                if s.contains("default_key is set but server.default_cert is not"))
        );
    }

    // ---- [dial] ----

    #[test]
    fn parses_dial_section() {
        let cfg = parse(
            r#"
            [server]

            [dial]
            pubkey   = "x25519:1111111111111111111111111111111111111111111111111111111111111111"
            endpoint = "u.example.com:7117"
            "#,
        )
        .unwrap();
        let up = cfg.dial.expect("dial parsed");
        assert_eq!(up.endpoint, "u.example.com:7117");
        assert_eq!(up.heartbeat_interval, Duration::from_secs(5));
        assert_eq!(up.rekey_interval, Duration::from_secs(3600));
        assert_eq!(
            up.pubkey,
            PubKey::X25519([0x11; ratatoskr::auth::PUBLIC_KEY_LEN])
        );
    }

    #[test]
    fn dial_rejects_untagged_pubkey() {
        let err = parse(
            r#"
            [server]

            [dial]
            pubkey   = "1111111111111111111111111111111111111111111111111111111111111111"
            endpoint = "host:1"
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Proto(_)));
    }

    #[test]
    fn dial_rejects_empty_endpoint() {
        let err = parse(
            r#"
            [server]

            [dial]
            pubkey   = "x25519:1111111111111111111111111111111111111111111111111111111111111111"
            endpoint = ""
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Invalid(s) if s.contains("endpoint must not be empty")));
    }

    #[test]
    fn dial_rejects_endpoint_without_port() {
        let err = parse(
            r#"
            [server]

            [dial]
            pubkey   = "x25519:1111111111111111111111111111111111111111111111111111111111111111"
            endpoint = "host-no-port"
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Invalid(s) if s.contains("host:port")));
    }

    #[test]
    fn dial_parses_humantime_intervals() {
        let cfg = parse(
            r#"
            [server]

            [dial]
            pubkey             = "x25519:2222222222222222222222222222222222222222222222222222222222222222"
            endpoint           = "host:1"
            heartbeat_interval = "2s"
            rekey_interval     = "30m"
            "#,
        )
        .unwrap();
        let up = cfg.dial.unwrap();
        assert_eq!(up.heartbeat_interval, Duration::from_secs(2));
        assert_eq!(up.rekey_interval, Duration::from_secs(30 * 60));
    }

    // ---- [accept] ----

    #[test]
    fn relay_with_accept_section_parses() {
        let cfg = parse(
            r#"
            [server]

            [accept]
            pubkey = "x25519:3333333333333333333333333333333333333333333333333333333333333333"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        let acc = cfg.accept.expect("accept parsed");
        assert_eq!(
            acc.pubkey,
            PubKey::X25519([0x33; ratatoskr::auth::PUBLIC_KEY_LEN])
        );
        assert_eq!(acc.listen, "0.0.0.0:51820".parse::<SocketAddr>().unwrap());
        assert_eq!(acc.rekey_interval, Duration::from_secs(3600));
    }

    #[test]
    fn accept_missing_listen_is_rejected() {
        let err = parse(
            r#"
            [server]

            [accept]
            pubkey = "x25519:4444444444444444444444444444444444444444444444444444444444444444"
            "#,
        )
        .err()
        .unwrap();
        // Missing required `listen` is a TOML / serde deserialisation error,
        // surfaced through ConfigError::Proto.
        assert!(matches!(err, ConfigError::Proto(_)));
    }

    #[test]
    fn accept_missing_pubkey_is_rejected() {
        let err = parse(
            r#"
            [server]

            [accept]
            listen = "0.0.0.0:51820"
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Proto(_)));
    }

    #[test]
    fn terminal_mode_accepts_only_dial() {
        let cfg = parse(
            r#"
            [server]

            [dial]
            pubkey   = "x25519:6666666666666666666666666666666666666666666666666666666666666666"
            endpoint = "u.example.com:7117"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.derived_mode().unwrap(), Mode::Terminal);
        assert!(cfg.dial.is_some());
        assert!(cfg.accept.is_none());
    }

    #[test]
    fn relay_with_both_dial_and_accept_parses() {
        let cfg = parse(
            r#"
            [server]

            [dial]
            pubkey   = "x25519:7777777777777777777777777777777777777777777777777777777777777777"
            endpoint = "uu.example.com:7117"

            [accept]
            pubkey = "x25519:8888888888888888888888888888888888888888888888888888888888888888"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        assert!(cfg.dial.is_some());
        assert!(cfg.accept.is_some());
    }

    #[test]
    fn empty_chain_sections_are_invalid() {
        let err = parse(
            r#"
            [server]
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Invalid(s) if s.contains("at least one of [dial] or [accept]")));
    }
}
