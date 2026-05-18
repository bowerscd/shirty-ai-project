//! Server configuration schema (`/etc/yggdrasil/config.toml`).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use yggdrasil_proto::Error as ProtoError;

/// Top-level server config file. Validated on load.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub server:  ServerSection,
    #[serde(default)]
    pub metrics: MetricsSection,
    #[serde(default)]
    pub control: ControlSection,
    /// The single enrolled ratatoskr peer. Empty `public_key_hex` means
    /// no peer is enrolled yet — TOFU candidates may then be staged via `yggdrasilctl`.
    #[serde(default)]
    pub peer:    PeerSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    /// UDP socket to receive ratatoskr heartbeats on.
    pub heartbeat_listen: SocketAddr,
    /// Directory containing `*.toml` branch files.
    pub branches_dir: PathBuf,
    /// Per-host state directory (TOFU staging, runtime markers).
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    /// Path to the server's static X25519 identity (created by `yggdrasil keygen`).
    #[serde(default = "default_identity_file")]
    pub identity_file: PathBuf,
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
    /// Hex-encoded X25519 public key of the enrolled ratatoskr peer.
    /// Empty string means "not yet enrolled".
    #[serde(default)]
    pub public_key_hex: String,
    /// Re-handshake after at most this much time (default 1h).
    #[serde(default = "default_rekey_interval", with = "humantime_serde")]
    pub rekey_interval: Duration,
}

fn default_state_dir() -> PathBuf       { PathBuf::from("/var/lib/yggdrasil") }
fn default_identity_file() -> PathBuf   { PathBuf::from("/etc/yggdrasil/identity.key") }
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

    fn validate(&self) -> Result<(), ConfigError> {
        if !self.peer.public_key_hex.is_empty() {
            let bytes = hex::decode(&self.peer.public_key_hex)
                .map_err(|_| ConfigError::Invalid("peer.public_key_hex is not valid hex"))?;
            if bytes.len() != yggdrasil_proto::auth::PUBLIC_KEY_LEN {
                return Err(ConfigError::Invalid(
                    "peer.public_key_hex must decode to exactly 32 bytes",
                ));
            }
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
    Invalid(&'static str),
}
