//! Client configuration schema (`/etc/ratatoskr/config.toml`).

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use yggdrasil_proto::Error as ProtoError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub client: ClientSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSection {
    /// `host:port` of the yggdrasil heartbeat listener. Hostname is resolved on
    /// each handshake attempt so the public IP of yggdrasil itself can change too.
    pub yggdrasil_endpoint: String,
    /// Hex-encoded X25519 public key of the yggdrasil server.
    pub yggdrasil_pubkey_hex: String,
    /// Path to this client's static X25519 identity file (created by `ratatoskr keygen`).
    #[serde(default = "default_identity_file")]
    pub identity_file: PathBuf,
    /// How often to emit a heartbeat. Default: 5s.
    #[serde(default = "default_heartbeat_interval", with = "humantime_serde")]
    pub heartbeat_interval: Duration,
    /// Re-handshake after at most this much time. Default: 1h.
    #[serde(default = "default_rekey_interval", with = "humantime_serde")]
    pub rekey_interval: Duration,
}

fn default_identity_file() -> PathBuf       { PathBuf::from("/etc/ratatoskr/identity.key") }
fn default_heartbeat_interval() -> Duration { Duration::from_secs(5) }
fn default_rekey_interval() -> Duration     { Duration::from_secs(3600) }

impl ClientConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
            path: path.to_path_buf(),
            source: e,
        })?;
        let cfg: ClientConfig = toml::from_str(&raw).map_err(|e| ConfigError::Proto(ProtoError::TomlParse {
            path:   path.to_path_buf(),
            source: e,
        }))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.client.yggdrasil_endpoint.trim().is_empty() {
            return Err(ConfigError::Invalid("client.yggdrasil_endpoint must be set"));
        }
        let bytes = hex::decode(&self.client.yggdrasil_pubkey_hex)
            .map_err(|_| ConfigError::Invalid("client.yggdrasil_pubkey_hex is not valid hex"))?;
        if bytes.len() != yggdrasil_proto::auth::PUBLIC_KEY_LEN {
            return Err(ConfigError::Invalid(
                "client.yggdrasil_pubkey_hex must decode to exactly 32 bytes",
            ));
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
