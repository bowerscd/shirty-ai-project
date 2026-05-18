//! CLI surface for the `yggdrasil` server binary.

use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::config::Mode;

/// `yggdrasil` — reverse proxy server.
#[derive(Debug, Parser)]
#[command(name = "yggdrasil", version, about, propagate_version = true)]
pub struct Cli {
    /// Output format for structured logs.
    #[arg(long, value_enum, default_value_t = LogFormat::Json, global = true,
          env = "YGGDRASIL_LOG_FORMAT")]
    pub log_format: LogFormat,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LogFormat {
    /// One JSON object per line (suitable for journald, ELK, Loki, etc.).
    Json,
    /// Human-readable single-line format with ANSI colour (suitable for terminals).
    Pretty,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the proxy server.
    Run(RunArgs),
    /// Generate the server's static X25519 identity keypair.
    Keygen(KeygenArgs),
    /// Emit an out-of-band enrollment token for a huginn peer.
    #[command(name = "enroll-token")]
    EnrollToken(EnrollTokenArgs),
    /// Print the build version.
    Version,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Path to the server configuration file.
    #[arg(long, default_value = "/etc/yggdrasil/config.toml", env = "YGGDRASIL_CONFIG")]
    pub config: PathBuf,

    /// Override the rules directory specified in the config file.
    ///
    /// See [docs/configuration.md](../docs/configuration.md) for the `[server].rules_dir`
    /// field this overrides.
    #[arg(long, env = "YGGDRASIL_RULES_DIR")]
    pub rules_dir: Option<PathBuf>,

    /// Override `[server].mode`. English-only; no aliases.
    ///
    /// See [docs/configuration.md](../docs/configuration.md) for the per-mode
    /// validation matrix.
    #[arg(long, value_enum)]
    pub mode: Option<ModeArg>,

    /// Hard-override every rule's `listen` IP with this address. The rule's
    /// port is preserved; only the IP is replaced. Overrides
    /// `[server].default_bind`.
    ///
    /// See [docs/configuration.md](../docs/configuration.md) for the bind-override semantics.
    #[arg(long, value_name = "IP")]
    pub bind: Option<IpAddr>,
}

/// CLI-side mirror of [`crate::config::Mode`]. Kept as a separate type so
/// clap's `ValueEnum` derive doesn't have to coexist with serde's
/// `rename_all = "lowercase"` on the same enum.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ModeArg {
    Relay,
    Terminal,
}

impl From<ModeArg> for Mode {
    fn from(m: ModeArg) -> Self {
        match m {
            ModeArg::Relay => Mode::Relay,
            ModeArg::Terminal => Mode::Terminal,
        }
    }
}

#[derive(Debug, Args)]
pub struct KeygenArgs {
    /// Where to write the secret key (mode 0600).
    #[arg(long, default_value = "/etc/yggdrasil/identity.key")]
    pub identity_file: PathBuf,

    /// Overwrite the file if it already exists.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct EnrollTokenArgs {
    /// X25519 public key of the huginn peer (hex-encoded, 64 chars).
    #[arg(long)]
    pub peer_pubkey: String,

    /// Endpoint hint embedded in the token (host:port that huginn should heartbeat to).
    #[arg(long)]
    pub endpoint: String,

    /// Output path for the binary token.
    #[arg(long, short = 'o', default_value = "huginn-enrollment.token")]
    pub output: PathBuf,

    /// Path to the yggdrasil server config (used to look up the local pubkey).
    #[arg(long, default_value = "/etc/yggdrasil/config.toml")]
    pub config: PathBuf,

    /// Overwrite `peer.public_key_hex` in the config even if a different peer
    /// is already enrolled.
    #[arg(long)]
    pub force: bool,
}
