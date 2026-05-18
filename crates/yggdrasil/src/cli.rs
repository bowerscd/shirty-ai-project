//! CLI surface for the `yggdrasil` server binary.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

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
    /// Emit an out-of-band enrollment token for a ratatoskr peer.
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

    /// Override the branches directory specified in the config file.
    #[arg(long, env = "YGGDRASIL_BRANCHES_DIR")]
    pub branches_dir: Option<PathBuf>,
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
    /// X25519 public key of the ratatoskr peer (hex-encoded, 64 chars).
    #[arg(long)]
    pub peer_pubkey: String,

    /// Endpoint hint embedded in the token (host:port that ratatoskr should heartbeat to).
    #[arg(long)]
    pub endpoint: String,

    /// Output path for the binary token.
    #[arg(long, short = 'o', default_value = "ratatoskr-enrollment.token")]
    pub output: PathBuf,

    /// Path to the yggdrasil server config (used to look up the local pubkey).
    #[arg(long, default_value = "/etc/yggdrasil/config.toml")]
    pub config: PathBuf,

    /// Overwrite `peer.public_key_hex` in the config even if a different peer
    /// is already enrolled.
    #[arg(long)]
    pub force: bool,
}
