//! CLI surface for the `yggdrasil` server binary.
//!
//! As of the chain-control rework the daemon binary exposes only `run`
//! (and the inherent `version` subcommand). Identity management,
//! enrollment, and administrative queries live in `yggdrasilctl`.

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
    /// Print the build version.
    Version,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Path to the server configuration file.
    #[arg(long, default_value = "/etc/yggdrasil/config.toml", env = "YGGDRASIL_CONFIG")]
    pub config: PathBuf,

    /// Override the rules directory specified in the config file.
    #[arg(long, env = "YGGDRASIL_RULES_DIR")]
    pub rules_dir: Option<PathBuf>,

    /// Override `[server].mode`. English-only; no aliases.
    #[arg(long, value_enum)]
    pub mode: Option<ModeArg>,

    /// Hard-override every rule's `listen` IP with this address. The rule's
    /// port is preserved; only the IP is replaced. Overrides
    /// `[server].default_bind`.
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
