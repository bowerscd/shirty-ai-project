//! `yggdrasil` (the daemon) command-tree definitions.
//!
//! Moved out of `crates/yggdrasil/src/cli.rs` so `crates/yggdrasil/build.rs`
//! (a separate compile unit) can introspect the same definitions.

use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// `yggdrasil` — reverse proxy server.
#[derive(Debug, Parser)]
#[command(
    name = "yggdrasil",
    version,
    about = "High-performance TCP/UDP reverse proxy for residential upstreams",
    propagate_version = true
)]
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
    /// Print a shell-completion script for `yggdrasil` to stdout.
    Completions(crate::completions::CompletionsArgs),
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Path to the server configuration file.
    #[arg(
        long,
        default_value = "/etc/yggdrasil/config.toml",
        env = "YGGDRASIL_CONFIG"
    )]
    pub config: PathBuf,

    /// Override the rules directory specified in the config file.
    #[arg(long, env = "YGGDRASIL_RULES_DIR")]
    pub rules_dir: Option<PathBuf>,

    /// Assert the config resolves to this derived mode and fail fast if not.
    #[arg(long, value_enum)]
    pub require_mode: Option<RequireModeArg>,

    /// Hard-override every rule's `listen` IP with this address. The rule's
    /// port is preserved; only the IP is replaced. Overrides
    /// `[server].default_bind`.
    #[arg(long, value_name = "IP")]
    pub bind: Option<IpAddr>,
}

/// CLI-side mirror of the daemon's runtime `Mode`. Stays in cli-defs so
/// build.rs can introspect it; the conversion impl into the live `Mode`
/// type lives in the yggdrasil crate (see `crates/yggdrasil/src/cli.rs`).
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum RequireModeArg {
    Gateway,
    Relay,
    Terminal,
}
