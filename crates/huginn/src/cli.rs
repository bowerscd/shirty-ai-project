//! CLI surface for the `huginn` client binary.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// `huginn` — heartbeat client; runs on the residential upstream box.
#[derive(Debug, Parser)]
#[command(name = "huginn", version, about, propagate_version = true)]
pub struct Cli {
    #[arg(long, value_enum, default_value_t = LogFormat::Json, global = true,
          env = "HUGINN_LOG_FORMAT")]
    pub log_format: LogFormat,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the heartbeat daemon.
    Run(RunArgs),
    /// Generate the client's static X25519 identity keypair.
    Keygen(KeygenArgs),
    /// Print this client's public key (hex-encoded).
    Pubkey(IdentityArgs),
    /// Print this client's short fingerprint (for TOFU display).
    Fingerprint(IdentityArgs),
    /// Import an out-of-band enrollment token from yggdrasil.
    Enroll(EnrollArgs),
    /// Print the build version.
    Version,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    #[arg(long, default_value = "/etc/huginn/config.toml", env = "HUGINN_CONFIG")]
    pub config: PathBuf,
}

#[derive(Debug, Args)]
pub struct KeygenArgs {
    #[arg(long, default_value = "/etc/huginn/identity.key")]
    pub identity_file: PathBuf,

    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct IdentityArgs {
    #[arg(long, default_value = "/etc/huginn/identity.key")]
    pub identity_file: PathBuf,
}

#[derive(Debug, Args)]
pub struct EnrollArgs {
    /// Path to the enrollment token file produced by `yggdrasil enroll-token`.
    pub token: PathBuf,

    /// Path to the huginn config file to update.
    #[arg(long, default_value = "/etc/huginn/config.toml")]
    pub config: PathBuf,
}
