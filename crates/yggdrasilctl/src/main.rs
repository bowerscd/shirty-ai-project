//! yggdrasilctl — admin CLI for yggdrasil.
//!
//! The CLI is organised into three scopes:
//!
//! * `local` — talks to the running daemon over its Unix domain socket
//!   (`/run/yggdrasil/control.sock` by default). Used for status, rule
//!   inspection, and downstream TOFU management.
//! * `chain` — inspects/manages the chain-control plane. Stubs in Phase 1;
//!   filled in in Phase 4-5 once the chain wire protocol lands.
//! * `identity` — offline operations on this node's identity file and the
//!   daemon's config TOML. Mints intro/invite files and edits
//!   `[dial]` / `[accept]` sections. No daemon required.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod chain;
mod identity;
mod local;
mod validate;

/// Default path to the daemon's main config file.
const DEFAULT_CONFIG_PATH: &str = "/etc/yggdrasil/config.toml";

/// Default path to the daemon's control socket.
const DEFAULT_SOCKET_PATH: &str = "/run/yggdrasil/control.sock";

#[derive(Debug, Parser)]
#[command(name = "yggdrasilctl", version, about, propagate_version = true)]
struct Cli {
    /// Path to the yggdrasil config file. Used by the `identity` and
    /// `validate` scopes; `local` and `chain` ignore it.
    #[arg(
        long,
        default_value = DEFAULT_CONFIG_PATH,
        env = "YGGDRASIL_CONFIG",
        global = true
    )]
    config: PathBuf,

    /// Emit responses as raw JSON instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    scope: Scope,
}

/// Shared `--socket` option for the daemon-talking scopes (`local` and
/// `chain`). Identity and validate scopes never contact the daemon and
/// deliberately don't accept this flag (config-UX item 28).
#[derive(Debug, clap::Args)]
struct SocketOpts {
    /// Path to the yggdrasil control socket.
    #[arg(
        long,
        default_value = DEFAULT_SOCKET_PATH,
        env = "YGGDRASIL_CONTROL_SOCKET",
    )]
    socket: PathBuf,
}

#[derive(Debug, Subcommand)]
enum Scope {
    /// Daemon-local operations over the control socket.
    Local {
        #[command(flatten)]
        socket: SocketOpts,
        #[command(subcommand)]
        cmd: local::Cmd,
    },
    /// Chain-control plane operations.
    Chain {
        #[command(flatten)]
        socket: SocketOpts,
        #[command(subcommand)]
        cmd: chain::Cmd,
    },
    /// Identity and enrollment (offline; mutates config file).
    Identity {
        #[command(subcommand)]
        cmd: identity::Cmd,
    },
    /// Validate the daemon's config file and rules directory offline.
    Validate(validate::ValidateArgs),
}

fn main() -> Result<ExitCode> {
    let cli = Cli::parse();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    runtime.block_on(async move {
        match cli.scope {
            Scope::Local { socket, cmd } => local::run(cmd, &socket.socket, cli.json)
                .await
                .map(|()| ExitCode::SUCCESS),
            Scope::Chain { socket, cmd } => chain::run(cmd, &socket.socket, cli.json)
                .await
                .map(|()| ExitCode::SUCCESS),
            Scope::Identity { cmd } => identity::run(cmd, &cli.config, cli.json)
                .await
                .map(|()| ExitCode::SUCCESS),
            Scope::Validate(args) => validate::run(args, &cli.config, cli.json).await,
        }
    })
}
