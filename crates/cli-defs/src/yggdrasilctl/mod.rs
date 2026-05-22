//! `yggdrasilctl` (the admin CLI) command-tree definitions.
//!
//! Extracted from the original `crates/yggdrasilctl/src/{main,chain,identity,
//! local,validate}.rs` so `crates/yggdrasilctl/build.rs` can introspect the
//! same `Cli` the runtime uses. Dispatch logic stays in the
//! `yggdrasilctl` bin crate; only the type definitions move.

pub mod chain;
pub mod identity;
pub mod local;
pub mod validate;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Default path to the daemon's main config file.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/yggdrasil/config.toml";

/// Default path to the daemon's control socket.
pub const DEFAULT_SOCKET_PATH: &str = "/run/yggdrasil/control.sock";

#[derive(Debug, Parser)]
#[command(
    name = "yggdrasilctl",
    version,
    about = "Admin CLI for yggdrasil; speaks JSON over a Unix domain socket",
    propagate_version = true
)]
pub struct Cli {
    /// Path to the yggdrasil config file. Used by the `identity` and
    /// `validate` scopes; `local` and `chain` ignore it.
    #[arg(
        long,
        default_value = DEFAULT_CONFIG_PATH,
        env = "YGGDRASIL_CONFIG",
        global = true
    )]
    pub config: PathBuf,

    /// Emit responses as raw JSON instead of human-readable text.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub scope: Scope,
}

/// Shared `--socket` option for the daemon-talking scopes (`local` and
/// `chain`). Identity and validate scopes never contact the daemon and
/// deliberately don't accept this flag (config-UX item 28).
#[derive(Debug, clap::Args)]
pub struct SocketOpts {
    /// Path to the yggdrasil control socket.
    #[arg(
        long,
        default_value = DEFAULT_SOCKET_PATH,
        env = "YGGDRASIL_CONTROL_SOCKET",
    )]
    pub socket: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum Scope {
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
    /// Print a shell-completion script for `yggdrasilctl` to stdout.
    Completions(crate::completions::CompletionsArgs),
}
