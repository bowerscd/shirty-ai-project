//! yggdrasilctl — admin CLI for yggdrasil.
//!
//! The CLI is organised into four scopes:
//!
//! * `local` — talks to the running daemon over its Unix domain socket
//!   (`/run/yggdrasil/control.sock` by default). Used for status, rule
//!   inspection, and downstream TOFU management.
//! * `chain` — inspects/manages the chain-control plane.
//! * `identity` — offline operations on this node's identity file and the
//!   daemon's config TOML. Mints request/grant files and edits
//!   `[dial]` / `[accept]` sections. No daemon required.
//! * `validate` — offline check of the config + rules directory.
//!
//! All clap-derive command-tree types live in the sibling `cli-defs`
//! crate so `crates/yggdrasilctl/build.rs` (a separate compile unit)
//! can introspect them for the auto-generated CLI reference. Dispatch
//! logic stays here.

use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};

use cli_defs::yggdrasilctl::{Cli, Scope};

mod chain;
mod identity;
mod local;
mod validate;

fn main() -> Result<ExitCode> {
    let cli = Cli::parse();

    // The `completions` scope is synchronous and doesn't need a tokio
    // runtime. Handle it before building the runtime to avoid the
    // per-process cost on a no-op.
    if let Scope::Completions(c) = &cli.scope {
        let mut cmd = Cli::command();
        clap_complete::generate(c.shell, &mut cmd, "yggdrasilctl", &mut std::io::stdout());
        return Ok(ExitCode::SUCCESS);
    }

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
            Scope::Completions(_) => unreachable!("handled before runtime build"),
        }
    })
}
