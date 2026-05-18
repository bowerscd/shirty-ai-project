//! Thin binary entrypoint. All server logic lives in the `yggdrasil` library
//! crate (`src/lib.rs`); this file just parses args, builds the tokio
//! runtime, and dispatches subcommands.

use anyhow::{Context, Result};
use clap::Parser;

use yggdrasil::{cli, commands, log, run};

fn main() -> Result<()> {
    let args = cli::Cli::parse();

    // Tracing must be initialised before any logging happens.
    log::init_tracing(args.log_format)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    runtime.block_on(async move {
        match args.command {
            cli::Command::Run(run_args) => run(run_args).await,
            cli::Command::Keygen(args) => commands::keygen(args),
            cli::Command::EnrollToken(args) => commands::enroll_token(args),
            cli::Command::Version => {
                println!("yggdrasil {}", env!("CARGO_PKG_VERSION"));
                Ok(())
            }
        }
    })
}
