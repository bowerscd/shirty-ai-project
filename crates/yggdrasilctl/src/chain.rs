//! `chain` scope — chain-control plane operations.
//!
//! These are stubbed in Phase 1. The chain control wire protocol
//! (PacketType tags `0x06`/`0x07`) lands in Phase 4-5, at which point this
//! module will gain commands like `chain show`, `chain failover`, and
//! `chain diagnose`.

use std::path::Path;

use anyhow::{bail, Result};
use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Reserved for Phase 4-5: show chain-control plane state (currently a stub).
    Show,
}

pub async fn run(_cmd: Cmd, _socket: &Path, _json: bool) -> Result<()> {
    bail!(
        "the `chain` scope is reserved for the Phase 4-5 chain-control plane \
         and is not implemented yet"
    );
}
