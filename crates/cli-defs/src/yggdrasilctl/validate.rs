//! `yggdrasilctl validate` command tree.
//!
//! Type definitions only — dispatch lives in `crates/yggdrasilctl/src/validate.rs`.

use std::path::PathBuf;

use clap::Args;

#[derive(Debug, Args)]
pub struct ValidateArgs {
    /// Override the rules directory. When omitted, uses
    /// `[server].rules_dir` from the loaded config (default
    /// `/etc/yggdrasil/conf.d`).
    #[arg(long)]
    pub rules_dir: Option<PathBuf>,
}
