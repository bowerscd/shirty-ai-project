//! CLI surface for the `yggdrasil` server binary.
//!
//! As of the chain-control rework the daemon binary exposes only `run`
//! (and the inherent `version` subcommand). Identity management,
//! enrollment, and administrative queries live in `yggdrasilctl`.
//!
//! The clap-derive type definitions live in the sibling `cli-defs`
//! crate so `crates/yggdrasil/build.rs` (a separate compile unit) can
//! introspect them for the auto-generated CLI reference. We re-export
//! them here so downstream call-sites (`crate::lib`, `tests`) keep
//! using the original `crate::cli::*` paths.

pub use cli_defs::yggdrasil::{Cli, Command, LogFormat, RequireModeArg, RunArgs};

use crate::config::Mode;

impl From<RequireModeArg> for Mode {
    fn from(m: RequireModeArg) -> Self {
        match m {
            RequireModeArg::Gateway => Mode::Gateway,
            RequireModeArg::Relay => Mode::Relay,
            RequireModeArg::Terminal => Mode::Terminal,
        }
    }
}
