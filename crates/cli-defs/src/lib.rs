//! Shared clap-derive command-tree definitions for both bin crates.
//!
//! `build.rs` is compiled separately from its host bin crate, so it
//! cannot reach into the bin's own modules to introspect the `Cli`
//! struct. The structs are extracted here, into a small lib-only
//! crate that both the bin (as a regular dep) and its build script
//! (as a build-dep) pull in.
//!
//! No runtime logic lives here — only the type definitions, their
//! `clap` annotations, and tiny `ValueEnum` conversions.

pub mod completions;
pub mod yggdrasil;
pub mod yggdrasilctl;
