//! Regenerates `docs/cli-reference/yggdrasil.md` on every build by
//! walking the clap command tree in `cli_defs::yggdrasil` and feeding
//! it to `clap-markdown`.
//!
//! Why a build script:
//! * The doc is committed to the repo, so contributors don't have to
//!   remember a separate `cargo xtask docs` step — any normal
//!   `cargo build` keeps the markdown current.
//! * CI's `git diff --exit-code docs/cli-reference/` step catches the
//!   one remaining failure mode: contributors changing the CLI and
//!   forgetting to commit the regenerated doc.
//!
//! Why a sibling `cli-defs` crate:
//! * `build.rs` is compiled separately from its host's bin/lib; it
//!   cannot `use crate::cli::Cli`. `cli-defs` is the path-dep both
//!   the build script and the runtime pull in (so they always agree
//!   on the type tree).

use clap::CommandFactory;

fn main() {
    // Re-run only when the clap-derive definitions themselves change.
    // The doc string and arg attribute metadata feed through clap-markdown,
    // so any change in cli-defs sources should regenerate the markdown.
    println!("cargo:rerun-if-changed=../cli-defs/src/lib.rs");
    println!("cargo:rerun-if-changed=../cli-defs/src/yggdrasil.rs");
    println!("cargo:rerun-if-changed=../cli-defs/src/completions.rs");
    println!("cargo:rerun-if-changed=build.rs");

    let cmd = <cli_defs::yggdrasil::Cli as CommandFactory>::command();
    let md = clap_markdown::help_markdown_command(&cmd);

    // Workspace-root-relative output path: from
    // crates/yggdrasil/Cargo.toml the workspace root is two levels up.
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out_path = manifest_dir
        .join("../..")
        .join("docs/cli-reference/yggdrasil.md");
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|e| panic!("create_dir_all {}: {e}", parent.display()));
    }
    // Only write when the contents would actually change so we don't
    // bump the file's mtime on every incremental build (IDE friendliness).
    let new_bytes = md.as_bytes();
    let needs_write = match std::fs::read(&out_path) {
        Ok(existing) => existing != new_bytes,
        Err(_) => true,
    };
    if needs_write {
        std::fs::write(&out_path, new_bytes)
            .unwrap_or_else(|e| panic!("write {}: {e}", out_path.display()));
    }
}
