//! Regenerates `docs/cli-reference/yggdrasilctl.md` on every build by
//! walking the clap command tree in `cli_defs::yggdrasilctl` and
//! feeding it to `clap-markdown`. See `crates/yggdrasil/build.rs` for
//! the design rationale; both build scripts share the same shape.

use clap::CommandFactory;

fn main() {
    println!("cargo:rerun-if-changed=../cli-defs/src/lib.rs");
    println!("cargo:rerun-if-changed=../cli-defs/src/yggdrasilctl");
    println!("cargo:rerun-if-changed=../cli-defs/src/completions.rs");
    println!("cargo:rerun-if-changed=build.rs");

    let cmd = <cli_defs::yggdrasilctl::Cli as CommandFactory>::command();
    let md = clap_markdown::help_markdown_command(&cmd);

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out_path = manifest_dir
        .join("../..")
        .join("docs/cli-reference/yggdrasilctl.md");
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|e| panic!("create_dir_all {}: {e}", parent.display()));
    }
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
