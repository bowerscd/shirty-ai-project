//! `yggdrasilctl identity` command tree.
//!
//! Type definitions only — dispatch lives in `crates/yggdrasilctl/src/identity.rs`.

use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Print this node's pubkey and fingerprint from the identity file.
    Show(ShowArgs),

    /// Generate a fresh identity key. Refuses to overwrite an existing file
    /// unless `--force` is given.
    Rotate(RotateArgs),

    /// Write a request file (this node asking to be enrolled as a
    /// `dial`-side peer).
    #[command(name = "export-request")]
    ExportRequest(ExportRequestArgs),

    /// Apply a grant file: verify it targets this node and write
    /// `[dial]` into the daemon config.
    #[command(name = "add-dial")]
    AddDial(AddDialArgs),

    /// Apply a request file: mint a grant for the requester, and write
    /// `[accept]` into the daemon config.
    #[command(name = "add-accept")]
    AddAccept(AddAcceptArgs),

    /// Remove `[dial]` from the daemon config.
    #[command(name = "remove-dial")]
    RemoveDial,

    /// Remove `[accept]` from the daemon config.
    #[command(name = "remove-accept")]
    RemoveAccept,
}

#[derive(Debug, Args)]
pub struct ShowArgs {
    /// Override the identity file path. If unset, read from `[server].identity_file`
    /// in `--config`, falling back to `/etc/yggdrasil/identity.key`.
    #[arg(long)]
    pub identity_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct RotateArgs {
    /// Override the identity file path.
    #[arg(long)]
    pub identity_file: Option<PathBuf>,

    /// Overwrite an existing identity file. Without this flag, `rotate`
    /// refuses to clobber an existing key. When the identity file is
    /// absent (fresh install), `--force` is a no-op.
    #[arg(long)]
    pub force: bool,

    /// Skip the interactive fingerprint-confirmation prompt. Required for
    /// non-interactive overwrite of an existing identity. Use only when
    /// you have already audited the chain enrollments that this rotation
    /// will break (`identity show` lists the breakage). Pair with
    /// `--force`.
    #[arg(long = "yes-i-understand-this-breaks-existing-chains")]
    pub yes_i_understand_this_breaks_existing_chains: bool,
}

#[derive(Debug, Args)]
pub struct ExportRequestArgs {
    /// Override the identity file path.
    #[arg(long)]
    pub identity_file: Option<PathBuf>,

    /// Where to write the request file. When omitted, the request TOML
    /// is printed to stdout (operators can pipe it directly or redirect
    /// to a file). When supplied, the file is written with 0600 perms.
    #[arg(short = 'o', long = "out")]
    pub out: Option<PathBuf>,

    /// Free-form note included in the request file (operator hint).
    #[arg(long, default_value = "")]
    pub note: String,
}

#[derive(Debug, Args)]
pub struct AddDialArgs {
    /// Path to the grant file emitted by the accept-side.
    #[arg(long = "from")]
    pub from: PathBuf,

    /// Override the identity file path (used to verify the grant targets us).
    #[arg(long)]
    pub identity_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct AddAcceptArgs {
    /// Path to the request file received from the prospective dial-side peer.
    #[arg(long = "from")]
    pub from: PathBuf,

    /// The endpoint string (`host:port`) this node advertises as its
    /// accept-side reachable address. Written into both the grant file
    /// and the `[dial].endpoint` field that the requester will paste in.
    #[arg(long = "my-endpoint")]
    pub my_endpoint: String,

    /// Where to write the resulting grant file. Defaults to `grant.txt`.
    #[arg(short = 'o', long = "out", default_value = "grant.txt")]
    pub out: PathBuf,

    /// Override the identity file path (used to populate the grant's
    /// `accept_pubkey`).
    #[arg(long)]
    pub identity_file: Option<PathBuf>,

    /// Free-form note included in the grant file.
    #[arg(long, default_value = "")]
    pub note: String,
}
