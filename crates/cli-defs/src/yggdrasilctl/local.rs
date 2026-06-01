//! `yggdrasilctl local` command tree.
//!
//! Type definitions only — dispatch lives in `crates/yggdrasilctl/src/local.rs`.

use clap::{Args, Subcommand};

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Show high-level server status (mode, downstream IP, last heartbeat,
    /// rule count, uptime).
    Status,
    /// Inspect or manage loaded rules.
    Rules {
        #[command(subcommand)]
        action: RuleAction,
    },
    /// Inspect or manage the enrolled accept-side peer (the inbound chain
    /// peer pinned by `[accept]` — for relay-mode this is the downstream
    /// terminal node).
    Accept {
        #[command(subcommand)]
        action: AcceptAction,
    },
    /// Render the daemon's Prometheus metrics in text exposition
    /// format, retrieved over the control socket.
    Metrics,
    /// Liveness/readiness probe served over the control socket. Exit
    /// status: 0 if ready, 1 if not yet ready, 2 on RPC error.
    Health,
    /// Snapshot of this node's chain-applied predicates, derived rule
    /// set, and chain identity. Pretty-printed JSON to stdout.
    DerivedRules,
    /// Adjust the daemon's tracing-subscriber filter at runtime.
    /// Pass a directive (`debug`, `yggdrasil::heartbeat=trace,info`,
    /// etc.) or `--reset` to revert to the startup filter. With no
    /// args, prints the current and default directives without
    /// changing anything.
    Trace(TraceArgs),
    /// Inspect or manage the daemon's ACME-managed certs.
    Acme {
        #[command(subcommand)]
        action: AcmeAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum AcmeAction {
    /// List ACME-managed hostnames with their renewer state, next
    /// renewal time, and last error (if any).
    List,
    /// Force an immediate ACME issuance for `<hostname>`. Bypasses
    /// the renewer's schedule. Blocks until issuance completes
    /// (typically 5-60 seconds) or the daemon's 5-minute deadline
    /// expires.
    Renew(AcmeRenewArgs),
}

#[derive(Debug, Args)]
pub struct AcmeRenewArgs {
    /// The route hostname to renew. Case-insensitive.
    pub hostname: String,
}

#[derive(Debug, Args)]
pub struct TraceArgs {
    /// New EnvFilter directive to install. Required unless `--reset` is set.
    #[arg(conflicts_with = "reset", required_unless_present = "reset")]
    pub directive: Option<String>,
    /// Restore the directive the daemon was launched with.
    #[arg(long)]
    pub reset: bool,
}

#[derive(Debug, Subcommand)]
pub enum RuleAction {
    /// List loaded rules.
    List,
    /// Force a reload of the rules directory (in addition to inotify).
    Reload,
}

#[derive(Debug, Subcommand)]
pub enum AcceptAction {
    /// Show the currently enrolled accept-side pubkey and fingerprint.
    Show,
    /// List staged TOFU candidates awaiting approval.
    Pending,
    /// Approve a staged candidate by its fingerprint or any unique
    /// 8+-hex-char prefix.
    Approve(ApproveArgs),
}

#[derive(Debug, Args)]
pub struct ApproveArgs {
    /// Tagged fingerprint (e.g. `x25519:<32 hex chars>` for X25519) of
    /// the accept-side peer to approve, or any unique prefix of at
    /// least 8 hex chars of the hash tail (the algorithm prefix is
    /// optional). The daemon disambiguates against the staged queue;
    /// ambiguous prefixes return an error listing every match.
    pub fingerprint: String,
}
