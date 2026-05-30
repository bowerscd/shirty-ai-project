//! `yggdrasilctl chain` command tree.
//!
//! Type definitions only — dispatch lives in `crates/yggdrasilctl/src/chain.rs`.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Subcommand, ValueEnum};

use ratatoskr::pubkey::PubKey;

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Push a candidate rule set from a TOML file into the running
    /// terminal daemon without touching its rules directory on disk.
    /// The daemon validates the candidate, projects its predicate set,
    /// and (if a chain upstream is configured) publishes the projection
    /// on its next push tick.
    Apply(ApplyArgs),
    /// Compare the local terminal's published predicate set with what
    /// each upstream node believes it accepted.
    Diff(DiffArgs),
    /// One-line-per-hop overview of the chain (pubkey, role, version,
    /// uptime, rule count). Pure projection of the same
    /// `Request::ChainSummary` RPC that backs `chain diff`; no extra
    /// daemon plumbing.
    Summary(SummaryArgs),
    /// Per-hop health (healthy / degraded / down / starting), aggregated
    /// to a chain-wide worst-of-hops verdict. Exit code reflects the
    /// worst hop: 0=healthy/starting, 1=degraded, 2=down, 3=RPC error.
    Health(HealthArgs),
    /// Per-hop control-plane round-trip time. Walks the chain via the
    /// same `Request::ChainSummary` RPC and prints each hop's measured
    /// query→reply RTT (or `-` for the local hop, which has no RTT to
    /// report). Useful for isolating "slow link" vs. "unreachable hop"
    /// during a chain incident.
    Ping(PingArgs),
    /// Probe a rule's L4 forwarding path end-to-end through the chain
    /// and report per-direction throughput, loss, and latency. Routes
    /// a token-prefixed probe through the rule's listener so the
    /// terminal hop short-circuits to an in-process echo — testing
    /// the chain without depending on the rule's configured backend
    /// being reachable.
    ///
    /// Exit code: 0=OK, 1=DEGRADED, 2=NO_SUCH_RULE, 3=CHAIN_DEAD,
    /// 4=RPC error.
    Canary(CanaryArgs),
}

/// L4 transport selector for `chain canary --proto`.
#[derive(Debug, Clone, Copy, ValueEnum)]
#[clap(rename_all = "lowercase")]
pub enum ProtoArg {
    Tcp,
    Udp,
}

#[derive(Debug, Args)]
pub struct CanaryArgs {
    /// Port the rule listens on. Required.
    #[arg(long, value_name = "PORT")]
    pub port: u16,
    /// Transport. Required only when the local node has more than one
    /// rule binding `--port` (one TCP, one UDP); inferred from the
    /// rule set otherwise.
    #[arg(long, value_enum, value_name = "PROTO")]
    pub proto: Option<ProtoArg>,
    /// Overall budget for the chain to walk and assemble the arming
    /// reply. Matches the `--timeout` shape of the other `chain`
    /// subcommands. Caps how long we wait before giving up with
    /// `CHAIN_DEAD`; the data probe runs for a fixed daemon-side
    /// duration regardless.
    #[arg(
        long,
        value_name = "DURATION",
        value_parser = humantime::parse_duration,
        default_value = "5s",
    )]
    pub timeout: Duration,
}

#[derive(Debug, Args)]
pub struct ApplyArgs {
    /// Path to a candidate `rules.toml` file. Parsed locally for early
    /// schema errors with line context, then shipped to the daemon as
    /// a pre-parsed rule vector. The daemon performs defensive
    /// re-validation (per-rule + cross-rule) before applying.
    #[arg(long, value_name = "PATH")]
    pub file: PathBuf,
}

#[derive(Debug, Args)]
pub struct DiffArgs {
    /// Overall budget for assembling the chain summary across all
    /// hops. Terminals with no `[dial]` upstream return synchronously
    /// and effectively ignore this value.
    #[arg(
        long,
        value_name = "DURATION",
        value_parser = humantime::parse_duration,
        default_value = "5s",
    )]
    pub timeout: Duration,
}

#[derive(Debug, Args)]
pub struct SummaryArgs {
    /// Overall budget for assembling the chain summary across all
    /// hops. Terminals with no `[dial]` upstream return synchronously
    /// and effectively ignore this value.
    #[arg(
        long,
        value_name = "DURATION",
        value_parser = humantime::parse_duration,
        default_value = "5s",
    )]
    pub timeout: Duration,
}

#[derive(Debug, Args)]
pub struct HealthArgs {
    /// Overall budget for assembling the chain summary across all
    /// hops. Terminals with no `[dial]` upstream return synchronously
    /// and effectively ignore this value.
    #[arg(
        long,
        value_name = "DURATION",
        value_parser = humantime::parse_duration,
        default_value = "5s",
    )]
    pub timeout: Duration,
}

#[derive(Debug, Args)]
pub struct PingArgs {
    /// Overall budget for assembling the chain summary across all
    /// hops. Terminals with no `[dial]` upstream return synchronously
    /// and effectively ignore this value.
    #[arg(
        long,
        value_name = "DURATION",
        value_parser = humantime::parse_duration,
        default_value = "5s",
    )]
    pub timeout: Duration,
    /// If set, restrict the rendered output to a single hop matching
    /// this tagged x25519 pubkey (`x25519:<hex>`). The whole chain is
    /// still walked — only the rendering is filtered. Useful in
    /// scripts that probe a specific hop without needing to compute
    /// its index.
    #[arg(long, value_name = "PUBKEY")]
    pub hop: Option<PubKey>,
}
