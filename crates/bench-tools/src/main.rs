//! `loadgen` — TCP/UDP load generator for yggdrasil end-to-end benchmarks.
//!
//! Modes:
//!
//! * `udp` — open N flows, send packets at the requested rate, capture echo
//!   round-trip latency in an HDR histogram. Used by `bench/udp-pps.sh`
//!   (N=1) and `bench/udp-flows.sh` (N≫1).
//! * `udp-churn` — repeatedly open new UDP flows, send one packet each, and
//!   discard. Measures new-flow/sec capacity. Used by `bench/udp-flowchurn.sh`.
//! * `tcp` — open N TCP connections, ping-pong fixed-size messages on each,
//!   capture round-trip latency. Used by `bench/tcp-latency.sh`.
//! * `tcp-throughput` — open N TCP connections, fill each with a continuous
//!   stream of bytes for the whole duration, measure aggregate bytes/sec.
//!   Used by `bench/tcp-throughput.sh`.
//! * `tcp-connrate` — repeatedly open + close short-lived TCP connections,
//!   measure connections/sec. Used by `bench/tcp-connrate.sh`.
//! * `tcp-idle` — open N TCP connections at bounded ramp-up parallelism,
//!   hold every one idle for a fixed duration, then close. Captures the
//!   per-connect latency histogram; the established count is reported as
//!   `stats.tx_packets` / `stats.rx_packets`. Used by
//!   `bench/tcp-idle-conns.sh` to drive a memory-footprint scenario.
//!
//! Each mode emits a single JSON document on stdout (or via
//! `--report-json <path>`) describing what it did, what it measured, and a
//! latency CDF. `bench/compare.py` parses these.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod report;
mod tcp;
mod udp;

#[derive(Debug, Parser)]
#[command(name = "loadgen", version, about)]
struct Cli {
    /// Human label included verbatim in the JSON report. Use this to tag
    /// runs with the subject under test (e.g. "yggdrasil", "nginx", "direct").
    #[arg(long, global = true, default_value = "loadgen")]
    subject: String,

    /// Where to write the JSON report. Default is stdout.
    #[arg(long, global = true)]
    report_json: Option<PathBuf>,

    /// Override the scenario name in the JSON report. By default each
    /// mode picks its own (`tcp-latency`, `tcp-throughput`,
    /// `tcp-connrate`, `tcp-idle`, `udp-pps`, `udp-churn`). The
    /// generic `udp` mode is shared by `udp-pps` and `udp-flows` —
    /// the latter passes `--scenario-name udp-flows` to disambiguate.
    /// Reports landing in the same results directory must have unique
    /// (scenario, subject) pairs or `compare.py`'s aggregator will
    /// silently collapse them.
    #[arg(long, global = true)]
    scenario_name: Option<String>,

    #[command(subcommand)]
    mode: Mode,
}

#[derive(Debug, Subcommand)]
enum Mode {
    /// Open N concurrent UDP flows and send echo-RTT-measured packets.
    Udp(UdpArgs),
    /// Repeatedly open fresh UDP flows; measure new-flow/sec capacity.
    UdpChurn(UdpChurnArgs),
    /// Open N TCP connections, ping-pong fixed messages, measure RTT.
    Tcp(TcpArgs),
    /// Open N TCP connections, sustain bytes/sec across all of them.
    TcpThroughput(TcpThroughputArgs),
    /// Repeatedly open + close TCP connections; measure connect/sec.
    TcpConnrate(TcpConnrateArgs),
    /// Open N idle TCP connections, hold them, then close. Used to
    /// characterise per-connection memory cost of the subject.
    TcpIdle(TcpIdleArgs),
}

#[derive(Debug, clap::Args)]
struct UdpArgs {
    /// Target address (host:port).
    #[arg(long)]
    target: String,
    /// Number of concurrent flows (each gets its own source port).
    #[arg(long, default_value_t = 1)]
    flows: u32,
    /// Aggregate target send rate across all flows.
    #[arg(long, default_value_t = 100_000)]
    pps: u64,
    /// UDP payload size in bytes.
    #[arg(long, default_value_t = 64)]
    packet_size: usize,
    /// Total run duration.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "10s")]
    duration: Duration,
    /// Warmup duration excluded from the reported stats.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "1s")]
    warmup: Duration,
}

#[derive(Debug, clap::Args)]
struct UdpChurnArgs {
    /// Target address (host:port).
    #[arg(long)]
    target: String,
    /// Target new-flows/sec.
    #[arg(long, default_value_t = 10_000)]
    rate: u64,
    /// Total run duration.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "10s")]
    duration: Duration,
}

#[derive(Debug, clap::Args)]
struct TcpArgs {
    /// Target address (host:port).
    #[arg(long)]
    target: String,
    /// Number of concurrent TCP connections.
    #[arg(long, default_value_t = 1)]
    connections: u32,
    /// Ping-pong message size in bytes.
    #[arg(long, default_value_t = 64)]
    message_size: usize,
    /// Total run duration.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "10s")]
    duration: Duration,
    /// Warmup duration excluded from the reported stats.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "1s")]
    warmup: Duration,
}

#[derive(Debug, clap::Args)]
struct TcpThroughputArgs {
    /// Target address (host:port).
    #[arg(long)]
    target: String,
    /// Number of concurrent TCP streams.
    #[arg(long, default_value_t = 8)]
    streams: u32,
    /// Buffer size per write.
    #[arg(long, default_value_t = 64 * 1024)]
    buffer_size: usize,
    /// Total run duration.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "10s")]
    duration: Duration,
}

#[derive(Debug, clap::Args)]
struct TcpConnrateArgs {
    /// Target address (host:port).
    #[arg(long)]
    target: String,
    /// Maximum concurrent in-flight connect attempts.
    #[arg(long, default_value_t = 64)]
    concurrency: u32,
    /// Total run duration.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "10s")]
    duration: Duration,
}

#[derive(Debug, clap::Args)]
struct TcpIdleArgs {
    /// Target address (host:port).
    #[arg(long)]
    target: String,
    /// Total number of TCP connections to open and hold idle.
    #[arg(long, default_value_t = 1_000)]
    connections: u32,
    /// Maximum in-flight `connect()` attempts during ramp-up. The permit
    /// is released as soon as a socket is established, so the steady-state
    /// simultaneously-open count converges to `connections`.
    #[arg(long, default_value_t = 256)]
    concurrency: u32,
    /// How long each established connection is held idle before closing.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "15s")]
    hold: Duration,
}

fn main() -> Result<()> {
    // Dedicated tokio runtime so we can keep loadgen single-threaded for
    // single-core SLO measurements; switchable via env var if desired.
    let runtime = if std::env::var_os("LOADGEN_MULTI_THREAD").is_some() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
    } else {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
    };
    runtime.block_on(async move { run(Cli::parse()).await })
}

async fn run(cli: Cli) -> Result<()> {
    let mut report = match cli.mode {
        Mode::Udp(args) => udp::run_udp(&cli.subject, args).await?,
        Mode::UdpChurn(args) => udp::run_udp_churn(&cli.subject, args).await?,
        Mode::Tcp(args) => tcp::run_tcp(&cli.subject, args).await?,
        Mode::TcpThroughput(args) => tcp::run_tcp_throughput(&cli.subject, args).await?,
        Mode::TcpConnrate(args) => tcp::run_tcp_connrate(&cli.subject, args).await?,
        Mode::TcpIdle(args) => tcp::run_tcp_idle(&cli.subject, args).await?,
    };
    if let Some(name) = cli.scenario_name {
        report.scenario = name;
    }
    let text = serde_json::to_string_pretty(&report).context("serialise report")?;
    match cli.report_json {
        Some(path) => std::fs::write(&path, text)
            .with_context(|| format!("write report to {}", path.display()))?,
        None => println!("{text}"),
    }
    Ok(())
}
