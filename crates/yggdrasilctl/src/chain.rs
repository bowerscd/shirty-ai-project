//! `chain` scope — chain-control plane operations.
//!
//! `chain apply`: push a candidate `rules.toml` into the running
//! terminal daemon without touching its on-disk rules directory.
//!
//! `chain diff`: compare the local terminal's published predicate
//! set with what each upstream node believes it accepted. Currently
//! served from a single-RPC `ChainSummary` reply over UDS; multi-hop
//! fanout is a follow-up increment.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use ratatoskr::control::{ChainSummaryResponse, Request, Response};
use ratatoskr::predicate::Predicate;
use ratatoskr::pubkey::PubKey;
use ratatoskr::rule::{RuleFile, RuleSet};

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
    /// Overall budget for the daemon to assemble its chain summary
    /// reply. Applies once across the whole walk; multi-hop fanout (a
    /// follow-up increment) will respect it as a per-hop deadline.
    /// Local-only replies return synchronously and effectively ignore
    /// this value.
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
    /// hops. Local-only replies effectively ignore this.
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
    /// hops. Local-only replies effectively ignore this.
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
    /// hops. Local-only replies effectively ignore this.
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

pub async fn run(cmd: Cmd, socket: &Path, json: bool) -> Result<()> {
    match cmd {
        Cmd::Apply(args) => apply(socket, &args).await,
        Cmd::Diff(args) => diff(socket, &args, json).await,
        Cmd::Summary(args) => summary(socket, &args, json).await,
        Cmd::Health(args) => health(socket, &args, json).await,
        Cmd::Ping(args) => ping(socket, &args, json).await,
    }
}

/// Push a candidate rule set from `args.file` to the running daemon.
///
/// Local parse + validation runs first so the CLI fails fast with line
/// context on schema errors (the daemon's own error path would only see
/// a `Vec<Rule>` and couldn't point at TOML line numbers). The daemon
/// re-validates as defence in depth.
async fn apply(socket: &Path, args: &ApplyArgs) -> Result<()> {
    // 1. Read and parse the candidate file. `RuleFile::from_toml`
    //    attaches the path to any TOML parse error.
    let contents = std::fs::read_to_string(&args.file)
        .with_context(|| format!("reading {}", args.file.display()))?;
    let rule_file = RuleFile::from_toml(args.file.clone(), &contents)
        .with_context(|| format!("parsing {}", args.file.display()))?;
    let rules = rule_file.rule;
    if rules.is_empty() {
        bail!(
            "{} contains no `[[rule]]` blocks; nothing to apply",
            args.file.display()
        );
    }

    // 2. Locally pre-validate so schema errors don't even hit the
    //    wire. The daemon will run the same checks again.
    if let Err(e) = RuleSet::from_rules(rules.clone()) {
        bail!("{} failed local validation: {e}", args.file.display());
    }

    // 3. Send the request and await the single response line.
    let request = Request::ChainApply { rules };
    let response = send_chain_apply(socket, &request, Duration::from_secs(5)).await?;

    match response {
        Response::ChainApplied(b) => {
            println!(
                "applied {} rule{} ({} projected predicate{}{})",
                b.applied_rule_count,
                if b.applied_rule_count == 1 { "" } else { "s" },
                b.predicate_count,
                if b.predicate_count == 1 { "" } else { "s" },
                if b.skipped_https.is_empty() {
                    String::new()
                } else {
                    format!(
                        "; {} HTTPS rule{} skipped from projection: {}",
                        b.skipped_https.len(),
                        if b.skipped_https.len() == 1 { "" } else { "s" },
                        b.skipped_https.join(", ")
                    )
                }
            );
            Ok(())
        }
        Response::Error { code, message } => {
            bail!("daemon refused apply: code={code} message={message}");
        }
        other => bail!("daemon returned unexpected response to ChainApply: {other:?}"),
    }
}

/// Connect to the UDS, write a single `Request::ChainApply` line, read
/// exactly one response line back. Mirrors `local::send` but kept
/// separate so the `chain` scope doesn't depend on `local` internals.
async fn send_chain_apply(socket: &Path, request: &Request, timeout: Duration) -> Result<Response> {
    let socket: PathBuf = socket.to_path_buf();
    let mut stream = tokio::time::timeout(timeout, UnixStream::connect(&socket))
        .await
        .with_context(|| format!("connect timeout after {timeout:?}"))?
        .with_context(|| format!("connecting to {}", socket.display()))?;

    let mut buf = serde_json::to_vec(request).context("encode ChainApply request")?;
    buf.push(b'\n');
    tokio::time::timeout(timeout, stream.write_all(&buf))
        .await
        .context("write timeout")?
        .context("writing ChainApply request")?;

    let (reader, _w) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    let line = tokio::time::timeout(timeout, lines.next_line())
        .await
        .context("read timeout")?
        .context("reading ChainApply response")?
        .ok_or_else(|| anyhow!("server closed connection before responding to ChainApply"))?;
    serde_json::from_str(&line).context("decode ChainApply response")
}

// =============================================================================
// Phase 5D: `chain diff`
// =============================================================================

// CLI-side aliases for the wire types defined in
// [`ratatoskr::control`]. The daemon emits a `Response::DerivedRules`
// over UDS for the local hop, and (in stage B3, once the chain tunnel
// learns to forward UDS-style ndjson) for upstream hops too. Using the
// wire types directly removes the parallel-mirror divergence risk that
// existed when we defined our own `IntrospectionView` shape.
use ratatoskr::control::DerivedRulesResponse as IntrospectionView;

/// A single hop's contribution to the report. Hop 0 is the local node;
/// hops 1..N are reached over chain tunnels.
#[derive(Debug, Clone, Serialize)]
struct HopReport {
    /// 0 for the local hop, 1 for its immediate upstream, etc.
    index: usize,
    /// Pubkey we *expected* at this hop — the previous hop's
    /// `dial`. For hop 0 this is the local node's own
    /// `chain.local`; we record it for cross-check symmetry.
    expected_pubkey: PubKey,
    /// Snapshot the hop returned. `chain.local` is asserted to equal
    /// `expected_pubkey` before this struct is constructed; any mismatch
    /// aborts the walk.
    view: IntrospectionView,
    /// Predicate-set drift between this hop's `predicates` and the
    /// previous hop's `predicates`. `None` when (a) this is hop 0, (b)
    /// the previous hop had no predicates to compare against, or (c)
    /// the predicate origins don't match (the chain isn't sharing a
    /// single terminal's projection).
    drift: Option<PredicateDiff>,
}

/// Structured diff between two hops' predicate sets.
///
/// "Local" refers to the *publishing* side (the hop further down the
/// chain — i.e., closer to the operator) and "upstream" refers to the
/// *accepting* side (the hop further up the chain).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct PredicateDiff {
    /// Predicates the local hop published that the upstream hop did
    /// not record. The most common cause is a stale upstream that
    /// hasn't acked the latest push yet.
    missing_upstream: Vec<Predicate>,
    /// Predicates the upstream hop has on record but that the local
    /// hop did not include in its latest projection. Indicates either
    /// (a) a deleted local rule whose deletion hasn't propagated, or
    /// (b) the upstream is mixing predicates from another origin.
    extra_upstream: Vec<Predicate>,
    /// Predicates whose `name` matches on both sides but whose other
    /// fields (port / protocol / idle_timeout_ms) differ. Indicates an
    /// in-flight push where the upstream still has the previous
    /// version's shape.
    changed: Vec<PredicateChange>,
    local_version: Option<u64>,
    upstream_version: Option<u64>,
    local_origin: Option<PubKey>,
    upstream_origin: Option<PubKey>,
}

impl PredicateDiff {
    /// True when nothing differs between the two hops.
    fn is_in_sync(&self) -> bool {
        self.missing_upstream.is_empty()
            && self.extra_upstream.is_empty()
            && self.changed.is_empty()
            && self.local_version == self.upstream_version
            && self.local_origin == self.upstream_origin
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct PredicateChange {
    /// The predicate name (same on both sides).
    name: String,
    /// Local-hop shape.
    local: Predicate,
    /// Upstream-hop shape.
    upstream: Predicate,
}

/// Top-level diff report rendered to the operator.
#[derive(Debug, Clone, Serialize)]
struct DiffReport {
    hops: Vec<HopReport>,
    /// True when at least one hop's `drift` is non-empty *or* a hop
    /// the previous hop pointed at could not be reached. The CLI's
    /// exit code reflects this so CI pipelines can gate on it.
    drift_detected: bool,
    /// Whether the daemon's chain summary was incomplete (some
    /// upstream hop could not be reached within the timeout). Always
    /// `false` for local-only summaries; multi-hop fanout flips it
    /// when the walk truncates.
    partial: bool,
}

/// Walk the chain upward from the local node, fetch each hop's
/// derived-rules snapshot, and emit a structured diff. See module
/// docstring for the operator-facing semantics.
///
/// Wire path (B3b): the CLI sends a single
/// [`Request::ChainSummary`] over UDS; the daemon assembles a
/// [`ChainSummaryResponse`] containing one [`ChainHop`] per chain
/// node it can reach (today only the local hop; multi-hop fanout via
/// the chain control plane is a follow-up increment). The diff is a
/// pure function over the resulting `Vec<ChainHop>` — no HTTP, no
/// tunnel, no per-hop dialing from the CLI.
async fn diff(socket: &Path, args: &DiffArgs, json_output: bool) -> Result<()> {
    let summary = fetch_chain_summary(socket, args.timeout)
        .await
        .context("fetching chain summary over UDS")?;

    if summary.hops.is_empty() {
        bail!("daemon returned an empty chain summary; no hops to diff");
    }

    let mut hops: Vec<HopReport> = Vec::with_capacity(summary.hops.len());
    let mut prev_view: Option<IntrospectionView> = None;
    for wire_hop in summary.hops {
        let drift = match &prev_view {
            None => None,
            Some(prev) => compute_diff(prev, &wire_hop.view),
        };
        let expected_pubkey = wire_hop.view.chain.local;
        prev_view = Some(wire_hop.view.clone());
        hops.push(HopReport {
            index: wire_hop.hop_index as usize,
            expected_pubkey,
            view: wire_hop.view,
            drift,
        });
    }

    let drift_detected = hops
        .iter()
        .any(|h| h.drift.as_ref().is_some_and(|d| !d.is_in_sync()));
    let report = DiffReport {
        hops,
        drift_detected,
        partial: summary.partial,
    };

    if json_output {
        let s = serde_json::to_string_pretty(&report).context("serialise diff report")?;
        println!("{s}");
    } else {
        render_human(&report);
    }

    if drift_detected {
        // Non-zero exit so CI / `set -e` shell wrappers see drift.
        std::process::exit(1);
    }
    Ok(())
}

/// Send `Request::ChainSummary` over UDS and read back the single
/// `Response::ChainSummary` ndjson line. Errors are wrapped with the
/// socket path for operator-friendly diagnostics.
async fn fetch_chain_summary(socket: &Path, timeout: Duration) -> Result<ChainSummaryResponse> {
    let socket_path: PathBuf = socket.to_path_buf();
    let stream = tokio::time::timeout(timeout, UnixStream::connect(&socket_path))
        .await
        .with_context(|| format!("UDS connect timeout to {}", socket_path.display()))?
        .with_context(|| format!("connecting to {}", socket_path.display()))?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let request = Request::ChainSummary {
        timeout_ms: Some(timeout.as_millis().min(u64::MAX as u128) as u64),
    };
    let mut buf = serde_json::to_vec(&request).context("encode ChainSummary request")?;
    buf.push(b'\n');
    tokio::time::timeout(timeout, writer.write_all(&buf))
        .await
        .context("write timeout sending ChainSummary")?
        .context("writing ChainSummary request")?;

    let mut line = String::new();
    let n = tokio::time::timeout(timeout, reader.read_line(&mut line))
        .await
        .context("read timeout awaiting ChainSummary response")?
        .context("reading ChainSummary response")?;
    if n == 0 {
        bail!("daemon closed UDS without responding to ChainSummary");
    }
    let response: Response = serde_json::from_str(line.trim())
        .with_context(|| format!("parsing daemon response: {line:?}"))?;
    match response {
        Response::ChainSummary(s) => Ok(s),
        Response::Error { code, message } => {
            bail!("daemon returned error for ChainSummary: code={code} message={message}");
        }
        other => bail!("unexpected response to ChainSummary: {other:?}"),
    }
}

/// Compare two hops' predicate sets. Returns `None` when no comparison
/// is meaningful at this boundary (no predicates on either side, or the
/// origins point at different terminals — which means the upstream is
/// driven by a different chain branch and a diff would be apples to
/// oranges).
fn compute_diff(
    publisher: &IntrospectionView,
    receiver: &IntrospectionView,
) -> Option<PredicateDiff> {
    // No predicates on either side → nothing to compare.
    if publisher.predicates.is_empty() && receiver.predicates.is_empty() {
        return None;
    }

    // If both sides have origins recorded, they must agree for the
    // comparison to be meaningful. If they disagree the receiver is
    // driven by a different terminal — skip rather than report
    // misleading "drift".
    let pub_origin = publisher.chain.predicate_origin;
    let recv_origin = receiver.chain.predicate_origin;
    if let (Some(p), Some(r)) = (pub_origin, recv_origin) {
        if p != r {
            return None;
        }
    }

    let local_by_name: std::collections::BTreeMap<&str, &Predicate> = publisher
        .predicates
        .iter()
        .map(|p| (p.name.as_str(), p))
        .collect();
    let upstream_by_name: std::collections::BTreeMap<&str, &Predicate> = receiver
        .predicates
        .iter()
        .map(|p| (p.name.as_str(), p))
        .collect();

    let mut missing_upstream = Vec::new();
    let mut changed = Vec::new();
    for (name, local) in &local_by_name {
        match upstream_by_name.get(name) {
            None => missing_upstream.push((*local).clone()),
            Some(upstream) if upstream != local => {
                changed.push(PredicateChange {
                    name: (*name).to_string(),
                    local: (*local).clone(),
                    upstream: (*upstream).clone(),
                });
            }
            Some(_) => {}
        }
    }
    let mut extra_upstream = Vec::new();
    for (name, upstream) in &upstream_by_name {
        if !local_by_name.contains_key(name) {
            extra_upstream.push((*upstream).clone());
        }
    }

    Some(PredicateDiff {
        missing_upstream,
        extra_upstream,
        changed,
        local_version: publisher.chain.predicate_version,
        upstream_version: receiver.chain.predicate_version,
        local_origin: pub_origin,
        upstream_origin: recv_origin,
    })
}

/// Render the report in the default human-readable form.
///
/// One block per hop:
///
/// ```text
/// hop 0 (local x25519:abc…): predicates=2 v=12 origin=x25519:abc…
///   derived_rules: 2 active
/// hop 1 (upstream x25519:def…): predicates=2 v=12 origin=x25519:abc…
///   in sync with hop 0
/// hop 2 (upstream x25519:fff…): predicates=0
///   no predicates on this hop (deeper relays may not receive pushes
///   under v1 — relays do not re-publish)
/// ```
fn render_human(report: &DiffReport) {
    for hop in &report.hops {
        let role = if hop.index == 0 { "local" } else { "upstream" };
        let v = &hop.view;
        let version_label = v
            .chain
            .predicate_version
            .map(|n| format!(" v={n}"))
            .unwrap_or_default();
        let origin_label = v
            .chain
            .predicate_origin
            .map(|p| format!(" origin={p}"))
            .unwrap_or_default();
        println!(
            "hop {idx} ({role} {pk}): predicates={count}{version_label}{origin_label}",
            idx = hop.index,
            pk = v.chain.local,
            count = v.predicates.len(),
        );
        println!("  derived_rules: {} active", v.derived_rules.len());
        match &hop.drift {
            None if hop.index == 0 => {}
            None => {
                if v.predicates.is_empty() {
                    println!(
                        "  no predicates on this hop (under v1 only the \
                         immediate upstream of a terminal carries the \
                         pushed set; deeper hops are reported for chain \
                         identity only)"
                    );
                } else {
                    println!(
                        "  no comparison performed (origin mismatch with \
                         previous hop)"
                    );
                }
            }
            Some(d) if d.is_in_sync() => {
                println!("  in sync with hop {}", hop.index - 1);
            }
            Some(d) => {
                println!("  DRIFT vs hop {}:", hop.index - 1);
                if d.local_version != d.upstream_version {
                    println!(
                        "    version: local={:?} upstream={:?}",
                        d.local_version, d.upstream_version
                    );
                }
                if d.local_origin != d.upstream_origin {
                    println!(
                        "    origin: local={:?} upstream={:?}",
                        d.local_origin.map(|p| p.to_string()),
                        d.upstream_origin.map(|p| p.to_string()),
                    );
                }
                for p in &d.missing_upstream {
                    println!(
                        "    + {name} (proto={proto:?} port={port}) missing upstream",
                        name = p.name,
                        proto = p.protocol,
                        port = p.listen_port
                    );
                }
                for p in &d.extra_upstream {
                    println!(
                        "    - {name} (proto={proto:?} port={port}) extra upstream",
                        name = p.name,
                        proto = p.protocol,
                        port = p.listen_port
                    );
                }
                for c in &d.changed {
                    println!(
                        "    ~ {name}: local=(proto={lp:?} port={lpo} idle={li:?}) \
                         upstream=(proto={up:?} port={upo} idle={ui:?})",
                        name = c.name,
                        lp = c.local.protocol,
                        lpo = c.local.listen_port,
                        li = c.local.idle_timeout_ms,
                        up = c.upstream.protocol,
                        upo = c.upstream.listen_port,
                        ui = c.upstream.idle_timeout_ms,
                    );
                }
            }
        }
    }
    if report.drift_detected {
        println!("\nDRIFT detected on at least one hop.");
    } else {
        println!("\nin sync across {} hop(s).", report.hops.len());
    }
    if report.partial {
        println!(
            "note: chain summary is partial — some upstream hops could \
             not be reached within the timeout."
        );
    }
}

// =============================================================================
// CP22: `chain summary`
// =============================================================================

/// One-line-per-hop entry in the structured summary report.
#[derive(Debug, Clone, Serialize)]
struct SummaryHop {
    /// `0 = local`, `1 = local's upstream`, …
    index: u32,
    /// Hop's tagged x25519 pubkey.
    pubkey: PubKey,
    /// Runtime mode the hop is operating in.
    mode: ratatoskr::control::Mode,
    /// Hop's process uptime in whole seconds.
    uptime_secs: u64,
    /// Number of derived rules currently loaded by the proxy supervisor.
    rule_count: usize,
    /// Number of accepted predicates (relays) or projected predicates
    /// (terminals).
    predicate_count: usize,
    /// `PredicateSet.version` of the most recently applied push, if any.
    predicate_version: Option<u64>,
}

/// Structured top-level summary report. The `--json` rendering serialises
/// this directly; the human renderer projects it onto one line per hop.
#[derive(Debug, Clone, Serialize)]
struct SummaryReport {
    hops: Vec<SummaryHop>,
    /// Mirrors [`ChainSummaryResponse::partial`] so JSON consumers and
    /// the human renderer can both surface the truncation note.
    partial: bool,
}

/// Render the chain summary. Reuses [`fetch_chain_summary`] so any
/// improvements to the wire path (multi-hop fanout, retry semantics)
/// are picked up here automatically.
async fn summary(socket: &Path, args: &SummaryArgs, json_output: bool) -> Result<()> {
    let resp = fetch_chain_summary(socket, args.timeout)
        .await
        .context("fetching chain summary over UDS")?;

    if resp.hops.is_empty() {
        bail!("daemon returned an empty chain summary; no hops to render");
    }

    let hops: Vec<SummaryHop> = resp
        .hops
        .iter()
        .map(|h| SummaryHop {
            index: h.hop_index,
            pubkey: h.view.chain.local,
            mode: h.mode,
            uptime_secs: h.uptime_secs,
            rule_count: h.view.derived_rules.len(),
            predicate_count: h.view.predicates.len(),
            predicate_version: h.view.chain.predicate_version,
        })
        .collect();
    let report = SummaryReport {
        hops,
        partial: resp.partial,
    };

    if json_output {
        let s = serde_json::to_string_pretty(&report).context("serialise chain summary report")?;
        println!("{s}");
    } else {
        render_summary_human(&report);
    }
    Ok(())
}

/// Render the report in the default human-readable form. Format:
///
/// ```text
/// hop 0  terminal  x25519:abc…  uptime=12s  rules=2  predicates=2 v=7
/// hop 1  relay     x25519:def…  uptime=304s rules=2  predicates=2 v=7
/// hop 2  gateway   x25519:fff…  uptime=304s rules=0  predicates=0
/// ```
fn render_summary_human(report: &SummaryReport) {
    for hop in &report.hops {
        let version_label = hop
            .predicate_version
            .map(|v| format!(" v={v}"))
            .unwrap_or_default();
        println!(
            "hop {idx}  {mode:<8}  {pk}  uptime={uptime}s  rules={rules}  predicates={preds}{version_label}",
            idx = hop.index,
            mode = format!("{:?}", hop.mode).to_lowercase(),
            pk = hop.pubkey,
            uptime = hop.uptime_secs,
            rules = hop.rule_count,
            preds = hop.predicate_count,
        );
    }
    if report.partial {
        println!(
            "note: chain summary is partial — some upstream hops could \
             not be reached within the timeout."
        );
    }
}

// =============================================================================
// CP22: `chain health`
// =============================================================================

/// Health tier per hop. `worst-of-hops` becomes the chain-wide verdict.
///
/// Order matters: `Down > Degraded > Starting > Healthy`. Comparisons
/// use the derived `PartialOrd` to bubble worst tiers up.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum HealthTier {
    /// All checks pass.
    Healthy,
    /// Daemon recently started; predicate freshness has not had time
    /// to be measured. Distinct tier so monitoring doesn't page on
    /// initial boot.
    Starting,
    /// One or more checks are warning. Operator should investigate but
    /// no immediate action required.
    Degraded,
    /// One or more checks are failing. Operator should act now.
    Down,
}

/// Per-hop health entry. The `reasons` field carries the human-readable
/// findings that drove the tier; empty when `tier == Healthy`.
#[derive(Debug, Clone, Serialize)]
struct HealthHop {
    index: u32,
    pubkey: PubKey,
    mode: ratatoskr::control::Mode,
    uptime_secs: u64,
    tier: HealthTier,
    /// Plain English notes explaining how the tier was reached. Always
    /// present (possibly empty) so JSON consumers can rely on the
    /// field shape.
    reasons: Vec<String>,
}

/// Top-level health report.
#[derive(Debug, Clone, Serialize)]
struct HealthReport {
    /// Worst-of-hops tier; drives the process exit code.
    overall: HealthTier,
    hops: Vec<HealthHop>,
    /// Mirrors [`ChainSummaryResponse::partial`].
    partial: bool,
}

/// Boot grace window: hops with `uptime_secs < 30` are reported as
/// `Starting` regardless of predicate freshness.
const STARTING_GRACE_SECS: u64 = 30;
/// Predicate freshness thresholds (seconds since `last_apply_unix`).
const PREDICATE_DEGRADED_AGE_SECS: i64 = 300; // 5 min
const PREDICATE_DOWN_AGE_SECS: i64 = 1_800; // 30 min

async fn health(socket: &Path, args: &HealthArgs, json_output: bool) -> Result<()> {
    let resp = fetch_chain_summary(socket, args.timeout)
        .await
        .context("fetching chain summary over UDS")?;
    if resp.hops.is_empty() {
        bail!("daemon returned an empty chain summary; no hops to health-check");
    }

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let hops: Vec<HealthHop> = resp
        .hops
        .iter()
        .map(|h| classify_hop(h, now_unix))
        .collect();
    let overall = hops
        .iter()
        .map(|h| h.tier)
        .max()
        .unwrap_or(HealthTier::Healthy);
    let report = HealthReport {
        overall,
        hops,
        partial: resp.partial,
    };

    if json_output {
        let s = serde_json::to_string_pretty(&report).context("serialise chain health report")?;
        println!("{s}");
    } else {
        render_health_human(&report);
    }

    let code = match report.overall {
        HealthTier::Healthy | HealthTier::Starting => 0,
        HealthTier::Degraded => 1,
        HealthTier::Down => 2,
    };
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

/// Classify a single hop. Currently considers (a) the boot grace
/// window and (b) predicate freshness from `last_apply_unix`.
/// Heartbeat-age, rekey-age, and TLS-cert-expiry checks are deferred
/// until [`ratatoskr::control::ChainHop`] grows the corresponding
/// fields (CP37).
fn classify_hop(hop: &ratatoskr::control::ChainHop, now_unix: i64) -> HealthHop {
    let mut reasons: Vec<String> = Vec::new();
    let mut tier = HealthTier::Healthy;

    // Predicate freshness — only meaningful if a push has ever
    // happened. Hops that never receive predicates (deeper relays in
    // v1) legitimately report `last_apply_unix = None` and are not
    // penalised.
    if let Some(last_apply) = hop.view.chain.last_apply_unix {
        let age = now_unix.saturating_sub(last_apply);
        if age >= PREDICATE_DOWN_AGE_SECS {
            tier = tier.max(HealthTier::Down);
            reasons.push(format!(
                "predicate set is stale ({}s since last apply; threshold {}s)",
                age, PREDICATE_DOWN_AGE_SECS,
            ));
        } else if age >= PREDICATE_DEGRADED_AGE_SECS {
            tier = tier.max(HealthTier::Degraded);
            reasons.push(format!(
                "predicate set is aging ({}s since last apply; threshold {}s)",
                age, PREDICATE_DEGRADED_AGE_SECS,
            ));
        }
    }

    // Boot grace window — overrides Healthy with Starting only.
    // Degraded/Down findings already raised above stay as-is so
    // monitoring still surfaces actionable problems even during boot.
    if hop.uptime_secs < STARTING_GRACE_SECS && tier == HealthTier::Healthy {
        tier = HealthTier::Starting;
        reasons.push(format!(
            "daemon recently started ({}s uptime; grace window {}s)",
            hop.uptime_secs, STARTING_GRACE_SECS,
        ));
    }

    HealthHop {
        index: hop.hop_index,
        pubkey: hop.view.chain.local,
        mode: hop.mode,
        uptime_secs: hop.uptime_secs,
        tier,
        reasons,
    }
}

fn render_health_human(report: &HealthReport) {
    for hop in &report.hops {
        let tier_label = match hop.tier {
            HealthTier::Healthy => "healthy",
            HealthTier::Starting => "starting",
            HealthTier::Degraded => "degraded",
            HealthTier::Down => "down",
        };
        println!(
            "hop {idx}  {mode:<8}  {pk}  {tier}",
            idx = hop.index,
            mode = format!("{:?}", hop.mode).to_lowercase(),
            pk = hop.pubkey,
            tier = tier_label,
        );
        for reason in &hop.reasons {
            println!("    - {reason}");
        }
    }
    let overall_label = match report.overall {
        HealthTier::Healthy => "healthy",
        HealthTier::Starting => "starting",
        HealthTier::Degraded => "degraded",
        HealthTier::Down => "down",
    };
    println!("\noverall: {overall_label}");
    if report.partial {
        println!(
            "note: chain summary is partial — some upstream hops could \
             not be reached within the timeout."
        );
    }
}

// =============================================================================
// CP22: `chain ping`
// =============================================================================

/// One hop's RTT measurement in the structured ping report.
#[derive(Debug, Clone, Serialize)]
struct PingHop {
    /// `0 = local`, `1 = local's upstream`, …
    index: u32,
    /// Hop's tagged x25519 pubkey (used for `--hop` filtering).
    pubkey: PubKey,
    /// Wall-clock RTT measured by this hop's parent for the
    /// `ChainHopQuery` that produced it. `None` on the local hop and
    /// (legacy daemons) on hops whose parent didn't stamp an RTT.
    query_rtt_ms: Option<u64>,
}

/// Structured top-level ping report. The `--json` rendering serialises
/// this directly; the human renderer projects it onto one line per hop.
#[derive(Debug, Clone, Serialize)]
struct PingReport {
    hops: Vec<PingHop>,
    /// Mirrors [`ChainSummaryResponse::partial`] so JSON consumers and
    /// the human renderer can both surface the truncation note.
    partial: bool,
}

/// Render per-hop control-plane RTT. Walks the chain via the same
/// `Request::ChainSummary` RPC as `chain summary`/`chain diff`/`chain
/// health`; the RTT field on each [`ratatoskr::control::ChainHop`]
/// carries the wall-clock time that the hop's parent measured for its
/// upstream query.
async fn ping(socket: &Path, args: &PingArgs, json_output: bool) -> Result<()> {
    let resp = fetch_chain_summary(socket, args.timeout)
        .await
        .context("fetching chain summary over UDS")?;

    if resp.hops.is_empty() {
        bail!("daemon returned an empty chain summary; no hops to ping");
    }

    let mut hops: Vec<PingHop> = resp
        .hops
        .iter()
        .map(|h| PingHop {
            index: h.hop_index,
            pubkey: h.view.chain.local,
            query_rtt_ms: h.query_rtt_ms,
        })
        .collect();

    if let Some(filter) = args.hop.as_ref() {
        hops.retain(|h| &h.pubkey == filter);
        if hops.is_empty() {
            bail!("--hop {filter} did not match any pubkey in the chain summary");
        }
    }

    let report = PingReport {
        hops,
        partial: resp.partial,
    };

    if json_output {
        let s = serde_json::to_string_pretty(&report).context("serialise chain ping report")?;
        println!("{s}");
    } else {
        render_ping_human(&report);
    }
    Ok(())
}

/// Render the report in the default human-readable form. Format:
///
/// ```text
/// hop 0  x25519:abc…  rtt=-
/// hop 1  x25519:def…  rtt=12ms
/// hop 2  x25519:fff…  rtt=37ms
/// ```
fn render_ping_human(report: &PingReport) {
    for hop in &report.hops {
        let rtt = match hop.query_rtt_ms {
            Some(ms) => format!("{ms}ms"),
            None => "-".to_string(),
        };
        println!(
            "hop {idx}  {pk}  rtt={rtt}",
            idx = hop.index,
            pk = hop.pubkey,
        );
    }
    if report.partial {
        println!(
            "note: chain summary is partial — some upstream hops could \
             not be reached within the timeout."
        );
    }
}

// =============================================================================
// Tests — diff comparison + serde round-trip
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ratatoskr::control::ChainIdentity as ChainView;
    use ratatoskr::rule::Protocol;

    fn pk(seed: u8) -> PubKey {
        PubKey::x25519([seed; 32])
    }

    fn pred(name: &str, port: u16, proto: Protocol) -> Predicate {
        Predicate {
            name: name.into(),
            listen_port: port,
            protocol: proto,
            idle_timeout_ms: None,
            https_http3: false,
        }
    }

    fn view(
        predicates: Vec<Predicate>,
        local: PubKey,
        upstream: Option<PubKey>,
        origin: Option<PubKey>,
        version: Option<u64>,
    ) -> IntrospectionView {
        IntrospectionView {
            predicates,
            derived_rules: Vec::new(),
            chain: ChainView {
                local,
                upstream,
                downstream: None,
                predicate_origin: origin,
                predicate_version: version,
                last_apply_unix: None,
            },
        }
    }

    #[test]
    fn diff_in_sync_when_predicates_versions_origins_all_match() {
        let preds = vec![
            pred("a", 1000, Protocol::Tcp),
            pred("b", 1001, Protocol::Udp),
        ];
        let local = view(preds.clone(), pk(1), Some(pk(2)), Some(pk(1)), Some(7));
        let upstream = view(preds, pk(2), None, Some(pk(1)), Some(7));
        let d = compute_diff(&local, &upstream).expect("comparable");
        assert!(d.is_in_sync(), "expected in sync, got {d:?}");
    }

    #[test]
    fn diff_detects_predicate_missing_upstream() {
        let local_preds = vec![
            pred("a", 1000, Protocol::Tcp),
            pred("b", 1001, Protocol::Udp),
        ];
        let upstream_preds = vec![pred("a", 1000, Protocol::Tcp)];
        let local = view(local_preds, pk(1), Some(pk(2)), Some(pk(1)), Some(7));
        let upstream = view(upstream_preds, pk(2), None, Some(pk(1)), Some(7));
        let d = compute_diff(&local, &upstream).expect("comparable");
        assert!(!d.is_in_sync());
        assert_eq!(d.missing_upstream.len(), 1);
        assert_eq!(d.missing_upstream[0].name, "b");
        assert!(d.extra_upstream.is_empty());
        assert!(d.changed.is_empty());
    }

    #[test]
    fn diff_detects_predicate_extra_upstream() {
        let local_preds = vec![pred("a", 1000, Protocol::Tcp)];
        let upstream_preds = vec![
            pred("a", 1000, Protocol::Tcp),
            pred("ghost", 2000, Protocol::Tcp),
        ];
        let local = view(local_preds, pk(1), Some(pk(2)), Some(pk(1)), Some(7));
        let upstream = view(upstream_preds, pk(2), None, Some(pk(1)), Some(7));
        let d = compute_diff(&local, &upstream).expect("comparable");
        assert!(!d.is_in_sync());
        assert!(d.missing_upstream.is_empty());
        assert_eq!(d.extra_upstream.len(), 1);
        assert_eq!(d.extra_upstream[0].name, "ghost");
    }

    #[test]
    fn diff_detects_changed_predicate_with_same_name_but_different_port() {
        let local = view(
            vec![pred("a", 1000, Protocol::Tcp)],
            pk(1),
            Some(pk(2)),
            Some(pk(1)),
            Some(7),
        );
        let upstream = view(
            vec![pred("a", 1001, Protocol::Tcp)],
            pk(2),
            None,
            Some(pk(1)),
            Some(7),
        );
        let d = compute_diff(&local, &upstream).expect("comparable");
        assert!(!d.is_in_sync());
        assert_eq!(d.changed.len(), 1);
        assert_eq!(d.changed[0].name, "a");
        assert_eq!(d.changed[0].local.listen_port, 1000);
        assert_eq!(d.changed[0].upstream.listen_port, 1001);
    }

    #[test]
    fn diff_detects_version_drift_with_matching_predicates() {
        let preds = vec![pred("a", 1000, Protocol::Tcp)];
        let local = view(preds.clone(), pk(1), Some(pk(2)), Some(pk(1)), Some(8));
        let upstream = view(preds, pk(2), None, Some(pk(1)), Some(7));
        let d = compute_diff(&local, &upstream).expect("comparable");
        assert!(
            !d.is_in_sync(),
            "version drift alone should fail is_in_sync"
        );
        assert!(d.missing_upstream.is_empty());
        assert!(d.extra_upstream.is_empty());
        assert!(d.changed.is_empty());
        assert_eq!(d.local_version, Some(8));
        assert_eq!(d.upstream_version, Some(7));
    }

    #[test]
    fn diff_returns_none_when_no_predicates_on_either_side() {
        let local = view(Vec::new(), pk(1), Some(pk(2)), None, None);
        let upstream = view(Vec::new(), pk(2), None, None, None);
        assert!(
            compute_diff(&local, &upstream).is_none(),
            "no predicates anywhere → no comparison performed"
        );
    }

    #[test]
    fn diff_returns_none_when_origins_disagree() {
        // Both sides have predicates but they come from different
        // terminals. The receiver isn't this terminal's upstream in any
        // meaningful sense, so we skip the comparison rather than
        // emit misleading drift.
        let local = view(
            vec![pred("a", 1000, Protocol::Tcp)],
            pk(1),
            Some(pk(2)),
            Some(pk(1)),
            Some(7),
        );
        let upstream = view(
            vec![pred("b", 2000, Protocol::Tcp)],
            pk(2),
            None,
            Some(pk(99)), // different terminal authored this set
            Some(3),
        );
        assert!(compute_diff(&local, &upstream).is_none());
    }

    #[test]
    fn introspection_view_round_trips_through_serde() {
        // Build a snapshot in the daemon's exact JSON shape and ensure
        // we deserialise into the CLI mirror without losing fields.
        let raw = serde_json::json!({
            "predicates": [
                {
                    "name": "alpha",
                    "listen_port": 9001,
                    "protocol": "tcp",
                    "idle_timeout_ms": null,
                },
                {
                    "name": "beta",
                    "listen_port": 9002,
                    "protocol": "udp",
                    "idle_timeout_ms": 60000,
                }
            ],
            "derived_rules": [],
            "chain": {
                "local": "x25519:0101010101010101010101010101010101010101010101010101010101010101",
                "upstream": "x25519:0202020202020202020202020202020202020202020202020202020202020202",
                "downstream": null,
                "predicate_origin": "x25519:0101010101010101010101010101010101010101010101010101010101010101",
                "predicate_version": 42,
                "last_apply_unix": 1737244800,
            }
        });
        let v: IntrospectionView = serde_json::from_value(raw).expect("deserialise");
        assert_eq!(v.predicates.len(), 2);
        assert_eq!(v.predicates[0].name, "alpha");
        assert_eq!(v.predicates[1].idle_timeout_ms, Some(60_000));
        assert_eq!(v.chain.local, pk(1));
        assert_eq!(v.chain.upstream, Some(pk(2)));
        assert_eq!(v.chain.predicate_version, Some(42));
        assert_eq!(v.chain.last_apply_unix, Some(1737244800));
    }

    // ---------- chain health classification ----------

    fn hop(uptime_secs: u64, last_apply_unix: Option<i64>) -> ratatoskr::control::ChainHop {
        ratatoskr::control::ChainHop {
            hop_index: 0,
            mode: ratatoskr::control::Mode::Terminal,
            uptime_secs,
            query_rtt_ms: None,
            view: view(Vec::new(), pk(1), None, None, None).pipe(|mut v| {
                v.chain.last_apply_unix = last_apply_unix;
                v
            }),
        }
    }

    /// Tiny helper trait so the closure form above reads cleanly.
    trait Pipe: Sized {
        fn pipe<F: FnOnce(Self) -> Self>(self, f: F) -> Self {
            f(self)
        }
    }
    impl<T> Pipe for T {}

    #[test]
    fn health_starting_when_uptime_under_grace_and_no_predicate_age() {
        let h = hop(5, None);
        let r = classify_hop(&h, 1_700_000_000);
        assert_eq!(r.tier, HealthTier::Starting);
        assert_eq!(r.reasons.len(), 1);
    }

    #[test]
    fn health_healthy_after_grace_with_no_predicate_history() {
        let h = hop(120, None);
        let r = classify_hop(&h, 1_700_000_000);
        assert_eq!(r.tier, HealthTier::Healthy);
        assert!(r.reasons.is_empty());
    }

    #[test]
    fn health_healthy_when_predicate_recently_applied() {
        let now = 1_700_000_000;
        let h = hop(120, Some(now - 30));
        let r = classify_hop(&h, now);
        assert_eq!(r.tier, HealthTier::Healthy);
    }

    #[test]
    fn health_degraded_when_predicate_aging() {
        let now = 1_700_000_000;
        let h = hop(120, Some(now - PREDICATE_DEGRADED_AGE_SECS - 1));
        let r = classify_hop(&h, now);
        assert_eq!(r.tier, HealthTier::Degraded);
    }

    #[test]
    fn health_down_when_predicate_stale() {
        let now = 1_700_000_000;
        let h = hop(120, Some(now - PREDICATE_DOWN_AGE_SECS - 1));
        let r = classify_hop(&h, now);
        assert_eq!(r.tier, HealthTier::Down);
    }

    #[test]
    fn health_tier_ordering_bubbles_worst_up() {
        assert!(HealthTier::Down > HealthTier::Degraded);
        assert!(HealthTier::Degraded > HealthTier::Starting);
        assert!(HealthTier::Starting > HealthTier::Healthy);
    }

    #[test]
    fn health_down_overrides_starting_during_boot() {
        // Stale predicate should not be masked by the starting grace
        // window — operators must see persistent down conditions even
        // during boot.
        let now = 1_700_000_000;
        let h = hop(5, Some(now - PREDICATE_DOWN_AGE_SECS - 1));
        let r = classify_hop(&h, now);
        assert_eq!(r.tier, HealthTier::Down);
    }
}
