//! `chain` scope — chain-control plane operations.
//!
//! `chain apply`: push a candidate `rules.toml` into the running
//! terminal daemon without touching its on-disk rules directory.
//!
//! `chain diff`: compare the local terminal's published predicate
//! set with what each upstream node believes it accepted. Served
//! from a single-RPC `ChainSummary` reply over UDS; the daemon
//! handles the recursive upstream walk via the chain control plane.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use ratatoskr::control::{ChainSummaryResponse, Mode, Request, Response};
use ratatoskr::predicate::Predicate;
use ratatoskr::pubkey::PubKey;
use ratatoskr::rule::{RuleFile, RuleSet};

pub use cli_defs::yggdrasilctl::chain::{
    ApplyArgs, CanaryArgs, Cmd, DiffArgs, HealthArgs, PingArgs, ProtoArg, SummaryArgs,
};

/// Number of hex characters used for the short-pubkey fallback /
/// collision disambiguator in chain-hop renderers. Eight hex chars =
/// 32 bits of identity, ample for human cross-reference in any
/// realistic chain.
pub const HOP_LABEL_PUBKEY_PREFIX_HEX: usize = 8;

/// Format the short-pubkey form used when no `[server].name` is set
/// or when two hops in the same chain collide on name.
///
/// Returns e.g. `"x25519:7f3a2b1c"`. The full pubkey is wire-form
/// `x25519:<64 hex chars>`; we truncate the hex tail.
fn short_pubkey(pk: &PubKey) -> String {
    let full = pk.to_string();
    // PubKey::to_string() formats as `"x25519:<hex>"`. Find the
    // colon and keep the prefix bytes after it. If the encoding ever
    // changes shape, fall back to the full form.
    match full.find(':') {
        Some(idx) => {
            let prefix = &full[..=idx];
            let hex = &full[idx + 1..];
            let take = hex.len().min(HOP_LABEL_PUBKEY_PREFIX_HEX);
            format!("{prefix}{}", &hex[..take])
        }
        None => full,
    }
}

/// Compute display labels for an ordered list of chain hops. Prefers
/// each hop's `[server].name` when set (non-empty); falls back to the
/// short pubkey form. When two or more hops in the same chain walk
/// share a name, every colliding hop's label is suffixed with its
/// short pubkey for disambiguation (`"vps (x25519:7f3a2b1c)"`).
///
/// Pure function; takes `(name, pubkey)` pairs and returns labels in
/// the same order. Sized for tens of hops, not thousands.
pub fn hop_labels<'a, I>(hops: I) -> Vec<String>
where
    I: IntoIterator<Item = (Option<&'a str>, &'a PubKey)>,
{
    let pairs: Vec<(Option<&str>, &PubKey)> = hops.into_iter().collect();
    let mut name_counts: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::with_capacity(pairs.len());
    for (name, _) in &pairs {
        if let Some(n) = name.filter(|s| !s.is_empty()) {
            *name_counts.entry(n).or_insert(0) += 1;
        }
    }
    pairs
        .iter()
        .map(|(name, pk)| match name.filter(|s| !s.is_empty()) {
            Some(n) if name_counts.get(n).copied().unwrap_or(0) > 1 => {
                format!("{n} ({})", short_pubkey(pk))
            }
            Some(n) => n.to_string(),
            None => short_pubkey(pk),
        })
        .collect()
}

pub async fn run(cmd: Cmd, socket: &Path, json: bool) -> Result<()> {
    match cmd {
        Cmd::Apply(args) => apply(socket, &args).await,
        Cmd::Diff(args) => diff(socket, &args, json).await,
        Cmd::Summary(args) => summary(socket, &args, json).await,
        Cmd::Health(args) => health(socket, &args, json).await,
        Cmd::Ping(args) => ping(socket, &args, json).await,
        Cmd::Canary(args) => canary(socket, &args, json).await,
    }
}

/// Push a candidate rule set from `args.file` to the running daemon.
///
/// The CLI queries daemon mode first so terminal-only applies fail before
/// shipping a candidate rule set to an intermediary. Local parse +
/// validation then provides line context on schema errors (the daemon's
/// own error path would only see a `Vec<Rule>`). The daemon re-validates
/// as defence in depth.
async fn apply(socket: &Path, args: &ApplyArgs) -> Result<()> {
    ensure_terminal_mode(socket).await?;

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
    let response = send_chain_request(socket, &request, DEFAULT_CLIENT_TIMEOUT_SECS).await?;

    match response {
        Response::ChainApplied(b) => {
            println!(
                "applied {} rule{} ({} projected predicate{})",
                b.applied_rule_count,
                if b.applied_rule_count == 1 { "" } else { "s" },
                b.predicate_count,
                if b.predicate_count == 1 { "" } else { "s" },
            );
            Ok(())
        }
        Response::Error { code, message } => {
            bail!("daemon refused apply: code={code} message={message}");
        }
        other => bail!("daemon returned unexpected response to ChainApply: {other:?}"),
    }
}

// =============================================================================
// `chain diff`
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
    /// Hop's resolved `[server].name` (falls back to hostname on
    /// the daemon side). Used by the renderer for human-friendly
    /// labelling; `None` means the daemon predates the field or
    /// the operator explicitly cleared it.
    #[serde(default)]
    name: Option<String>,
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
    /// previous shape.
    changed: Vec<PredicateChange>,
    local_origin: Option<PubKey>,
    upstream_origin: Option<PubKey>,
}

impl PredicateDiff {
    /// True when nothing differs between the two hops.
    fn is_in_sync(&self) -> bool {
        self.missing_upstream.is_empty()
            && self.extra_upstream.is_empty()
            && self.changed.is_empty()
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
    /// upstream hop could not be reached within the timeout, or the
    /// walk truncated below the depth budget).
    partial: bool,
}

/// Walk the chain upward from the local node, fetch each hop's
/// derived-rules snapshot, and emit a structured diff. See module
/// docstring for the operator-facing semantics.
///
/// Wire path: the CLI sends a single [`Request::ChainSummary`] over
/// UDS; the daemon assembles a [`ChainSummaryResponse`] containing
/// one [`ChainHop`] per chain node it can reach (the daemon does the
/// recursive upstream walk via `ChainHopQuery` / `ChainHopReply`).
/// The diff is a pure function over the resulting `Vec<ChainHop>` —
/// no HTTP, no tunnel, no per-hop dialing from the CLI.
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
            name: wire_hop.name,
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
/// is meaningful at this boundary: either neither side has any
/// predicates yet, or the origins disagree. Origin disagreement should
/// only show up transiently while a terminal-rotation push is
/// propagating up the chain — every node has at most one upstream and
/// at most one downstream by design, so in steady state every hop
/// reports the same origin pubkey.
fn compute_diff(
    publisher: &IntrospectionView,
    receiver: &IntrospectionView,
) -> Option<PredicateDiff> {
    // No predicates on either side → nothing to compare.
    if publisher.predicates.is_empty() && receiver.predicates.is_empty() {
        return None;
    }

    // If both sides have origins recorded, they must agree for the
    // comparison to be meaningful. Disagreement should only happen
    // transiently (e.g. a terminal-rotation push catching up to the
    // upper hops); skip rather than report misleading "drift" while
    // propagation is in flight.
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
        local_origin: pub_origin,
        upstream_origin: recv_origin,
    })
}

/// Render the report in the default human-readable form.
///
/// One block per hop:
///
/// ```text
/// hop 0 (local x25519:abc…): predicates=2 origin=x25519:abc…
///   derived_rules: 2 active
/// hop 1 (upstream x25519:def…): predicates=2 origin=x25519:abc…
///   in sync with hop 0
/// hop 2 (upstream x25519:fff…): predicates=2 origin=x25519:abc…
///   in sync with hop 1
/// ```
///
/// Mid-chain relays forward the original push bytes verbatim upstream,
/// so every settled hop reports the same origin + predicate content as
/// the terminal at hop 0.
fn render_human(report: &DiffReport) {
    let labels = hop_labels(
        report
            .hops
            .iter()
            .map(|h| (h.name.as_deref(), &h.view.chain.local)),
    );
    for (idx, hop) in report.hops.iter().enumerate() {
        let role = if hop.index == 0 { "local" } else { "upstream" };
        let v = &hop.view;
        let origin_label = v
            .chain
            .predicate_origin
            .map(|p| format!(" origin={p}"))
            .unwrap_or_default();
        println!(
            "hop {idx_disp} ({role} {label}): predicates={count}{origin_label}",
            idx_disp = hop.index,
            label = labels[idx],
            count = v.predicates.len(),
        );
        println!("  derived_rules: {} active", v.derived_rules.len());
        match &hop.drift {
            None if hop.index == 0 => {}
            None => {
                if v.predicates.is_empty() {
                    println!(
                        "  no predicates on this hop yet (push has not \
                         propagated this far — chain may still be coming \
                         up, or this hop's chain client is down; check \
                         yggdrasil_chain_predicate_recv_total / \
                         yggdrasil_chain_predicate_forward_total)"
                    );
                } else {
                    println!(
                        "  no comparison performed (origin mismatch with \
                         previous hop — terminal rotation in flight)"
                    );
                }
            }
            Some(d) if d.is_in_sync() => {
                println!("  in sync with hop {}", hop.index - 1);
            }
            Some(d) => {
                println!("  DRIFT vs hop {}:", hop.index - 1);
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
    /// Hop's resolved `[server].name` (or hostname fallback). Used by
    /// the renderer for human-friendly labelling.
    #[serde(default)]
    name: Option<String>,
    /// Runtime mode the hop is operating in.
    mode: ratatoskr::control::Mode,
    /// Hop's process uptime in whole seconds.
    uptime_secs: u64,
    /// Number of derived rules currently loaded by the proxy supervisor.
    rule_count: usize,
    /// Number of accepted predicates (relays) or projected predicates
    /// (terminals).
    predicate_count: usize,
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
            name: h.name.clone(),
            mode: h.mode,
            uptime_secs: h.uptime_secs,
            rule_count: h.view.derived_rules.len(),
            predicate_count: h.view.predicates.len(),
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
/// hop 0  terminal  x25519:abc…  uptime=12s  rules=2  predicates=2
/// hop 1  relay     x25519:def…  uptime=304s rules=2  predicates=2
/// hop 2  gateway   x25519:fff…  uptime=304s rules=2  predicates=2
/// ```
fn render_summary_human(report: &SummaryReport) {
    let labels = hop_labels(report.hops.iter().map(|h| (h.name.as_deref(), &h.pubkey)));
    for (idx, hop) in report.hops.iter().enumerate() {
        println!(
            "hop {hop_idx}  {mode:<8}  {label}  uptime={uptime}s  rules={rules}  predicates={preds}",
            hop_idx = hop.index,
            mode = format!("{:?}", hop.mode).to_lowercase(),
            label = labels[idx],
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
    /// Hop's resolved `[server].name` (or hostname fallback). Used by
    /// the renderer for human-friendly labelling.
    #[serde(default)]
    name: Option<String>,
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
    // happened. Hops that have not yet received any push
    // (`last_apply_unix = None`) legitimately report no predicates and
    // are not penalised; this is the normal state during fresh boot
    // before the chain converges.
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
        name: hop.name.clone(),
        mode: hop.mode,
        uptime_secs: hop.uptime_secs,
        tier,
        reasons,
    }
}

fn render_health_human(report: &HealthReport) {
    let labels = hop_labels(report.hops.iter().map(|h| (h.name.as_deref(), &h.pubkey)));
    for (idx, hop) in report.hops.iter().enumerate() {
        let tier_label = match hop.tier {
            HealthTier::Healthy => "healthy",
            HealthTier::Starting => "starting",
            HealthTier::Degraded => "degraded",
            HealthTier::Down => "down",
        };
        println!(
            "hop {hop_idx}  {mode:<8}  {label}  {tier}",
            hop_idx = hop.index,
            mode = format!("{:?}", hop.mode).to_lowercase(),
            label = labels[idx],
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
    /// Hop's resolved `[server].name` (or hostname fallback). Used by
    /// the renderer for human-friendly labelling.
    #[serde(default)]
    name: Option<String>,
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
            name: h.name.clone(),
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
    let labels = hop_labels(report.hops.iter().map(|h| (h.name.as_deref(), &h.pubkey)));
    for (idx, hop) in report.hops.iter().enumerate() {
        let rtt = match hop.query_rtt_ms {
            Some(ms) => format!("{ms}ms"),
            None => "-".to_string(),
        };
        println!(
            "hop {hop_idx}  {label}  rtt={rtt}",
            hop_idx = hop.index,
            label = labels[idx],
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
// `chain canary` — probe a rule's L4 forwarding end-to-end
// =============================================================================

use ratatoskr::control::{CanaryStatus, ChainCanaryResponse, DerivedRulesResponse as DerivedRules};
use ratatoskr::rule::Protocol;

/// Exit code map matching the cli-reference docs.
const CANARY_EXIT_OK: i32 = 0;
const CANARY_EXIT_DEGRADED: i32 = 1;
const CANARY_EXIT_NO_SUCH_RULE: i32 = 2;
const CANARY_EXIT_CHAIN_DEAD: i32 = 3;

/// CLI-side default probe duration. Not exposed as a flag — the
/// daemon's classifier thresholds + the 5 s arming `--timeout` are
/// the two operator-tunable knobs.
const CANARY_PROBE_DURATION: Duration = Duration::from_secs(3);

async fn canary(socket: &Path, args: &CanaryArgs, json_output: bool) -> Result<()> {
    // 1. Resolve which rule(s) match the operator's `--port [--proto]`
    //    by pre-fetching the local rule snapshot. This catches the
    //    "no such rule" / "HTTPS dual-probe" / "ambiguous port"
    //    branches before hitting the daemon's full canary path.
    let derived = fetch_derived_rules(socket).await?;
    let matches = derived
        .derived_rules
        .iter()
        .filter(|r| r.listen.port() == args.port)
        .collect::<Vec<_>>();

    let probes: Vec<(std::net::SocketAddr, Protocol)> = if matches.is_empty() {
        // No match locally — let the daemon's NO_SUCH_RULE path
        // emit the close-match suggestions.
        let listen: std::net::SocketAddr = format!("0.0.0.0:{}", args.port).parse().unwrap();
        let proto = match args.proto {
            Some(ProtoArg::Tcp) => Protocol::Tcp,
            Some(ProtoArg::Udp) => Protocol::Udp,
            None => Protocol::Tcp, // arbitrary; the daemon won't find a match either way
        };
        vec![(listen, proto)]
    } else {
        select_probes_from_matches(&matches, args)?
    };

    let mut overall_exit = CANARY_EXIT_OK;
    let mut json_collected: Vec<ChainCanaryResponse> = Vec::with_capacity(probes.len());

    for (listen, proto) in probes {
        let req = Request::ChainCanary {
            rule_listen: listen,
            rule_protocol: proto,
            duration_ms: (CANARY_PROBE_DURATION.as_millis().min(u32::MAX as u128)) as u32,
            // `0` tells the daemon to use the protocol's documented
            // default rate / payload (see `control/handlers/canary.rs`).
            rate: 0,
            payload_bytes: 0,
            timeout_ms: Some((args.timeout.as_millis().min(u32::MAX as u128)) as u32),
        };
        let resp_timeout = args.timeout + CANARY_PROBE_DURATION + Duration::from_secs(5);
        let response = send_chain_request(socket, &req, resp_timeout).await?;
        let c = match response {
            Response::ChainCanary(c) => c,
            Response::Error { code, message } => {
                bail!("daemon returned Error({code}): {message}");
            }
            other => bail!("unexpected response: {other:?}"),
        };
        // Track worst-of outcomes across multiple probes (HTTPS
        // dual-probe path).
        let this_exit = match c.status {
            CanaryStatus::Ok => CANARY_EXIT_OK,
            CanaryStatus::Degraded => CANARY_EXIT_DEGRADED,
            CanaryStatus::NoSuchRule => CANARY_EXIT_NO_SUCH_RULE,
            CanaryStatus::ChainDead => CANARY_EXIT_CHAIN_DEAD,
        };
        if this_exit > overall_exit {
            overall_exit = this_exit;
        }
        if !json_output {
            render_canary_human(&c, proto, listen);
        }
        json_collected.push(c);
    }

    if json_output {
        // Emit one JSON object per probe as an array. For a single
        // probe consumers can `[0]`-index; for HTTPS dual-probe the
        // array carries both.
        let s = serde_json::to_string_pretty(&json_collected).context("serialise canary report")?;
        println!("{s}");
    }

    if overall_exit != CANARY_EXIT_OK {
        std::process::exit(overall_exit);
    }
    Ok(())
}

/// Choose which `(listen, proto)` probe(s) to send based on the local
/// rule snapshot. Encodes the HTTPS dual-probe rule (run both TCP and
/// UDP for an HTTPS rule) and the "ambiguous port, --proto required"
/// rule.
fn select_probes_from_matches(
    matches: &[&ratatoskr::rule::Rule],
    args: &CanaryArgs,
) -> Result<Vec<(std::net::SocketAddr, Protocol)>> {
    // Distinct (listen, protocol) tuples in the matched rules,
    // expanding HTTPS into its underlying TCP + UDP listeners.
    let mut tuples: Vec<(std::net::SocketAddr, Protocol)> = Vec::new();
    for r in matches {
        match r.protocol {
            Protocol::Tcp | Protocol::Udp => tuples.push((r.listen, r.protocol)),
            Protocol::Https => {
                tuples.push((r.listen, Protocol::Tcp));
                tuples.push((r.listen, Protocol::Udp));
            }
        }
    }
    tuples.sort_by_key(|(_, p)| match p {
        Protocol::Tcp => 0,
        Protocol::Udp => 1,
        Protocol::Https => 2,
    });
    tuples.dedup();

    let want_proto = args.proto.map(|p| match p {
        ProtoArg::Tcp => Protocol::Tcp,
        ProtoArg::Udp => Protocol::Udp,
    });

    let filtered: Vec<(std::net::SocketAddr, Protocol)> = match want_proto {
        Some(p) => tuples.iter().copied().filter(|(_, pp)| *pp == p).collect(),
        None => tuples,
    };

    if filtered.is_empty() {
        bail!(
            "no rule binds {}/{} on this node",
            args.port,
            args.proto
                .map(|p| match p {
                    ProtoArg::Tcp => "tcp",
                    ProtoArg::Udp => "udp",
                })
                .unwrap_or("?"),
        );
    }
    if want_proto.is_none() && filtered.len() > 1 {
        // Multiple transports on the same port that aren't paired
        // into a single HTTPS rule — operator must disambiguate.
        // Exception: an HTTPS rule produces (TCP, UDP) at the same
        // listen, and we want to run both. Detect that case by
        // checking if any matched rule is `Protocol::Https`.
        let has_https = matches.iter().any(|r| r.protocol == Protocol::Https);
        if !has_https {
            bail!(
                "port {} has multiple transports bound; pass --proto tcp or --proto udp",
                args.port,
            );
        }
    }
    Ok(filtered)
}

async fn fetch_derived_rules(socket: &Path) -> Result<DerivedRules> {
    let response =
        send_chain_request(socket, &Request::DerivedRules, DEFAULT_CLIENT_TIMEOUT_SECS).await?;
    match response {
        Response::DerivedRules(d) => Ok(d),
        other => bail!("expected DerivedRules response, got {other:?}"),
    }
}

async fn ensure_terminal_mode(socket: &Path) -> Result<()> {
    let response =
        send_chain_request(socket, &Request::Status, DEFAULT_CLIENT_TIMEOUT_SECS).await?;
    let mode = match response {
        Response::Status(status) => status.mode,
        Response::Error { code, message } => {
            bail!("status query failed before mode check: {code}: {message}");
        }
        other => bail!("expected Status response before mode check, got {other:?}"),
    };
    if mode != Mode::Terminal {
        bail!(
            "this command requires a terminal-mode daemon; target at {} is a {}",
            socket.display(),
            mode.as_str(),
        );
    }
    Ok(())
}

const DEFAULT_CLIENT_TIMEOUT_SECS: Duration = Duration::from_secs(5);

/// Generic UDS round-trip helper. Sends `req` as one JSON line, reads
/// one JSON line back, deserialises into `Response`.
async fn send_chain_request(socket: &Path, req: &Request, timeout: Duration) -> Result<Response> {
    let socket_path: PathBuf = socket.to_path_buf();
    let stream = tokio::time::timeout(timeout, UnixStream::connect(&socket_path))
        .await
        .with_context(|| format!("UDS connect timeout to {}", socket_path.display()))?
        .with_context(|| format!("connecting to {}", socket_path.display()))?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let mut buf = serde_json::to_vec(req).context("encode request")?;
    buf.push(b'\n');
    tokio::time::timeout(timeout, writer.write_all(&buf))
        .await
        .context("write timeout sending request")?
        .context("writing request")?;

    let mut line = String::new();
    let n = tokio::time::timeout(timeout, reader.read_line(&mut line))
        .await
        .context("read timeout awaiting response")?
        .context("reading response")?;
    if n == 0 {
        bail!("daemon closed UDS without responding");
    }
    serde_json::from_str(&line).context("parse response")
}

fn render_canary_human(c: &ChainCanaryResponse, proto: Protocol, listen: std::net::SocketAddr) {
    let proto_str = match proto {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Https => "https",
    };

    match c.status {
        CanaryStatus::NoSuchRule => {
            println!(
                "no rule binds {}/{} on this node.\n",
                listen.port(),
                proto_str,
            );
            if c.close_matches.is_empty() {
                println!("no close matches.");
            } else {
                println!("closest matches:");
                for m in &c.close_matches {
                    let p = match m.protocol {
                        Protocol::Tcp => "tcp",
                        Protocol::Udp => "udp",
                        Protocol::Https => "https",
                    };
                    println!(
                        "  {port:<5} /{p:<5}  rule {name:?}  on {bind}",
                        port = m.listen.port(),
                        name = m.rule_name,
                        bind = m.listen.ip(),
                    );
                }
            }
            println!("\nresult: NO_SUCH_RULE");
        }
        CanaryStatus::ChainDead => {
            print_chain_header(c, proto_str, listen);
            println!();
            println!("setup phase:");
            for (idx, hop) in c.chain.iter().enumerate() {
                let label = hop_label_for(hop);
                let prev = if idx == 0 {
                    "(self)".to_string()
                } else {
                    hop_label_for(&c.chain[idx - 1])
                };
                let detail = if let Some(rtt_ms) = hop.query_rtt_ms {
                    format!("OK ({rtt_ms} ms)")
                } else {
                    "OK".to_string()
                };
                println!("  {prev:>20} → {label:<20}  {detail}");
            }
            if c.partial {
                println!();
                println!("chain truncated; last reachable hop above. The next hop along");
                println!("the chain did not respond within the arming timeout.");
            }
            println!();
            println!("result: CHAIN_DEAD");
        }
        CanaryStatus::Ok | CanaryStatus::Degraded => {
            print_chain_header(c, proto_str, listen);
            if let Some(p) = c.probe_results.as_ref() {
                println!();
                render_probe_table(p, proto);
            }
            println!();
            println!(
                "result: {}",
                match c.status {
                    CanaryStatus::Ok => "OK",
                    CanaryStatus::Degraded => "DEGRADED",
                    _ => unreachable!(),
                }
            );
        }
    }
}

fn print_chain_header(c: &ChainCanaryResponse, proto_str: &str, listen: std::net::SocketAddr) {
    let rule = c.rule_name.as_deref().unwrap_or("?");
    println!(
        "rule:   {rule}  ({proto_str}, listen {bind}:{port})",
        bind = listen.ip(),
        port = listen.port(),
    );
    let chain_line = c
        .chain
        .iter()
        .enumerate()
        .map(|(idx, hop)| {
            let label = hop_label_for(hop);
            if idx == 0 {
                format!("{label} (self)")
            } else {
                label
            }
        })
        .collect::<Vec<_>>()
        .join(" → ");
    println!("chain:  {chain_line}");
}

fn render_probe_table(p: &ProbeResultsAlias, proto: Protocol) {
    let proto_str = match proto {
        Protocol::Tcp => "TCP byte-stream",
        Protocol::Udp => "UDP datagrams",
        Protocol::Https => "HTTPS",
    };
    let duration_ms = p.duration_micros / 1_000;
    println!("probe:  duration {duration_ms} ms, {proto_str}");
    println!();
    println!("{:<18}  {:>12}  {:>10}", "direction", "throughput", "loss",);
    let rows = [
        ("client → server", &p.c_to_s),
        ("server → client", &p.s_to_c),
    ];
    for (name, d) in rows {
        let loss = if d.sent == 0 {
            0.0
        } else {
            1.0 - (d.received as f64 / d.sent as f64).min(1.0)
        };
        let mbps = (d.throughput_bps as f64) / 1_000_000.0;
        println!("{:<18}  {:>10.2} Mbps  {:>7.2} %", name, mbps, loss * 100.0,);
    }
    println!();
    println!(
        "round-trip latency  p50 {} µs   p99 {} µs",
        p.round_trip_p50_micros, p.round_trip_p99_micros,
    );
    if let Some(rtt) = p.connection_rtt_micros {
        println!("connection establish: {rtt} µs");
    }
}

// Alias so the function signature reads naturally without re-importing
// the full path.
use ratatoskr::control::ProbeResults as ProbeResultsAlias;

/// Hop label resolution mirroring [`hop_labels`] but for one
/// `CanaryHop` — `name` when set, short pubkey otherwise.
fn hop_label_for(hop: &ratatoskr::canary::CanaryHop) -> String {
    match hop.name.as_deref().filter(|s| !s.is_empty()) {
        Some(n) => n.to_string(),
        None => short_pubkey(&hop.pubkey),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatoskr::control::{ChainIdentity as ChainView, StatusResponse};
    use ratatoskr::rule::Protocol;
    use tokio::net::UnixListener;

    fn status_response(mode: Mode) -> Response {
        Response::Status(StatusResponse {
            version: "test".into(),
            mode,
            downstream_ip: None,
            last_heartbeat_age_ms: None,
            rule_count: 0,
            uptime_secs: 0,
            downstream_enrolled: false,
            default_cert_path: None,
            default_cert_loaded_age_secs: None,
            ephemeral_cert_count: 0,
            nat: None,
            lan_cidrs: Vec::new(),
            lan_cidrs_source: "default".into(),
            certless_route_count: 0,
        })
    }

    async fn collect_requests_until_idle(
        listener: UnixListener,
        response: Response,
    ) -> Vec<Request> {
        let mut seen = Vec::new();
        for accept_index in 0..2 {
            let accepted = if accept_index == 0 {
                tokio::time::timeout(Duration::from_secs(1), listener.accept())
                    .await
                    .expect("client did not connect")
                    .expect("accept failed")
            } else {
                match tokio::time::timeout(Duration::from_millis(250), listener.accept()).await {
                    Ok(Ok(pair)) => pair,
                    Ok(Err(e)) => panic!("accept failed: {e}"),
                    Err(_) => break,
                }
            };
            let (stream, _) = accepted;
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            seen.push(serde_json::from_str(line.trim()).unwrap());
            let mut buf = serde_json::to_vec(&response).unwrap();
            buf.push(b'\n');
            writer.write_all(&buf).await.unwrap();
        }
        seen
    }

    fn pk(seed: u8) -> PubKey {
        PubKey::x25519([seed; 32])
    }

    #[tokio::test]
    async fn chain_apply_refuses_gateway_before_dispatch() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("control.sock");
        let rules_file = tmp.path().join("rules.toml");
        std::fs::write(
            &rules_file,
            r#"[[rule]]
name = "ssh"
listen = "127.0.0.1:2222"
protocol = "tcp"
target = "127.0.0.1:22"
"#,
        )
        .unwrap();

        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(collect_requests_until_idle(
            listener,
            status_response(Mode::Gateway),
        ));

        let err = run(Cmd::Apply(ApplyArgs { file: rules_file }), &socket, false)
            .await
            .expect_err("gateway-mode daemon should be rejected client-side");
        let message = err.to_string();
        assert!(
            message.contains("requires a terminal-mode daemon"),
            "unexpected error: {message}"
        );
        assert!(message.contains("gateway"), "unexpected error: {message}");
        assert!(
            message.contains(&socket.display().to_string()),
            "unexpected error: {message}"
        );

        let seen = server.await.unwrap();
        assert_eq!(seen, vec![Request::Status]);
    }

    // ---- hop_labels ----

    #[test]
    fn hop_labels_prefer_name_when_set() {
        let k1 = pk(1);
        let k2 = pk(2);
        let labels = hop_labels([(Some("vps"), &k1), (Some("home"), &k2)]);
        assert_eq!(labels, vec!["vps".to_string(), "home".to_string()]);
    }

    #[test]
    fn hop_labels_fall_back_to_short_pubkey_when_unset() {
        let k = pk(0x7f);
        let labels = hop_labels([(None, &k)]);
        assert_eq!(labels.len(), 1);
        assert!(
            labels[0].starts_with("x25519:"),
            "expected short pubkey, got {:?}",
            labels[0]
        );
        assert_eq!(
            labels[0].len(),
            "x25519:".len() + HOP_LABEL_PUBKEY_PREFIX_HEX
        );
    }

    #[test]
    fn hop_labels_treat_empty_string_as_unset() {
        let k = pk(1);
        let labels = hop_labels([(Some(""), &k)]);
        assert!(labels[0].starts_with("x25519:"));
    }

    #[test]
    fn hop_labels_disambiguate_collisions_with_short_pubkey_suffix() {
        let k1 = pk(0x11);
        let k2 = pk(0x22);
        let labels = hop_labels([(Some("vps"), &k1), (Some("vps"), &k2)]);
        assert_eq!(labels.len(), 2);
        assert!(labels[0].starts_with("vps ("), "got {:?}", labels[0]);
        assert!(labels[0].ends_with(')'));
        assert!(labels[1].starts_with("vps ("), "got {:?}", labels[1]);
        assert_ne!(
            labels[0], labels[1],
            "colliding labels must still be distinguishable"
        );
    }

    #[test]
    fn hop_labels_no_disambiguation_when_only_one_hop_holds_a_given_name() {
        let k1 = pk(1);
        let k2 = pk(2);
        let labels = hop_labels([(Some("vps"), &k1), (Some("home"), &k2)]);
        assert_eq!(labels, vec!["vps".to_string(), "home".to_string()]);
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
    ) -> IntrospectionView {
        IntrospectionView {
            predicates,
            derived_rules: Vec::new(),
            chain: ChainView {
                local,
                upstream,
                downstream: None,
                predicate_origin: origin,
                last_apply_unix: None,
            },
        }
    }

    #[test]
    fn diff_in_sync_when_predicates_origins_all_match() {
        let preds = vec![
            pred("a", 1000, Protocol::Tcp),
            pred("b", 1001, Protocol::Udp),
        ];
        let local = view(preds.clone(), pk(1), Some(pk(2)), Some(pk(1)));
        let upstream = view(preds, pk(2), None, Some(pk(1)));
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
        let local = view(local_preds, pk(1), Some(pk(2)), Some(pk(1)));
        let upstream = view(upstream_preds, pk(2), None, Some(pk(1)));
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
        let local = view(local_preds, pk(1), Some(pk(2)), Some(pk(1)));
        let upstream = view(upstream_preds, pk(2), None, Some(pk(1)));
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
        );
        let upstream = view(
            vec![pred("a", 1001, Protocol::Tcp)],
            pk(2),
            None,
            Some(pk(1)),
        );
        let d = compute_diff(&local, &upstream).expect("comparable");
        assert!(!d.is_in_sync());
        assert_eq!(d.changed.len(), 1);
        assert_eq!(d.changed[0].name, "a");
        assert_eq!(d.changed[0].local.listen_port, 1000);
        assert_eq!(d.changed[0].upstream.listen_port, 1001);
    }

    #[test]
    fn diff_returns_none_when_no_predicates_on_either_side() {
        let local = view(Vec::new(), pk(1), Some(pk(2)), None);
        let upstream = view(Vec::new(), pk(2), None, None);
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
        );
        let upstream = view(
            vec![pred("b", 2000, Protocol::Tcp)],
            pk(2),
            None,
            Some(pk(99)), // different terminal authored this set
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
                "last_apply_unix": 1737244800,
            }
        });
        let v: IntrospectionView = serde_json::from_value(raw).expect("deserialise");
        assert_eq!(v.predicates.len(), 2);
        assert_eq!(v.predicates[0].name, "alpha");
        assert_eq!(v.predicates[1].idle_timeout_ms, Some(60_000));
        assert_eq!(v.chain.local, pk(1));
        assert_eq!(v.chain.upstream, Some(pk(2)));
        assert_eq!(v.chain.last_apply_unix, Some(1737244800));
    }

    // ---------- chain health classification ----------

    fn hop(uptime_secs: u64, last_apply_unix: Option<i64>) -> ratatoskr::control::ChainHop {
        ratatoskr::control::ChainHop {
            hop_index: 0,
            mode: ratatoskr::control::Mode::Terminal,
            uptime_secs,
            name: None,
            query_rtt_ms: None,
            view: view(Vec::new(), pk(1), None, None).pipe(|mut v| {
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
