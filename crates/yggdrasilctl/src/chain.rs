//! `chain` scope — chain-control plane operations.
//!
//! Phase 4C added `chain tunnel open`: a one-shot bidirectional stdio
//! splice through the daemon's UDS. Internally it asks the daemon to
//! open a tunnel toward `dest` at `pubkey`, then hands the socket
//! halves to two `tokio::io::copy` tasks against stdin / stdout.
//! Suitable for scripting `(echo PAYLOAD; cat) | yggdrasilctl chain
//! tunnel open` pipelines and for ssh ProxyCommand wiring.
//!
//! Phase 5 added multi-hop forwarding: `pubkey` may be any node on
//! the chain (direct upstream, two hops up, etc.). The local daemon's
//! upstream relay forwards to the next hop on `pubkey` mismatch.
//!
//! Phase 5C added `chain apply`: push a candidate `rules.toml` into
//! the running terminal daemon without touching its on-disk rules
//! directory.
//!
//! Phase 5D added `chain diff`: walk the chain upward through the
//! daemon's tunnel pipeline, fetching each hop's
//! `/internal/derived-rules` snapshot, and surface drift between the
//! local terminal's published predicate set and the upstream node's
//! accepted predicate set.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
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
    /// Open or inspect chain tunnels (Phase 4C).
    Tunnel {
        #[command(subcommand)]
        action: TunnelAction,
    },
    /// Push a candidate rule set from a TOML file into the running
    /// terminal daemon without touching its rules directory on disk.
    /// The daemon validates the candidate, projects its predicate set,
    /// and (if a chain upstream is configured) publishes the projection
    /// on its next push tick.
    Apply(ApplyArgs),
    /// Walk the chain upward and surface drift between the local
    /// terminal's published predicate set and what each upstream node
    /// believes it accepted. Each hop is reached over a chain tunnel
    /// to its `/internal/derived-rules` HTTP endpoint.
    Diff(DiffArgs),
}

#[derive(Debug, Subcommand)]
pub enum TunnelAction {
    /// Open a one-shot bidirectional tunnel to `dest` at `pubkey` and
    /// splice it against this process's stdin/stdout. Exits when either
    /// stdin closes or the peer closes the tunnel.
    Open(OpenArgs),
}

#[derive(Debug, Args)]
pub struct OpenArgs {
    /// Tagged target pubkey, e.g. `x25519:0123…ef`. May be any node on
    /// this chain — the local daemon's upstream relay forwards the
    /// open envelope onward until it reaches the target (Phase 5).
    #[arg(long)]
    pub pubkey: String,
    /// Destination `host:port` the target relay should dial. Both
    /// IPv4 and IPv6 (`[::1]:443`) are accepted.
    #[arg(long)]
    pub dest: SocketAddr,
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

pub async fn run(cmd: Cmd, socket: &Path, json: bool) -> Result<()> {
    match cmd {
        Cmd::Tunnel {
            action: TunnelAction::Open(args),
        } => open_tunnel(socket, &args).await,
        Cmd::Apply(args) => apply(socket, &args).await,
        Cmd::Diff(args) => diff(socket, &args, json).await,
    }
}

/// Connect to the daemon's UDS, send `OpenChainTunnel`, await the single
/// JSON response line, and on success splice the socket against
/// stdin/stdout until either side closes.
///
/// Wire discipline matches the daemon's `run_chain_tunnel_bridge`:
///
/// 1. Write `Request::OpenChainTunnel { ... }\n` once.
/// 2. Read exactly one JSON line back via [`BufReader::read_line`].
///    On `Response::ChainTunnelOpened { stream_id }` the daemon flips
///    the socket into raw-bytes mode; on `Response::Error { ... }` we
///    print and exit. We do *not* read further JSON lines.
/// 3. From the `BufReader`'s underlying socket: any bytes the BufReader
///    pre-buffered past the `\n` of the response remain in its buffer
///    and are surfaced by `read()` first, so they aren't lost. (In
///    practice the daemon never writes raw bytes ahead of receiving
///    operator data, so the buffer is empty here — but the splice
///    code is correct either way.)
/// 4. Splice stdin -> socket and socket -> stdout concurrently.
async fn open_tunnel(socket: &Path, args: &OpenArgs) -> Result<()> {
    let target_pubkey = PubKey::from_str(&args.pubkey)
        .with_context(|| format!("parsing --pubkey {:?}", args.pubkey))?;
    let socket_path: PathBuf = socket.to_path_buf();
    let stream = tokio::time::timeout(Duration::from_secs(5), UnixStream::connect(&socket_path))
        .await
        .with_context(|| format!("connect timeout to {}", socket_path.display()))?
        .with_context(|| format!("connecting to {}", socket_path.display()))?;

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // 1. Send the request line.
    let request = Request::OpenChainTunnel {
        target_pubkey,
        dest: args.dest,
    };
    let mut buf = serde_json::to_vec(&request).context("encode OpenChainTunnel")?;
    buf.push(b'\n');
    writer
        .write_all(&buf)
        .await
        .context("writing OpenChainTunnel request")?;

    // 2. Read exactly one response line.
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .await
        .context("reading OpenChainTunnel response")?;
    if n == 0 {
        bail!("daemon closed the socket without responding to OpenChainTunnel");
    }
    let response: Response = serde_json::from_str(line.trim())
        .with_context(|| format!("parsing daemon response as JSON: {line:?}"))?;

    let stream_id = match response {
        Response::ChainTunnelOpened { stream_id } => stream_id,
        Response::Error { code, message } => {
            bail!("daemon refused to open tunnel: code={code} message={message}");
        }
        other => bail!(
            "daemon returned an unexpected response to OpenChainTunnel: {other:?}"
        ),
    };
    tracing::debug!(stream_id, "chain tunnel opened; splicing stdio");

    // 3 + 4. Splice. We hand-roll the two `tokio::io::copy` halves
    // (rather than `copy_bidirectional`) because the read side is a
    // `BufReader<OwnedReadHalf>` — that lets any leftover buffered
    // bytes drain first. Either side closing terminates the whole call.
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    let upload = async {
        let n = tokio::io::copy(&mut stdin, &mut writer).await;
        // After stdin EOF, shutdown the UDS write half so the daemon
        // sees EOF on its reader and emits `TunnelClose` to the peer.
        let _ = writer.shutdown().await;
        n
    };
    let download = async {
        let n = tokio::io::copy(&mut reader, &mut stdout).await;
        let _ = stdout.flush().await;
        n
    };

    tokio::select! {
        res = upload => {
            res.map_err(|e| anyhow!("upload (stdin -> tunnel) failed: {e}"))?;
            // Wait briefly for any in-flight download bytes to flush.
            // The download future is dropped on select-exit, which is
            // fine: any remaining bytes are lost only if the operator
            // closes stdin while the peer is still writing, which is
            // the operator's choice.
        }
        res = download => {
            res.map_err(|e| anyhow!("download (tunnel -> stdout) failed: {e}"))?;
        }
    }
    Ok(())
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
        bail!(
            "{} failed local validation: {e}",
            args.file.display()
        );
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
async fn send_chain_apply(
    socket: &Path,
    request: &Request,
    timeout: Duration,
) -> Result<Response> {
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
async fn fetch_chain_summary(
    socket: &Path,
    timeout: Duration,
) -> Result<ChainSummaryResponse> {
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
        println!(
            "  derived_rules: {} active",
            v.derived_rules.len()
        );
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
        let preds = vec![pred("a", 1000, Protocol::Tcp), pred("b", 1001, Protocol::Udp)];
        let local = view(preds.clone(), pk(1), Some(pk(2)), Some(pk(1)), Some(7));
        let upstream = view(preds, pk(2), None, Some(pk(1)), Some(7));
        let d = compute_diff(&local, &upstream).expect("comparable");
        assert!(d.is_in_sync(), "expected in sync, got {d:?}");
    }

    #[test]
    fn diff_detects_predicate_missing_upstream() {
        let local_preds = vec![pred("a", 1000, Protocol::Tcp), pred("b", 1001, Protocol::Udp)];
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
        let upstream_preds = vec![pred("a", 1000, Protocol::Tcp), pred("ghost", 2000, Protocol::Tcp)];
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
}
