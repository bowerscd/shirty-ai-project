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
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};

use ratatoskr::control::{Request, Response};
use ratatoskr::predicate::Predicate;
use ratatoskr::pubkey::PubKey;
use ratatoskr::rule::{Rule, RuleFile, RuleSet};

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
    /// TCP port on each node's loopback that exposes the metrics
    /// listener (the `[metrics] listen` setting in `config.toml`). The
    /// local node is queried directly on this port; upstream nodes are
    /// reached through chain tunnels with the same port assumed on
    /// each hop's loopback.
    #[arg(long, value_name = "PORT", default_value_t = 9090)]
    pub metrics_port: u16,
    /// Maximum number of upstream hops to walk before stopping. Each
    /// hop's `/internal/derived-rules` reveals the next hop via its
    /// `chain.upstream` pubkey. A chain deeper than the default of 8
    /// is unusual; tune up only if you've explicitly designed one.
    #[arg(long, value_name = "N", default_value_t = 8)]
    pub max_hops: usize,
    /// Per-fetch deadline. Applies to each individual hop's HTTP GET
    /// (over TCP for the local hop, over a chain tunnel for upstream
    /// hops). The overall walk time is bounded by `max_hops *
    /// per_hop_timeout`.
    #[arg(long, value_name = "DURATION", value_parser = humantime::parse_duration, default_value = "5s")]
    pub per_hop_timeout: Duration,
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

/// CLI-side mirror of [`yggdrasil::chain::introspection::IntrospectionSnapshot`].
/// The daemon serialises via `IntrospectionSnapshot`; we deserialise into
/// this shape. Field names + JSON shape must stay in lock-step with the
/// daemon side — `tests/chain_introspection_e2e.rs` exercises the
/// daemon's emit, and `introspection_view_round_trips_through_serde`
/// below exercises this deserialise.
///
/// We keep the mirror local (rather than importing
/// `yggdrasil::chain::introspection`) because `yggdrasilctl` deliberately
/// does not depend on `yggdrasil` — the daemon crate is large and
/// pulling it in would balloon the CLI binary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct IntrospectionView {
    /// Predicates the hop is currently driven by. On a terminal these
    /// are the *projection* of `derived_rules`; on a relay these are
    /// the set last *received and accepted* from its downstream.
    predicates: Vec<Predicate>,
    /// The hop's currently-active rule set, as the proxy supervisor
    /// reports it. Mostly informational in the diff; the comparison is
    /// driven by `predicates`.
    derived_rules: Vec<Rule>,
    chain: ChainView,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ChainView {
    /// This hop's own static x25519 pubkey. Used to detect mis-routing
    /// (the tunnel forwarder should have delivered us to the pubkey we
    /// requested).
    local: PubKey,
    /// Next hop upward, if any. The walker uses this to decide whether
    /// to continue past this hop.
    upstream: Option<PubKey>,
    /// Hop's downstream pubkey (purely informational at this layer).
    downstream: Option<PubKey>,
    /// Pubkey of the terminal that authored the predicates currently
    /// driving this hop. When `predicate_origin == previous_hop.local`,
    /// it confirms the predicate set arrived from the hop we expect.
    predicate_origin: Option<PubKey>,
    /// Monotonic predicate-set version recorded on the last apply.
    predicate_version: Option<u64>,
    /// Wall-clock seconds since UNIX epoch at the last apply. Lets the
    /// operator tell whether an upstream is *stale* or *was never
    /// pushed*.
    last_apply_unix: Option<i64>,
}

/// A single hop's contribution to the report. Hop 0 is the local node;
/// hops 1..N are reached over chain tunnels.
#[derive(Debug, Clone, Serialize)]
struct HopReport {
    /// 0 for the local hop, 1 for its immediate upstream, etc.
    index: usize,
    /// Pubkey we *expected* at this hop — the previous hop's
    /// `chain.upstream`. For hop 0 this is the local node's own
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
}

/// Walk the chain upward from the local node, fetch each hop's
/// `/internal/derived-rules`, and emit a structured diff. See module
/// docstring for the operator-facing semantics.
///
/// The walk:
/// 1. Fetches hop 0 (local) over `127.0.0.1:metrics_port`.
/// 2. For each `chain.upstream` it finds, opens a chain tunnel via
///    the daemon's UDS and fetches that hop's `/internal/derived-rules`
///    through the tunnel.
/// 3. Bounds total work at `args.max_hops` to keep a misconfigured
///    chain (or a forwarding loop) from running forever.
async fn diff(socket: &Path, args: &DiffArgs, json_output: bool) -> Result<()> {
    let local_addr: SocketAddr = format!("127.0.0.1:{}", args.metrics_port)
        .parse()
        .with_context(|| format!("constructing local metrics addr for port {}", args.metrics_port))?;

    let local_view = fetch_local_introspection(local_addr, args.per_hop_timeout)
        .await
        .with_context(|| {
            format!(
                "fetching local /internal/derived-rules from {local_addr}"
            )
        })?;

    let mut hops: Vec<HopReport> = Vec::new();
    let local_pubkey = local_view.chain.local;
    let mut next_upstream = local_view.chain.upstream;
    let mut previous = local_view.clone();
    hops.push(HopReport {
        index: 0,
        expected_pubkey: local_pubkey,
        view: local_view,
        drift: None,
    });

    let mut hop_index = 1usize;
    while let Some(target) = next_upstream {
        if hop_index > args.max_hops {
            tracing::warn!(
                max_hops = args.max_hops,
                "chain diff walk stopped at max-hops; chain may continue further"
            );
            break;
        }
        let hop_view = fetch_upstream_introspection(
            socket,
            target,
            args.metrics_port,
            args.per_hop_timeout,
        )
        .await
        .with_context(|| {
            format!("fetching hop {hop_index} (target {target}) /internal/derived-rules through chain tunnel")
        })?;

        if hop_view.chain.local != target {
            bail!(
                "hop {hop_index} routing mismatch: tunnel reached pubkey {actual}, expected {target}",
                actual = hop_view.chain.local,
                target = target
            );
        }

        let drift = compute_diff(&previous, &hop_view);
        next_upstream = hop_view.chain.upstream;
        previous = hop_view.clone();
        hops.push(HopReport {
            index: hop_index,
            expected_pubkey: target,
            view: hop_view,
            drift,
        });
        hop_index += 1;
    }

    let drift_detected = hops
        .iter()
        .any(|h| h.drift.as_ref().is_some_and(|d| !d.is_in_sync()));
    let report = DiffReport {
        hops,
        drift_detected,
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
}

/// Fetch the local node's `/internal/derived-rules` snapshot via a
/// direct TCP connection to its metrics listener. The endpoint is
/// loopback-gated on the daemon side; this path is the only one that
/// works without involving a chain tunnel.
async fn fetch_local_introspection(
    addr: SocketAddr,
    timeout: Duration,
) -> Result<IntrospectionView> {
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .with_context(|| format!("connect timeout to {addr}"))?
        .with_context(|| format!("connecting to {addr}"))?;
    let raw = tokio::time::timeout(
        timeout,
        http_get_collect(&mut stream, "127.0.0.1", "/internal/derived-rules"),
    )
    .await
    .context("HTTP GET timed out")??;
    parse_introspection_response(&raw)
}

/// Fetch an upstream hop's `/internal/derived-rules` over a chain
/// tunnel via the local daemon's UDS. The tunnel terminates at the
/// upstream hop's loopback and dials `127.0.0.1:metrics_port` from
/// there, so the metrics listener sees a 127.0.0.1 peer and passes
/// the loopback gate.
async fn fetch_upstream_introspection(
    socket: &Path,
    target_pubkey: PubKey,
    metrics_port: u16,
    timeout: Duration,
) -> Result<IntrospectionView> {
    let socket_path: PathBuf = socket.to_path_buf();
    let dest: SocketAddr = format!("127.0.0.1:{metrics_port}")
        .parse()
        .with_context(|| format!("constructing dest addr for port {metrics_port}"))?;

    let stream = tokio::time::timeout(timeout, UnixStream::connect(&socket_path))
        .await
        .with_context(|| format!("UDS connect timeout to {}", socket_path.display()))?
        .with_context(|| format!("connecting to {}", socket_path.display()))?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // 1. Send OpenChainTunnel.
    let request = Request::OpenChainTunnel {
        target_pubkey,
        dest,
    };
    let mut buf = serde_json::to_vec(&request).context("encode OpenChainTunnel")?;
    buf.push(b'\n');
    tokio::time::timeout(timeout, writer.write_all(&buf))
        .await
        .context("write timeout sending OpenChainTunnel")?
        .context("writing OpenChainTunnel request")?;

    // 2. Read exactly one JSON response line.
    let mut line = String::new();
    let n = tokio::time::timeout(timeout, reader.read_line(&mut line))
        .await
        .context("read timeout awaiting OpenChainTunnel response")?
        .context("reading OpenChainTunnel response")?;
    if n == 0 {
        bail!("daemon closed UDS without responding to OpenChainTunnel");
    }
    let response: Response = serde_json::from_str(line.trim())
        .with_context(|| format!("parsing daemon response: {line:?}"))?;
    match response {
        Response::ChainTunnelOpened { .. } => {}
        Response::Error { code, message } => {
            bail!("daemon refused tunnel to {target_pubkey}: code={code} message={message}");
        }
        other => bail!(
            "daemon returned unexpected response to OpenChainTunnel: {other:?}"
        ),
    }
    // 3. The socket is now in raw-bytes mode. Splice an HTTP GET
    //    through it. `reader` may hold buffered bytes past the JSON
    //    response's `\n`; the BufReader will surface them first on
    //    subsequent reads, which is correct.
    let raw = tokio::time::timeout(
        timeout,
        http_get_through_split(&mut reader, &mut writer, "127.0.0.1", "/internal/derived-rules"),
    )
    .await
    .context("HTTP GET through chain tunnel timed out")??;
    parse_introspection_response(&raw)
}

/// Write an HTTP/1.1 GET to `stream` and read until EOF. Returns the
/// raw response bytes. Caller is responsible for parsing.
async fn http_get_collect(
    stream: &mut TcpStream,
    host: &str,
    path: &str,
) -> Result<Vec<u8>> {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .await
        .context("writing HTTP GET request")?;
    let mut buf = Vec::with_capacity(8192);
    stream
        .read_to_end(&mut buf)
        .await
        .context("reading HTTP response")?;
    Ok(buf)
}

/// Same as [`http_get_collect`] but for a tunnel stream whose halves
/// have been split. Used by [`fetch_upstream_introspection`] because
/// the read half is wrapped in a `BufReader` for the prior
/// `read_line`.
async fn http_get_through_split<R, W>(
    reader: &mut R,
    writer: &mut W,
    host: &str,
    path: &str,
) -> Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );
    writer
        .write_all(req.as_bytes())
        .await
        .context("writing HTTP GET through tunnel")?;
    // Send EOF to the tunnel's write half so the terminator-side dial
    // proxy closes its end and the server emits Connection: close +
    // EOF on read. Without this the read below would block forever
    // waiting for the server to close.
    writer
        .shutdown()
        .await
        .context("shutting down tunnel write half after GET")?;
    let mut buf = Vec::with_capacity(8192);
    reader
        .read_to_end(&mut buf)
        .await
        .context("reading HTTP response through tunnel")?;
    Ok(buf)
}

/// Parse a raw HTTP/1.1 response. Expects status 200; otherwise
/// surfaces the status line in the error so the operator can debug.
fn parse_introspection_response(raw: &[u8]) -> Result<IntrospectionView> {
    let text = std::str::from_utf8(raw)
        .context("HTTP response was not valid UTF-8")?;
    let status_end = text
        .find("\r\n")
        .ok_or_else(|| anyhow!("HTTP response missing CRLF after status line"))?;
    let status_line = &text[..status_end];
    if !status_line.starts_with("HTTP/1.1 200") && !status_line.starts_with("HTTP/1.0 200") {
        bail!(
            "/internal/derived-rules returned non-200 status: {status_line:?}\n\
             (404 means the daemon was built without chain introspection; \
             403 means the connection didn't appear loopback to the listener; \
             5xx means a daemon-side error)"
        );
    }
    let body_start = text
        .find("\r\n\r\n")
        .ok_or_else(|| anyhow!("HTTP response missing CRLF/CRLF body separator"))?
        + 4;
    let body = &text[body_start..];
    serde_json::from_str::<IntrospectionView>(body)
        .with_context(|| format!("parsing /internal/derived-rules body as JSON: {body:.256}"))
}

// =============================================================================
// Tests — diff comparison + serde round-trip
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn parse_introspection_response_rejects_non_200() {
        let raw = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        let err = parse_introspection_response(raw).unwrap_err();
        assert!(
            err.to_string().contains("403"),
            "error should mention 403, got: {err}"
        );
    }

    #[test]
    fn parse_introspection_response_parses_well_formed_200() {
        let body = serde_json::json!({
            "predicates": [],
            "derived_rules": [],
            "chain": {
                "local": "x25519:0101010101010101010101010101010101010101010101010101010101010101",
                "upstream": null,
                "downstream": null,
                "predicate_origin": null,
                "predicate_version": null,
                "last_apply_unix": null,
            }
        })
        .to_string();
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let v = parse_introspection_response(raw.as_bytes()).expect("200 should parse");
        assert_eq!(v.chain.local, pk(1));
        assert!(v.predicates.is_empty());
    }
}
