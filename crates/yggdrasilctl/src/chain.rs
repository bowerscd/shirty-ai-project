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

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use ratatoskr::control::{Request, Response};
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

pub async fn run(cmd: Cmd, socket: &Path, _json: bool) -> Result<()> {
    match cmd {
        Cmd::Tunnel {
            action: TunnelAction::Open(args),
        } => open_tunnel(socket, &args).await,
        Cmd::Apply(args) => apply(socket, &args).await,
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
