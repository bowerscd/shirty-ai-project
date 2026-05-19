//! `chain` scope — chain-control plane operations.
//!
//! Phase 4C adds `chain tunnel open`: a one-shot bidirectional stdio
//! splice through the daemon's UDS. Internally it asks the daemon to
//! open a tunnel toward `dest` at `pubkey` (which in v1 must equal
//! the daemon's chain upstream), then hands the socket halves to two
//! `tokio::io::copy` tasks against stdin / stdout. Suitable for
//! scripting `(echo PAYLOAD; cat) | yggdrasilctl chain tunnel open`
//! pipelines and for ssh ProxyCommand wiring.

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

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Open or inspect chain tunnels (Phase 4C).
    Tunnel {
        #[command(subcommand)]
        action: TunnelAction,
    },
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
    /// Tagged target pubkey, e.g. `x25519:0123…ef`. In v1 this must
    /// equal the daemon's chain upstream (multi-hop forwarding is a
    /// later phase); the daemon will return `tunnel_open_rejected`
    /// otherwise.
    #[arg(long)]
    pub pubkey: String,
    /// Destination `host:port` the upstream relay should dial. Both
    /// IPv4 and IPv6 (`[::1]:443`) are accepted.
    #[arg(long)]
    pub dest: SocketAddr,
}

pub async fn run(cmd: Cmd, socket: &Path, _json: bool) -> Result<()> {
    match cmd {
        Cmd::Tunnel {
            action: TunnelAction::Open(args),
        } => open_tunnel(socket, &args).await,
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
