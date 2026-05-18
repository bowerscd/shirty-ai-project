//! yggdrasilctl — admin CLI for yggdrasil over a Unix domain socket.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use yggdrasil_proto::control::{Request, Response};

#[derive(Debug, Parser)]
#[command(name = "yggdrasilctl", version, about, propagate_version = true)]
struct Cli {
    /// Path to the yggdrasil control socket.
    #[arg(long, default_value = "/run/yggdrasil/control.sock",
          env = "YGGDRASIL_CONTROL_SOCKET", global = true)]
    socket: PathBuf,

    /// Emit responses as raw JSON instead of human-readable.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show the high-level server status (peer IP, last heartbeat, branch count).
    Status,
    /// Inspect or manage loaded branches.
    Branches {
        #[command(subcommand)]
        action: BranchAction,
    },
    /// Inspect or manage the enrolled peer.
    Peer {
        #[command(subcommand)]
        action: PeerAction,
    },
}

#[derive(Debug, Subcommand)]
enum BranchAction {
    /// List loaded branches.
    List,
    /// Force a reload of the branches directory (in addition to inotify).
    Reload,
}

#[derive(Debug, Subcommand)]
enum PeerAction {
    /// Show the currently enrolled peer's pubkey and fingerprint.
    Show,
    /// List staged TOFU candidates awaiting approval.
    Pending,
    /// Approve a staged peer by its short fingerprint.
    Approve(ApproveArgs),
}

#[derive(Debug, Args)]
struct ApproveArgs {
    /// Short BLAKE2s-128 fingerprint (hex) of the peer to approve.
    fingerprint: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    runtime.block_on(async move {
        let request = build_request(&cli.command);
        let response = send(&cli.socket, &request, Duration::from_secs(5)).await?;
        if cli.json {
            print_json(&response)
        } else {
            print_human(&request, &response)
        }
    })
}

fn build_request(cmd: &Command) -> Request {
    match cmd {
        Command::Status => Request::Status,
        Command::Branches { action } => match action {
            BranchAction::List => Request::BranchesList,
            BranchAction::Reload => Request::BranchesReload,
        },
        Command::Peer { action } => match action {
            PeerAction::Show => Request::PeerShow,
            PeerAction::Pending => Request::PeerPending,
            PeerAction::Approve(a) => Request::PeerApprove {
                fingerprint: a.fingerprint.clone(),
            },
        },
    }
}

async fn send(socket: &PathBuf, request: &Request, timeout: Duration) -> Result<Response> {
    let mut stream = tokio::time::timeout(timeout, UnixStream::connect(socket))
        .await
        .with_context(|| format!("connect timeout after {timeout:?}"))?
        .with_context(|| format!("connecting to {}", socket.display()))?;

    let mut buf = serde_json::to_vec(request).context("encode request")?;
    buf.push(b'\n');
    tokio::time::timeout(timeout, stream.write_all(&buf))
        .await
        .context("write timeout")?
        .context("writing request")?;

    let (reader, _w) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    let line = tokio::time::timeout(timeout, lines.next_line())
        .await
        .context("read timeout")?
        .context("reading response")?
        .ok_or_else(|| anyhow!("server closed connection before responding"))?;
    let resp: Response = serde_json::from_str(&line).context("decode response")?;
    Ok(resp)
}

fn print_json(response: &Response) -> Result<()> {
    let s = serde_json::to_string_pretty(response)?;
    println!("{s}");
    if matches!(response, Response::Error { .. }) {
        std::process::exit(2);
    }
    Ok(())
}

fn print_human(request: &Request, response: &Response) -> Result<()> {
    match response {
        Response::Status(s) => {
            println!("version:        {}", s.version);
            println!(
                "peer_ip:        {}",
                s.peer_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "(none)".to_string())
            );
            println!(
                "last_heartbeat: {}",
                match s.last_heartbeat_age_ms {
                    Some(ms) => format!("{ms} ms ago"),
                    None => "(none)".to_string(),
                }
            );
            println!("branches:       {}", s.branch_count);
            println!("uptime:         {} s", s.uptime_secs);
            println!("peer_enrolled:  {}", s.peer_enrolled);
        }
        Response::Branches(b) => {
            if b.branches.is_empty() {
                println!("(no branches loaded)");
            } else {
                println!("{:<24}  {:<5}  {:<24}  upstream_port", "name", "proto", "listen");
                for br in &b.branches {
                    println!(
                        "{:<24}  {:<5}  {:<24}  {}",
                        br.name, br.protocol, br.listen, br.upstream_port
                    );
                }
            }
        }
        Response::BranchesReloaded {
            reloaded_rule_count,
        } => {
            println!(
                "reload requested ({reloaded_rule_count} branches currently loaded; \
                 new state visible on next `branches list`)"
            );
        }
        Response::Peer(p) => {
            if !p.enrolled {
                println!("(no peer enrolled)");
            } else {
                println!("pubkey:      {}", p.public_key_hex);
                println!("fingerprint: {}", p.fingerprint);
            }
        }
        Response::PeerPending(p) => {
            if p.candidates.is_empty() {
                println!("(no pending candidates)");
            } else {
                println!("{:<34} attempts  first_seen", "fingerprint");
                for c in &p.candidates {
                    println!(
                        "{:<34} {:<8}  {}",
                        c.fingerprint, c.attempt_count, c.first_seen_unix_ms
                    );
                }
            }
        }
        Response::PeerApproved { fingerprint } => {
            println!("approved {fingerprint}");
        }
        Response::Error { code, message } => {
            // Annotate which command triggered it so error output is greppable.
            eprintln!("error from server: {code}: {message}");
            eprintln!("(request was {request:?})");
            bail!("server returned error");
        }
    }
    Ok(())
}
