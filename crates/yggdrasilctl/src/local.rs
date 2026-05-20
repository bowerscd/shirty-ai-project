//! `local` scope — daemon-local commands over the Unix domain control socket.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use ratatoskr::control::{Mode, Request, Response};

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
    /// Inspect or manage the enrolled downstream peer (relay mode only).
    Downstream {
        #[command(subcommand)]
        action: DownstreamAction,
    },
    /// Inspect loaded TLS certificates (HTTPS L7 frontend).
    Certs {
        #[command(subcommand)]
        action: CertAction,
    },
    /// Render the daemon's Prometheus metrics in text exposition format
    /// (the same body the `/metrics` HTTP endpoint serves), retrieved
    /// over the control socket.
    Metrics,
    /// Liveness/readiness probe served over the control socket. Exit
    /// status: 0 if ready, 1 if not yet ready, 2 on RPC error.
    Health,
}

#[derive(Debug, Subcommand)]
pub enum RuleAction {
    /// List loaded rules.
    List,
    /// Force a reload of the rules directory (in addition to inotify).
    Reload,
}

#[derive(Debug, Subcommand)]
pub enum DownstreamAction {
    /// Show the currently enrolled downstream pubkey and fingerprint.
    Show,
    /// List staged TOFU candidates awaiting approval.
    Pending,
    /// Approve a staged candidate by its short fingerprint.
    Approve(ApproveArgs),
}

#[derive(Debug, Args)]
pub struct ApproveArgs {
    /// Short BLAKE2s-128 fingerprint (32 hex chars) of the downstream to approve.
    pub fingerprint: String,
}

#[derive(Debug, Subcommand)]
pub enum CertAction {
    /// List loaded certificates (one entry per hostname).
    List,
}

pub async fn run(cmd: Cmd, socket: &Path, json: bool) -> Result<()> {
    let request = build_request(&cmd);
    let response = send(socket, &request, Duration::from_secs(5)).await?;
    if json {
        print_json(&response)
    } else {
        print_human(&request, &response)
    }
}

fn build_request(cmd: &Cmd) -> Request {
    match cmd {
        Cmd::Status => Request::Status,
        Cmd::Rules { action } => match action {
            RuleAction::List => Request::RulesList,
            RuleAction::Reload => Request::RulesReload,
        },
        Cmd::Downstream { action } => match action {
            DownstreamAction::Show => Request::DownstreamShow,
            DownstreamAction::Pending => Request::DownstreamPending,
            DownstreamAction::Approve(a) => Request::DownstreamApprove {
                fingerprint: a.fingerprint.clone(),
            },
        },
        Cmd::Certs { action } => match action {
            CertAction::List => Request::CertsList,
        },
        Cmd::Metrics => Request::Metrics,
        Cmd::Health => Request::Health,
    }
}

async fn send(socket: &Path, request: &Request, timeout: Duration) -> Result<Response> {
    let socket: PathBuf = socket.to_path_buf();
    let mut stream = tokio::time::timeout(timeout, UnixStream::connect(&socket))
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
            // `mode` controls which fields are meaningful: terminal-mode
            // daemons have no downstream concept, so we omit the heartbeat /
            // enrollment lines. Gateway and relay both accept inbound chain
            // traffic and so do have a downstream.
            let mode_str = match s.mode {
                Mode::Gateway => "gateway",
                Mode::Relay => "relay",
                Mode::Terminal => "terminal",
            };
            let has_downstream = matches!(s.mode, Mode::Gateway | Mode::Relay);
            println!("version:         {}", s.version);
            println!("mode:            {mode_str}");
            if has_downstream {
                println!(
                    "downstream_ip:   {}",
                    s.downstream_ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "(none)".to_string())
                );
                println!(
                    "last_heartbeat:  {}",
                    match s.last_heartbeat_age_ms {
                        Some(ms) => format!("{ms} ms ago"),
                        None => "(none)".to_string(),
                    }
                );
            }
            println!("rules:           {}", s.rule_count);
            println!("uptime:          {} s", s.uptime_secs);
            if has_downstream {
                println!("downstream_enrolled: {}", s.downstream_enrolled);
            }
        }
        Response::Rules(b) => {
            if b.rules.is_empty() {
                println!("(no rules loaded)");
            } else {
                println!("{:<24}  {:<5}  {:<24}  target", "name", "proto", "listen");
                for br in &b.rules {
                    println!(
                        "{:<24}  {:<5}  {:<24}  {}",
                        br.name, br.protocol, br.listen, br.target
                    );
                }
            }
        }
        Response::RulesReloaded {
            reloaded_rule_count,
        } => {
            println!(
                "reload requested ({reloaded_rule_count} rules currently loaded; \
                 new state visible on next `rules list`)"
            );
        }
        Response::Downstream(p) => {
            if !p.enrolled {
                println!("(no downstream enrolled)");
            } else {
                println!("pubkey:      {}", p.pubkey);
                println!("fingerprint: {}", p.fingerprint);
            }
        }
        Response::DownstreamPending(p) => {
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
        Response::DownstreamApproved { fingerprint } => {
            println!("approved {fingerprint}");
        }
        Response::Certs(c) => {
            if c.certs.is_empty() {
                println!("(no certificates loaded)");
            } else {
                println!("{:<32}  {:<48}  loaded_unix_ms", "hostname", "source");
                for entry in &c.certs {
                    println!(
                        "{:<32}  {:<48}  {}",
                        entry.hostname, entry.cert_source, entry.loaded_at_unix_ms,
                    );
                }
            }
        }
        Response::Error { code, message } => {
            // Annotate which command triggered it so error output is greppable.
            eprintln!("error from server: {code}: {message}");
            eprintln!("(request was {request:?})");
            bail!("server returned error");
        }
        Response::ChainTunnelOpened { .. } => {
            // `ChainTunnelOpened` belongs to the `chain tunnel open`
            // connection-hijack path and is never produced for any
            // request issued from the `local` scope. Treat reaching
            // this arm as a server misbehaviour rather than a panic so
            // the operator sees a useful message.
            bail!(
                "server returned unexpected ChainTunnelOpened response \
                 to local request {request:?}"
            );
        }
        Response::ChainApplied(_) => {
            // `ChainApplied` belongs to the `chain apply` path and is
            // never produced for any request issued from the `local`
            // scope. Defensive arm so the Response enum stays
            // exhaustive at this match site.
            bail!(
                "server returned unexpected ChainApplied response \
                 to local request {request:?}"
            );
        }
        Response::Metrics(m) => {
            // Prometheus text format — the body already ends with a
            // trailing newline; print as-is to avoid double-spacing.
            print!("{}", m.body);
        }
        Response::Health(h) => {
            println!("ready:           {}", h.ready);
            println!("uptime:          {} s", h.uptime_secs);
            if !h.ready {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
