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
    /// Inspect or manage the enrolled accept-side peer (the inbound chain
    /// peer pinned by `[accept]` — for relay-mode this is the downstream
    /// terminal node).
    Accept {
        #[command(subcommand)]
        action: AcceptAction,
    },
    /// Render the daemon's Prometheus metrics in text exposition
    /// format, retrieved over the control socket.
    Metrics,
    /// Liveness/readiness probe served over the control socket. Exit
    /// status: 0 if ready, 1 if not yet ready, 2 on RPC error.
    Health,
    /// Snapshot of this node's chain-applied predicates, derived rule
    /// set, and chain identity. Pretty-printed JSON to stdout.
    DerivedRules,
    /// Adjust the daemon's tracing-subscriber filter at runtime.
    /// Pass a directive (`debug`, `yggdrasil::heartbeat=trace,info`,
    /// etc.) or `--reset` to revert to the startup filter. With no
    /// args, prints the current and default directives without
    /// changing anything.
    Trace(TraceArgs),
}

#[derive(Debug, Args)]
pub struct TraceArgs {
    /// New EnvFilter directive to install. Required unless `--reset` is set.
    #[arg(conflicts_with = "reset", required_unless_present = "reset")]
    pub directive: Option<String>,
    /// Restore the directive the daemon was launched with.
    #[arg(long)]
    pub reset: bool,
}

#[derive(Debug, Subcommand)]
pub enum RuleAction {
    /// List loaded rules.
    List,
    /// Force a reload of the rules directory (in addition to inotify).
    Reload,
}

#[derive(Debug, Subcommand)]
pub enum AcceptAction {
    /// Show the currently enrolled accept-side pubkey and fingerprint.
    Show,
    /// List staged TOFU candidates awaiting approval.
    Pending,
    /// Approve a staged candidate by its fingerprint or any unique
    /// 8+-hex-char prefix.
    Approve(ApproveArgs),
}

#[derive(Debug, Args)]
pub struct ApproveArgs {
    /// Full BLAKE2s-128 fingerprint (32 hex chars) of the accept-side
    /// peer to approve, or any unique prefix of at least 8 hex chars. The
    /// daemon disambiguates against the staged queue; ambiguous
    /// prefixes return an error listing every match.
    pub fingerprint: String,
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
        Cmd::Accept { action } => match action {
            AcceptAction::Show => Request::DownstreamShow,
            AcceptAction::Pending => Request::DownstreamPending,
            AcceptAction::Approve(a) => Request::DownstreamApprove {
                fingerprint: a.fingerprint.clone(),
            },
        },
        Cmd::Metrics => Request::Metrics,
        Cmd::Health => Request::Health,
        Cmd::DerivedRules => Request::DerivedRules,
        Cmd::Trace(args) => {
            if args.reset {
                Request::TraceSet { directive: None }
            } else {
                let d = args
                    .directive
                    .clone()
                    .expect("clap enforces directive XOR --reset");
                Request::TraceSet {
                    directive: Some(d),
                }
            }
        }
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
            // Cert summary (item 29 — folded in from the dropped
            // `local certs list` subcommand). Only printed when the
            // daemon has at least one TLS-aware rule loaded;
            // otherwise both fields are absent and the operator gets
            // no noise.
            if s.default_cert_path.is_some() || s.ephemeral_cert_count > 0 {
                let cert_part = match (&s.default_cert_path, s.default_cert_loaded_age_secs) {
                    (Some(p), Some(age)) => format!("cert: {p} (loaded {age}s ago)"),
                    (Some(p), None)      => format!("cert: {p}"),
                    (None, _)            => "cert: (none)".to_string(),
                };
                println!(
                    "{cert_part}; ephemeral certs: {}",
                    s.ephemeral_cert_count
                );
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
        Response::Error { code, message } => {
            // Annotate which command triggered it so error output is greppable.
            eprintln!("error from server: {code}: {message}");
            eprintln!("(request was {request:?})");
            bail!("server returned error");
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
        Response::DerivedRules(d) => {
            // Pretty-print the snapshot; matches the body the
            // previous `/internal/derived-rules` HTTP endpoint emitted.
            let s = serde_json::to_string_pretty(d)
                .context("serialise DerivedRulesResponse")?;
            println!("{s}");
        }
        Response::ChainSummary(_) => {
            // `ChainSummary` belongs to the `chain summary` / `diff`
            // paths and is never produced for any request issued from
            // the `local` scope.
            bail!(
                "server returned unexpected ChainSummary response \
                 to local request {request:?}"
            );
        }
        Response::TraceSet { active, default } => {
            println!("trace: active={active}");
            println!("       default={default}");
        }
    }
    Ok(())
}
