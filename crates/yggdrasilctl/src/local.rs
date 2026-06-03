//! `local` scope — daemon-local commands over the Unix domain control socket.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use ratatoskr::control::{Mode, Request, Response};

pub use cli_defs::yggdrasilctl::local::{AcceptAction, AcmeAction, Cmd, RuleAction};

pub async fn run(cmd: Cmd, socket: &Path, json: bool) -> Result<()> {
    if terminal_only_command(&cmd) {
        ensure_terminal_mode(socket).await?;
    }

    let request = build_request(&cmd);
    let response = send(socket, &request, Duration::from_secs(5)).await?;
    if json {
        print_json(&response)
    } else {
        print_human(&request, &response)
    }
}

fn terminal_only_command(cmd: &Cmd) -> bool {
    matches!(cmd, Cmd::Rules { .. } | Cmd::Acme { .. })
}

async fn ensure_terminal_mode(socket: &Path) -> Result<()> {
    let response = send(socket, &Request::Status, Duration::from_secs(5)).await?;
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
                Request::TraceSet { directive: Some(d) }
            }
        }
        Cmd::Acme { action } => match action {
            AcmeAction::List => Request::AcmeList,
            AcmeAction::Renew(a) => Request::AcmeRenew {
                hostname: a.hostname.clone(),
            },
        },
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
                    (Some(p), None) => format!("cert: {p}"),
                    (None, _) => "cert: (none)".to_string(),
                };
                println!("{cert_part}; ephemeral certs: {}", s.ephemeral_cert_count);
            }
            // NAT-traversal block: present only when the daemon's
            // `[server].nat_traversal` is something other than `off`
            // *and* the mapper successfully bound a socket. Older
            // daemons that don't know about NAT serialize this field
            // as absent → `None` here → block elided.
            if let Some(nat) = &s.nat {
                println!("NAT traversal:");
                println!("  mode:        {}", nat.mode);
                println!("  state:       {}", nat.state);
                if let Some(p) = &nat.protocol {
                    println!("  protocol:    {p}");
                }
                if let Some(g) = nat.gateway {
                    println!("  gateway:     {g}");
                }
                if let Some(ext) = nat.external_ip {
                    println!("  external IP: {ext}");
                }
                println!("  mappings:    {} active", nat.active_mapping_count);
                for m in &nat.mappings {
                    println!(
                        "    {:<24} {} {:<5} -> ext {:<5} (renew in {}s)",
                        m.origin, m.protocol, m.internal_port, m.external_port, m.renew_in_secs,
                    );
                }
                if let Some(err) = &nat.last_error {
                    println!("  last error:  {err}");
                }
            }
            // Cert-less route + lan_cidrs block: present only when
            // the daemon has at least one cert-less route loaded.
            // Older daemons that don't know about the feature
            // serialise `certless_route_count` as 0 (#[serde(default)])
            // → block elided.
            if s.certless_route_count > 0 {
                println!("cert-less routes: {}", s.certless_route_count);
                let label = if s.lan_cidrs_source == "override" {
                    "override"
                } else {
                    "default"
                };
                println!("lan_cidrs ({label}):");
                for cidr in &s.lan_cidrs {
                    println!("  {cidr}");
                }
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
            let s = serde_json::to_string_pretty(d).context("serialise DerivedRulesResponse")?;
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
        Response::AcmeList(a) => {
            if a.hosts.is_empty() {
                println!("(no ACME-managed hosts)");
            } else {
                println!(
                    "{:<32}  {:<12}  {:<10}  next_renewal",
                    "hostname", "provider", "state",
                );
                for h in &a.hosts {
                    let next = match h.next_renewal_unix {
                        Some(ts) => format_unix_secs(ts),
                        None => "(unscheduled)".to_string(),
                    };
                    println!(
                        "{:<32}  {:<12}  {:<10}  {}",
                        h.hostname, h.provider, h.state, next,
                    );
                    if let Some(err) = &h.last_error {
                        println!("    last_error: {err}");
                    }
                }
            }
        }
        Response::AcmeRenewed { hostname, success } => {
            if *success {
                println!("renewed {hostname}");
            } else {
                println!("renewal kicked for {hostname} (no result)");
            }
        }
        Response::ChainCanary(_) => {
            // `ChainCanary` belongs to the `chain canary` subcommand
            // and is never produced for any request issued from the
            // `local` scope. Treat as a routing bug.
            bail!(
                "server returned unexpected ChainCanary response \
                 to local request {request:?}"
            );
        }
    }
    Ok(())
}

fn format_unix_secs(secs: u64) -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let when = UNIX_EPOCH + Duration::from_secs(secs);
    match when.duration_since(SystemTime::now()) {
        Ok(future) => {
            let mins = future.as_secs() / 60;
            if mins < 60 {
                format!("in {mins} m  ({secs})")
            } else {
                let h = mins / 60;
                let m = mins % 60;
                if h < 48 {
                    format!("in {h} h {m} m  ({secs})")
                } else {
                    let d = h / 24;
                    format!("in {d} d  ({secs})")
                }
            }
        }
        Err(e) => {
            let ago = e.duration().as_secs() / 60;
            format!("{ago} m ago  ({secs})")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cli_defs::yggdrasilctl::local::{AcmeRenewArgs, ApproveArgs, TraceArgs};
    use ratatoskr::control::StatusResponse;
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

    #[tokio::test]
    async fn local_rules_refuses_gateway_before_dispatch() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("control.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(collect_requests_until_idle(
            listener,
            status_response(Mode::Gateway),
        ));

        let err = run(
            Cmd::Rules {
                action: RuleAction::Reload,
            },
            &socket,
            false,
        )
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

    #[tokio::test]
    async fn local_acme_refuses_gateway_before_dispatch() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("control.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(collect_requests_until_idle(
            listener,
            status_response(Mode::Gateway),
        ));

        let err = run(
            Cmd::Acme {
                action: AcmeAction::List,
            },
            &socket,
            false,
        )
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

    /// Each `Cmd` variant must map to the expected `Request` so the CLI
    /// surface stays in sync with the wire surface. A regression in
    /// `build_request` is otherwise only observable end-to-end.
    #[test]
    fn build_request_maps_status() {
        assert_eq!(build_request(&Cmd::Status), Request::Status);
    }

    #[test]
    fn build_request_maps_rules_list_and_reload() {
        let list = build_request(&Cmd::Rules {
            action: RuleAction::List,
        });
        assert_eq!(list, Request::RulesList);
        let reload = build_request(&Cmd::Rules {
            action: RuleAction::Reload,
        });
        assert_eq!(reload, Request::RulesReload);
    }

    #[test]
    fn build_request_maps_accept_subcommands() {
        let show = build_request(&Cmd::Accept {
            action: AcceptAction::Show,
        });
        assert_eq!(show, Request::DownstreamShow);
        let pending = build_request(&Cmd::Accept {
            action: AcceptAction::Pending,
        });
        assert_eq!(pending, Request::DownstreamPending);
        let approve = build_request(&Cmd::Accept {
            action: AcceptAction::Approve(ApproveArgs {
                fingerprint: "abcdef0123456789".into(),
            }),
        });
        assert_eq!(
            approve,
            Request::DownstreamApprove {
                fingerprint: "abcdef0123456789".into(),
            }
        );
    }

    #[test]
    fn build_request_maps_metrics_health_derived_rules() {
        assert_eq!(build_request(&Cmd::Metrics), Request::Metrics);
        assert_eq!(build_request(&Cmd::Health), Request::Health);
        assert_eq!(build_request(&Cmd::DerivedRules), Request::DerivedRules);
    }

    #[test]
    fn build_request_trace_with_directive_carries_some() {
        let req = build_request(&Cmd::Trace(TraceArgs {
            directive: Some("debug".into()),
            reset: false,
        }));
        assert_eq!(
            req,
            Request::TraceSet {
                directive: Some("debug".into()),
            }
        );
    }

    #[test]
    fn build_request_trace_reset_yields_none_directive() {
        let req = build_request(&Cmd::Trace(TraceArgs {
            directive: None,
            reset: true,
        }));
        assert_eq!(req, Request::TraceSet { directive: None });
    }

    #[test]
    fn build_request_maps_acme_list() {
        let req = build_request(&Cmd::Acme {
            action: AcmeAction::List,
        });
        assert_eq!(req, Request::AcmeList);
    }

    #[test]
    fn build_request_maps_acme_renew() {
        let req = build_request(&Cmd::Acme {
            action: AcmeAction::Renew(AcmeRenewArgs {
                hostname: "example.com".into(),
            }),
        });
        assert_eq!(
            req,
            Request::AcmeRenew {
                hostname: "example.com".into(),
            }
        );
    }
}
