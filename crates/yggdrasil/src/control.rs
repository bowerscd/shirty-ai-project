//! UDS control surface for `yggdrasilctl`.
//!
//! Wire format: one newline-delimited JSON object per request, one per
//! response. Backed by [`ratatoskr::control`]. The listener binds the
//! socket with mode `0o660`; group ownership is left to the operator (we don't
//! ship a packaging story yet).
//!
//! ## Why a worker task per connection?
//!
//! Each connection is short-lived and emits at most a handful of JSON
//! objects. There's no broadcast or fan-out, so a per-connection task with
//! buffered IO is the simplest correct design and trivially cancellable from
//! the parent token.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use ratatoskr::auth::public_key_fingerprint;
use ratatoskr::control::{
    error_codes, ChainAppliedResponse, ChainHop, ChainSummaryResponse, CertInfo,
    CertsListResponse, DownstreamResponse, HealthResponse, MetricsResponse, Mode,
    PendingResponse, Request, Response, RuleInfo, RulesResponse, StatusResponse,
};
use ratatoskr::predicate::PREDICATE_SET_MAX_WIRE_BYTES;
use ratatoskr::pubkey::PubKey;
use ratatoskr::rule::{Rule, RuleSet};
use ratatoskr::tunnel::TUNNEL_DATA_MAX_PAYLOAD;

use crate::chain::predicate_extractor;
use crate::chain::tunnel_initiator::{OpenError, TunnelInitiator};
use crate::heartbeat::PeerState;
use crate::pending_peers::PendingPeerStore;
use crate::proxy::supervisor::{ProxySupervisor, SupervisorHandle};
use crate::rules::ReloadTrigger;

/// Handle to a running control server.
pub struct ControlServer {
    cancel: CancellationToken,
    main_handle: JoinHandle<()>,
    socket_path: PathBuf,
}

/// Shared state every connection task sees.
///
/// `peer_state` and `pending_store` are `Option` so the same control surface
/// can serve both relay-mode daemons (downstream enrolled, heartbeat live)
/// and terminal-mode daemons (no downstream concept). When `None`, any
/// `downstream ...` request returns [`error_codes::NOT_SUPPORTED_IN_TERMINAL_MODE`].
struct ControlState {
    started_at: Instant,
    /// The mode the daemon was started in. Surfaced verbatim in
    /// [`StatusResponse::mode`] and used as the gate for the
    /// `downstream ...` request family.
    mode: Mode,
    peer_state: Option<Arc<PeerState>>,
    snapshot_rx: tokio::sync::watch::Receiver<Vec<crate::proxy::supervisor::ProxySnapshot>>,
    reload_trigger: ReloadTrigger,
    /// Shared cert store handle; surfaces via `Request::CertsList`.
    cert_store: Arc<crate::proxy::certs::CertStore>,
    pending_store: Option<Arc<PendingPeerStore>>,
    /// Path to the main server config; the approve flow rewrites
    /// `[accept].pubkey` atomically (tmp + rename). Held even in
    /// terminal mode (unused; cheap to carry).
    config_path: PathBuf,
    /// Initiator-side of the chain tunnel. `Some` only when this node
    /// has a chain upstream configured (`[dial]`); without an
    /// upstream we have nowhere to forward `TunnelOpen` envelopes, so
    /// the `OpenChainTunnel` UDS request returns
    /// [`error_codes::NO_CHAIN_UPSTREAM`].
    tunnel_initiator: Option<Arc<TunnelInitiator>>,
    /// Handle to the proxy supervisor. Owned here so the
    /// `Request::ChainApply` path can call
    /// [`SupervisorHandle::apply_ruleset`] directly without going
    /// through the file-watch reload mechanism (which would race the
    /// operator's request against an in-flight reload). The handle is
    /// cheap to clone and tied to the supervisor task's lifetime.
    supervisor_handle: SupervisorHandle,
    /// Prometheus recorder handle used by [`Request::Metrics`] to
    /// render the text exposition format directly over the UDS,
    /// without going through the HTTP listener.
    prom_handle: PrometheusHandle,
    /// Optional chain-introspection state used by
    /// [`Request::DerivedRules`]. `None` on pure-local terminals (no
    /// chain) or in tests that don't exercise predicate apply.
    introspection: Option<Arc<crate::chain::IntrospectionState>>,
}

impl ControlServer {
    /// Bind the UDS at `socket_path`, set mode `0o660`, and start accepting
    /// connections.
    ///
    /// If the path already exists it is removed first; that matches the
    /// systemd convention of "the daemon owns the socket file" and avoids
    /// the common "previous run crashed, EADDRINUSE" footgun.
    ///
    /// `peer_state` and `pending_store` are `None` in terminal mode. All
    /// `downstream ...` requests then return `not_supported_in_terminal_mode`.
    ///
    /// `tunnel_initiator` is `Some` only when the daemon has a chain
    /// upstream configured (predicate publisher / chain tunnel both
    /// depend on it). Pure-local terminals leave it `None`; the
    /// `OpenChainTunnel` UDS request then returns
    /// [`error_codes::NO_CHAIN_UPSTREAM`].
    #[allow(clippy::too_many_arguments)]
    pub async fn bind(
        socket_path: impl Into<PathBuf>,
        mode: Mode,
        peer_state: Option<Arc<PeerState>>,
        supervisor: &ProxySupervisor,
        pending_store: Option<Arc<PendingPeerStore>>,
        config_path: PathBuf,
        tunnel_initiator: Option<Arc<TunnelInitiator>>,
        prom_handle: PrometheusHandle,
        introspection: Option<Arc<crate::chain::IntrospectionState>>,
        shutdown: CancellationToken,
    ) -> Result<Self> {
        let socket_path: PathBuf = socket_path.into();
        if let Some(parent) = socket_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
        }
        // Best-effort: drop any stale socket file.
        match std::fs::remove_file(&socket_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(anyhow::anyhow!(e).context(format!(
                    "removing stale control socket {}",
                    socket_path.display()
                )))
            }
        }

        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("binding control socket {}", socket_path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o660))
                .with_context(|| format!("chmod 0660 {}", socket_path.display()))?;
        }

        let cancel = shutdown.child_token();
        let state = Arc::new(ControlState {
            started_at: Instant::now(),
            mode,
            peer_state,
            snapshot_rx: {
                // The supervisor exposes only a `snapshot()` snapshot getter.
                // We grab its underlying receiver via a small helper we add
                // alongside.
                supervisor.snapshot_receiver()
            },
            reload_trigger: supervisor.reload_trigger(),
            cert_store: supervisor.cert_store(),
            pending_store,
            config_path,
            tunnel_initiator,
            supervisor_handle: supervisor.handle(),
            prom_handle,
            introspection,
        });

        let main_cancel = cancel.clone();
        let main_handle = tokio::spawn(accept_loop(listener, state, main_cancel));

        tracing::info!(socket = %socket_path.display(), "control server bound");
        Ok(Self {
            cancel,
            main_handle,
            socket_path,
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = self.main_handle.await;
        // Best-effort cleanup; ignore if already gone.
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

async fn accept_loop(
    listener: UnixListener,
    state: Arc<ControlState>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                tracing::info!("control server received shutdown");
                return;
            }
            res = listener.accept() => {
                match res {
                    Ok((stream, _addr)) => {
                        let state = Arc::clone(&state);
                        let cancel = cancel.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, state, cancel).await {
                                tracing::debug!(error = %e, "control connection ended with error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "control accept failed");
                    }
                }
            }
        }
    }
}

async fn handle_connection(
    stream: UnixStream,
    state: Arc<ControlState>,
    cancel: CancellationToken,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            res = reader.read_line(&mut line) => {
                let n = res.context("read control request")?;
                if n == 0 {
                    return Ok(()); // peer closed
                }
                let parsed: std::result::Result<Request, _> =
                    serde_json::from_str(line.trim());
                match parsed {
                    Ok(Request::OpenChainTunnel { target_pubkey, dest }) => {
                        // Hand the connection off to the tunnel bridge:
                        // after this call returns the UDS half is dead
                        // either way (success → splice consumed it;
                        // failure → an `Error` response was written and
                        // we close).
                        return run_chain_tunnel_bridge(
                            target_pubkey,
                            dest,
                            reader,
                            writer,
                            state,
                            cancel,
                        )
                        .await;
                    }
                    Ok(Request::ChainApply { rules }) => {
                        // ChainApply needs `supervisor_handle.apply_ruleset`
                        // which is async; the synchronous `dispatch`
                        // table can't await. Route it here, mirroring
                        // how `OpenChainTunnel` is hoisted out for the
                        // same reason. The defensive arm in `dispatch`
                        // returns INTERNAL_ERROR if routing slips.
                        let response = dispatch_chain_apply(rules, &state).await;
                        let mut buf =
                            serde_json::to_vec(&response).context("encode response")?;
                        buf.push(b'\n');
                        writer.write_all(&buf).await.context("write response")?;
                    }
                    Ok(req) => {
                        let response = dispatch(req, &state);
                        let mut buf =
                            serde_json::to_vec(&response).context("encode response")?;
                        buf.push(b'\n');
                        writer.write_all(&buf).await.context("write response")?;
                    }
                    Err(e) => {
                        let response = Response::Error {
                            code: error_codes::INVALID_REQUEST.into(),
                            message: format!("could not parse request as JSON: {e}"),
                        };
                        let mut buf =
                            serde_json::to_vec(&response).context("encode response")?;
                        buf.push(b'\n');
                        writer.write_all(&buf).await.context("write response")?;
                    }
                }
            }
        }
    }
}

/// Single-line response writer used by the connection-hijack path. The
/// non-hijack path inlines the equivalent two lines because keeping the
/// error-flow ergonomics close to the surrounding loop matters more
/// than the line count.
async fn write_response(
    writer: &mut OwnedWriteHalf,
    response: &Response,
) -> Result<()> {
    let mut buf = serde_json::to_vec(response).context("encode response")?;
    buf.push(b'\n');
    writer.write_all(&buf).await.context("write response")?;
    Ok(())
}

fn dispatch(req: Request, state: &ControlState) -> Response {
    match req {
        Request::Status => {
            // Relay mode: report `downstream_ip`, `last_heartbeat_age_ms`, and
            // `downstream_enrolled` from the live peer state. Terminal mode
            // has no downstream concept; emit `None` for the heartbeat
            // fields and `downstream_enrolled = false`.
            let (downstream_ip, last_heartbeat_age_ms, downstream_enrolled) = match &state.peer_state {
                Some(ps) => {
                    let age = ps.last_heartbeat_ms().and_then(|ts| {
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .ok()
                            .map(|now| now.as_millis() as u64)
                            .map(|now| now.saturating_sub(ts))
                    });
                    (ps.current_ip(), age, ps.is_peer_enrolled())
                }
                None => (None, None, false),
            };
            let rule_count = state.snapshot_rx.borrow().len();
            Response::Status(StatusResponse {
                version: env!("CARGO_PKG_VERSION").to_string(),
                mode: state.mode,
                downstream_ip,
                last_heartbeat_age_ms,
                rule_count,
                uptime_secs: state.started_at.elapsed().as_secs(),
                downstream_enrolled,
            })
        }
        Request::RulesList => {
            let snapshot = state.snapshot_rx.borrow().clone();
            let rules = snapshot
                .into_iter()
                .map(|s| RuleInfo {
                    name: s.name,
                    protocol: s.protocol.as_str().to_string(),
                    listen: s.listen.to_string(),
                    target: s.upstream_description,
                })
                .collect();
            Response::Rules(RulesResponse { rules })
        }
        Request::RulesReload => {
            state.reload_trigger.force_reload();
            // Synchronous count of what's currently loaded; the reload itself
            // is asynchronous so we don't try to report the new count here.
            let reloaded_rule_count = state.snapshot_rx.borrow().len();
            Response::RulesReloaded {
                reloaded_rule_count,
            }
        }
        Request::DownstreamShow => {
            let peer_state = match &state.peer_state {
                Some(ps) => ps,
                None => return terminal_mode_unsupported("downstream show"),
            };
            let enrolled = peer_state.is_peer_enrolled();
            let raw = peer_state.peer_static_key();
            let pubkey = if enrolled {
                PubKey::X25519(raw).to_string()
            } else {
                String::new()
            };
            let fingerprint = if enrolled {
                public_key_fingerprint(&raw)
            } else {
                String::new()
            };
            Response::Downstream(DownstreamResponse {
                enrolled,
                pubkey,
                fingerprint,
            })
        }
        Request::DownstreamPending => {
            let pending_store = match &state.pending_store {
                Some(ps) => ps,
                None => return terminal_mode_unsupported("downstream pending"),
            };
            Response::DownstreamPending(PendingResponse {
                candidates: pending_store.list(),
            })
        }
        Request::DownstreamApprove { fingerprint } => approve_downstream(state, &fingerprint),
        Request::CertsList => {
            let certs = state
                .cert_store
                .list_full()
                .into_iter()
                .map(|(hostname, origin, loaded_at_unix_ms)| CertInfo {
                    hostname,
                    cert_source: origin.as_label(),
                    loaded_at_unix_ms,
                })
                .collect();
            Response::Certs(CertsListResponse { certs })
        }
        Request::Metrics => Response::Metrics(MetricsResponse {
            body: state.prom_handle.render(),
        }),
        Request::Health => {
            let uptime_secs = state.started_at.elapsed().as_secs();
            Response::Health(HealthResponse {
                ready: crate::health::is_ready(),
                uptime_secs,
            })
        }
        Request::DerivedRules => match state.introspection.as_ref() {
            Some(ix) => Response::DerivedRules(ix.snapshot()),
            None => Response::Error {
                code: error_codes::INTERNAL_ERROR.into(),
                message: "introspection state not configured for this daemon"
                    .into(),
            },
        },
        Request::ChainSummary { timeout_ms: _ } => match state.introspection.as_ref() {
            // B3a-local: only the local hop. Upward fanout via the
            // chain control plane is a follow-up increment; the wire
            // shape already supports it via `Vec<ChainHop>` + `partial`.
            Some(ix) => Response::ChainSummary(ChainSummaryResponse {
                hops: vec![ChainHop {
                    hop_index: 0,
                    mode: state.mode,
                    uptime_secs: state.started_at.elapsed().as_secs(),
                    view: ix.snapshot(),
                }],
                partial: false,
            }),
            None => Response::Error {
                code: error_codes::INTERNAL_ERROR.into(),
                message: "introspection state not configured for this daemon"
                    .into(),
            },
        },
        // `OpenChainTunnel` is handled by [`run_chain_tunnel_bridge`] in
        // [`handle_connection`] before reaching this synchronous
        // dispatch table: the bridge owns the socket halves and pumps
        // raw bytes between the operator and the chain. If we ever
        // reach this arm it means the connection-loop routing slipped.
        Request::OpenChainTunnel { .. } => Response::Error {
            code: error_codes::INTERNAL_ERROR.into(),
            message: "internal routing error: OpenChainTunnel reached \
                      the synchronous dispatcher (should have been \
                      hijacked by handle_connection)"
                .to_string(),
        },
        // `ChainApply` is handled by [`dispatch_chain_apply`] in
        // [`handle_connection`]: the apply path is async because
        // [`SupervisorHandle::apply_ruleset`] awaits a channel send,
        // and this synchronous dispatch table can't.
        Request::ChainApply { .. } => Response::Error {
            code: error_codes::INTERNAL_ERROR.into(),
            message: "internal routing error: ChainApply reached \
                      the synchronous dispatcher (should have been \
                      hoisted by handle_connection)"
                .to_string(),
        },
    }
}

/// Async dispatch for [`Request::ChainApply`]. Hoisted out of the
/// synchronous [`dispatch`] table because
/// [`SupervisorHandle::apply_ruleset`] awaits an mpsc channel send.
///
/// Flow:
/// 1. Refuse if the daemon is running in [`Mode::Relay`] — relays
///    receive rule sets from downstream predicate pushes and would
///    immediately overwrite anything applied here
///    ([`error_codes::NOT_SUPPORTED_IN_RELAY_MODE`]).
/// 2. Validate the candidate vector by constructing a [`RuleSet`]; this
///    runs the same per-rule + cross-rule checks the file-watch reload
///    runs ([`error_codes::RULES_INVALID`]).
/// 3. If the daemon has a chain upstream (presence of
///    `tunnel_initiator`), project the rule set through
///    [`predicate_extractor::extract`] and postcard-encode it. If the
///    encoded body would exceed
///    [`PREDICATE_SET_MAX_WIRE_BYTES`], refuse synchronously
///    ([`error_codes::PREDICATE_SET_OVERSIZE`]) — without this guard
///    the apply would "succeed" here but the publisher would silently
///    drop the push.
/// 4. Hand the [`RuleSet`] to [`SupervisorHandle::apply_ruleset`]. The
///    handle's `apply_tx` enqueues the set onto the supervisor task;
///    actual diff + listener mutation happens on that task. We return
///    once the push is *enqueued*, not once it has been applied.
async fn dispatch_chain_apply(rules: Vec<Rule>, state: &ControlState) -> Response {
    if state.mode != Mode::Terminal {
        return Response::Error {
            code: error_codes::NOT_SUPPORTED_IN_RELAY_MODE.into(),
            message: "`chain apply` is only supported on terminal-mode \
                      daemons; relays derive their rule set from \
                      downstream predicate pushes and would overwrite \
                      any manual apply on the next push"
                .to_string(),
        };
    }

    let applied_rule_count = rules.len();
    let ruleset = match RuleSet::from_rules(rules) {
        Ok(rs) => rs,
        Err(e) => {
            return Response::Error {
                code: error_codes::RULES_INVALID.into(),
                message: format!("candidate rule set failed validation: {e}"),
            };
        }
    };

    // Predicate projection + wire-size pre-check are only meaningful
    // when this terminal actually pushes upstream. Pure-local terminals
    // skip the projection and report `predicate_count = 0`.
    let (predicate_count, skipped_https) = if state.tunnel_initiator.is_some() {
        // The pre-check is sizing-only; the origin and version don't
        // affect whether the body fits under the cap (origin is 32B,
        // version is 8B; both are constant-sized regardless of value).
        // The publisher will project again with the real origin and
        // monotonic version on its next tick.
        let outcome = predicate_extractor::extract(&ruleset, PubKey::x25519([0u8; 32]), 0);
        let encoded = match postcard::to_allocvec(&outcome.set) {
            Ok(b) => b,
            Err(e) => {
                return Response::Error {
                    code: error_codes::APPLY_FAILED.into(),
                    message: format!(
                        "failed to encode projected predicate set for \
                         size pre-check: {e}"
                    ),
                };
            }
        };
        if encoded.len() > PREDICATE_SET_MAX_WIRE_BYTES {
            return Response::Error {
                code: error_codes::PREDICATE_SET_OVERSIZE.into(),
                message: format!(
                    "projected predicate set is {} bytes encoded; the \
                     wire cap is {} bytes. Shrink the rule set (fewer \
                     rules, shorter names, or fewer HTTPS routes) and \
                     retry.",
                    encoded.len(),
                    PREDICATE_SET_MAX_WIRE_BYTES
                ),
            };
        }
        (outcome.set.predicates.len(), outcome.skipped_https)
    } else {
        (0usize, Vec::new())
    };

    if let Err(e) = state.supervisor_handle.apply_ruleset(ruleset).await {
        return Response::Error {
            code: error_codes::APPLY_FAILED.into(),
            message: format!("supervisor refused the apply: {e}"),
        };
    }

    tracing::info!(
        applied_rule_count,
        predicate_count,
        skipped_https = skipped_https.len(),
        "chain apply enqueued via control surface"
    );

    Response::ChainApplied(ChainAppliedResponse {
        applied_rule_count,
        predicate_count,
        skipped_https,
    })
}

/// Build the canonical "not supported in terminal mode" error response.
fn terminal_mode_unsupported(verb: &str) -> Response {
    Response::Error {
        code: error_codes::NOT_SUPPORTED_IN_TERMINAL_MODE.into(),
        message: format!(
            "`{verb}` is not supported on a terminal-mode daemon \
             (terminal daemons have no downstream identity)"
        ),
    }
}

/// Hijack the UDS connection for a chain tunnel.
///
/// Wire shape:
/// 1. Caller has already written `Request::OpenChainTunnel { ... }\n` to
///    the socket and is awaiting a single response line.
/// 2. On success we write `Response::ChainTunnelOpened { stream_id }\n`
///    once, then enter raw-bytes mode: bytes from the UDS reader are
///    chunked and fed to [`TunnelInitiator::send_data`]; bytes coming
///    back through the [`crate::chain::tunnel_initiator::InitiatorStream::inbound_rx`]
///    are written directly to the UDS writer.
/// 3. The connection closes when the operator closes their write half
///    (EOF on the UDS reader) or when the upstream sends `TunnelClose`
///    (the `close_rx` oneshot fires and the inbox drains).
///
/// On failure (no upstream / target mismatch / open rejected / open
/// failed) we write a single `Response::Error { code, message }\n` and
/// return; the connection then drops. No partial response is ever
/// emitted: callers can rely on "exactly one JSON response line then
/// either raw bytes or EOF".
async fn run_chain_tunnel_bridge(
    target_pubkey: PubKey,
    dest: std::net::SocketAddr,
    mut reader: BufReader<OwnedReadHalf>,
    mut writer: OwnedWriteHalf,
    state: Arc<ControlState>,
    cancel: CancellationToken,
) -> Result<()> {
    let initiator = match &state.tunnel_initiator {
        Some(i) => i.clone(),
        None => {
            let err = Response::Error {
                code: error_codes::NO_CHAIN_UPSTREAM.into(),
                message: "this node has no chain upstream configured; \
                          OpenChainTunnel is unavailable"
                    .to_string(),
            };
            write_response(&mut writer, &err).await?;
            return Ok(());
        }
    };

    let stream = match initiator.open(target_pubkey, dest).await {
        Ok(s) => s,
        Err(OpenError::Rejected(reason)) => {
            let err = Response::Error {
                code: error_codes::TUNNEL_OPEN_REJECTED.into(),
                message: format!(
                    "upstream rejected the tunnel open with reason \
                     code 0x{reason:04x}"
                ),
            };
            write_response(&mut writer, &err).await?;
            return Ok(());
        }
        Err(e) => {
            let err = Response::Error {
                code: error_codes::TUNNEL_OPEN_FAILED.into(),
                message: format!("failed to open chain tunnel: {e}"),
            };
            write_response(&mut writer, &err).await?;
            return Ok(());
        }
    };

    let stream_id = stream.stream_id;
    let ok = Response::ChainTunnelOpened { stream_id };
    write_response(&mut writer, &ok).await?;
    tracing::debug!(stream_id, target = %target_pubkey, dest = %dest, "chain tunnel opened; entering splice");

    let crate::chain::tunnel_initiator::InitiatorStream {
        mut inbound_rx,
        close_rx,
        ..
    } = stream;

    // Spawn the upload pump (operator stdin / UDS reader → tunnel).
    // We hold the reader in the task because it's owned and we need
    // raw `read()` semantics; the BufReader will drain its internal
    // buffer first (any bytes the operator pipelined after the
    // request line) before pulling from the underlying socket.
    let upload_initiator = initiator.clone();
    let upload_done = CancellationToken::new();
    let upload_done_for_task = upload_done.clone();
    let upload_join = tokio::spawn(async move {
        let mut buf = vec![0u8; TUNNEL_DATA_MAX_PAYLOAD];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    tracing::debug!(stream_id, "upload: UDS read EOF");
                    break;
                }
                Ok(n) => {
                    if let Err(e) = upload_initiator
                        .send_data(stream_id, buf[..n].to_vec())
                        .await
                    {
                        tracing::warn!(
                            stream_id,
                            error = %e,
                            "upload: send_data failed; aborting splice"
                        );
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!(stream_id, error = %e, "upload: UDS read error");
                    break;
                }
            }
        }
        upload_done_for_task.cancel();
    });

    // Main task: pump inbox → UDS writer, watching for the upload
    // pump exiting (operator closed write half), an explicit
    // `close_rx` from the peer, or daemon shutdown.
    //
    // TCP-style half-close: when the operator closes their UDS write
    // half (`upload_done` fires), we send a wire `TunnelClose` to the
    // peer via [`TunnelInitiator::signal_close`] but **keep the local
    // registry entry alive** so any response bytes the peer is still
    // flushing make it back to the operator. Without this, the
    // [`TunnelInitiator::close`] path would also `remove_stream` and
    // any subsequent `TunnelData` would be rejected with
    // `STREAM_NOT_FOUND`. Matters for request/response patterns like
    // `yggdrasilctl chain diff` over HTTP/1.1 with `Connection:
    // close`, where the server emits its response *after* seeing FIN.
    tokio::pin!(close_rx);
    let mut peer_initiated_close = false;
    let mut we_sent_close = false;
    let mut upload_done_seen = false;
    let mut bridge_bytes_written: usize = 0;
    let mut bridge_chunks_written: usize = 0;
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                tracing::debug!(stream_id, "bridge: cancel arm");
                break;
            }
            _ = upload_done.cancelled(), if !upload_done_seen => {
                upload_done_seen = true;
                tracing::debug!(
                    stream_id,
                    "bridge: upload_done arm; calling signal_close"
                );
                initiator.signal_close(stream_id, 0).await;
                tracing::debug!(stream_id, "bridge: signal_close returned");
                we_sent_close = true;
            }
            res = &mut close_rx => {
                tracing::debug!(
                    stream_id,
                    close_rx_ok = res.is_ok(),
                    "bridge: close_rx arm fired; draining inbound_rx"
                );
                peer_initiated_close = res.is_ok();
                let mut drained_chunks: usize = 0;
                let mut drained_bytes: usize = 0;
                while let Ok(payload) = inbound_rx.try_recv() {
                    drained_chunks += 1;
                    drained_bytes += payload.len();
                    if let Err(e) = writer.write_all(&payload).await {
                        tracing::warn!(
                            stream_id,
                            error = %e,
                            "bridge: UDS write_all failed during close drain"
                        );
                        break;
                    }
                    bridge_bytes_written += payload.len();
                    bridge_chunks_written += 1;
                }
                tracing::debug!(
                    stream_id,
                    drained_chunks,
                    drained_bytes,
                    "bridge: close_rx drain complete"
                );
                break;
            }
            res = inbound_rx.recv() => match res {
                Some(payload) => {
                    let len = payload.len();
                    if let Err(e) = writer.write_all(&payload).await {
                        tracing::warn!(stream_id, error = %e, "bridge: UDS write_all failed");
                        break;
                    }
                    bridge_bytes_written += len;
                    bridge_chunks_written += 1;
                    tracing::trace!(
                        stream_id,
                        chunk_bytes = len,
                        bridge_bytes_written,
                        bridge_chunks_written,
                        "bridge: inbound_rx arm wrote chunk to UDS"
                    );
                }
                None => {
                    tracing::debug!(
                        stream_id,
                        "bridge: inbound_rx arm hit None (registry entry removed)"
                    );
                    peer_initiated_close = true;
                    break;
                }
            }
        }
    }
    tracing::debug!(
        stream_id,
        bridge_bytes_written,
        bridge_chunks_written,
        peer_initiated_close,
        we_sent_close,
        upload_done_seen,
        "bridge: main loop exit"
    );

    // Cleanup: if neither side has wire-closed yet (cancel path), do
    // a full close. If we already half-closed, the peer's TunnelClose
    // back removed the local entry (or will, idempotently); calling
    // `close` here is a safe no-op via the `remove_stream` returns-
    // `false` path.
    if !we_sent_close && !peer_initiated_close {
        initiator.close(stream_id, 0).await;
    } else if we_sent_close && !peer_initiated_close {
        // Peer never wire-closed (e.g. cancel midway through). Make
        // sure we drop our local entry so the registry doesn't leak.
        initiator.close(stream_id, 0).await;
    }
    let _ = writer.shutdown().await;
    upload_join.abort();
    let _ = upload_join.await;
    tracing::debug!(stream_id, "chain tunnel bridge exited");
    Ok(())
}

fn approve_downstream(state: &ControlState, fingerprint: &str) -> Response {
    let (peer_state, pending_store) = match (&state.peer_state, &state.pending_store) {
        (Some(ps), Some(store)) => (ps, store),
        _ => return terminal_mode_unsupported("downstream approve"),
    };
    let key = match pending_store.approve(fingerprint) {
        Ok(Some(k)) => k,
        Ok(None) => {
            return Response::Error {
                code: error_codes::NO_SUCH_FINGERPRINT.into(),
                message: format!("fingerprint {fingerprint:?} is not in the pending queue"),
            };
        }
        Err(e) => {
            return Response::Error {
                code: error_codes::INTERNAL_ERROR.into(),
                message: format!("failed to pop staged candidate: {e:#}"),
            };
        }
    };
    let tagged = PubKey::X25519(key).to_string();
    if let Err(e) = update_downstream_pubkey(&state.config_path, &tagged) {
        return Response::Error {
            code: error_codes::CONFIG_WRITE_FAILED.into(),
            message: format!(
                "approve: failed to write {} ({e:#}). \
                 Candidate has been removed from the pending queue; \
                 set `accept.pubkey = \"{tagged}\"` manually.",
                state.config_path.display()
            ),
        };
    }
    peer_state.set_peer_static_key(key);
    tracing::info!(
        fingerprint = fingerprint,
        "downstream approved via control surface; key is now live"
    );
    Response::DownstreamApproved {
        fingerprint: fingerprint.to_string(),
    }
}

/// Atomic rewrite of `[accept].pubkey` in `config_path`. Round-trips
/// the file through `toml::Value` so other keys are preserved (formatting
/// and comments are lost — acceptable trade-off; explicit `*.tmp` + rename
/// keeps the change crash-safe).
fn update_downstream_pubkey(config_path: &Path, tagged_pubkey: &str) -> Result<()> {
    let text = std::fs::read_to_string(config_path)
        .with_context(|| format!("read {}", config_path.display()))?;
    let mut doc: toml::Value = text.parse()
        .with_context(|| format!("parse {}", config_path.display()))?;
    let table = doc
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("{} is not a TOML table", config_path.display()))?;
    let accept_entry = table
        .entry("accept".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
    let accept_table = accept_entry
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!(
            "`accept` in {} is not a table",
            config_path.display()
        ))?;
    accept_table.insert(
        "pubkey".to_string(),
        toml::Value::String(tagged_pubkey.to_string()),
    );
    let serialised = toml::to_string_pretty(&doc).context("serialise updated config")?;
    let tmp = config_path.with_extension("toml.tmp");
    std::fs::write(&tmp, serialised).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, config_path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), config_path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heartbeat::PeerState;
    use crate::proxy::resolver::ResolverFactory;
    use crate::proxy::supervisor::{CertConfig, ProxySupervisor};
    use std::net::IpAddr;
    use std::time::Duration;

    async fn make_supervisor(dir: &Path) -> (ProxySupervisor, Arc<PeerState>, CancellationToken) {
        make_supervisor_with_enrolled(dir, false).await
    }

    /// `enrolled = true` uses a random non-zero key so
    /// `peer_state.is_peer_enrolled()` returns true.
    async fn make_supervisor_with_enrolled(
        dir: &Path,
        enrolled: bool,
    ) -> (ProxySupervisor, Arc<PeerState>, CancellationToken) {
        std::fs::create_dir_all(dir).unwrap();
        let key = if enrolled { [7u8; 32] } else { [0u8; 32] };
        let peer_state = PeerState::new(key);
        let shutdown = CancellationToken::new();
        let supervisor = ProxySupervisor::spawn(
            dir,
            Duration::from_millis(50),
            ResolverFactory::new_relay(peer_state.clone()),
            None,
            CertConfig::default(),
            shutdown.clone(),
        )
        .await
        .unwrap();
        (supervisor, peer_state, shutdown)
    }

    /// Build the supporting state needed by `ControlServer::bind`: a pending
    /// store rooted in `dir/state` and a writable placeholder config path
    /// rooted in `dir/yggdrasil.toml`.
    fn aux_state(dir: &Path) -> (Arc<PendingPeerStore>, PathBuf) {
        let state_dir = dir.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let store = Arc::new(PendingPeerStore::load(&state_dir).unwrap());
        let config_path = dir.join("yggdrasil.toml");
        // Minimal valid TOML so `update_downstream_pubkey` has something
        // to round-trip if a test ends up approving.
        std::fs::write(
            &config_path,
            "[server]\nidentity_file = \"/tmp/id.key\"\n",
        )
        .unwrap();
        (store, config_path)
    }

    async fn send_request(socket_path: &Path, req: &Request) -> Response {
        let mut stream = UnixStream::connect(socket_path).await.unwrap();
        let mut buf = serde_json::to_vec(req).unwrap();
        buf.push(b'\n');
        stream.write_all(&buf).await.unwrap();
        let (reader, _w) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        let line = lines.next_line().await.unwrap().unwrap();
        serde_json::from_str(&line).unwrap()
    }

    /// Bind a relay-mode `ControlServer` for tests. Wraps the
    /// peer-state/pending-store args in `Some(...)` so individual tests stay
    /// terse. Terminal-mode tests (which want `None` for both) bind
    /// directly.
    async fn bind_relay_control(
        socket: PathBuf,
        peer_state: Arc<PeerState>,
        supervisor: &ProxySupervisor,
        pending: Arc<PendingPeerStore>,
        cfg: PathBuf,
        shutdown: CancellationToken,
    ) -> ControlServer {
        ControlServer::bind(
            socket,
            Mode::Relay,
            Some(peer_state),
            supervisor,
            Some(pending),
            cfg,
            None,
            crate::metrics::detached_handle_for_tests(),
            None,
            shutdown,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn status_reports_initial_state() {
        let tmp = tempfile::tempdir().unwrap();
        let rules = tmp.path().join("rules");
        let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
        let socket = tmp.path().join("control.sock");
        let (pending, cfg) = aux_state(tmp.path());

        let server = bind_relay_control(
            socket.clone(),
            peer_state.clone(),
            &supervisor,
            pending,
            cfg,
            shutdown.clone(),
        )
        .await;

        let resp = send_request(&socket, &Request::Status).await;
        match resp {
            Response::Status(s) => {
                assert_eq!(s.downstream_ip, None);
                assert_eq!(s.rule_count, 0);
                assert!(!s.downstream_enrolled);
            }
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    #[tokio::test]
    async fn status_reflects_heartbeat() {
        let tmp = tempfile::tempdir().unwrap();
        let rules = tmp.path().join("rules");
        let (supervisor, peer_state, shutdown) =
            make_supervisor_with_enrolled(&rules, true).await;
        let socket = tmp.path().join("control.sock");
        let (pending, cfg) = aux_state(tmp.path());
        let server = bind_relay_control(
            socket.clone(),
            peer_state.clone(),
            &supervisor,
            pending,
            cfg,
            shutdown.clone(),
        )
        .await;

        let ip: IpAddr = "192.0.2.5".parse().unwrap();
        peer_state.record_heartbeat(std::net::SocketAddr::new(ip, 7117));

        let resp = send_request(&socket, &Request::Status).await;
        match resp {
            Response::Status(s) => {
                assert_eq!(s.downstream_ip, Some(ip));
                assert!(s.downstream_enrolled);
                assert!(s.last_heartbeat_age_ms.is_some());
            }
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    #[tokio::test]
    async fn downstream_show_returns_pubkey_when_enrolled() {
        let tmp = tempfile::tempdir().unwrap();
        let rules = tmp.path().join("rules");
        let (supervisor, peer_state, shutdown) =
            make_supervisor_with_enrolled(&rules, true).await;
        let socket = tmp.path().join("control.sock");
        let (pending, cfg) = aux_state(tmp.path());
        let server = bind_relay_control(
            socket.clone(),
            peer_state.clone(),
            &supervisor,
            pending,
            cfg,
            shutdown.clone(),
        )
        .await;

        let resp = send_request(&socket, &Request::DownstreamShow).await;
        match resp {
            Response::Downstream(p) => {
                assert!(p.enrolled);
                // tagged form: "x25519:" + 64 hex chars = 71 chars
                assert_eq!(p.pubkey.len(), 71);
                assert!(p.pubkey.starts_with("x25519:"));
                assert_eq!(p.fingerprint.len(), 32);
            }
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    #[tokio::test]
    async fn downstream_show_returns_empty_when_not_enrolled() {
        let tmp = tempfile::tempdir().unwrap();
        let rules = tmp.path().join("rules");
        let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
        let socket = tmp.path().join("control.sock");
        let (pending, cfg) = aux_state(tmp.path());
        let server = bind_relay_control(
            socket.clone(),
            peer_state.clone(),
            &supervisor,
            pending,
            cfg,
            shutdown.clone(),
        )
        .await;

        let resp = send_request(&socket, &Request::DownstreamShow).await;
        match resp {
            Response::Downstream(p) => {
                assert!(!p.enrolled);
                assert!(p.pubkey.is_empty());
                assert!(p.fingerprint.is_empty());
            }
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    #[tokio::test]
    async fn rules_reload_returns_current_count() {
        let tmp = tempfile::tempdir().unwrap();
        let rules = tmp.path().join("rules");
        let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
        let socket = tmp.path().join("control.sock");
        let (pending, cfg) = aux_state(tmp.path());
        let server = bind_relay_control(
            socket.clone(),
            peer_state.clone(),
            &supervisor,
            pending,
            cfg,
            shutdown.clone(),
        )
        .await;

        let resp = send_request(&socket, &Request::RulesReload).await;
        match resp {
            Response::RulesReloaded {
                reloaded_rule_count,
            } => {
                assert_eq!(reloaded_rule_count, 0);
            }
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    #[tokio::test]
    async fn invalid_json_returns_error_response() {
        let tmp = tempfile::tempdir().unwrap();
        let rules = tmp.path().join("rules");
        let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
        let socket = tmp.path().join("control.sock");
        let (pending, cfg) = aux_state(tmp.path());
        let server = bind_relay_control(
            socket.clone(),
            peer_state.clone(),
            &supervisor,
            pending,
            cfg,
            shutdown.clone(),
        )
        .await;

        let mut stream = UnixStream::connect(&socket).await.unwrap();
        stream.write_all(b"not json at all\n").await.unwrap();
        let (reader, _w) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        let line = lines.next_line().await.unwrap().unwrap();
        let resp: Response = serde_json::from_str(&line).unwrap();
        match resp {
            Response::Error { code, .. } => assert_eq!(code, error_codes::INVALID_REQUEST),
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    #[tokio::test]
    async fn peer_pending_lists_staged_candidates() {
        let tmp = tempfile::tempdir().unwrap();
        let rules = tmp.path().join("rules");
        let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
        let socket = tmp.path().join("control.sock");
        let (pending, cfg) = aux_state(tmp.path());
        pending.record_candidate([0xAAu8; 32]).unwrap();
        pending.record_candidate([0xBBu8; 32]).unwrap();
        let server = bind_relay_control(
            socket.clone(),
            peer_state.clone(),
            &supervisor,
            pending,
            cfg,
            shutdown.clone(),
        )
        .await;

        let resp = send_request(&socket, &Request::DownstreamPending).await;
        match resp {
            Response::DownstreamPending(p) => {
                assert_eq!(p.candidates.len(), 2);
            }
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    #[tokio::test]
    async fn downstream_approve_writes_config_and_swaps_live_key() {
        let tmp = tempfile::tempdir().unwrap();
        let rules = tmp.path().join("rules");
        let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
        let socket = tmp.path().join("control.sock");
        let (pending, cfg) = aux_state(tmp.path());

        let candidate = [0x42u8; 32];
        pending.record_candidate(candidate).unwrap();
        let fp = ratatoskr::auth::public_key_fingerprint(&candidate);

        assert!(!peer_state.is_peer_enrolled());

        let server = bind_relay_control(
            socket.clone(),
            peer_state.clone(),
            &supervisor,
            pending,
            cfg.clone(),
            shutdown.clone(),
        )
        .await;

        let resp = send_request(
            &socket,
            &Request::DownstreamApprove {
                fingerprint: fp.clone(),
            },
        )
        .await;
        match resp {
            Response::DownstreamApproved { fingerprint } => assert_eq!(fingerprint, fp),
            other => panic!("unexpected response: {other:?}"),
        }
        // Live key was swapped in.
        assert!(peer_state.is_peer_enrolled());
        assert_eq!(peer_state.peer_static_key(), candidate);
        // Config file was rewritten with the approved key in tagged form.
        let rewritten = std::fs::read_to_string(&cfg).unwrap();
        let tagged = format!("x25519:{}", hex::encode(candidate));
        assert!(
            rewritten.contains(&tagged),
            "config not rewritten with tagged pubkey: {rewritten}"
        );
        assert!(
            rewritten.contains("[accept]"),
            "config missing [accept]: {rewritten}"
        );

        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    #[tokio::test]
    async fn downstream_approve_unknown_fingerprint_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let rules = tmp.path().join("rules");
        let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
        let socket = tmp.path().join("control.sock");
        let (pending, cfg) = aux_state(tmp.path());
        let server = bind_relay_control(
            socket.clone(),
            peer_state.clone(),
            &supervisor,
            pending,
            cfg,
            shutdown.clone(),
        )
        .await;

        let resp = send_request(
            &socket,
            &Request::DownstreamApprove {
                fingerprint: "not-a-real-fingerprint".to_string(),
            },
        )
        .await;
        match resp {
            Response::Error { code, .. } => {
                assert_eq!(code, error_codes::NO_SUCH_FINGERPRINT)
            }
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    #[tokio::test]
    async fn certs_list_returns_empty_when_no_https_rules_loaded() {
        let tmp = tempfile::tempdir().unwrap();
        let rules = tmp.path().join("rules");
        let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
        let socket = tmp.path().join("control.sock");
        let (pending, cfg) = aux_state(tmp.path());
        let server = bind_relay_control(
            socket.clone(),
            peer_state.clone(),
            &supervisor,
            pending,
            cfg,
            shutdown.clone(),
        )
        .await;

        let resp = send_request(&socket, &Request::CertsList).await;
        match resp {
            Response::Certs(c) => {
                assert!(c.certs.is_empty(), "expected empty certs list, got {:?}", c.certs);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }
}
