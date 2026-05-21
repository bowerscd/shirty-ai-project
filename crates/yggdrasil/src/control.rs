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
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use ratatoskr::auth::public_key_fingerprint;
use ratatoskr::control::{
    error_codes, ChainAppliedResponse, ChainHop, ChainSummaryResponse, DownstreamResponse,
    HealthResponse, MetricsResponse, Mode, PendingResponse, Request, Response, RuleInfo,
    RulesResponse, StatusResponse,
};
use ratatoskr::predicate::PREDICATE_SET_MAX_WIRE_BYTES;
use ratatoskr::pubkey::PubKey;
use ratatoskr::rule::{Rule, RuleSet};

use crate::chain::client::ChainClientHandle;
use crate::chain::predicate_extractor;
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
    /// Shared cert store handle; surfaces via `Request::Status`.
    cert_store: Arc<crate::proxy::certs::CertStore>,
    pending_store: Option<Arc<PendingPeerStore>>,
    /// Path to the main server config; the approve flow rewrites
    /// `[accept].pubkey` atomically (tmp + rename). Held even in
    /// terminal mode (unused; cheap to carry).
    config_path: PathBuf,
    /// True when this node has a chain upstream configured (`[dial]`).
    /// Gates the predicate-projection pre-check in
    /// [`dispatch_chain_apply`]: pure-local terminals skip projection
    /// (no upstream to push to) and report `predicate_count = 0`.
    has_chain_upstream: bool,
    /// Handle to the proxy supervisor. Owned here so the
    /// `Request::ChainApply` path can call
    /// [`SupervisorHandle::apply_ruleset`] directly without going
    /// through the file-watch reload mechanism (which would race the
    /// operator's request against an in-flight reload). The handle is
    /// cheap to clone and tied to the supervisor task's lifetime.
    supervisor_handle: SupervisorHandle,
    /// Prometheus recorder handle used by [`Request::Metrics`] to
    /// render the text exposition format directly over the UDS.
    prom_handle: PrometheusHandle,
    /// Optional chain-introspection state used by
    /// [`Request::DerivedRules`]. `None` on pure-local terminals (no
    /// chain) or in tests that don't exercise predicate apply.
    introspection: Option<Arc<crate::chain::IntrospectionState>>,
    /// Optional upstream chain-client handle used by
    /// [`Request::ChainSummary`] to walk the chain. `None` on nodes
    /// without a `[dial]` section (gateways, root relays, pure-local
    /// terminals); the response then contains only the local hop with
    /// `partial = false`.
    chain_client_handle: Option<ChainClientHandle>,
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
    /// `has_chain_upstream` is `true` when the daemon has a `[dial]`
    /// section (and the chain client/publisher have been wired). It
    /// gates the predicate-projection pre-check in `chain apply`.
    #[allow(clippy::too_many_arguments)]
    pub async fn bind(
        socket_path: impl Into<PathBuf>,
        mode: Mode,
        peer_state: Option<Arc<PeerState>>,
        supervisor: &ProxySupervisor,
        pending_store: Option<Arc<PendingPeerStore>>,
        config_path: PathBuf,
        has_chain_upstream: bool,
        prom_handle: PrometheusHandle,
        introspection: Option<Arc<crate::chain::IntrospectionState>>,
        chain_client_handle: Option<ChainClientHandle>,
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
            has_chain_upstream,
            supervisor_handle: supervisor.handle(),
            prom_handle,
            introspection,
            chain_client_handle,
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

async fn accept_loop(listener: UnixListener, state: Arc<ControlState>, cancel: CancellationToken) {
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
                    Ok(Request::ChainApply { rules }) => {
                        // ChainApply needs `supervisor_handle.apply_ruleset`
                        // which is async; the synchronous `dispatch`
                        // table can't await. Route it here. The
                        // defensive arm in `dispatch` returns
                        // INTERNAL_ERROR if routing slips.
                        let response = dispatch_chain_apply(rules, &state).await;
                        let mut buf =
                            serde_json::to_vec(&response).context("encode response")?;
                        buf.push(b'\n');
                        writer.write_all(&buf).await.context("write response")?;
                    }
                    Ok(Request::ChainSummary { timeout_ms }) => {
                        // ChainSummary may walk upstream via
                        // `ChainClientHandle::query_upstream`, which
                        // is async; route it like ChainApply.
                        let response = dispatch_chain_summary(timeout_ms, &state).await;
                        let mut buf =
                            serde_json::to_vec(&response).context("encode response")?;
                        buf.push(b'\n');
                        writer.write_all(&buf).await.context("write response")?;
                    }
                    Ok(Request::RulesReload) => {
                        // CP31: block until the watcher has drained
                        // the trigger and (if the set changed) the
                        // supervisor has applied it. Returns the
                        // post-reload count.
                        let response = dispatch_rules_reload(&state).await;
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

/// Dispatcher for synchronous control requests.
fn dispatch(req: Request, state: &ControlState) -> Response {
    match req {
        Request::Status => {
            // Relay mode: report `downstream_ip`, `last_heartbeat_age_ms`, and
            // `downstream_enrolled` from the live peer state. Terminal mode
            // has no downstream concept; emit `None` for the heartbeat
            // fields and `downstream_enrolled = false`.
            let (downstream_ip, last_heartbeat_age_ms, downstream_enrolled) =
                match &state.peer_state {
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
            // Cert summary: traverse the cert store once for the
            // default-cert age and ephemeral count. The default cert's
            // path is taken from the first store entry whose origin is
            // `Default`. `None` when the daemon has no HTTPS rules
            // loaded against the operator-supplied default.
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let mut default_cert_path: Option<String> = None;
            let mut default_cert_loaded_age_secs: Option<u64> = None;
            let mut ephemeral_cert_count: usize = 0;
            for (_host, origin, loaded_at_unix_ms) in state.cert_store.list_full() {
                match origin {
                    crate::proxy::certs::CertOrigin::Default { ref cert, .. }
                        if default_cert_path.is_none() =>
                    {
                        default_cert_path = Some(cert.display().to_string());
                        default_cert_loaded_age_secs =
                            Some(now_ms.saturating_sub(loaded_at_unix_ms) / 1000);
                    }
                    crate::proxy::certs::CertOrigin::Ephemeral => {
                        ephemeral_cert_count += 1;
                    }
                    _ => {}
                }
            }
            Response::Status(StatusResponse {
                version: env!("CARGO_PKG_VERSION").to_string(),
                mode: state.mode,
                downstream_ip,
                last_heartbeat_age_ms,
                rule_count,
                uptime_secs: state.started_at.elapsed().as_secs(),
                downstream_enrolled,
                default_cert_path,
                default_cert_loaded_age_secs,
                ephemeral_cert_count,
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
        Request::RulesReload => Response::Error {
            code: error_codes::INTERNAL_ERROR.into(),
            message: "internal routing error: RulesReload reached \
                      the synchronous dispatcher (should have been \
                      hoisted by handle_connection)"
                .to_string(),
        },
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
                message: "introspection state not configured for this daemon".into(),
            },
        },
        Request::ChainSummary { timeout_ms: _ } => Response::Error {
            code: error_codes::INTERNAL_ERROR.into(),
            message: "internal routing error: ChainSummary reached \
                      the synchronous dispatcher (should have been \
                      hoisted by handle_connection)"
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
        Request::TraceSet { directive } => match directive {
            Some(d) => match crate::log::set_trace_directive(&d) {
                Ok(active) => {
                    let default = crate::log::trace_directives()
                        .map(|(_, def)| def)
                        .unwrap_or_default();
                    Response::TraceSet { active, default }
                }
                Err(msg) => Response::Error {
                    code: error_codes::INVALID_REQUEST.into(),
                    message: format!("invalid tracing directive: {msg}"),
                },
            },
            None => match crate::log::reset_trace_directive() {
                Ok(active) => {
                    let default = active.clone();
                    Response::TraceSet { active, default }
                }
                Err(msg) => Response::Error {
                    code: error_codes::INTERNAL_ERROR.into(),
                    message: format!("could not reset tracing filter: {msg}"),
                },
            },
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
/// 3. If the daemon has a chain upstream
///    (`state.has_chain_upstream`), project the rule set through
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
    let (predicate_count, skipped_https) = if state.has_chain_upstream {
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

/// Async dispatch for [`Request::ChainSummary`]. Always returns at
/// least the local hop. When a chain-client handle is wired
/// (i.e. this node has `[dial]`), forwards a `ChainHopQuery`
/// upstream and aggregates the upstream hops into the response.
///
/// Caller-supplied `timeout_ms` caps the wait on the upstream walk.
/// Falls back to `5_000` ms when zero/absent. On any upstream error
/// (timeout, encode failure, client-down) the local hop is still
/// returned with `partial = true`.
async fn dispatch_chain_summary(timeout_ms: Option<u64>, state: &ControlState) -> Response {
    let ix = match state.introspection.as_ref() {
        Some(ix) => ix,
        None => {
            return Response::Error {
                code: error_codes::INTERNAL_ERROR.into(),
                message: "introspection state not configured for this daemon".into(),
            };
        }
    };
    let local = ChainHop {
        hop_index: 0,
        mode: state.mode,
        uptime_secs: state.started_at.elapsed().as_secs(),
        view: ix.snapshot(),
        query_rtt_ms: None,
    };

    let upstream = match state.chain_client_handle.as_ref() {
        Some(h) => h,
        None => {
            return Response::ChainSummary(ChainSummaryResponse {
                hops: vec![local],
                partial: false,
            });
        }
    };

    let deadline_ms = timeout_ms
        .filter(|m| *m > 0)
        .unwrap_or(ratatoskr::chain_query::CHAIN_HOP_DEFAULT_DEADLINE_MS as u64);
    let deadline = std::time::Duration::from_millis(deadline_ms);
    let started = std::time::Instant::now();
    match upstream
        .query_upstream(
            ratatoskr::chain_query::CHAIN_HOP_DEFAULT_DEPTH_BUDGET,
            deadline,
        )
        .await
    {
        Ok(reply) => {
            let rtt_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
            let mut hops = vec![local];
            for (offset, mut hop) in reply.hops.into_iter().enumerate() {
                hop.hop_index = (hops.len() + offset) as u32;
                // Stamp the RTT we just measured on the immediately
                // adjacent upstream hop (offset == 0). Hops further
                // upstream were already RTT-stamped by the relay that
                // queried them recursively.
                if offset == 0 {
                    hop.query_rtt_ms = Some(rtt_ms);
                }
                hops.push(hop);
            }
            Response::ChainSummary(ChainSummaryResponse {
                hops,
                partial: reply.partial,
            })
        }
        Err(e) => {
            tracing::warn!(error = %e, "chain summary upstream walk failed; returning local only");
            Response::ChainSummary(ChainSummaryResponse {
                hops: vec![local],
                partial: true,
            })
        }
    }
}

/// Default budget for `dispatch_rules_reload`. Bounded so a stuck
/// watcher worker can never hang the control socket; on timeout we
/// fall back to reporting the current snapshot count.
const RULES_RELOAD_BLOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Follow-on grace window after the watcher signals completion, used
/// to also wait for the supervisor's snapshot publication when the
/// reload was non-noop. Noop reloads don't update the snapshot at
/// all, so we time out cheaply and proceed.
const RULES_RELOAD_SNAPSHOT_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// Async dispatch for [`Request::RulesReload`]. Triggers a reload and
/// blocks until both the watcher has drained the trigger and (when
/// applicable) the supervisor has published its post-swap snapshot,
/// then returns the resulting rule count.
///
/// CP31 (config-UX plan): the previous synchronous dispatch returned
/// the *pre-reload* count and let the swap race the operator's next
/// command. Blocking here removes that race; subsequent
/// `RulesList`/`Status` calls observe the new set.
///
/// Two-phase wait:
///   1. `force_reload_and_wait` — watcher drains the trigger.
///   2. `snapshot_rx.changed()` with a short grace — supervisor
///      publishes the new snapshot if the reload was non-noop.
///      Noop reloads time out cheaply (no snapshot change) and we
///      proceed to read the current count, which is already correct.
///
/// On watcher timeout we still return a `RulesReloaded` response with
/// whatever count is currently in the snapshot, plus a warning log.
/// Returning an error here would force operators to retry harmlessly
/// in the common no-actionable-failure case.
async fn dispatch_rules_reload(state: &ControlState) -> Response {
    let mut snapshot_rx = state.snapshot_rx.clone();
    snapshot_rx.borrow_and_update();

    let watcher_outcome = state
        .reload_trigger
        .force_reload_and_wait(RULES_RELOAD_BLOCK_TIMEOUT)
        .await;
    if watcher_outcome.is_err() {
        tracing::warn!(
            timeout = ?RULES_RELOAD_BLOCK_TIMEOUT,
            "rules reload watcher did not complete within budget; \
             returning current snapshot count"
        );
    }

    // Best-effort wait for the supervisor's snapshot publication. A
    // timeout here is the expected outcome on no-op reloads (no
    // snapshot change to observe) and is not an error.
    let _ = tokio::time::timeout(RULES_RELOAD_SNAPSHOT_GRACE, snapshot_rx.changed()).await;

    let reloaded_rule_count = state.snapshot_rx.borrow().len();
    Response::RulesReloaded {
        reloaded_rule_count,
    }
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

fn approve_downstream(state: &ControlState, fingerprint: &str) -> Response {
    let (peer_state, pending_store) = match (&state.peer_state, &state.pending_store) {
        (Some(ps), Some(store)) => (ps, store),
        _ => return terminal_mode_unsupported("downstream approve"),
    };
    let (resolved_fp, key) = match pending_store.approve(fingerprint) {
        Ok(crate::pending_peers::ApproveOutcome::Approved { fingerprint, key }) => {
            (fingerprint, key)
        }
        Ok(crate::pending_peers::ApproveOutcome::NotFound) => {
            return Response::Error {
                code: error_codes::NO_SUCH_FINGERPRINT.into(),
                message: format!("no pending candidate matches fingerprint prefix {fingerprint:?}"),
            };
        }
        Ok(crate::pending_peers::ApproveOutcome::Ambiguous { matches }) => {
            return Response::Error {
                code: error_codes::AMBIGUOUS_FINGERPRINT.into(),
                message: format!(
                    "fingerprint prefix {fingerprint:?} is ambiguous; matches {} candidates: {}. \
                     Re-run `local accept approve` with a longer prefix.",
                    matches.len(),
                    matches.join(", ")
                ),
            };
        }
        Ok(crate::pending_peers::ApproveOutcome::PrefixTooShort { provided, required }) => {
            return Response::Error {
                code: error_codes::AMBIGUOUS_FINGERPRINT.into(),
                message: format!(
                    "fingerprint prefix {fingerprint:?} is too short ({provided} hex chars); \
                     a minimum of {required} hex chars is required to disambiguate."
                ),
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
        fingerprint = %resolved_fp,
        "downstream approved via control surface; key is now live"
    );
    Response::DownstreamApproved {
        fingerprint: resolved_fp,
    }
}

/// Atomic rewrite of `[accept].pubkey` in `config_path`. Round-trips
/// the file through `toml::Value` so other keys are preserved (formatting
/// and comments are lost — acceptable trade-off; explicit `*.tmp` + rename
/// keeps the change crash-safe).
fn update_downstream_pubkey(config_path: &Path, tagged_pubkey: &str) -> Result<()> {
    let text = std::fs::read_to_string(config_path)
        .with_context(|| format!("read {}", config_path.display()))?;
    let mut doc: toml::Value = text
        .parse()
        .with_context(|| format!("parse {}", config_path.display()))?;
    let table = doc
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("{} is not a TOML table", config_path.display()))?;
    let accept_entry = table
        .entry("accept".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
    let accept_table = accept_entry
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("`accept` in {} is not a table", config_path.display()))?;
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
        std::fs::write(&config_path, "[server]\nidentity_file = \"/tmp/id.key\"\n").unwrap();
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
            false,
            crate::metrics::detached_handle_for_tests(),
            None,
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
        let (supervisor, peer_state, shutdown) = make_supervisor_with_enrolled(&rules, true).await;
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
        let (supervisor, peer_state, shutdown) = make_supervisor_with_enrolled(&rules, true).await;
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
    async fn status_reports_zero_certs_when_no_https_rules_loaded() {
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
                assert_eq!(s.ephemeral_cert_count, 0);
                assert!(s.default_cert_path.is_none());
                assert!(s.default_cert_loaded_age_secs.is_none());
            }
            other => panic!("unexpected response: {other:?}"),
        }

        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    /// `Request::Metrics` renders the Prometheus text exposition from the
    /// installed handle. `detached_handle_for_tests` produces an empty
    /// body (no recorder installed in tests); we're verifying the
    /// dispatch path renders without panicking and the response shape
    /// is well-formed.
    #[tokio::test]
    async fn metrics_endpoint_renders_prometheus_text() {
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

        let resp = send_request(&socket, &Request::Metrics).await;
        match resp {
            Response::Metrics(m) => {
                assert!(
                    m.body.is_empty() || m.body.ends_with('\n'),
                    "expected empty or newline-terminated body, got: {:?}",
                    m.body
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    /// `Request::Health` reports `ready = true` after `mark_ready` has
    /// been called. The flag is process-global and one-way; previous
    /// tests in this binary may already have flipped it, but after our
    /// `mark_ready` call the contract holds unconditionally.
    #[tokio::test]
    async fn health_endpoint_reports_ready_after_mark_ready() {
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

        crate::health::mark_ready();

        let resp = send_request(&socket, &Request::Health).await;
        match resp {
            Response::Health(h) => {
                assert!(h.ready, "health endpoint should report ready=true");
                // Sanity: uptime should be small; we just bound the server.
                assert!(h.uptime_secs < 3600);
            }
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    /// `Request::DerivedRules` returns the introspection snapshot when
    /// the control server has one wired. The wire path here is the
    /// counterpart to `chain_introspection_e2e.rs`, which exercises
    /// `IntrospectionState::snapshot()` directly without going through
    /// the UDS dispatcher.
    #[tokio::test]
    async fn derived_rules_endpoint_returns_snapshot_when_introspection_wired() {
        use ratatoskr::pubkey::PubKey;

        let tmp = tempfile::tempdir().unwrap();
        let rules = tmp.path().join("rules");
        let (supervisor, peer_state, shutdown) = make_supervisor(&rules).await;
        let socket = tmp.path().join("control.sock");
        let (pending, cfg) = aux_state(tmp.path());

        let local = PubKey::x25519([0x11; 32]);
        let introspection = crate::chain::IntrospectionState::new(
            local,
            Some(PubKey::x25519([0x22; 32])),
            None,
            supervisor.handle(),
        );

        let server = ControlServer::bind(
            socket.clone(),
            Mode::Relay,
            Some(peer_state.clone()),
            &supervisor,
            Some(pending),
            cfg,
            false,
            crate::metrics::detached_handle_for_tests(),
            Some(introspection),
            None,
            shutdown.clone(),
        )
        .await
        .unwrap();

        let resp = send_request(&socket, &Request::DerivedRules).await;
        match resp {
            Response::DerivedRules(d) => {
                assert!(d.predicates.is_empty(), "no apply yet");
                assert!(d.derived_rules.is_empty(), "no rules loaded");
                assert_eq!(d.chain.local, local);
                assert!(d.chain.predicate_origin.is_none());
                assert!(d.chain.predicate_version.is_none());
                assert!(d.chain.last_apply_unix.is_none());
            }
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    /// `Request::DerivedRules` on a server with no introspection state
    /// reports `INTERNAL_ERROR` via the dispatcher's defensive arm.
    /// `bind_relay_control` passes `None` for introspection, which is
    /// the configuration tests want here.
    #[tokio::test]
    async fn derived_rules_endpoint_errors_when_introspection_absent() {
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

        let resp = send_request(&socket, &Request::DerivedRules).await;
        match resp {
            Response::Error { code, .. } => {
                assert_eq!(code, error_codes::INTERNAL_ERROR);
            }
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    /// `Request::TraceSet` with an invalid directive returns
    /// `INVALID_REQUEST`. The dispatcher's two failure modes
    /// (`EnvFilter::try_new` parse error and "tracing not initialised")
    /// both land on the same error code, so this test is robust to
    /// whether a sibling test has already installed the global
    /// subscriber.
    #[tokio::test]
    async fn trace_set_with_invalid_directive_returns_invalid_request() {
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

        // Best-effort init so `EnvFilter::try_new` is the error source.
        // If a sibling test already installed a subscriber, this call
        // returns Err but `TRACE_CONTROLLER` is already set by that
        // test — the dispatcher lands on the same INVALID_REQUEST code
        // either way.
        let _ = crate::log::init_tracing(crate::cli::LogFormat::Pretty);

        let resp = send_request(
            &socket,
            &Request::TraceSet {
                directive: Some("= not a valid filter =".to_string()),
            },
        )
        .await;
        match resp {
            Response::Error { code, message } => {
                assert_eq!(code, error_codes::INVALID_REQUEST);
                assert!(
                    message.contains("tracing directive"),
                    "expected directive error message, got: {message}"
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }
}
