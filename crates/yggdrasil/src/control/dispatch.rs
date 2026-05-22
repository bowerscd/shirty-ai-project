//! Synchronous request → response dispatcher for the simple verbs
//! (Status, RulesList, Downstream{Show,Pending,Approve}, Metrics, Health,
//! DerivedRules, TraceSet). Async verbs (`ChainApply`, `ChainSummary`,
//! `RulesReload`) are hoisted to dedicated handlers under `handlers/`
//! by `server::handle_connection`.
//!
//! Split out from the original monolithic `control.rs` (Phase B2).

use std::time::{SystemTime, UNIX_EPOCH};

use ratatoskr::auth::public_key_fingerprint;
use ratatoskr::control::{
    error_codes, DownstreamResponse, HealthResponse, MetricsResponse, PendingResponse, Request,
    Response, RuleInfo, RulesResponse, StatusResponse,
};
use ratatoskr::pubkey::PubKey;

use super::handlers::{approve_downstream, terminal_mode_unsupported};
use super::ControlState;

/// Dispatcher for synchronous control requests.
pub(super) fn dispatch(req: Request, state: &ControlState) -> Response {
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
        // `ChainApply` is handled by [`super::handlers::dispatch_chain_apply`]
        // in [`super::server::handle_connection`]: the apply path is async
        // because [`crate::proxy::supervisor::SupervisorHandle::apply_ruleset`]
        // awaits a channel send, and this synchronous dispatch table can't.
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
        Request::AcmeList => super::handlers::dispatch_acme_list(state),
        Request::AcmeRenew { .. } => Response::Error {
            code: error_codes::INTERNAL_ERROR.into(),
            message: "internal routing error: AcmeRenew reached \
                      the synchronous dispatcher (should have been \
                      hoisted by handle_connection)"
                .to_string(),
        },
    }
}
