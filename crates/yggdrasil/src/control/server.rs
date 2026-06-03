//! UDS accept loop and per-connection request reader/writer.
//!

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::sync::CancellationToken;

use ratatoskr::control::{error_codes, Request, Response};

use super::handlers::{
    dispatch_chain_apply, dispatch_chain_canary, dispatch_chain_reconnect, dispatch_chain_summary,
    dispatch_rules_reload,
};
use super::{dispatch, ControlState};

pub(super) async fn accept_loop(
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
                let response = match serde_json::from_str::<Request>(line.trim()) {
                    Ok(req) => dispatch_request(req, &state).await,
                    Err(e) => Response::Error {
                        code: error_codes::INVALID_REQUEST.into(),
                        message: format!("could not parse request as JSON: {e}"),
                    },
                };
                let mut buf = serde_json::to_vec(&response).context("encode response")?;
                buf.push(b'\n');
                writer.write_all(&buf).await.context("write response")?;
            }
        }
    }
}

async fn dispatch_request(req: Request, state: &ControlState) -> Response {
    if let Some(method) = terminal_only_method(&req) {
        if state.mode != ratatoskr::control::Mode::Terminal {
            return method_not_available_on_mode(method, state.mode);
        }
    }

    match req {
        Request::ChainApply { rules } => {
            // ChainApply needs `supervisor_handle.apply_ruleset`
            // which is async; the synchronous `dispatch` table can't
            // await. Route it here. The defensive arm in `dispatch`
            // returns INTERNAL_ERROR if routing slips.
            dispatch_chain_apply(rules, state).await
        }
        Request::AcmeRenew { hostname } => {
            // Same shape as ChainApply: the daemon may block for many
            // seconds while the ACME flow runs.
            super::handlers::dispatch_acme_renew(&hostname, state).await
        }
        Request::ChainSummary { timeout_ms } => {
            // ChainSummary may walk via `ChainClientHandle::query_upstream`,
            // which is async; route it like ChainApply.
            dispatch_chain_summary(timeout_ms, state).await
        }
        Request::ChainReconnect => {
            // Sync (notify-only) but lives in the async dispatcher so
            // all chain-affined surface is wired in one place. The
            // handler itself does no awaits — the per-request
            // refusal-vs-deliver branch is the `chain_client_handle`
            // presence check.
            dispatch_chain_reconnect(state)
        }
        Request::RulesReload => {
            // CP31: block until the watcher has drained the trigger and
            // (if the set changed) the supervisor has applied it. Returns
            // the post-reload count.
            dispatch_rules_reload(state).await
        }
        Request::ChainCanary {
            rule_listen,
            rule_protocol,
            duration_ms,
            rate,
            payload_bytes,
            timeout_ms,
        } => {
            // Canary runs an arm-phase RPC up the chain and then drives a
            // real L4 probe through the rule's listener; both phases await
            // across the network, so it's hoisted out of the sync dispatcher.
            dispatch_chain_canary(
                rule_listen,
                rule_protocol,
                duration_ms,
                rate,
                payload_bytes,
                timeout_ms,
                state,
            )
            .await
        }
        req => dispatch(req, state),
    }
}

fn terminal_only_method(req: &Request) -> Option<&'static str> {
    match req {
        Request::ChainApply { .. } => Some("chain apply"),
        Request::RulesReload => Some("local rules reload"),
        Request::AcmeList => Some("local acme list"),
        Request::AcmeRenew { .. } => Some("local acme renew"),
        _ => None,
    }
}

fn method_not_available_on_mode(method: &str, mode: ratatoskr::control::Mode) -> Response {
    Response::Error {
        code: error_codes::METHOD_NOT_AVAILABLE_ON_MODE.into(),
        message: format!(
            "`{method}` is not available on {}-mode daemons; \
             this method requires a terminal-mode daemon",
            mode.as_str(),
        ),
    }
}
