//! UDS accept loop and per-connection request reader/writer.
//!

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::sync::CancellationToken;

use ratatoskr::control::{error_codes, Request, Response};

use super::handlers::{
    dispatch_chain_apply, dispatch_chain_canary, dispatch_chain_summary, dispatch_rules_reload,
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
                    Ok(Request::AcmeRenew { hostname }) => {
                        // Same shape as ChainApply: the daemon may
                        // block for many seconds while the ACME flow
                        // runs.
                        let response = super::handlers::dispatch_acme_renew(&hostname, &state).await;
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
                    Ok(Request::ChainCanary {
                        rule_listen,
                        rule_protocol,
                        duration_ms,
                        rate,
                        payload_bytes,
                        timeout_ms,
                    }) => {
                        // Canary runs an arm-phase RPC up the chain and
                        // then drives a real L4 probe through the rule's
                        // listener; both phases await across the network,
                        // so it's hoisted out of the sync dispatcher.
                        let response = dispatch_chain_canary(
                            rule_listen,
                            rule_protocol,
                            duration_ms,
                            rate,
                            payload_bytes,
                            timeout_ms,
                            &state,
                        )
                        .await;
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
