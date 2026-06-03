//! Async dispatchers for `Request::ChainApply` and `Request::ChainSummary`.
//!

use ratatoskr::control::{
    error_codes, ChainAppliedResponse, ChainHop, ChainSummaryResponse, Response,
};
use ratatoskr::predicate::PREDICATE_SET_MAX_WIRE_BYTES;
use ratatoskr::pubkey::PubKey;
use ratatoskr::rule::{Rule, RuleSet};

use crate::chain::predicate_extractor;

use super::super::ControlState;

/// Async dispatch for [`ratatoskr::control::Request::ChainApply`]. Hoisted
/// out of the synchronous dispatch table because
/// [`crate::proxy::supervisor::SupervisorHandle::apply_ruleset`] awaits
/// an mpsc channel send.
///
/// Flow:
/// 1. Validate the candidate vector by constructing a [`RuleSet`]; this
///    runs the same per-rule + cross-rule checks the file-watch reload
///    runs ([`error_codes::RULES_INVALID`]).
/// 2. If the daemon has a chain upstream
///    (`state.has_chain_upstream`), project the rule set through
///    [`predicate_extractor::extract`] and postcard-encode it. If the
///    encoded body would exceed
///    [`PREDICATE_SET_MAX_WIRE_BYTES`], refuse synchronously
///    ([`error_codes::PREDICATE_SET_OVERSIZE`]) — without this guard
///    the apply would "succeed" here but the publisher would silently
///    drop the push.
/// 3. Hand the [`RuleSet`] to
///    [`crate::proxy::supervisor::SupervisorHandle::apply_ruleset`].
///    The handle's `apply_tx` enqueues the set onto the supervisor
///    task; actual diff + listener mutation happens on that task. We
///    return once the push is *enqueued*, not once it has been applied.
pub(in crate::control) async fn dispatch_chain_apply(
    rules: Vec<Rule>,
    state: &ControlState,
) -> Response {
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
    let predicate_count = if state.has_chain_upstream {
        // The pre-check is sizing-only; the origin and version don't
        // affect whether the body fits under the cap (origin is 32B,
        // version is 8B; both are constant-sized regardless of value).
        // The publisher will project again with the real origin and
        // monotonic version on its next tick.
        let outcome = predicate_extractor::extract(
            &ruleset,
            predicate_extractor::HttpsPredicateMeta::default(),
            PubKey::x25519([0u8; 32]),
            0,
        );
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
        outcome.set.predicates.len()
    } else {
        0usize
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
        "chain apply enqueued via control surface"
    );

    Response::ChainApplied(ChainAppliedResponse {
        applied_rule_count,
        predicate_count,
    })
}

/// Async dispatch for [`ratatoskr::control::Request::ChainSummary`].
/// Always returns at least the local hop. When a chain-client handle
/// is wired (i.e. this node has `[dial]`), forwards a `ChainHopQuery`
/// upstream and aggregates the upstream hops into the response.
///
/// Caller-supplied `timeout_ms` caps the wait on the upstream walk.
/// Falls back to `CHAIN_HOP_DEFAULT_DEADLINE_MS` when zero/absent. On
/// any upstream error (timeout, encode failure, client-down) the local
/// hop is still returned with `partial = true`.
pub(in crate::control) async fn dispatch_chain_summary(
    timeout_ms: Option<u64>,
    state: &ControlState,
) -> Response {
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
        name: Some(state.node_name.clone()),
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
