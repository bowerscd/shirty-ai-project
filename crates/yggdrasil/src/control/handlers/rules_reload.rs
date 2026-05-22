//! Async dispatch for [`ratatoskr::control::Request::RulesReload`].
//!
//! Split out from the original monolithic `control.rs` (Phase B2).

use std::time::Duration;

use ratatoskr::control::Response;

use super::super::ControlState;

/// Default budget for [`dispatch_rules_reload`]. Bounded so a stuck
/// watcher worker can never hang the control socket; on timeout we
/// fall back to reporting the current snapshot count.
const RULES_RELOAD_BLOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// Follow-on grace window after the watcher signals completion, used
/// to also wait for the supervisor's snapshot publication when the
/// reload was non-noop. Noop reloads don't update the snapshot at
/// all, so we time out cheaply and proceed.
const RULES_RELOAD_SNAPSHOT_GRACE: Duration = Duration::from_millis(500);

/// Async dispatch for `Request::RulesReload`. Triggers a reload and
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
pub(in crate::control) async fn dispatch_rules_reload(state: &ControlState) -> Response {
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
