//! Async handlers for the control verbs that need to `await` (chain
//! apply, chain summary, rules reload) plus the downstream-approve flow
//! (which is synchronous but big enough to warrant its own file).
//!
//! Split out from the original monolithic `control.rs` (Phase B2).

pub(super) mod accept;
pub(super) mod acme;
pub(super) mod canary;
pub(super) mod chain;
pub(super) mod rules_reload;

pub(super) use accept::approve_downstream;
pub(super) use acme::{dispatch_acme_list, dispatch_acme_renew};
pub(super) use canary::dispatch_chain_canary;
pub(super) use chain::{dispatch_chain_apply, dispatch_chain_summary};
pub(super) use rules_reload::dispatch_rules_reload;

use ratatoskr::control::{error_codes, Response};

/// Build the canonical "not supported in terminal mode" error response.
pub(super) fn terminal_mode_unsupported(verb: &str) -> Response {
    Response::Error {
        code: error_codes::NOT_SUPPORTED_IN_TERMINAL_MODE.into(),
        message: format!(
            "`{verb}` is not supported on a terminal-mode daemon \
             (terminal daemons have no downstream identity)"
        ),
    }
}
