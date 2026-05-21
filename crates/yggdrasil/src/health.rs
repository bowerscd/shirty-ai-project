//! Readiness signaling for the `Request::Health` UDS handler exposed by
//! [`crate::control`].
//!
//! ## Why a separate flag from `sd_notify`?
//!
//! [`crate::systemd::notify_ready`] tells *systemd* the daemon is up, which
//! it does by writing `READY=1` to a unix datagram socket. That works for
//! init systems but doesn't help process-external probes (kubelet,
//! load-balancer health checks, `wait_for_service.sh` scripts, etc.) that
//! reach the daemon through `yggdrasilctl local health`.
//!
//! This module mirrors the same fact in a process-local
//! [`AtomicBool`](std::sync::atomic::AtomicBool) so the control-socket
//! `Health` handler can serve it. The flag flips to `true` at exactly the
//! same point [`crate::systemd::notify_ready`] is called — after the
//! heartbeat socket (relay only), proxy supervisor's initial rule load,
//! and UDS control socket have all bound.
//!
//! Readiness is one-way: there is no `mark_unready`. If a critical
//! subsystem fails *after* startup we crash and rely on the supervisor
//! (systemd / Kubernetes / docker `restart=always`) to relaunch us. That
//! matches the existing failure model — there is no in-flight degraded
//! mode.

use std::sync::atomic::{AtomicBool, Ordering};

static READY: AtomicBool = AtomicBool::new(false);

/// Mark the daemon as ready. Subsequent `yggdrasilctl local health`
/// probes will report `ready = true`. Idempotent — calling more than
/// once is harmless.
pub fn mark_ready() {
    READY.store(true, Ordering::Release);
}

/// Returns whether the daemon has signaled readiness yet. `false` from
/// process start until [`mark_ready`] is called.
pub fn is_ready() -> bool {
    READY.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `is_ready()` is `false` until `mark_ready()` is called, and `true`
    /// afterwards. We can't easily reset the static between tests, so this
    /// is the one test we run on the flag's lifecycle in isolation.
    #[test]
    fn ready_flag_flips_on_mark() {
        // We're racing against other tests in the same process that may
        // call mark_ready, so we can't assert a starting state of false.
        // Just check that after mark_ready, is_ready() returns true.
        mark_ready();
        assert!(is_ready());
    }
}
