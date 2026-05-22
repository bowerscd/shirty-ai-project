//! systemd `sd_notify` readiness integration.
//!
//! yggdrasil's startup is *not* atomic — the metrics exporter, heartbeat
//! socket, proxy supervisor (which performs its initial rule load
//! synchronously, see [`ProxySupervisor::spawn`]), and the UDS control
//! socket all bind in sequence inside [`run_relay`] / [`run_terminal`].
//! Until all four are up the daemon is not actually serving traffic.
//!
//! The right place to signal `READY=1` is *after* the last of those bindings
//! succeeds. Pairing the unit file with `Type=notify` then gives operators:
//!
//! * `systemctl is-active` semantics that match reality (not "the process
//!   started" but "the process is serving").
//! * Correct ordering against `After=yggdrasil.service` dependents.
//! * `TimeoutStartSec=` actually meaning what it says.
//!
//! When the daemon is *not* running under systemd (i.e. `NOTIFY_SOCKET` is
//! unset) the [`sd_notify`] call is a no-op. Errors writing to the socket
//! are logged at warn and swallowed — systemd integration must never block
//! or fail startup.
//!
//! ## Reload contract (`Type=notify-reload`)
//!
//! When `systemctl reload yggdrasil` is invoked, systemd sends SIGHUP to
//! the main PID. The daemon then:
//!
//! 1. emits `RELOADING=1` *and* `MONOTONIC_USEC=<n>` before starting the
//!    reload work, where `n` is the current monotonic-clock value in
//!    microseconds (see [`notify_reloading`]);
//! 2. performs the reload (in our case: the rule-watcher + supervisor
//!    reconcile pipeline);
//! 3. emits `READY=1` after the reload settles (see
//!    [`notify_ready_after_reload`]).
//!
//! systemd uses the `MONOTONIC_USEC` value to disambiguate the matching
//! `READY=1` from a stale one — without it, the reload would silently
//! fail with EPROTO. Both helpers are no-ops when `NOTIFY_SOCKET` is unset.
//!
//! [`ProxySupervisor::spawn`]: crate::proxy::supervisor::ProxySupervisor::spawn
//! [`run_relay`]: crate::run_relay
//! [`run_terminal`]: crate::run_terminal

/// Send `READY=1` to systemd. No-op when `NOTIFY_SOCKET` is unset.
///
/// `unset_env = true` clears `NOTIFY_SOCKET` from this process's environment
/// after the notification fires, so any child process we spawn later cannot
/// accidentally inherit the socket and confuse systemd by sending its own
/// ready signal.
pub fn notify_ready() {
    match sd_notify::notify(true, &[sd_notify::NotifyState::Ready]) {
        Ok(()) => tracing::debug!("sent sd_notify READY=1"),
        Err(e) => tracing::warn!(error = %e, "sd_notify READY=1 failed; continuing"),
    }
}

/// Send `STATUS=...` and `READY=1` together so `systemctl status` shows the
/// effective runtime shape (`mode=..., dial=..., accept=...`) at startup.
pub fn notify_ready_with_status(status: &str) {
    match sd_notify::notify(
        true,
        &[
            sd_notify::NotifyState::Status(status),
            sd_notify::NotifyState::Ready,
        ],
    ) {
        Ok(()) => tracing::debug!(status, "sent sd_notify STATUS + READY=1"),
        Err(e) => tracing::warn!(error = %e, "sd_notify STATUS + READY=1 failed; continuing"),
    }
}

/// Send `RELOADING=1` plus `MONOTONIC_USEC=<n>` to systemd. Required by
/// `Type=notify-reload` units before the daemon begins reload work.
///
/// `unset_env = false` because the supervisor is still running and may
/// reload again later; we don't want to forget the socket path between
/// reloads.
///
/// No-op when `NOTIFY_SOCKET` is unset.
pub fn notify_reloading() {
    let usec = match sd_notify::NotifyState::monotonic_usec_now() {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "could not read monotonic clock; skipping RELOADING=1");
            return;
        }
    };
    match sd_notify::notify(false, &[sd_notify::NotifyState::Reloading, usec]) {
        Ok(()) => tracing::debug!("sent sd_notify RELOADING=1 + MONOTONIC_USEC"),
        Err(e) => tracing::warn!(error = %e, "sd_notify RELOADING failed; continuing"),
    }
}

/// Send `READY=1` after a reload completes. Distinct from
/// [`notify_ready`] only in that it preserves `NOTIFY_SOCKET` for the
/// next reload (the daemon is still running).
///
/// No-op when `NOTIFY_SOCKET` is unset.
pub fn notify_ready_after_reload() {
    match sd_notify::notify(false, &[sd_notify::NotifyState::Ready]) {
        Ok(()) => tracing::debug!("sent sd_notify READY=1 (post-reload)"),
        Err(e) => tracing::warn!(error = %e, "sd_notify READY=1 (post-reload) failed; continuing"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// When `NOTIFY_SOCKET` is unset the notify call must be a silent no-op
    /// (returns `Ok(())` from the underlying crate). Anything else would
    /// break local `cargo run` workflows.
    #[test]
    fn notify_ready_is_noop_without_notify_socket() {
        // The test runner inherits the developer's environment, so be
        // defensive — explicitly remove the variable for the duration of
        // this test.
        // SAFETY: tests in this module are not run in parallel with code
        // that reads NOTIFY_SOCKET; the only reader is `sd_notify::notify`
        // invoked inside `notify_ready` below.
        unsafe { std::env::remove_var("NOTIFY_SOCKET") };
        notify_ready();
        notify_ready_with_status("mode=relay, accept=yes, dial=no");
        notify_reloading();
        notify_ready_after_reload();
    }
}
