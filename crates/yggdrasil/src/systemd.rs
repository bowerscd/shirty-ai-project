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
    }
}
