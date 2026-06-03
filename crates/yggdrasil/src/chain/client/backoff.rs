//! Backoff constants and the cancel-aware sleep helper used by the
//! reconnect loop.
//!

use std::time::Duration;

use tokio_util::sync::CancellationToken;

pub(super) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const BACKOFF_MIN: Duration = Duration::from_millis(500);
pub(super) const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// If we go this many heartbeat intervals without seeing an ACK, give up
/// on the current session and re-handshake.
///
/// This is a **backstop** — the active path is the fast-probe machinery
/// in [`super::run_loop::heartbeat_loop`], which under steady-state
/// packet loss bails at roughly
/// `(FAST_PROBE_AFTER_MULTIPLIER + FAST_PROBE_DEADLINE_MULTIPLIER) ×
/// heartbeat_interval`. Detection at this multiplier should never
/// actually fire unless the probe-send itself fails or the loop is
/// pathologically starved.
pub(super) const ACK_DEADLINE_MULTIPLIER: u32 = 6;
/// Number of heartbeat intervals of silence after the last ACK before
/// we send a one-off fast probe. The fast probe is just an extra
/// heartbeat fired immediately (no new wire shape), so the server
/// acks it normally; receipt clears the probe deadline and resets the
/// liveness state.
///
/// Tuned for "two missed heartbeats are interesting, three is dead":
/// at the default `heartbeat_interval = 5s` this is 10s before the
/// extra probe goes out.
pub(super) const FAST_PROBE_AFTER_MULTIPLIER: u32 = 2;
/// Number of heartbeat intervals after the fast probe was sent before
/// we declare the session dead. If the probe ACK arrives in that
/// window, the deadline is cancelled and the session continues
/// normally.
///
/// Combined detection latency (probe-trigger + probe-deadline) is
/// `(FAST_PROBE_AFTER_MULTIPLIER + FAST_PROBE_DEADLINE_MULTIPLIER) ×
/// heartbeat_interval = 15s` at default heartbeat. The pre-fix
/// behaviour waited the full `ACK_DEADLINE_MULTIPLIER × heartbeat
/// = 30s` instead.
pub(super) const FAST_PROBE_DEADLINE_MULTIPLIER: u32 = 1;

/// Returns `true` if the cancel token fired before the sleep completed.
pub(super) async fn sleep_or_cancel(cancel: &CancellationToken, dur: Duration) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => true,
        _ = tokio::time::sleep(dur) => false,
    }
}
