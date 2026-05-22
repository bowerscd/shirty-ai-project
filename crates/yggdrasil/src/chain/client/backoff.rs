//! Backoff constants and the cancel-aware sleep helper used by the
//! reconnect loop.
//!
//! Split out from the original monolithic `client.rs` (Phase B6).

use std::time::Duration;

use tokio_util::sync::CancellationToken;

pub(super) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const BACKOFF_MIN: Duration = Duration::from_millis(500);
pub(super) const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// If we go this many heartbeat intervals without seeing an ACK, give up
/// on the current session and re-handshake.
pub(super) const ACK_DEADLINE_MULTIPLIER: u32 = 6;

/// Returns `true` if the cancel token fired before the sleep completed.
pub(super) async fn sleep_or_cancel(cancel: &CancellationToken, dur: Duration) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => true,
        _ = tokio::time::sleep(dur) => false,
    }
}
