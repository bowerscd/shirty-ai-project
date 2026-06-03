//! Outbound chain control client.
//!
//! Every node — relay or terminal — that declares `[dial]` in its
//! config dials that upstream over UDP and maintains a single Noise_IK
//! session, emitting an authenticated heartbeat every `heartbeat_interval`.
//! Re-handshakes every `rekey_interval`. On any transport / decode error
//! the client sleeps with exponential backoff and re-resolves the
//! endpoint, so an upstream restart (or upstream IP change) recovers
//! automatically.
//!
//! ## Concurrency
//!
//! The whole client runs on one task: `tokio::select!` between the cancel
//! token, the heartbeat ticker, the control-channel retransmit timer, the
//! caller-side control-send queue, and the UDP recv arm. No locking, no
//! shared mutable state, no rendezvous — the heartbeat [`Session`] and
//! [`ControlChannel`] are exclusively owned by the loop.
//!
//! ## Control channel
//!
//! The loop owns a per-session [`ControlChannel`] that sequences,
//! retransmits, and dedups `Control` / `ControlAck` packets. The
//! client task pulls outbound sends from an `mpsc` fed by callers
//! holding a [`ChainClientHandle`], and dispatches inbound envelopes
//! through an optional [`BodyHandler`] (production default: ack
//! everything `Unknown`).
//!
//! ## Module layout
//!
//! - [`backoff`] — reconnect-loop constants + cancel-aware sleep helper.
//! - [`body_handler`] — `BodyHandler` typedef plus the externally-facing
//!   `ChainClientHandle` / `ControlOp` / `QueryError` / `ChainClientShutDown`.
//! - [`handshake`] — Noise_IK initiator dance + endpoint resolution.
//! - [`run_loop`] — `run_session_once` + the central `tokio::select!`
//!   heartbeat loop + body dispatch.
//!
//! [`ControlChannel`]: crate::chain::reliability::ControlChannel
//! [`Session`]: ratatoskr::auth::Session

mod backoff;
mod body_handler;
mod handshake;
mod run_loop;

#[cfg(test)]
mod tests;

pub use body_handler::{
    BodyHandler, ChainClientHandle, ChainClientShutDown, ControlOp, QueryError,
};

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::{mpsc, watch, Notify};
use tokio_util::sync::CancellationToken;

use ratatoskr::auth::StaticKeyPair;
use ratatoskr::pubkey::PubKey;

use crate::chain::query_router::QueryRouter;

use self::backoff::{sleep_or_cancel, BACKOFF_MAX, BACKOFF_MIN};
use self::run_loop::SessionExit;

/// Static configuration of the chain client.
pub struct ChainClientConfig {
    /// `host:port` (or `[ipv6]:port`) of the upstream node.
    pub endpoint: String,
    /// Tagged pubkey of the upstream — what Noise_IK pins.
    pub upstream_pubkey: PubKey,
    /// This node's static identity.
    pub local_keys: StaticKeyPair,
    pub heartbeat_interval: Duration,
    pub rekey_interval: Duration,
    /// Optional dispatcher for delivered control envelopes. `None` →
    /// every inbound envelope acks [`ratatoskr::control_frame::AckStatus::Unknown`].
    pub body_handler: Option<BodyHandler>,
    /// Optional source IP for the outbound UDP socket. When `None`, the
    /// client binds the wildcard (`0.0.0.0:0` / `[::]:0`) and the kernel
    /// picks the source address by routing. When `Some(ip)` and the
    /// resolved upstream address is the same family, the client binds
    /// `(ip, 0)` so the upstream sees that IP as the peer source —
    /// this is what `[server].default_bind` plumbs through.
    /// A family mismatch (IPv4 local_bind, IPv6 upstream or vice versa)
    /// silently falls back to the wildcard.
    pub local_bind: Option<IpAddr>,
}

impl std::fmt::Debug for ChainClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainClientConfig")
            .field("endpoint", &self.endpoint)
            .field("upstream_pubkey", &self.upstream_pubkey.to_string())
            .field("local_keys", &"<redacted>")
            .field("heartbeat_interval", &self.heartbeat_interval)
            .field("rekey_interval", &self.rekey_interval)
            .field("body_handler", &self.body_handler.as_ref().map(|_| "<fn>"))
            .field("local_bind", &self.local_bind)
            .finish()
    }
}

/// Driver: owns the config, the cancel token, and the control-send queue;
/// consumed by [`ChainClient::run`].
pub struct ChainClient {
    pub(super) config: ChainClientConfig,
    pub(super) cancel: CancellationToken,
    pub(super) control_tx: mpsc::UnboundedSender<ControlOp>,
    pub(super) control_rx: mpsc::UnboundedReceiver<ControlOp>,
    pub(super) router: Arc<QueryRouter>,
    /// Monotone counter bumped after each successful handshake. Consumers
    /// (notably the predicate publisher) watch this to detect that
    /// upstream may have lost in-memory state on a restart and re-sync
    /// accordingly. Initial value `0` means "no session yet established";
    /// the first handshake bumps to `1`. See
    /// [`ChainClientHandle::session_epoch_rx`] for the consumer side.
    pub(super) session_epoch_tx: watch::Sender<u64>,
    /// Operator-facing "reconnect now" signal shared with every
    /// [`ChainClientHandle`]. The heartbeat loop selects on
    /// [`Notify::notified`]; firing causes the current session to be
    /// abandoned and re-handshake to proceed immediately, bypassing
    /// the ack-deadline detection wait (default ~30s). See
    /// [`ChainClientHandle::reconnect_now`] for the operator surface
    /// and [`ratatoskr::control::Request::ChainReconnect`] for the
    /// control-plane RPC that fans into it.
    pub(super) reconnect_signal: Arc<Notify>,
}

impl std::fmt::Debug for ChainClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainClient")
            .field("config", &self.config)
            .field("cancel", &"<token>")
            .finish()
    }
}

impl ChainClient {
    pub fn new(config: ChainClientConfig, cancel: CancellationToken) -> Self {
        let (control_tx, control_rx) = mpsc::unbounded_channel();
        let (session_epoch_tx, _session_epoch_rx) = watch::channel(0u64);
        let reconnect_signal = Arc::new(Notify::new());
        Self {
            config,
            cancel,
            control_tx,
            control_rx,
            router: QueryRouter::new(),
            session_epoch_tx,
            reconnect_signal,
        }
    }

    /// Clone the control-send handle. Multiple callers may hold handles
    /// concurrently; each enqueued op is processed in FIFO order by the
    /// client task.
    pub fn handle(&self) -> ChainClientHandle {
        ChainClientHandle {
            tx: self.control_tx.clone(),
            router: Arc::clone(&self.router),
            session_epoch_rx: self.session_epoch_tx.subscribe(),
            reconnect_signal: Arc::clone(&self.reconnect_signal),
        }
    }

    /// The query-router shared with [`ChainClientHandle`]s. Callers
    /// constructing the body-handler must install a router-aware
    /// dispatcher (see
    /// [`QueryRouter::install_into_body_handler`]) so inbound
    /// `ChainHopReply` envelopes reach their awaiting oneshots.
    pub fn query_router(&self) -> Arc<QueryRouter> {
        Arc::clone(&self.router)
    }

    /// Install (or replace) the per-envelope body handler.
    ///
    /// `ChainClientConfig::body_handler` is normally set at construction
    /// time, but the chain-tunnel initiator needs the [`ChainClientHandle`]
    /// (only available *after* `ChainClient::new`) in order to build its
    /// dispatcher closure. This setter lets the caller construct the
    /// initiator with the live handle and then register its body handler
    /// before [`ChainClient::run`] is called. Idempotent; callers must
    /// finish wiring before `run()` begins consuming the chain socket.
    pub fn set_body_handler(&mut self, handler: BodyHandler) {
        self.config.body_handler = Some(handler);
    }

    /// Run forever until the cancel token fires. Returns `Ok(())` on clean
    /// shutdown. Inner session errors are logged and trigger backoff +
    /// reconnect, so this only returns when explicitly cancelled.
    pub async fn run(mut self) -> Result<()> {
        let mut backoff = BACKOFF_MIN;
        loop {
            if self.cancel.is_cancelled() {
                return Ok(());
            }
            match self.run_session_once().await {
                Ok(SessionExit::Rekey) => {
                    tracing::info!("rekey interval reached; renegotiating");
                    backoff = BACKOFF_MIN;
                }
                Ok(SessionExit::ReconnectRequested) => {
                    // Operator-initiated nudge (or test-harness nudge):
                    // re-handshake immediately, skip the backoff sleep.
                    // The session_epoch bump in run_session_once() will
                    // poke the predicate publisher to re-push on the
                    // new session — same recovery shape as a Rekey.
                    tracing::info!(
                        "operator-requested chain reconnect; re-handshaking immediately"
                    );
                    backoff = BACKOFF_MIN;
                }
                Ok(SessionExit::Cancelled) => {
                    tracing::info!("chain client cancelled");
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(error = %e, backoff = ?backoff, "chain session ended");
                    if sleep_or_cancel(&self.cancel, backoff).await {
                        return Ok(());
                    }
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                }
            }
        }
    }
}
