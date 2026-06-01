//! `BodyHandler`, `ControlOp`, and the external-facing
//! [`ChainClientHandle`] / [`QueryError`] / [`ChainClientShutDown`] types.
//!

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use ratatoskr::canary::{CanaryArm as CanaryArmFrame, CanaryReply};
use ratatoskr::chain_query::{ChainHopQuery, ChainHopReply};
use ratatoskr::control_frame::{AckStatus, ControlBodyType};

use crate::chain::query_router::QueryRouter;
use crate::chain::reliability::SendError;

/// Body-type dispatcher invoked when an inbound control envelope is
/// classified as `Deliver` by the [`ControlChannel`]. The handler returns
/// the [`AckStatus`] to send back to the peer.
///
/// In production builds the default is `None`, which acks every inbound
/// envelope as [`AckStatus::Unknown`] — the dispatcher itself ships no
/// real body-type handlers, so any non-`Reserved` body must come from a
/// peer running a newer version of the protocol that this node has not
/// yet been upgraded to.
///
/// [`ControlChannel`]: crate::chain::reliability::ControlChannel
pub type BodyHandler = Arc<dyn Fn(u8, &[u8]) -> AckStatus + Send + Sync>;

/// Request issued by a [`ChainClientHandle`] consumer; consumed by the
/// chain client task and folded into the per-session `ControlChannel`.
#[derive(Debug)]
pub struct ControlOp {
    pub body_type: u8,
    pub body: Vec<u8>,
    pub completion: oneshot::Sender<Result<(), SendError>>,
}

/// Clone-able handle that lets external code enqueue control envelopes on
/// the chain client. Sending on a handle whose client task has exited
/// fails with [`ChainClientShutDown`].
#[derive(Debug, Clone)]
pub struct ChainClientHandle {
    pub(super) tx: mpsc::UnboundedSender<ControlOp>,
    /// Shared per-session query/reply router used by
    /// [`ChainClientHandle::query_upstream`]. The chain client's
    /// body-handler closure resolves [`ChainHopReply`] envelopes
    /// through this same router.
    pub(super) router: Arc<QueryRouter>,
}

#[derive(Debug, thiserror::Error)]
#[error("chain client is shut down")]
pub struct ChainClientShutDown;

impl ChainClientHandle {
    /// Enqueue a control envelope for the upstream. Returns the per-send
    /// `Receiver`; its value is `Ok(())` on `AckStatus::Ok`, or a
    /// [`SendError`] for any other outcome. The receiver itself may resolve
    /// with `Err(oneshot::error::RecvError)` if the client task drops the
    /// completion sender before producing a result (e.g. session ended
    /// during shutdown without a clean ack).
    pub fn send_control(
        &self,
        body_type: u8,
        body: Vec<u8>,
    ) -> Result<oneshot::Receiver<Result<(), SendError>>, ChainClientShutDown> {
        let (completion, rx) = oneshot::channel();
        self.tx
            .send(ControlOp {
                body_type,
                body,
                completion,
            })
            .map_err(|_| ChainClientShutDown)?;
        Ok(rx)
    }

    /// Test-only constructor: wrap a pre-built sender so unit tests can
    /// observe enqueued ops without running a full chain session. Not
    /// part of the public API.
    #[cfg(test)]
    #[doc(hidden)]
    pub(crate) fn __test_new(tx: mpsc::UnboundedSender<ControlOp>) -> Self {
        Self {
            tx,
            router: QueryRouter::new(),
        }
    }

    /// Shared per-session query router. The body handler installed on
    /// the chain client must be wired to resolve [`ChainHopReply`]
    /// envelopes through this same router (see
    /// [`QueryRouter::install_into_body_handler`]).
    pub fn query_router(&self) -> Arc<QueryRouter> {
        Arc::clone(&self.router)
    }

    /// Issue a [`ChainHopQuery`] upstream and await the matching
    /// [`ChainHopReply`]. The receiver acks the query immediately;
    /// the reply arrives as a separate `ChainHopReply` envelope routed
    /// through [`QueryRouter`].
    ///
    /// On timeout the router registration is cancelled so a late
    /// reply doesn't leak the oneshot slot; the caller receives
    /// [`QueryError::Timeout`]. On any underlying `send_control`
    /// failure (channel closed, retransmits exhausted, peer rejected)
    /// the error variant carries the underlying [`SendError`].
    pub async fn query_upstream(
        &self,
        depth_budget: u32,
        deadline: Duration,
    ) -> Result<ChainHopReply, QueryError> {
        let (query_id, rx) = self.router.register();
        let deadline_ms = u32::try_from(deadline.as_millis()).unwrap_or(u32::MAX);
        let query = ChainHopQuery {
            query_id,
            depth_budget,
            deadline_ms,
        };
        let body = postcard::to_allocvec(&query).map_err(QueryError::Encode)?;
        let ack_rx = self
            .send_control(ControlBodyType::ChainHopQuery.as_byte(), body)
            .map_err(|_| {
                self.router.cancel(query_id);
                QueryError::ClientDown
            })?;

        // First, await the ACK so we know the query was actually
        // delivered. If the peer can't even ack we won't get a reply
        // either, so propagate.
        let ack_outcome = tokio::time::timeout(deadline, ack_rx).await;
        match ack_outcome {
            Err(_) => {
                self.router.cancel(query_id);
                return Err(QueryError::Timeout);
            }
            Ok(Err(_)) => {
                self.router.cancel(query_id);
                return Err(QueryError::ClientDown);
            }
            Ok(Ok(Err(e))) => {
                self.router.cancel(query_id);
                return Err(QueryError::Send(e));
            }
            Ok(Ok(Ok(()))) => {}
        }

        // Then await the actual reply.
        match tokio::time::timeout(deadline, rx).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(_)) => Err(QueryError::ClientDown),
            Err(_) => {
                self.router.cancel(query_id);
                Err(QueryError::Timeout)
            }
        }
    }

    /// Issue a [`CanaryArmFrame`] upstream and await the matching
    /// [`CanaryReply`]. Mirrors [`query_upstream`](Self::query_upstream)
    /// but uses the canary-side correlation map on the
    /// [`QueryRouter`]. The originator's [`CanaryArmFrame::query_id`]
    /// field is overwritten with the router-assigned id; callers
    /// pass `0` (or any placeholder) for that field.
    pub async fn query_upstream_canary(
        &self,
        mut arm: CanaryArmFrame,
        deadline: Duration,
    ) -> Result<CanaryReply, QueryError> {
        let (query_id, rx) = self.router.register_canary();
        arm.query_id = query_id;
        let deadline_ms = u32::try_from(deadline.as_millis()).unwrap_or(u32::MAX);
        arm.deadline_ms = deadline_ms;
        let body = postcard::to_allocvec(&arm).map_err(QueryError::Encode)?;
        let ack_rx = self
            .send_control(ControlBodyType::CanaryArm.as_byte(), body)
            .map_err(|_| {
                self.router.cancel_canary(query_id);
                QueryError::ClientDown
            })?;

        let ack_outcome = tokio::time::timeout(deadline, ack_rx).await;
        match ack_outcome {
            Err(_) => {
                self.router.cancel_canary(query_id);
                return Err(QueryError::Timeout);
            }
            Ok(Err(_)) => {
                self.router.cancel_canary(query_id);
                return Err(QueryError::ClientDown);
            }
            Ok(Ok(Err(e))) => {
                self.router.cancel_canary(query_id);
                return Err(QueryError::Send(e));
            }
            Ok(Ok(Ok(()))) => {}
        }

        match tokio::time::timeout(deadline, rx).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(_)) => Err(QueryError::ClientDown),
            Err(_) => {
                self.router.cancel_canary(query_id);
                Err(QueryError::Timeout)
            }
        }
    }
}

/// Failure modes for [`ChainClientHandle::query_upstream`].
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    /// The deadline expired before a reply arrived. The local hop is
    /// still usable; the CLI surfaces this as `partial = true`.
    #[error("chain hop query timed out")]
    Timeout,
    /// The chain client task is no longer running (cancellation or
    /// fatal session error).
    #[error("chain client is shut down")]
    ClientDown,
    /// The send layer reported a delivery failure (retransmits
    /// exhausted, peer rejected the body type, etc.).
    #[error("chain hop query send failed: {0}")]
    Send(#[from] SendError),
    /// Postcard refused to encode the query body. Pure internal bug;
    /// surfaces here so tests catch it.
    #[error("failed to encode ChainHopQuery body: {0}")]
    Encode(postcard::Error),
}
