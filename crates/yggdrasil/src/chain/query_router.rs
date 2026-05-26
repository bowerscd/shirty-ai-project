//! Per-session query/reply correlation for the recursive `ChainSummary`
//! and `chain canary` RPCs.
//!
//! Both query types share the same correlation shape: the originator
//! allocates a `query_id`, registers a oneshot, sends the query
//! envelope upstream, and awaits the reply with a timeout. The router
//! holds two parallel pending maps — one per reply type — so a
//! [`ChainHopReply`] and a [`CanaryReply`] with the same `query_id`
//! don't collide (each is matched against its own map based on the
//! control body type at decode time).
//!
//! Production handlers wrap the router via
//! [`QueryRouter::install_into_body_handler`], which composes it with
//! any caller-supplied secondary body handler so other body types
//! (today: only `Reserved`/`Noop`/`PredicateSetUpdate`) still reach
//! their dispatchers.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use ratatoskr::canary::CanaryReply;
use ratatoskr::chain_query::ChainHopReply;
use ratatoskr::control_frame::{AckStatus, ControlBodyType};
use tokio::sync::oneshot;

use super::client::BodyHandler;

/// Shared per-session router for outstanding `ChainHopReply` and
/// `CanaryReply` correlations.
#[derive(Debug, Default)]
pub struct QueryRouter {
    next_id: AtomicU32,
    pending_chain_hop: Mutex<HashMap<u32, oneshot::Sender<ChainHopReply>>>,
    pending_canary: Mutex<HashMap<u32, oneshot::Sender<CanaryReply>>>,
}

impl QueryRouter {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            // Start non-zero so logs visibly differ from the zero
            // default of test fixtures.
            next_id: AtomicU32::new(1),
            pending_chain_hop: Mutex::new(HashMap::new()),
            pending_canary: Mutex::new(HashMap::new()),
        })
    }

    /// Allocate a fresh `query_id` and register a oneshot that will
    /// be resolved when a [`ChainHopReply`] with that id is received.
    /// Cancellation drops the receiver; the next [`resolve`](Self::resolve)
    /// for that id then logs and discards the reply.
    pub fn register(self: &Arc<Self>) -> (u32, oneshot::Receiver<ChainHopReply>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        let mut guard = self
            .pending_chain_hop
            .lock()
            .expect("query router lock poisoned");
        guard.insert(id, tx);
        (id, rx)
    }

    /// Allocate a fresh `query_id` and register a oneshot that will
    /// be resolved when a [`CanaryReply`] with that id is received.
    pub fn register_canary(self: &Arc<Self>) -> (u32, oneshot::Receiver<CanaryReply>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        let mut guard = self
            .pending_canary
            .lock()
            .expect("query router lock poisoned");
        guard.insert(id, tx);
        (id, rx)
    }

    /// Drop a `ChainHopReply` registration without awaiting the reply.
    /// Used by timeout paths so a late reply doesn't leak the oneshot
    /// slot.
    pub fn cancel(&self, query_id: u32) {
        let mut guard = self
            .pending_chain_hop
            .lock()
            .expect("query router lock poisoned");
        guard.remove(&query_id);
    }

    /// Drop a `CanaryReply` registration without awaiting the reply.
    pub fn cancel_canary(&self, query_id: u32) {
        let mut guard = self
            .pending_canary
            .lock()
            .expect("query router lock poisoned");
        guard.remove(&query_id);
    }

    /// Try to route a decoded [`ChainHopReply`] onto its awaiting
    /// oneshot. Returns `true` if a matching registration was found.
    /// Late replies (after the waiter timed out and dropped the
    /// receiver) and replies for unknown ids both return `false`.
    pub fn resolve(&self, reply: ChainHopReply) -> bool {
        let mut guard = self
            .pending_chain_hop
            .lock()
            .expect("query router lock poisoned");
        match guard.remove(&reply.query_id) {
            Some(tx) => tx.send(reply).is_ok(),
            None => false,
        }
    }

    /// Try to route a decoded [`CanaryReply`] onto its awaiting oneshot.
    pub fn resolve_canary(&self, reply: CanaryReply) -> bool {
        let mut guard = self
            .pending_canary
            .lock()
            .expect("query router lock poisoned");
        match guard.remove(&reply.query_id) {
            Some(tx) => tx.send(reply).is_ok(),
            None => false,
        }
    }

    /// Build a [`BodyHandler`] that special-cases
    /// [`ControlBodyType::ChainHopReply`] and
    /// [`ControlBodyType::CanaryReply`] (decodes + routes to this
    /// router, acks `Ok`) and delegates every other body type to
    /// `inner`. When `inner` is `None`, every other body type acks
    /// `Unknown` (the chain-client default).
    pub fn install_into_body_handler(self: &Arc<Self>, inner: Option<BodyHandler>) -> BodyHandler {
        let router = Arc::clone(self);
        Arc::new(move |body_type: u8, body: &[u8]| {
            if body_type == ControlBodyType::ChainHopReply.as_byte() {
                match postcard::from_bytes::<ChainHopReply>(body) {
                    Ok(reply) => {
                        let resolved = router.resolve(reply);
                        if !resolved {
                            tracing::debug!(
                                "ChainHopReply for unknown or already-resolved query_id; \
                                 the originating walk may have timed out"
                            );
                        }
                        AckStatus::Ok
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to decode inbound ChainHopReply");
                        AckStatus::Unknown
                    }
                }
            } else if body_type == ControlBodyType::CanaryReply.as_byte() {
                match postcard::from_bytes::<CanaryReply>(body) {
                    Ok(reply) => {
                        let resolved = router.resolve_canary(reply);
                        if !resolved {
                            tracing::debug!(
                                "CanaryReply for unknown or already-resolved query_id; \
                                 the originating canary may have timed out"
                            );
                        }
                        AckStatus::Ok
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to decode inbound CanaryReply");
                        AckStatus::Unknown
                    }
                }
            } else if let Some(inner) = inner.as_ref() {
                inner(body_type, body)
            } else {
                AckStatus::Unknown
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatoskr::control_frame::ControlBodyType;

    fn empty_reply(id: u32) -> ChainHopReply {
        ChainHopReply {
            query_id: id,
            hops: vec![],
            partial: false,
            error: None,
        }
    }

    #[tokio::test]
    async fn register_resolves_reply() {
        let r = QueryRouter::new();
        let (id, rx) = r.register();
        assert!(r.resolve(empty_reply(id)));
        let got = rx.await.unwrap();
        assert_eq!(got.query_id, id);
    }

    #[tokio::test]
    async fn resolve_unknown_id_returns_false() {
        let r = QueryRouter::new();
        assert!(!r.resolve(empty_reply(999)));
    }

    #[tokio::test]
    async fn cancel_drops_pending() {
        let r = QueryRouter::new();
        let (id, _rx) = r.register();
        r.cancel(id);
        // Subsequent resolve sees no entry.
        assert!(!r.resolve(empty_reply(id)));
    }

    #[tokio::test]
    async fn body_handler_routes_reply_and_delegates_other() {
        let r = QueryRouter::new();
        let (id, rx) = r.register();
        let inner: BodyHandler = Arc::new(|bt, _body| {
            if bt == ControlBodyType::PredicateSetUpdate.as_byte() {
                AckStatus::Ok
            } else {
                AckStatus::Unknown
            }
        });
        let h = r.install_into_body_handler(Some(inner));

        // Encode a reply and feed it through the handler.
        let reply = empty_reply(id);
        let body = postcard::to_allocvec(&reply).unwrap();
        assert_eq!(
            h(ControlBodyType::ChainHopReply.as_byte(), &body),
            AckStatus::Ok,
        );
        assert_eq!(rx.await.unwrap().query_id, id);

        // Inner handler still reachable for non-reply types.
        assert_eq!(
            h(ControlBodyType::PredicateSetUpdate.as_byte(), &[]),
            AckStatus::Ok,
        );
        assert_eq!(h(0xFE, &[]), AckStatus::Unknown);
    }

    #[tokio::test]
    async fn body_handler_with_no_inner_acks_unknown() {
        let r = QueryRouter::new();
        let h = r.install_into_body_handler(None);
        assert_eq!(
            h(ControlBodyType::PredicateSetUpdate.as_byte(), &[]),
            AckStatus::Unknown,
        );
    }
}
