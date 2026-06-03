//! Terminal-side predicate publisher.
//!
//! Watches the proxy supervisor's `current_set` channel; on each applied
//! [`RuleSet`] the publisher projects to a [`PredicateSet`], dedupes by
//! encoded predicate-set content, and pushes the result to the relay this
//! terminal dials via [`ChainClientHandle::send_control`] as a
//! [`ControlBodyType::PredicateSetUpdate`] envelope.
//!
//! The publisher keeps only in-memory dedup state. On session-epoch bumps it
//! clears that snapshot and re-pushes the current set so a restarted relay
//! rebuilds its predicate view.
//!
//! Run only on terminal nodes (mode = `terminal`). Spawned by
//! [`crate::run_terminal`] when both a chain peer *and* a supervisor are
//! configured; relays do not author predicates — they only derive and
//! forward what the terminal published.
//!
//! [`RuleSet`]: ratatoskr::rule::RuleSet
//! [`PredicateSet`]: ratatoskr::predicate::PredicateSet
//! [`ControlBodyType::PredicateSetUpdate`]: ratatoskr::control_frame::ControlBodyType::PredicateSetUpdate

use std::sync::Arc;
use std::time::Duration;

use blake2::{Blake2s256, Digest};
use ratatoskr::control_frame::ControlBodyType;
use ratatoskr::predicate::PREDICATE_SET_MAX_WIRE_BYTES;
use ratatoskr::pubkey::PubKey;
use ratatoskr::rule::RuleSet;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::chain::client::{ChainClientHandle, ChainClientShutDown};
use crate::chain::introspection::IntrospectionState;
use crate::chain::predicate_extractor::{self, HttpsPredicateMeta};
use crate::chain::reliability::SendError;

/// How long to wait for an upstream ack before treating the in-flight
/// push as failed and moving on. The reliability layer's own retransmit
/// budget (`RETX_MAX_ATTEMPTS` × `RETX_MAX`) bounds this from below, so
/// the publisher's deadline is purely defensive against a stuck client
/// task. Set well above the reliability budget; failure here implies the
/// client task is wedged, not just packet loss.
const PUBLISH_ACK_DEADLINE: Duration = Duration::from_secs(30);

/// Spawn the publisher task. Returns the join handle; the caller awaits
/// it during shutdown.
///
/// `introspection` is the chain-introspection sink backing
/// `Request::DerivedRules`: on every successful upstream-acked push the
/// publisher calls [`IntrospectionState::record_apply`] with the
/// predicate set we just shipped. Pass `None` when the terminal
/// disables introspection (the publisher then degenerates to its
/// pre-introspection behaviour).
pub fn spawn(
    rules_rx: watch::Receiver<RuleSet>,
    chain_handle: ChainClientHandle,
    origin: PubKey,
    https_meta: HttpsPredicateMeta,
    introspection: Option<Arc<IntrospectionState>>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(run(
        rules_rx,
        chain_handle,
        origin,
        https_meta,
        introspection,
        cancel,
    ))
}

async fn run(
    mut rules_rx: watch::Receiver<RuleSet>,
    chain_handle: ChainClientHandle,
    origin: PubKey,
    https_meta: HttpsPredicateMeta,
    introspection: Option<Arc<IntrospectionState>>,
    cancel: CancellationToken,
) {
    let mut last_sent_body_hash: Option<[u8; 32]> = None;

    // Session-epoch watch: bumps each time the chain client completes
    // a fresh handshake (upstream restart, network blip rekey, etc.).
    // We mark the initial value as "seen" so the first arm fires only
    // on subsequent handshakes; the initial handshake itself is
    // covered by the normal rules_rx flow on startup. If the sender
    // ever drops (typically: the chain client task has exited), the
    // arm flips to inactive and the publisher falls back to rules_rx
    // only.
    let mut session_epoch_rx = chain_handle.session_epoch_rx();
    session_epoch_rx.borrow_and_update();
    let mut epoch_source_alive = true;

    tracing::info!(
        origin = %origin,
        "predicate publisher started"
    );

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                tracing::info!("predicate publisher shutdown");
                return;
            }
            res = session_epoch_rx.changed(), if epoch_source_alive => {
                if res.is_err() {
                    // Chain client's session_epoch sender dropped (its
                    // task exited or the handle was constructed
                    // without a live chain client, e.g. unit tests).
                    // Not fatal: continue serving rules_rx; the
                    // resync-on-new-session guarantee just becomes a
                    // no-op for the rest of the publisher's lifetime.
                    tracing::debug!(
                        "chain client session-epoch source closed; \
                         publisher continues on rules_rx alone"
                    );
                    epoch_source_alive = false;
                    continue;
                }
                let epoch = *session_epoch_rx.borrow_and_update();
                // If we've never successfully pushed in this process,
                // there's no stale upstream state to refresh — the
                // first rules_rx emission will handle the initial
                // push naturally. Skip the resync. Otherwise, clear
                // the dedup snapshot and push the current set so a
                // restarted upstream (which lost its in-memory
                // predicate state) rebuilds its view from scratch.
                if last_sent_body_hash.is_none() {
                    tracing::debug!(
                        epoch,
                        "chain session bumped; no prior push to resync"
                    );
                    continue;
                }
                tracing::info!(
                    epoch,
                    "chain session re-established; resyncing predicate set to upstream"
                );
                metrics::counter!(
                    "yggdrasil_chain_predicate_push_total",
                    "outcome" => "session_resync"
                )
                .increment(1);
                last_sent_body_hash = None;
                let set = rules_rx.borrow().clone();
                publish_and_remember(
                    &set,
                    origin,
                    &mut last_sent_body_hash,
                    https_meta,
                    &chain_handle,
                    introspection.as_deref(),
                    &cancel,
                )
                .await;
            }
            res = rules_rx.changed() => {
                if res.is_err() {
                    tracing::info!(
                        "supervisor rule channel closed; predicate publisher exiting"
                    );
                    return;
                }
                let set = rules_rx.borrow_and_update().clone();
                publish_and_remember(
                    &set,
                    origin,
                    &mut last_sent_body_hash,
                    https_meta,
                    &chain_handle,
                    introspection.as_deref(),
                    &cancel,
                )
                .await;
            }
        }
    }
}

/// Push one rule set's projection upstream, and on a successful ack
/// update the in-memory content-dedup snapshot. Factored out so the
/// main loop's normal-flow arm (`rules_rx.changed()`) and the
/// session-resync arm (`session_epoch_rx.changed()`) share one
/// implementation.
#[allow(clippy::too_many_arguments)]
async fn publish_and_remember(
    set: &RuleSet,
    origin: PubKey,
    last_sent_body_hash: &mut Option<[u8; 32]>,
    https_meta: HttpsPredicateMeta,
    chain_handle: &ChainClientHandle,
    introspection: Option<&IntrospectionState>,
    cancel: &CancellationToken,
) {
    let Some(applied) = publish_one(
        set,
        origin,
        https_meta,
        last_sent_body_hash.as_ref(),
        chain_handle,
        introspection,
        cancel,
    )
    .await
    else {
        return;
    };
    *last_sent_body_hash = Some(applied.body_hash);
}

/// Result of a successful publish: the encoded content hash the
/// publisher should remember for the next dedup comparison.
struct AppliedPush {
    body_hash: [u8; 32],
}

/// One push attempt. Returns `Some` only when the upstream acked `Ok`
/// (or we deduped to a no-op). Skipped/rejected/timed-out pushes return
/// `None` and the publisher carries the previous content hash forward
/// unchanged.
#[allow(clippy::too_many_arguments)]
async fn publish_one(
    set: &RuleSet,
    origin: PubKey,
    https_meta: HttpsPredicateMeta,
    last_sent_hash: Option<&[u8; 32]>,
    chain_handle: &ChainClientHandle,
    introspection: Option<&IntrospectionState>,
    cancel: &CancellationToken,
) -> Option<AppliedPush> {
    let outcome = predicate_extractor::extract(set, https_meta, origin);
    let predicate_set = outcome.set;

    let body = match postcard::to_allocvec(&predicate_set) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(
                error = %e,
                "failed to encode PredicateSet; dropping push"
            );
            metrics::counter!(
                "yggdrasil_chain_predicate_push_total",
                "outcome" => "encode_error"
            )
            .increment(1);
            return None;
        }
    };
    if body.len() > PREDICATE_SET_MAX_WIRE_BYTES {
        tracing::error!(
            bytes = body.len(),
            cap = PREDICATE_SET_MAX_WIRE_BYTES,
            predicates = predicate_set.predicates.len(),
            "predicate set exceeds wire cap; dropping push"
        );
        metrics::counter!(
            "yggdrasil_chain_predicate_push_total",
            "outcome" => "skip_oversize"
        )
        .increment(1);
        return None;
    }

    let body_hash = predicate_body_hash(&body);
    if last_sent_hash.is_some_and(|prev| prev == &body_hash) {
        metrics::counter!(
            "yggdrasil_chain_predicate_push_total",
            "outcome" => "skip_dedup"
        )
        .increment(1);
        tracing::debug!(
            predicates = predicate_set.predicates.len(),
            "skipping predicate push: identical to last accepted set"
        );
        return None;
    }

    metrics::gauge!("yggdrasil_chain_predicate_set_size_bytes").set(body.len() as f64);

    let ack_rx =
        match chain_handle.send_control(ControlBodyType::PredicateSetUpdate.as_byte(), body) {
            Ok(rx) => rx,
            Err(ChainClientShutDown) => {
                tracing::warn!("chain client is shut down; dropping predicate push");
                metrics::counter!(
                    "yggdrasil_chain_predicate_push_total",
                    "outcome" => "client_down"
                )
                .increment(1);
                return None;
            }
        };

    let result = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            tracing::debug!(
                "cancelled while awaiting predicate ack"
            );
            return None;
        }
        r = tokio::time::timeout(PUBLISH_ACK_DEADLINE, ack_rx) => r,
    };

    match result {
        Ok(Ok(Ok(()))) => {
            tracing::info!(
                predicates = predicate_set.predicates.len(),
                "predicate set accepted by upstream"
            );
            metrics::counter!(
                "yggdrasil_chain_predicate_push_total",
                "outcome" => "ok"
            )
            .increment(1);
            // Notify the introspection sink with the set we just
            // successfully pushed.
            if let Some(ix) = introspection {
                ix.record_apply(&predicate_set);
            }
            Some(AppliedPush { body_hash })
        }
        Ok(Ok(Err(SendError::Rejected(code)))) => {
            tracing::warn!(reject_code = code, "predicate set rejected by upstream");
            metrics::counter!(
                "yggdrasil_chain_predicate_push_total",
                "outcome" => "reject",
                "code" => code.to_string(),
            )
            .increment(1);
            None
        }
        Ok(Ok(Err(SendError::Timeout(attempts)))) => {
            tracing::warn!(
                attempts = attempts,
                "predicate push timed out waiting for ack"
            );
            metrics::counter!(
                "yggdrasil_chain_predicate_push_total",
                "outcome" => "timeout"
            )
            .increment(1);
            None
        }
        Ok(Ok(Err(SendError::UnknownBodyType))) => {
            tracing::error!(
                "peer does not recognise PredicateSetUpdate body type — \
                 protocol mismatch between terminal and relay"
            );
            metrics::counter!(
                "yggdrasil_chain_predicate_push_total",
                "outcome" => "unknown_body"
            )
            .increment(1);
            None
        }
        Ok(Ok(Err(SendError::ChannelClosed))) => {
            tracing::warn!(
                "control channel closed before predicate ack arrived \
                 (session re-establish in progress)"
            );
            metrics::counter!(
                "yggdrasil_chain_predicate_push_total",
                "outcome" => "channel_closed"
            )
            .increment(1);
            None
        }
        Ok(Err(_recv_err)) => {
            // oneshot::Sender was dropped without a value — the chain
            // client task is exiting.
            tracing::warn!("ack receiver dropped before resolution");
            metrics::counter!(
                "yggdrasil_chain_predicate_push_total",
                "outcome" => "client_down"
            )
            .increment(1);
            None
        }
        Err(_elapsed) => {
            tracing::error!(
                deadline = ?PUBLISH_ACK_DEADLINE,
                "publisher gave up waiting on ack (client task wedged?)"
            );
            metrics::counter!(
                "yggdrasil_chain_predicate_push_total",
                "outcome" => "publisher_timeout"
            )
            .increment(1);
            None
        }
    }
}

fn predicate_body_hash(body: &[u8]) -> [u8; 32] {
    let digest = Blake2s256::digest(body);
    digest.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use ratatoskr::auth::X25519_PUBLIC_LEN;
    use ratatoskr::predicate::{predicate_reject, PredicateSet};
    use ratatoskr::rule::{Protocol, Rule, RuleSet};
    use tokio::sync::Mutex;

    use crate::chain::client::{ChainClientHandle, ControlOp};

    fn tcp_rule(name: &str, port: u16) -> Rule {
        Rule {
            name: name.to_string(),
            listen: format!("127.0.0.1:{port}").parse().unwrap(),
            protocol: Protocol::Tcp,
            target_port: Some(port),
            target: None,
            idle_timeout: None,
            proxy_protocol: None,
        }
    }

    fn origin() -> PubKey {
        PubKey::x25519([0x42u8; X25519_PUBLIC_LEN])
    }

    /// Build a `(ChainClientHandle, sink)` pair for tests. The sink
    /// records every `ControlOp` the publisher hands off. Tests answer
    /// the embedded `completion` oneshot to drive the publisher state
    /// machine.
    fn fake_handle() -> (ChainClientHandle, Arc<Mutex<Vec<ControlOp>>>) {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ControlOp>();
        let sink: Arc<Mutex<Vec<ControlOp>>> = Arc::new(Mutex::new(Vec::new()));
        let sink_task = Arc::clone(&sink);
        tokio::spawn(async move {
            while let Some(op) = rx.recv().await {
                sink_task.lock().await.push(op);
            }
        });
        let handle = ChainClientHandle::__test_new(tx);
        (handle, sink)
    }

    /// Pop the next captured op (with a generous timeout for parallel
    /// test execution). The 10 ms poll is unavoidable here: the test
    /// fundamentally has to wait for a future event to land in the
    /// sink, and the sink isn't `Notify`-backed today. Tight enough
    /// to keep tests fast, loose enough to not burn CPU when several
    /// tests run in parallel.
    async fn next_op(sink: &Arc<Mutex<Vec<ControlOp>>>) -> ControlOp {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            {
                let mut g = sink.lock().await;
                if !g.is_empty() {
                    return g.remove(0);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("publisher did not emit a control op within 5s");
            }
            // 10 ms poll backoff; see fn-level doc for the rationale.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn pushes_on_rule_set_change_and_dedups_identical_resends() {
        let cancel = CancellationToken::new();
        let (handle, sink) = fake_handle();
        let (tx, rx) = watch::channel(RuleSet::default());
        let publisher = spawn(
            rx,
            handle,
            origin(),
            HttpsPredicateMeta::default(),
            None,
            cancel.clone(),
        );

        // First applied set: one TCP rule.
        let set1 = RuleSet::from_rules(vec![tcp_rule("alpha", 8080)]).unwrap();
        tx.send(set1.clone()).unwrap();

        let op1 = next_op(&sink).await;
        assert_eq!(op1.body_type, ControlBodyType::PredicateSetUpdate.as_byte());
        let decoded1: PredicateSet = postcard::from_bytes(&op1.body).unwrap();
        assert_eq!(decoded1.predicates.len(), 1);
        assert_eq!(decoded1.predicates[0].name, "alpha");
        assert_eq!(decoded1.predicates[0].listen_port, 8080);
        assert_eq!(decoded1.origin, origin());

        // Ack OK so the publisher bumps remembers the set.
        op1.completion.send(Ok(())).unwrap();

        // Identical re-send — supervisor reapplies the same set (e.g.
        // file touch with unchanged content reaching the watcher). The
        // publisher should dedup and NOT call send_control again.
        //
        // We assert this with the marker-pattern: send the duplicate,
        // then send a DIFFERENT set, then wait for that set's op.
        // If the duplicate had erroneously been pushed, the sink
        // would emit it BEFORE the distinct set; the first op we
        // see must therefore be the distinct one. Deterministic; no
        // sleep-based negative assertion.
        tx.send(set1.clone()).unwrap();
        let set2 =
            RuleSet::from_rules(vec![tcp_rule("alpha", 8080), tcp_rule("beta", 9090)]).unwrap();
        tx.send(set2).unwrap();
        let op2 = next_op(&sink).await;
        let decoded2: PredicateSet = postcard::from_bytes(&op2.body).unwrap();
        assert_eq!(
            decoded2.predicates.len(),
            2,
            "first op after duplicate must be the DISTINCT set (proving the duplicate was deduped)"
        );
        op2.completion.send(Ok(())).unwrap();

        cancel.cancel();
        let _ = publisher.await;
    }

    #[tokio::test]
    async fn rejected_push_does_not_update_dedup_state() {
        let cancel = CancellationToken::new();
        let (handle, sink) = fake_handle();
        let (tx, rx) = watch::channel(RuleSet::default());
        let publisher = spawn(
            rx,
            handle,
            origin(),
            HttpsPredicateMeta::default(),
            None,
            cancel.clone(),
        );

        let set1 = RuleSet::from_rules(vec![tcp_rule("alpha", 8080)]).unwrap();
        tx.send(set1.clone()).unwrap();

        let op1 = next_op(&sink).await;
        let decoded1: PredicateSet = postcard::from_bytes(&op1.body).unwrap();
        assert_eq!(decoded1.predicates[0].name, "alpha");

        // Relay says no.
        op1.completion
            .send(Err(SendError::Rejected(
                predicate_reject::INVALID_PREDICATE,
            )))
            .unwrap();

        // Resending the SAME set should produce a fresh attempt (publisher
        // didn't remember anything because nothing was acked), again.
        tx.send(set1.clone()).unwrap();
        let op2 = next_op(&sink).await;
        let decoded2: PredicateSet = postcard::from_bytes(&op2.body).unwrap();
        assert_eq!(decoded2.predicates[0].name, "alpha");

        op2.completion.send(Ok(())).unwrap();
        cancel.cancel();
        let _ = publisher.await;
    }

    /// Discard the initial RuleSet::default() carried by the watch — the
    /// publisher only fires on changes, not on the channel's initial value.
    #[tokio::test]
    async fn does_not_push_for_initial_default_value() {
        let cancel = CancellationToken::new();
        let (handle, sink) = fake_handle();
        let (tx, rx) = watch::channel(RuleSet::default());
        let publisher = spawn(
            rx,
            handle,
            origin(),
            HttpsPredicateMeta::default(),
            None,
            cancel.clone(),
        );

        // Marker-pattern negative assertion: push a real update on the
        // same channel. The publisher processes its watch::Receiver
        // serially, so the FIRST op landing in the sink must be the
        // real update — if the initial default value had erroneously
        // been pushed, it would have arrived first.
        tx.send(RuleSet::from_rules(vec![tcp_rule("marker", 1)]).unwrap())
            .unwrap();
        let op = next_op(&sink).await;
        let decoded: PredicateSet = postcard::from_bytes(&op.body).unwrap();
        assert_eq!(decoded.predicates.len(), 1);
        assert_eq!(
            decoded.predicates[0].name, "marker",
            "first op must be the marker (proving initial default was NOT pushed)"
        );

        cancel.cancel();
        let _ = publisher.await;
    }

    /// `gateway-udp-claim-conflict` companion finding: a restarted
    /// upstream loses its in-memory predicate state, but the
    /// publisher's dedup snapshot would otherwise prevent a re-push.
    /// Bumping `session_epoch_tx` simulates the chain client completing
    /// a fresh handshake against a restarted upstream; the publisher
    /// must clear its dedup snapshot and re-emit the current set so
    /// upstream rebuilds its view.
    #[tokio::test]
    async fn resyncs_after_chain_session_re_establishment() {
        let cancel = CancellationToken::new();
        // fake_handle_with_epoch returns both the handle and the live
        // epoch sender so we can drive the resync arm.
        let (tx, mut control_rx) = tokio::sync::mpsc::unbounded_channel::<ControlOp>();
        let sink: Arc<Mutex<Vec<ControlOp>>> = Arc::new(Mutex::new(Vec::new()));
        let sink_task = Arc::clone(&sink);
        tokio::spawn(async move {
            while let Some(op) = control_rx.recv().await {
                sink_task.lock().await.push(op);
            }
        });
        let (handle, epoch_tx) = ChainClientHandle::__test_new_with_epoch(tx);

        let (rules_tx, rules_rx) = watch::channel(RuleSet::default());
        let publisher = spawn(
            rules_rx,
            handle,
            origin(),
            HttpsPredicateMeta::default(),
            None,
            cancel.clone(),
        );

        // Initial push of a real rule, acked OK so the publisher
        // remembers it (last_sent_body_hash = Some(...)).
        let set = RuleSet::from_rules(vec![tcp_rule("alpha", 8080)]).unwrap();
        rules_tx.send(set.clone()).unwrap();
        let op1 = next_op(&sink).await;
        let decoded1: PredicateSet = postcard::from_bytes(&op1.body).unwrap();
        assert_eq!(decoded1.predicates.len(), 1);
        op1.completion.send(Ok(())).unwrap();

        // Simulate a fresh handshake against a restarted upstream:
        // bump the session epoch. The publisher must observe the bump
        // and re-push the current set even though its
        // dedup snapshot matches the current content.
        epoch_tx.send_modify(|e| {
            *e = e.saturating_add(1);
        });

        let op2 = next_op(&sink).await;
        let decoded2: PredicateSet = postcard::from_bytes(&op2.body).unwrap();
        assert_eq!(
            decoded2.predicates.len(),
            1,
            "resync push must contain the current rule set, not an empty/stale one"
        );
        assert_eq!(decoded2.predicates[0].name, "alpha");
        op2.completion.send(Ok(())).unwrap();

        // Verify subsequent epoch bumps continue to resync: bump
        // again, expect another push. Use a marker-set so dedup
        // would not accidentally produce the same result.
        let set2 =
            RuleSet::from_rules(vec![tcp_rule("alpha", 8080), tcp_rule("beta", 9090)]).unwrap();
        rules_tx.send(set2).unwrap();
        let op_set2 = next_op(&sink).await;
        let decoded_set2: PredicateSet = postcard::from_bytes(&op_set2.body).unwrap();
        assert_eq!(decoded_set2.predicates.len(), 2);
        op_set2.completion.send(Ok(())).unwrap();

        epoch_tx.send_modify(|e| {
            *e = e.saturating_add(1);
        });
        let op4 = next_op(&sink).await;
        let decoded4: PredicateSet = postcard::from_bytes(&op4.body).unwrap();
        assert_eq!(decoded4.predicates.len(), 2);
        op4.completion.send(Ok(())).unwrap();

        cancel.cancel();
        let _ = publisher.await;
    }

    /// First-handshake case: when the publisher has never pushed yet
    /// (`last_sent_body_hash == None`), an epoch bump should NOT
    /// synthesise an empty push. The first rules_rx emission still
    /// drives the actual first push.
    #[tokio::test]
    async fn first_session_epoch_bump_does_not_force_empty_push() {
        let cancel = CancellationToken::new();
        let (tx, mut control_rx) = tokio::sync::mpsc::unbounded_channel::<ControlOp>();
        let sink: Arc<Mutex<Vec<ControlOp>>> = Arc::new(Mutex::new(Vec::new()));
        let sink_task = Arc::clone(&sink);
        tokio::spawn(async move {
            while let Some(op) = control_rx.recv().await {
                sink_task.lock().await.push(op);
            }
        });
        let (handle, epoch_tx) = ChainClientHandle::__test_new_with_epoch(tx);

        let (rules_tx, rules_rx) = watch::channel(RuleSet::default());
        let publisher = spawn(
            rules_rx,
            handle,
            origin(),
            HttpsPredicateMeta::default(),
            None,
            cancel.clone(),
        );

        // Bump the epoch BEFORE any rules_rx emission. The publisher
        // has never pushed, so there's no upstream state to resync.
        // The resync arm should observe `last_sent_body_hash =
        // None` and skip silently. Then the first real rules_rx
        // emission should trigger the actual first push.
        epoch_tx.send_modify(|e| {
            *e = e.saturating_add(1);
        });
        // Small async yield so the publisher gets a chance to observe
        // the epoch change before we drive rules_rx — without this,
        // both events may be observed in the same select iteration
        // and the test wouldn't actually exercise "epoch first,
        // then rules". Borrowed pattern from notify-debouncer-mini
        // tests.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        let set = RuleSet::from_rules(vec![tcp_rule("alpha", 8080)]).unwrap();
        rules_tx.send(set).unwrap();

        let op1 = next_op(&sink).await;
        let decoded1: PredicateSet = postcard::from_bytes(&op1.body).unwrap();
        // Marker assertion: the FIRST op must contain the real set,
        // not an empty resync push that would have arrived first if
        // the epoch arm had erroneously synthesised one.
        assert_eq!(
            decoded1.predicates.len(),
            1,
            "first push must be the real set, not an empty epoch-triggered resync"
        );
        op1.completion.send(Ok(())).unwrap();

        cancel.cancel();
        let _ = publisher.await;
    }
}
