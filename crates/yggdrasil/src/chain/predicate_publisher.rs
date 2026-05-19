//! Terminal-side predicate publisher.
//!
//! Watches the proxy supervisor's `current_set` channel; on each applied
//! [`RuleSet`] the publisher projects to a [`PredicateSet`], dedupes by
//! the projected predicates list (so HTTPS-only diffs are filtered out),
//! and pushes the result to the upstream relay via
//! [`ChainClientHandle::send_control`] as a
//! [`ControlBodyType::PredicateSetUpdate`] envelope.
//!
//! The publisher tracks a monotone `version: u64` counter that is
//! persisted to `state_dir/chain-predicate-version.toml` after every
//! successful upstream ack. On startup the counter is loaded from that
//! file; the first push therefore uses `last_persisted + 1` rather than
//! restarting at 1 and tripping the relay's `VERSION_STALE` invariant.
//!
//! Run only on terminal nodes (mode = `terminal`). Spawned by
//! [`crate::run_terminal`] when both a chain upstream *and* a supervisor
//! are configured; relays do not author predicates in v1.
//!
//! [`RuleSet`]: ratatoskr::rule::RuleSet
//! [`PredicateSet`]: ratatoskr::predicate::PredicateSet
//! [`ControlBodyType::PredicateSetUpdate`]: ratatoskr::control_frame::ControlBodyType::PredicateSetUpdate

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use ratatoskr::control_frame::ControlBodyType;
use ratatoskr::predicate::{
    predicate_reject, Predicate, PREDICATE_SET_MAX_WIRE_BYTES,
};
use ratatoskr::pubkey::PubKey;
use ratatoskr::rule::RuleSet;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::chain::client::{ChainClientHandle, ChainClientShutDown};
use crate::chain::introspection::IntrospectionState;
use crate::chain::predicate_extractor;
use crate::chain::reliability::SendError;

/// File name used to persist the publisher's monotone version under
/// `state_dir`.
const VERSION_FILE: &str = "chain-predicate-version.toml";

/// On-disk shape. Wrapped in a struct so the TOML reads as
/// `version = N` rather than a bare integer.
#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedVersion {
    #[serde(default)]
    version: u64,
}

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
/// `state_dir` holds the persisted version counter (see
/// [`VERSION_FILE`]). Loading errors are non-fatal: a corrupt or absent
/// file resets the counter to `0` and emits a warn-level log so the
/// operator notices.
///
/// `introspection` is the Phase 5B `/internal/derived-rules` sink: on
/// every successful upstream-acked push the publisher calls
/// [`IntrospectionState::record_apply`] with the predicate set we just
/// shipped. Pass `None` when the terminal disables the introspection
/// endpoint (the publisher then degenerates to its pre-5B behaviour).
pub fn spawn(
    rules_rx: watch::Receiver<RuleSet>,
    chain_handle: ChainClientHandle,
    origin: PubKey,
    state_dir: PathBuf,
    introspection: Option<Arc<IntrospectionState>>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(run(
        rules_rx,
        chain_handle,
        origin,
        state_dir,
        introspection,
        cancel,
    ))
}

async fn run(
    mut rules_rx: watch::Receiver<RuleSet>,
    chain_handle: ChainClientHandle,
    origin: PubKey,
    state_dir: PathBuf,
    introspection: Option<Arc<IntrospectionState>>,
    cancel: CancellationToken,
) {
    let version_path = state_dir.join(VERSION_FILE);
    let mut version: u64 = match load_version(&version_path) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %version_path.display(),
                "failed to load persisted predicate version; restarting at 0"
            );
            0
        }
    };
    let mut last_sent_predicates: Option<Vec<Predicate>> = None;

    tracing::info!(
        origin = %origin,
        version,
        "predicate publisher started"
    );

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                tracing::info!("predicate publisher shutdown");
                return;
            }
            res = rules_rx.changed() => {
                if res.is_err() {
                    tracing::info!(
                        "supervisor rule channel closed; predicate publisher exiting"
                    );
                    return;
                }
                let set = rules_rx.borrow_and_update().clone();
                let next_version = version.saturating_add(1);
                if let Some(applied) = publish_one(
                    &set,
                    origin,
                    next_version,
                    last_sent_predicates.as_deref(),
                    &chain_handle,
                    introspection.as_deref(),
                    &cancel,
                ).await {
                    version = applied.version;
                    last_sent_predicates = Some(applied.predicates);
                    if let Err(e) = persist_version(&version_path, version) {
                        // Persist failure does not roll the in-memory
                        // version back: the upstream has already accepted
                        // and a future restart that loses this write
                        // will only ever request a *lower* version, which
                        // the upstream will reject with VERSION_STALE.
                        // That is the safe failure mode.
                        tracing::error!(
                            error = %e,
                            path = %version_path.display(),
                            version,
                            "failed to persist predicate version"
                        );
                        metrics::counter!(
                            "yggdrasil_chain_predicate_push_total",
                            "outcome" => "persist_error"
                        )
                        .increment(1);
                    }
                }
            }
        }
    }
}

/// Result of a successful publish: the [`PredicateSet`] fields the
/// publisher should remember for the next dedup comparison + monotone
/// bump.
struct AppliedPush {
    version: u64,
    predicates: Vec<Predicate>,
}

/// One push attempt. Returns `Some` only when the upstream acked `Ok`
/// (or we deduped to a no-op). Skipped/rejected/timed-out pushes return
/// `None` and the publisher carries the previous `(version,
/// last_sent_predicates)` forward unchanged.
async fn publish_one(
    set: &RuleSet,
    origin: PubKey,
    next_version: u64,
    last_sent: Option<&[Predicate]>,
    chain_handle: &ChainClientHandle,
    introspection: Option<&IntrospectionState>,
    cancel: &CancellationToken,
) -> Option<AppliedPush> {
    let outcome = predicate_extractor::extract(set, origin, next_version);
    let predicate_set = outcome.set;
    if !outcome.skipped_https.is_empty() {
        tracing::debug!(
            count = outcome.skipped_https.len(),
            names = ?outcome.skipped_https,
            "skipped HTTPS rules during predicate extraction"
        );
    }

    // Dedup against the last successfully-sent predicates list. Identical
    // predicates → no wire push; the persisted upstream state is already
    // accurate. `last_sent == None` (first iteration after boot) always
    // pushes, even when the projection happens to be empty: relays use
    // the first push to learn that a terminal that previously held N
    // rules has gone empty.
    if let Some(prev) = last_sent {
        if prev == predicate_set.predicates.as_slice() {
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
    }

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

    metrics::gauge!("yggdrasil_chain_predicate_set_size_bytes")
        .set(body.len() as f64);

    let ack_rx = match chain_handle.send_control(
        ControlBodyType::PredicateSetUpdate.as_byte(),
        body,
    ) {
        Ok(rx) => rx,
        Err(ChainClientShutDown) => {
            tracing::warn!(
                "chain client is shut down; dropping predicate push"
            );
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
                version = predicate_set.version,
                predicates = predicate_set.predicates.len(),
                "predicate set accepted by upstream"
            );
            metrics::counter!(
                "yggdrasil_chain_predicate_push_total",
                "outcome" => "ok"
            )
            .increment(1);
            metrics::gauge!("yggdrasil_chain_predicate_version")
                .set(predicate_set.version as f64);
            // Phase 5B: notify the introspection sink with the set we
            // just successfully pushed. `predicate_set` is moved into
            // `AppliedPush` below, so we record_apply BEFORE the
            // destructure.
            if let Some(ix) = introspection {
                ix.record_apply(&predicate_set);
            }
            Some(AppliedPush {
                version: predicate_set.version,
                predicates: predicate_set.predicates,
            })
        }
        Ok(Ok(Err(SendError::Rejected(code)))) => {
            tracing::warn!(
                reject_code = code,
                version = predicate_set.version,
                "predicate set rejected by upstream"
            );
            metrics::counter!(
                "yggdrasil_chain_predicate_push_total",
                "outcome" => "reject",
                "code" => code.to_string(),
            )
            .increment(1);
            // VERSION_STALE means the upstream already has a higher
            // version recorded under our `origin`. This is a recoverable
            // condition once we add persistence in 3C — until then a
            // restart that loses the counter trips it. Log loudly so
            // operators notice during 3B testing.
            if code == predicate_reject::VERSION_STALE {
                tracing::warn!(
                    "version-stale reject — restart-induced counter regression \
                     (persistence is wired in Phase 3C)"
                );
            }
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
                "upstream does not recognise PredicateSetUpdate body type — \
                 version skew between terminal and relay"
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

fn load_version(path: &Path) -> Result<u64> {
    if !path.exists() {
        return Ok(0);
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let p: PersistedVersion =
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    Ok(p.version)
}

fn persist_version(path: &Path, version: u64) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
    }
    let text = toml::to_string_pretty(&PersistedVersion { version })
        .context("serialise chain-predicate-version TOML")?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use ratatoskr::auth::PUBLIC_KEY_LEN;
    use ratatoskr::predicate::PredicateSet;
    use ratatoskr::rule::{Protocol, Rule, RuleSet};
    use tokio::sync::Mutex;

    use crate::chain::client::{ChainClientHandle, ControlOp};

    fn tcp_rule(name: &str, port: u16) -> Rule {
        Rule {
            name: name.to_string(),
            listen: format!("127.0.0.1:{port}").parse().unwrap(),
            protocol: Protocol::Tcp,
            upstream_port: Some(port),
            upstream_addr: None,
            upstream_host: None,
            idle_timeout: None,
            proxy_protocol: None,
            routes: None,
            cert_dir: None,
        }
    }

    fn origin() -> PubKey {
        PubKey::x25519([0x42u8; PUBLIC_KEY_LEN])
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
    /// test execution).
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
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn pushes_on_rule_set_change_and_dedups_identical_resends() {
        let cancel = CancellationToken::new();
        let (handle, sink) = fake_handle();
        let (tx, rx) = watch::channel(RuleSet::default());
        let state_dir = tempfile::tempdir().unwrap();
        let publisher = spawn(
            rx,
            handle,
            origin(),
            state_dir.path().to_path_buf(),
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
        assert_eq!(decoded1.version, 1);
        assert_eq!(decoded1.origin, origin());

        // Ack OK so the publisher bumps version + remembers the set.
        op1.completion.send(Ok(())).unwrap();

        // Identical re-send — supervisor reapplies the same set (e.g.
        // file touch with unchanged content reaching the watcher). The
        // publisher should dedup and NOT call send_control again.
        tx.send(set1.clone()).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        {
            let g = sink.lock().await;
            assert!(g.is_empty(), "duplicate set should be deduped");
        }

        // A NEW set — version should bump to 2.
        let set2 = RuleSet::from_rules(vec![
            tcp_rule("alpha", 8080),
            tcp_rule("beta", 9090),
        ])
        .unwrap();
        tx.send(set2).unwrap();
        let op2 = next_op(&sink).await;
        let decoded2: PredicateSet = postcard::from_bytes(&op2.body).unwrap();
        assert_eq!(decoded2.predicates.len(), 2);
        assert_eq!(decoded2.version, 2);
        op2.completion.send(Ok(())).unwrap();

        cancel.cancel();
        let _ = publisher.await;
    }

    #[tokio::test]
    async fn rejected_push_does_not_bump_version_or_dedup_state() {
        let cancel = CancellationToken::new();
        let (handle, sink) = fake_handle();
        let (tx, rx) = watch::channel(RuleSet::default());
        let state_dir = tempfile::tempdir().unwrap();
        let publisher = spawn(
            rx,
            handle,
            origin(),
            state_dir.path().to_path_buf(),
            None,
            cancel.clone(),
        );

        let set1 = RuleSet::from_rules(vec![tcp_rule("alpha", 8080)]).unwrap();
        tx.send(set1.clone()).unwrap();

        let op1 = next_op(&sink).await;
        let decoded1: PredicateSet = postcard::from_bytes(&op1.body).unwrap();
        assert_eq!(decoded1.version, 1);

        // Relay says no.
        op1.completion
            .send(Err(SendError::Rejected(predicate_reject::INVALID_PREDICATE)))
            .unwrap();

        // Resending the SAME set should produce a fresh attempt (publisher
        // didn't remember anything because nothing was acked), still at
        // version 1.
        tx.send(set1.clone()).unwrap();
        let op2 = next_op(&sink).await;
        let decoded2: PredicateSet = postcard::from_bytes(&op2.body).unwrap();
        assert_eq!(decoded2.version, 1, "version stays 1 after reject");

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
        let (_tx, rx) = watch::channel(RuleSet::default());
        let state_dir = tempfile::tempdir().unwrap();
        let publisher = spawn(
            rx,
            handle,
            origin(),
            state_dir.path().to_path_buf(),
            None,
            cancel.clone(),
        );

        tokio::time::sleep(Duration::from_millis(200)).await;
        {
            let g = sink.lock().await;
            assert!(g.is_empty(), "initial RuleSet::default should not push");
        }

        cancel.cancel();
        let _ = publisher.await;
    }

    /// A second publisher instance pointed at the same `state_dir`
    /// resumes counting from the persisted version, so the first push
    /// after restart is `last + 1` rather than `1`.
    #[tokio::test]
    async fn persisted_version_survives_restart() {
        let state_dir = tempfile::tempdir().unwrap();

        // First publisher: accept 1 push, version becomes 1, persisted to disk.
        {
            let cancel = CancellationToken::new();
            let (handle, sink) = fake_handle();
            let (tx, rx) = watch::channel(RuleSet::default());
            let publisher = spawn(
                rx,
                handle,
                origin(),
                state_dir.path().to_path_buf(),
                None,
                cancel.clone(),
            );
            tx.send(RuleSet::from_rules(vec![tcp_rule("alpha", 8080)]).unwrap())
                .unwrap();
            let op = next_op(&sink).await;
            let decoded: PredicateSet = postcard::from_bytes(&op.body).unwrap();
            assert_eq!(decoded.version, 1);
            op.completion.send(Ok(())).unwrap();
            // Give the publisher a moment to land the persist call after
            // resolving the ack.
            tokio::time::sleep(Duration::from_millis(100)).await;
            cancel.cancel();
            let _ = publisher.await;
        }

        // Second publisher with the same state_dir: next push must be
        // version 2.
        let cancel = CancellationToken::new();
        let (handle, sink) = fake_handle();
        let (tx, rx) = watch::channel(RuleSet::default());
        let publisher = spawn(
            rx,
            handle,
            origin(),
            state_dir.path().to_path_buf(),
            None,
            cancel.clone(),
        );
        tx.send(RuleSet::from_rules(vec![tcp_rule("beta", 9090)]).unwrap())
            .unwrap();
        let op = next_op(&sink).await;
        let decoded: PredicateSet = postcard::from_bytes(&op.body).unwrap();
        assert_eq!(
            decoded.version, 2,
            "expected v2 after restart with persisted v1"
        );
        op.completion.send(Ok(())).unwrap();

        cancel.cancel();
        let _ = publisher.await;
    }
}
