//! Relay-side chain receive dispatcher.
//!
//! Glues together the three steps a relay performs when an inbound
//! `Control` envelope with body type [`ControlBodyType::PredicateSetUpdate`]
//! arrives:
//!
//! 1. Decode the postcard-encoded [`PredicateSet`] body.
//! 2. Enforce the per-origin monotone version invariant (the persisted
//!    `chain-predicates.toml` carries the last accepted version per
//!    `PredicateSet.origin`). Out-of-order pushes ack
//!    [`predicate_reject::VERSION_STALE`].
//! 3. Project the set to a [`RuleSet`] via [`chain::derive`] and hand it
//!    to the proxy supervisor via [`SupervisorHandle::apply_ruleset`].
//!
//! All steps are wrapped in a single [`dispatch`](ChainAcceptor::dispatch)
//! call that returns the [`AckStatus`] the receiver should encode into
//! the outbound `ControlAck`.
//!
//! The acceptor is **shared** across heartbeat sessions: re-handshaking
//! does not reset the persisted versions. The persistence layer uses an
//! atomic tmp+rename write keyed off `state_dir/chain-predicates.toml`.
//!
//! Phase 3C invariant: terminals are the only authors of predicates, so
//! `PredicateSet.origin` always identifies a terminal. Mid-chain relays
//! forwarding upstream are a future-phase concern; until then the relay
//! does not validate that `origin == downstream_pubkey` so that test
//! drivers and future multi-tenant relays can issue pushes from synthetic
//! origins.
//!
//! [`PredicateSet`]: ratatoskr::predicate::PredicateSet
//! [`ControlBodyType::PredicateSetUpdate`]: ratatoskr::control_frame::ControlBodyType::PredicateSetUpdate
//! [`RuleSet`]: ratatoskr::rule::RuleSet
//! [`predicate_reject::VERSION_STALE`]: ratatoskr::predicate::predicate_reject::VERSION_STALE

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use ratatoskr::control_frame::{AckStatus, ControlBodyType};
use ratatoskr::predicate::{predicate_reject, PredicateSet, PREDICATE_SET_MAX_WIRE_BYTES};
use ratatoskr::pubkey::PubKey;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::chain::derive::{derive, DeriveConfig};
use crate::chain::introspection::IntrospectionState;
use crate::proxy::supervisor::SupervisorHandle;

/// State file name under `state_dir`. Single file regardless of how many
/// origins the relay accepts predicates from.
const STATE_FILE: &str = "chain-predicates.toml";

/// On-disk envelope. `origins` ordered by serialised pubkey for stable
/// diffs.
#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedState {
    #[serde(default)]
    origins: Vec<OriginRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OriginRecord {
    pubkey: PubKey,
    version: u64,
}

/// In-memory tracking state. Mirrors `PersistedState.origins` indexed by
/// `PubKey` for O(1) lookup.
#[derive(Debug, Default)]
struct InMemoryState {
    versions: HashMap<PubKey, u64>,
}

impl InMemoryState {
    fn from_persisted(p: &PersistedState) -> Self {
        let mut versions = HashMap::new();
        for r in &p.origins {
            versions.insert(r.pubkey, r.version);
        }
        Self { versions }
    }

    fn to_persisted(&self) -> PersistedState {
        let mut origins: Vec<OriginRecord> = self
            .versions
            .iter()
            .map(|(k, v)| OriginRecord {
                pubkey: *k,
                version: *v,
            })
            .collect();
        // Stable order for diffs / human inspection.
        origins.sort_by_key(|a| a.pubkey.to_string());
        PersistedState { origins }
    }
}

/// Relay-side chain control-plane dispatcher. Construct via
/// [`ChainAcceptor::load`] and pass into [`HeartbeatServer::bind`] (a
/// future signature change) or invoke directly from tests.
pub struct ChainAcceptor {
    supervisor: SupervisorHandle,
    derive_cfg: DeriveConfig,
    state_path: PathBuf,
    state: Mutex<InMemoryState>,
    /// Late-bound chain-introspection sink. Phase 5B's
    /// `/internal/derived-rules` HTTP endpoint reads from this. When
    /// unset (e.g. tests, or relays where the introspection endpoint
    /// is intentionally disabled), `handle_predicate_set_update`
    /// silently skips the `record_apply` notification.
    ///
    /// See [`set_introspection`](ChainAcceptor::set_introspection).
    introspection: OnceLock<Arc<IntrospectionState>>,
}

impl ChainAcceptor {
    /// Load (or initialise) the per-origin version state from
    /// `<state_dir>/chain-predicates.toml`. Missing file is treated as
    /// empty state; malformed file is a hard error (operator action
    /// required, same posture as `pending_peers.toml`).
    pub fn load(
        supervisor: SupervisorHandle,
        derive_cfg: DeriveConfig,
        state_dir: impl AsRef<Path>,
    ) -> Result<Arc<Self>> {
        let state_path = state_dir.as_ref().join(STATE_FILE);
        let persisted = if state_path.exists() {
            let text = std::fs::read_to_string(&state_path)
                .with_context(|| format!("read {}", state_path.display()))?;
            toml::from_str::<PersistedState>(&text)
                .with_context(|| format!("parse {}", state_path.display()))?
        } else {
            PersistedState::default()
        };
        let state = InMemoryState::from_persisted(&persisted);
        Ok(Arc::new(Self {
            supervisor,
            derive_cfg,
            state_path,
            state: Mutex::new(state),
            introspection: OnceLock::new(),
        }))
    }

    /// Attach the chain-introspection sink. Must be called at most
    /// once; further calls return the state back to the caller.
    ///
    /// Wiring is opt-in: relays that disable the introspection HTTP
    /// endpoint simply never call this and the `record_apply` notify
    /// in [`handle_predicate_set_update`](Self::handle_predicate_set_update)
    /// degenerates to a no-op.
    pub fn set_introspection(
        &self,
        ix: Arc<IntrospectionState>,
    ) -> std::result::Result<(), Arc<IntrospectionState>> {
        self.introspection.set(ix)
    }

    /// Decode + dispatch one [`ControlEnvelope`] body and return the
    /// status the receiver should ack with. Unknown body types ack
    /// `Unknown`; recognised bodies that fail validation ack
    /// `Reject(code)`.
    ///
    /// [`ControlEnvelope`]: ratatoskr::control_frame::ControlEnvelope
    pub async fn dispatch(&self, body_type: u8, body: &[u8]) -> AckStatus {
        let kind = match ControlBodyType::from_byte(body_type) {
            Some(k) => k,
            None => {
                tracing::debug!(
                    body_type = body_type,
                    "control envelope: unknown body type"
                );
                metrics::counter!(
                    "yggdrasil_chain_predicate_recv_total",
                    "outcome" => "unknown_body",
                )
                .increment(1);
                return AckStatus::Unknown;
            }
        };
        match kind {
            ControlBodyType::Reserved | ControlBodyType::Noop => {
                tracing::debug!(
                    body_type = body_type,
                    "control envelope: ignorable body type, acking Ok"
                );
                AckStatus::Ok
            }
            ControlBodyType::PredicateSetUpdate => {
                self.handle_predicate_set_update(body).await
            }
        }
    }

    async fn handle_predicate_set_update(&self, body: &[u8]) -> AckStatus {
        if body.len() > PREDICATE_SET_MAX_WIRE_BYTES {
            tracing::warn!(
                bytes = body.len(),
                cap = PREDICATE_SET_MAX_WIRE_BYTES,
                "predicate set exceeds wire cap; rejecting"
            );
            metrics::counter!(
                "yggdrasil_chain_predicate_recv_total",
                "outcome" => "too_large",
            )
            .increment(1);
            return AckStatus::Reject(predicate_reject::PREDICATE_SET_TOO_LARGE);
        }
        let set: PredicateSet = match postcard::from_bytes(body) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "predicate set decode failed");
                metrics::counter!(
                    "yggdrasil_chain_predicate_recv_total",
                    "outcome" => "decode_error",
                )
                .increment(1);
                // No registry code for "this body did not parse as the
                // body type declared on the wire" — INVALID_PREDICATE is
                // the closest match and the operator will see the warn
                // in logs.
                return AckStatus::Reject(predicate_reject::INVALID_PREDICATE);
            }
        };

        // Version invariant: strictly monotone per origin.
        {
            let state = self.state.lock().await;
            if let Some(&last) = state.versions.get(&set.origin) {
                if set.version <= last {
                    tracing::warn!(
                        origin = %set.origin,
                        offered = set.version,
                        last_accepted = last,
                        "predicate set version is stale"
                    );
                    metrics::counter!(
                        "yggdrasil_chain_predicate_recv_total",
                        "outcome" => "stale",
                    )
                    .increment(1);
                    return AckStatus::Reject(predicate_reject::VERSION_STALE);
                }
            }
        }

        // Derive into a RuleSet. Errors here are operator-fault on the
        // sender (invalid name, duplicate listen, etc.).
        let rules = match derive(&set, &self.derive_cfg) {
            Ok(r) => r,
            Err(e) => {
                let code = e.reject_code();
                tracing::warn!(
                    origin = %set.origin,
                    version = set.version,
                    error = %e,
                    reject_code = code,
                    "predicate set rejected by derive"
                );
                metrics::counter!(
                    "yggdrasil_chain_predicate_recv_total",
                    "outcome" => "derive_error",
                    "code" => code.to_string(),
                )
                .increment(1);
                return AckStatus::Reject(code);
            }
        };

        // Apply to the supervisor. The supervisor recomputes its own diff
        // against `current_set`; we just hand off the new set.
        if let Err(e) = self.supervisor.apply_ruleset(rules).await {
            tracing::error!(
                origin = %set.origin,
                version = set.version,
                error = %e,
                "supervisor refused predicate apply (shutting down?)"
            );
            metrics::counter!(
                "yggdrasil_chain_predicate_recv_total",
                "outcome" => "supervisor_down",
            )
            .increment(1);
            // Use Reject so the sender retries on the next session.
            return AckStatus::Reject(predicate_reject::INVALID_PREDICATE);
        }

        // Persist the new accepted version. Hold the lock across the
        // disk write so a concurrent dispatch cannot observe a stale
        // in-memory state that hasn't been written yet.
        {
            let mut state = self.state.lock().await;
            state.versions.insert(set.origin, set.version);
            if let Err(e) = write_atomic(&self.state_path, &state.to_persisted()) {
                tracing::error!(
                    error = %e,
                    "failed to persist chain-predicates state file"
                );
                // We already applied to the supervisor; reverting now
                // would be worse than carrying on. Surface the failure
                // in metrics so operators can alert.
                metrics::counter!(
                    "yggdrasil_chain_predicate_recv_total",
                    "outcome" => "persist_error",
                )
                .increment(1);
            }
        }

        tracing::info!(
            origin = %set.origin,
            version = set.version,
            predicates = set.predicates.len(),
            "predicate set accepted and applied"
        );
        metrics::counter!(
            "yggdrasil_chain_predicate_recv_total",
            "outcome" => "ok",
        )
        .increment(1);
        metrics::gauge!(
            "yggdrasil_chain_predicate_accepted_version",
            "origin" => set.origin.to_string(),
        )
        .set(set.version as f64);

        // Phase 5B: notify the introspection sink, if one is attached.
        // This populates the `/internal/derived-rules` snapshot with the
        // predicate set we just applied. Skipped silently when no sink
        // is wired (tests, future opt-out).
        if let Some(ix) = self.introspection.get() {
            ix.record_apply(&set);
        }

        AckStatus::Ok
    }

    /// Test-only accessor for the last accepted version of `origin`.
    #[cfg(test)]
    pub(crate) async fn last_accepted_version(&self, origin: &PubKey) -> Option<u64> {
        self.state.lock().await.versions.get(origin).copied()
    }
}

fn write_atomic(path: &Path, state: &PersistedState) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
    }
    let text = toml::to_string_pretty(state).context("serialise chain-predicates TOML")?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use ratatoskr::auth::PUBLIC_KEY_LEN;
    use ratatoskr::predicate::Predicate;
    use ratatoskr::rule::Protocol;
    use tokio::time::sleep;
    use tokio_util::sync::CancellationToken;

    use crate::proxy::resolver::ResolverFactory;
    use crate::proxy::supervisor::{CertConfig, ProxySupervisor};

    fn origin_a() -> PubKey {
        PubKey::x25519([0xAAu8; PUBLIC_KEY_LEN])
    }

    fn predicate_set(origin: PubKey, version: u64, ports: &[u16]) -> PredicateSet {
        let mut predicates: Vec<Predicate> = ports
            .iter()
            .enumerate()
            .map(|(i, p)| Predicate {
                name: format!("rule-{i}"),
                listen_port: *p,
                protocol: Protocol::Tcp,
                idle_timeout_ms: None,
            })
            .collect();
        predicates.sort_by(|a, b| a.name.cmp(&b.name));
        PredicateSet {
            predicates,
            version,
            origin,
        }
    }

    fn encode(set: &PredicateSet) -> Vec<u8> {
        postcard::to_allocvec(set).unwrap()
    }

    /// Spawn a real supervisor against an empty rules dir; returns the
    /// supervisor plus its handle.
    async fn spawn_supervisor(
        cancel: CancellationToken,
    ) -> (ProxySupervisor, SupervisorHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let peer = crate::heartbeat::PeerState::new([0u8; 32]);
        let factory = ResolverFactory::new_relay(peer);
        let sup = ProxySupervisor::spawn(
            dir.path().to_path_buf(),
            Duration::from_millis(50),
            factory,
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            CertConfig::default(),
            cancel,
        )
        .await
        .unwrap();
        let handle = sup.handle();
        (sup, handle, dir)
    }

    async fn await_snapshot_len(sup: &ProxySupervisor, target: usize) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if sup.snapshot().len() == target {
                return;
            }
            if std::time::Instant::now() >= deadline {
                panic!(
                    "timed out waiting for snapshot len {target}; have {}",
                    sup.snapshot().len()
                );
            }
            sleep(Duration::from_millis(20)).await;
        }
    }

    fn derive_cfg() -> DeriveConfig {
        DeriveConfig {
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            proxy_protocol: None,
        }
    }

    #[tokio::test]
    async fn accepts_fresh_set_and_applies_to_supervisor() {
        let cancel = CancellationToken::new();
        let (sup, handle, _rules_dir) = spawn_supervisor(cancel.clone()).await;
        let state_dir = tempfile::tempdir().unwrap();
        let acc = ChainAcceptor::load(handle, derive_cfg(), state_dir.path()).unwrap();

        let set = predicate_set(origin_a(), 1, &[free_port(), free_port()]);
        let bytes = encode(&set);
        let status = acc
            .dispatch(ControlBodyType::PredicateSetUpdate.as_byte(), &bytes)
            .await;
        assert_eq!(status, AckStatus::Ok);

        await_snapshot_len(&sup, 2).await;
        assert_eq!(acc.last_accepted_version(&origin_a()).await, Some(1));

        // The state file should exist on disk and reflect the accepted version.
        let written = std::fs::read_to_string(state_dir.path().join(STATE_FILE)).unwrap();
        assert!(written.contains(&origin_a().to_string()));
        assert!(written.contains("version = 1"));

        cancel.cancel();
        sup.stop().await;
    }

    #[tokio::test]
    async fn rejects_stale_version() {
        let cancel = CancellationToken::new();
        let (sup, handle, _rules_dir) = spawn_supervisor(cancel.clone()).await;
        let state_dir = tempfile::tempdir().unwrap();
        let acc = ChainAcceptor::load(handle, derive_cfg(), state_dir.path()).unwrap();

        let p = free_port();
        let v2 = encode(&predicate_set(origin_a(), 2, &[p]));
        assert_eq!(
            acc.dispatch(ControlBodyType::PredicateSetUpdate.as_byte(), &v2)
                .await,
            AckStatus::Ok
        );

        // v1 < v2 → stale.
        let v1 = encode(&predicate_set(origin_a(), 1, &[p]));
        assert_eq!(
            acc.dispatch(ControlBodyType::PredicateSetUpdate.as_byte(), &v1)
                .await,
            AckStatus::Reject(predicate_reject::VERSION_STALE),
        );

        // v2 again is also stale (strict monotone, not just LE).
        let v2_again = encode(&predicate_set(origin_a(), 2, &[p]));
        assert_eq!(
            acc.dispatch(ControlBodyType::PredicateSetUpdate.as_byte(), &v2_again)
                .await,
            AckStatus::Reject(predicate_reject::VERSION_STALE),
        );

        cancel.cancel();
        sup.stop().await;
    }

    #[tokio::test]
    async fn rejects_oversize_body() {
        let cancel = CancellationToken::new();
        let (sup, handle, _rules_dir) = spawn_supervisor(cancel.clone()).await;
        let state_dir = tempfile::tempdir().unwrap();
        let acc = ChainAcceptor::load(handle, derive_cfg(), state_dir.path()).unwrap();

        let big = vec![0u8; PREDICATE_SET_MAX_WIRE_BYTES + 1];
        assert_eq!(
            acc.dispatch(ControlBodyType::PredicateSetUpdate.as_byte(), &big)
                .await,
            AckStatus::Reject(predicate_reject::PREDICATE_SET_TOO_LARGE),
        );

        cancel.cancel();
        sup.stop().await;
    }

    #[tokio::test]
    async fn unknown_body_type_acks_unknown() {
        let cancel = CancellationToken::new();
        let (sup, handle, _rules_dir) = spawn_supervisor(cancel.clone()).await;
        let state_dir = tempfile::tempdir().unwrap();
        let acc = ChainAcceptor::load(handle, derive_cfg(), state_dir.path()).unwrap();

        // 0x7F is unassigned in the registry.
        let status = acc.dispatch(0x7F, &[]).await;
        assert_eq!(status, AckStatus::Unknown);

        cancel.cancel();
        sup.stop().await;
    }

    #[tokio::test]
    async fn malformed_body_rejects_with_invalid_predicate() {
        let cancel = CancellationToken::new();
        let (sup, handle, _rules_dir) = spawn_supervisor(cancel.clone()).await;
        let state_dir = tempfile::tempdir().unwrap();
        let acc = ChainAcceptor::load(handle, derive_cfg(), state_dir.path()).unwrap();

        // Random bytes that aren't a valid postcard PredicateSet.
        let junk = b"this is not a predicate set";
        assert_eq!(
            acc.dispatch(ControlBodyType::PredicateSetUpdate.as_byte(), junk)
                .await,
            AckStatus::Reject(predicate_reject::INVALID_PREDICATE),
        );

        cancel.cancel();
        sup.stop().await;
    }

    #[tokio::test]
    async fn state_persists_across_load_reload() {
        let cancel = CancellationToken::new();
        let (sup, handle, _rules_dir) = spawn_supervisor(cancel.clone()).await;
        let state_dir = tempfile::tempdir().unwrap();

        let acc1 = ChainAcceptor::load(handle.clone(), derive_cfg(), state_dir.path()).unwrap();
        let bytes = encode(&predicate_set(origin_a(), 7, &[free_port()]));
        assert_eq!(
            acc1.dispatch(ControlBodyType::PredicateSetUpdate.as_byte(), &bytes)
                .await,
            AckStatus::Ok
        );
        drop(acc1);

        let acc2 = ChainAcceptor::load(handle, derive_cfg(), state_dir.path()).unwrap();
        assert_eq!(acc2.last_accepted_version(&origin_a()).await, Some(7));

        cancel.cancel();
        sup.stop().await;
    }

    fn free_port() -> u16 {
        // Bind synchronously to get an OS-assigned port. Listener drops
        // immediately; brief race-on-bind is tolerable because each test
        // only constructs the predicate set, never actually listens.
        let s = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let p = s.local_addr().unwrap().port();
        drop(s);
        p
    }
}
