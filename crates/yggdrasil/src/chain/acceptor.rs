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
//! Terminals are the only authors of predicates, so `PredicateSet.origin`
//! always identifies a terminal. The relay deliberately does not
//! validate that `origin == downstream_pubkey`: in a multi-hop chain,
//! a mid-chain relay receives the predicate set forwarded by the
//! immediate downstream relay, whose body still carries the original
//! terminal's pubkey as `origin` (forwarding is byte-identical; see
//! `handle_predicate_set_update` below). Test drivers also rely on
//! this looseness to push synthetic origins.
//!
//! [`PredicateSet`]: ratatoskr::predicate::PredicateSet
//! [`ControlBodyType::PredicateSetUpdate`]: ratatoskr::control_frame::ControlBodyType::PredicateSetUpdate
//! [`RuleSet`]: ratatoskr::rule::RuleSet
//! [`predicate_reject::VERSION_STALE`]: ratatoskr::predicate::predicate_reject::VERSION_STALE

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use ratatoskr::canary::{
    CanaryArm as CanaryArmFrame, CanaryHop, CanaryReply, CANARY_REPLY_MAX_WIRE_BYTES,
};
use ratatoskr::chain_query::{ChainHopQuery, ChainHopReply, CHAIN_HOP_REPLY_MAX_WIRE_BYTES};
use ratatoskr::control::{ChainHop, Mode};
use ratatoskr::control_frame::{AckStatus, ControlBodyType, ControlEnvelope};
use ratatoskr::predicate::{predicate_reject, PredicateSet, PREDICATE_SET_MAX_WIRE_BYTES};
use ratatoskr::pubkey::PubKey;
use ratatoskr::rule::Protocol;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};

use crate::chain::client::{ChainClientHandle, QueryError};
use crate::chain::derive::{derive, DeriveConfig};
use crate::chain::introspection::IntrospectionState;
use crate::proxy::canary::CanaryArmTable;
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
    /// Late-bound chain-introspection sink. The `Request::DerivedRules`
    /// UDS handler reads from this. When unset (e.g. tests, or relays
    /// where the introspection endpoint is intentionally disabled),
    /// `handle_predicate_set_update` silently skips the `record_apply`
    /// notification.
    ///
    /// See [`set_introspection`](ChainAcceptor::set_introspection).
    introspection: OnceLock<Arc<IntrospectionState>>,
    /// Wall-clock process start (Instant). Used to compute the
    /// `uptime_secs` field of the local [`ChainHop`] returned in
    /// `ChainHopReply`.
    started_at: Instant,
    /// Daemon mode. Stamped onto the local [`ChainHop`] emitted in
    /// `ChainHopReply`. Settable via
    /// [`set_mode`](ChainAcceptor::set_mode); defaults to
    /// [`Mode::Relay`] (the only mode that runs an acceptor on the
    /// downstream-facing side).
    mode: OnceLock<Mode>,
    /// Resolved `[server].name` (or hostname fallback). Stamped onto
    /// the local [`ChainHop`] so cross-chain renderers can label hops
    /// by something more readable than their pubkey. Set via
    /// [`set_node_name`](ChainAcceptor::set_node_name); when unset
    /// the local hop reports `name = None`.
    node_name: OnceLock<String>,
    /// Downstream-facing outbound channel hand into the heartbeat
    /// server. The acceptor uses this to push `ChainHopReply`
    /// envelopes back down the chain after assembling them. Unset
    /// for relays without a wired heartbeat server (tests); in that
    /// case `ChainHopQuery` is acked `Ok` but no reply is emitted.
    outbound: OnceLock<mpsc::UnboundedSender<ControlEnvelope>>,
    /// Optional upstream chain-client handle used to recursively
    /// forward `ChainHopQuery` further up the chain. Absent on
    /// nodes without `[dial]` (gateways and top-of-chain relays); in
    /// that case the reply contains only this hop's local view.
    upstream: OnceLock<ChainClientHandle>,
    /// Shared per-daemon canary arm table. Set by `set_arm_table`
    /// when the daemon wires the canary surface. When unset, an
    /// incoming `CanaryArm` is still handled (the recursion continues
    /// up the chain so the reply assembles correctly) but the local
    /// arm-installation step is a no-op, so probe traffic at this
    /// hop's listeners would forward to the configured backend.
    arm_table: OnceLock<Arc<CanaryArmTable>>,
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
            started_at: Instant::now(),
            mode: OnceLock::new(),
            node_name: OnceLock::new(),
            outbound: OnceLock::new(),
            upstream: OnceLock::new(),
            arm_table: OnceLock::new(),
        }))
    }

    /// Set the daemon mode reported on the local [`ChainHop`] of
    /// `ChainHopReply`. Must be called at most once. Idempotent
    /// no-op for callers that don't need to override the default
    /// [`Mode::Relay`].
    pub fn set_mode(&self, mode: Mode) -> std::result::Result<(), Mode> {
        self.mode.set(mode)
    }

    /// Install the resolved node name (`[server].name`, falling back
    /// to `gethostname(3)`) reported in the local [`ChainHop::name`].
    /// Must be called at most once; idempotent no-op when omitted —
    /// the local hop then reports `name = None`.
    pub fn set_node_name(&self, name: String) -> std::result::Result<(), String> {
        self.node_name.set(name)
    }

    /// Install the downstream-facing outbound channel hand from the
    /// heartbeat server. Must be called at most once. Acceptors
    /// without a wired outbound silently drop `ChainHopReply`
    /// emission (the local query times out).
    pub fn set_outbound(
        &self,
        sender: mpsc::UnboundedSender<ControlEnvelope>,
    ) -> std::result::Result<(), mpsc::UnboundedSender<ControlEnvelope>> {
        self.outbound.set(sender)
    }

    /// Install the upstream chain-client handle so this acceptor can
    /// forward `ChainHopQuery`s recursively. Optional: relays without
    /// `[dial]` skip the call and the reply contains only this hop.
    pub fn set_upstream(
        &self,
        handle: ChainClientHandle,
    ) -> std::result::Result<(), ChainClientHandle> {
        self.upstream.set(handle)
    }

    /// Install the shared canary arm table. The terminal-mode handler
    /// for `CanaryArm` consults this to install per-rule arm entries
    /// (so the rule's L4 listener short-circuits matching probe
    /// traffic to an in-process echo). Optional: omit on nodes that
    /// don't run rule listeners.
    pub fn set_arm_table(
        &self,
        table: Arc<CanaryArmTable>,
    ) -> std::result::Result<(), Arc<CanaryArmTable>> {
        self.arm_table.set(table)
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
    /// `ChainHopQuery` is acked `Ok` synchronously; the reply walk
    /// runs in a background task spawned on the current tokio runtime
    /// (see [`spawn_chain_hop_query_handler`](Self::spawn_chain_hop_query_handler)).
    ///
    /// [`ControlEnvelope`]: ratatoskr::control_frame::ControlEnvelope
    pub async fn dispatch(self: &Arc<Self>, body_type: u8, body: &[u8]) -> AckStatus {
        let kind = match ControlBodyType::from_byte(body_type) {
            Some(k) => k,
            None => {
                tracing::debug!(body_type = body_type, "control envelope: unknown body type");
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
            ControlBodyType::PredicateSetUpdate => self.handle_predicate_set_update(body).await,
            ControlBodyType::ChainHopQuery => {
                self.spawn_chain_hop_query_handler(body);
                AckStatus::Ok
            }
            ControlBodyType::ChainHopReply => {
                // Acceptors do not consume ChainHopReply — replies are
                // received on the *upstream-facing* chain client side
                // and routed through `QueryRouter`. A reply arriving
                // at the acceptor means the downstream is using the
                // body type backwards; ack Unknown so the operator
                // sees the misuse in metrics/logs.
                tracing::warn!(
                    "drop ChainHopReply on relay-acceptor side (replies flow upstream-to-downstream)"
                );
                AckStatus::Unknown
            }
            ControlBodyType::CanaryArm => {
                self.spawn_canary_arm_handler(body);
                AckStatus::Ok
            }
            ControlBodyType::CanaryReply => {
                // Like ChainHopReply, replies belong on the
                // upstream-facing chain-client side. If one shows up
                // at an acceptor the downstream is mis-encoding.
                tracing::warn!(
                    "drop CanaryReply on relay-acceptor side (replies flow upstream-to-downstream)"
                );
                AckStatus::Unknown
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
        let set: PredicateSet = match PredicateSet::from_wire_bytes(body) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "predicate set decode/validation failed");
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

        // Notify the introspection sink, if one is attached. This
        // populates the `Request::DerivedRules` snapshot with the
        // predicate set we just applied. Skipped silently when no
        // sink is wired (tests, future opt-out).
        if let Some(ix) = self.introspection.get() {
            ix.record_apply(&set);
        }

        // Mid-chain forwarding: if this relay also has an upstream
        // (`[dial]` configured), forward the original body bytes
        // verbatim up the chain. The wire-level origin/version is
        // preserved so each hop applies the same monotone-version
        // invariant against the terminal's pubkey. Failures here are
        // logged but do not fail the downstream ack — the downstream
        // has already done its job by getting the predicate to us.
        if let Some(upstream) = self.upstream.get() {
            match upstream
                .send_control(ControlBodyType::PredicateSetUpdate.as_byte(), body.to_vec())
            {
                Ok(_completion) => {
                    // Fire-and-forget: drop the completion receiver. The
                    // chain client's ControlChannel handles retransmits
                    // internally; if the upstream session is down we
                    // rely on the publisher's reliability layer there.
                    metrics::counter!(
                        "yggdrasil_chain_predicate_forward_total",
                        "outcome" => "enqueued",
                    )
                    .increment(1);
                    tracing::debug!(
                        origin = %set.origin,
                        version = set.version,
                        "predicate set forwarded upstream"
                    );
                }
                Err(_) => {
                    metrics::counter!(
                        "yggdrasil_chain_predicate_forward_total",
                        "outcome" => "client_down",
                    )
                    .increment(1);
                    tracing::warn!(
                        origin = %set.origin,
                        version = set.version,
                        "chain client down; predicate set not forwarded upstream"
                    );
                }
            }
        }

        AckStatus::Ok
    }

    /// Test-only accessor for the last accepted version of `origin`.
    #[cfg(test)]
    pub(crate) async fn last_accepted_version(&self, origin: &PubKey) -> Option<u64> {
        self.state.lock().await.versions.get(origin).copied()
    }

    /// Decode a `ChainHopQuery` body and spawn a background task to
    /// assemble + send the matching `ChainHopReply`. The dispatch
    /// caller has already returned `AckStatus::Ok` for the query
    /// envelope; the reply is a separate `ChainHopReply` envelope
    /// pushed back to the downstream via [`Self::outbound`].
    ///
    /// Decoding failure logs at `warn` and drops the query. Missing
    /// `outbound` channel (acceptor wired without a heartbeat server)
    /// is also a silent drop — the downstream's `query_upstream`
    /// awaiter then times out and surfaces it as `partial = true`.
    fn spawn_chain_hop_query_handler(self: &Arc<Self>, body: &[u8]) {
        let query: ChainHopQuery = match postcard::from_bytes(body) {
            Ok(q) => q,
            Err(e) => {
                tracing::warn!(error = %e, "failed to decode inbound ChainHopQuery");
                metrics::counter!(
                    "yggdrasil_chain_hop_query_total",
                    "outcome" => "decode_error",
                )
                .increment(1);
                return;
            }
        };
        let this = Arc::clone(self);
        tokio::spawn(async move {
            this.handle_chain_hop_query(query).await;
        });
    }

    async fn handle_chain_hop_query(self: Arc<Self>, query: ChainHopQuery) {
        let query_id = query.query_id;
        metrics::counter!(
            "yggdrasil_chain_hop_query_total",
            "outcome" => "received",
        )
        .increment(1);
        let started = Instant::now();

        // 1. Assemble the local hop. Without an introspection sink we
        //    cannot produce a meaningful reply at all; bail with a
        //    partial+error reply so the downstream still sees something.
        let view = match self.introspection.get() {
            Some(ix) => ix.snapshot(),
            None => {
                tracing::warn!(
                    query_id,
                    "ChainHopQuery received but no introspection sink wired; \
                     replying partial",
                );
                self.send_reply(ChainHopReply {
                    query_id,
                    hops: vec![],
                    partial: true,
                    error: Some("local introspection unavailable".into()),
                })
                .await;
                return;
            }
        };
        let mode = self.mode.get().copied().unwrap_or(Mode::Relay);
        let uptime_secs = self.started_at.elapsed().as_secs();
        let name = self.node_name.get().cloned();
        let local_hop = ChainHop {
            hop_index: 0,
            mode,
            uptime_secs,
            name,
            view,
            query_rtt_ms: None,
        };

        // 2. If we have an upstream and budget remaining, forward
        //    the query recursively. Reserve a small overhead for our
        //    own assembly + send so the upstream doesn't deadline
        //    exactly on the boundary.
        const FORWARDING_OVERHEAD_MS: u32 = 250;
        let depth_budget = query.depth_budget.saturating_sub(1);
        let upstream_deadline_ms = query.deadline_ms.saturating_sub(FORWARDING_OVERHEAD_MS);
        let mut hops = vec![local_hop];
        let mut partial = false;
        let mut error: Option<String> = None;

        if let Some(upstream) = self.upstream.get() {
            if depth_budget > 0 && upstream_deadline_ms > 0 {
                let deadline = std::time::Duration::from_millis(upstream_deadline_ms as u64);
                let upstream_started = Instant::now();
                match upstream.query_upstream(depth_budget, deadline).await {
                    Ok(reply) => {
                        let rtt_ms =
                            upstream_started.elapsed().as_millis().min(u64::MAX as u128) as u64;
                        // Renumber upstream hops to extend the local
                        // sequence (local = 0, upstream = 1, ...).
                        // Stamp the RTT we measured on the immediately
                        // adjacent upstream hop (offset == 0); hops
                        // further up the chain were timed by their
                        // respective parents.
                        for (offset, mut hop) in reply.hops.into_iter().enumerate() {
                            hop.hop_index = (hops.len() + offset) as u32;
                            if offset == 0 {
                                hop.query_rtt_ms = Some(rtt_ms);
                            }
                            hops.push(hop);
                        }
                        partial |= reply.partial;
                        if reply.error.is_some() {
                            error = reply.error;
                        }
                    }
                    Err(QueryError::Timeout) => {
                        partial = true;
                        error = Some("upstream chain hop query timed out".into());
                    }
                    Err(e) => {
                        partial = true;
                        error = Some(format!("upstream chain hop query failed: {e}"));
                    }
                }
            } else if depth_budget == 0 {
                // Reached the depth budget; this is an expected truncation,
                // not a failure.
                partial = true;
                error = Some("depth budget exhausted".into());
            } else {
                partial = true;
                error = Some("deadline exhausted before upstream forward".into());
            }
        }

        // 3. Encode + size-check the reply. If oversized, drop upstream
        //    hops and flag partial.
        let mut reply = ChainHopReply {
            query_id,
            hops,
            partial,
            error,
        };
        match postcard::to_allocvec(&reply) {
            Ok(bytes) if bytes.len() > CHAIN_HOP_REPLY_MAX_WIRE_BYTES => {
                tracing::warn!(
                    query_id,
                    bytes = bytes.len(),
                    cap = CHAIN_HOP_REPLY_MAX_WIRE_BYTES,
                    "ChainHopReply oversized; truncating to local hop only",
                );
                reply.hops.truncate(1);
                reply.partial = true;
                reply.error = Some(format!(
                    "reply exceeded {CHAIN_HOP_REPLY_MAX_WIRE_BYTES} bytes; \
                     truncated to local hop"
                ));
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(query_id, error = %e, "failed to encode ChainHopReply");
                return;
            }
        }

        metrics::counter!(
            "yggdrasil_chain_hop_query_total",
            "outcome" => if reply.partial { "replied_partial" } else { "replied_ok" },
        )
        .increment(1);
        metrics::histogram!("yggdrasil_chain_hop_query_walk_seconds")
            .record(started.elapsed().as_secs_f64());

        self.send_reply(reply).await;
    }

    async fn send_reply(self: &Arc<Self>, reply: ChainHopReply) {
        let bytes = match postcard::to_allocvec(&reply) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "failed to encode ChainHopReply for send");
                return;
            }
        };
        let outbound = match self.outbound.get() {
            Some(o) => o,
            None => {
                tracing::debug!(
                    query_id = reply.query_id,
                    "no downstream outbound wired; dropping ChainHopReply",
                );
                return;
            }
        };
        let env = ControlEnvelope {
            seq: 0, // heartbeat server assigns the per-session seq
            body_type: ControlBodyType::ChainHopReply.as_byte(),
            body: bytes,
        };
        if outbound.send(env).is_err() {
            tracing::warn!(
                query_id = reply.query_id,
                "outbound channel closed; dropping ChainHopReply",
            );
        }
    }

    /// Decode a `CanaryArm` body and spawn a background task to
    /// install the arm locally (terminal-only), recurse upstream, and
    /// emit a [`CanaryReply`] back down the chain. Mirrors the
    /// [`spawn_chain_hop_query_handler`](Self::spawn_chain_hop_query_handler)
    /// shape.
    fn spawn_canary_arm_handler(self: &Arc<Self>, body: &[u8]) {
        let arm: CanaryArmFrame = match postcard::from_bytes(body) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(error = %e, "failed to decode inbound CanaryArm");
                metrics::counter!(
                    "yggdrasil_canary_arm_total",
                    "outcome" => "decode_error",
                )
                .increment(1);
                return;
            }
        };
        let this = Arc::clone(self);
        tokio::spawn(async move {
            this.handle_canary_arm(arm).await;
        });
    }

    async fn handle_canary_arm(self: Arc<Self>, arm: CanaryArmFrame) {
        let query_id = arm.query_id;
        metrics::counter!(
            "yggdrasil_canary_arm_total",
            "outcome" => "received",
        )
        .increment(1);
        let started = Instant::now();

        // 1. Local hop assembly. Without introspection we don't know
        //    our own pubkey, so bail with a partial reply.
        let local_pubkey = match self.introspection.get() {
            Some(ix) => ix.snapshot().chain.local,
            None => {
                tracing::warn!(
                    query_id,
                    "CanaryArm received but no introspection sink wired; replying partial",
                );
                self.send_canary_reply(CanaryReply {
                    query_id,
                    hops: vec![],
                    partial: true,
                    error: Some("local introspection unavailable".into()),
                })
                .await;
                return;
            }
        };
        let mode = self.mode.get().copied().unwrap_or(Mode::Relay);
        let name = self.node_name.get().cloned();
        let rule_present = self.has_matching_rule(arm.rule_listen, arm.rule_protocol);
        // Only terminal-mode hops install the in-process echo
        // intercept — relays just pass bytes through at L4, so there's
        // nothing to short-circuit at the relay's rule listener.
        let echo_armed = if mode == Mode::Terminal && rule_present {
            if let Some(table) = self.arm_table.get() {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                // Server-side TTL clamp: never trust a remote-supplied
                // expiry beyond a local maximum. 60s comfortably covers
                // the canary's default probe duration + grace; longer
                // arms have no operational use case and represent
                // unnecessary surface.
                const SERVER_MAX_ARM_TTL_MS: u64 = 60_000;
                let raw_ttl_ms = arm.expires_unix_ms.saturating_sub(now_ms);
                let ttl_ms = raw_ttl_ms.min(SERVER_MAX_ARM_TTL_MS);
                if ttl_ms > 0 {
                    table.arm(
                        arm.rule_listen,
                        arm.rule_protocol,
                        arm.token,
                        Duration::from_millis(ttl_ms),
                    );
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        let local_hop = CanaryHop {
            hop_index: 0,
            pubkey: local_pubkey,
            name,
            mode,
            rule_present,
            echo_armed,
            query_rtt_ms: None,
        };

        // 2. Recurse upstream when we still have budget + an upstream.
        const FORWARDING_OVERHEAD_MS: u32 = 250;
        let depth_budget = arm.depth_budget.saturating_sub(1);
        let upstream_deadline_ms = arm.deadline_ms.saturating_sub(FORWARDING_OVERHEAD_MS);
        let mut hops = vec![local_hop];
        let mut partial = false;
        let mut error: Option<String> = None;

        if let Some(upstream) = self.upstream.get() {
            if depth_budget > 0 && upstream_deadline_ms > 0 {
                let deadline = Duration::from_millis(upstream_deadline_ms as u64);
                let upstream_started = Instant::now();
                let upstream_arm = CanaryArmFrame {
                    query_id: 0, // overwritten by the router
                    depth_budget,
                    deadline_ms: upstream_deadline_ms,
                    rule_listen: arm.rule_listen,
                    rule_protocol: arm.rule_protocol,
                    token: arm.token,
                    expires_unix_ms: arm.expires_unix_ms,
                };
                match upstream.query_upstream_canary(upstream_arm, deadline).await {
                    Ok(reply) => {
                        let rtt_ms =
                            upstream_started.elapsed().as_millis().min(u64::MAX as u128) as u64;
                        for (offset, mut hop) in reply.hops.into_iter().enumerate() {
                            hop.hop_index = (hops.len() + offset) as u32;
                            if offset == 0 {
                                hop.query_rtt_ms = Some(rtt_ms);
                            }
                            hops.push(hop);
                        }
                        if reply.partial {
                            partial = true;
                            error = reply.error;
                        }
                    }
                    Err(e) => {
                        partial = true;
                        error = Some(format!("upstream canary arm failed: {e}"));
                    }
                }
            } else if depth_budget == 0 {
                partial = true;
                error = Some("depth budget exhausted".into());
            } else {
                partial = true;
                error = Some("deadline exhausted before upstream forward".into());
            }
        }

        // 3. Encode + size-check the reply. Oversize → truncate to
        //    local hop + flag partial.
        let mut reply = CanaryReply {
            query_id,
            hops,
            partial,
            error,
        };
        match postcard::to_allocvec(&reply) {
            Ok(bytes) if bytes.len() > CANARY_REPLY_MAX_WIRE_BYTES => {
                tracing::warn!(
                    query_id,
                    bytes = bytes.len(),
                    cap = CANARY_REPLY_MAX_WIRE_BYTES,
                    "CanaryReply oversized; truncating to local hop only",
                );
                reply.hops.truncate(1);
                reply.partial = true;
                reply.error = Some(format!(
                    "reply exceeded {CANARY_REPLY_MAX_WIRE_BYTES} bytes; truncated to local hop"
                ));
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(query_id, error = %e, "failed to encode CanaryReply");
                return;
            }
        }

        metrics::counter!(
            "yggdrasil_canary_arm_total",
            "outcome" => if reply.partial { "replied_partial" } else { "replied_ok" },
        )
        .increment(1);
        metrics::histogram!("yggdrasil_canary_arm_walk_seconds")
            .record(started.elapsed().as_secs_f64());

        self.send_canary_reply(reply).await;
    }

    /// Check the supervisor's current rule set for a non-HTTPS rule
    /// whose `listen` and `protocol` exactly match the canary arm's
    /// targets. HTTPS rules are not matched: canary operates on a
    /// single L4 transport per invocation, and an HTTPS rule's
    /// `protocol` is [`Protocol::Https`], not [`Protocol::Tcp`] or
    /// [`Protocol::Udp`].
    fn has_matching_rule(&self, listen: std::net::SocketAddr, protocol: Protocol) -> bool {
        let set = self.supervisor.current_set_rx();
        let snap = set.borrow();
        snap.rules()
            .iter()
            .any(|r| r.listen == listen && r.protocol == protocol)
    }

    async fn send_canary_reply(self: &Arc<Self>, reply: CanaryReply) {
        let bytes = match postcard::to_allocvec(&reply) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "failed to encode CanaryReply for send");
                return;
            }
        };
        let outbound = match self.outbound.get() {
            Some(o) => o,
            None => {
                tracing::debug!(
                    query_id = reply.query_id,
                    "no downstream outbound wired; dropping CanaryReply",
                );
                return;
            }
        };
        let env = ControlEnvelope {
            seq: 0,
            body_type: ControlBodyType::CanaryReply.as_byte(),
            body: bytes,
        };
        if outbound.send(env).is_err() {
            tracing::warn!(
                query_id = reply.query_id,
                "outbound channel closed; dropping CanaryReply",
            );
        }
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
                https_http3: false,
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
            None,
            CertConfig::default(),
            None,
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
