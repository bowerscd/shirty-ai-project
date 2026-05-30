//! ACME (RFC 8555) issuance and renewal for routes that declare
//! `cert = "acme"`.
//!
//! ## Architecture
//!
//! [`AcmeManager`] owns the per-host renewer tasks. It hangs off the
//! proxy supervisor for the lifetime of the daemon and gets a clone of
//! the shared [`CertStore`] handle so it can drive
//! [`CertStore::reload_host`] after writing each freshly-issued cert.
//!
//! Per ACME route (i.e. each `[[rule.route]]` whose `cert = "acme"`):
//!
//! 1. The supervisor invokes `AcmeManager::register(host, AcmeRouteConfig)`
//!    at rule-load time.
//! 2. The manager spawns (or reuses) a [`renewer::Renewer`] task scoped
//!    to that host. The renewer's first action is to check the
//!    convention path: if `fullchain.pem` exists and `not_after` is
//!    further out than `renew_before`, schedule renewal at
//!    `not_after - renew_before ± jitter`. Otherwise: issue now.
//! 3. Issuance drives the ACME order against the operator-configured
//!    directory URL via [`client::AcmeClient`]; HTTP-01 challenges land
//!    on the shared [`http01::AcmeResponder`] (registered with the
//!    `:80` `RedirectListener`); DNS-01 challenges go through the
//!    [`provider::DnsProvider`] resolved from the [`provider::ProviderRegistry`].
//! 4. On success, the renewer writes `{storage_dir}/{host}/{fullchain,
//!    privkey}.pem` atomically (tempfile + rename) and calls
//!    `cert_store.reload_host(host)` plus re-registers the host with
//!    `cert_watcher` so subsequent operator-side rewrites also hot-reload.
//!
//! ## Module layout
//!
//! - [`account`] — long-lived ACME account key load/persist.
//! - [`client`] — ACME directory client (issuance, finalisation, polling).
//! - [`http01`] — token responder hooked into the `:80` redirect listener.
//! - [`dns01`] — DNS-01 challenge driver + propagation poll.
//! - [`provider`] — [`provider::DnsProvider`] trait + registry.
//! - [`providers::cloudflare`] — Cloudflare REST-API DNS provider.
//! - [`renewer`] — per-host renewal scheduler.
//! - [`storage`] — atomic on-disk writeout of issued cert material.
//!
//! [`CertStore`]: crate::proxy::certs::CertStore
//! [`CertStore::reload_host`]: crate::proxy::certs::CertStore::reload_host

pub mod account;
pub mod client;
pub mod dns01;
pub mod http01;
pub mod provider;
pub mod providers;
pub mod renewer;
pub mod storage;

pub use http01::AcmeResponder;
pub use provider::{DnsProvider, ProviderRegistry, TxtHandle};

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::config::AcmeSection;
use crate::proxy::certs::CertStore;

/// Per-route ACME configuration. Owned by this module after the
/// schema-cleanup that removed per-route cert sources from
/// `ratatoskr::rule::HttpRoute`. Kept as a stable shape so the
/// renewer/client/storage layers continue to compile against the
/// existing API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcmeRouteConfig {
    pub challenge: AcmeChallenge,
    pub provider: Option<String>,
}

impl AcmeRouteConfig {
    pub fn http01() -> Self {
        Self {
            challenge: AcmeChallenge::Http01,
            provider: None,
        }
    }
}

/// Challenge selector for an ACME-managed route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcmeChallenge {
    Http01,
    Dns01,
}

/// Errors produced anywhere in the ACME pipeline.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error("ACME route {host:?}: provider {provider:?} is not registered in [acme.dns]")]
    UnknownProvider { host: String, provider: String },
    #[error("ACME route {host:?}: HTTP-01 requires the daemon's :80 redirect listener to be online (no HTTPS rule loaded yet)")]
    NoHttp01Responder { host: String },
    #[error("ACME route {host:?}: DNS provider error: {detail}")]
    Dns { host: String, detail: String },
    #[error("ACME route {host:?}: account-key error: {detail}")]
    Account { host: String, detail: String },
    #[error("ACME route {host:?}: storage error: {detail}")]
    Storage { host: String, detail: String },
    #[error("ACME route {host:?}: directory client error: {detail}")]
    Client { host: String, detail: String },
}

/// Public handle: the supervisor owns one of these, and registers each
/// ACME-managed hostname against it.
#[derive(Debug, Clone)]
pub struct AcmeManager {
    inner: Arc<AcmeManagerInner>,
}

#[derive(Debug)]
struct AcmeManagerInner {
    /// Operator config (directory URL, contact email, renew window).
    config: AcmeSection,
    /// Where to write issued certs. Falls back to `[server].cert_dir`
    /// when `[acme].storage_dir` is unset.
    storage_dir: PathBuf,
    /// Provider registry built from `[acme.dns.*]` at startup.
    providers: ProviderRegistry,
    /// HTTP-01 token responder. Hooked into the `:80` redirect listener
    /// by the supervisor when the first HTTPS rule loads.
    responder: AcmeResponder,
    /// Shared cert store: we call `reload_host` after each successful
    /// issuance/renewal so the new PEM bytes go live without a daemon
    /// restart.
    cert_store: Arc<CertStore>,
    /// Per-supervisor cancellation token. Renewer tasks observe this
    /// cooperatively.
    cancel: CancellationToken,
    /// Renew certs this far in advance of `not_after`.
    renew_before: Duration,
    /// Random jitter added to the renewal time.
    renew_jitter: Duration,
    /// Per-host renewer-task state. Read by `list_managed()` /
    /// `force_renew()`, updated by the renewer task on every cycle.
    hosts: parking_lot::RwLock<std::collections::HashMap<String, HostState>>,
}

/// In-memory view of a single ACME-managed route. The renewer task
/// updates this on every issue attempt; the control surface reads
/// snapshots via [`AcmeManager::list_managed`].
#[derive(Debug, Clone)]
pub(crate) struct HostState {
    pub(crate) route_cfg: AcmeRouteConfig,
    pub(crate) state: HostStatus,
    pub(crate) last_error: Option<String>,
    pub(crate) next_renewal_unix: Option<u64>,
    pub(crate) not_after_unix: Option<u64>,
    /// `mpsc` sender into the per-host renewer task, used by
    /// `force_renew` to kick an immediate issuance attempt.
    pub(crate) kick_tx: tokio::sync::mpsc::Sender<KickRequest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostStatus {
    /// First issuance hasn't completed yet (ephemeral stand-in
    /// serving meanwhile).
    Pending,
    /// PEM on disk, in active rotation.
    Active,
    /// Last issuance attempt failed; stand-in still serving.
    Error,
}

impl HostStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Error => "error",
        }
    }
}

/// Renewer-task kick request: a one-shot "issue NOW and report back".
#[derive(Debug)]
pub(crate) struct KickRequest {
    pub(crate) reply: tokio::sync::oneshot::Sender<Result<(), AcmeError>>,
}

impl AcmeManager {
    /// Build an `AcmeManager` from the operator config and the shared
    /// cert store. The HTTP-01 responder is created here but stays
    /// dormant until the supervisor wires it into the `:80` redirect
    /// listener.
    pub fn spawn(
        config: AcmeSection,
        server_cert_dir: PathBuf,
        cert_store: Arc<CertStore>,
        cancel: CancellationToken,
    ) -> Result<Self, AcmeError> {
        let storage_dir = config.storage_dir.clone().unwrap_or(server_cert_dir);
        let providers = ProviderRegistry::from_config(&config.dns)?;
        let responder = AcmeResponder::new();
        let renew_before = config.renew_before;
        let renew_jitter = config.renew_jitter;
        Ok(Self {
            inner: Arc::new(AcmeManagerInner {
                config,
                storage_dir,
                providers,
                responder,
                cert_store,
                cancel,
                renew_before,
                renew_jitter,
                hosts: parking_lot::RwLock::new(std::collections::HashMap::new()),
            }),
        })
    }

    /// Read-only handle to the shared HTTP-01 responder. The supervisor
    /// passes this to the per-IP redirect listener so
    /// `/.well-known/acme-challenge/<token>` requests get matched
    /// against active challenges.
    pub fn responder(&self) -> AcmeResponder {
        self.inner.responder.clone()
    }

    /// Register an ACME-managed hostname. Spawns (or reuses) a renewer
    /// task and returns immediately — issuance happens asynchronously
    /// on the renewer task.
    ///
    /// Idempotent: registering the same `host` twice is a no-op (the
    /// existing renewer task stays in charge).
    pub async fn register(&self, host: &str, route_cfg: &AcmeRouteConfig) -> Result<(), AcmeError> {
        renewer::register_host(self, host, route_cfg).await
    }

    /// Bootstrap the wildcard issuance loop for the operator-configured
    /// `[acme].domain`. Picks the (single, validated-at-config-load)
    /// DNS provider sub-table to drive DNS-01.
    ///
    /// Returns immediately; issuance + scheduled renewals happen on the
    /// background renewer task.
    pub async fn start_wildcard(&self) -> Result<(), AcmeError> {
        let cfg = self.config();
        let host = cfg.domain.clone();
        // Exactly one [acme.dns.<name>] sub-table is validated at config
        // load. Pick the lone provider name.
        let provider = cfg
            .dns
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| AcmeError::Account {
                host: host.clone(),
                detail: "no [acme.dns.<provider>] sub-table configured (validator gap)".into(),
            })?;
        let route_cfg = AcmeRouteConfig {
            challenge: AcmeChallenge::Dns01,
            provider: Some(provider),
        };
        renewer::register_host(self, &host, &route_cfg).await
    }

    /// Snapshot the renewer-task state of every managed hostname.
    /// Returns an empty vec when `[acme]` is unconfigured / no
    /// ACME-managed routes are loaded.
    pub fn list_managed(&self) -> Vec<ratatoskr::control::AcmeHostInfo> {
        let g = self.inner.hosts.read();
        let mut out: Vec<ratatoskr::control::AcmeHostInfo> = g
            .iter()
            .map(|(host, st)| ratatoskr::control::AcmeHostInfo {
                hostname: host.clone(),
                challenge: match st.route_cfg.challenge {
                    AcmeRouteChallengeEcho::Http01 => "http01".to_string(),
                    AcmeRouteChallengeEcho::Dns01 => "dns01".to_string(),
                },
                provider: st.route_cfg.provider.clone(),
                state: st.state.as_str().to_string(),
                last_error: st.last_error.clone(),
                next_renewal_unix: st.next_renewal_unix,
                not_after_unix: st.not_after_unix,
            })
            .collect();
        out.sort_by(|a, b| a.hostname.cmp(&b.hostname));
        out
    }

    /// Kick the renewer for `host` to issue immediately, bypassing its
    /// schedule. Returns once the renewer reports the result —
    /// callers should give this a generous timeout (ACME orders take
    /// 5-60 seconds typically).
    pub async fn force_renew(&self, host: &str) -> Result<(), AcmeError> {
        let kick_tx = {
            let g = self.inner.hosts.read();
            g.get(&host.to_ascii_lowercase())
                .map(|s| s.kick_tx.clone())
                .ok_or_else(|| AcmeError::Client {
                    host: host.into(),
                    detail: "no ACME-managed route declares this hostname".into(),
                })?
        };
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        kick_tx
            .send(KickRequest { reply: reply_tx })
            .await
            .map_err(|_| AcmeError::Client {
                host: host.into(),
                detail: "renewer task is no longer running".into(),
            })?;
        reply_rx.await.map_err(|_| AcmeError::Client {
            host: host.into(),
            detail: "renewer task dropped the kick reply".into(),
        })?
    }

    /// Storage directory for renewed certs. Cloned for the renewer to
    /// resolve `{storage_dir}/{host}/{fullchain,privkey}.pem`.
    pub(super) fn storage_dir(&self) -> &std::path::Path {
        &self.inner.storage_dir
    }

    pub(super) fn providers(&self) -> &ProviderRegistry {
        &self.inner.providers
    }

    pub(super) fn cert_store(&self) -> &CertStore {
        &self.inner.cert_store
    }

    pub(super) fn cancel(&self) -> CancellationToken {
        self.inner.cancel.clone()
    }

    pub(super) fn config(&self) -> &AcmeSection {
        &self.inner.config
    }

    pub(super) fn renew_before(&self) -> Duration {
        self.inner.renew_before
    }

    pub(super) fn renew_jitter(&self) -> Duration {
        self.inner.renew_jitter
    }

    /// Mutate the per-host state map. Held under a write lock for the
    /// closure's duration; renewer tasks call this on every cycle.
    pub(super) fn with_host_state<R>(
        &self,
        host: &str,
        f: impl FnOnce(&mut HostState) -> R,
    ) -> Option<R> {
        let mut g = self.inner.hosts.write();
        g.get_mut(&host.to_ascii_lowercase()).map(f)
    }

    /// Insert the initial host-state entry. Called from
    /// `renewer::register_host` once per managed hostname.
    pub(super) fn install_host(&self, host: &str, state: HostState) -> bool {
        let mut g = self.inner.hosts.write();
        match g.entry(host.to_ascii_lowercase()) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(state);
                true
            }
            std::collections::hash_map::Entry::Occupied(_) => false,
        }
    }
}

// AcmeChallenge is now defined locally above (was previously
// `ratatoskr::rule::AcmeChallenge`). The alias is kept so renewer
// code referring to `AcmeRouteChallengeEcho` keeps compiling.
pub(crate) use AcmeChallenge as AcmeRouteChallengeEcho;
