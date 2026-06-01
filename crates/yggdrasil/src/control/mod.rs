//! UDS control surface for `yggdrasilctl`.
//!
//! Wire format: one newline-delimited JSON object per request, one per
//! response. Backed by [`ratatoskr::control`]. The listener binds the
//! socket with mode `0o660`; group ownership is left to the operator
//! (we don't ship a packaging story yet).
//!
//! ## Why a worker task per connection?
//!
//! Each connection is short-lived and emits at most a handful of JSON
//! objects. There's no broadcast or fan-out, so a per-connection task with
//! buffered IO is the simplest correct design and trivially cancellable
//! from the parent token.
//!
//! ## Module layout
//!
//! - [`server`] — accept loop + per-connection request reader/writer.
//! - [`dispatch`] — synchronous request → response dispatcher for the
//!   simple verbs.
//! - [`handlers`] — async handlers for the verbs that need to `await`
//!   (chain apply, chain summary, rules reload) plus the
//!   downstream-approve flow.

mod dispatch;
mod handlers;
mod server;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use ratatoskr::control::Mode;

use crate::chain::client::ChainClientHandle;
use crate::heartbeat::PeerState;
use crate::pending_peers::PendingPeerStore;
use crate::proxy::supervisor::{ProxySupervisor, SupervisorHandle};
use crate::rules::ReloadTrigger;

use self::dispatch::dispatch;

/// Handle to a running control server.
pub struct ControlServer {
    cancel: CancellationToken,
    main_handle: JoinHandle<()>,
    socket_path: PathBuf,
}

/// Shared state every connection task sees.
///
/// `peer_state` and `pending_store` are `Option` so the same control surface
/// can serve both relay-mode daemons (downstream enrolled, heartbeat live)
/// and terminal-mode daemons (no downstream concept). When `None`, any
/// `downstream ...` request returns
/// [`ratatoskr::control::error_codes::NOT_SUPPORTED_IN_TERMINAL_MODE`].
///
/// Fields are `pub(in crate::control)` so siblings under `control/` (the
/// dispatcher and per-verb handlers) can read them without going through
/// accessor methods. Visibility is confined to this module subtree —
/// nothing outside `crate::control` should poke at these directly.
pub(in crate::control) struct ControlState {
    pub(in crate::control) started_at: Instant,
    /// The mode the daemon was started in. Surfaced verbatim in
    /// [`ratatoskr::control::StatusResponse::mode`] and used as the gate
    /// for the `downstream ...` request family.
    pub(in crate::control) mode: Mode,
    /// Resolved `[server].name` (falling back to `gethostname(3)`).
    /// Embedded in `ChainHop.name` so cross-chain renderers can label
    /// hops by something more readable than their pubkey. Captured
    /// at startup; not hot-reloadable.
    pub(in crate::control) node_name: String,
    pub(in crate::control) peer_state: Option<Arc<PeerState>>,
    pub(in crate::control) snapshot_rx:
        tokio::sync::watch::Receiver<Vec<crate::proxy::supervisor::ProxySnapshot>>,
    pub(in crate::control) reload_trigger: ReloadTrigger,
    /// Shared cert store handle; surfaces via `Request::Status`.
    pub(in crate::control) cert_store: Arc<crate::proxy::certs::CertStore>,
    pub(in crate::control) pending_store: Option<Arc<PendingPeerStore>>,
    /// Path to the main server config; the approve flow rewrites
    /// `[accept].pubkey` atomically (tmp + rename). Held even in
    /// terminal mode (unused; cheap to carry).
    pub(in crate::control) config_path: PathBuf,
    /// True when this node has a chain upstream configured (`[dial]`).
    /// Gates the predicate-projection pre-check in
    /// [`handlers::chain::dispatch_chain_apply`]: pure-local terminals
    /// skip projection (no upstream to push to) and report
    /// `predicate_count = 0`.
    pub(in crate::control) has_chain_upstream: bool,
    /// Handle to the proxy supervisor. Owned here so the
    /// `Request::ChainApply` path can call
    /// [`SupervisorHandle::apply_ruleset`] directly without going
    /// through the file-watch reload mechanism (which would race the
    /// operator's request against an in-flight reload). The handle is
    /// cheap to clone and tied to the supervisor task's lifetime.
    pub(in crate::control) supervisor_handle: SupervisorHandle,
    /// Prometheus recorder handle used by `Request::Metrics` to render
    /// the text exposition format directly over the UDS.
    pub(in crate::control) prom_handle: PrometheusHandle,
    /// Optional chain-introspection state used by
    /// `Request::DerivedRules`. `None` on pure-local terminals (no
    /// chain) or in tests that don't exercise predicate apply.
    pub(in crate::control) introspection: Option<Arc<crate::chain::IntrospectionState>>,
    /// Optional upstream chain-client handle used by
    /// `Request::ChainSummary` to walk the chain. `None` on nodes
    /// without a `[dial]` section (gateways, root relays, pure-local
    /// terminals); the response then contains only the local hop with
    /// `partial = false`.
    pub(in crate::control) chain_client_handle: Option<ChainClientHandle>,
    /// Optional ACME manager. `None` when `[acme]` is unconfigured.
    /// Used by `Request::AcmeList` / `Request::AcmeRenew`.
    pub(in crate::control) acme: Option<crate::proxy::acme::AcmeManager>,
    /// Optional NAT-traversal mapper handle. `None` when
    /// `[server].nat_traversal = "off"` (the default) or when the
    /// mapper's startup discovery failed. Read by `Request::Status`
    /// in `dispatch.rs::project_nat_status` to surface the NAT block
    /// when the subsystem is live.
    pub(in crate::control) nat: Option<crate::nat::NatMapperHandle>,
    /// Shared per-daemon canary arm table. The `ChainCanary` handler
    /// installs an arm here when this node is the terminal hop for
    /// the rule under test (so the originator's probe traffic is
    /// echoed in-process at this node's rule listener) and disarms
    /// it on completion. Always present on daemons that ran through
    /// `run_relay` / `run_terminal`.
    pub(in crate::control) canary_arm_table: Arc<crate::proxy::canary::CanaryArmTable>,
    /// Resolved `[server].lan_cidrs` snapshot. Surfaced verbatim in
    /// [`ratatoskr::control::StatusResponse::lan_cidrs`] +
    /// [`ratatoskr::control::StatusResponse::lan_cidrs_source`] so
    /// `yggdrasilctl local status` can render the resolved set.
    pub(in crate::control) lan_cidrs: Arc<crate::lan_cidrs::LanCidrs>,
}

impl ControlServer {
    /// Bind the UDS at `socket_path`, set mode `0o660`, and start accepting
    /// connections.
    ///
    /// If the path already exists it is removed first; that matches the
    /// systemd convention of "the daemon owns the socket file" and avoids
    /// the common "previous run crashed, EADDRINUSE" footgun.
    ///
    /// `peer_state` and `pending_store` are `None` in terminal mode. All
    /// `downstream ...` requests then return `not_supported_in_terminal_mode`.
    ///
    /// `has_chain_upstream` is `true` when the daemon has a `[dial]`
    /// section (and the chain client/publisher have been wired). It
    /// gates the predicate-projection pre-check in `chain apply`.
    ///
    /// `acme` is the optional ACME manager; only terminal-mode
    /// daemons with `[acme]` set wire one. When `None`, the
    /// `acme list` / `acme renew` verbs return empty / not_configured.
    ///
    /// `nat` is the optional NAT-traversal mapper handle. `None`
    /// when `[server].nat_traversal = "off"` or when the mapper
    /// failed startup discovery; the `local status` rendering then
    /// omits the NAT block entirely.
    #[allow(clippy::too_many_arguments)]
    pub async fn bind(
        socket_path: impl Into<PathBuf>,
        mode: Mode,
        node_name: String,
        peer_state: Option<Arc<PeerState>>,
        supervisor: &ProxySupervisor,
        pending_store: Option<Arc<PendingPeerStore>>,
        config_path: PathBuf,
        has_chain_upstream: bool,
        prom_handle: PrometheusHandle,
        introspection: Option<Arc<crate::chain::IntrospectionState>>,
        chain_client_handle: Option<ChainClientHandle>,
        acme: Option<crate::proxy::acme::AcmeManager>,
        nat: Option<crate::nat::NatMapperHandle>,
        canary_arm_table: Arc<crate::proxy::canary::CanaryArmTable>,
        lan_cidrs: Arc<crate::lan_cidrs::LanCidrs>,
        shutdown: CancellationToken,
    ) -> Result<Self> {
        let socket_path: PathBuf = socket_path.into();
        if let Some(parent) = socket_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
        }
        // Best-effort: drop any stale socket file.
        match std::fs::remove_file(&socket_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(anyhow::anyhow!(e).context(format!(
                    "removing stale control socket {}",
                    socket_path.display()
                )))
            }
        }

        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("binding control socket {}", socket_path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o660))
                .with_context(|| format!("chmod 0660 {}", socket_path.display()))?;
        }

        let cancel = shutdown.child_token();
        let state = Arc::new(ControlState {
            started_at: Instant::now(),
            mode,
            node_name,
            peer_state,
            snapshot_rx: supervisor.snapshot_receiver(),
            reload_trigger: supervisor.reload_trigger(),
            cert_store: supervisor.cert_store(),
            pending_store,
            config_path,
            has_chain_upstream,
            supervisor_handle: supervisor.handle(),
            prom_handle,
            introspection,
            chain_client_handle,
            acme,
            nat,
            canary_arm_table,
            lan_cidrs,
        });

        let main_cancel = cancel.clone();
        let main_handle = tokio::spawn(server::accept_loop(listener, state, main_cancel));

        tracing::info!(socket = %socket_path.display(), "control server bound");
        Ok(Self {
            cancel,
            main_handle,
            socket_path,
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = self.main_handle.await;
        // Best-effort cleanup; ignore if already gone.
        let _ = std::fs::remove_file(&self.socket_path);
    }
}
