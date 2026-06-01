//! Core NAT-traversal subsystem: target derivation, gateway RPC,
//! mapping table reconciler, renewal scheduling, and shutdown release
//! pass.
//!
//! ## Responsibilities
//!
//! - **Target derivation** ([`compute_targets`]) — pure function from
//!   `(RuleSet, Option<accept_listen>, local_source)` to the set of
//!   `(protocol, internal_port, internal_addr)` triples the daemon
//!   wants the gateway to forward. Includes HTTPS frontend listeners,
//!   their HTTP/3 UDP companions (when enabled), the per-IP HTTPS
//!   redirect listeners, plain TCP / UDP rule listeners, and the
//!   chain `[accept].listen` UDP socket when present.
//!
//! - **Gateway RPC** ([`Rpc`]) — talks PCP (RFC 6887) or NAT-PMP
//!   (RFC 6886) to the gateway over a single connected UDP socket.
//!   Retries with exponential backoff per RFC 6887 §8.1.1.
//!
//! - **Reconciliation loop** ([`Reconciler::run`]) — owns the active
//!   mapping table, observes the supervisor's `RuleSet` watch, applies
//!   adds / drops / renewals, surfaces errors via metrics + the
//!   `last_error` snapshot field. Renewals fire at `lifetime / 2`.
//!
//! - **Shutdown release pass** — on observing the daemon's shutdown
//!   cancellation, iterates every active mapping and sends a
//!   `lifetime = 0` request to the gateway, bounded by a 3-second
//!   internal deadline so a dead gateway can't hold up daemon exit.
//!
//! ## Test hooks
//!
//! [`NatMapperParams`] exposes two override fields used by integration
//! tests in `tests/nat_traversal.rs`:
//!
//! - `gateway_override` — supplies a fixed `(addr, local_source)`
//!   instead of running real default-route discovery, so tests can
//!   point the mapper at a `MockNatGateway` listening on
//!   `127.0.0.1:0`.
//! - `shutdown_release_timeout` — caps the release pass at a shorter
//!   value (the production default is 3 s, which is too long for unit
//!   test wall-clock).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;
use parking_lot::RwLock;
use rand::RngCore;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use ratatoskr::rule::{Protocol, Rule, RuleSet};

use super::discovery::{discover as discover_gateway, Gateway};
use super::wire::natpmp;
use super::wire::pcp;
use super::wire::MapProtocol;
use super::NatTraversalMode;

/// Default budget for the shutdown release pass. Bounded so a dead
/// gateway can't hold the daemon hostage during `SIGTERM`.
pub const DEFAULT_SHUTDOWN_RELEASE_TIMEOUT: Duration = Duration::from_secs(3);

/// Per-mapping lifetime we ask for from the gateway. Many consumer
/// routers cap mappings at 1 hour regardless of request; the gateway
/// returns the actual lifetime it intends to honor in its response
/// and we renew at half of *that*.
pub const REQUESTED_LIFETIME_SECS: u32 = 7_200;

/// Initial retransmit timeout for gateway RPCs. RFC 6887 §8.1.1
/// recommends 1–3s; doubled per retry.
pub const RPC_INITIAL_TIMEOUT: Duration = Duration::from_millis(2_000);
pub const RPC_MAX_RETRIES: usize = 3;

/// Number of consecutive RPC failures we tolerate in the `Active`
/// state before transitioning to `Backoff`.
pub const ERROR_THRESHOLD_TO_BACKOFF: u32 = 3;

/// Backoff probe schedule: 30s, 1m, 5m, 15m, then stays at 15m.
pub const BACKOFF_SCHEDULE: &[Duration] = &[
    Duration::from_secs(30),
    Duration::from_secs(60),
    Duration::from_secs(300),
    Duration::from_secs(900),
];

/// What the mapper actually wants reachable.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MappingTarget {
    pub protocol: MapProtocol,
    pub internal_port: u16,
    /// The listener's bind IP, used to filter loopback / link-local
    /// listeners that have no business being mapped. For listeners
    /// bound to `0.0.0.0`, the reconciler substitutes the kernel-
    /// selected `local_source` when sending the actual PCP request.
    pub internal_addr: Ipv4Addr,
    /// Stable, human-readable origin tag. Carries through to metric
    /// labels and the `Status` rendering. Not part of the dedupe key
    /// for mapping equality (two origins producing the same target
    /// are coalesced into one mapping).
    pub origin: MappingOrigin,
}

/// Why a particular mapping was requested.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MappingOrigin {
    /// A `[[rule]]` listener, plain TCP or UDP or the HTTPS TCP frontend.
    Rule(String),
    /// The chain `[accept].listen` UDP socket (relay / gateway modes).
    AcceptListen,
    /// The per-IP HTTP→HTTPS redirect listener auto-spawned for every
    /// `protocol = "https"` rule. Deduplicated per bind IP — the
    /// daemon only spawns one redirect listener per unique IP.
    HttpsRedirect(IpAddr),
    /// The HTTP/3 UDP companion of an HTTPS rule. Same name as the
    /// originating rule so `rule:foo` + `http3:foo` group cleanly in
    /// dashboards.
    Http3(String),
}

impl MappingOrigin {
    /// Wire-friendly serialization used in `Status` and metrics. The
    /// shape is documented in [`crate::nat`]'s top-of-file comments.
    pub fn as_token(&self) -> String {
        match self {
            Self::Rule(name) => format!("rule:{name}"),
            Self::AcceptListen => "accept".to_owned(),
            Self::HttpsRedirect(ip) => format!("redirect:{ip}"),
            Self::Http3(name) => format!("http3:{name}"),
        }
    }
}

/// Configuration for the node-wide HTTPS listener as it affects NAT
/// mapping. Sourced from `[server].https_listen` + `[server].https_http3`.
///
/// Passed through [`compute_targets`] / [`enumerate_targets`] only when
/// the live rule set has at least one top-level `[[route]]` — when
/// routes are empty the daemon doesn't bind the HTTPS listener at all
/// and there's nothing to map.
#[derive(Debug, Clone, Copy)]
pub struct HttpsTarget {
    pub listen: SocketAddr,
    pub http3: bool,
}

/// A live mapping the gateway has confirmed.
#[derive(Clone, Debug)]
pub struct ActiveMapping {
    pub target: MappingTarget,
    pub external_port: u16,
    pub external_addr: Option<Ipv4Addr>,
    pub assigned_lifetime: Duration,
    pub renew_at: Instant,
    pub last_renewed: Instant,
    pub protocol_used: NatProtocol,
    /// PCP nonce associated with this mapping. RFC 6887 requires the
    /// same nonce on renewal so the gateway can match against its
    /// state. `None` for NAT-PMP (no nonces).
    pub pcp_nonce: Option<[u8; 12]>,
}

/// Which NAT-traversal protocol is currently in use on the wire.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NatProtocol {
    Pcp,
    NatPmp,
}

impl NatProtocol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pcp => "pcp",
            Self::NatPmp => "natpmp",
        }
    }
}

/// Coarse-grained mapper state surfaced in `Status` and Prometheus.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NatState {
    /// `nat_traversal = "off"`. The mapper task is not running.
    Disabled,
    /// Initial state. The mapper is probing the gateway to determine
    /// reachability and which protocol it speaks.
    Discovering,
    /// Gateway responds; the mapper is keeping the active table in
    /// sync with the supervisor.
    Active,
    /// Three or more consecutive RPC failures. Mapper holds the last-
    /// known table but stops trying to mutate it; periodically probes
    /// per [`BACKOFF_SCHEDULE`] to re-emerge.
    Backoff,
}

impl NatState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Discovering => "discovering",
            Self::Active => "active",
            Self::Backoff => "backoff",
        }
    }
}

/// Cheap-to-clone snapshot of the mapper's state. Used by `Status` to
/// render the NAT block and by integration tests to assert progress.
#[derive(Debug, Clone)]
pub struct NatSnapshot {
    pub mode: NatTraversalMode,
    pub state: NatState,
    pub gateway: Option<Ipv4Addr>,
    pub external_ip: Option<Ipv4Addr>,
    pub protocol: Option<NatProtocol>,
    pub active_mappings: Vec<ActiveMapping>,
    pub last_error: Option<String>,
}

impl NatSnapshot {
    pub fn disabled() -> Self {
        Self {
            mode: NatTraversalMode::Off,
            state: NatState::Disabled,
            gateway: None,
            external_ip: None,
            protocol: None,
            active_mappings: Vec::new(),
            last_error: None,
        }
    }
}

/// Parameters consumed by [`NatMapper::spawn`]. Includes test-only
/// override knobs accessed by integration tests; production callers
/// leave them `None`.
pub struct NatMapperParams {
    pub mode: NatTraversalMode,
    pub accept_listen: Option<SocketAddr>,
    pub rule_set_rx: watch::Receiver<RuleSet>,
    pub shutdown: CancellationToken,
    /// Node-wide HTTPS listener. Sourced from `[server].https_listen`.
    /// The mapper emits TCP / UDP-h3 / redirect targets for it only
    /// when the live rule set has at least one `[[route]]`.
    pub https_listen: SocketAddr,
    /// Whether the node's HTTPS frontend brings up an HTTP/3 endpoint.
    /// Sourced from `[server].https_http3`. When `false`, the mapper
    /// emits only the TCP target (no UDP) for the HTTPS listener.
    pub https_http3: bool,
    /// Override the default-route discovery probe. Production:
    /// `None`. Integration tests: `Some(Gateway{addr=127.0.0.1, ...})`
    /// pointing at the in-process `MockNatGateway`.
    pub gateway_override: Option<Gateway>,
    /// Override the shutdown-release deadline. Production: `None`
    /// (3 seconds). Tests: a shorter value, typically 250 ms.
    pub shutdown_release_timeout: Option<Duration>,
}

/// Public handle to a running NAT mapper.
pub struct NatMapper {
    handle: NatMapperHandle,
    join: JoinHandle<()>,
}

impl NatMapper {
    /// Spawn the mapper task. Returns an [`Err`] only if the up-front
    /// gateway-discovery probe failed when `mode != Off` and no
    /// `gateway_override` was supplied; that failure mode is the
    /// daemon's call to either treat as fatal or downgrade to a warn
    /// and run with the mapper disabled.
    pub async fn spawn(params: NatMapperParams) -> Result<Self, MapperSpawnError> {
        if matches!(params.mode, NatTraversalMode::Off) {
            return Err(MapperSpawnError::Disabled);
        }
        let gateway = match params.gateway_override {
            Some(g) => g,
            None => discover_gateway().map_err(|e| MapperSpawnError::Discovery(e.to_string()))?,
        };

        let initial_snapshot = NatSnapshot {
            mode: params.mode,
            state: NatState::Discovering,
            gateway: Some(gateway.addr),
            external_ip: None,
            protocol: None,
            active_mappings: Vec::new(),
            last_error: None,
        };
        let snapshot_arc = Arc::new(RwLock::new(initial_snapshot));

        let release_timeout = params
            .shutdown_release_timeout
            .unwrap_or(DEFAULT_SHUTDOWN_RELEASE_TIMEOUT);

        let reconciler = Reconciler::new(
            params.mode,
            gateway,
            params.accept_listen,
            params.https_listen,
            params.https_http3,
            params.rule_set_rx,
            params.shutdown.clone(),
            snapshot_arc.clone(),
            release_timeout,
        );

        let handle = NatMapperHandle {
            snapshot: snapshot_arc,
            mode: params.mode,
        };

        let join = tokio::spawn(reconciler.run());

        Ok(Self { handle, join })
    }

    pub fn handle(&self) -> NatMapperHandle {
        self.handle.clone()
    }

    /// Wait for the mapper task to exit. Callers do this after they
    /// have cancelled the shutdown token, so the release pass has a
    /// chance to send unmap requests before the daemon process exits.
    pub async fn shutdown(self) {
        let _ = self.join.await;
    }
}

/// Cloneable handle to the running mapper. The mapper publishes
/// snapshots to a shared `Arc<RwLock<NatSnapshot>>` that handle
/// holders can read cheaply via [`NatMapperHandle::snapshot`].
#[derive(Clone)]
pub struct NatMapperHandle {
    snapshot: Arc<RwLock<NatSnapshot>>,
    mode: NatTraversalMode,
}

impl NatMapperHandle {
    /// Cheap clone of the most recent published snapshot. Reads
    /// happen under a `parking_lot::RwLock` read guard so they don't
    /// block writes for long.
    pub fn snapshot(&self) -> NatSnapshot {
        self.snapshot.read().clone()
    }

    /// Convenience accessor used by `local status` rendering.
    pub fn external_ip(&self) -> Option<Ipv4Addr> {
        self.snapshot.read().external_ip
    }

    pub fn mode(&self) -> NatTraversalMode {
        self.mode
    }
}

/// Errors returned by [`NatMapper::spawn`]. The daemon converts these
/// into a `tracing::warn` + continues with the mapper disabled, so
/// they're informational rather than fatal.
#[derive(Debug, thiserror::Error)]
pub enum MapperSpawnError {
    #[error("NAT traversal is disabled (mode = off)")]
    Disabled,
    #[error("gateway discovery failed: {0}")]
    Discovery(String),
}

// ----------------------------------------------------------------------------
// Target derivation
// ----------------------------------------------------------------------------

/// Compute the desired set of mappings from a rule list plus the
/// daemon's accept-socket. Pure function — no IO, no clocks.
///
/// `local_source` is used to substitute for listeners bound to
/// `0.0.0.0`; PCP needs a concrete client-internal-address.
///
/// Takes `&[Rule]` rather than `&RuleSet` so unit tests can supply
/// test fixtures without going through the full cross-rule validator
/// (only the per-rule derivation logic matters here).
pub fn compute_targets(
    rules: &[Rule],
    accept_listen: Option<SocketAddr>,
    https: Option<HttpsTarget>,
    local_source: Ipv4Addr,
) -> HashSet<MappingTarget> {
    enumerate_targets(rules, accept_listen, https, local_source).targets
}

/// What [`enumerate_targets`] returns: both the targets we'll try to
/// map and the listeners we filtered out (with the reason). The
/// reconciler uses the second bucket to emit
/// `yggdrasil_nat_mapping_skipped_total{reason}`.
#[derive(Debug, Clone, Default)]
pub struct TargetEnumeration {
    pub targets: HashSet<MappingTarget>,
    /// `(listener identifier, reason)` for each skipped listener.
    /// The identifier mirrors `MappingOrigin::as_token` so dashboards
    /// can correlate skips with rule names.
    pub skipped: Vec<(String, SkipReason)>,
}

/// Full enumeration of NAT-mapping decisions. Like [`compute_targets`]
/// but also returns the skipped listeners so the reconciler can emit
/// the `yggdrasil_nat_mapping_skipped_total{reason}` metric.
pub fn enumerate_targets(
    rules: &[Rule],
    accept_listen: Option<SocketAddr>,
    https: Option<HttpsTarget>,
    local_source: Ipv4Addr,
) -> TargetEnumeration {
    let mut targets: HashSet<MappingTarget> = HashSet::new();
    let mut redirect_ips: HashSet<IpAddr> = HashSet::new();
    let mut skipped: Vec<(String, SkipReason)> = Vec::new();

    for rule in rules {
        let listen = rule.listen;
        let port = listen.port();
        let bind_ip = listen.ip();

        // Filter listeners we should not even try to map. These are
        // surfaced via `yggdrasil_nat_mapping_skipped_total{reason}`
        // by the reconciler; the pure derivation just omits them.
        match filter_bind_ip(bind_ip) {
            FilterDecision::Skip(reason) => {
                skipped.push((MappingOrigin::Rule(rule.name.clone()).as_token(), reason));
                continue;
            }
            FilterDecision::Keep(v4) => {
                let resolved_internal = if v4.is_unspecified() {
                    local_source
                } else {
                    v4
                };

                match rule.protocol {
                    Protocol::Tcp => {
                        targets.insert(MappingTarget {
                            protocol: MapProtocol::Tcp,
                            internal_port: port,
                            internal_addr: resolved_internal,
                            origin: MappingOrigin::Rule(rule.name.clone()),
                        });
                    }
                    Protocol::Udp => {
                        targets.insert(MappingTarget {
                            protocol: MapProtocol::Udp,
                            internal_port: port,
                            internal_addr: resolved_internal,
                            origin: MappingOrigin::Rule(rule.name.clone()),
                        });
                    }
                    Protocol::Https => {
                        // Rule::validate rejects protocol = "https" — HTTPS
                        // listeners come from top-level [[route]] blocks,
                        // mapped via the `https` parameter passed alongside.
                        debug_assert!(
                            false,
                            "Rule with protocol = Https should be rejected at validation"
                        );
                    }
                }
            }
        }
    }

    // Node-wide HTTPS listener. Sourced from `[server].https_listen` +
    // `[server].https_http3`. The caller passes `None` when the live
    // rule set has no `[[route]]` entries (so the daemon hasn't bound
    // anything to map).
    if let Some(https) = https {
        let listen = https.listen;
        let bind_ip = listen.ip();
        let port = listen.port();
        match filter_bind_ip(bind_ip) {
            FilterDecision::Skip(reason) => {
                skipped.push((MappingOrigin::Rule("https".to_string()).as_token(), reason));
            }
            FilterDecision::Keep(v4) => {
                let resolved_internal = if v4.is_unspecified() {
                    local_source
                } else {
                    v4
                };
                targets.insert(MappingTarget {
                    protocol: MapProtocol::Tcp,
                    internal_port: port,
                    internal_addr: resolved_internal,
                    origin: MappingOrigin::Rule("https".to_string()),
                });
                if https.http3 {
                    targets.insert(MappingTarget {
                        protocol: MapProtocol::Udp,
                        internal_port: port,
                        internal_addr: resolved_internal,
                        origin: MappingOrigin::Http3("https".to_string()),
                    });
                }
                redirect_ips.insert(IpAddr::V4(v4));
            }
        }
    }

    // Redirect listeners are always on the HTTPS rule's bind IP.
    // Port 80 is the standard; if `http_redirect_port` was set to
    // something else at the daemon level the supervisor binds there
    // instead. v1 hardcodes 80 — the redirect listener is part of
    // the convention regardless of port override (the override is for
    // unprivileged daemons that can't bind 80 at all).
    //
    // We deliberately *do not* claim a mapping for ephemeral (port=0)
    // redirect listeners — those exist only for tests and never need
    // a port forward.
    for ip in redirect_ips {
        if let IpAddr::V4(v4) = ip {
            let resolved_internal = if v4.is_unspecified() {
                local_source
            } else {
                v4
            };
            match filter_bind_ip(IpAddr::V4(v4)) {
                FilterDecision::Skip(reason) => {
                    skipped.push((
                        MappingOrigin::HttpsRedirect(IpAddr::V4(v4)).as_token(),
                        reason,
                    ));
                }
                FilterDecision::Keep(_) => {
                    targets.insert(MappingTarget {
                        protocol: MapProtocol::Tcp,
                        internal_port: 80,
                        internal_addr: resolved_internal,
                        origin: MappingOrigin::HttpsRedirect(IpAddr::V4(v4)),
                    });
                }
            }
        }
    }

    if let Some(addr) = accept_listen {
        if let IpAddr::V4(v4) = addr.ip() {
            let resolved_internal = if v4.is_unspecified() {
                local_source
            } else {
                v4
            };
            match filter_bind_ip(IpAddr::V4(v4)) {
                FilterDecision::Skip(reason) => {
                    skipped.push((MappingOrigin::AcceptListen.as_token(), reason));
                }
                FilterDecision::Keep(_) => {
                    targets.insert(MappingTarget {
                        protocol: MapProtocol::Udp,
                        internal_port: addr.port(),
                        internal_addr: resolved_internal,
                        origin: MappingOrigin::AcceptListen,
                    });
                }
            }
        } else {
            // IPv6 accept listen — outside v1's IPv4-only scope.
            skipped.push((MappingOrigin::AcceptListen.as_token(), SkipReason::Ipv6));
        }
    }

    TargetEnumeration { targets, skipped }
}

/// Why a particular listener was filtered out. Surfaced as a metric
/// label (`reason`) by the reconciler.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SkipReason {
    Loopback,
    LinkLocal,
    PublicInternal,
    Ipv6,
}

impl SkipReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::LinkLocal => "link_local",
            Self::PublicInternal => "public_internal",
            Self::Ipv6 => "ipv6",
        }
    }
}

enum FilterDecision {
    Keep(Ipv4Addr),
    Skip(SkipReason),
}

fn filter_bind_ip(ip: IpAddr) -> FilterDecision {
    match ip {
        IpAddr::V6(_) => FilterDecision::Skip(SkipReason::Ipv6),
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                FilterDecision::Skip(SkipReason::Loopback)
            } else if v4.is_link_local() {
                FilterDecision::Skip(SkipReason::LinkLocal)
            } else if v4.is_unspecified() || is_rfc1918_or_cgnat(v4) {
                // Either bound to all interfaces (kernel resolves the
                // source IP at gateway-talk time) or to a private
                // RFC-1918 / CGNAT address that legitimately sits
                // behind NAT.
                FilterDecision::Keep(v4)
            } else {
                // The host has bound the listener directly to a
                // public IP; either it's not behind NAT (so the
                // mapper would do nothing useful) or something is
                // misconfigured. Skip and surface via the metric.
                FilterDecision::Skip(SkipReason::PublicInternal)
            }
        }
    }
}

/// True for RFC 1918 (10/8, 172.16/12, 192.168/16) and CGNAT
/// (100.64/10) and benchmarking (198.18/15) ranges. These are the
/// only IPv4 ranges that legitimately appear as bind addresses on a
/// box behind NAT.
fn is_rfc1918_or_cgnat(v4: Ipv4Addr) -> bool {
    let [a, b, _, _] = v4.octets();
    matches!(
        (a, b),
        (10, _) | (172, 16..=31) | (192, 168) | (100, 64..=127) | (198, 18..=19)
    )
}

// ----------------------------------------------------------------------------
// Reconciler
// ----------------------------------------------------------------------------

/// The owned-by-task reconciler. Built once, runs until shutdown.
struct Reconciler {
    mode: NatTraversalMode,
    gateway: Gateway,
    accept_listen: Option<SocketAddr>,
    https_listen: SocketAddr,
    https_http3: bool,
    rule_set_rx: watch::Receiver<RuleSet>,
    shutdown: CancellationToken,

    /// Shared snapshot we publish into so handle holders can read
    /// the current state cheaply.
    snapshot: Arc<RwLock<NatSnapshot>>,

    /// Active mappings keyed by `(protocol, internal_port)`. PCP
    /// allows multiple mappings on the same port with different
    /// nonces, but we never want that (one daemon, one nonce per
    /// listener), so the simpler key is correct.
    mappings: HashMap<MappingKey, ActiveMapping>,

    /// Per-mapping PCP nonces. Stable across renewals and unmaps so
    /// the gateway can pair our messages with its state.
    nonces: HashMap<MappingKey, [u8; 12]>,

    /// State machine state.
    state: NatState,

    /// PCP vs NAT-PMP — set on first successful gateway response, or
    /// fixed by config for `pcp` / `natpmp` modes.
    current_protocol: Option<NatProtocol>,

    /// Most recent epoch from the gateway. PCP: from `epoch_time` in
    /// response; NAT-PMP: from `seconds_since_epoch`. RFC 6887 §8.5:
    /// a backwards jump means the gateway lost state and we must
    /// re-establish every mapping.
    last_epoch: Option<u32>,

    /// External IP (learned from the first successful PCP response
    /// or a NAT-PMP external-address request).
    external_ip: Option<Ipv4Addr>,

    /// Counter of consecutive RPC failures in the `Active` state.
    /// Reset on success; once it crosses [`ERROR_THRESHOLD_TO_BACKOFF`]
    /// we transition to `Backoff`.
    consecutive_errors: u32,

    /// Already-counted (listener, reason) tuples. Stops
    /// `yggdrasil_nat_mapping_skipped_total{reason}` from inflating
    /// on every reconcile pass: a misconfigured listener counts as
    /// one skip event for the daemon's lifetime, not one per
    /// rule push.
    seen_skipped: HashSet<(String, SkipReason)>,

    /// Index into [`BACKOFF_SCHEDULE`] for the current backoff
    /// attempt. Reset on successful probe.
    backoff_attempt: usize,

    /// Last error surfaced in `Status`.
    last_error: Option<String>,

    /// Connected UDP socket to the gateway. Re-created on protocol
    /// fallback / gateway change.
    rpc_socket: Option<UdpSocket>,

    /// How long we'll wait for the release pass on shutdown.
    shutdown_release_timeout: Duration,
}

type MappingKey = (MapProtocol, u16);

impl Reconciler {
    #[allow(clippy::too_many_arguments)]
    fn new(
        mode: NatTraversalMode,
        gateway: Gateway,
        accept_listen: Option<SocketAddr>,
        https_listen: SocketAddr,
        https_http3: bool,
        rule_set_rx: watch::Receiver<RuleSet>,
        shutdown: CancellationToken,
        snapshot: Arc<RwLock<NatSnapshot>>,
        shutdown_release_timeout: Duration,
    ) -> Self {
        let initial_protocol = match mode {
            NatTraversalMode::Pcp | NatTraversalMode::Auto => Some(NatProtocol::Pcp),
            NatTraversalMode::NatPmp => Some(NatProtocol::NatPmp),
            NatTraversalMode::Off => None,
        };
        Self {
            mode,
            gateway,
            accept_listen,
            https_listen,
            https_http3,
            rule_set_rx,
            shutdown,
            snapshot,
            mappings: HashMap::new(),
            nonces: HashMap::new(),
            state: NatState::Discovering,
            current_protocol: initial_protocol,
            last_epoch: None,
            external_ip: None,
            consecutive_errors: 0,
            seen_skipped: HashSet::new(),
            backoff_attempt: 0,
            last_error: None,
            rpc_socket: None,
            shutdown_release_timeout,
        }
    }

    /// Main reconciler loop. Returns when `shutdown` is cancelled,
    /// after the bounded release pass.
    async fn run(mut self) {
        info!(
            target: "yggdrasil::nat",
            mode = self.mode.as_str(),
            gateway = %self.gateway.addr,
            local_source = %self.gateway.local_source,
            "NAT mapper starting"
        );

        // Open the RPC socket. If we can't even bind, log + sit in
        // Backoff so the daemon keeps running; the operator can fix
        // the network and SIGHUP us (future work) or restart.
        if let Err(e) = self.ensure_rpc_socket().await {
            warn!(
                target: "yggdrasil::nat",
                error = %e,
                "failed to open RPC socket; mapper will retry"
            );
            self.transition_backoff(format!("rpc socket: {e}"));
        }

        // Initial reconciliation against whatever's currently in the
        // supervisor watch — typically empty, but a relay receiving
        // predicates before this task spawned would have non-empty.
        self.reconcile_targets().await;

        loop {
            let next_tick = self.compute_next_tick();
            tokio::select! {
                biased;

                _ = self.shutdown.cancelled() => {
                    info!(target: "yggdrasil::nat", "shutdown observed; releasing mappings");
                    self.release_all_with_deadline().await;
                    info!(target: "yggdrasil::nat", "NAT mapper exiting");
                    return;
                }

                changed = self.rule_set_rx.changed() => {
                    if changed.is_err() {
                        // Supervisor's watch channel closed — that
                        // means the supervisor has exited. Treat as
                        // shutdown.
                        debug!(target: "yggdrasil::nat", "rule_set watch closed; releasing mappings");
                        self.release_all_with_deadline().await;
                        return;
                    }
                    self.reconcile_targets().await;
                }

                _ = tokio::time::sleep_until(next_tick) => {
                    match self.state {
                        NatState::Discovering => {
                            self.reconcile_targets().await;
                        }
                        NatState::Active => {
                            self.refresh_due_mappings().await;
                        }
                        NatState::Backoff => {
                            self.backoff_probe().await;
                        }
                        NatState::Disabled => unreachable!("disabled mapper never runs"),
                    }
                }
            }
        }
    }

    /// Time of the next non-input wake. In `Active`, that's the
    /// earliest `renew_at`. In `Discovering`, a short retry tick. In
    /// `Backoff`, the next backoff probe instant.
    fn compute_next_tick(&self) -> Instant {
        let now = Instant::now();
        match self.state {
            NatState::Discovering => now + Duration::from_secs(2),
            NatState::Active => self
                .mappings
                .values()
                .map(|m| m.renew_at)
                .min()
                .unwrap_or(now + Duration::from_secs(60)),
            NatState::Backoff => {
                let step = BACKOFF_SCHEDULE
                    .get(self.backoff_attempt)
                    .copied()
                    .unwrap_or(*BACKOFF_SCHEDULE.last().unwrap());
                now + step
            }
            NatState::Disabled => now + Duration::from_secs(3600),
        }
    }

    async fn ensure_rpc_socket(&mut self) -> std::io::Result<()> {
        if self.rpc_socket.is_some() {
            return Ok(());
        }
        let bind = SocketAddr::V4(SocketAddrV4::new(self.gateway.local_source, 0));
        let sock = UdpSocket::bind(bind).await?;
        let target = SocketAddr::V4(SocketAddrV4::new(self.gateway.addr, self.gateway.port));
        sock.connect(target).await?;
        self.rpc_socket = Some(sock);
        Ok(())
    }

    /// The full reconciliation pass: recompute desired targets from
    /// the current `RuleSet`, diff against the active mapping table,
    /// issue adds / drops, publish snapshot.
    async fn reconcile_targets(&mut self) {
        if self.rpc_socket.is_none() {
            if let Err(e) = self.ensure_rpc_socket().await {
                self.transition_backoff(format!("rpc socket: {e}"));
                self.publish_snapshot();
                return;
            }
        }

        let rules = self.rule_set_rx.borrow().clone();
        // HTTPS targets fire only when at least one top-level `[[route]]`
        // exists — otherwise the daemon hasn't bound the listener and
        // there's nothing to map.
        let https = if rules.routes().is_empty() {
            None
        } else {
            Some(HttpsTarget {
                listen: self.https_listen,
                http3: self.https_http3,
            })
        };
        let enumeration = enumerate_targets(
            rules.rules(),
            self.accept_listen,
            https,
            self.gateway.local_source,
        );
        // Emit skipped-listener metric once per (listener, reason)
        // tuple. Re-pushes of the same misconfigured config don't
        // re-increment.
        for (listener, reason) in &enumeration.skipped {
            if self.seen_skipped.insert((listener.clone(), *reason)) {
                metrics::counter!(
                    "yggdrasil_nat_mapping_skipped_total",
                    "reason" => reason.as_str(),
                )
                .increment(1);
                debug!(
                    target: "yggdrasil::nat",
                    listener = %listener,
                    reason = reason.as_str(),
                    "listener excluded from NAT mapping"
                );
            }
        }
        let desired = enumeration.targets;

        // Map by key for diff. If two targets in `desired` share a
        // key (same protocol + port from different origins), the
        // first wins; the duplicate is dropped on the floor with a
        // debug log.
        let mut desired_by_key: HashMap<MappingKey, MappingTarget> = HashMap::new();
        for t in desired {
            let key = (t.protocol, t.internal_port);
            desired_by_key.entry(key).or_insert(t);
        }

        // Drops: keys in `mappings` not in `desired_by_key`.
        let to_drop: Vec<MappingKey> = self
            .mappings
            .keys()
            .filter(|k| !desired_by_key.contains_key(k))
            .copied()
            .collect();
        for key in to_drop {
            if let Some(mapping) = self.mappings.remove(&key) {
                self.release_one(&mapping).await;
            }
        }

        // Adds: keys in `desired_by_key` not in `mappings`.
        let to_add: Vec<MappingTarget> = desired_by_key
            .iter()
            .filter(|(k, _)| !self.mappings.contains_key(k))
            .map(|(_, t)| t.clone())
            .collect();
        for target in to_add {
            self.create_one(target).await;
        }

        // Renewals are handled by `refresh_due_mappings` on the
        // renewal tick, not here. Reconciliation only handles set-
        // membership changes.

        self.publish_snapshot();
    }

    /// Pre-renewal pass: any mapping whose `renew_at` is in the past
    /// gets re-sent.
    async fn refresh_due_mappings(&mut self) {
        let now = Instant::now();
        let due: Vec<MappingKey> = self
            .mappings
            .iter()
            .filter(|(_, m)| m.renew_at <= now)
            .map(|(k, _)| *k)
            .collect();
        for key in due {
            // We re-create with the same target/nonce.
            let target = self.mappings.get(&key).map(|m| m.target.clone());
            if let Some(t) = target {
                self.renew_one(t).await;
            }
        }
        self.publish_snapshot();
    }

    /// In `Backoff`, periodically retry the gateway. On success we
    /// re-establish every mapping we hold; on failure we step the
    /// backoff schedule.
    async fn backoff_probe(&mut self) {
        // The simplest probe is a re-reconcile: if every target gets
        // a fresh mapping or extends an existing one cleanly, we
        // exit backoff.
        let saved_mappings: Vec<MappingTarget> =
            self.mappings.values().map(|m| m.target.clone()).collect();
        self.mappings.clear();
        self.nonces.clear();
        self.consecutive_errors = 0;
        self.state = NatState::Discovering;
        for t in saved_mappings {
            self.create_one(t).await;
        }
        self.reconcile_targets().await;
        if self.state != NatState::Backoff {
            self.backoff_attempt = 0;
        } else {
            self.backoff_attempt = (self.backoff_attempt + 1).min(BACKOFF_SCHEDULE.len() - 1);
        }
    }

    /// Issue a MAP request for a single target.
    async fn create_one(&mut self, target: MappingTarget) {
        self.send_map_request(target, false).await;
    }

    /// Like [`Self::create_one`] but emitted on the renewal path —
    /// only the metric label differs.
    async fn renew_one(&mut self, target: MappingTarget) {
        self.send_map_request(target, true).await;
    }

    async fn send_map_request(&mut self, target: MappingTarget, is_renewal: bool) {
        let key = (target.protocol, target.internal_port);

        // PCP needs a stable nonce per (protocol, port). NAT-PMP
        // doesn't, but generating one is harmless.
        let nonce = *self.nonces.entry(key).or_insert_with(|| {
            let mut n = [0u8; pcp::PCP_NONCE_LEN];
            rand::thread_rng().fill_bytes(&mut n);
            n
        });

        let protocols_to_try: &[NatProtocol] = match self.mode {
            NatTraversalMode::Pcp => &[NatProtocol::Pcp],
            NatTraversalMode::NatPmp => &[NatProtocol::NatPmp],
            NatTraversalMode::Auto => {
                if matches!(self.current_protocol, Some(NatProtocol::NatPmp)) {
                    &[NatProtocol::NatPmp]
                } else {
                    &[NatProtocol::Pcp, NatProtocol::NatPmp]
                }
            }
            NatTraversalMode::Off => return,
        };

        let mut last_err: Option<RpcError> = None;
        for proto in protocols_to_try {
            match self.try_map_via(*proto, &target, nonce).await {
                Ok((resp, epoch)) => {
                    self.note_epoch(epoch).await;
                    self.current_protocol = Some(*proto);
                    let now = Instant::now();
                    let assigned = Duration::from_secs(resp.assigned_lifetime_secs as u64);
                    let renew_at = now + (assigned / 2);
                    self.mappings.insert(
                        key,
                        ActiveMapping {
                            target: target.clone(),
                            external_port: resp.external_port,
                            external_addr: resp.external_addr,
                            assigned_lifetime: assigned,
                            renew_at,
                            last_renewed: now,
                            protocol_used: *proto,
                            pcp_nonce: if *proto == NatProtocol::Pcp {
                                Some(nonce)
                            } else {
                                None
                            },
                        },
                    );
                    if let Some(ext) = resp.external_addr {
                        self.external_ip = Some(ext);
                    }
                    self.state = NatState::Active;
                    self.consecutive_errors = 0;
                    self.backoff_attempt = 0;
                    self.last_error = None;
                    let result_label = "success";
                    let kind_label = if is_renewal { "renewal" } else { "create" };
                    metrics::counter!(
                        match kind_label {
                            "renewal" => "yggdrasil_nat_renewals_total",
                            _ => "yggdrasil_nat_mappings_created_total",
                        },
                        "protocol" => proto.as_str(),
                        "origin" => target.origin.as_token(),
                        "result_code" => result_label,
                    )
                    .increment(1);
                    debug!(
                        target: "yggdrasil::nat",
                        proto = proto.as_str(),
                        origin = %target.origin.as_token(),
                        internal_port = target.internal_port,
                        external_port = resp.external_port,
                        lifetime_secs = resp.assigned_lifetime_secs,
                        renewal = is_renewal,
                        "mapping established"
                    );
                    return;
                }
                Err(e) => {
                    last_err = Some(e);
                    // Auto-mode: if PCP says "unsupported version",
                    // try NAT-PMP next.
                    if matches!(self.mode, NatTraversalMode::Auto)
                        && matches!(*proto, NatProtocol::Pcp)
                        && last_err
                            .as_ref()
                            .map(|e| e.should_fall_back_to_natpmp())
                            .unwrap_or(false)
                    {
                        info!(
                            target: "yggdrasil::nat",
                            "gateway does not speak PCP; falling back to NAT-PMP"
                        );
                        continue;
                    }
                    break;
                }
            }
        }

        // Reached only if every attempted protocol failed.
        let err = last_err.expect("at least one rpc attempt yielded an error");
        let label = err.metric_label();
        let proto_label = self
            .current_protocol
            .map(|p| p.as_str())
            .unwrap_or("unknown");
        let kind_metric = if is_renewal {
            "yggdrasil_nat_renewals_total"
        } else {
            "yggdrasil_nat_mappings_created_total"
        };
        metrics::counter!(
            kind_metric,
            "protocol" => proto_label,
            "origin" => target.origin.as_token(),
            "result_code" => label,
        )
        .increment(1);
        self.last_error = Some(format!("{err}"));
        self.consecutive_errors = self.consecutive_errors.saturating_add(1);
        if !err.is_transient() {
            // Permanent error: drop the desired target so we don't
            // loop on it. Reconciliation will re-add if the operator
            // adjusts config.
            self.mappings.remove(&key);
        }
        if self.consecutive_errors >= ERROR_THRESHOLD_TO_BACKOFF {
            self.transition_backoff(format!("{err}"));
        }
    }

    /// Send a release ("lifetime=0") request for an active mapping.
    /// Best-effort: one shot, no retry.
    async fn release_one(&mut self, mapping: &ActiveMapping) {
        let target = &mapping.target;
        let nonce = mapping.pcp_nonce.unwrap_or_else(|| {
            self.nonces
                .get(&(target.protocol, target.internal_port))
                .copied()
                .unwrap_or_default()
        });

        let proto = mapping.protocol_used;
        let _ = self.try_unmap_via(proto, target, nonce).await;
        metrics::counter!(
            "yggdrasil_nat_mappings_released_total",
            "protocol" => proto.as_str(),
            "origin" => target.origin.as_token(),
        )
        .increment(1);
        self.nonces.remove(&(target.protocol, target.internal_port));
    }

    /// Bounded shutdown release: kick off `release_one` for every
    /// active mapping in parallel, but cap the whole pass with a
    /// `tokio::time::timeout`.
    async fn release_all_with_deadline(&mut self) {
        let snapshot: Vec<ActiveMapping> = self.mappings.values().cloned().collect();
        if snapshot.is_empty() {
            return;
        }
        let deadline = self.shutdown_release_timeout;
        let socket = match self.rpc_socket.as_ref() {
            Some(s) => s,
            None => return,
        };

        // We can't borrow self mutably across multiple parallel
        // tasks, but `release_one` only needs the socket + target +
        // nonce. Construct standalone release futures.
        let release_futures = snapshot.into_iter().map(|mapping| {
            let nonce = mapping.pcp_nonce.unwrap_or_default();
            let target = mapping.target.clone();
            let proto = mapping.protocol_used;
            async move {
                let _ = send_unmap_to_socket(socket, proto, &target, nonce).await;
                metrics::counter!(
                    "yggdrasil_nat_mappings_released_total",
                    "protocol" => proto.as_str(),
                    "origin" => target.origin.as_token(),
                )
                .increment(1);
            }
        });
        let _ = timeout(deadline, join_all(release_futures)).await;
        self.mappings.clear();
        self.nonces.clear();
    }

    fn transition_backoff(&mut self, why: String) {
        warn!(
            target: "yggdrasil::nat",
            error = %why,
            attempt = self.backoff_attempt,
            "entering backoff"
        );
        self.state = NatState::Backoff;
        self.last_error = Some(why);
    }

    async fn note_epoch(&mut self, new_epoch: u32) {
        match self.last_epoch {
            Some(prev) if new_epoch + 16 < prev => {
                // Backwards / huge gap → gateway lost state. RFC
                // 6887 §8.5: drop everything and re-establish.
                warn!(
                    target: "yggdrasil::nat",
                    prev_epoch = prev,
                    new_epoch,
                    "gateway epoch regressed; dropping all mappings"
                );
                metrics::counter!("yggdrasil_nat_epoch_resets_total").increment(1);
                let targets: Vec<MappingTarget> =
                    self.mappings.values().map(|m| m.target.clone()).collect();
                self.mappings.clear();
                self.nonces.clear();
                self.last_epoch = Some(new_epoch);
                // Re-create everything inline. The reconcile loop
                // will pick up any remaining drift on its next pass.
                for t in targets {
                    self.send_map_request_inline(t, false).await;
                }
            }
            _ => {
                self.last_epoch = Some(new_epoch);
            }
        }
    }

    /// Helper used by [`Self::note_epoch`] when it needs to recreate
    /// mappings without recursing into the epoch handler again.
    /// Behaves like [`Self::send_map_request`] but does not call
    /// `note_epoch` on the response.
    async fn send_map_request_inline(&mut self, target: MappingTarget, is_renewal: bool) {
        let key = (target.protocol, target.internal_port);
        let nonce = *self.nonces.entry(key).or_insert_with(|| {
            let mut n = [0u8; pcp::PCP_NONCE_LEN];
            rand::thread_rng().fill_bytes(&mut n);
            n
        });
        let proto = self.current_protocol.unwrap_or(NatProtocol::Pcp);
        if let Ok((resp, _epoch)) = self.try_map_via(proto, &target, nonce).await {
            let now = Instant::now();
            let assigned = Duration::from_secs(resp.assigned_lifetime_secs as u64);
            self.mappings.insert(
                key,
                ActiveMapping {
                    target: target.clone(),
                    external_port: resp.external_port,
                    external_addr: resp.external_addr,
                    assigned_lifetime: assigned,
                    renew_at: now + (assigned / 2),
                    last_renewed: now,
                    protocol_used: proto,
                    pcp_nonce: if proto == NatProtocol::Pcp {
                        Some(nonce)
                    } else {
                        None
                    },
                },
            );
            let metric = if is_renewal {
                "yggdrasil_nat_renewals_total"
            } else {
                "yggdrasil_nat_mappings_created_total"
            };
            metrics::counter!(
                metric,
                "protocol" => proto.as_str(),
                "origin" => target.origin.as_token(),
                "result_code" => "success",
            )
            .increment(1);
        }
    }

    async fn try_map_via(
        &self,
        proto: NatProtocol,
        target: &MappingTarget,
        nonce: [u8; pcp::PCP_NONCE_LEN],
    ) -> Result<(MapAck, u32), RpcError> {
        let socket = self.rpc_socket.as_ref().ok_or(RpcError::NoSocket)?;
        match proto {
            NatProtocol::Pcp => {
                let req = pcp::PcpMapRequest {
                    lifetime_secs: REQUESTED_LIFETIME_SECS,
                    client_addr: target.internal_addr,
                    nonce,
                    protocol: target.protocol,
                    internal_port: target.internal_port,
                    suggested_external_port: target.internal_port,
                    suggested_external_addr: Ipv4Addr::UNSPECIFIED,
                };
                let resp = pcp_rpc(socket, &req).await?;
                if resp.result_code != pcp::PcpResultCode::Success {
                    return Err(RpcError::Pcp(resp.result_code));
                }
                if resp.nonce != nonce {
                    return Err(RpcError::Wire(super::wire::WireError::NonceMismatch));
                }
                Ok((
                    MapAck {
                        external_port: resp.assigned_external_port,
                        external_addr: Some(resp.assigned_external_addr),
                        assigned_lifetime_secs: resp.assigned_lifetime,
                    },
                    resp.epoch_time,
                ))
            }
            NatProtocol::NatPmp => {
                let req = natpmp::NatPmpMapRequest {
                    protocol: target.protocol,
                    internal_port: target.internal_port,
                    suggested_external_port: target.internal_port,
                    lifetime_secs: REQUESTED_LIFETIME_SECS,
                };
                let resp = natpmp_rpc(socket, &req).await?;
                if resp.result_code != natpmp::NatPmpResultCode::Success {
                    return Err(RpcError::NatPmp(resp.result_code));
                }
                Ok((
                    MapAck {
                        external_port: resp.assigned_external_port,
                        external_addr: None,
                        assigned_lifetime_secs: resp.assigned_lifetime,
                    },
                    resp.seconds_since_epoch,
                ))
            }
        }
    }

    async fn try_unmap_via(
        &self,
        proto: NatProtocol,
        target: &MappingTarget,
        nonce: [u8; pcp::PCP_NONCE_LEN],
    ) -> Result<(), RpcError> {
        let socket = self.rpc_socket.as_ref().ok_or(RpcError::NoSocket)?;
        send_unmap_to_socket(socket, proto, target, nonce).await
    }

    /// Write the current state into the shared snapshot. Cheap.
    fn publish_snapshot(&self) {
        let snapshot = NatSnapshot {
            mode: self.mode,
            state: self.state,
            gateway: Some(self.gateway.addr),
            external_ip: self.external_ip,
            protocol: self.current_protocol,
            active_mappings: self.mappings.values().cloned().collect(),
            last_error: self.last_error.clone(),
        };
        metrics::gauge!("yggdrasil_nat_active_mappings").set(self.mappings.len() as f64);
        for state in [NatState::Discovering, NatState::Active, NatState::Backoff] {
            metrics::gauge!(
                "yggdrasil_nat_state",
                "state" => state.as_str(),
            )
            .set(if state == self.state { 1.0 } else { 0.0 });
        }
        metrics::gauge!("yggdrasil_nat_external_ip_known").set(if self.external_ip.is_some() {
            1.0
        } else {
            0.0
        });
        *self.snapshot.write() = snapshot;
    }
}

// ----------------------------------------------------------------------------
// Low-level RPC
// ----------------------------------------------------------------------------

/// What both protocols return when a map succeeds, normalized.
struct MapAck {
    external_port: u16,
    external_addr: Option<Ipv4Addr>,
    assigned_lifetime_secs: u32,
}

#[derive(Debug, thiserror::Error)]
enum RpcError {
    #[error("no RPC socket bound")]
    NoSocket,
    #[error("RPC timed out after {0} retries")]
    Timeout(usize),
    #[error("PCP error: {0:?}")]
    Pcp(pcp::PcpResultCode),
    #[error("NAT-PMP error: {0:?}")]
    NatPmp(natpmp::NatPmpResultCode),
    #[error("wire: {0}")]
    Wire(#[from] super::wire::WireError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl RpcError {
    fn is_transient(&self) -> bool {
        match self {
            Self::Pcp(code) => code.is_transient(),
            Self::NatPmp(code) => code.is_transient(),
            Self::Timeout(_) | Self::Io(_) | Self::NoSocket => true,
            Self::Wire(_) => false,
        }
    }
    fn should_fall_back_to_natpmp(&self) -> bool {
        match self {
            Self::Pcp(code) => code.should_fall_back_to_natpmp(),
            // Socket-timeout against a PCP request → most likely the
            // gateway just isn't listening on the PCP version we sent.
            // Per RFC 6887 §9 we fall back to NAT-PMP.
            Self::Timeout(_) => true,
            _ => false,
        }
    }
    fn metric_label(&self) -> &'static str {
        match self {
            Self::Pcp(code) => code.as_metric_label(),
            Self::NatPmp(code) => code.as_metric_label(),
            Self::Timeout(_) => "timeout",
            Self::Io(_) => "io",
            Self::Wire(_) => "wire_error",
            Self::NoSocket => "no_socket",
        }
    }
}

/// PCP request/response RPC with retry + exponential backoff. Returns
/// the parsed response (regardless of result_code).
async fn pcp_rpc(
    socket: &UdpSocket,
    req: &pcp::PcpMapRequest,
) -> Result<pcp::PcpMapResponse, RpcError> {
    let mut buf = [0u8; pcp::PCP_MAP_REQUEST_LEN];
    pcp::encode_map_request(req, &mut buf);
    let mut rt = RPC_INITIAL_TIMEOUT;
    let mut recv = [0u8; 1500];
    for attempt in 0..RPC_MAX_RETRIES {
        socket.send(&buf).await?;
        match timeout(rt, socket.recv(&mut recv)).await {
            Ok(Ok(n)) => {
                let parsed = pcp::decode_map_response(&recv[..n])?;
                if parsed.nonce != req.nonce {
                    // RFC 6887 §11.1: silently discard responses with
                    // mismatched nonces, then keep waiting on the
                    // same socket. The simplest implementation is to
                    // retry the whole RPC.
                    continue;
                }
                return Ok(parsed);
            }
            Ok(Err(e)) => return Err(RpcError::Io(e)),
            Err(_elapsed) => {
                rt *= 2;
                if attempt + 1 == RPC_MAX_RETRIES {
                    return Err(RpcError::Timeout(RPC_MAX_RETRIES));
                }
            }
        }
    }
    Err(RpcError::Timeout(RPC_MAX_RETRIES))
}

async fn natpmp_rpc(
    socket: &UdpSocket,
    req: &natpmp::NatPmpMapRequest,
) -> Result<natpmp::NatPmpMapResponse, RpcError> {
    let mut buf = [0u8; natpmp::NATPMP_MAP_REQUEST_LEN];
    natpmp::encode_map_request(req, &mut buf);
    let mut rt = RPC_INITIAL_TIMEOUT;
    let mut recv = [0u8; 1500];
    for attempt in 0..RPC_MAX_RETRIES {
        socket.send(&buf).await?;
        match timeout(rt, socket.recv(&mut recv)).await {
            Ok(Ok(n)) => {
                let parsed = natpmp::decode_map_response(&recv[..n])?;
                return Ok(parsed);
            }
            Ok(Err(e)) => return Err(RpcError::Io(e)),
            Err(_elapsed) => {
                rt *= 2;
                if attempt + 1 == RPC_MAX_RETRIES {
                    return Err(RpcError::Timeout(RPC_MAX_RETRIES));
                }
            }
        }
    }
    Err(RpcError::Timeout(RPC_MAX_RETRIES))
}

/// One-shot release. Sends a `lifetime=0` MAP. Doesn't retry.
async fn send_unmap_to_socket(
    socket: &UdpSocket,
    proto: NatProtocol,
    target: &MappingTarget,
    nonce: [u8; pcp::PCP_NONCE_LEN],
) -> Result<(), RpcError> {
    match proto {
        NatProtocol::Pcp => {
            let req = pcp::PcpMapRequest {
                lifetime_secs: 0,
                client_addr: target.internal_addr,
                nonce,
                protocol: target.protocol,
                internal_port: target.internal_port,
                suggested_external_port: target.internal_port,
                suggested_external_addr: Ipv4Addr::UNSPECIFIED,
            };
            let mut buf = [0u8; pcp::PCP_MAP_REQUEST_LEN];
            pcp::encode_map_request(&req, &mut buf);
            socket.send(&buf).await?;
            // Best-effort: we don't wait for the ack on release. If
            // the gateway already forgot the mapping, the response
            // would be `NotAuthorized` anyway and we'd be retrying
            // for nothing.
        }
        NatProtocol::NatPmp => {
            let req = natpmp::NatPmpMapRequest {
                protocol: target.protocol,
                internal_port: target.internal_port,
                suggested_external_port: 0,
                lifetime_secs: 0,
            };
            let mut buf = [0u8; natpmp::NATPMP_MAP_REQUEST_LEN];
            natpmp::encode_map_request(&req, &mut buf);
            socket.send(&buf).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatoskr::rule::Rule;
    use std::str::FromStr;

    fn tcp_rule(name: &str, listen: &str) -> Rule {
        Rule {
            name: name.into(),
            listen: SocketAddr::from_str(listen).unwrap(),
            protocol: Protocol::Tcp,
            target_port: Some(22),
            target: None,
            idle_timeout: None,
            proxy_protocol: None,
        }
    }

    fn udp_rule(name: &str, listen: &str) -> Rule {
        Rule {
            name: name.into(),
            listen: SocketAddr::from_str(listen).unwrap(),
            protocol: Protocol::Udp,
            target_port: Some(53),
            target: None,
            idle_timeout: None,
            proxy_protocol: None,
        }
    }

    fn local_source() -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, 100)
    }

    #[test]
    fn tcp_rule_yields_one_tcp_target() {
        let rules = vec![tcp_rule("ssh", "192.168.1.10:22")];
        let targets = compute_targets(&rules, None, None, local_source());
        assert_eq!(targets.len(), 1);
        let t = targets.iter().next().unwrap();
        assert_eq!(t.protocol, MapProtocol::Tcp);
        assert_eq!(t.internal_port, 22);
        assert_eq!(t.internal_addr, Ipv4Addr::new(192, 168, 1, 10));
        assert!(matches!(&t.origin, MappingOrigin::Rule(n) if n == "ssh"));
    }

    #[test]
    fn udp_rule_yields_one_udp_target() {
        let rules = vec![udp_rule("dns", "192.168.1.10:53")];
        let targets = compute_targets(&rules, None, None, local_source());
        assert_eq!(targets.len(), 1);
        let t = targets.iter().next().unwrap();
        assert_eq!(t.protocol, MapProtocol::Udp);
        assert_eq!(t.internal_port, 53);
    }

    fn https_target(listen: &str, http3: bool) -> HttpsTarget {
        HttpsTarget {
            listen: SocketAddr::from_str(listen).unwrap(),
            http3,
        }
    }

    #[test]
    fn https_default_yields_tcp_udp_redirect() {
        let rules: Vec<Rule> = vec![];
        let https = Some(https_target("192.168.1.10:443", true));
        let targets = compute_targets(&rules, None, https, local_source());
        let mut origins: Vec<String> = targets.iter().map(|t| t.origin.as_token()).collect();
        origins.sort();
        assert_eq!(
            origins,
            vec![
                "http3:https".to_owned(),
                "redirect:192.168.1.10".to_owned(),
                "rule:https".to_owned(),
            ]
        );
        // TCP frontend on 443, UDP H/3 on 443, TCP redirect on 80.
        let mut by_port: Vec<(MapProtocol, u16)> = targets
            .iter()
            .map(|t| (t.protocol, t.internal_port))
            .collect();
        by_port.sort_by_key(|&(p, port)| (port, p as u8));
        assert_eq!(
            by_port,
            vec![
                (MapProtocol::Tcp, 80),
                (MapProtocol::Tcp, 443),
                (MapProtocol::Udp, 443),
            ]
        );
    }

    #[test]
    fn https_with_http3_false_yields_only_tcp_and_redirect() {
        let rules: Vec<Rule> = vec![];
        let https = Some(https_target("192.168.1.10:443", false));
        let targets = compute_targets(&rules, None, https, local_source());
        let mut origins: Vec<String> = targets.iter().map(|t| t.origin.as_token()).collect();
        origins.sort();
        assert_eq!(
            origins,
            vec!["redirect:192.168.1.10".to_owned(), "rule:https".to_owned(),]
        );
    }

    #[test]
    fn https_redirect_is_single_target() {
        // Node-wide HTTPS produces exactly one redirect target on
        // the listener's bind IP — no per-rule dedup needed any more.
        let rules: Vec<Rule> = vec![];
        let https = Some(https_target("192.168.1.10:443", true));
        let targets = compute_targets(&rules, None, https, local_source());
        let redirects: Vec<&MappingTarget> = targets
            .iter()
            .filter(|t| matches!(t.origin, MappingOrigin::HttpsRedirect(_)))
            .collect();
        assert_eq!(redirects.len(), 1);
    }

    #[test]
    fn loopback_listener_is_filtered() {
        let rules = vec![tcp_rule("local", "127.0.0.1:1234")];
        let targets = compute_targets(&rules, None, None, local_source());
        assert!(
            targets.is_empty(),
            "loopback-bound listeners must not be mapped"
        );
    }

    #[test]
    fn link_local_listener_is_filtered() {
        let rules = vec![tcp_rule("ll", "169.254.1.2:1234")];
        let targets = compute_targets(&rules, None, None, local_source());
        assert!(targets.is_empty());
    }

    #[test]
    fn public_internal_listener_is_filtered() {
        let rules = vec![tcp_rule("pub", "203.0.113.5:1234")];
        let targets = compute_targets(&rules, None, None, local_source());
        assert!(
            targets.is_empty(),
            "publicly-bound listeners need no NAT mapping"
        );
    }

    #[test]
    fn unspecified_listener_uses_local_source() {
        let rules = vec![tcp_rule("any", "0.0.0.0:8080")];
        let targets = compute_targets(&rules, None, None, local_source());
        let t = targets.iter().next().unwrap();
        assert_eq!(t.internal_addr, local_source());
    }

    #[test]
    fn accept_listen_yields_udp_target() {
        let rules: Vec<Rule> = vec![];
        let accept = SocketAddr::from_str("0.0.0.0:51820").unwrap();
        let targets = compute_targets(&rules, Some(accept), None, local_source());
        assert_eq!(targets.len(), 1);
        let t = targets.iter().next().unwrap();
        assert_eq!(t.protocol, MapProtocol::Udp);
        assert_eq!(t.internal_port, 51820);
        assert!(matches!(t.origin, MappingOrigin::AcceptListen));
    }

    #[test]
    fn accept_listen_on_public_ip_is_filtered() {
        let rules: Vec<Rule> = vec![];
        let accept = SocketAddr::from_str("203.0.113.1:51820").unwrap();
        let targets = compute_targets(&rules, Some(accept), None, local_source());
        assert!(targets.is_empty());
    }

    #[test]
    fn cgnat_listener_is_allowed() {
        // 100.64.0.0/10 (CGNAT) bind IPs are legitimate residential
        // addresses that we should still try to map; the mapper will
        // surface the gateway's likely `AddressMismatch` later via
        // metrics, but the listener itself is in scope.
        let rules = vec![tcp_rule("cg", "100.64.5.10:443")];
        let targets = compute_targets(&rules, None, None, local_source());
        assert_eq!(targets.len(), 1);
    }

    // ---- enumerate_targets: skipped path ----

    #[test]
    fn enumerate_records_loopback_skip() {
        let rules = vec![tcp_rule("local", "127.0.0.1:1234")];
        let e = enumerate_targets(&rules, None, None, local_source());
        assert!(e.targets.is_empty());
        assert_eq!(e.skipped.len(), 1);
        assert_eq!(e.skipped[0].0, "rule:local");
        assert_eq!(e.skipped[0].1, SkipReason::Loopback);
    }

    #[test]
    fn enumerate_records_link_local_skip() {
        let rules = vec![tcp_rule("ll", "169.254.5.6:1234")];
        let e = enumerate_targets(&rules, None, None, local_source());
        assert_eq!(e.skipped.len(), 1);
        assert_eq!(e.skipped[0].1, SkipReason::LinkLocal);
    }

    #[test]
    fn enumerate_records_public_internal_skip() {
        let rules = vec![tcp_rule("pub", "203.0.113.7:443")];
        let e = enumerate_targets(&rules, None, None, local_source());
        assert_eq!(e.skipped.len(), 1);
        assert_eq!(e.skipped[0].1, SkipReason::PublicInternal);
    }

    #[test]
    fn enumerate_records_accept_listen_skip_on_public_ip() {
        let rules: Vec<Rule> = vec![];
        let accept = SocketAddr::from_str("203.0.113.1:51820").unwrap();
        let e = enumerate_targets(&rules, Some(accept), None, local_source());
        assert!(e.targets.is_empty());
        assert_eq!(e.skipped.len(), 1);
        assert_eq!(e.skipped[0].0, "accept");
        assert_eq!(e.skipped[0].1, SkipReason::PublicInternal);
    }

    #[test]
    fn skip_reason_metric_labels_are_stable() {
        // Stable metric labels — surface-level test so a future
        // rename ripples through here loudly.
        assert_eq!(SkipReason::Loopback.as_str(), "loopback");
        assert_eq!(SkipReason::LinkLocal.as_str(), "link_local");
        assert_eq!(SkipReason::PublicInternal.as_str(), "public_internal");
        assert_eq!(SkipReason::Ipv6.as_str(), "ipv6");
    }

    #[test]
    fn mapping_origin_token_shapes() {
        assert_eq!(MappingOrigin::Rule("foo".into()).as_token(), "rule:foo");
        assert_eq!(MappingOrigin::AcceptListen.as_token(), "accept");
        assert_eq!(
            MappingOrigin::HttpsRedirect(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))).as_token(),
            "redirect:1.2.3.4"
        );
        assert_eq!(MappingOrigin::Http3("bar".into()).as_token(), "http3:bar");
    }
}
