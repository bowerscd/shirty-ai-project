//! Control-plane protocol between `yggdrasil` (server) and `yggdrasilctl` (CLI).
//!
//! ## Framing
//!
//! Newline-delimited JSON over the Unix domain socket. Each request is a
//! single JSON object terminated by a `\n`. The server replies with one JSON
//! object also terminated by `\n`, then either reads the next request on the
//! same connection or closes.
//!
//! Why not length-prefixed? A line-delimited transport composes with `socat`,
//! `nc -U`, and `jq`, which is invaluable when debugging on a box where you
//! cannot run the real `yggdrasilctl` binary.
//!
//! ## Backwards compatibility
//!
//! Both [`Request`] and [`Response`] are `#[serde(tag = "kind")]`. New variants
//! may be added at any time; old clients must error out gracefully when they
//! encounter a variant they don't recognise. Reusing a kind string with a
//! different schema is forbidden.

use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::predicate::Predicate;
use crate::pubkey::PubKey;
use crate::rule::{Protocol, Rule};

/// Runtime mode the daemon is operating in, surfaced in status responses.
///
/// Derived from `[dial]`/`[accept]` presence in the daemon's config:
///
/// | mode       | `[dial]` | `[accept]` |
/// |------------|----------|------------|
/// | `gateway`  | absent   | present    |
/// | `relay`    | present  | present    |
/// | `terminal` | present  | absent     |
///
/// (Both absent is rejected at config-load time.) Wire serialisation
/// matches the daemon's derived runtime mode and `--require-mode` CLI
/// values exactly.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Head of chain. `[accept]` only — accepts inbound chain traffic
    /// but does not dial any further upstream.
    Gateway,
    /// Mid-chain. `[accept]` + `[dial]` — accepts inbound and
    /// republishes predicates upward.
    #[default]
    Relay,
    /// Tail. `[dial]` only — no inbound chain traffic; dials upstream
    /// to publish its own predicates.
    Terminal,
}

impl Mode {
    /// Stable English string for log/metric formatting.
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Gateway => "gateway",
            Mode::Relay => "relay",
            Mode::Terminal => "terminal",
        }
    }
}

/// All possible client → server messages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Request {
    /// High-level summary.
    Status,
    /// List loaded rules with their listen sockets.
    RulesList,
    /// Force a reload of the rules directory.
    RulesReload,
    /// Currently enrolled downstream pubkey + fingerprint.
    DownstreamShow,
    /// Staged (TOFU) downstream candidates awaiting approval.
    DownstreamPending,
    /// Approve a staged candidate by its fingerprint or any unique
    /// 8+-hex-char prefix. The daemon disambiguates: a unique match
    /// pops the candidate and emits [`Response::DownstreamApproved`];
    /// an ambiguous prefix returns
    /// [`error_codes::AMBIGUOUS_FINGERPRINT`] with the colliding
    /// fingerprints in the message.
    DownstreamApprove {
        /// Full BLAKE2s-128 fingerprint (32 hex chars) or any unique
        /// prefix of at least 8 hex chars.
        fingerprint: String,
    },
    /// List TLS certificates currently loaded into the cert store, one
    /// entry per `(rule, route)`. Each entry includes the resolved
    /// hostname, where the cert came from, and parsed metadata.
    // (`CertsList` was removed; cert summary now folded into `Status`.)
    /// Render the daemon's Prometheus metrics in text exposition format.
    /// The daemon dispatches the request to its in-process recorder.
    /// Backs `yggdrasilctl local metrics`.
    Metrics,
    /// Liveness/readiness probe served over the control socket. Backs
    /// `yggdrasilctl local health`.
    Health,
    /// Snapshot of this node's chain-applied predicates, derived rule
    /// set, and chain identity. Backs both `yggdrasilctl local
    /// derived-rules` and the local-hop fetch in `yggdrasilctl chain
    /// diff`.
    DerivedRules,
    /// Walk the chain from this node upward and collect a per-hop
    /// summary suitable for `yggdrasilctl chain summary` / `health` /
    /// `diff` / `ping`. The single comprehensive reply
    /// ([`ChainSummaryResponse`]) carries every per-hop field; CLI
    /// subcommands project the slices they care about (CP23 in the
    /// config-UX plan).
    ///
    /// The daemon always returns its own local hop; when a chain
    /// upstream is configured (`[dial]` set), it additionally
    /// forwards a `ChainHopQuery` upstream and aggregates the
    /// returned hops into the reply. Terminals with no upstream
    /// return only the local hop and `partial = false`.
    ChainSummary {
        /// Optional overall budget in milliseconds the operator is
        /// willing to wait for the upstream walk. `None` means "use
        /// the daemon default". Daemons with no upstream return
        /// synchronously and effectively ignore this.
        timeout_ms: Option<u64>,
    },
    /// Push a candidate rule set into the daemon's running supervisor
    /// without touching the rules directory on disk. Backs
    /// `yggdrasilctl chain apply --file rules.toml`.
    ///
    /// The CLI is the canonical parser: it reads `rules.toml`, parses
    /// it via [`crate::rule::RuleFile::from_toml`], performs per-rule
    /// validation, and ships the resulting `Vec<Rule>` over the wire.
    /// The daemon performs defensive re-validation (cross-rule
    /// uniqueness, listen/protocol conflicts) and refuses the apply if
    /// any rule fails. On terminals with `[dial]` configured,
    /// the daemon additionally pre-checks the projected predicate set
    /// against [`crate::predicate::PREDICATE_SET_MAX_WIRE_BYTES`] so an
    /// oversize push fails synchronously here instead of silently
    /// failing later in the publisher.
    ///
    /// **Terminal mode only.** Relays receive their rule set from
    /// downstream predicate pushes and cannot accept a manual apply
    /// without it being immediately overwritten on the next push;
    /// returns [`error_codes::NOT_SUPPORTED_IN_RELAY_MODE`].
    ChainApply {
        /// Pre-parsed rules from the operator's candidate file. Order
        /// is preserved across the wire; uniqueness + listen-conflict
        /// checks run on the daemon side.
        rules: Vec<Rule>,
    },
    /// Adjust the daemon's `tracing` filter at runtime. `directive` is
    /// any string accepted by [`tracing_subscriber::EnvFilter`] (a bare
    /// level like `"debug"`, or a comma-separated set of
    /// `target=level` rules). When `directive` is `None`, the filter
    /// reverts to the value the daemon was started with (from the
    /// `YGGDRASIL_LOG` env var, or `info` if unset). Backs
    /// `yggdrasilctl local trace [<DIRECTIVE>] [--reset]`.
    TraceSet {
        /// New filter directive, or `None` to reset to the startup
        /// default.
        directive: Option<String>,
    },
    /// List ACME-managed hostnames with the renewer's view of their
    /// state (next-renewal timestamp, last result, current cert
    /// origin). Backs `yggdrasilctl local acme list`.
    AcmeList,
    /// Force an immediate ACME issuance for `hostname`, bypassing the
    /// renewer's schedule. The daemon performs the standard
    /// order/authorise/finalise flow and returns once the result is
    /// known (success → cert reloaded into the live store; failure →
    /// stand-in keeps serving). Backs `yggdrasilctl local acme renew`.
    AcmeRenew {
        /// The route hostname (case-insensitive).
        hostname: String,
    },
    /// Probe a rule's L4 forwarding path end-to-end through the chain.
    /// The daemon:
    ///   1. Resolves a rule for `(rule_listen, rule_protocol)` on the
    ///      local node, returning [`error_codes::NO_SUCH_RULE`] with a
    ///      close-match suggestion list if none matches.
    ///   2. Arms every hop along the chain via a recursive `CanaryArm`
    ///      fanout. If any hop is unreachable, returns
    ///      [`ChainCanaryResponse::status`] = [`CanaryStatus::ChainDead`].
    ///   3. Opens a probe connection to its own rule listener,
    ///      prefixing the 32-byte arming token. Token-matched traffic
    ///      short-circuits to an in-process echo at the terminal hop
    ///      (never reaches the configured backend). Computes per-
    ///      direction throughput / loss / latency over `duration_ms`.
    ///   4. Classifies the outcome as [`CanaryStatus::Ok`] or
    ///      [`CanaryStatus::Degraded`] based on loss / latency
    ///      thresholds.
    ///
    /// Backs `yggdrasilctl chain canary --port N [--proto tcp|udp]`.
    ChainCanary {
        /// Rule's listen `(bind, port)` tuple. The CLI typically
        /// translates `--port N` into `0.0.0.0:N` (or the rule's
        /// explicit bind when `--bind` is supplied) before sending.
        rule_listen: SocketAddr,
        /// L4 protocol of the rule. The daemon's lookup is on
        /// `(rule_listen, rule_protocol)`; `Protocol::Https` is
        /// invalid here because canary operates on a single
        /// transport per invocation — HTTPS rules are probed via two
        /// `ChainCanary` requests issued back-to-back by the CLI
        /// (one TCP, one UDP).
        rule_protocol: Protocol,
        /// Probe duration in milliseconds. Defaults at the CLI side
        /// to 3000.
        duration_ms: u32,
        /// Sustained rate. For `Protocol::Tcp` this is interpreted as
        /// megabits per second per direction (the CLI default is
        /// 1 MB/s); for `Protocol::Udp` it is packets per second per
        /// direction (the CLI default is 100 pps). Setting to `0`
        /// uses the daemon's protocol default.
        rate: u32,
        /// UDP-only payload size in bytes. Ignored for TCP. CLI
        /// default: 1200 (fits one MTU after chain framing overhead).
        /// `0` uses the daemon's default.
        payload_bytes: u32,
        /// End-to-end timeout for the arm phase, in milliseconds.
        /// `None` uses [`crate::canary::CANARY_ARM_DEFAULT_DEADLINE_MS`].
        timeout_ms: Option<u32>,
    },
}

/// All possible server → client messages.
///
/// Exactly one of these is emitted per request. The `Error` variant is used
/// for anything from "no such fingerprint" through "config file unwritable".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    /// Successful response to [`Request::ChainSummary`]. See
    /// [`ChainSummaryResponse`] for the field semantics.
    ChainSummary(ChainSummaryResponse),
    Status(StatusResponse),
    Rules(RulesResponse),
    RulesReloaded {
        reloaded_rule_count: usize,
    },
    Downstream(DownstreamResponse),
    DownstreamPending(PendingResponse),
    DownstreamApproved {
        fingerprint: String,
    },
    // (`Response::Certs` was removed; cert summary now folded into `Status`.)
    /// Successful response to [`Request::Metrics`]. Body is a single
    /// string containing the Prometheus text exposition format. Newlines
    /// inside `body` are preserved verbatim; clients should print as-is.
    Metrics(MetricsResponse),
    /// Successful response to [`Request::Health`]. See
    /// [`HealthResponse`] for the field semantics.
    Health(HealthResponse),
    /// Successful response to [`Request::DerivedRules`]. See
    /// [`DerivedRulesResponse`] for the field semantics.
    DerivedRules(DerivedRulesResponse),
    /// Successful response to [`Request::ChainApply`]. Reports the
    /// number of rules that were handed to the supervisor and, for
    /// terminal daemons with a chain upstream, what the projected
    /// predicate set looks like.
    ChainApplied(ChainAppliedResponse),
    /// Successful response to [`Request::TraceSet`]. `active` is the
    /// directive now in effect (after the change applied);
    /// `default` is the startup directive a `--reset` would restore.
    TraceSet {
        /// Filter directive currently in effect.
        active: String,
        /// Filter directive a `--reset` would restore (the value the
        /// daemon was launched with).
        default: String,
    },
    /// Generic failure. Always preserves the request kind for diagnostics.
    Error {
        /// e.g. "no_such_fingerprint", "config_write_failed", "unknown_request".
        code: String,
        message: String,
    },
    /// Successful response to [`Request::AcmeList`].
    AcmeList(AcmeListResponse),
    /// Successful response to [`Request::AcmeRenew`].
    AcmeRenewed {
        /// The hostname whose renewer was kicked.
        hostname: String,
        /// `true` if the daemon ran issuance to completion and wrote a
        /// fresh PEM to disk; `false` if issuance failed (the daemon
        /// returns a separate `Error` response in that case, so this
        /// field is `true` in practice).
        success: bool,
    },
    /// Successful response to [`Request::ChainCanary`]. The `status`
    /// field discriminates between the four primary outcomes; the
    /// other fields carry the structured detail rendered by the CLI.
    ChainCanary(ChainCanaryResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusResponse {
    /// Build version (`env!("CARGO_PKG_VERSION")`).
    pub version: String,
    /// Runtime mode the daemon was started in. Defaults to [`Mode::Relay`]
    /// for forward-compatibility: an older `yggdrasilctl` parsing a newer
    /// daemon's response still sees a valid `Mode`, and a newer
    /// `yggdrasilctl` against an older daemon defaults to `relay` (the only
    /// mode that used to exist).
    #[serde(default)]
    pub mode: Mode,
    /// Currently known downstream IP (`None` until first heartbeat). Always
    /// `None` in terminal mode.
    pub downstream_ip: Option<IpAddr>,
    /// Milliseconds since the last accepted heartbeat (`None` if no heartbeats yet).
    /// Always `None` in terminal mode.
    pub last_heartbeat_age_ms: Option<u64>,
    /// Number of currently-loaded rules.
    pub rule_count: usize,
    /// Server uptime in seconds.
    pub uptime_secs: u64,
    /// Whether a downstream has been enrolled (`[accept]` present
    /// in config). Always `false` in terminal mode.
    pub downstream_enrolled: bool,
    /// Path to the operator-supplied default cert, if loaded into the
    /// cert store. `None` when no `[server].default_cert` was set or no
    /// loaded cert traces back to it (terminal-without-https).
    #[serde(default)]
    pub default_cert_path: Option<String>,
    /// Seconds since the default cert was loaded into the store. `None`
    /// when [`Self::default_cert_path`] is `None`.
    #[serde(default)]
    pub default_cert_loaded_age_secs: Option<u64>,
    /// Count of dynamically-generated ephemeral (self-signed) certs in
    /// the store. Always `0` on a daemon without HTTPS rules.
    #[serde(default)]
    pub ephemeral_cert_count: usize,
    /// NAT-traversal subsystem state. `None` when
    /// `[server].nat_traversal = "off"` (the default) or when the
    /// gateway-discovery probe failed on startup. The field is
    /// omitted from JSON in that case for backwards compatibility
    /// with older `yggdrasilctl`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nat: Option<NatStatus>,
    /// Resolved `lan_cidrs` set, in CIDR-string form, used by the
    /// per-IP companion listener to gate cert-less route serving on
    /// `:80`. Empty when the daemon has no HTTPS rules loaded (the
    /// resolved set still has a value, but the operator-facing
    /// renderer suppresses the block when [`Self::certless_route_count`]
    /// is zero — same pattern as the existing cert summary). Older
    /// `yggdrasilctl` builds default this to an empty Vec via
    /// `#[serde(default)]`.
    #[serde(default)]
    pub lan_cidrs: Vec<String>,
    /// Source of [`Self::lan_cidrs`]: `"default"` (no operator
    /// override, hard-coded set in use) or `"override"` (operator set
    /// `[server].lan_cidrs`).
    #[serde(default)]
    pub lan_cidrs_source: String,
    /// Count of routes currently served via the per-IP companion
    /// listener's plaintext path (no cert source resolved). The
    /// `yggdrasilctl local status` renderer prints the `lan_cidrs`
    /// block only when this is non-zero, matching the cert-summary
    /// "only when applicable" pattern.
    #[serde(default)]
    pub certless_route_count: usize,
}

/// NAT-traversal subsystem state surfaced under
/// [`StatusResponse::nat`]. Strings are used for `mode`, `state`,
/// `protocol`, and `MappingEntry::origin` so that adding new variants
/// (e.g. a hypothetical future `pq` algorithm or `relay-mode-only`
/// state) on the daemon side doesn't break older `yggdrasilctl`
/// builds: they just see an unknown string and render it verbatim.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NatStatus {
    /// One of `"off"` / `"pcp"` / `"natpmp"` / `"auto"`. Echoes the
    /// operator-configured `[server].nat_traversal`. `"off"` is only
    /// observable on this field when the subsystem was started and
    /// later disabled at runtime — at config time `off` produces a
    /// `None` parent field, which is omitted from the JSON.
    pub mode: String,
    /// One of `"discovering"` / `"active"` / `"backoff"` /
    /// `"disabled"`.
    pub state: String,
    /// Gateway IP (default route's next-hop) the mapper is talking
    /// to. `None` while gateway discovery is still in flight or has
    /// failed.
    pub gateway: Option<IpAddr>,
    /// External IP the gateway reported in the most recent
    /// successful map response. `None` until the first map succeeds.
    /// NAT-PMP-only deployments require a separate "external
    /// address" request to learn this; we may not have made one yet.
    pub external_ip: Option<IpAddr>,
    /// Protocol currently in use. `Some("pcp")` after the first
    /// successful PCP response; `Some("natpmp")` after the first
    /// successful NAT-PMP response; `None` while we're still
    /// probing.
    pub protocol: Option<String>,
    /// Number of mappings currently held. Always equal to
    /// `mappings.len()` — exposed separately so older clients that
    /// don't parse `mappings` can still display a useful summary.
    pub active_mapping_count: usize,
    /// Most recent error surfaced by the mapper, if any. Cleared on
    /// next successful operation.
    pub last_error: Option<String>,
    /// Per-mapping detail. Bounded by the number of listeners the
    /// daemon has — typically O(rules) plus the one accept listener
    /// plus one redirect listener per HTTPS bind IP.
    #[serde(default)]
    pub mappings: Vec<NatMappingEntry>,
}

/// Single mapping entry within [`NatStatus::mappings`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NatMappingEntry {
    /// Human-readable origin tag: `"rule:<name>"` / `"accept"` /
    /// `"redirect:<ip>"` / `"http3:<name>"`. Stable across renewals;
    /// the daemon documents the format in
    /// `crate::nat::MappingOrigin::as_token`.
    pub origin: String,
    /// `"tcp"` or `"udp"`.
    pub protocol: String,
    pub internal_port: u16,
    pub external_port: u16,
    /// Assigned lifetime the gateway returned. Renewal is at
    /// `assigned_lifetime_secs / 2`; if the value drops to a low
    /// number we're on a router that caps mappings aggressively.
    pub assigned_lifetime_secs: u32,
    /// Time until the daemon will next renew this mapping. `0`
    /// means "right now" (the daemon will renew on its next tick).
    pub renew_in_secs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RulesResponse {
    pub rules: Vec<RuleInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleInfo {
    pub name: String,
    /// `"tcp"` or `"udp"`.
    pub protocol: String,
    /// `host:port`.
    pub listen: String,
    /// Stable, human-readable description of the dial target. Renders as
    /// `dynamic:peer:<port>` for relay-mode rules and as `static:<ip>:<port>`
    /// for terminal-mode rules. Not a parse target — diagnostic only.
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DownstreamResponse {
    /// Whether the server has a downstream enrolled yet.
    pub enrolled: bool,
    /// Tagged pubkey form (`x25519:<hex>`); empty if `!enrolled`.
    pub pubkey: String,
    /// Short fingerprint (empty if `!enrolled`).
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingResponse {
    pub candidates: Vec<PendingCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingCandidate {
    pub fingerprint: String,
    pub public_key_hex: String,
    /// Unix epoch milliseconds when the candidate was first seen.
    pub first_seen_unix_ms: u64,
    /// Number of failed handshake attempts observed from this candidate.
    pub attempt_count: u64,
}

/// Response body for [`Request::Metrics`]. The `body` field is the
/// Prometheus text exposition format, ready to be written to stdout or
/// piped into a scraper.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetricsResponse {
    pub body: String,
}

/// Response body for [`Request::Health`]. `ready` flips to `true` once
/// every subsystem has signalled readiness via
/// `yggdrasil::health::mark_ready`. `uptime_secs` is monotonic since
/// process start and is convenient to gate "daemon is in `starting`
/// tier" health logic against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthResponse {
    /// `true` once the readiness latch has been triggered.
    pub ready: bool,
    /// Process uptime in whole seconds.
    pub uptime_secs: u64,
}

/// Response body for [`Request::DerivedRules`]. Snapshot of this node's
/// chain-applied predicates, derived rule set, and chain identity.
///
/// Wire-stable: `yggdrasilctl chain diff` parses this from older daemons
/// over UDS and (when the multi-hop tunneled path lands) over chain
/// tunnels. Field names + JSON shape must not change without a wire
/// version bump.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DerivedRulesResponse {
    /// Predicates this node is currently driven by. On a terminal these
    /// are the projection of `derived_rules`; on a relay these are the
    /// set last *received and accepted* from its downstream.
    pub predicates: Vec<Predicate>,
    /// Active rule set on this node, as the proxy supervisor reports
    /// it. Always reflects the supervisor's `current_set` watch at
    /// snapshot time.
    pub derived_rules: Vec<Rule>,
    /// Chain identity facts and predicate-set metadata for the hop.
    pub chain: ChainIdentity,
}

/// Chain-identity facts and predicate-set metadata. Carried inside
/// [`DerivedRulesResponse`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainIdentity {
    /// This node's static x25519 pubkey, tagged. Lets `chain diff`
    /// confirm which node it actually reached.
    pub local: PubKey,
    /// Upstream node pubkey when `[dial]` is configured.
    pub upstream: Option<PubKey>,
    /// Downstream node pubkey when `[accept]` is configured.
    pub downstream: Option<PubKey>,
    /// `PredicateSet.origin` of the most recently applied push. On a
    /// terminal this equals `local`; on a relay it equals the terminal
    /// further down the chain that authored the predicates.
    pub predicate_origin: Option<PubKey>,
    /// `PredicateSet.version` of the most recently applied push.
    pub predicate_version: Option<u64>,
    /// Wall-clock seconds since UNIX epoch of the most recent
    /// `record_apply`. `None` until the first push has been applied.
    pub last_apply_unix: Option<i64>,
}

/// Aggregated reply for [`Request::ChainSummary`]. Each hop is one
/// element of `hops`; index 0 is the daemon that received the UDS
/// request, index N is the head-of-chain.
///
/// CP23 (config-UX plan): single comprehensive reply struct covering
/// every per-hop field; `chain summary`, `chain health`, `chain diff`,
/// `chain ping` all hang off this primitive and project the slices
/// they care about.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainSummaryResponse {
    /// One entry per chain hop, ordered from local (index 0) outward
    /// to the head-of-chain. On terminals with no chain upstream this
    /// is always exactly one element (the local hop).
    pub hops: Vec<ChainHop>,
    /// Whether the daemon was unable to collect every upstream hop
    /// before the budget expired. `false` when no fanout happened
    /// (terminal with no upstream); set to `true` when the upstream
    /// walk timed out, errored, or truncated below the depth budget.
    pub partial: bool,
}

/// One hop's view of itself, as reported on the chain control plane.
/// Composed from this node's [`DerivedRulesResponse`] plus mode +
/// uptime so the CLI can render summary / health / diff without a
/// second RPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainHop {
    /// `0 = local`, `1 = local's upstream`, `2 = grandparent`, …
    pub hop_index: u32,
    /// Runtime mode (`gateway` / `relay` / `terminal`).
    pub mode: Mode,
    /// Process uptime in whole seconds.
    pub uptime_secs: u64,
    /// Human-readable label for this hop, sourced from the hop's
    /// `[server].name` config (falling back to `gethostname(3)`).
    /// Renderers prefer this over [`ChainIdentity::local`] for display.
    pub name: Option<String>,
    /// Predicates, derived rule set, and chain identity facts. Every
    /// field of [`DerivedRulesResponse`] is wire-stable across hops.
    pub view: DerivedRulesResponse,
    /// Wall-clock round-trip time, in milliseconds, that the *parent*
    /// hop measured for the upstream `ChainHopQuery` that produced
    /// this entry. `None` on the local hop (index 0 in any reply, no
    /// RTT applies — it's the responder itself) and on hops further
    /// upstream that were already known to the responder via cached
    /// state.
    ///
    /// Backs `chain ping` and lets `chain summary --json` expose
    /// per-hop RTT for monitoring.
    pub query_rtt_ms: Option<u64>,
}

/// Response body for a successful [`Request::ChainApply`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainAppliedResponse {
    /// Total rules handed to the supervisor.
    pub applied_rule_count: usize,
    /// Predicates that will be projected upstream from the new rule
    /// set, if the daemon has a chain upstream. Zero on terminals
    /// without `[dial]` and on pure-local nodes.
    pub predicate_count: usize,
    /// Compatibility list for rules skipped by older HTTPS-unaware predicate
    /// projection. Current daemons emit HTTPS predicates, so this is empty;
    /// it is also empty on nodes without an upstream because no projection is run.
    pub skipped_https: Vec<String>,
}

/// Successful response to [`Request::AcmeList`]. Empty when `[acme]`
/// is unconfigured or no routes declare `cert = "acme"`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcmeListResponse {
    pub hosts: Vec<AcmeHostInfo>,
}

/// Per-managed-host renewer snapshot. Returned in
/// [`AcmeListResponse::hosts`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcmeHostInfo {
    /// Lowercased route hostname.
    pub hostname: String,
    /// Either `"http01"` or `"dns01"`. Stable string so older
    /// `yggdrasilctl` builds don't break when newer challenge types
    /// land.
    pub challenge: String,
    /// DNS-01 provider name, if `challenge == "dns01"`.
    pub provider: Option<String>,
    /// State of the current cert. One of `"pending"` (renewer hasn't
    /// completed first issuance), `"active"` (PEM on disk, in use),
    /// `"error"` (last issuance attempt failed; stand-in still serving).
    pub state: String,
    /// Last error message from the renewer task, if any.
    pub last_error: Option<String>,
    /// Unix-epoch seconds of the next scheduled renewal attempt.
    /// `None` if the renewer hasn't computed a schedule yet (e.g.
    /// initial issuance still in progress).
    pub next_renewal_unix: Option<u64>,
    /// Unix-epoch seconds of the current cert's `not_after`, when
    /// known. `None` for `pending` / `error` states.
    pub not_after_unix: Option<u64>,
}

/// Top-level discriminator for [`ChainCanaryResponse::status`]. Drives
/// the renderer's output shape and the CLI's exit code.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CanaryStatus {
    /// Probe ran clean: arm phase reached every hop, data phase
    /// completed within loss / latency thresholds.
    Ok,
    /// Probe ran but the loss rate or tail latency exceeded the
    /// daemon's classifier thresholds. Numbers are still in
    /// [`ChainCanaryResponse::probe_results`].
    Degraded,
    /// No rule on this node binds the requested `(rule_listen,
    /// rule_protocol)`. The accompanying
    /// [`ChainCanaryResponse::close_matches`] suggests likely
    /// near-misses for the renderer.
    NoSuchRule,
    /// The arm phase couldn't reach a hop. The chain was up to the
    /// last responding hop in [`ChainCanaryResponse::chain`]; further
    /// hops are absent. [`ChainCanaryResponse::probe_results`] is
    /// `None` — no data phase ran.
    ChainDead,
}

/// Per-direction probe statistics surfaced to the CLI. Computed at the
/// originator from observations on its own end of the probe
/// connection; no per-hop accounting is needed because the data phase
/// rides the rule's existing L4 forwarding code.
///
/// **Latency lives on [`ProbeResults`], not here.** A single
/// originator-only viewpoint can't separate c→s from s→c latency
/// without out-of-band time synchronisation, and pretending to do so
/// in two parallel fields produced misleading output. The round-trip
/// number on `ProbeResults` is the only honestly measurable quantity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectionStats {
    /// Total bytes (TCP) or datagrams (UDP) emitted by this side
    /// during the probe.
    pub sent: u64,
    /// Total bytes / datagrams received back from the echo. For TCP
    /// `received` is bounded by `min(sent, bytes_read)` so a chain
    /// that fails mid-probe shows a truthful gap; for UDP it reflects
    /// per-flow loss measured at the originator.
    pub received: u64,
    /// Sustained throughput in bits per second.
    pub throughput_bps: u64,
}

/// Aggregate probe results returned alongside [`CanaryStatus::Ok`]
/// or [`CanaryStatus::Degraded`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeResults {
    /// Client → server direction: throughput + bytes/datagrams sent
    /// and (best-effort) received at the echo terminus.
    pub c_to_s: DirectionStats,
    /// Server → client direction: throughput + bytes/datagrams echoed
    /// from the terminal and received at the originator.
    pub s_to_c: DirectionStats,
    /// Round-trip latency p50 in microseconds, measured at the
    /// originator as `recv_time - send_time` for echoed chunks /
    /// datagrams. This is the only honestly per-end-only-observable
    /// latency value.
    pub round_trip_p50_micros: u64,
    /// Round-trip latency p99 in microseconds. See `round_trip_p50_micros`.
    pub round_trip_p99_micros: u64,
    /// Actual wall-clock probe duration in microseconds. Set by the
    /// daemon to the elapsed time spent in the probe send/recv loop;
    /// renderers use this when reporting "probe: duration X ms".
    pub duration_micros: u64,
    /// Connection-establishment RTT in microseconds, TCP only. `None`
    /// for UDP and for chains that didn't get past the arm phase.
    pub connection_rtt_micros: Option<u64>,
}

/// Suggested near-miss when `chain canary` hits [`CanaryStatus::NoSuchRule`].
/// The CLI walks these and prints a "closest matches" block before
/// exiting non-zero.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloseMatch {
    /// Listener address (bind IP + port) the suggested rule binds.
    pub listen: SocketAddr,
    /// Protocol of the suggested rule.
    pub protocol: crate::rule::Protocol,
    /// Human-readable rule name as declared in the terminal's
    /// `conf.d/*.toml` (and, for derived rules on relays, copied
    /// through verbatim).
    pub rule_name: String,
}

/// Successful response to [`Request::ChainCanary`]. The CLI dispatches
/// on `status` to pick between the four output shapes (OK / DEGRADED /
/// NO_SUCH_RULE / CHAIN_DEAD).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainCanaryResponse {
    /// Primary outcome word; drives exit code and renderer.
    pub status: CanaryStatus,
    /// Hop-by-hop chain assembly from the arm-phase recursion.
    /// Includes the local hop at index 0. For [`CanaryStatus::ChainDead`]
    /// this is the truncated chain up to the last responding hop.
    pub chain: Vec<crate::canary::CanaryHop>,
    /// Per-direction probe statistics. `None` for
    /// [`CanaryStatus::NoSuchRule`] and [`CanaryStatus::ChainDead`] —
    /// the data phase never ran.
    pub probe_results: Option<ProbeResults>,
    /// Mirrors [`crate::canary::CanaryReply::partial`].
    #[serde(default)]
    pub partial: bool,
    /// Close-matches suggested when `status == NoSuchRule`. Empty for
    /// every other status.
    #[serde(default)]
    pub close_matches: Vec<CloseMatch>,
    /// Resolved rule name as declared on the local node, when a rule
    /// was matched. `None` for [`CanaryStatus::NoSuchRule`]; populated
    /// in every other case for renderer convenience.
    #[serde(default)]
    pub rule_name: Option<String>,
}

/// Stable error-code strings used in `Response::Error.code`. Kept in one place
/// so tests on both sides can assert against them without typos.
pub mod error_codes {
    pub const NO_SUCH_FINGERPRINT: &str = "no_such_fingerprint";
    /// The fingerprint prefix supplied to
    /// [`super::Request::DownstreamApprove`] matched more than one
    /// staged candidate, or was shorter than the minimum prefix length.
    /// The error `message` lists the colliding full fingerprints (or
    /// the required minimum length) so the operator can re-run with a
    /// longer / more specific prefix.
    pub const AMBIGUOUS_FINGERPRINT: &str = "ambiguous_fingerprint";
    pub const CONFIG_WRITE_FAILED: &str = "config_write_failed";
    pub const RELOAD_FAILED: &str = "reload_failed";
    pub const DOWNSTREAM_ALREADY_ENROLLED: &str = "downstream_already_enrolled";
    pub const INVALID_REQUEST: &str = "invalid_request";
    pub const INTERNAL_ERROR: &str = "internal_error";
    /// The daemon is running in `mode = "terminal"`, which has no peer
    /// identity. Peer-related commands (`peer show`, `peer pending`,
    /// `peer approve`) are not meaningful and return this code.
    pub const NOT_SUPPORTED_IN_TERMINAL_MODE: &str = "not_supported_in_terminal_mode";
    /// The daemon is running in `mode = "relay"`. The requested
    /// operation is meaningful only on terminal-mode daemons; relays
    /// have their rule sets derived from downstream predicate pushes
    /// and would immediately overwrite anything applied manually.
    pub const NOT_SUPPORTED_IN_RELAY_MODE: &str = "not_supported_in_relay_mode";
    /// The candidate rule set sent with [`super::Request::ChainApply`]
    /// failed validation: a duplicate name, a duplicate listen/protocol
    /// pair, or a per-rule shape error. The error `message` field
    /// carries the human-readable detail emitted by
    /// [`crate::rule::RuleSet::from_rules`].
    pub const RULES_INVALID: &str = "rules_invalid";
    /// The candidate rule set projects to a predicate set larger than
    /// [`crate::predicate::PREDICATE_SET_MAX_WIRE_BYTES`], so the
    /// publisher would silently drop the push. `chain apply` rejects
    /// synchronously so the operator can shrink the set.
    pub const PREDICATE_SET_OVERSIZE: &str = "predicate_set_oversize";
    /// The supervisor task is no longer running (shutdown or panic) and
    /// cannot accept the candidate rule set. The daemon is likely on
    /// its way down; the operator should restart and try again.
    pub const APPLY_FAILED: &str = "apply_failed";
    /// `local acme renew <host>` was called for a host that the
    /// daemon's `AcmeManager` doesn't know about (no `cert = "acme"`
    /// route declares it, or `[acme]` itself is unconfigured).
    pub const ACME_UNKNOWN_HOST: &str = "acme_unknown_host";
    /// `local acme renew <host>` ran issuance but it failed before
    /// the daemon could write a new cert to disk. The error
    /// `message` field carries the detail.
    pub const ACME_RENEW_FAILED: &str = "acme_renew_failed";
    /// The daemon has no `[acme]` section configured but the operator
    /// asked for ACME-managed state via `local acme list/renew`.
    pub const ACME_NOT_CONFIGURED: &str = "acme_not_configured";
    /// `chain canary --port N --proto X` was called but no rule on
    /// this node binds `(port, proto)`. The accompanying response
    /// carries [`super::ChainCanaryResponse::close_matches`] for
    /// renderer-side suggestion. Not surfaced as an `Error` — the
    /// daemon returns a successful [`super::Response::ChainCanary`]
    /// with `status = [super::CanaryStatus::NoSuchRule]`.
    pub const NO_SUCH_RULE: &str = "no_such_rule";
}

/// Default UDS path the server binds and the CLI connects to.
pub const DEFAULT_SOCKET_PATH: &str = "/run/yggdrasil/control.sock";

/// Read timeout the CLI applies before giving up on a slow server.
pub const DEFAULT_CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_through_json() {
        let cases = [
            Request::Status,
            Request::RulesList,
            Request::RulesReload,
            Request::DownstreamShow,
            Request::DownstreamPending,
            Request::DownstreamApprove {
                fingerprint: "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            },
            Request::ChainSummary { timeout_ms: None },
            Request::ChainSummary {
                timeout_ms: Some(2500),
            },
        ];
        for r in cases {
            let s = serde_json::to_string(&r).unwrap();
            let back: Request = serde_json::from_str(&s).unwrap();
            assert_eq!(r, back);
        }
    }

    #[test]
    fn response_round_trips_through_json() {
        let resp = Response::Status(StatusResponse {
            version: "0.1.0".into(),
            mode: Mode::Relay,
            downstream_ip: Some("192.0.2.1".parse().unwrap()),
            last_heartbeat_age_ms: Some(123),
            rule_count: 3,
            uptime_secs: 60,
            downstream_enrolled: true,
            default_cert_path: None,
            default_cert_loaded_age_secs: None,
            ephemeral_cert_count: 0,
            nat: None,
            lan_cidrs: vec![],
            lan_cidrs_source: String::new(),
            certless_route_count: 0,
        });
        let s = serde_json::to_string(&resp).unwrap();
        let back: Response = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn mode_serialises_as_lowercase() {
        assert_eq!(
            serde_json::to_string(&Mode::Gateway).unwrap(),
            "\"gateway\""
        );
        assert_eq!(serde_json::to_string(&Mode::Relay).unwrap(), "\"relay\"");
        assert_eq!(
            serde_json::to_string(&Mode::Terminal).unwrap(),
            "\"terminal\""
        );
        let back: Mode = serde_json::from_str("\"terminal\"").unwrap();
        assert_eq!(back, Mode::Terminal);
        let back: Mode = serde_json::from_str("\"gateway\"").unwrap();
        assert_eq!(back, Mode::Gateway);
    }

    #[test]
    fn status_response_mode_defaults_to_relay_when_field_absent() {
        // Older yggdrasilctl + older daemon: no `mode` field on the wire.
        // The newer client parses successfully and sees `Mode::Relay`.
        let s = serde_json::json!({
            "kind": "status",
            "version": "0.1.0",
            "downstream_ip": null,
            "last_heartbeat_age_ms": null,
            "rule_count": 0,
            "uptime_secs": 0,
            "downstream_enrolled": false,
        })
        .to_string();
        let parsed: Response = serde_json::from_str(&s).unwrap();
        match parsed {
            Response::Status(st) => assert_eq!(st.mode, Mode::Relay),
            other => panic!("unexpected response variant: {other:?}"),
        }
    }

    #[test]
    fn terminal_mode_status_round_trip() {
        let resp = Response::Status(StatusResponse {
            version: "0.1.0".into(),
            mode: Mode::Terminal,
            downstream_ip: None,
            last_heartbeat_age_ms: None,
            rule_count: 2,
            uptime_secs: 30,
            downstream_enrolled: false,
            default_cert_path: None,
            default_cert_loaded_age_secs: None,
            ephemeral_cert_count: 0,
            nat: None,
            lan_cidrs: vec![],
            lan_cidrs_source: String::new(),
            certless_route_count: 0,
        });
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"mode\":\"terminal\""), "got: {s}");
        let back: Response = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn status_response_nat_field_round_trip() {
        let resp = Response::Status(StatusResponse {
            version: "0.1.0".into(),
            mode: Mode::Terminal,
            downstream_ip: None,
            last_heartbeat_age_ms: None,
            rule_count: 1,
            uptime_secs: 12,
            downstream_enrolled: false,
            default_cert_path: None,
            default_cert_loaded_age_secs: None,
            ephemeral_cert_count: 0,
            nat: Some(NatStatus {
                mode: "auto".into(),
                state: "active".into(),
                gateway: Some("192.168.1.1".parse().unwrap()),
                external_ip: Some("203.0.113.7".parse().unwrap()),
                protocol: Some("pcp".into()),
                active_mapping_count: 2,
                last_error: None,
                mappings: vec![
                    NatMappingEntry {
                        origin: "rule:ssh".into(),
                        protocol: "tcp".into(),
                        internal_port: 22,
                        external_port: 22,
                        assigned_lifetime_secs: 7200,
                        renew_in_secs: 3600,
                    },
                    NatMappingEntry {
                        origin: "accept".into(),
                        protocol: "udp".into(),
                        internal_port: 51820,
                        external_port: 51820,
                        assigned_lifetime_secs: 7200,
                        renew_in_secs: 3590,
                    },
                ],
            }),
            lan_cidrs: vec![],
            lan_cidrs_source: String::new(),
            certless_route_count: 0,
        });
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"nat\""), "nat field should be present: {s}");
        let back: Response = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn status_response_nat_none_is_omitted_from_json() {
        // Backwards-compat invariant: when nat is None, the field
        // must not appear in the serialised form. Older yggdrasilctl
        // parsing a daemon with nat=None should see exactly the
        // pre-NAT shape.
        let resp = Response::Status(StatusResponse {
            version: "0.1.0".into(),
            mode: Mode::Relay,
            downstream_ip: None,
            last_heartbeat_age_ms: None,
            rule_count: 0,
            uptime_secs: 0,
            downstream_enrolled: false,
            default_cert_path: None,
            default_cert_loaded_age_secs: None,
            ephemeral_cert_count: 0,
            nat: None,
            lan_cidrs: vec![],
            lan_cidrs_source: String::new(),
            certless_route_count: 0,
        });
        let s = serde_json::to_string(&resp).unwrap();
        assert!(!s.contains("\"nat\""), "nat must be omitted when None: {s}");
    }

    #[test]
    fn status_response_parses_legacy_payload_without_nat() {
        // Forwards-compat invariant: a newer yggdrasilctl parsing an
        // older daemon's status payload (no `nat` field) must succeed
        // and see `nat = None`.
        let s = serde_json::json!({
            "kind": "status",
            "version": "0.1.0",
            "mode": "terminal",
            "downstream_ip": null,
            "last_heartbeat_age_ms": null,
            "rule_count": 0,
            "uptime_secs": 0,
            "downstream_enrolled": false,
            "default_cert_path": null,
            "default_cert_loaded_age_secs": null,
            "ephemeral_cert_count": 0,
        })
        .to_string();
        let parsed: Response = serde_json::from_str(&s).unwrap();
        match parsed {
            Response::Status(st) => assert!(st.nat.is_none()),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn error_response_round_trip() {
        let resp = Response::Error {
            code: error_codes::NO_SUCH_FINGERPRINT.to_string(),
            message: "fingerprint abc not in pending set".to_string(),
        };
        let s = serde_json::to_string(&resp).unwrap();
        let back: Response = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn unknown_kind_is_a_decode_error() {
        let s = r#"{"kind":"definitely_not_real"}"#;
        let r: Result<Request, _> = serde_json::from_str(s);
        assert!(r.is_err(), "expected serde to reject unknown variant");
    }

    #[test]
    fn chain_summary_request_serialises() {
        let r = Request::ChainSummary {
            timeout_ms: Some(1000),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"kind\":\"chain_summary\""), "got: {s}");
        assert!(s.contains("\"timeout_ms\":1000"), "got: {s}");
        let back: Request = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn chain_summary_response_round_trip() {
        let view = DerivedRulesResponse {
            predicates: vec![],
            derived_rules: vec![],
            chain: ChainIdentity {
                local: PubKey::x25519([0xAA; 32]),
                upstream: None,
                downstream: None,
                predicate_origin: None,
                predicate_version: None,
                last_apply_unix: None,
            },
        };
        let resp = Response::ChainSummary(ChainSummaryResponse {
            hops: vec![ChainHop {
                hop_index: 0,
                mode: Mode::Terminal,
                uptime_secs: 42,
                name: None,
                view,
                query_rtt_ms: None,
            }],
            partial: false,
        });
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"kind\":\"chain_summary\""), "got: {s}");
        assert!(s.contains("\"hop_index\":0"), "got: {s}");
        assert!(s.contains("\"mode\":\"terminal\""), "got: {s}");
        let back: Response = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn chain_apply_request_round_trip() {
        use crate::rule::{Protocol, Rule};
        let r = Request::ChainApply {
            rules: vec![Rule {
                name: "echo-tcp".into(),
                listen: "127.0.0.1:9100".parse().unwrap(),
                protocol: Protocol::Tcp,
                target: Some("10.0.0.5:9000".to_string()),
                target_port: None,
                idle_timeout: None,
                proxy_protocol: None,
            }],
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"kind\":\"chain_apply\""), "got: {s}");
        assert!(s.contains("\"echo-tcp\""), "got: {s}");
        let back: Request = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn chain_applied_response_round_trip() {
        let resp = Response::ChainApplied(ChainAppliedResponse {
            applied_rule_count: 3,
            predicate_count: 2,
            skipped_https: vec!["api-l7".into()],
        });
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"kind\":\"chain_applied\""), "got: {s}");
        let back: Response = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn chain_apply_error_codes_are_stable_strings() {
        // Pin the wire-stable strings so daemon + CLI never drift.
        assert_eq!(
            error_codes::NOT_SUPPORTED_IN_RELAY_MODE,
            "not_supported_in_relay_mode"
        );
        assert_eq!(error_codes::RULES_INVALID, "rules_invalid");
        assert_eq!(
            error_codes::PREDICATE_SET_OVERSIZE,
            "predicate_set_oversize"
        );
        assert_eq!(error_codes::APPLY_FAILED, "apply_failed");
    }
}
