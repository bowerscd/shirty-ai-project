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

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::predicate::Predicate;
use crate::pubkey::PubKey;
use crate::rule::Rule;

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
    /// Approve a staged candidate by its short fingerprint.
    DownstreamApprove {
        /// Short BLAKE2s-128 fingerprint (32 hex chars).
        fingerprint: String,
    },
    /// List TLS certificates currently loaded into the cert store, one
    /// entry per `(rule, route)`. Each entry includes the resolved
    /// hostname, where the cert came from, and parsed metadata.
    CertsList,
    /// Render the daemon's Prometheus metrics in text exposition format.
    /// The daemon dispatches the request to its in-process recorder; no
    /// HTTP listener is required. Backs `yggdrasilctl local metrics`.
    Metrics,
    /// Liveness/readiness probe served over the control socket. Backs
    /// `yggdrasilctl local health`.
    Health,
    /// Snapshot of this node's chain-applied predicates, derived rule
    /// set, and chain identity. Replaces the previous loopback-gated
    /// `GET /internal/derived-rules` HTTP endpoint. Backs both
    /// `yggdrasilctl local derived-rules` and the local-hop fetch in
    /// `yggdrasilctl chain diff`.
    DerivedRules,
    /// Open a chain tunnel from this node toward `target_pubkey`, which
    /// must terminate the tunnel at `dest` (a TCP `host:port`). This
    /// request **hijacks the UDS connection**: once the server responds
    /// with [`Response::ChainTunnelOpened`], no further newline-delimited
    /// JSON is exchanged on the socket. Both sides switch to bidirectional
    /// raw byte streaming, which the daemon bridges to
    /// [`tunnel::TunnelData`](crate::tunnel::TunnelData) envelopes on the
    /// chain control channel. Closing either half of the UDS triggers a
    /// [`tunnel::TunnelClose`](crate::tunnel::TunnelClose) emission and
    /// shutdown of the other half. There is no second JSON response.
    ///
    /// `target_pubkey` is the node where the tunnel terminates. Today the
    /// only supported topology is `target_pubkey == this node's upstream`;
    /// multi-hop forwarding is deferred.
    OpenChainTunnel {
        /// Pubkey of the node that should terminate the tunnel.
        target_pubkey: PubKey,
        /// Destination socket address on the terminating node.
        dest: SocketAddr,
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
}

/// All possible server → client messages.
///
/// Exactly one of these is emitted per request. The `Error` variant is used
/// for anything from "no such fingerprint" through "config file unwritable".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Status(StatusResponse),
    Rules(RulesResponse),
    RulesReloaded { reloaded_rule_count: usize },
    Downstream(DownstreamResponse),
    DownstreamPending(PendingResponse),
    DownstreamApproved {
        fingerprint: String,
    },
    Certs(CertsListResponse),
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
    /// Successful response to [`Request::OpenChainTunnel`]. The originator-
    /// chosen `stream_id` is echoed so the operator can correlate logs.
    /// After this object is sent, the daemon stops parsing newline-JSON on
    /// the UDS connection and begins streaming tunnel bytes in both
    /// directions; the client must do the same.
    ChainTunnelOpened {
        /// Stream id allocated by the daemon's initiator-side registry.
        stream_id: u32,
    },
    /// Generic failure. Always preserves the request kind for diagnostics.
    Error {
        /// e.g. "no_such_fingerprint", "config_write_failed", "unknown_request".
        code: String,
        message: String,
    },
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

/// Response body for [`Request::CertsList`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertsListResponse {
    pub certs: Vec<CertInfo>,
}

/// Response body for [`Request::Metrics`]. The `body` field is the
/// Prometheus text exposition format, ready to be written to stdout or
/// piped into a scraper.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetricsResponse {
    pub body: String,
}

/// Response body for [`Request::Health`]. Mirrors the previous
/// `/healthz` + `/readyz` HTTP endpoints: `ready` flips to `true` once
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

/// Metadata for a single (hostname, cert) pair loaded into the cert store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertInfo {
    /// The route's `hostname` (lowercased, no port, no trailing dot).
    pub hostname: String,
    /// Where the cert came from. One of: `"path"`, `"ephemeral"`,
    /// `"convention"`, `"default"`. Stable English string, safe to print.
    pub cert_source: String,
    /// Unix epoch milliseconds when the cert was loaded into the store.
    pub loaded_at_unix_ms: u64,
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
    /// Names of rules dropped during predicate projection because their
    /// protocol isn't representable as a predicate (currently HTTPS).
    /// Empty on nodes without an upstream because no projection is run.
    pub skipped_https: Vec<String>,
}

/// Stable error-code strings used in `Response::Error.code`. Kept in one place
/// so tests on both sides can assert against them without typos.
pub mod error_codes {
    pub const NO_SUCH_FINGERPRINT: &str = "no_such_fingerprint";
    pub const CONFIG_WRITE_FAILED: &str = "config_write_failed";
    pub const RELOAD_FAILED:       &str = "reload_failed";
    pub const DOWNSTREAM_ALREADY_ENROLLED: &str = "downstream_already_enrolled";
    pub const INVALID_REQUEST:     &str = "invalid_request";
    pub const INTERNAL_ERROR:      &str = "internal_error";
    /// The daemon is running in `mode = "terminal"`, which has no peer
    /// identity. Peer-related commands (`peer show`, `peer pending`,
    /// `peer approve`) are not meaningful and return this code.
    pub const NOT_SUPPORTED_IN_TERMINAL_MODE: &str = "not_supported_in_terminal_mode";
    /// The daemon has no chain upstream configured (no `[dial]`
    /// section in its config), so it has no way to forward tunnel control
    /// frames. `chain tunnel open` requests return this code.
    pub const NO_CHAIN_UPSTREAM: &str = "no_chain_upstream";
    /// The chain control channel rejected the tunnel-open envelope with a
    /// reject reason from [`crate::tunnel::tunnel_reject`]. The reason
    /// code is appended to the message text for the operator.
    pub const TUNNEL_OPEN_REJECTED: &str = "tunnel_open_rejected";
    /// The chain control channel failed to deliver the tunnel-open frame
    /// (transport failure, retransmit budget exhausted, or upstream client
    /// task gone). `chain tunnel open` returns this code; the operator can
    /// retry.
    pub const TUNNEL_OPEN_FAILED: &str = "tunnel_open_failed";
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
            Request::CertsList,
            Request::OpenChainTunnel {
                target_pubkey: PubKey::x25519([0x42; 32]),
                dest: "127.0.0.1:9100".parse().unwrap(),
            },
        ];
        for r in cases {
            let s = serde_json::to_string(&r).unwrap();
            let back: Request = serde_json::from_str(&s).unwrap();
            assert_eq!(r, back);
        }
    }

    #[test]
    fn open_chain_tunnel_request_uses_tagged_pubkey() {
        let r = Request::OpenChainTunnel {
            target_pubkey: PubKey::x25519([0x11; 32]),
            dest: "10.0.0.1:443".parse().unwrap(),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"kind\":\"open_chain_tunnel\""), "got: {s}");
        assert!(s.contains("\"x25519:"), "expected tagged pubkey form, got: {s}");
        assert!(s.contains("\"10.0.0.1:443\""), "expected dest in payload, got: {s}");
    }

    #[test]
    fn chain_tunnel_opened_response_round_trip() {
        let resp = Response::ChainTunnelOpened { stream_id: 0xC0DE_C0DE };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(
            s.contains("\"kind\":\"chain_tunnel_opened\""),
            "got: {s}"
        );
        let back: Response = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, back);
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
        });
        let s = serde_json::to_string(&resp).unwrap();
        let back: Response = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn mode_serialises_as_lowercase() {
        assert_eq!(serde_json::to_string(&Mode::Gateway).unwrap(), "\"gateway\"");
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
        });
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"mode\":\"terminal\""), "got: {s}");
        let back: Response = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, back);
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
    fn certs_response_round_trip() {
        let resp = Response::Certs(CertsListResponse {
            certs: vec![
                CertInfo {
                    hostname: "api.example.com".into(),
                    cert_source: "path".into(),
                    loaded_at_unix_ms: 1_700_000_000_000,
                },
                CertInfo {
                    hostname: "app.example.com".into(),
                    cert_source: "ephemeral".into(),
                    loaded_at_unix_ms: 1_700_000_001_000,
                },
            ],
        });
        let s = serde_json::to_string(&resp).unwrap();
        let back: Response = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, back);
        // kind is serialised at the top level for compatibility with the
        // existing dispatcher.
        assert!(s.contains("\"kind\":\"certs\""), "got: {s}");
    }

    #[test]
    fn chain_apply_request_round_trip() {
        use crate::rule::{Protocol, Rule};
        let r = Request::ChainApply {
            rules: vec![Rule {
                name: "echo-tcp".into(),
                listen: "127.0.0.1:9100".parse().unwrap(),
                protocol: Protocol::Tcp,
                target_addr: Some("10.0.0.5:9000".parse().unwrap()),
                target_port: None,
                target_host: None,
                idle_timeout: None,
                proxy_protocol: None,
                routes: None,
                cert_dir: None,
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
        assert_eq!(error_codes::NOT_SUPPORTED_IN_RELAY_MODE, "not_supported_in_relay_mode");
        assert_eq!(error_codes::RULES_INVALID, "rules_invalid");
        assert_eq!(error_codes::PREDICATE_SET_OVERSIZE, "predicate_set_oversize");
        assert_eq!(error_codes::APPLY_FAILED, "apply_failed");
    }
}
