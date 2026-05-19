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
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Runtime mode the daemon is operating in, surfaced in status responses.
///
/// `relay` is the cloud-side daemon with heartbeat + dynamic peer-IP
/// resolution; `terminal` is the home-side daemon with static
/// `upstream_addr` rules and no peer identity. Wire serialisation matches
/// the on-disk `[server] mode = "..."` and `--mode` CLI strings exactly.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Cloud-side daemon. Heartbeat + dynamic peer-IP resolution.
    #[default]
    Relay,
    /// Home-side daemon. Static `upstream_addr` rules. No peer identity.
    Terminal,
}

impl Mode {
    /// Stable English string for log/metric formatting.
    pub fn as_str(&self) -> &'static str {
        match self {
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
    /// Whether a downstream has been enrolled (`[chain.downstream]` present
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
    pub upstream: String,
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
        });
        let s = serde_json::to_string(&resp).unwrap();
        let back: Response = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn mode_serialises_as_lowercase() {
        assert_eq!(serde_json::to_string(&Mode::Relay).unwrap(), "\"relay\"");
        assert_eq!(
            serde_json::to_string(&Mode::Terminal).unwrap(),
            "\"terminal\""
        );
        let back: Mode = serde_json::from_str("\"terminal\"").unwrap();
        assert_eq!(back, Mode::Terminal);
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
}
