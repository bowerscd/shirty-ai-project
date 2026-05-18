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

/// All possible client → server messages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Request {
    /// High-level summary.
    Status,
    /// List loaded branch rules with their listen sockets.
    BranchesList,
    /// Force a reload of the branches directory.
    BranchesReload,
    /// Currently enrolled peer pubkey + fingerprint.
    PeerShow,
    /// Staged (TOFU) peer candidates awaiting approval.
    PeerPending,
    /// Approve a staged candidate by its short fingerprint.
    PeerApprove {
        /// Short BLAKE2s-128 fingerprint (32 hex chars).
        fingerprint: String,
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
    Branches(BranchesResponse),
    BranchesReloaded { reloaded_rule_count: usize },
    Peer(PeerResponse),
    PeerPending(PendingResponse),
    PeerApproved {
        fingerprint: String,
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
    /// Currently known peer IP (`None` until first heartbeat).
    pub peer_ip: Option<IpAddr>,
    /// Milliseconds since the last accepted heartbeat (`None` if no heartbeats yet).
    pub last_heartbeat_age_ms: Option<u64>,
    /// Number of currently-loaded branches.
    pub branch_count: usize,
    /// Server uptime in seconds.
    pub uptime_secs: u64,
    /// Whether a peer has been enrolled (`peer.public_key_hex` non-empty in config).
    pub peer_enrolled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BranchesResponse {
    pub branches: Vec<BranchInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BranchInfo {
    pub name: String,
    /// `"tcp"` or `"udp"`.
    pub protocol: String,
    /// `host:port`.
    pub listen: String,
    /// Upstream port (on the residential side).
    pub upstream_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerResponse {
    /// Whether the server has a peer enrolled yet.
    pub enrolled: bool,
    /// Hex-encoded pubkey (empty if `!enrolled`).
    pub public_key_hex: String,
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

/// Stable error-code strings used in `Response::Error.code`. Kept in one place
/// so tests on both sides can assert against them without typos.
pub mod error_codes {
    pub const NO_SUCH_FINGERPRINT: &str = "no_such_fingerprint";
    pub const CONFIG_WRITE_FAILED: &str = "config_write_failed";
    pub const RELOAD_FAILED:       &str = "reload_failed";
    pub const PEER_ALREADY_ENROLLED: &str = "peer_already_enrolled";
    pub const INVALID_REQUEST:     &str = "invalid_request";
    pub const INTERNAL_ERROR:      &str = "internal_error";
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
            Request::BranchesList,
            Request::BranchesReload,
            Request::PeerShow,
            Request::PeerPending,
            Request::PeerApprove {
                fingerprint: "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
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
            peer_ip: Some("192.0.2.1".parse().unwrap()),
            last_heartbeat_age_ms: Some(123),
            branch_count: 3,
            uptime_secs: 60,
            peer_enrolled: true,
        });
        let s = serde_json::to_string(&resp).unwrap();
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
}
