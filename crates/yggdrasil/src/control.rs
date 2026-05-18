//! UDS control surface for `yggdrasilctl`.
//!
//! Wire format: one newline-delimited JSON object per request, one per
//! response. Backed by [`yggdrasil_proto::control`]. The listener binds the
//! socket with mode `0o660`; group ownership is left to the operator (we don't
//! ship a packaging story yet).
//!
//! ## Why a worker task per connection?
//!
//! Each connection is short-lived and emits at most a handful of JSON
//! objects. There's no broadcast or fan-out, so a per-connection task with
//! buffered IO is the simplest correct design and trivially cancellable from
//! the parent token.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use yggdrasil_proto::auth::public_key_fingerprint;
use yggdrasil_proto::branch::Protocol;
use yggdrasil_proto::control::{
    error_codes, BranchInfo, BranchesResponse, PeerResponse, PendingResponse, Request, Response,
    StatusResponse,
};

use crate::branches::ReloadTrigger;
use crate::heartbeat::PeerState;
use crate::pending_peers::PendingPeerStore;
use crate::proxy::supervisor::ProxySupervisor;

/// Handle to a running control server.
pub struct ControlServer {
    cancel: CancellationToken,
    main_handle: JoinHandle<()>,
    socket_path: PathBuf,
}

/// Shared state every connection task sees.
struct ControlState {
    started_at: Instant,
    peer_state: Arc<PeerState>,
    snapshot_rx: tokio::sync::watch::Receiver<Vec<crate::proxy::supervisor::ProxySnapshot>>,
    reload_trigger: ReloadTrigger,
    pending_store: Arc<PendingPeerStore>,
    /// Path to the main server config; the approve flow rewrites
    /// `[peer].public_key_hex` atomically (tmp + rename).
    config_path: PathBuf,
}

impl ControlServer {
    /// Bind the UDS at `socket_path`, set mode `0o660`, and start accepting
    /// connections.
    ///
    /// If the path already exists it is removed first; that matches the
    /// systemd convention of "the daemon owns the socket file" and avoids
    /// the common "previous run crashed, EADDRINUSE" footgun.
    pub async fn bind(
        socket_path: impl Into<PathBuf>,
        peer_state: Arc<PeerState>,
        supervisor: &ProxySupervisor,
        pending_store: Arc<PendingPeerStore>,
        config_path: PathBuf,
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
            peer_state,
            snapshot_rx: {
                // The supervisor exposes only a `snapshot()` snapshot getter.
                // We grab its underlying receiver via a small helper we add
                // alongside.
                supervisor.snapshot_receiver()
            },
            reload_trigger: supervisor.reload_trigger(),
            pending_store,
            config_path,
        });

        let main_cancel = cancel.clone();
        let main_handle = tokio::spawn(accept_loop(listener, state, main_cancel));

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

async fn accept_loop(
    listener: UnixListener,
    state: Arc<ControlState>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                tracing::info!("control server received shutdown");
                return;
            }
            res = listener.accept() => {
                match res {
                    Ok((stream, _addr)) => {
                        let state = Arc::clone(&state);
                        let cancel = cancel.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, state, cancel).await {
                                tracing::debug!(error = %e, "control connection ended with error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "control accept failed");
                    }
                }
            }
        }
    }
}

async fn handle_connection(
    stream: UnixStream,
    state: Arc<ControlState>,
    cancel: CancellationToken,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            line = lines.next_line() => {
                let line = match line.context("read control request")? {
                    Some(s) => s,
                    None => return Ok(()), // peer closed
                };
                let response = handle_request_text(&line, &state);
                let mut buf = serde_json::to_vec(&response).context("encode response")?;
                buf.push(b'\n');
                writer.write_all(&buf).await.context("write response")?;
            }
        }
    }
}

fn handle_request_text(line: &str, state: &ControlState) -> Response {
    let req: Request = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            return Response::Error {
                code: error_codes::INVALID_REQUEST.into(),
                message: format!("could not parse request as JSON: {e}"),
            }
        }
    };
    dispatch(req, state)
}

fn dispatch(req: Request, state: &ControlState) -> Response {
    match req {
        Request::Status => {
            let last_heartbeat_age_ms = state
                .peer_state
                .last_heartbeat_ms()
                .and_then(|ts| {
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .ok()
                        .map(|now| now.as_millis() as u64)
                        .map(|now| now.saturating_sub(ts))
                });
            let branch_count = state.snapshot_rx.borrow().len();
            Response::Status(StatusResponse {
                version: env!("CARGO_PKG_VERSION").to_string(),
                peer_ip: state.peer_state.current_ip(),
                last_heartbeat_age_ms,
                branch_count,
                uptime_secs: state.started_at.elapsed().as_secs(),
                peer_enrolled: state.peer_state.is_peer_enrolled(),
            })
        }
        Request::BranchesList => {
            let snapshot = state.snapshot_rx.borrow().clone();
            let branches = snapshot
                .into_iter()
                .map(|s| BranchInfo {
                    name: s.name,
                    protocol: match s.protocol {
                        Protocol::Tcp => "tcp".to_string(),
                        Protocol::Udp => "udp".to_string(),
                    },
                    listen: s.listen.to_string(),
                    upstream_port: s.upstream_port,
                })
                .collect();
            Response::Branches(BranchesResponse { branches })
        }
        Request::BranchesReload => {
            state.reload_trigger.force_reload();
            // Synchronous count of what's currently loaded; the reload itself
            // is asynchronous so we don't try to report the new count here.
            let reloaded_rule_count = state.snapshot_rx.borrow().len();
            Response::BranchesReloaded {
                reloaded_rule_count,
            }
        }
        Request::PeerShow => {
            let enrolled = state.peer_state.is_peer_enrolled();
            let pubkey = state.peer_state.peer_static_key();
            let public_key_hex = if enrolled { hex::encode(pubkey) } else { String::new() };
            let fingerprint = if enrolled {
                public_key_fingerprint(&pubkey)
            } else {
                String::new()
            };
            Response::Peer(PeerResponse {
                enrolled,
                public_key_hex,
                fingerprint,
            })
        }
        Request::PeerPending => {
            Response::PeerPending(PendingResponse {
                candidates: state.pending_store.list(),
            })
        }
        Request::PeerApprove { fingerprint } => approve_peer(state, &fingerprint),
    }
}

fn approve_peer(state: &ControlState, fingerprint: &str) -> Response {
    let key = match state.pending_store.approve(fingerprint) {
        Ok(Some(k)) => k,
        Ok(None) => {
            return Response::Error {
                code: error_codes::NO_SUCH_FINGERPRINT.into(),
                message: format!("fingerprint {fingerprint:?} is not in the pending queue"),
            };
        }
        Err(e) => {
            return Response::Error {
                code: error_codes::INTERNAL_ERROR.into(),
                message: format!("failed to pop staged candidate: {e:#}"),
            };
        }
    };
    let key_hex = hex::encode(key);
    if let Err(e) = update_server_peer_config(&state.config_path, &key_hex) {
        return Response::Error {
            code: error_codes::CONFIG_WRITE_FAILED.into(),
            message: format!(
                "approve: failed to write {} ({e:#}). \
                 Candidate has been removed from the pending queue; \
                 set `peer.public_key_hex = \"{key_hex}\"` manually.",
                state.config_path.display()
            ),
        };
    }
    state.peer_state.set_peer_static_key(key);
    tracing::info!(
        fingerprint = fingerprint,
        "peer approved via control surface; key is now live"
    );
    Response::PeerApproved {
        fingerprint: fingerprint.to_string(),
    }
}

/// Atomic rewrite of `[peer].public_key_hex` in `config_path`. Round-trips
/// the file through `toml::Value` so other keys are preserved (formatting
/// and comments are lost — acceptable trade-off documented in commands.rs).
fn update_server_peer_config(config_path: &Path, peer_pubkey_hex: &str) -> Result<()> {
    let text = std::fs::read_to_string(config_path)
        .with_context(|| format!("read {}", config_path.display()))?;
    let mut doc: toml::Value = text.parse()
        .with_context(|| format!("parse {}", config_path.display()))?;
    let table = doc
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("{} is not a TOML table", config_path.display()))?;
    let peer_entry = table
        .entry("peer".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
    let peer_table = peer_entry
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("`peer` in {} is not a table", config_path.display()))?;
    peer_table.insert(
        "public_key_hex".to_string(),
        toml::Value::String(peer_pubkey_hex.to_string()),
    );
    let serialised = toml::to_string_pretty(&doc).context("serialise updated config")?;
    let tmp = config_path.with_extension("toml.tmp");
    std::fs::write(&tmp, serialised).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, config_path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), config_path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heartbeat::PeerState;
    use crate::proxy::supervisor::ProxySupervisor;
    use std::net::IpAddr;
    use std::time::Duration;

    async fn make_supervisor(dir: &Path) -> (ProxySupervisor, Arc<PeerState>, CancellationToken) {
        make_supervisor_with_enrolled(dir, false).await
    }

    /// `enrolled = true` uses a random non-zero key so
    /// `peer_state.is_peer_enrolled()` returns true.
    async fn make_supervisor_with_enrolled(
        dir: &Path,
        enrolled: bool,
    ) -> (ProxySupervisor, Arc<PeerState>, CancellationToken) {
        std::fs::create_dir_all(dir).unwrap();
        let key = if enrolled { [7u8; 32] } else { [0u8; 32] };
        let peer_state = PeerState::new(key);
        let shutdown = CancellationToken::new();
        let supervisor = ProxySupervisor::spawn(
            dir,
            Duration::from_millis(50),
            peer_state.clone(),
            shutdown.clone(),
        )
        .await
        .unwrap();
        (supervisor, peer_state, shutdown)
    }

    /// Build the supporting state needed by `ControlServer::bind`: a pending
    /// store rooted in `dir/state` and a writable placeholder config path
    /// rooted in `dir/yggdrasil.toml`.
    fn aux_state(dir: &Path) -> (Arc<PendingPeerStore>, PathBuf) {
        let state_dir = dir.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let store = Arc::new(PendingPeerStore::load(&state_dir).unwrap());
        let config_path = dir.join("yggdrasil.toml");
        // Minimal valid-looking config so `update_server_peer_config` has
        // something to round-trip if a test ends up approving.
        std::fs::write(
            &config_path,
            "[server]\nheartbeat_listen = \"127.0.0.1:0\"\n[peer]\npublic_key_hex = \"\"\n",
        )
        .unwrap();
        (store, config_path)
    }

    async fn send_request(socket_path: &Path, req: &Request) -> Response {
        let mut stream = UnixStream::connect(socket_path).await.unwrap();
        let mut buf = serde_json::to_vec(req).unwrap();
        buf.push(b'\n');
        stream.write_all(&buf).await.unwrap();
        let (reader, _w) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        let line = lines.next_line().await.unwrap().unwrap();
        serde_json::from_str(&line).unwrap()
    }

    #[tokio::test]
    async fn status_reports_initial_state() {
        let tmp = tempfile::tempdir().unwrap();
        let branches = tmp.path().join("branches");
        let (supervisor, peer_state, shutdown) = make_supervisor(&branches).await;
        let socket = tmp.path().join("control.sock");
        let (pending, cfg) = aux_state(tmp.path());

        let server = ControlServer::bind(
            socket.clone(),
            peer_state.clone(),
            &supervisor,
            pending,
            cfg,
            shutdown.clone(),
        )
        .await
        .unwrap();

        let resp = send_request(&socket, &Request::Status).await;
        match resp {
            Response::Status(s) => {
                assert_eq!(s.peer_ip, None);
                assert_eq!(s.branch_count, 0);
                assert!(!s.peer_enrolled);
            }
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    #[tokio::test]
    async fn status_reflects_heartbeat() {
        let tmp = tempfile::tempdir().unwrap();
        let branches = tmp.path().join("branches");
        let (supervisor, peer_state, shutdown) =
            make_supervisor_with_enrolled(&branches, true).await;
        let socket = tmp.path().join("control.sock");
        let (pending, cfg) = aux_state(tmp.path());
        let server = ControlServer::bind(
            socket.clone(),
            peer_state.clone(),
            &supervisor,
            pending,
            cfg,
            shutdown.clone(),
        )
        .await
        .unwrap();

        let ip: IpAddr = "192.0.2.5".parse().unwrap();
        peer_state.record_heartbeat(std::net::SocketAddr::new(ip, 7117));

        let resp = send_request(&socket, &Request::Status).await;
        match resp {
            Response::Status(s) => {
                assert_eq!(s.peer_ip, Some(ip));
                assert!(s.peer_enrolled);
                assert!(s.last_heartbeat_age_ms.is_some());
            }
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    #[tokio::test]
    async fn peer_show_returns_pubkey_when_enrolled() {
        let tmp = tempfile::tempdir().unwrap();
        let branches = tmp.path().join("branches");
        let (supervisor, peer_state, shutdown) =
            make_supervisor_with_enrolled(&branches, true).await;
        let socket = tmp.path().join("control.sock");
        let (pending, cfg) = aux_state(tmp.path());
        let server = ControlServer::bind(
            socket.clone(),
            peer_state.clone(),
            &supervisor,
            pending,
            cfg,
            shutdown.clone(),
        )
        .await
        .unwrap();

        let resp = send_request(&socket, &Request::PeerShow).await;
        match resp {
            Response::Peer(p) => {
                assert!(p.enrolled);
                assert_eq!(p.public_key_hex.len(), 64);
                assert_eq!(p.fingerprint.len(), 32);
            }
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    #[tokio::test]
    async fn peer_show_returns_empty_when_not_enrolled() {
        let tmp = tempfile::tempdir().unwrap();
        let branches = tmp.path().join("branches");
        let (supervisor, peer_state, shutdown) = make_supervisor(&branches).await;
        let socket = tmp.path().join("control.sock");
        let (pending, cfg) = aux_state(tmp.path());
        let server = ControlServer::bind(
            socket.clone(),
            peer_state.clone(),
            &supervisor,
            pending,
            cfg,
            shutdown.clone(),
        )
        .await
        .unwrap();

        let resp = send_request(&socket, &Request::PeerShow).await;
        match resp {
            Response::Peer(p) => {
                assert!(!p.enrolled);
                assert!(p.public_key_hex.is_empty());
                assert!(p.fingerprint.is_empty());
            }
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    #[tokio::test]
    async fn branches_reload_returns_current_count() {
        let tmp = tempfile::tempdir().unwrap();
        let branches = tmp.path().join("branches");
        let (supervisor, peer_state, shutdown) = make_supervisor(&branches).await;
        let socket = tmp.path().join("control.sock");
        let (pending, cfg) = aux_state(tmp.path());
        let server = ControlServer::bind(
            socket.clone(),
            peer_state.clone(),
            &supervisor,
            pending,
            cfg,
            shutdown.clone(),
        )
        .await
        .unwrap();

        let resp = send_request(&socket, &Request::BranchesReload).await;
        match resp {
            Response::BranchesReloaded {
                reloaded_rule_count,
            } => {
                assert_eq!(reloaded_rule_count, 0);
            }
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    #[tokio::test]
    async fn invalid_json_returns_error_response() {
        let tmp = tempfile::tempdir().unwrap();
        let branches = tmp.path().join("branches");
        let (supervisor, peer_state, shutdown) = make_supervisor(&branches).await;
        let socket = tmp.path().join("control.sock");
        let (pending, cfg) = aux_state(tmp.path());
        let server = ControlServer::bind(
            socket.clone(),
            peer_state.clone(),
            &supervisor,
            pending,
            cfg,
            shutdown.clone(),
        )
        .await
        .unwrap();

        let mut stream = UnixStream::connect(&socket).await.unwrap();
        stream.write_all(b"not json at all\n").await.unwrap();
        let (reader, _w) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        let line = lines.next_line().await.unwrap().unwrap();
        let resp: Response = serde_json::from_str(&line).unwrap();
        match resp {
            Response::Error { code, .. } => assert_eq!(code, error_codes::INVALID_REQUEST),
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    #[tokio::test]
    async fn peer_pending_lists_staged_candidates() {
        let tmp = tempfile::tempdir().unwrap();
        let branches = tmp.path().join("branches");
        let (supervisor, peer_state, shutdown) = make_supervisor(&branches).await;
        let socket = tmp.path().join("control.sock");
        let (pending, cfg) = aux_state(tmp.path());
        pending.record_candidate([0xAAu8; 32]).unwrap();
        pending.record_candidate([0xBBu8; 32]).unwrap();
        let server = ControlServer::bind(
            socket.clone(),
            peer_state.clone(),
            &supervisor,
            pending,
            cfg,
            shutdown.clone(),
        )
        .await
        .unwrap();

        let resp = send_request(&socket, &Request::PeerPending).await;
        match resp {
            Response::PeerPending(p) => {
                assert_eq!(p.candidates.len(), 2);
            }
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    #[tokio::test]
    async fn peer_approve_writes_config_and_swaps_live_key() {
        let tmp = tempfile::tempdir().unwrap();
        let branches = tmp.path().join("branches");
        let (supervisor, peer_state, shutdown) = make_supervisor(&branches).await;
        let socket = tmp.path().join("control.sock");
        let (pending, cfg) = aux_state(tmp.path());

        let candidate = [0x42u8; 32];
        pending.record_candidate(candidate).unwrap();
        let fp = yggdrasil_proto::auth::public_key_fingerprint(&candidate);

        assert!(!peer_state.is_peer_enrolled());

        let server = ControlServer::bind(
            socket.clone(),
            peer_state.clone(),
            &supervisor,
            pending,
            cfg.clone(),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let resp = send_request(
            &socket,
            &Request::PeerApprove {
                fingerprint: fp.clone(),
            },
        )
        .await;
        match resp {
            Response::PeerApproved { fingerprint } => assert_eq!(fingerprint, fp),
            other => panic!("unexpected response: {other:?}"),
        }
        // Live key was swapped in.
        assert!(peer_state.is_peer_enrolled());
        assert_eq!(peer_state.peer_static_key(), candidate);
        // Config file was rewritten with the approved key.
        let rewritten = std::fs::read_to_string(&cfg).unwrap();
        assert!(
            rewritten.contains(&hex::encode(candidate)),
            "config not rewritten: {rewritten}"
        );

        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }

    #[tokio::test]
    async fn peer_approve_unknown_fingerprint_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let branches = tmp.path().join("branches");
        let (supervisor, peer_state, shutdown) = make_supervisor(&branches).await;
        let socket = tmp.path().join("control.sock");
        let (pending, cfg) = aux_state(tmp.path());
        let server = ControlServer::bind(
            socket.clone(),
            peer_state.clone(),
            &supervisor,
            pending,
            cfg,
            shutdown.clone(),
        )
        .await
        .unwrap();

        let resp = send_request(
            &socket,
            &Request::PeerApprove {
                fingerprint: "not-a-real-fingerprint".to_string(),
            },
        )
        .await;
        match resp {
            Response::Error { code, .. } => {
                assert_eq!(code, error_codes::NO_SUCH_FINGERPRINT)
            }
            other => panic!("unexpected response: {other:?}"),
        }
        shutdown.cancel();
        server.stop().await;
        supervisor.stop().await;
    }
}
