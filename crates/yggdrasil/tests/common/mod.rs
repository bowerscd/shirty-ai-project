//! Shared test helpers for `yggdrasil` integration tests.
//!
//! Cargo treats every `.rs` in `tests/` as its own crate; `tests/common/mod.rs`
//! is the conventional way to share code between them.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use ratatoskr::auth::{Initiator, Session, StaticKeyPair};
use ratatoskr::wire::{self, SessionId};

use yggdrasil::heartbeat::{HeartbeatServer, PeerState};
use yggdrasil::pending_peers::PendingPeerStore;
use yggdrasil::proxy::resolver::ResolverFactory;
use yggdrasil::proxy::supervisor::{CertConfig, ProxySupervisor};

/// Test-only `StaticKeyPair` clone via raw bytes.
///
/// `StaticKeyPair` intentionally does not implement `Clone` to discourage
/// passing the secret around at runtime. Test code is fine to do this.
pub fn clone_kp(k: &StaticKeyPair) -> StaticKeyPair {
    StaticKeyPair::from_raw(*k.secret_bytes(), *k.public_key())
}

/// Bind a UDP echo socket on loopback. Returns the socket and its address.
pub async fn echo_udp_socket() -> (UdpSocket, SocketAddr) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    (sock, addr)
}

/// Spawn a background task that echoes every received UDP datagram back to
/// its sender. The returned handle aborts the task on drop.
pub fn spawn_udp_echo(sock: UdpSocket) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], from).await;
        }
    })
}

/// Bind a TCP echo listener on loopback. Returns the listener and its address.
pub async fn echo_tcp_listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

/// Spawn a background task that accepts TCP connections and echoes bytes
/// back until the peer closes.
pub fn spawn_tcp_echo(listener: TcpListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (mut stream, _peer) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    if stream.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    })
}

/// Pick a free UDP port by binding to `:0` and reading the assigned port.
/// The socket is dropped before the function returns; there is a tiny race
/// window before the proxy re-binds the port, but loopback testing tolerates
/// it.
pub async fn pick_free_udp_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.local_addr().unwrap().port()
}

/// Same as `pick_free_udp_port` but for TCP.
pub async fn pick_free_tcp_port() -> u16 {
    let s = TcpListener::bind("127.0.0.1:0").await.unwrap();
    s.local_addr().unwrap().port()
}

/// Drive a full Noise_IK handshake against an already-running
/// `HeartbeatServer`. Returns the resulting transport session and the
/// connected UDP socket bound for further heartbeats.
pub async fn drive_handshake(
    server_pub: &[u8; 32],
    client: &StaticKeyPair,
    server_addr: SocketAddr,
) -> (Session, UdpSocket) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.connect(server_addr).await.unwrap();
    let sid = SessionId::random();
    let (init, hs1) = Initiator::start(client, server_pub, sid).unwrap();
    sock.send(&hs1).await.unwrap();
    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf))
        .await
        .expect("Handshake2 timeout")
        .unwrap();
    let view = wire::parse(&buf[..n]).unwrap();
    let session = init.complete(&view).unwrap();
    (session, sock)
}

/// Send one authenticated heartbeat through the supplied `session` and read
/// its ACK. Returns the next counter value to use.
pub async fn send_heartbeat(
    session: &mut Session,
    sock: &UdpSocket,
    counter: u64,
) -> anyhow::Result<()> {
    let (_c, pkt) = session.encode_heartbeat(counter, 0)?;
    sock.send(&pkt).await?;
    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(1), sock.recv(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("HeartbeatAck timeout"))??;
    let view = wire::parse(&buf[..n])?;
    let _ = session.decode_heartbeat_ack(&view)?;
    Ok(())
}

/// Write a single TOML rule into `rules_dir/<filename>`. Caller is
/// responsible for first creating `rules_dir`.
pub fn write_rule(
    rules_dir: &Path,
    filename: &str,
    name: &str,
    protocol: &str,
    listen_port: u16,
    upstream_port: u16,
) {
    let toml = format!(
        r#"
[[rule]]
name = "{name}"
protocol = "{protocol}"
listen = "127.0.0.1:{listen_port}"
upstream_port = {upstream_port}
"#,
    );
    std::fs::write(rules_dir.join(filename), toml).unwrap();
}

/// Write a terminal-mode TOML rule (`upstream_addr` form) into
/// `rules_dir/<filename>`. Caller is responsible for first creating
/// `rules_dir`. Terminal rules dial a static `host:port` on the LAN; the
/// `upstream` arg is passed through verbatim (e.g. `"127.0.0.1:9001"`).
pub fn write_terminal_rule(
    rules_dir: &Path,
    filename: &str,
    name: &str,
    protocol: &str,
    listen_port: u16,
    upstream: &str,
) {
    let toml = format!(
        r#"
[[rule]]
name = "{name}"
protocol = "{protocol}"
listen = "127.0.0.1:{listen_port}"
upstream_addr = "{upstream}"
"#,
    );
    std::fs::write(rules_dir.join(filename), toml).unwrap();
}

/// Convenient bundle that owns the heartbeat server and its tempdir-backed
/// pending-peer store so they outlive the spawned task.
pub struct HeartbeatHarness {
    pub addr: SocketAddr,
    pub handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    pub _pending_dir: tempfile::TempDir,
}

impl HeartbeatHarness {
    pub async fn spawn(
        server_keys: StaticKeyPair,
        peer_state: Arc<PeerState>,
        shutdown: CancellationToken,
    ) -> Self {
        let pending_dir = tempfile::tempdir().unwrap();
        let pending_store = Arc::new(PendingPeerStore::load(pending_dir.path()).unwrap());
        let hb = HeartbeatServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            server_keys,
            peer_state,
            pending_store,
            shutdown,
        )
        .await
        .unwrap();
        let addr = hb.local_addr().unwrap();
        let handle = tokio::spawn(hb.run());
        Self {
            addr,
            handle,
            _pending_dir: pending_dir,
        }
    }
}

/// Spawn a proxy supervisor over the given rules dir. Caller controls the
/// shutdown token.
pub async fn spawn_supervisor(
    rules_dir: PathBuf,
    debounce: Duration,
    peer_state: Arc<PeerState>,
    shutdown: CancellationToken,
) -> ProxySupervisor {
    // All integration tests run in relay mode; bind override defaults to
    // None (rules carry explicit listen addresses in test fixtures).
    ProxySupervisor::spawn(
        rules_dir,
        debounce,
        ResolverFactory::new_relay(peer_state),
        None,
        CertConfig::default(),
        shutdown,
    )
    .await
    .unwrap()
}

/// Spawn a proxy supervisor in **terminal** mode. The supervisor uses a
/// static resolver factory; each rule must carry `upstream_addr` (the helper
/// [`write_terminal_rule`] writes rules of that shape).
pub async fn spawn_terminal_supervisor(
    rules_dir: PathBuf,
    debounce: Duration,
    shutdown: CancellationToken,
) -> ProxySupervisor {
    ProxySupervisor::spawn(
        rules_dir,
        debounce,
        ResolverFactory::new_terminal(),
        None,
        CertConfig::default(),
        shutdown,
    )
    .await
    .unwrap()
}

/// Spawn a proxy supervisor in **terminal** mode with the given
/// [`CertConfig`]. Used by the HTTPS integration tests so they can point
/// `cert_dir` at a per-test scratch directory.
pub async fn spawn_terminal_supervisor_with_certs(
    rules_dir: PathBuf,
    debounce: Duration,
    cert_config: CertConfig,
    shutdown: CancellationToken,
) -> ProxySupervisor {
    ProxySupervisor::spawn(
        rules_dir,
        debounce,
        ResolverFactory::new_terminal(),
        None,
        cert_config,
        shutdown,
    )
    .await
    .unwrap()
}

/// Read N bytes from a TCP stream into a heap buffer with a sensible timeout.
pub async fn read_exact_or_timeout(
    stream: &mut TcpStream,
    n: usize,
    label: &str,
) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut buf))
        .await
        .unwrap_or_else(|_| panic!("{label}: TCP read timeout"))
        .unwrap_or_else(|e| panic!("{label}: TCP read error: {e}"));
    buf
}
