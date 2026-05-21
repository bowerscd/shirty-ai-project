//! End-to-end terminal-mode integration tests.
//!
//! These tests prove the four core invariants of the terminal/relay
//! topology:
//!
//! 1. **Chained TCP**: a terminal-mode supervisor accepts TCP on its rule's
//!    `listen` socket and dials the rule's static `target_addr` on the
//!    LAN. Chained behind a relay-mode supervisor, the round-trip from
//!    client → relay → terminal → echo is byte-stable.
//! 2. **Chained UDP**: the same shape with UDP datagrams. Both proxies are
//!    L4 pass-through; the terminal's flow table behaves exactly as in
//!    relay mode (one client port → one upstream-bound socket).
//! 3. **PROXY-protocol pass-through**: when the relay rule sets
//!    `proxy_protocol = "v2"`, the relay prepends a v2 header on the
//!    upstream side. The terminal is opaque to that header (it sees just
//!    bytes), so the echo upstream receives bytes starting with the v2
//!    magic.
//! 4. **Control-plane shape**: a terminal-mode `ControlServer` answers
//!    `status` with `mode: terminal` and no peer fields, and any `peer ...`
//!    request returns the `not_supported_in_terminal_mode` error.
//!
//! The tests do not call `yggdrasil::run_terminal` directly: integration
//! tests bind the supervisor + control server pieces individually so they
//! can inject fixtures and assert against snapshots without going through
//! the full signal-driven shutdown cascade.

mod common;

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket, UnixStream};
use tokio_util::sync::CancellationToken;

use ratatoskr::auth::StaticKeyPair;
use ratatoskr::control::{error_codes, Mode, Request, Response, StatusResponse};
use ratatoskr::rule::Protocol;

use yggdrasil::control::ControlServer;
use yggdrasil::heartbeat::PeerState;

use crate::common::{
    drive_handshake, echo_tcp_listener, echo_udp_socket, pick_free_tcp_port, pick_free_udp_port,
    send_heartbeat, spawn_supervisor, spawn_tcp_echo, spawn_terminal_supervisor, spawn_udp_echo,
    write_rule, write_terminal_rule, HeartbeatHarness,
};

/// Drive the chain `client → relay → terminal → echo` over TCP and assert
/// the bytes echo back unchanged.
#[tokio::test]
async fn chained_tcp_relay_to_terminal_to_echo_round_trips() {
    let server_keys = StaticKeyPair::generate().unwrap();
    let client_keys = StaticKeyPair::generate().unwrap();
    let peer_state = PeerState::new(*client_keys.public_key());
    let shutdown = CancellationToken::new();
    let server_pub = *server_keys.public_key();

    // Heartbeat server so the relay's `peer_state.current_ip()` is populated.
    let hb = HeartbeatHarness::spawn(server_keys, peer_state.clone(), shutdown.clone()).await;

    // Echo TCP backend on a free 127.0.0.1 port.
    let (echo_listener, echo_addr) = echo_tcp_listener().await;
    let _echo_handle = spawn_tcp_echo(echo_listener);

    // Terminal supervisor: one TCP rule that dials echo_addr directly.
    let terminal_dir = tempfile::tempdir().unwrap();
    let terminal_rules = terminal_dir.path().join("rules");
    std::fs::create_dir_all(&terminal_rules).unwrap();
    let terminal_listen_port = pick_free_tcp_port().await;
    write_terminal_rule(
        &terminal_rules,
        "echo.toml",
        "echo",
        "tcp",
        terminal_listen_port,
        &format!("127.0.0.1:{}", echo_addr.port()),
    );
    let terminal_supervisor =
        spawn_terminal_supervisor(terminal_rules, Duration::from_millis(50), shutdown.clone())
            .await;
    assert!(
        terminal_supervisor
            .wait_for_nonempty(Duration::from_secs(2))
            .await,
        "terminal supervisor never spawned its proxy"
    );

    // Relay supervisor: one TCP rule that dials peer-ip:terminal_listen_port.
    // The relay learns the peer IP via the heartbeat below, then resolves
    // the upstream to the terminal's listen socket.
    let relay_dir = tempfile::tempdir().unwrap();
    let relay_rules = relay_dir.path().join("rules");
    std::fs::create_dir_all(&relay_rules).unwrap();
    let relay_listen_port = pick_free_tcp_port().await;
    write_rule(
        &relay_rules,
        "echo.toml",
        "echo",
        "tcp",
        relay_listen_port,
        terminal_listen_port,
    );
    let relay_supervisor = spawn_supervisor(
        relay_rules,
        Duration::from_millis(50),
        peer_state.clone(),
        shutdown.clone(),
    )
    .await;
    assert!(
        relay_supervisor
            .wait_for_nonempty(Duration::from_secs(2))
            .await,
        "relay supervisor never spawned its proxy"
    );

    let snap = relay_supervisor.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].protocol, Protocol::Tcp);
    let relay_listen = snap[0].listen;

    // Drive the handshake + a heartbeat to populate peer_state.current_ip().
    let (mut session, hb_sock) = drive_handshake(&server_pub, &client_keys, hb.addr).await;
    send_heartbeat(&mut session, &hb_sock, 0).await.unwrap();
    assert!(peer_state.current_ip().is_some());

    // External client opens a TCP connection to the relay and round-trips
    // a payload through the full chain.
    let mut stream = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(relay_listen))
        .await
        .expect("relay TcpStream connect timeout")
        .expect("relay TcpStream connect failed");

    stream.write_all(b"hello\n").await.unwrap();
    let mut buf = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut buf))
        .await
        .expect("chain TCP echo timeout")
        .unwrap();
    assert_eq!(&buf, b"hello\n");

    shutdown.cancel();
    relay_supervisor.stop().await;
    terminal_supervisor.stop().await;
    let _ = hb.handle.await;
}

/// Sibling of `chained_tcp_*`: same topology but UDP. One client datagram
/// makes it through `client → relay → terminal → echo` and back.
#[tokio::test]
async fn chained_udp_relay_to_terminal_to_echo_round_trips() {
    let server_keys = StaticKeyPair::generate().unwrap();
    let client_keys = StaticKeyPair::generate().unwrap();
    let peer_state = PeerState::new(*client_keys.public_key());
    let shutdown = CancellationToken::new();
    let server_pub = *server_keys.public_key();

    let hb = HeartbeatHarness::spawn(server_keys, peer_state.clone(), shutdown.clone()).await;

    let (echo_sock, echo_addr) = echo_udp_socket().await;
    let _echo_handle = spawn_udp_echo(echo_sock);

    let terminal_dir = tempfile::tempdir().unwrap();
    let terminal_rules = terminal_dir.path().join("rules");
    std::fs::create_dir_all(&terminal_rules).unwrap();
    let terminal_listen_port = pick_free_udp_port().await;
    write_terminal_rule(
        &terminal_rules,
        "echo.toml",
        "echo",
        "udp",
        terminal_listen_port,
        &format!("127.0.0.1:{}", echo_addr.port()),
    );
    let terminal_supervisor =
        spawn_terminal_supervisor(terminal_rules, Duration::from_millis(50), shutdown.clone())
            .await;
    assert!(
        terminal_supervisor
            .wait_for_nonempty(Duration::from_secs(2))
            .await
    );

    let relay_dir = tempfile::tempdir().unwrap();
    let relay_rules = relay_dir.path().join("rules");
    std::fs::create_dir_all(&relay_rules).unwrap();
    let relay_listen_port = pick_free_udp_port().await;
    write_rule(
        &relay_rules,
        "echo.toml",
        "echo",
        "udp",
        relay_listen_port,
        terminal_listen_port,
    );
    let relay_supervisor = spawn_supervisor(
        relay_rules,
        Duration::from_millis(50),
        peer_state.clone(),
        shutdown.clone(),
    )
    .await;
    assert!(
        relay_supervisor
            .wait_for_nonempty(Duration::from_secs(2))
            .await
    );
    let relay_listen = relay_supervisor.snapshot()[0].listen;

    let (mut session, hb_sock) = drive_handshake(&server_pub, &client_keys, hb.addr).await;
    send_heartbeat(&mut session, &hb_sock, 0).await.unwrap();
    assert!(peer_state.current_ip().is_some());

    // Send one datagram through the full chain and wait for the echo back.
    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_sock.connect(relay_listen).await.unwrap();
    client_sock.send(b"ping\n").await.unwrap();
    let mut buf = [0u8; 32];
    let n = tokio::time::timeout(Duration::from_secs(2), client_sock.recv(&mut buf))
        .await
        .expect("chain UDP echo timeout")
        .unwrap();
    assert_eq!(&buf[..n], b"ping\n");

    shutdown.cancel();
    relay_supervisor.stop().await;
    terminal_supervisor.stop().await;
    let _ = hb.handle.await;
}

/// **PROXY-protocol pass-through invariant.** When the relay rule sets
/// `proxy_protocol = "v2"` the relay emits a v2 header on the upstream
/// side. The terminal is L4 pass-through and treats those bytes as opaque
/// data. The upstream echo therefore receives bytes starting with the v2
/// magic preamble (`0x0d 0x0a 0x0d 0x0a 0x00 0x0d 0x0a 0x51 0x55 0x49 0x54
/// 0x0a`) followed by the v2 fixed header byte and the address block.
#[tokio::test]
async fn proxy_protocol_v2_passes_through_terminal_unchanged() {
    use tokio::net::TcpListener;

    let server_keys = StaticKeyPair::generate().unwrap();
    let client_keys = StaticKeyPair::generate().unwrap();
    let peer_state = PeerState::new(*client_keys.public_key());
    let shutdown = CancellationToken::new();
    let server_pub = *server_keys.public_key();

    let hb = HeartbeatHarness::spawn(server_keys, peer_state.clone(), shutdown.clone()).await;

    // Special echo backend: capture the first 256 bytes received on the
    // first connection so we can assert on the v2 magic preamble.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = listener.local_addr().unwrap();
    let (capture_tx, capture_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    let echo_handle = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 256];
        let n = sock.read(&mut buf).await.unwrap();
        buf.truncate(n);
        let _ = capture_tx.send(buf);
        // Drain so the relay's write half does not block — we don't care
        // about contents past the captured prefix.
        let mut sink = [0u8; 4096];
        loop {
            match sock.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });

    // Terminal supervisor: plain pass-through TCP rule (no proxy_protocol;
    // terminal rejects that combination anyway).
    let terminal_dir = tempfile::tempdir().unwrap();
    let terminal_rules = terminal_dir.path().join("rules");
    std::fs::create_dir_all(&terminal_rules).unwrap();
    let terminal_listen_port = pick_free_tcp_port().await;
    write_terminal_rule(
        &terminal_rules,
        "echo.toml",
        "echo",
        "tcp",
        terminal_listen_port,
        &format!("127.0.0.1:{}", echo_addr.port()),
    );
    let terminal_supervisor =
        spawn_terminal_supervisor(terminal_rules, Duration::from_millis(50), shutdown.clone())
            .await;
    assert!(
        terminal_supervisor
            .wait_for_nonempty(Duration::from_secs(2))
            .await
    );

    // Relay supervisor: TCP rule with `proxy_protocol = "v2"`.
    let relay_dir = tempfile::tempdir().unwrap();
    let relay_rules = relay_dir.path().join("rules");
    std::fs::create_dir_all(&relay_rules).unwrap();
    let relay_listen_port = pick_free_tcp_port().await;
    let relay_toml = format!(
        r#"
[[rule]]
name = "echo"
protocol = "tcp"
listen = "127.0.0.1:{relay_listen_port}"
target_port = {terminal_listen_port}
proxy_protocol = "v2"
"#
    );
    std::fs::write(relay_rules.join("echo.toml"), relay_toml).unwrap();
    let relay_supervisor = spawn_supervisor(
        relay_rules,
        Duration::from_millis(50),
        peer_state.clone(),
        shutdown.clone(),
    )
    .await;
    assert!(
        relay_supervisor
            .wait_for_nonempty(Duration::from_secs(2))
            .await
    );
    let relay_listen = relay_supervisor.snapshot()[0].listen;

    let (mut session, hb_sock) = drive_handshake(&server_pub, &client_keys, hb.addr).await;
    send_heartbeat(&mut session, &hb_sock, 0).await.unwrap();
    assert!(peer_state.current_ip().is_some());

    // Open a TCP connection through the relay; send some payload so the
    // backend has a reason to read.
    let mut stream = TcpStream::connect(relay_listen).await.unwrap();
    stream.write_all(b"after-proxy-header\n").await.unwrap();

    // Read the captured prefix and assert on the v2 magic. We don't check
    // the address bytes precisely — the relay encodes its observed client
    // address, which depends on ephemeral local-loopback ports.
    let captured = tokio::time::timeout(Duration::from_secs(2), capture_rx)
        .await
        .expect("echo capture timeout")
        .expect("echo capture channel dropped");
    let v2_magic: [u8; 12] = [
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
    ];
    assert!(
        captured.len() >= 16,
        "captured prefix too short: {} bytes",
        captured.len()
    );
    assert_eq!(
        &captured[..12],
        &v2_magic,
        "first 12 bytes were not the PROXY-protocol v2 magic"
    );

    shutdown.cancel();
    relay_supervisor.stop().await;
    terminal_supervisor.stop().await;
    let _ = echo_handle.await;
    let _ = hb.handle.await;
}

/// `yggdrasilctl status` against a terminal-mode daemon: response carries
/// `mode = terminal` and `peer_ip` / `last_heartbeat_age_ms` are `None`.
#[tokio::test]
async fn terminal_control_status_response_shape() {
    let shutdown = CancellationToken::new();
    let rules_tmp = tempfile::tempdir().unwrap();
    let rules_dir = rules_tmp.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let supervisor =
        spawn_terminal_supervisor(rules_dir, Duration::from_millis(50), shutdown.clone()).await;

    let socket_dir = tempfile::tempdir().unwrap();
    let socket_path = socket_dir.path().join("control.sock");
    let config_path = socket_dir.path().join("yggdrasil.toml");
    std::fs::write(
        &config_path,
        "[server]\nmode = \"terminal\"\n[peer]\npublic_key_hex = \"\"\n",
    )
    .unwrap();

    let server = ControlServer::bind(
        socket_path.clone(),
        Mode::Terminal,
        None,
        &supervisor,
        None,
        config_path,
        false,
        yggdrasil::metrics::detached_handle_for_tests(),
        None,
        None,
        shutdown.clone(),
    )
    .await
    .unwrap();

    let resp = send_request(&socket_path, &Request::Status).await;
    match resp {
        Response::Status(StatusResponse {
            mode,
            downstream_ip,
            last_heartbeat_age_ms,
            downstream_enrolled,
            ..
        }) => {
            assert_eq!(mode, Mode::Terminal);
            assert_eq!(downstream_ip, None);
            assert_eq!(last_heartbeat_age_ms, None);
            assert!(!downstream_enrolled);
        }
        other => panic!("unexpected response: {other:?}"),
    }

    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

/// All three `downstream ...` commands return the terminal-mode unsupported error.
#[tokio::test]
async fn terminal_control_peer_commands_are_rejected() {
    let shutdown = CancellationToken::new();
    let rules_tmp = tempfile::tempdir().unwrap();
    let rules_dir = rules_tmp.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let supervisor =
        spawn_terminal_supervisor(rules_dir, Duration::from_millis(50), shutdown.clone()).await;

    let socket_dir = tempfile::tempdir().unwrap();
    let socket_path = socket_dir.path().join("control.sock");
    let config_path = socket_dir.path().join("yggdrasil.toml");
    std::fs::write(&config_path, "[server]\nmode = \"terminal\"\n").unwrap();

    let server = ControlServer::bind(
        socket_path.clone(),
        Mode::Terminal,
        None,
        &supervisor,
        None,
        config_path,
        false,
        yggdrasil::metrics::detached_handle_for_tests(),
        None,
        None,
        shutdown.clone(),
    )
    .await
    .unwrap();

    let cases = [
        Request::DownstreamShow,
        Request::DownstreamPending,
        Request::DownstreamApprove {
            fingerprint: "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        },
    ];
    for req in cases {
        let resp = send_request(&socket_path, &req).await;
        match resp {
            Response::Error { code, .. } => {
                assert_eq!(
                    code,
                    error_codes::NOT_SUPPORTED_IN_TERMINAL_MODE,
                    "wrong error code for request {req:?}"
                );
            }
            other => panic!("expected error response, got {other:?}"),
        }
    }

    // Sanity: `rules list` and `rules reload` still work in terminal
    // mode (proxy supervisor is shared between modes).
    let resp = send_request(&socket_path, &Request::RulesList).await;
    assert!(matches!(resp, Response::Rules(_)));
    let resp = send_request(&socket_path, &Request::RulesReload).await;
    assert!(matches!(resp, Response::RulesReloaded { .. }));

    shutdown.cancel();
    server.stop().await;
    supervisor.stop().await;
}

// Helpers private to this test file. The `control.rs` module has a
// `send_request` helper but it's gated behind `#[cfg(test)]` on the lib
// crate; integration tests can't reach it.

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
