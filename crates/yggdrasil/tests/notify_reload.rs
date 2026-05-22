//! Integration test for `Type=notify-reload` integration.
//!
//! Spins up a real `ProxySupervisor` with a temp rules directory, points
//! `NOTIFY_SOCKET` at a `UnixDatagram` we own, drops a rule file, and
//! asserts the supervisor emitted the `RELOADING=1` + `MONOTONIC_USEC=…`
//! pair before the reconcile and `READY=1` after.
//!
//! Lives in its own integration-test binary so it doesn't race other
//! tests over the global `NOTIFY_SOCKET` env var.

use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use yggdrasil::heartbeat::PeerState;
use yggdrasil::proxy::resolver::ResolverFactory;
use yggdrasil::proxy::supervisor::{CertConfig, ProxySupervisor};

#[tokio::test]
async fn reload_emits_reloading_then_ready_when_notify_socket_set() {
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    // Keep the socket path short to stay under sun_path's ~108-byte limit.
    let notify_path = tmp.path().join("ns");

    // Bind the systemd-side notify socket *before* setting the env var,
    // so the very first sd_notify call has something to write to.
    let recv_sock = UnixDatagram::bind(&notify_path).expect("bind notify socket");
    recv_sock
        .set_nonblocking(true)
        .expect("set notify socket non-blocking");

    // SAFETY: this test runs alone in its `tests/notify_reload.rs`
    // binary, so no other test in the same process can race on
    // NOTIFY_SOCKET.
    unsafe {
        std::env::set_var("NOTIFY_SOCKET", &notify_path);
    }

    let peer_state = PeerState::new([0u8; 32]);
    let shutdown = CancellationToken::new();
    let supervisor = ProxySupervisor::spawn(
        rules_dir.clone(),
        Duration::from_millis(100),
        ResolverFactory::new_relay(peer_state.clone()),
        None,
        None,
        CertConfig::default(),
        shutdown.clone(),
    )
    .await
    .expect("spawn supervisor");

    // The initial empty-load completes with no notify (the supervisor
    // suppresses the cycle when both old and new sets are empty). Give
    // the watcher a moment to confirm that.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Pick a free port for the new rule's listen address.
    let listen_port = {
        let s = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("free port");
        s.local_addr().unwrap().port()
    };
    let toml = format!(
        r#"
[[rule]]
name = "alpha"
protocol = "tcp"
listen = "127.0.0.1:{listen_port}"
target_port = 9001
"#,
    );
    std::fs::write(rules_dir.join("a.toml"), toml).expect("write rule file");

    // Wait for the supervisor to actually apply the new rule.
    let mut rx = supervisor.snapshot_receiver();
    let saw = timeout(Duration::from_secs(5), async {
        loop {
            if rx.borrow().len() == 1 {
                return true;
            }
            if rx.changed().await.is_err() {
                return false;
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(saw, "supervisor never reflected the new rule");

    // Drain the notify socket. We expect at least two messages: one
    // containing RELOADING=1 + MONOTONIC_USEC=, and one with READY=1.
    // recv()s happen on a blocking thread because std::UnixDatagram is
    // sync; the deadline keeps the test from hanging if a message is
    // lost.
    let collected = tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 4096];
        let mut all = String::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            match recv_sock.recv(&mut buf) {
                Ok(n) => {
                    let s = String::from_utf8_lossy(&buf[..n]).to_string();
                    all.push_str(&s);
                    all.push('\n');
                    if all.contains("RELOADING=1")
                        && all.contains("MONOTONIC_USEC=")
                        && all.contains("READY=1")
                    {
                        return all;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("recv on notify socket failed: {e}"),
            }
        }
        all
    })
    .await
    .expect("notify-recv task panicked");

    // Unset NOTIFY_SOCKET before tearing down: any further sd_notify
    // calls (e.g. from the shutdown path) would otherwise hit a now
    // unbound path.
    unsafe {
        std::env::remove_var("NOTIFY_SOCKET");
    }

    assert!(
        collected.contains("RELOADING=1"),
        "missing RELOADING=1 in notify stream: {collected:?}"
    );
    assert!(
        collected.contains("MONOTONIC_USEC="),
        "missing MONOTONIC_USEC in notify stream: {collected:?}"
    );
    assert!(
        collected.contains("READY=1"),
        "missing READY=1 in notify stream: {collected:?}"
    );

    // RELOADING=1 must precede READY=1 in the byte stream.
    let reloading_at = collected.find("RELOADING=1").unwrap();
    let ready_at = collected.find("READY=1").unwrap();
    assert!(
        reloading_at < ready_at,
        "RELOADING=1 should come before READY=1: {collected:?}"
    );

    shutdown.cancel();
    supervisor.stop().await;
}
