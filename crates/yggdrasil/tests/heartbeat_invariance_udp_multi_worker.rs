//! Heartbeat-invariance test under multi-worker fan-out.
//!
//! Spawns a `UdpProxy` with N=4 workers (SO_REUSEPORT fan-out + per-shard
//! flow tables). Establishes a fleet of UDP flows from 100+ distinct client
//! source ports, fires 50+ same-IP heartbeats, and asserts that no flow is
//! dropped or replaced.

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use metrics_exporter_prometheus::PrometheusHandle;
use tokio::net::UdpSocket;

use yggdrasil::heartbeat::PeerState;
use yggdrasil::proxy::resolver::UpstreamResolver;
use yggdrasil::proxy::udp::{UdpProxy, MAX_FLOWS_PER_RULE_DEFAULT};

const WORKERS: usize = 4;
const CLIENTS: usize = 128;
const HEARTBEATS: u16 = 64;

static METRICS: OnceLock<PrometheusHandle> = OnceLock::new();

fn metrics_handle() -> &'static PrometheusHandle {
    METRICS.get_or_init(|| {
        yggdrasil::metrics::install_recorder(ratatoskr::control::Mode::Relay)
            .expect("install prometheus recorder for UDP integration test")
    })
}

async fn observed_echo_server() -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (n, from) = match sock.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => return,
            };
            let mut out = from.to_string().into_bytes();
            out.push(b'\n');
            out.extend_from_slice(&buf[..n]);
            let _ = sock.send_to(&out, from).await;
        }
    });
    addr
}

fn udp_rule(name: &str, target_port: u16) -> ratatoskr::rule::Rule {
    let f = ratatoskr::rule::RuleFile::from_toml(
        "test.toml",
        &format!(
            r#"
            [[rule]]
            name = "{name}"
            listen = "127.0.0.1:0"
            protocol = "udp"
            target_port = {target_port}
            idle_timeout = "60s"
            "#,
        ),
    )
    .unwrap();
    f.rule.into_iter().next().unwrap()
}

fn dynamic_resolver(peer: Arc<PeerState>, port: u16) -> UpstreamResolver {
    UpstreamResolver::Dynamic {
        peer_state: peer,
        port,
    }
}

async fn send_recv_observed(
    client: &UdpSocket,
    proxy_addr: SocketAddr,
    payload: &[u8],
) -> (Vec<u8>, SocketAddr) {
    client.send_to(payload, proxy_addr).await.unwrap();
    let mut buf = [0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("recv timeout — flow may have been disturbed")
        .unwrap();
    let split = buf[..n]
        .iter()
        .position(|&b| b == b'\n')
        .expect("observed echo response missing upstream address separator");
    let observed_addr = std::str::from_utf8(&buf[..split]).unwrap().parse().unwrap();
    (buf[split + 1..n].to_vec(), observed_addr)
}

async fn wait_for_active_flows(proxy: &UdpProxy, expected: usize) {
    for _ in 0..100 {
        if proxy.active_flows() == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(proxy.active_flows(), expected);
}

fn label_value<'a>(line: &'a str, label: &str) -> Option<&'a str> {
    let needle = format!(r#"{label}=""#);
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn shard_flow_counts(rule_name: &str) -> Vec<usize> {
    let rendered = metrics_handle().render();
    let mut counts = vec![None; WORKERS];

    for line in rendered.lines() {
        if !line.starts_with("yggdrasil_udp_active_flows{") {
            continue;
        }
        if label_value(line, "rule") != Some(rule_name) {
            continue;
        }
        let worker = label_value(line, "worker")
            .and_then(|value| value.parse::<usize>().ok())
            .expect("active flow metric should carry a numeric worker label");
        let value = line
            .split_whitespace()
            .last()
            .and_then(|value| value.parse::<f64>().ok())
            .expect("active flow metric should carry a numeric value");
        if worker < WORKERS {
            counts[worker] = Some(value as usize);
        }
    }

    counts
        .into_iter()
        .enumerate()
        .map(|(worker, count)| {
            count.unwrap_or_else(|| panic!("missing active flow metric for worker {worker}"))
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_worker_heartbeat_invariance() {
    let _ = metrics_handle();
    let upstream = observed_echo_server().await;
    let peer = PeerState::new([0u8; 32]);
    let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());

    let proxy = UdpProxy::spawn_with(
        udp_rule("invariance-mw", upstream.port()),
        dynamic_resolver(peer.clone(), upstream.port()),
        MAX_FLOWS_PER_RULE_DEFAULT,
        WORKERS,
    )
    .await
    .unwrap();

    let mut clients = Vec::with_capacity(CLIENTS);
    let mut upstream_sock_addrs = Vec::with_capacity(CLIENTS);
    for i in 0..CLIENTS {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let payload = [i as u8; 8];
        let (echoed, upstream_sock_addr) =
            send_recv_observed(&client, proxy.local_addr(), &payload).await;
        assert_eq!(echoed, payload);
        upstream_sock_addrs.push(upstream_sock_addr);
        clients.push(client);
    }
    wait_for_active_flows(&proxy, CLIENTS).await;

    let flows_before = proxy.active_flows();
    assert_eq!(flows_before, CLIENTS, "expected all flows established");
    let shard_counts_before = shard_flow_counts("invariance-mw");
    assert_eq!(
        shard_counts_before.iter().sum::<usize>(),
        CLIENTS,
        "per-shard gauges should account for every flow"
    );
    assert!(
        shard_counts_before.iter().all(|&count| count > 0),
        "expected SO_REUSEPORT fan-out to place flows on every shard: {shard_counts_before:?}"
    );

    for port in 2000..2000 + HEARTBEATS {
        let _ = peer.record_heartbeat(format!("127.0.0.1:{port}").parse().unwrap());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let flows_after = proxy.active_flows();
    assert_eq!(
        flows_after, CLIENTS,
        "same-IP heartbeats must not disturb the flow table"
    );
    assert_eq!(
        shard_flow_counts("invariance-mw"),
        shard_counts_before,
        "same-IP heartbeats must leave every shard length unchanged"
    );

    for (i, client) in clients.iter().enumerate() {
        let payload = [i as u8; 8];
        let (echoed, upstream_sock_addr) =
            send_recv_observed(client, proxy.local_addr(), &payload).await;
        assert_eq!(echoed, payload);
        assert_eq!(
            upstream_sock_addr, upstream_sock_addrs[i],
            "client {i} upstream socket must be preserved across same-IP heartbeats"
        );
    }

    proxy.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_worker_ip_change_drains_all_shards() {
    let _ = metrics_handle();
    let upstream = observed_echo_server().await;
    let peer = PeerState::new([0u8; 32]);
    let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());

    let proxy = UdpProxy::spawn_with(
        udp_rule("drain-mw", upstream.port()),
        dynamic_resolver(peer.clone(), upstream.port()),
        MAX_FLOWS_PER_RULE_DEFAULT,
        WORKERS,
    )
    .await
    .unwrap();

    let mut clients = Vec::new();
    for i in 0..32u8 {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let payload = [i; 4];
        let (echoed, _) = send_recv_observed(&client, proxy.local_addr(), &payload).await;
        assert_eq!(echoed, payload);
        clients.push(client);
    }
    assert!(!clients.is_empty());
    wait_for_active_flows(&proxy, clients.len()).await;
    assert!(proxy.active_flows() >= 1);

    let _ = peer.record_heartbeat("198.51.100.1:1".parse().unwrap());
    for _ in 0..50 {
        if proxy.active_flows() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert_eq!(
        proxy.active_flows(),
        0,
        "ALL shards must drain on IP change"
    );
    assert_eq!(
        shard_flow_counts("drain-mw"),
        vec![0; WORKERS],
        "per-shard gauges must show every shard drained"
    );

    proxy.stop().await;
}
