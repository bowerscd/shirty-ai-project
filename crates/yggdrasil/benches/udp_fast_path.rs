//! Criterion bench for the UDP frontend's steady-state throughput.
//!
//! `proxy/udp/mod.rs` was changed so the `recvmmsg`-batched frontend
//! loop dispatches its datagrams synchronously over borrowed scratch
//! slices via `try_handle_inbound_fast`, instead of `.to_vec()`-ing
//! every datagram into an owned buffer for an async dispatch loop.
//! The optimisation eliminates a per-packet `Vec` allocation **and**
//! a per-packet tokio scheduler hop on the steady-state existing-flow
//! path.
//!
//! ## What this bench can and cannot measure
//!
//! It measures **end-to-end throughput on loopback** with N concurrent
//! client sockets each firing a fixed burst. That captures the
//! frontend's ability to keep up with parallel arrivals — exactly the
//! shape the fast path optimises for.
//!
//! It does **not** measure per-packet cost in isolation. The loopback
//! kernel round-trip dominates anything under ~1 µs, which is where
//! the per-packet `Vec` allocation lives. To see the structural cost
//! reduction, this bench would need either an in-process allocator
//! counter or a profiler — both out of scope for a criterion bench.
//!
//! Use this as a **regression detector**: if a future change to the
//! frontend pipeline tanks steady-state throughput by 2× or more,
//! this bench surfaces it. Don't read absolute numbers as a quality
//! measurement.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;

use ratatoskr::rule::{Protocol, Rule, RuleFile};
use yggdrasil::heartbeat::PeerState;
use yggdrasil::proxy::resolver::UpstreamResolver;
use yggdrasil::proxy::udp::{UdpProxy, MAX_FLOWS_PER_RULE_DEFAULT};

/// Number of concurrent client sockets firing into the frontend.
/// Each client gets its own flow-table entry, so this scales the
/// fan-in pressure the frontend's per-batch loop has to handle.
const CONCURRENT_CLIENTS: usize = 32;
/// Datagrams per client per iteration. Multiplied by `CONCURRENT_CLIENTS`
/// for the criterion `Throughput::Elements` axis.
const DATAGRAMS_PER_CLIENT: usize = 16;
const PAYLOAD_SIZES: &[usize] = &[64, 512];

fn build_proxy(runtime: &Runtime) -> (UdpProxy, SocketAddr) {
    runtime.block_on(async {
        let upstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let (n, from) = match upstream.recv_from(&mut buf).await {
                    Ok(r) => r,
                    Err(_) => return,
                };
                let _ = upstream.send_to(&buf[..n], from).await;
            }
        });

        let rule_file = RuleFile::from_toml(
            "bench.toml",
            &format!(
                r#"
                [[rule]]
                name = "bench-fast-path"
                listen = "127.0.0.1:0"
                protocol = "udp"
                target_port = {}
                idle_timeout = "60s"
                "#,
                upstream_addr.port(),
            ),
        )
        .unwrap();
        let rule: Rule = rule_file.rule.into_iter().next().unwrap();
        assert_eq!(rule.protocol, Protocol::Udp);

        let peer = PeerState::new(None);
        let _ = peer.record_heartbeat("127.0.0.1:1".parse().unwrap());
        let resolver = UpstreamResolver::Dynamic {
            peer_state: peer,
            port: upstream_addr.port(),
        };
        let proxy = UdpProxy::spawn_with(rule, resolver, MAX_FLOWS_PER_RULE_DEFAULT, 1)
            .await
            .unwrap();
        let frontend_addr = proxy.local_addr();
        (proxy, frontend_addr)
    })
}

fn bench_fast_path(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let (proxy, frontend_addr) = build_proxy(&runtime);

    let mut group = c.benchmark_group("udp_frontend_fast_path");
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(3));

    for &payload_size in PAYLOAD_SIZES {
        let total_per_iter = (CONCURRENT_CLIENTS * DATAGRAMS_PER_CLIENT) as u64;
        group.throughput(Throughput::Elements(total_per_iter));
        group.bench_function(
            BenchmarkId::new("concurrent_clients_burst", payload_size),
            |b| {
                b.iter_custom(|iters| {
                    runtime.block_on(async {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            // Fresh per-iteration client sockets so the
                            // flow table state is reproducible across
                            // iterations.
                            let mut clients = Vec::with_capacity(CONCURRENT_CLIENTS);
                            for _ in 0..CONCURRENT_CLIENTS {
                                let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                                c.connect(frontend_addr).await.unwrap();
                                clients.push(Arc::new(c));
                            }
                            let start = std::time::Instant::now();
                            let mut tasks = Vec::with_capacity(CONCURRENT_CLIENTS);
                            for c in &clients {
                                let c = Arc::clone(c);
                                let payload = vec![0xAB; payload_size];
                                tasks.push(tokio::spawn(async move {
                                    let mut recv_buf = vec![0u8; payload_size + 16];
                                    for _ in 0..DATAGRAMS_PER_CLIENT {
                                        c.send(&payload).await.unwrap();
                                        let _ = tokio::time::timeout(
                                            Duration::from_millis(500),
                                            c.recv(&mut recv_buf),
                                        )
                                        .await
                                        .expect("echo timed out")
                                        .unwrap();
                                    }
                                }));
                            }
                            for t in tasks {
                                t.await.unwrap();
                            }
                            total += start.elapsed();
                        }
                        total
                    })
                });
            },
        );
    }
    group.finish();

    runtime.block_on(async {
        proxy.stop().await;
    });
}

criterion_group!(benches, bench_fast_path);
criterion_main!(benches);
