//! Criterion bench for the UDP flow table's hot-path operations.
//!
//! The yggdrasil UDP proxy maintains a `DashMap<SocketAddr, Arc<FlowEntry>>`
//! per rule. Every inbound datagram hits the table with a `get(&client_addr)`
//! on the fast path; new client addresses go through `entry(addr).or_insert(...)`.
//! Idle eviction iterates the whole table periodically.
//!
//! This bench measures those three operations at realistic table sizes
//! (1k / 10k / 100k) so we can:
//!   1. detect regressions in DashMap or our usage of it (criterion baseline
//!      gating),
//!   2. quantify the cost-per-datagram contribution of the flow table, and
//!   3. give the bench/compare.py harness a reproducible micro-bench
//!      counterpart to the e2e UDP throughput numbers.
//!
//! We bench a synthetic `BenchFlow` value (just an `AtomicU64`) instead of the
//! real `FlowEntry` because the latter owns an `Arc<UdpSocket>` and an
//! `AbortHandle` whose construction would dominate the timing. The data
//! structure under test is the `DashMap` shape, which is what we care about.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use dashmap::DashMap;

#[derive(Default)]
struct BenchFlow {
    last_seen_ms: AtomicU64,
}

type FlowTable = DashMap<SocketAddr, Arc<BenchFlow>>;

const SIZES: &[usize] = &[1_000, 10_000, 100_000];

fn make_addr(i: usize) -> SocketAddr {
    // 256³ = 16.7M unique addresses; well over our largest size. Vary the
    // octets so the hasher gets a good distribution.
    let a = (i & 0xff) as u8;
    let b = ((i >> 8) & 0xff) as u8;
    let c = ((i >> 16) & 0xff) as u8;
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, a, b, c), 1234))
}

fn make_populated_table(n: usize) -> FlowTable {
    let map: FlowTable = DashMap::with_capacity(n);
    for i in 0..n {
        map.insert(make_addr(i), Arc::new(BenchFlow::default()));
    }
    map
}

/// Hot path: lookup of an existing flow on every inbound datagram.
fn bench_lookup_hit(c: &mut Criterion) {
    let mut g = c.benchmark_group("flow_table/lookup_hit");
    for &n in SIZES {
        let table = make_populated_table(n);
        g.throughput(Throughput::Elements(1));
        g.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            // Cycle through a deterministic set of keys so we stress the
            // hash distribution rather than a single shard.
            let mut idx: usize = 0;
            b.iter(|| {
                let key = make_addr(idx);
                idx = (idx + 7919) % n; // prime stride
                let entry = table.get(&key).expect("hit");
                entry
                    .value()
                    .last_seen_ms
                    .store(idx as u64, Ordering::Relaxed);
            });
        });
    }
    g.finish();
}

/// Miss path: lookup of a non-existent flow (the proxy checks for an existing
/// flow before going to the slower create_flow path).
fn bench_lookup_miss(c: &mut Criterion) {
    let mut g = c.benchmark_group("flow_table/lookup_miss");
    for &n in SIZES {
        let table = make_populated_table(n);
        g.throughput(Throughput::Elements(1));
        g.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            // Use a different /16 so we never collide with populated keys.
            let mut idx: usize = 0;
            b.iter(|| {
                let key = SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(192, 168, (idx & 0xff) as u8, ((idx >> 8) & 0xff) as u8),
                    9999,
                ));
                idx = idx.wrapping_add(1);
                table.get(&key).is_none()
            });
        });
    }
    g.finish();
}

/// New-flow path: `entry(addr).or_insert(...)`. Measures the cost of
/// allocating + inserting a fresh flow.
fn bench_insert(c: &mut Criterion) {
    let mut g = c.benchmark_group("flow_table/insert_new");
    for &n in SIZES {
        g.throughput(Throughput::Elements(1));
        g.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched(
                || make_populated_table(n),
                |table| {
                    // Insert one fresh address, then drop the table.
                    let key = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(172, 31, 0, 1), 9999));
                    table.insert(key, Arc::new(BenchFlow::default()));
                },
                criterion::BatchSize::LargeInput,
            );
        });
    }
    g.finish();
}

/// Eviction sweep: iterate the whole table, classify each flow as idle or
/// not, and collect the victims. Mirrors `UdpProxy::reap_idle`.
fn bench_reap_sweep(c: &mut Criterion) {
    let mut g = c.benchmark_group("flow_table/reap_sweep");
    for &n in SIZES {
        let table = make_populated_table(n);
        // Pre-stamp last_seen so half are "idle" and half are "fresh".
        for (i, entry) in table.iter().enumerate() {
            entry
                .value()
                .last_seen_ms
                .store(if i % 2 == 0 { 0 } else { 1_000_000 }, Ordering::Relaxed);
        }
        g.throughput(Throughput::Elements(n as u64));
        g.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let cutoff: u64 = 500_000;
                let mut victims: Vec<SocketAddr> = Vec::new();
                for entry in table.iter() {
                    if entry.value().last_seen_ms.load(Ordering::Relaxed) < cutoff {
                        victims.push(*entry.key());
                    }
                }
                // Don't actually remove — we want to keep the table size
                // stable for the next iteration. The cost of `.remove()` is
                // bench-equivalent to `.insert()` and already covered.
                criterion::black_box(victims);
            });
        });
    }
    g.finish();
}

criterion_group!(
    benches,
    bench_lookup_hit,
    bench_lookup_miss,
    bench_insert,
    bench_reap_sweep
);
criterion_main!(benches);
