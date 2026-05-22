//! Criterion benches for the UDP flow table's hot-path operations.
//!
//! The yggdrasil UDP proxy keeps one
//! `Arc<DashMap<SocketAddr, Arc<FlowEntry>>>` shard per UDP worker. The
//! kernel's `SO_REUSEPORT` fan-out sends each datagram to one worker, so new
//! flow creation contends only with other flows assigned to that worker's shard.
//!
//! This bench still tracks lookup and reaper costs at realistic table sizes
//! (1k / 10k / 100k), and the insertion benchmark compares the old
//! single-shard fan-out pattern with the current per-worker-shard layout.
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
type FlowShard = Arc<FlowTable>;

const TABLE_SIZES: &[usize] = &[1_000, 10_000, 100_000];
const WORKER_COUNTS: &[usize] = &[1, 2, 4, 8];
const INSERTS_PER_SHARD: &[usize] = &[100, 1_000, 10_000];

#[derive(Clone, Copy)]
struct InsertCase {
    workers: usize,
    inserts_per_shard: usize,
}

impl InsertCase {
    fn total_inserts(self) -> usize {
        self.workers * self.inserts_per_shard
    }

    fn label(self) -> String {
        format!(
            "{}_workers/{}_per_shard",
            self.workers, self.inserts_per_shard
        )
    }
}

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

fn make_empty_shards(workers: usize) -> Vec<FlowShard> {
    (0..workers).map(|_| Arc::new(DashMap::new())).collect()
}

fn build_runtime(workers: usize) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .expect("build UDP flow-table bench runtime")
}

fn insert_worker(shard: FlowShard, worker_id: usize, inserts_per_shard: usize) {
    let base = worker_id * inserts_per_shard;
    for offset in 0..inserts_per_shard {
        let flow = shard
            .entry(make_addr(base + offset))
            .or_insert_with(|| Arc::new(BenchFlow::default()));
        flow.last_seen_ms.store(offset as u64, Ordering::Relaxed);
    }
}

async fn insert_single_shard(shard: FlowShard, workers: usize, inserts_per_shard: usize) -> usize {
    let mut handles = Vec::with_capacity(workers);
    for worker_id in 0..workers {
        let shard = Arc::clone(&shard);
        handles.push(tokio::spawn(async move {
            insert_worker(shard, worker_id, inserts_per_shard);
        }));
    }

    for handle in handles {
        handle.await.expect("flow insertion task panicked");
    }
    shard.len()
}

async fn insert_per_worker_shards(shards: Vec<FlowShard>, inserts_per_shard: usize) -> usize {
    let mut handles = Vec::with_capacity(shards.len());
    for (worker_id, shard) in shards.iter().cloned().enumerate() {
        handles.push(tokio::spawn(async move {
            insert_worker(shard, worker_id, inserts_per_shard);
        }));
    }

    for handle in handles {
        handle.await.expect("flow insertion task panicked");
    }
    shards.iter().map(|shard| shard.len()).sum()
}

/// Hot path: lookup of an existing flow on every inbound datagram.
fn bench_lookup_hit(c: &mut Criterion) {
    let mut g = c.benchmark_group("flow_table/lookup_hit");
    for &n in TABLE_SIZES {
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
    for &n in TABLE_SIZES {
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

/// New-flow path: N workers concurrently create flows. `single_shard` models
/// the old one-map layout; `per_worker_shard` models `UdpProxy::shards` today.
fn bench_insert(c: &mut Criterion) {
    let mut g = c.benchmark_group("flow_table/insert_fanout");
    for &workers in WORKER_COUNTS {
        let rt = build_runtime(workers);
        for &inserts_per_shard in INSERTS_PER_SHARD {
            let case = InsertCase {
                workers,
                inserts_per_shard,
            };
            let label = case.label();
            g.throughput(Throughput::Elements(case.total_inserts() as u64));

            g.bench_with_input(
                BenchmarkId::new("single_shard", label.clone()),
                &case,
                |b, &case| {
                    b.iter_batched(
                        || Arc::new(DashMap::new()),
                        |shard| {
                            let len = rt.block_on(insert_single_shard(
                                shard,
                                case.workers,
                                case.inserts_per_shard,
                            ));
                            let _ = criterion::black_box(len);
                        },
                        criterion::BatchSize::LargeInput,
                    );
                },
            );

            g.bench_with_input(
                BenchmarkId::new("per_worker_shard", label),
                &case,
                |b, &case| {
                    b.iter_batched(
                        || make_empty_shards(case.workers),
                        |shards| {
                            let len = rt
                                .block_on(insert_per_worker_shards(shards, case.inserts_per_shard));
                            let _ = criterion::black_box(len);
                        },
                        criterion::BatchSize::LargeInput,
                    );
                },
            );
        }
    }
    g.finish();
}

/// Eviction sweep: iterate the whole table, classify each flow as idle or
/// not, and collect the victims. Mirrors `UdpProxy::reap_idle`.
fn bench_reap_sweep(c: &mut Criterion) {
    let mut g = c.benchmark_group("flow_table/reap_sweep");
    for &n in TABLE_SIZES {
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
