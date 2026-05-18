//! Noise_IK + AEAD micro-benchmarks.
//!
//! Run with `cargo bench -p yggdrasil-proto --bench noise`.
//!
//! Measures:
//! - `handshake/full`: full Initiator → Responder → Initiator round trip
//!   (`start` + `process_handshake_1` + `complete` + `Initiator::complete`).
//! - `aead/encrypt_64`: `Session::encode_heartbeat` on a 64-byte heartbeat
//!   plaintext (the steady-state hot loop on the residential box).
//! - `aead/decrypt_64`: `Session::decode_heartbeat` on the server side
//!   (the steady-state hot loop on the VPS).
//!
//! Targets (from plan): ≥ 50k handshakes/sec, ≥ 1 GB/s AEAD per core.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use yggdrasil_proto::auth::{Initiator, Responder, Session, StaticKeyPair};
use yggdrasil_proto::wire::{self, SessionId};

/// Build an established session pair for the AEAD benches. Returns (client, server).
fn established_pair() -> (Session, Session) {
    let server = StaticKeyPair::generate().unwrap();
    let client = StaticKeyPair::generate().unwrap();
    let sid = SessionId::random();
    let (init, hs1) = Initiator::start(&client, server.public_key(), sid).unwrap();
    let view = wire::parse(&hs1).unwrap();
    let half = Responder::process_handshake_1(&server, &view).unwrap();
    let (server_session, hs2) = half.complete().unwrap();
    let view2 = wire::parse(&hs2).unwrap();
    let client_session = init.complete(&view2).unwrap();
    (client_session, server_session)
}

fn bench_handshake(c: &mut Criterion) {
    let server = StaticKeyPair::generate().unwrap();
    let client = StaticKeyPair::generate().unwrap();
    let server_pub = *server.public_key();

    let mut group = c.benchmark_group("handshake");
    group.throughput(Throughput::Elements(1));
    group.bench_function("full", |b| {
        b.iter(|| {
            let sid = SessionId::random();
            let (init, hs1) = Initiator::start(&client, &server_pub, sid).unwrap();
            let v1 = wire::parse(&hs1).unwrap();
            let half = Responder::process_handshake_1(&server, &v1).unwrap();
            let (server_session, hs2) = half.complete().unwrap();
            let v2 = wire::parse(&hs2).unwrap();
            let client_session = init.complete(&v2).unwrap();
            black_box((client_session, server_session));
        });
    });
    group.finish();
}

fn bench_aead(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead");
    group.throughput(Throughput::Bytes(64));

    group.bench_function("encrypt_64", |b| {
        let (mut client, _server) = established_pair();
        let mut counter: u64 = 0;
        b.iter(|| {
            counter = counter.wrapping_add(1);
            let (_c, packet) = client
                .encode_heartbeat(black_box(0x1122_3344_5566_7788), 0)
                .unwrap();
            black_box(packet);
        });
    });

    group.bench_function("decrypt_64", |b| {
        // Pre-generate a stream of heartbeats; the server-side session
        // expects strictly monotonic counters so we have to be careful not
        // to feed it the same packet twice.
        let (mut client, mut server) = established_pair();
        // Build a reasonably large pool of consecutive packets; iter_batched
        // would also work but this is simpler for criterion.
        let mut packets = Vec::with_capacity(10_000);
        for _ in 0..packets.capacity() {
            let (_c, p) = client.encode_heartbeat(0xdeadbeef, 0).unwrap();
            packets.push(p);
        }
        let mut idx = 0usize;
        b.iter(|| {
            let p = &packets[idx];
            idx += 1;
            if idx == packets.len() {
                // Refill the pool — we've drained the monotonic counter
                // window. Rebuild the session pair to reset replay state.
                let (c2, s2) = established_pair();
                client = c2;
                server = s2;
                packets.clear();
                for _ in 0..10_000 {
                    let (_c, p) = client.encode_heartbeat(0xdeadbeef, 0).unwrap();
                    packets.push(p);
                }
                idx = 0;
                return;
            }
            let view = wire::parse(p).unwrap();
            let decoded = server.decode_heartbeat(&view).unwrap();
            black_box(decoded);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_handshake, bench_aead);
criterion_main!(benches);
