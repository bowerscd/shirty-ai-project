//! Branch-file parsing micro-benchmark.
//!
//! Run with `cargo bench -p yggdrasil-proto --bench branch_parse`.
//!
//! Generates synthetic branch TOML at three scales (1 / 10 / 100 rules) and
//! benchmarks `BranchFile::from_toml` followed by per-file validation. This
//! is the hot path on yggdrasil startup and on every hot-reload.
//!
//! Target SLO: ≤ 10 ms to parse + validate 100 rules.

use std::path::PathBuf;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use yggdrasil_proto::branch::{BranchFile, BranchSet};

fn synth_toml(n_rules: usize) -> String {
    let mut out = String::with_capacity(n_rules * 100);
    for i in 0..n_rules {
        let protocol = if i % 2 == 0 { "tcp" } else { "udp" };
        // Stay in the high port range to avoid privileged-port reservations
        // and keep the test bytes realistic.
        let port = 20_000 + i;
        out.push_str(&format!(
            "[[rule]]\nname = \"rule-{i}\"\nprotocol = \"{protocol}\"\nlisten = \"0.0.0.0:{port}\"\nupstream_port = {port}\n\n"
        ));
    }
    out
}

fn bench_branch_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("branch_parse");
    let path: PathBuf = "synthetic.toml".into();

    for &n in &[1usize, 10, 100] {
        let text = synth_toml(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &text, |b, text| {
            b.iter(|| {
                let f = BranchFile::from_toml(path.clone(), black_box(text)).unwrap();
                f.validate_each().unwrap();
                black_box(f);
            });
        });
    }
    group.finish();
}

fn bench_branch_set(c: &mut Criterion) {
    let mut group = c.benchmark_group("branch_set");
    let path: PathBuf = "synthetic.toml".into();

    for &n in &[1usize, 10, 100] {
        let text = synth_toml(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &text, |b, text| {
            b.iter(|| {
                let f = BranchFile::from_toml(path.clone(), text).unwrap();
                let set = BranchSet::from_files([f]).unwrap();
                black_box(set);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_branch_parse, bench_branch_set);
criterion_main!(benches);
