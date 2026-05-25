# Copilot Instructions — yggdrasil

## Build & Test

```bash
# Build the entire workspace
cargo build --workspace

# Run all tests (unit + integration)
cargo test --workspace --all-targets

# Run a single integration test by name
cargo test --package yggdrasil --test hot_reload

# Run a single unit test
cargo test --package ratatoskr -- wire::tests::round_trip

# Clippy (CI treats warnings as errors: RUSTFLAGS="-D warnings")
cargo clippy --workspace --all-targets --benches -- -D warnings

# Format check
cargo fmt --all -- --check

# Criterion micro-benches (quick mode, as CI runs them)
cargo bench --workspace --benches -- --quick --warm-up-time 1 --measurement-time 3

# E2E smoke tests (require podman-compose)
tests/e2e/run.sh        # 2-node
tests/e2e/run-chain.sh  # 3-node chain
tests/e2e/run-l7.sh     # L7 HTTP frontend
```

Minimum toolchain: Rust 1.95.0, pinned in `rust-toolchain.toml` and matched by CI. No C dependencies or FFI.

## Architecture

**One binary, three modes.** The `yggdrasil` daemon derives its mode from config section presence:

| Mode       | `[dial]` | `[accept]` | Role                     |
|------------|-----------|------------|--------------------------|
| Gateway    | absent    | present    | Root VPS, no upstream    |
| Relay      | present   | present    | Mid-chain forwarder      |
| Terminal   | present   | absent     | Home box / chain leaf    |

**Workspace crates:**

- `ratatoskr` (lib) — Protocol source of truth: wire format, Noise_IK auth (`snow` crate), control frames, rule/predicate schemas, enrollment documents, chain query envelopes. `#![forbid(unsafe_code)]`.
- `yggdrasil` (bin + lib) — The daemon. Structured as a library so integration tests and criterion benches can drive production types directly. Subsystems: `proxy/` (TCP/UDP/HTTP forwarding, cert management), `heartbeat/` (keepalive + IP tracking), `chain/` (acceptor/client), `rules/` (file watcher + hot reload), `control.rs` (UDS admin socket).
- `yggdrasilctl` (bin) — Admin CLI with scopes: `local`, `chain`, `identity`, `validate`.
- `bench-tools` (bins, workspace-internal) — Benchmark helpers used by `bench/`: `loadgen` (UDP/TCP load generator) and `bench-echo` (native tokio echo backend with `SO_REUSEPORT` fan-out, replacing the older Python echo scripts).

**Data flow:** Terminal publishes its rule set as predicates upstream over the Noise_IK control channel. Each relay derives TCP/UDP listeners from received predicates. Forwarded application traffic flows back down the chain. Heartbeats update IP mappings when the terminal's address changes.

**Crypto:** Noise_IK_25519_ChaChaPoly_BLAKE2s (same suite as WireGuard). Mutual static-key auth, no PKI. Keys are 64-byte files (32 secret + 32 public), mode 0600. Public keys use tagged form `x25519:<hex>` everywhere — bare hex is rejected.

## Conventions

- **Error handling:** `anyhow::Result` at binary boundaries; `thiserror` enums in library crates (`ratatoskr::Error`).
- **Async runtime:** Tokio multi-thread for everything *except* UDP frontend workers, which run on per-worker `current_thread` runtimes pinned to dedicated OS threads (see `proxy/udp/mod.rs::UdpProxy::spawn_with` — moved here in commit `2d9b135` to eliminate cross-worker futex notifications that dominated UDP RTT). The per-flow `upstream_to_client` tasks spawned from inside a UDP worker stay on that worker's runtime. Reaper / IP-change watcher / control-plane / heartbeat continue on the daemon's global multi-thread runtime. Cancellation via `tokio_util::CancellationToken`.
- **Config format:** TOML with `serde(deny_unknown_fields)`. Rules live in `conf.d/*.toml` fragments, watched and hot-reloaded with 250ms debounce.
- **Wire serialization:** `postcard` (binary, no-std friendly) for on-the-wire frames; `toml`/`serde_json` for operator-facing files.
- **Public key types:** Always use `ratatoskr::pubkey::PubKey` tagged enum. Future algorithm variants (`ed25519:`, `pq:`) are accommodated by the enum discriminator.
- **Metrics:** `metrics` crate facade with Prometheus text export over the UDS control socket (no separate HTTP listener).
- **Systemd integration:** `sd-notify` for readiness; the daemon is designed for `Type=notify` units.
- **Integration tests** in `crates/yggdrasil/tests/` drive the full server stack via public library APIs. Test helpers live in `tests/common/`.
- **Benchmarks:** Criterion benches in `crates/*/benches/`. CI runs them with `--quick` on every PR; serious numbers come from a self-hosted runner via `.github/workflows/bench.yml`.

## End-to-end bench harness (`bench/`)

Separate from the Criterion micro-benches. Compares yggdrasil head-to-head against nginx / haproxy / traefik on real proxied workloads.

**Scenarios:** `tcp-throughput`, `tcp-latency`, `tcp-connrate`, `tcp-idle-conns`, `udp-duplex`, `udp-pps`, `udp-flowchurn`, `udp-flows`, `http-rps`.

**Run a single scenario, position-corrected across N rotations:**
```bash
BENCH_DURATION=10s BENCH_ROTATIONS=5 BENCH_SCENARIOS="udp-duplex" bench/run-rotated.sh
python3 bench/compare.py --rotations bench/results/<sha>-rot*
```

**Subject naming is a load-bearing convention.** Apples-to-apples requires matching hop count:
- 1-hop: `yggdrasil-terminal` vs `nginx` / `haproxy` / `traefik`.
- 2-hop chain: `yggdrasil-chain` vs `nginx-chain` / `haproxy-chain` / `traefik-chain`.
- `direct` is a no-proxy ceiling — **not** a comparison subject. Comparing yggdrasil to `direct` is not meaningful; comparing yggdrasil-terminal to yggdrasil-chain to its corresponding peer-chain *is*.

Position correction matters: single-run bench numbers exhibit ~25–70% run-order bias against the first subject (TCP TIME_WAIT, ARP cache, etc.). Always use `bench/run-rotated.sh` (≥3 rotations) and `compare.py --rotations` for any claim that influences a commit decision.

## Performance investigation tooling

Three complementary measurement surfaces:

| signal               | tool                                                         | tells you                                                |
|----------------------|--------------------------------------------------------------|----------------------------------------------------------|
| syscall mix + counts | `strace -c -f -o file <yggdrasil>` (launch under strace; signal the *tracee's* PID, not strace's, so the summary flushes) | how many recvmmsg / sendmmsg / futex / epoll_wait calls, total per-syscall time, EAGAIN ratio |
| CPU flame, leaf-attributed | `bench/profile.sh <scenario> [--pprof]` → `go tool pprof -top` | which kernel leaf (epoll_wait / recvmmsg / sendmmsg / send / clock_gettime / …) consumes which % of CPU |
| per-section userspace timing | `crate::profile::section("subsystem", "name")` RAII guard, scrape `yggdrasil_hot_section_seconds{subsystem,section}` | which Rust code block consumes which µs (the layer pprof can't reach because sigprof unwinding dies at the syscall boundary) |

The profiler is **dev-only** behind the `profile` Cargo feature. Production builds compile the entire `profile` module + every `section()` call out to nothing. `bench/profile.sh` rebuilds with `--features profile` + `RUSTFLAGS="-C force-frame-pointers=yes"`, captures, then rebuilds without the feature so subsequent un-profiled runs use the unmodified binary.

## Performance-work guardrails (learned the hard way)

When considering a UDP / HTTP / hot-path optimisation:

1. **Measure before theorising.** Subtracting a guessed syscall time from a measured section time and calling the remainder "tokio overhead" is unreliable: actual loopback sendto is 5–10 µs (varies by config) and the tokio wrapper is ~1 µs, *not* the inverse. Get the syscall time from `strace -c` on the same config you're trying to optimise.

2. **Check the precondition before designing the optimisation.** Batching optimisations (recvmmsg/sendmmsg coalescing, busy-loop drains) all depend on queue depth > 1. At ≤ 1 kpps/flow on loopback, recvmmsg returns 1 datagram per call — verifiable by `strace -c` showing `recvmmsg_calls ≈ datagrams`. Optimisations that batch nothing add overhead with no benefit.

3. **"Kernel docs recommend it" is not justification by itself.** `SO_BUSY_POLL=50` is widely recommended for latency-sensitive UDP. In our test workload it cost 20 % CPU for zero measurable latency improvement (kernel busy-spins 50 µs on every EAGAIN, and our PPS hits EAGAIN often). Always do the A/B in your own workload.

4. **Sub-noise wins are not wins.** Bench run-to-run noise on udp-duplex p50 is ~3–5 µs. A 1 µs section-histogram improvement that doesn't move the bench p50 above noise is a code-complexity tax, not progress. Hold the same standard for adds *and* keeps as for reverts.

5. **The 1P-only constraint has a measured ceiling on the UDP datapath.** After commit `2d9b135` (per-worker `current_thread` runtimes) closed the futex-domain gap, the remaining ~25 µs to nginx single-hop udp-duplex p50 lives inside tokio's send/recv state machine, `metrics`-crate label resolution, and `Arc` atomic ops. Material further reduction requires bypassing tokio's I/O subsystem (raw epoll loop or `tokio-uring`) — an architectural decision, not a micro-optimisation. Don't burn cycles chasing sub-µs UDP wins with the current architecture; pick the structural change deliberately.

## HTTPS / L7 gotchas

- `cert = "ephemeral"` (route-level) is **only valid for `localhost`, `*.localhost`, or `*.local` hostnames** (validator enforces this). For bench scenarios point loadgen at `https://localhost:<port>/` and let it resolve to 127.0.0.1. For prod, use `cert = "/path/to/leaf.pem"` (with separate key) or `cert = "acme"`.
- HTTPS rules auto-spawn an HTTP→HTTPS redirect listener on the rule's IP at port 80 (RFC 7230 standard). Unprivileged daemons (no `CAP_NET_BIND_SERVICE`) need `[server].http_redirect_port = <high-port-or-0>` or the rule fails to start with `bind :80 permission denied`. `0` selects an ephemeral kernel-assigned port — used by bench harness, fine for dev/containers.
