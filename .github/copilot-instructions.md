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

Minimum toolchain: stable Rust ≥1.85, CI pins 1.95.0. No C dependencies or FFI.

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
- **Async runtime:** Tokio multi-thread. Cancellation via `tokio_util::CancellationToken`.
- **Config format:** TOML with `serde(deny_unknown_fields)`. Rules live in `conf.d/*.toml` fragments, watched and hot-reloaded with 250ms debounce.
- **Wire serialization:** `postcard` (binary, no-std friendly) for on-the-wire frames; `toml`/`serde_json` for operator-facing files.
- **Public key types:** Always use `ratatoskr::pubkey::PubKey` tagged enum. Future algorithm variants (`ed25519:`, `pq:`) are accommodated by the enum discriminator.
- **Metrics:** `metrics` crate facade with Prometheus text export over the UDS control socket (no separate HTTP listener).
- **Systemd integration:** `sd-notify` for readiness; the daemon is designed for `Type=notify` units.
- **Integration tests** in `crates/yggdrasil/tests/` drive the full server stack via public library APIs. Test helpers live in `tests/common/`.
- **Benchmarks:** Criterion benches in `crates/*/benches/`. CI runs them with `--quick` on every PR; serious numbers come from a self-hosted runner via `.github/workflows/bench.yml`.
