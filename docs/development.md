# Development

Onboarding doc for engineers new to the yggdrasil codebase. Read this *after*
[README.md](../README.md) and [docs/quickstart.md](quickstart.md) — those tell
you what yggdrasil *is* and how to deploy it. This page tells you how to
*work on it*.

For the conventions that govern *how* PRs land (commit style, the
fmt/clippy/test gate), see [CONTRIBUTING.md](../CONTRIBUTING.md). This page
focuses on the code and the dependencies behind it.

## 1. Setup

### System dependencies

The workspace is pure Rust — no C toolchain, no `bindgen`, no native libs to
link. The only system-level packages you need are:

```bash
# Debian / Ubuntu
sudo apt-get install -y pkg-config podman-compose

# Fedora / RHEL
sudo dnf install -y pkg-config podman-compose
```

`pkg-config` is consulted by a couple of transitive build scripts.
`podman-compose` is only needed if you want to run the e2e smoke tests under
[`tests/e2e/`](../tests/e2e/) locally; unit and integration tests don't need
it.

### Rust toolchain

Install via [rustup](https://rustup.rs). The repo pins the exact toolchain
in `rust-toolchain.toml` (currently `1.95.0`), so cargo will fetch and use
that version automatically — you don't need to manage versions by hand.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### First build + smoke test

```bash
git clone https://github.com/bowerscd/yggdrasil
cd yggdrasil
cargo build --workspace                # warms the dep cache; ~3-5 min cold
cargo test  --workspace --all-targets  # ~2-3 min; should be all-green

# Optional: end-to-end smoke under podman-compose.
tests/e2e/run.sh                       # 2-node (relay + terminal)
```

If `cargo test` is green and `tests/e2e/run.sh` exits 0, you have a working
dev environment. From here, the [`docs/quickstart.md`](quickstart.md)
walkthrough deploys a real two-host topology against the binary you just
built.

## 2. Codebase tour

### Suggested reading order

1. [`README.md`](../README.md) — what the project is, in one screen.
2. [`docs/quickstart.md`](quickstart.md) — deploy a working two-host setup.
   Don't skip this; everything below assumes you've *seen the thing work*.
3. [`docs/architecture.md`](architecture.md) — why the design looks the way
   it does (chain plane, predicate projection, half-close).
4. Run [`tests/e2e/run.sh`](../tests/e2e/run.sh) and read it; it's the
   smallest exhaustive demonstration of "what good looks like."
5. [`crates/yggdrasil/src/main.rs`](../crates/yggdrasil/src/main.rs) →
   [`lib.rs`](../crates/yggdrasil/src/lib.rs). The binary entry point is
   thin; the subsystems are pub-exposed from the library so tests and
   benches can drive them directly.
6. Pick one rule and trace it end-to-end:
   - Terminal-side rule definition →
     [`crates/yggdrasil/src/rules/mod.rs`](../crates/yggdrasil/src/rules/mod.rs)
   - Predicate projection upstream →
     [`crates/yggdrasil/src/chain/predicate_publisher.rs`](../crates/yggdrasil/src/chain/predicate_publisher.rs)
   - Relay derives a listener →
     [`crates/yggdrasil/src/chain/derive.rs`](../crates/yggdrasil/src/chain/derive.rs)
   - Data plane forwards bytes →
     [`crates/yggdrasil/src/proxy/tcp.rs`](../crates/yggdrasil/src/proxy/tcp.rs)
     /
     [`udp/mod.rs`](../crates/yggdrasil/src/proxy/udp/mod.rs)

If you can sketch that flow on a whiteboard from memory, you understand the
core. Everything else (ACME, HTTP/3, NAT traversal) is bolted onto this
spine.

### Crates at a glance

| Crate           | Path                       | One-line                                                          |
| --------------- | -------------------------- | ----------------------------------------------------------------- |
| `yggdrasil`     | `crates/yggdrasil/`        | The daemon. Lib + bin. Subsystems: `chain/`, `proxy/`, `heartbeat/`, `rules/`, `control/`, `nat/`. |
| `ratatoskr`     | `crates/ratatoskr/`        | Protocol library. Wire format, Noise_IK auth, control frames, rule schema, predicate schema, enrollment documents. `#![forbid(unsafe_code)]`. |
| `yggdrasilctl`  | `crates/yggdrasilctl/`     | Admin CLI. Scopes: `local`, `chain`, `identity`, `validate`.       |
| `cli-defs`      | `crates/cli-defs/`         | Shared `clap`-derive command-tree structs. Lives separately so both bins *and* their `build.rs` scripts can introspect the same definitions when regenerating [`docs/cli-reference/`](cli-reference/). |
| `bench-tools`   | `crates/bench-tools/`      | Internal: `loadgen` (UDP/TCP load generator) and `bench-echo` (native echo backend) used by the [`bench/`](../bench/) harness. Not on crates.io. |

The **lib + bin split** in `yggdrasil` is deliberate. Integration tests in
`crates/yggdrasil/tests/` and Criterion benches in `crates/yggdrasil/benches/`
both drive production types via the public library API rather than spinning
up the binary under socket I/O. If you're adding a subsystem, expose it from
`lib.rs` so it's testable the same way.

### Auxiliary build infrastructure

- [`CMakeLists.txt`](../CMakeLists.txt) — **packaging frontend only**, not a
  development build system. Used by CPack to produce DEB/RPM artefacts in
  the [release workflow](../.github/workflows/). For day-to-day development
  use `cargo` directly.
- [`bench/`](../bench/) — apples-to-apples e2e benchmark harness against
  nginx / haproxy / traefik. Separate from Criterion micro-benches under
  `crates/*/benches/`. See [`bench/README.md`](../bench/README.md).
- [`tests/e2e/`](../tests/e2e/) — podman-compose smoke tests:
  `run.sh` (2-node), `run-chain.sh` (3-node), `run-l7.sh` (HTTPS),
  `run-acme.sh` (ACME issuance against pebble).
- [`contrib/`](../contrib/) — systemd unit, sysusers.d, tmpfiles.d, example
  config. Sourced by `CMakeLists.txt`; you generally don't touch these
  during feature work.

## 3. Dependency tour

For each load-bearing dependency: *what it is → how this codebase wires it
specifically → where in the tree → one external link.* Resist the urge to
re-teach the dep here; the external link is the canonical resource.

### `tokio` + `tokio-util` — async runtime

Almost the entire daemon runs on a Tokio multi-thread runtime. The one
exception is the UDP frontend, which uses per-worker `current_thread`
runtimes pinned to dedicated OS threads — see
[`crates/yggdrasil/src/proxy/udp/mod.rs`](../crates/yggdrasil/src/proxy/udp/mod.rs)
(`UdpProxy::spawn_with`). This split eliminates cross-worker futex
notifications that previously dominated UDP RTT (see §6 *Tokio runtime
layout* for the rationale). `tokio-util` is used for `CancellationToken`
and `TaskTracker` (graceful shutdown — §6 again).

New to async Rust? [Tokio tutorial](https://tokio.rs/tokio/tutorial)
chapters 1–5 cover the model.
[`tokio::runtime`](https://docs.rs/tokio/latest/tokio/runtime/index.html)
docs cover the multi-thread vs current-thread distinction.

### `snow` — Noise_IK handshake

Implements the chain handshake suite
`Noise_IK_25519_ChaChaPoly_BLAKE2s` — same as WireGuard. yggdrasil uses
it for mutual static-key authentication between adjacent chain hops; no
PKI, no SNI, no in-band key discovery. Each hop knows the next hop's
long-term public key out of band via the request/grant ceremony.
Integration lives in
[`crates/ratatoskr/src/auth.rs`](../crates/ratatoskr/src/auth.rs).

[Noise spec §5–7](https://noiseprotocol.org/noise.html#handshake-patterns)
covers the IK pattern; [`snow` crate docs](https://docs.rs/snow) cover
the API.

### `serde` + `postcard` + `toml` — serialisation

Three serde codecs, three purposes:

- **`postcard`** — binary, `no-std` compatible. Used for **every byte on
  the wire**: handshake frames, control envelopes, predicates,
  enrollment documents. See
  [`crates/ratatoskr/src/wire.rs`](../crates/ratatoskr/src/wire.rs) and
  [`control_frame.rs`](../crates/ratatoskr/src/control_frame.rs).
- **`toml`** — human-edited config (`/etc/yggdrasil/config.toml`,
  `conf.d/*.toml`). Every config struct uses
  `#[serde(deny_unknown_fields)]` so typos are hard parse errors.
- **`serde_json`** — operator-facing CLI output and a few
  state-persistence files. Never used on the wire.

[postcard format spec](https://postcard.jamesmunns.com/) /
[serde data model](https://serde.rs/data-model.html).

### `clap` (derive) + `cli-defs` crate

Both binaries (`yggdrasil`, `yggdrasilctl`) use `clap`'s derive macros.
The unusual bit: their **command-tree structs live in a separate crate**,
[`crates/cli-defs/`](../crates/cli-defs/). The reason is each bin's
`build.rs` script regenerates `docs/cli-reference/*.md` by introspecting
the clap structs, and `build.rs` is compiled as a separate compilation
unit that *cannot* reach into the bin's own modules.

Adding a new subcommand? Add it in `cli-defs` first, then the dispatch in
the bin. CI's `docs-cli-drift` job will fail if you change a flag
without committing the regenerated `docs/cli-reference/`.

[clap derive docs](https://docs.rs/clap/latest/clap/_derive/index.html).

### `tracing` + `tracing-subscriber` — structured logging

JSON-per-line by default; pretty/text format selectable via `--log-format
pretty` for interactive use. Verbosity controlled by `RUST_LOG`, e.g.
`RUST_LOG=yggdrasil=debug,ratatoskr=info,h2=warn`. The filter is **hot
swappable** at runtime over the control UDS — see
[`docs/operations.md` § Turning up verbose logging](operations.md). Setup
lives in
[`crates/yggdrasil/src/log.rs`](../crates/yggdrasil/src/log.rs).

[tracing crate docs](https://docs.rs/tracing/) cover spans and events;
[tracing-subscriber EnvFilter](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html)
covers the directive syntax.

### `hyper` + `tokio-rustls` + `rustls` + `rcgen` — L7 HTTPS frontend

HTTPS rules terminate TLS on the *terminal* node and parse HTTP/1.1 +
HTTP/2 in-process. `hyper` provides the HTTP state machines;
`tokio-rustls` is the async TLS wrapper around `rustls`. Certificates can
come from disk, an in-memory ephemeral self-signed CA generated via
`rcgen` (test fixtures and `cert = "ephemeral"`), or ACME (see
`instant-acme` below). The frontend lives in
[`crates/yggdrasil/src/proxy/http_frontend/`](../crates/yggdrasil/src/proxy/http_frontend/);
cert plumbing in
[`certs/`](../crates/yggdrasil/src/proxy/certs/).

[hyper docs](https://docs.rs/hyper/) /
[rustls docs](https://docs.rs/rustls/).

### `quinn` + `h3` + `h3-quinn` — HTTP/3 frontend

QUIC datagram transport (`quinn`) + HTTP/3 framing (`h3`) glued via
`h3-quinn`. HTTPS rules auto-enable HTTP/3 by default and advertise it
via `Alt-Svc`; the frontend lives in
[`crates/yggdrasil/src/proxy/h3_frontend.rs`](../crates/yggdrasil/src/proxy/h3_frontend.rs).
The same `rustls` cert plumbing as HTTP/1.1+2.

[quinn docs](https://docs.rs/quinn/) /
[h3 docs](https://docs.rs/h3/).

### `metrics` + `metrics-exporter-prometheus` — observability

`metrics` is a thin facade — call sites use `metrics::counter!{...}`,
`metrics::gauge!{...}`, `metrics::histogram!{...}` and never touch the
exporter directly. The Prometheus text exporter is served **over the
control UDS** (no separate HTTP listener); `yggdrasilctl local metrics`
emits the same text. See
[`crates/yggdrasil/src/metrics.rs`](../crates/yggdrasil/src/metrics.rs).

[metrics crate docs](https://docs.rs/metrics/).

### `notify` + `notify-debouncer-mini` — config hot reload

The rules watcher uses `notify` (inotify on Linux) wrapped in
`notify-debouncer-mini` with a 250 ms debounce window so a `git checkout`
swapping ten files in fast succession yields one reload, not ten. See
[`crates/yggdrasil/src/rules/watcher.rs`](../crates/yggdrasil/src/rules/watcher.rs).

[notify docs](https://docs.rs/notify/).

### `sd-notify` — systemd integration

`sd-notify` lets the daemon announce `READY=1` to systemd at the right
moment in startup (after listeners bind and the chain handshake
completes). The systemd unit in
[`contrib/systemd/yggdrasil.service`](../contrib/systemd/yggdrasil.service)
is `Type=notify`. See
[`crates/yggdrasil/src/systemd.rs`](../crates/yggdrasil/src/systemd.rs).

[sd-notify crate](https://docs.rs/sd-notify/) /
[`sd_notify(3)`](https://www.freedesktop.org/software/systemd/man/sd_notify.html).

### `instant-acme` + `hickory-resolver` + `x509-parser` — ACME issuance

ACME (RFC 8555) certificate issuance for HTTPS rules. `instant-acme`
drives the protocol; `hickory-resolver` is used for DNS-01 challenges
(checking propagation); `x509-parser` reads issued certs back for
metadata (expiry, SANs). Both HTTP-01 (any provider) and DNS-01
(Cloudflare today) are supported. Lives in
[`crates/yggdrasil/src/proxy/acme/`](../crates/yggdrasil/src/proxy/acme/).

[instant-acme docs](https://docs.rs/instant-acme/) /
[RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555).

### `dashmap` + `parking_lot` — concurrency primitives

`dashmap` is a sharded concurrent hash map; used in the UDP flow table
and the cert store. `parking_lot::Mutex`/`RwLock` replace `std::sync::*`
where contention matters. Avoid both unless you have a measured reason
— async-aware Tokio primitives (`tokio::sync::*`) are the default.

[dashmap docs](https://docs.rs/dashmap/) /
[parking_lot docs](https://docs.rs/parking_lot/).

### `anyhow` + `thiserror` — error model

Convention: `anyhow::Result` at binary boundaries (where context-chain
ergonomics matter and the consumer is human); `thiserror`-derived enums
in library crates (`ratatoskr::Error`, etc.) where typed errors are
matched programmatically. See §6 *Engineering conventions* for the full
rule.

[anyhow docs](https://docs.rs/anyhow/) /
[thiserror docs](https://docs.rs/thiserror/).

## 4. Glossary

Project-specific terms used throughout the docs and code. Industry-standard
terms (TLS, QUIC, HTTP/3, ACME, SO_REUSEPORT, etc.) are not redefined here.

- **Predicate** — a typed description of "a listener that would accept
  traffic for *this rule*" without specifying the implementation. The
  terminal projects its `RuleSet` into a `PredicateSet` and publishes that
  upstream; the relay derives an actual listener (TCP / UDP / HTTPS) from
  each predicate. See
  [`crates/ratatoskr/src/predicate.rs`](../crates/ratatoskr/src/predicate.rs).

- **Derived rule** — the rule a *relay* operates on, reconstructed from a
  downstream predicate. Contrast with a **`conf.d` rule fragment**, which is
  the operator-authored TOML file the *terminal* reads from disk. Relays
  don't (normally) read `conf.d/`; their rule set is whatever the
  downstream terminal published.

- **Predicate publisher** — terminal-side task that watches the rule
  supervisor for changes, projects to `PredicateSet`, and pushes upstream
  over the chain control channel. See
  [`chain/predicate_publisher.rs`](../crates/yggdrasil/src/chain/predicate_publisher.rs).

- **Predicate extractor** — the relay-side counterpart, called when a
  `PredicateSetUpdate` control frame arrives. See
  [`chain/predicate_extractor.rs`](../crates/yggdrasil/src/chain/predicate_extractor.rs).

- **Chain plane** (or **chain control plane**) — the Noise_IK-protected
  UDP transport between adjacent chain hops. Carries handshakes,
  heartbeats, predicate pushes, and `chain {summary,ping,diff,health}`
  queries. Does **not** carry forwarded application bytes (those go over
  separate per-rule data-plane sockets).

- **Mode** — `relay` or `terminal`. Derived at startup from config-section
  presence: `[dial]` only → terminal; `[accept]` only or `[accept]` +
  `[dial]` → relay. The daemon binary is the same.

- **`[accept]` / `[dial]` sections** — the two config tables that drive
  mode. `[accept]` configures the chain listener (relay-side); `[dial]`
  configures the chain client (terminal-side or mid-relay-side).

- **Request / grant ceremony** — the out-of-band enrollment handshake.
  The terminal emits a *request* file (its pubkey, fingerprint); the
  relay accepts it (`identity add-accept`) and emits a *grant* file
  (committing both pubkeys plus the relay's reachable endpoint); the
  terminal applies the grant (`identity add-dial`) to populate `[dial]`.
  See [`docs/security.md`](security.md) for the security analysis and
  [`docs/quickstart.md`](quickstart.md) for the operator walkthrough.

- **Enrollment** — the durable result of a successful request/grant
  exchange: both sides have each other's pinned long-term pubkeys and an
  endpoint to dial. After enrollment, IP changes on either side don't
  invalidate the trust relationship; only key rotation does. Enrollment
  documents live in
  [`crates/ratatoskr/src/enrollment.rs`](../crates/ratatoskr/src/enrollment.rs).

- **TOFU candidate** — a pubkey observed but not yet enrolled. A relay
  receiving an inbound handshake from an unknown pubkey records it as a
  candidate in `state_dir`; the operator decides whether to approve it via
  `yggdrasilctl accept pending` → `accept approve`. TOFU = Trust On First
  Use; we deliberately surface the choice rather than auto-trusting.

- **Heartbeat** — short authenticated UDP packet sent from terminal to
  relay (and at each subsequent hop) on a short interval (default ~2 s).
  Updates the relay's *downstream IP* mapping when the residential IP
  changes. Also the liveness signal — missing heartbeats trigger
  `degraded` health.

- **Rekey** — Noise session rekey, triggered before sequence-number
  exhaustion or on a time/byte budget. Transparent to upper layers.

- **Half-close** — TCP `shutdown(WR)` propagation across the chain. When
  the client closes its write half, the close is forwarded through each
  hop independently of the reverse direction, so a long-running upload
  that completes uploading but still wants to read response bytes works
  correctly. Implementation in
  [`proxy/forward.rs`](../crates/yggdrasil/src/proxy/forward.rs).

- **Alt-Svc** — RFC 7838 `Alt-Svc` header advertising HTTP/3 availability
  on the HTTP/1.1+2 listener. yggdrasil emits this automatically for any
  HTTPS rule with HTTP/3 enabled.

- **Canary** — chain self-test mechanism. `yggdrasilctl chain canary` arms
  a test packet at one hop and verifies it reaches the other end with the
  expected predicates / hop count. Distinct from production traffic.
  See
  [`crates/ratatoskr/src/canary.rs`](../crates/ratatoskr/src/canary.rs)
  and
  [`crates/yggdrasil/src/proxy/canary.rs`](../crates/yggdrasil/src/proxy/canary.rs).

## 5. Day-to-day workflow

### The local gate

Run before every push. CI runs the same commands with `RUSTFLAGS="-D
warnings"`; matching it locally avoids surprise red CI:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --benches -- -D warnings
cargo test  --workspace --all-targets
```

For changes touching CLI surfaces (`crates/cli-defs/`), also:

```bash
cargo build --workspace --locked         # build.rs regenerates docs/cli-reference/
git diff --exit-code -- docs/cli-reference/
```

CI's `docs-cli-drift` job fails if the regenerated files don't match
what's committed.

### Smallest-targeted-test selectors

`cargo test --workspace --all-targets` is the gate; while iterating, narrow
to one test for fast feedback:

```bash
# One integration test by file name (file = crates/yggdrasil/tests/hot_reload.rs)
cargo test --package yggdrasil --test hot_reload

# One unit test by module path
cargo test --package ratatoskr -- wire::tests::round_trip

# Show test output (default cargo swallows stdout for passing tests)
cargo test --package yggdrasil --test hot_reload -- --nocapture
```

### Verbose logging

`RUST_LOG` controls verbosity at startup; the value is a comma-separated
list of `crate=level` directives. Levels: `error < warn < info < debug <
trace`. Common patterns:

```bash
# Verbose for our crates, quiet for noisy transitive deps.
RUST_LOG=yggdrasil=debug,ratatoskr=debug,h2=warn,hyper=warn cargo run -- run --config ./config.toml

# Trace one module only.
RUST_LOG=yggdrasil::chain::predicate_publisher=trace cargo run -- run --config ./config.toml
```

Logs go to **stdout** when run via `cargo run`. When run under systemd
(production install), `journalctl -u yggdrasil` captures the same stream
— JSON-per-line, so pipe through `jq` for readability:

```bash
sudo journalctl -u yggdrasil --output=cat | jq -r '"\(.timestamp) [\(.level)] \(.target): \(.fields.message // .message)"'
```

### Hot-swapping the log filter on a running daemon

You don't need to restart to chase a transient issue — see
[`docs/operations.md` § Turning up verbose logging on a live daemon](operations.md).
TL;DR: `yggdrasilctl local log set-filter 'yggdrasil::chain=trace'`,
revert with `yggdrasilctl local log reset`.

### rust-analyzer

The workspace works out of the box with `rust-analyzer` (no per-crate
`rust-project.json` needed). One config tweak worth setting in your
editor (VS Code shown; equivalent settings exist for other editors):

```json
{
  "rust-analyzer.cargo.allTargets": true,
  "rust-analyzer.check.command": "clippy",
  "rust-analyzer.check.extraArgs": ["--", "-D", "warnings"]
}
```

This makes inline diagnostics match what CI runs.

### Debuggers

`gdb` and `lldb` both work on release-with-debuginfo builds. To get
symbols in a release build, override the profile temporarily:

```bash
RUSTFLAGS="-C debuginfo=2" cargo build --release -p yggdrasil
rust-gdb target/release/yggdrasil
```

For attach-to-running:

```bash
sudo gdb -p $(systemctl show -p MainPID --value yggdrasil)
```

Note: tokio tasks aren't first-class stack frames; you'll see worker
threads parked in `epoll_wait` more often than not. For "where is time
going" questions, prefer the profiling workflow in
[`docs/operations.md`](operations.md) over interactive debugger sessions.

### Disk-space guardrails

The workspace's `target/` directory can balloon to **100+ GB** on a dev
machine that benchmarks regularly. Three multiplicative factors:

1. `[profile.release]` and `[profile.bench]` use LTO + `codegen-units = 1`,
   which keep per-dep LLVM bitcode artefacts that are individually huge.
2. Feature-toggle rebuilds duplicate the dep graph. `bench/profile.sh`
   builds with `--features profile` (adds `pprof`), then rebuilds without
   it. Cargo keeps **both** feature-set graphs alive in
   `target/release/deps/` — there's no GC.
3. Cargo never deletes stale artefacts from old commits; they accumulate
   forever.

Rules that prevent this:

- **Never `COPY . .` in a Dockerfile/Containerfile without a
  `.dockerignore` that excludes `target/`.** The build-context preflight
  reads every byte; 100 GB of `target/` will fill the engine's storage
  driver before the first layer runs. The repo's
  [`.dockerignore`](../.dockerignore) is correct — extend it in the same
  commit if you add new large output trees (e.g. a new `dist/`, `out/`,
  or per-sha results dir).
- **Feature-toggle scripts must isolate their target dir.** `bench/profile.sh`
  sets `CARGO_TARGET_DIR=$REPO/bench/target-profile` for the feature-on
  build; clean independently with `rm -rf bench/target-profile`.
- **Periodic cleanup is on you, not cargo.** Install once:
  `cargo install cargo-sweep`. Reap stale artefacts:
  `cargo sweep -t 30` (drops anything not touched in 30 days). For full
  reset: `rm -rf target/ bench/target-profile/` (both gitignored).

Heuristic: if you happen to notice `target/` over ~30 GB, run
`cargo sweep -t 30` before your next heavy compile session. Don't poll
`du -sh target/` ritualistically — that's the smell, not the fix.

## 6. Engineering conventions

This section is the project's accumulated wisdom from real production
incidents and bench investigations. New contributors should read it before
their first non-trivial PR.

### 6.1 Performance-work guardrails

When considering a UDP / HTTP / hot-path optimisation, five rules learned
the hard way:

1. **Measure before theorising.** Subtracting a guessed syscall time from a
   measured section time and calling the remainder "tokio overhead" is
   unreliable. Get the syscall time from `strace -c -f` on the same config
   you're trying to optimise. Three complementary surfaces:

   | signal                       | tool                                                        | what it tells you                                                                            |
   | ---------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
   | syscall mix + counts         | `strace -c -f -o file <yggdrasil>` (signal the *tracee's* PID, not strace's, so the summary flushes) | how many `recvmmsg` / `sendmmsg` / `futex` / `epoll_wait` calls, total per-syscall time, EAGAIN ratio |
   | CPU flame, leaf-attributed   | `bench/profile.sh <scenario> [--pprof]` → `go tool pprof -top` | which kernel leaf (`epoll_wait` / `recvmmsg` / `sendmmsg` / `send` / `clock_gettime` / …) consumes which % of CPU |
   | per-section userspace timing | `crate::profile::section("subsystem", "name")` RAII guard, scrape `yggdrasil_hot_section_seconds{subsystem,section}` | which Rust code block consumes which µs (the layer pprof can't reach because sigprof unwinding dies at the syscall boundary) |

2. **Check the precondition before designing the optimisation.** Batching
   wins (`recvmmsg`/`sendmmsg` coalescing, busy-loop drains) all depend on
   queue depth > 1. At ≤ 1 kpps/flow on loopback, `recvmmsg` returns one
   datagram per call — verifiable by `strace -c` showing `recvmmsg_calls ≈
   datagrams`. Optimisations that batch nothing add overhead with no
   benefit.

3. **"Kernel docs recommend it" is not justification by itself.**
   `SO_BUSY_POLL=50` is widely recommended for latency-sensitive UDP. In
   our test workload it cost 20 % CPU for zero measurable latency
   improvement (the kernel busy-spins 50 µs on every EAGAIN, and our PPS
   hits EAGAIN often). Always do the A/B in your own workload.

4. **Sub-noise wins are not wins.** Bench run-to-run noise on `udp-duplex`
   p50 is ~3–5 µs. A 1 µs section-histogram improvement that doesn't move
   the bench p50 above noise is a code-complexity tax, not progress. Hold
   the same standard for *adds* and *keeps* as for *reverts*.

5. **The single-process UDP datapath has a measured Tokio ceiling.** After
   the per-worker `current_thread` runtime split (§6.3) closed the
   futex-domain gap, the remaining ~25 µs to nginx single-hop `udp-duplex`
   p50 lives inside tokio's send/recv state machine, `metrics`-crate label
   resolution, and `Arc` atomic ops. Material further reduction requires
   bypassing tokio's I/O subsystem (raw `epoll` loop or `tokio-uring`) —
   an architectural decision, not a micro-optimisation. Don't burn cycles
   chasing sub-µs UDP wins with the current architecture; pick the
   structural change deliberately.

See also [`bench/README.md`](../bench/README.md) for the
position-corrected rotation harness — apples-to-apples bench numbers
require ≥ 3 rotations because single-run order bias is 25–70 %.

### 6.2 Two-token graceful-shutdown pattern

When adding a new component with an accept-loop + per-connection tasks
(future protocol frontends, new acceptors), implement graceful drain with
**two `CancellationToken`s plus a `tokio_util::task::TaskTracker`**:

| token / type                       | observed by                          | semantics                                              |
| ---------------------------------- | ------------------------------------ | ------------------------------------------------------ |
| `accept_cancel: CancellationToken` | accept loop's `tokio::select!`       | "stop accepting new connections"                       |
| `conn_cancel:   CancellationToken` | per-conn task's `tokio::select!`     | "tear down in-flight conversation"                     |
| `conn_tracker:  TaskTracker`       | parent `stop()` method               | counts in-flight per-conn tasks for the drain wait     |

A single cancel token *does not work* — the per-connection task observing
the same cancel as the accept loop means cancelling accept also instantly
kills in-flight conversations, defeating drain entirely.

Canonical implementation:
[`crates/yggdrasil/src/proxy/tcp.rs`](../crates/yggdrasil/src/proxy/tcp.rs)
`TcpProxy::stop`. Sequence:

1. `accept_cancel.cancel()` — accept loops exit immediately.
2. Await accept-worker join handles.
3. `conn_tracker.close()` (so `wait()` can resolve when count hits 0).
4. `tokio::time::timeout(drain_timeout, conn_tracker.wait())` — drain
   naturally up to budget.
5. If the timeout fired: `conn_cancel.cancel()` plus a short final
   `timeout(_, conn_tracker.wait())` for cancelled tasks to wind down.
6. With `drain_timeout = None`: skip 4–5 and fire `conn_cancel`
   immediately — preserves the historical abrupt-stop behaviour
   byte-for-byte.

`tokio_util` is already a workspace dep with the `rt` feature, so
`TaskTracker` is available everywhere proxy code lives.

### 6.3 Tokio runtime layout

Almost everything runs on the daemon's global multi-thread runtime.
**Except UDP frontend workers**, which run on per-worker `current_thread`
runtimes pinned to dedicated OS threads. The split lives in
[`crates/yggdrasil/src/proxy/udp/mod.rs`](../crates/yggdrasil/src/proxy/udp/mod.rs)
(`UdpProxy::spawn_with`). It exists because cross-worker futex
notifications previously dominated UDP RTT — moving each worker to its
own runtime eliminates the wake-other-worker futex hop and gave a
measurable p50 improvement.

Per-flow `upstream_to_client` tasks spawned from inside a UDP worker
**stay on that worker's runtime** (they `tokio::spawn` on the
`current_thread`'s LocalSet equivalent, not the global runtime). Reaper,
IP-change watcher, control plane, heartbeat, and everything else
continue on the multi-thread runtime.

Cancellation throughout is via
`tokio_util::sync::CancellationToken`.

### 6.4 Error-handling convention

- **`anyhow::Result` at binary boundaries.** `main`, top-level CLI
  dispatch, `run_relay` / `run_terminal`, anything where the consumer is
  a human reading a log or CLI output and wants
  `.context("while loading config")?` chains.
- **`thiserror`-derived enums in library crates.** `ratatoskr::Error` is
  the canonical example: typed variants that callers match on
  programmatically. `#[from]` conversions are fine for transparent
  wrapping; avoid `#[error(transparent)]` for variants whose context the
  caller will actually want to log.

The boundary is "is the caller going to *match* on this, or *display* it
and move on?" Match → `thiserror`. Display → `anyhow`.

### 6.5 PubKey convention

Always use the tagged
[`ratatoskr::pubkey::PubKey`](../crates/ratatoskr/src/pubkey.rs) enum
for any public key crossing a serde boundary. Textual form is
`<algo>:<hex>` everywhere — `x25519:6c5a…0ff1`. **Bare hex without the
`x25519:` prefix is rejected on parse.**

The enum exists so future algorithm variants (`ed25519:`, post-quantum
KEMs) can land without a wire-format break or a TOML schema churn. New
code that writes a `[u8; 32]` directly into a config or wire frame is
wrong; route it through `PubKey`.

### 6.6 Operator-surface design rule

Runtime-state operations belong on the **signal-handler path**, not in
`yggdrasilctl`. The CLI is for:

- **Introspection** (read-only): `local status`, `local metrics`,
  `local health`, `local derived-rules`, `chain {summary,ping,health,diff}`.
- **One-shot config-file mutations** (operator-managed state, not daemon
  runtime): `identity rotate`, `accept approve`, `accept pending`.

Things that affect what the running daemon is *doing* hook signals:

| signal           | semantics                                                                                                                                |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `SIGTERM` / `SIGINT` | Stop the daemon (optionally with `[server].graceful_drain_timeout`). Any "drain X before quitting" knob goes through here, not a CLI verb. |
| `SIGHUP`         | Reload runtime config / rules. Existing rule-watcher reload path; the right home for any future hot-reloadable setting (live key rotation, drain-timeout adjustment, log-level reset). |

The reasoning: `systemctl stop yggdrasil` is the operator's existing exit
path. Making graceful drain a *property* of that signal means the operator
doesn't have to remember a separate runbook step. The TOML knob is the
only operator-facing surface. Don't add CLI commands for things that
should "just work" on Unix process lifecycle.

## Further reading

- [`docs/architecture.md`](architecture.md) — the design itself.
- [`docs/security.md`](security.md) — threat model and crypto.
- [`docs/operations.md`](operations.md) — runbook for deployed chains
  (metrics, log filter live-reload, profiling workflow).
- [`docs/configuration.md`](configuration.md) — every config field.
- [`docs/cli-reference.md`](cli-reference.md) — every CLI verb.
- [`bench/README.md`](../bench/README.md) — the e2e benchmark harness.
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) — fmt / clippy / test gate, PR
  conventions, commit style.
