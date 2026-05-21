# Yggdrasil bench harness

End-to-end benchmark suite that compares **yggdrasil** against **nginx** (stream module) and a **direct** baseline. Each scenario emits a JSON report under `bench/results/<git-sha>/<scenario>-<subject>.json`. `bench/compare.py` diffs two such trees and gates regressions.

## Why nginx?

nginx is the only widely-deployed L4 reverse proxy with comparable feature surface (TCP+UDP stream proxying, hot reload). It is the de-facto incumbent, and we should not claim "production-grade" without showing we are within a small constant of its performance on the same workload. The plan's acceptable-delta budget vs nginx (Phase 11.5):

| Scenario          | Metric           | Yggdrasil must be within |
| ----------------- | ---------------- | ------------------------ |
| `tcp-throughput`  | bytes/sec        | **−10 %**                |
| `tcp-connrate`    | conns/sec        | **−25 %**                |
| `tcp-idle-conns`  | proxy PSS KiB    | **≤ 2× nginx**          |
| `udp-pps`         | pkts/sec         | **−20 %**                |
| `udp-flows`       | pkts/sec         | **−20 %**                |
| `udp-flowchurn`   | new-flows/sec    | **−20 %**                |
| (all latency)     | p99              | **≤ 2× nginx**           |

`compare.py --check-nginx` enforces these budgets and exits 1 on violation.

The `direct` leg (loadgen → echo with no proxy in between) bounds what the kernel + echo backend can deliver in principle — useful for spotting cases where *both* proxies are bottlenecked on the harness, not the system under test.

## Prerequisites

This harness is **Linux-only** (Linux loopback semantics, `/sys/devices/system/cpu`, `ss`). On the host that will run it:

- `bash`, `python3 ≥ 3.8`, `ss` (iproute2), `git`
- The yggdrasil workspace toolchain (`rustup show` matches `rust-toolchain.toml`)
- `nginx` ≥ 1.18 with the `stream` module (Ubuntu/Debian: `apt install nginx`; Arch: `pacman -S nginx-mainline`). Set `BENCH_NGINX=/path/to/nginx` if it's not on `$PATH`.

### Host preparation for trustworthy numbers

Run these before each bench session — they materially affect the absolute numbers:

```bash
# Pin CPU frequency at max (the most impactful single tweak).
sudo cpupower frequency-set -g performance

# Generous socket buffers so neither stack stalls on a small SO_*BUF.
sudo sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216

# Wider ephemeral port range so connrate tests don't exhaust ports.
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"
sudo sysctl -w net.ipv4.tcp_tw_reuse=1

# Stop everything noisy (your editor, browser, …) — even on loopback,
# CPU contention shows up in p99.
```

`bench/collect-env.sh` records the resulting state into every result tree so you can spot a misconfigured host after the fact.

## Running

```bash
# Build once, then run the full matrix.
cargo build --release -p yggdrasil -p yggdrasilctl -p bench-tools
bench/run-all.sh
```

Or run a single scenario:

```bash
bench/udp-pps.sh
bench/tcp-throughput.sh
```

Override defaults via env vars (each script documents which it reads):

```bash
BENCH_DURATION=30s BENCH_PPS=200000 bench/udp-pps.sh
BENCH_SCENARIOS="udp-pps tcp-latency" bench/run-all.sh
```

Results land under `bench/results/<short-sha>/`. To benchmark uncommitted work, pass `BENCH_SHA=local-wip` or similar.

## Comparing two runs

```bash
# Regression gate: candidate must not be more than 5% worse on any metric.
bench/compare.py bench/results/abc1234 bench/results/def5678

# Per-PR CI use: also enforce the nginx delta budget table above.
bench/compare.py --check-nginx bench/results/main bench/results/HEAD
```

Exit codes:

- `0` — no regression beyond `--fail-on-regress` (default 5 %) and (if `--check-nginx`) within the budget table
- `1` — at least one regression or budget violation
- `2` — input error (missing dir, malformed JSON)

## Scenario catalogue

| Script               | Subjects                  | What it measures                                                |
| -------------------- | ------------------------- | --------------------------------------------------------------- |
| `udp-pps.sh`         | direct, yggdrasil, nginx  | single-flow UDP RTT & pps; sniff-test for per-packet overhead   |
| `udp-flows.sh`       | direct, yggdrasil, nginx  | 100 k concurrent flows; flow-table scaling                      |
| `udp-flowchurn.sh`   | direct, yggdrasil, nginx  | sustained new-flow rate; per-flow setup cost                    |
| `tcp-latency.sh`     | direct, yggdrasil, nginx  | TCP ping-pong p50/p99/p99.9                                     |
| `tcp-throughput.sh`  | direct, yggdrasil, nginx  | bulk TCP MB/s with a handful of streams                         |
| `tcp-connrate.sh`    | direct, yggdrasil, nginx  | TCP handshake rate (connect + close)                            |
| `tcp-idle-conns.sh`  | direct, yggdrasil, nginx  | proxy PSS while holding N idle TCP conns (per-conn memory cost) |
| `reload-latency.sh`  | yggdrasil, nginx          | time from "config dropped" to "new listener serves a request"   |

A future `heartbeat-roundtrip.sh` (yggdrasil-only — nginx has no analogous heartbeat) is tracked under Phase 12.

## How each leg works

For each non-direct subject, the harness:

1. Spawns the native `bench-echo` Rust binary on `127.0.0.1:<echo_port>`.
   By default it binds one listener per core via `SO_REUSEPORT`, so the
   backend has plenty of headroom and never bottlenecks the proxy under
   test.
2. Renders a fresh config + identity into a `mktemp -d` workspace:
   - **yggdrasil**: spins two `yggdrasil` daemons on loopback — a
     gateway (accept-mode) and a terminal (dial-mode). Identities are
     minted with `yggdrasilctl identity rotate` and wired together via
     the offline `identity export-request` → `identity add-accept`
     → `identity add-dial` handshake. The terminal owns the rule
     set; the gateway derives a matching listener from the chain
     predicate published over the dial session. The bench rule uses
     the current `target_addr = "127.0.0.1:<echo_port>"` schema.
   - **nginx**: a minimal `stream { server { listen <listen>; proxy_pass 127.0.0.1:<upstream>; [udp;] } }` config, started with `nginx -p $tmp -c $tmp/nginx.conf -g 'daemon off;'`.
3. Runs `loadgen` against `127.0.0.1:<listen_port>` (or `<echo_port>` for the direct leg).
4. SIGTERMs everything, removes the tmpdir, and pauses briefly to let TIME_WAIT clear before the next leg.

`bench/lib/common.sh` provides all the orchestration primitives. The per-scenario scripts are intentionally thin wrappers so a contributor can add a new scenario by copying an existing one.

## Known caveats

- 127.0.0.1 loopback bypasses the NIC entirely, so we are measuring per-packet overhead, scheduling, and userspace cost — *not* anything network-stack-bound. To exercise the NIC, replace `127.0.0.1` targets with a host on a separate kernel and rerun.
- nginx's per-config-reload cost includes a full worker fork; yggdrasil's includes filesystem inotify debounce. Both are realistic for their respective hot-reload models, but the absolute numbers are not directly comparable beyond an order-of-magnitude.
- `bench/collect-env.sh` records governor + sysctls but does **not** refuse to run on a misconfigured host. Check `env.json` before trusting the numbers.

## Adding a new scenario

1. Copy the closest existing script (e.g. `bench/tcp-latency.sh`) to `bench/<new>.sh`.
2. Adjust `SCENARIO=`, the loadgen subcommand, and any tunables.
3. Add the scenario name to the `SCENARIOS` array in `bench/run-all.sh`.
4. If the metric needs a new comparison rule, extend `HIGHER_BETTER`/`LOWER_BETTER`/`NGINX_DELTA_BUDGET` in `bench/compare.py`.
