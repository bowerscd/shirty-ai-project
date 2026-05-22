# Yggdrasil bench harness

End-to-end benchmark suite that compares **yggdrasil** (both as a single-hop terminal and as a full gateway→terminal chain) against **nginx** (stream module), **HAProxy**, and **Traefik** — each in single-hop and chained variants — plus a **direct** baseline. Each scenario emits a JSON report under `bench/results/<git-sha>/<scenario>-<subject>.json`. `bench/compare.py` diffs two such trees and gates regressions.

## Subjects

Every scenario runs against up to nine subjects so the topology counts match in comparisons (chain vs chain, single hop vs single hop):

| Subject | Hops | Topology | TCP | UDP |
| --- | --- | --- | --- | --- |
| `direct` | 0 | loadgen → echo | ✓ | ✓ |
| `yggdrasil-terminal` | 1 | loadgen → yggdrasil terminal → echo | ✓ | ✓ |
| `yggdrasil-chain` | 2 | loadgen → gateway → terminal → echo | ✓ | ✓ |
| `nginx` | 1 | loadgen → nginx → echo | ✓ | ✓ |
| `nginx-chain` | 2 | loadgen → outer nginx → inner nginx → echo | ✓ | ✓ |
| `haproxy` | 1 | loadgen → haproxy → echo | ✓ | — |
| `haproxy-chain` | 2 | loadgen → outer haproxy → inner haproxy → echo | ✓ | — |
| `traefik` | 1 | loadgen → traefik → echo | ✓ | ✓ |
| `traefik-chain` | 2 | loadgen → outer traefik → inner traefik → echo | ✓ | ✓ |

HAProxy 3.x has no `mode udp`, so it sits out the three UDP scenarios in both variants. Traefik supports both protocols at L4, so it covers everything.

## Why these peers?

Each is a widely-deployed L4 reverse proxy and the de-facto incumbent we have to be within a small constant of to claim "production-grade":

* **nginx** stream module — TCP + UDP stream proxying, hot reload via `nginx -s reload`. The original mainstream OSS L4 proxy with UDP support.
* **HAProxy** — TCP-only at L4 (`mode tcp`). Renowned for its TCP performance and per-connection memory footprint, which makes it a tougher comparison than nginx on those axes.
* **Traefik** — Go, dynamic-first design, TCP + UDP at L4 (since v2.0). Different runtime/model than the C-based incumbents; included to broaden the UDP comparison beyond nginx and to triangulate per-hop costs against a Go event loop.

Why two variants each? Yggdrasil's headline shape is a chain (gateway on a VPS dialing a terminal at home). Comparing chain-mode yggdrasil to a single nginx process gives yggdrasil two proxy hops while nginx has one — apples vs oranges. The `-chain` variants put the same number of hops on both sides for an honest comparison.

The plan's acceptable-delta budgets (Phase 11.5) apply per-hop:

| Scenario          | Metric           | vs nginx*         | vs HAProxy*       | vs Traefik*       |
| ----------------- | ---------------- | ----------------- | ----------------- | ----------------- |
| `tcp-throughput`  | bytes/sec        | **−10 %**         | **−10 %**         | **−10 %**         |
| `tcp-connrate`    | conns/sec        | **−25 %**         | **−25 %**         | **−25 %**         |
| `tcp-idle-conns`  | proxy PSS KiB    | **≤ 2× peer**     | **≤ 2× peer**     | **≤ 2× peer**     |
| `udp-pps`         | pkts/sec         | **−20 %**         | n/a — no UDP      | **−20 %**         |
| `udp-flows`       | pkts/sec         | **−20 %**         | n/a — no UDP      | **−20 %**         |
| `udp-flowchurn`   | new-flows/sec    | **−20 %**         | n/a — no UDP      | **−20 %**         |
| (all latency)     | p99              | **≤ 2× peer**     | **≤ 2× peer**     | **≤ 2× peer**     |

\*Each gate is enforced twice: 1-hop vs 1-hop (`yggdrasil-terminal` vs `nginx`/`haproxy`/`traefik`) and 2-hop vs 2-hop (`yggdrasil-chain` vs `nginx-chain`/`haproxy-chain`/`traefik-chain`).

`compare.py --check-nginx`, `--check-haproxy`, and `--check-traefik` enforce these budgets and exit 1 on violation. They can be combined.

> **Note — `reload-latency` has no nginx/HAProxy/Traefik leg.**
> Yggdrasil's rule hot-reload is driven by inotify with a 250 ms debounce
> window (so half-written / `cp`-streamed config drops don't trigger reload
> storms); `nginx -s reload` and `haproxy -sf` are operator-explicit IPCs
> with no debounce. Traefik does run a file watcher similar to yggdrasil's,
> but its rule shape is significantly different (full YAML reload vs
> per-fragment TOML drop-ins) so the comparison would still mislead. We
> run the scenario on every `bench/run-all.sh` invocation as a
> yggdrasil-only correctness and regression signal against previous yggdrasil runs.

The `direct` leg (loadgen → echo with no proxy in between) bounds what the kernel + echo backend can deliver in principle — useful for spotting cases where every proxy is bottlenecked on the harness, not the systems under test.

## Prerequisites

This harness is **Linux-only** (Linux loopback semantics, `/sys/devices/system/cpu`, `ss`). On the host that will run it:

- `bash`, `python3 ≥ 3.8`, `ss` (iproute2), `git`
- The yggdrasil workspace toolchain (`rustup show` matches `rust-toolchain.toml`)
- `nginx` ≥ 1.18 with the `stream` module (Ubuntu/Debian: `apt install nginx`; Arch: `pacman -S nginx-mainline`). Set `BENCH_NGINX=/path/to/nginx` if it's not on `$PATH`.
- `haproxy` ≥ 2.4 (Ubuntu/Debian: `apt install haproxy`; Arch: `pacman -S haproxy`). Set `BENCH_HAPROXY=/path/to/haproxy` if it's not on `$PATH`.
- `traefik` ≥ 3.0 (Ubuntu/Debian: `apt install traefik`; Arch: `pacman -S traefik`). Set `BENCH_TRAEFIK=/path/to/traefik` if it's not on `$PATH`.

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

### Criterion microbenches

Workspace Criterion benches live under `crates/*/benches/`. `crates/yggdrasil/benches/flow_table.rs` compares UDP flow-table insertion through the old single shared shard against the current per-worker-shard layout used by `UdpProxy`. `crates/yggdrasil/benches/h3_forward.rs` tracks HTTP/3 request-rewrite CPU cost (forwarding header strip/inject, URI rewrite, and HSTS injection).

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

# Per-PR CI use: also enforce the nginx, HAProxy, and Traefik delta budget tables above.
bench/compare.py --check-nginx --check-haproxy --check-traefik bench/results/main bench/results/HEAD
```

Exit codes:

- `0` — no regression beyond `--fail-on-regress` (default 5 %) and (if `--check-nginx` / `--check-haproxy` / `--check-traefik`) within the budget table
- `1` — at least one regression or budget violation
- `2` — input error (missing dir, malformed JSON)

## Scenario catalogue

The "Subjects" column abbreviates the matrix above. UDP scenarios omit haproxy/haproxy-chain (no `mode udp`); reload-latency stays yggdrasil-only.

| Script               | Subjects                                                                                              | What it measures                                                |
| -------------------- | ----------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| `udp-pps.sh`         | direct, yggdrasil-{terminal,chain}, nginx, nginx-chain, traefik, traefik-chain                        | single-flow UDP RTT & pps; sniff-test for per-packet overhead   |
| `udp-flows.sh`       | direct, yggdrasil-{terminal,chain}, nginx, nginx-chain, traefik, traefik-chain                        | 100 k concurrent flows; flow-table scaling                      |
| `udp-flowchurn.sh`   | direct, yggdrasil-{terminal,chain}, nginx, nginx-chain, traefik, traefik-chain                        | sustained new-flow rate; per-flow setup cost                    |
| `tcp-latency.sh`     | direct, yggdrasil-{terminal,chain}, nginx, nginx-chain, haproxy, haproxy-chain, traefik, traefik-chain | TCP ping-pong p50/p99/p99.9                                     |
| `tcp-throughput.sh`  | direct, yggdrasil-{terminal,chain}, nginx, nginx-chain, haproxy, haproxy-chain, traefik, traefik-chain | bulk TCP MB/s with a handful of streams                         |
| `tcp-connrate.sh`    | direct, yggdrasil-{terminal,chain}, nginx, nginx-chain, haproxy, haproxy-chain, traefik, traefik-chain | TCP handshake rate (connect + close)                            |
| `tcp-idle-conns.sh`  | direct, yggdrasil-{terminal,chain}, nginx, nginx-chain, haproxy, haproxy-chain, traefik, traefik-chain | proxy PSS while holding N idle TCP conns (per-conn memory cost; chain subjects sum PSS over both hops) |
| `reload-latency.sh`  | yggdrasil-chain only                                                                                  | time from "config dropped" to "new listener serves a request" — yggdrasil-only regression signal (see Why these peers? above for why there's no peer leg) |

A future `heartbeat-roundtrip.sh` (yggdrasil-only — none of the peer proxies has an analogous heartbeat) is tracked under Phase 12.

## How each leg works

For each non-direct subject, the harness:

1. Spawns the native `bench-echo` Rust binary on `127.0.0.1:<echo_port>`.
   By default it binds one listener per core via `SO_REUSEPORT`, so the
   backend has plenty of headroom and never bottlenecks the proxy under
   test.
2. Renders a fresh config + identity into a `mktemp -d` workspace:
   - **yggdrasil-terminal**: one `yggdrasil` daemon in terminal mode, no
     chain. Static rule binds `127.0.0.1:<listen_port>` →
     `127.0.0.1:<echo_port>`. The loadgen target is `127.0.0.1:<listen_port>`.
   - **yggdrasil-chain**: two `yggdrasil` daemons on loopback — gateway on
     `127.0.0.1` (accept-mode), terminal on `127.0.0.2` (dial-mode); the
     distinct loopback IPs are pinned via `[server].default_bind` so the
     two daemons don't collide on `<addr>:<listen_port>`. Identities are
     minted with `yggdrasilctl identity rotate` and wired via the offline
     `identity export-request` → `add-accept` → `add-dial` handshake. The
     terminal owns the rule set; the gateway derives a matching listener
     from the chain predicate published over the dial session. Loadgen
     target is `127.0.0.1:<listen_port>` (the gateway).
   - **nginx** / **haproxy** / **traefik**: a single proxy process.
     - nginx: minimal `stream { server { listen <addr>; proxy_pass 127.0.0.1:<upstream>; [udp;] } }`
       started with `nginx -p $tmp -c $tmp/nginx.conf -g 'daemon off;'`.
     - haproxy: minimal `frontend / default_backend echo` in `mode tcp`,
       `nbthread = $(nproc)`, started with `haproxy -db -f $tmp/haproxy/haproxy.cfg`.
     - traefik: a `traefik.yaml` static config (entry point + file
       provider) + a `dynamic.yaml` carrying the TCP or UDP router and
       service. The TCP rule uses `ClientIP(\`0.0.0.0/0\`) || ClientIP(\`::/0\`)`
       for raw passthrough — the default `HostSNI(\`*\`)` matcher would
       block on a TLS ClientHello that never arrives. Started with
       `traefik --configfile=$tmp/traefik/traefik.yaml`.
   - **nginx-chain** / **haproxy-chain** / **traefik-chain**: two of the
     same proxy on distinct loopback IPs — outer on `127.0.0.1:<listen_port>`
     proxying to inner on `127.0.0.2:<listen_port>`, inner proxying to
     the echo backend. Same IP-pinning trick as yggdrasil-chain. Loadgen
     target is `127.0.0.1:<listen_port>` (the outer).
3. Runs `loadgen` against `127.0.0.1:<listen_port>` (or `<echo_port>` for the direct leg).
4. SIGTERMs everything, removes the tmpdir, and pauses briefly to let TIME_WAIT clear before the next leg.

`bench/lib/common.sh` provides all the orchestration primitives. The per-scenario scripts are intentionally thin wrappers so a contributor can add a new scenario by copying an existing one.

## Known caveats

- 127.0.0.1 loopback bypasses the NIC entirely, so we are measuring per-packet overhead, scheduling, and userspace cost — *not* anything network-stack-bound. To exercise the NIC, replace `127.0.0.1` targets with a host on a separate kernel and rerun.
- `bench/collect-env.sh` records governor + sysctls but does **not** refuse to run on a misconfigured host. Check `env.json` before trusting the numbers.
- For chain subjects, `tcp-idle-conns.peak_established_conns` ~doubles because each TCP connection has an ESTABLISHED entry at each hop. The `proxy_rss_kib` PSS sum is the meaningful per-connection memory number — it's measured across both hops' process trees.

## Adding a new scenario

1. Copy the closest existing script (e.g. `bench/tcp-latency.sh`) to `bench/<new>.sh`.
2. Adjust `SCENARIO=`, the loadgen subcommand, and any tunables.
3. Add the scenario name to the `SCENARIOS` array in `bench/run-all.sh`.
4. If the metric needs a new comparison rule, extend `HIGHER_BETTER`/`LOWER_BETTER`/`NGINX_DELTA_BUDGET`/`HAPROXY_DELTA_BUDGET`/`TRAEFIK_DELTA_BUDGET` in `bench/compare.py`.
