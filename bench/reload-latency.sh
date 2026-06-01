#!/usr/bin/env bash
# Config reload latency scenario — yggdrasil-only.
#
# Measures the time from "I dropped a new rule fragment in conf.d/" to "the
# new listener serves traffic", driven by the inotify+250ms debounce hot
# reload path. This is a regression signal against previous yggdrasil runs
# only — there is no nginx leg, because `nginx -s reload` is a different
# trigger model (operator-explicit IPC, no debounce) and a head-to-head
# comparison would only penalise a deliberate product choice. See bench/README.md.
#
# Reported: mean/p50/p99/p99.9 reload-to-serve latency across N iterations.
# Output JSON shape matches loadgen reports (so compare.py treats it uniformly).

set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$HERE/lib/common.sh"
bench_install_traps
ensure_results_dir

readonly SCENARIO="reload-latency"
readonly ITERATIONS="${BENCH_ITERATIONS:-20}"
OUTDIR="$(bench_results_dir)"
readonly OUTDIR

# A helper: probe a TCP port — return 0 on first successful connect+ping-pong.
probe_tcp_until_serving() {
    local host="$1" port="$2" deadline_s="$3"
    local deadline=$(( SECONDS + deadline_s ))
    while (( SECONDS < deadline )); do
        if python3 - "$host" "$port" <<'PY' >/dev/null 2>&1
import socket, sys
s = socket.socket()
s.settimeout(0.05)
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
    s.sendall(b"x")
    s.recv(1)
    sys.exit(0)
except Exception:
    sys.exit(1)
PY
        then
            return 0
        fi
    done
    return 1
}

# python helper that records ns timestamps and emits a tiny json report
record_iterations() {
    local subject="$1"; shift
    local out="$1"; shift
    local samples_csv="$1"; shift  # comma-separated nanoseconds
    python3 - "$subject" "$out" "$samples_csv" <<'PY'
import json, statistics, sys, time

subject, out, samples_csv = sys.argv[1], sys.argv[2], sys.argv[3]
samples_ns = [int(x) for x in samples_csv.split(",") if x]
if not samples_ns:
    raise SystemExit("no samples")
samples_us = sorted(s / 1000.0 for s in samples_ns)


def pct(p):
    idx = max(0, min(len(samples_us) - 1, int(round((p / 100.0) * (len(samples_us) - 1)))))
    return samples_us[idx]


report = {
    "scenario": "reload-latency",
    "subject":  subject,
    "target":   "n/a",
    "params":   {"iterations": len(samples_us)},
    "stats": {
        "duration_s": 0,
        "tx_packets": len(samples_us),
        "rx_packets": len(samples_us),
        "tx_bytes": 0,
        "rx_bytes": 0,
        "errors": 0,
        "loss_pct": 0.0,
        "pps_tx": 0,
        "pps_rx": 0,
        "bytes_per_sec_tx": 0,
        "bytes_per_sec_rx": 0,
        "latency_us": {
            "samples": len(samples_us),
            "min":  samples_us[0],
            "p50":  pct(50),
            "p90":  pct(90),
            "p99":  pct(99),
            "p999": pct(99.9),
            "max":  samples_us[-1],
            "mean": statistics.fmean(samples_us),
        },
    },
    "ts_start_unix_ms": int(time.time() * 1000),
    "ts_end_unix_ms":   int(time.time() * 1000),
}
with open(out, "w") as f:
    json.dump(report, f, indent=2)
PY
}

# ---------- yggdrasil ----------

run_yggdrasil() {
    local tmp; tmp="$(bench_mktempdir)"
    local echo_port_a; echo_port_a="$(pick_free_tcp_port)"
    local echo_port_b; echo_port_b="$(pick_free_tcp_port)"
    local listen_a;    listen_a="$(pick_free_tcp_port)"

    bench_spawn_tcp_echo ECHO_A_PID "$echo_port_a" "$tmp/echo-a.log"
    bench_spawn_tcp_echo ECHO_B_PID "$echo_port_b" "$tmp/echo-b.log"

    # Start with one rule (rule-a) already in place.
    bench_spin_yggdrasil_chain "$tmp" "$listen_a" "$echo_port_a" tcp

    # We'll add additional branch files for rule-b<i> on each iteration.
    local samples=""
    local i
    for (( i = 1; i <= ITERATIONS; i++ )); do
        local p; p="$(pick_free_tcp_port)"
        local t0_ns; t0_ns="$(date +%s%N)"
        cat > "$tmp/rules/iter-$i.toml" <<EOF
[[rule]]
name     = "iter-$i"
listen   = "127.0.0.1:$p"
protocol = "tcp"
target   = "127.0.0.1:$echo_port_b"
EOF
        if ! probe_tcp_until_serving 127.0.0.1 "$p" 3; then
            die "yggdrasil iter $i: listener never came up"
        fi
        local t1_ns; t1_ns="$(date +%s%N)"
        samples+="$(( t1_ns - t0_ns )),"
    done
    record_iterations yggdrasil-chain "$OUTDIR/$SCENARIO-yggdrasil-chain.json" "$samples"
}

# Only one leg — yggdrasil-chain. There is no nginx comparison for this scenario;
# see the file header for why.
log "$SCENARIO/yggdrasil-chain: starting"
run_yggdrasil
bench_leg_teardown
log "$SCENARIO: done. results in $OUTDIR/"
