#!/usr/bin/env bash
# UDP single-flow pps + RTT scenario.
#
# Measures how many round-trips per second a single UDP flow can sustain through
# direct → yggdrasil → nginx, with p50/p99 latency from loadgen's HDR histogram.
#
# Acceptable delta vs nginx: pps within 20%, p99 ≤ 2× nginx (see plan §11.5).

set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$HERE/lib/common.sh"
bench_install_traps
ensure_results_dir

readonly SCENARIO="udp-pps"
readonly DURATION="${BENCH_DURATION:-10s}"
readonly WARMUP="${BENCH_WARMUP:-1s}"
readonly PPS="${BENCH_PPS:-100000}"
readonly PACKET_SIZE="${BENCH_PACKET_SIZE:-64}"
readonly OUTDIR="$(bench_results_dir)"

run_leg() {
    local subject="$1" target_host="$2" target_port="$3"
    bench_run_loadgen "$subject" "$OUTDIR/$SCENARIO-$subject.json" \
        udp \
        --target "$target_host:$target_port" \
        --flows 1 \
        --pps "$PPS" \
        --packet-size "$PACKET_SIZE" \
        --duration "$DURATION" \
        --warmup "$WARMUP"
}

# ---------- direct ----------
log "$SCENARIO/direct: starting"
echo_port="$(pick_free_udp_port)"
tmp="$(bench_mktempdir)"
bench_spawn_udp_echo ECHO_PID "$echo_port" "$tmp/echo.log"
run_leg direct 127.0.0.1 "$echo_port"
bench_leg_teardown

# ---------- yggdrasil ----------
log "$SCENARIO/yggdrasil: starting"
echo_port="$(pick_free_udp_port)"
listen_port="$(pick_free_udp_port)"
tmp="$(bench_mktempdir)"
bench_spawn_udp_echo ECHO_PID "$echo_port" "$tmp/echo.log"
bench_spin_yggdrasil "$tmp" "$listen_port" "$echo_port" udp
run_leg yggdrasil 127.0.0.1 "$listen_port"
bench_leg_teardown

# ---------- nginx ----------
log "$SCENARIO/nginx: starting"
echo_port="$(pick_free_udp_port)"
listen_port="$(pick_free_udp_port)"
tmp="$(bench_mktempdir)"
bench_spawn_udp_echo ECHO_PID "$echo_port" "$tmp/echo.log"
bench_spin_nginx "$tmp" "$listen_port" "$echo_port" udp
run_leg nginx 127.0.0.1 "$listen_port"
bench_leg_teardown

log "$SCENARIO: done. results in $OUTDIR/"
