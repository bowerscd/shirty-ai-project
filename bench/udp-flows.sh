#!/usr/bin/env bash
# UDP many-flows scaling scenario.
#
# Pushes loadgen with 100k concurrent UDP flows (each a unique source port) at
# a modest aggregate rate. Stresses the proxy's flow-table data structure
# (DashMap in yggdrasil; the connection-tracking-table inside nginx) and exposes
# any per-flow allocation/lookup regressions.
#
# Acceptable delta vs nginx: aggregate pps within 20%, p99 ≤ 2× nginx.

set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$HERE/lib/common.sh"
bench_install_traps
ensure_results_dir

readonly SCENARIO="udp-flows"
readonly DURATION="${BENCH_DURATION:-15s}"
readonly WARMUP="${BENCH_WARMUP:-2s}"
readonly FLOWS="${BENCH_FLOWS:-100000}"
readonly PPS="${BENCH_PPS:-100000}"
readonly PACKET_SIZE="${BENCH_PACKET_SIZE:-64}"
readonly OUTDIR="$(bench_results_dir)"

run_leg() {
    local subject="$1" target_host="$2" target_port="$3"
    bench_run_loadgen "$subject" "$OUTDIR/$SCENARIO-$subject.json" \
        udp \
        --target "$target_host:$target_port" \
        --flows "$FLOWS" \
        --pps "$PPS" \
        --packet-size "$PACKET_SIZE" \
        --duration "$DURATION" \
        --warmup "$WARMUP"
}

run_subject() {
    local subject="$1"
    local echo_port; echo_port="$(pick_free_udp_port)"
    local tmp; tmp="$(bench_mktempdir)"
    bench_spawn_udp_echo ECHO_PID "$echo_port" "$tmp/echo.log"
    case "$subject" in
        direct)
            run_leg direct 127.0.0.1 "$echo_port"
            ;;
        yggdrasil)
            local listen; listen="$(pick_free_udp_port)"
            bench_spin_yggdrasil "$tmp" "$listen" "$echo_port" udp
            run_leg yggdrasil 127.0.0.1 "$listen"
            ;;
        nginx)
            local listen; listen="$(pick_free_udp_port)"
            bench_spin_nginx "$tmp" "$listen" "$echo_port" udp
            run_leg nginx 127.0.0.1 "$listen"
            ;;
        *) die "unknown subject $subject" ;;
    esac
    bench_leg_teardown
}

for s in direct yggdrasil nginx; do
    log "$SCENARIO/$s: starting"
    run_subject "$s"
done
log "$SCENARIO: done. results in $OUTDIR/"
