#!/usr/bin/env bash
# UDP single-flow pps + RTT scenario.
#
# Measures how many round-trips per second a single UDP flow can sustain through
# direct → yggdrasil-* → nginx-*, with p50/p99 latency from loadgen's HDR histogram.
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

run_subject() {
    local subject="$1"
    local echo_port; echo_port="$(pick_free_udp_port)"
    local tmp; tmp="$(bench_mktempdir)"
    bench_spawn_udp_echo ECHO_PID "$echo_port" "$tmp/echo.log"
    case "$subject" in
        direct)
            run_leg direct 127.0.0.1 "$echo_port"
            ;;
        yggdrasil-terminal)
            local listen; listen="$(pick_free_udp_port)"
            bench_spin_yggdrasil_terminal "$tmp" "$listen" "$echo_port" udp
            run_leg yggdrasil-terminal 127.0.0.1 "$listen"
            ;;
        yggdrasil-chain)
            local listen; listen="$(pick_free_udp_port)"
            bench_spin_yggdrasil_chain "$tmp" "$listen" "$echo_port" udp
            run_leg yggdrasil-chain 127.0.0.1 "$listen"
            ;;
        nginx)
            local listen; listen="$(pick_free_udp_port)"
            bench_spin_nginx "$tmp" "$listen" "$echo_port" udp
            run_leg nginx 127.0.0.1 "$listen"
            ;;
        nginx-chain)
            local listen; listen="$(pick_free_udp_port)"
            bench_spin_nginx_chain "$tmp" "$listen" "$echo_port" udp
            run_leg nginx-chain 127.0.0.1 "$listen"
            ;;
        *) die "unknown subject $subject" ;;
    esac
    bench_leg_teardown
}

for s in direct yggdrasil-terminal yggdrasil-chain nginx nginx-chain; do
    log "$SCENARIO/$s: starting"
    run_subject "$s"
done
log "$SCENARIO: done. results in $OUTDIR/"
