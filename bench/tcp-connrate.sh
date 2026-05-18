#!/usr/bin/env bash
# TCP connection-rate scenario.
#
# Hammers the proxy with concurrent connect-then-close cycles. Measures how
# many fresh TCP handshakes per second the proxy can sink. Tests the
# accept()/proxy-setup/teardown hot path.
#
# Acceptable delta vs nginx: connrate within 25%.

set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$HERE/lib/common.sh"
bench_install_traps
ensure_results_dir

readonly SCENARIO="tcp-connrate"
readonly DURATION="${BENCH_DURATION:-10s}"
readonly CONCURRENCY="${BENCH_CONCURRENCY:-256}"
readonly OUTDIR="$(bench_results_dir)"

run_leg() {
    local subject="$1" target="$2"
    bench_run_loadgen "$subject" "$OUTDIR/$SCENARIO-$subject.json" \
        tcp-connrate \
        --target "$target" \
        --concurrency "$CONCURRENCY" \
        --duration "$DURATION"
}

run_subject() {
    local subject="$1"
    local echo_port; echo_port="$(pick_free_tcp_port)"
    local tmp; tmp="$(bench_mktempdir)"
    bench_spawn_tcp_echo ECHO_PID "$echo_port" "$tmp/echo.log"
    case "$subject" in
        direct)
            run_leg direct "127.0.0.1:$echo_port"
            ;;
        yggdrasil)
            local listen; listen="$(pick_free_tcp_port)"
            bench_spin_yggdrasil "$tmp" "$listen" "$echo_port" tcp
            run_leg yggdrasil "127.0.0.1:$listen"
            ;;
        nginx)
            local listen; listen="$(pick_free_tcp_port)"
            bench_spin_nginx "$tmp" "$listen" "$echo_port" tcp
            run_leg nginx "127.0.0.1:$listen"
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
