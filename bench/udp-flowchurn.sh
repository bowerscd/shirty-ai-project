#!/usr/bin/env bash
# UDP flow-churn scenario.
#
# Hammers the proxy with brand-new source ports at a steady rate. Each "flow"
# is one datagram from a fresh socket — exercises the proxy's per-flow setup
# path (DashMap insert in yggdrasil; new conntrack entry in nginx) without the
# steady-state cost of keeping all flows alive.
#
# Acceptable delta vs nginx: churn rate within 20%.

set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$HERE/lib/common.sh"
bench_install_traps
ensure_results_dir

readonly SCENARIO="udp-flowchurn"
readonly DURATION="${BENCH_DURATION:-10s}"
readonly RATE="${BENCH_RATE:-5000}"
readonly OUTDIR="$(bench_results_dir)"

run_leg() {
    local subject="$1" target="$2"
    bench_run_loadgen "$subject" "$OUTDIR/$SCENARIO-$subject.json" \
        udp-churn \
        --target "$target" \
        --rate "$RATE" \
        --duration "$DURATION"
}

run_subject() {
    local subject="$1"
    local echo_port; echo_port="$(pick_free_udp_port)"
    local tmp; tmp="$(bench_mktempdir)"
    bench_spawn_udp_echo ECHO_PID "$echo_port" "$tmp/echo.log"
    case "$subject" in
        direct)
            run_leg direct "127.0.0.1:$echo_port"
            ;;
        yggdrasil)
            local listen; listen="$(pick_free_udp_port)"
            bench_spin_yggdrasil "$tmp" "$listen" "$echo_port" udp
            run_leg yggdrasil "127.0.0.1:$listen"
            ;;
        nginx)
            local listen; listen="$(pick_free_udp_port)"
            bench_spin_nginx "$tmp" "$listen" "$echo_port" udp
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
