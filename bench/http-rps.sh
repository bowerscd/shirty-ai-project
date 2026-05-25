#!/usr/bin/env bash
# L7 HTTPS request-rate scenario.
#
# Spins a plain-HTTP backend (bench-echo http) and a TLS-terminating
# proxy in front of it (yggdrasil-terminal / nginx / traefik). Loadgen
# hammers the proxy's HTTPS frontend with persistent HTTP/1.1
# keep-alive connections and measures requests/sec + per-request
# latency.
#
# Apples-to-apples shape:
#
#   loadgen-https  →  proxy (terminate TLS, forward h1)  →  bench-echo http
#
# `direct` is the loadgen → bench-echo path with NO proxy and NO TLS
# (plain http). It gives a ceiling for what the backend can do; the
# proxy subjects' RPS will trail it by however much TLS termination +
# proxy overhead costs.

set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$HERE/lib/common.sh"
bench_install_traps
ensure_results_dir

readonly SCENARIO="http-rps"
readonly DURATION="${BENCH_DURATION:-10s}"
readonly WARMUP="${BENCH_WARMUP:-1s}"
readonly CONCURRENCY="${BENCH_CONCURRENCY:-64}"
readonly BODY_SIZE="${BENCH_BODY_SIZE:-100}"
readonly OUTDIR="$(bench_results_dir)"

run_leg() {
    local subject="$1" target_url="$2"
    bench_run_loadgen "$subject" "$OUTDIR/$SCENARIO-$subject.json" \
        http-rps \
        --target "$target_url" \
        --concurrency "$CONCURRENCY" \
        --duration "$DURATION" \
        --warmup "$WARMUP"
}

run_subject() {
    local subject="$1"
    local upstream; upstream="$(pick_free_tcp_port)"
    local tmp; tmp="$(bench_mktempdir)"
    bench_spawn_http_echo ECHO_PID "$upstream" "$tmp/echo.log" "$BODY_SIZE"

    case "$subject" in
        direct)
            run_leg direct "http://127.0.0.1:$upstream/"
            ;;
        yggdrasil-terminal)
            local listen; listen="$(pick_free_tcp_port)"
            bench_spin_yggdrasil_https "$tmp" "$listen" "$upstream"
            run_leg yggdrasil-terminal "https://localhost:$listen/"
            ;;
        nginx)
            local listen; listen="$(pick_free_tcp_port)"
            bench_spin_nginx_https "$tmp" "$listen" "$upstream"
            run_leg nginx "https://localhost:$listen/"
            ;;
        traefik)
            local listen; listen="$(pick_free_tcp_port)"
            bench_spin_traefik_https "$tmp" "$listen" "$upstream"
            run_leg traefik "https://localhost:$listen/"
            ;;
        *) die "unknown subject $subject" ;;
    esac
    bench_leg_teardown
}

mapfile -t SUBJECTS < <(bench_subjects_for http)
log "$SCENARIO subject order: ${SUBJECTS[*]}"
for s in "${SUBJECTS[@]}"; do
    log "$SCENARIO/$s: starting"
    run_subject "$s"
done
log "$SCENARIO: done. results in $OUTDIR/"
