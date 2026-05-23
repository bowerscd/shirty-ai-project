#!/usr/bin/env bash
# UDP bidirectional scenario.
#
# Each subject is exercised with simultaneous independent streams in both
# directions:
#
#   * client → server: loadgen sends at BENCH_TX_PPS aggregate.
#   * server → client: bench-echo is spawned with `--originate-pps` so it
#     pushes back at BENCH_RX_PPS *independently* of incoming traffic.
#
# Reported:
#   * Round-trip latency for the echo half (loadgen-tagged type=0 dgrams
#     come back; loadgen measures RTT).
#   * One-way latency for the server-originated half (bench-echo tags
#     type=1 dgrams with its own send timestamp).
#   * tx_packets / rx_packets per direction.
#
# Exercises both `handle_inbound` (c→s) AND `upstream_to_client_loop`
# (s→c) concurrently — the workload class the original `udp-pps`
# bench couldn't reach.

set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$HERE/lib/common.sh"
bench_install_traps
ensure_results_dir

readonly SCENARIO="udp-duplex"
readonly DURATION="${BENCH_DURATION:-10s}"
readonly WARMUP="${BENCH_WARMUP:-1s}"
readonly FLOWS="${BENCH_FLOWS:-32}"
readonly TX_PPS="${BENCH_TX_PPS:-50000}"
readonly RX_PPS="${BENCH_RX_PPS:-50000}"
readonly PACKET_SIZE="${BENCH_PACKET_SIZE:-64}"
readonly OUTDIR="$(bench_results_dir)"

run_leg() {
    local subject="$1" target_host="$2" target_port="$3"
    bench_run_loadgen "$subject" "$OUTDIR/$SCENARIO-$subject.json" \
        udp-duplex \
        --target "$target_host:$target_port" \
        --flows "$FLOWS" \
        --tx-pps "$TX_PPS" \
        --packet-size "$PACKET_SIZE" \
        --duration "$DURATION" \
        --warmup "$WARMUP"
}

run_subject() {
    local subject="$1"
    local echo_port; echo_port="$(pick_free_udp_port)"
    local tmp; tmp="$(bench_mktempdir)"
    # Per-source originate rate. We pass FLOWS as the max-sources cap
    # so bench-echo's originator count matches the loadgen's flow
    # count regardless of how many upstream source ports the proxy
    # under test uses. Without this cap, nginx (which uses fresh
    # upstream ports per flow + per-worker) would multiplicatively
    # amplify the originate count, making cross-subject comparison
    # unfair.
    local per_source_pps=$(( RX_PPS / FLOWS ))
    if (( per_source_pps < 1 )); then per_source_pps=1; fi
    bench_spawn_udp_echo_duplex ECHO_PID "$echo_port" "$tmp/echo.log" \
        "$per_source_pps" "$PACKET_SIZE" "$FLOWS"
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
        traefik)
            local listen; listen="$(pick_free_udp_port)"
            bench_spin_traefik "$tmp" "$listen" "$echo_port" udp
            run_leg traefik 127.0.0.1 "$listen"
            ;;
        traefik-chain)
            local listen; listen="$(pick_free_udp_port)"
            bench_spin_traefik_chain "$tmp" "$listen" "$echo_port" udp
            run_leg traefik-chain 127.0.0.1 "$listen"
            ;;
        *) die "unknown subject $subject" ;;
    esac
    bench_leg_teardown
}

mapfile -t SUBJECTS < <(bench_subjects_for udp)
log "$SCENARIO subject order: ${SUBJECTS[*]}"
for s in "${SUBJECTS[@]}"; do
    log "$SCENARIO/$s: starting"
    run_subject "$s"
done
log "$SCENARIO: done. results in $OUTDIR/"
