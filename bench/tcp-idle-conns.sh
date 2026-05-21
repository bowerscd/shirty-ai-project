#!/usr/bin/env bash
# TCP idle-connection memory-footprint scenario.
#
# Opens N concurrent TCP connections through the subject, holds them all
# idle for a fixed duration, then closes. A 250 ms background sampler
# tracks (a) total PSS of the proxy process tree and (b) the count of
# ESTABLISHED conns whose proxy-side source port is the listen port,
# storing the running maxima of both. The resulting JSON includes:
#
#   stats.proxy_rss_kib                  — peak PSS observed during the run
#   stats.tx_packets / stats.rx_packets  — connections actually established
#   stats.latency_us                     — per-connect-time histogram (μs)
#   params.proxy_rss_baseline_kib        — PSS before any connections opened
#   params.peak_established_conns        — max simultaneous conns observed
#   params.conns_at_peak_rss             — conn count at the moment PSS peaked
#   params.connections / params.hold_s   — the requested workload
#
# The interesting derived quantity is per-connection cost:
#
#     (proxy_rss_kib - proxy_rss_baseline_kib) / max(peak_established_conns, 1)
#
# For the `direct` subject (loadgen → echo with no proxy), all proxy_*
# fields are null and we report only the load-generator's view.
#
# Acceptable delta vs nginx: yggdrasil's proxy_rss_kib should be within
# 100 % (2×) of nginx's, gated by compare.py --check-nginx.

set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$HERE/lib/common.sh"
bench_install_traps
ensure_results_dir

readonly SCENARIO="tcp-idle-conns"
readonly CONNECTIONS="${BENCH_IDLE_CONNS:-5000}"
readonly CONCURRENCY="${BENCH_IDLE_CONCURRENCY:-256}"
readonly HOLD="${BENCH_IDLE_HOLD:-15s}"
readonly OUTDIR="$(bench_results_dir)"

command -v jq >/dev/null || die "jq is required for $SCENARIO post-processing"
command -v ss >/dev/null || die "ss (iproute2) is required for $SCENARIO"

# Sum PSS in KiB across a process and all its descendants from
# /proc/<pid>/smaps_rollup. Walks the tree via /proc/<pid>/task/<pid>/children.
sample_pss_tree() {
    local root_pid="$1"
    if [[ -z "$root_pid" ]] || [[ ! -d "/proc/$root_pid" ]]; then
        printf 0
        return
    fi
    local -a pids=("$root_pid")
    local -a frontier=("$root_pid")
    while ((${#frontier[@]} > 0)); do
        local -a next=()
        local p
        for p in "${frontier[@]}"; do
            local kids_file="/proc/$p/task/$p/children"
            [[ -r "$kids_file" ]] || continue
            local kids
            kids="$(<"$kids_file")" || continue
            local k
            for k in $kids; do
                pids+=("$k")
                next+=("$k")
            done
        done
        if ((${#next[@]} > 0)); then
            frontier=("${next[@]}")
        else
            frontier=()
        fi
    done
    local total=0
    local p
    for p in "${pids[@]}"; do
        local f="/proc/$p/smaps_rollup"
        [[ -r "$f" ]] || continue
        local v
        v="$(awk '/^Pss:/ {print $2; exit}' "$f" 2>/dev/null || true)"
        [[ -n "$v" ]] && total=$((total + v))
    done
    printf '%d' "$total"
}

# Background sampler. Every 250 ms, observe total PSS of the proxy tree
# and the count of ESTABLISHED conns with sport=listen_port (i.e. the
# proxy-accepted side). Write the running maxima to disk so the parent
# can harvest them after loadgen finishes.
run_sampler() {
    local root_pid="$1"
    local listen_port="$2"
    local rss_file="$3"
    local conn_file="$4"
    local conn_at_max_file="$5"
    local max_rss=0
    local max_conns=0
    local conn_at_max=0
    while true; do
        local r c
        r="$(sample_pss_tree "$root_pid")"
        c=$(ss -tnH state established "( sport = :$listen_port )" 2>/dev/null | wc -l)
        if (( r > max_rss )); then
            max_rss="$r"
            conn_at_max="$c"
            printf '%d' "$max_rss" > "$rss_file"
            printf '%d' "$conn_at_max" > "$conn_at_max_file"
        fi
        if (( c > max_conns )); then
            max_conns="$c"
            printf '%d' "$max_conns" > "$conn_file"
        fi
        sleep 0.25
    done
}

read_int_or_zero() {
    local f="$1"
    if [[ -s "$f" ]]; then
        local v
        v=$(cat "$f")
        [[ -n "$v" ]] && printf '%d' "$v" || printf 0
    else
        printf 0
    fi
}

run_subject() {
    local subject="$1"
    local echo_port
    echo_port="$(pick_free_tcp_port)"
    local tmp
    tmp="$(bench_mktempdir)"
    bench_spawn_tcp_echo ECHO_PID "$echo_port" "$tmp/echo.log"

    local target=""
    local listen=""
    local proxy_pid=""
    case "$subject" in
        direct)
            target="127.0.0.1:$echo_port"
            ;;
        yggdrasil)
            listen="$(pick_free_tcp_port)"
            bench_spin_yggdrasil "$tmp" "$listen" "$echo_port" tcp
            target="127.0.0.1:$listen"
            proxy_pid="${YGG_GW_PID:-}"
            ;;
        nginx)
            listen="$(pick_free_tcp_port)"
            bench_spin_nginx "$tmp" "$listen" "$echo_port" tcp
            target="127.0.0.1:$listen"
            proxy_pid="${NGINX_PID:-}"
            ;;
        *) die "unknown subject $subject" ;;
    esac

    # Baseline PSS before any connections.
    local baseline_rss=0
    if [[ -n "$proxy_pid" ]]; then
        baseline_rss=$(sample_pss_tree "$proxy_pid")
    fi

    local out="$OUTDIR/$SCENARIO-$subject.json"
    local root
    root="$(bench_workspace_root)"
    local lg="$root/target/release/loadgen"
    [[ -x "$lg" ]] || die "missing $lg — run: cargo build --release -p bench-tools"

    log "loadgen subject=$subject conns=$CONNECTIONS concurrency=$CONCURRENCY hold=$HOLD target=$target"
    "$lg" --subject "$subject" --report-json "$out" \
        tcp-idle --target "$target" \
        --connections "$CONNECTIONS" \
        --concurrency "$CONCURRENCY" \
        --hold "$HOLD" &
    local lg_pid=$!

    local sample_kib=0
    local peak_conns=0
    local conns_at_peak_rss=0
    local sampler_pid=""
    if [[ -n "$proxy_pid" ]] && [[ -n "$listen" ]]; then
        local rss_file="$tmp/sampler.rss"
        local conn_file="$tmp/sampler.conns"
        local cap_file="$tmp/sampler.conns_at_peak_rss"
        : > "$rss_file"
        : > "$conn_file"
        : > "$cap_file"
        run_sampler "$proxy_pid" "$listen" "$rss_file" "$conn_file" "$cap_file" &
        sampler_pid=$!
    fi

    wait "$lg_pid"

    if [[ -n "$sampler_pid" ]]; then
        kill "$sampler_pid" 2>/dev/null || true
        wait "$sampler_pid" 2>/dev/null || true
        sample_kib=$(read_int_or_zero "$tmp/sampler.rss")
        peak_conns=$(read_int_or_zero "$tmp/sampler.conns")
        conns_at_peak_rss=$(read_int_or_zero "$tmp/sampler.conns_at_peak_rss")
        log "  proxy_pid=$proxy_pid baseline=${baseline_rss}KiB peak=${sample_kib}KiB peak_conns=${peak_conns} conns_at_peak_rss=${conns_at_peak_rss}"
    fi

    # Inject the proxy memory facts into loadgen's JSON.
    local tmpfile="$out.tmp"
    if [[ -n "$proxy_pid" ]]; then
        jq --argjson rss "$sample_kib" \
           --argjson base "$baseline_rss" \
           --argjson peak_conns "$peak_conns" \
           --argjson conns_at_max "$conns_at_peak_rss" \
           '.stats.proxy_rss_kib = $rss
            | .params.proxy_rss_baseline_kib = $base
            | .params.peak_established_conns = $peak_conns
            | .params.conns_at_peak_rss = $conns_at_max' \
           "$out" > "$tmpfile" && mv "$tmpfile" "$out"
    else
        jq '.stats.proxy_rss_kib = null
            | .params.proxy_rss_baseline_kib = null
            | .params.peak_established_conns = null
            | .params.conns_at_peak_rss = null' \
           "$out" > "$tmpfile" && mv "$tmpfile" "$out"
    fi

    bench_leg_teardown
}

for s in direct yggdrasil nginx; do
    log "$SCENARIO/$s: starting"
    run_subject "$s"
done
log "$SCENARIO: done. results in $OUTDIR/"
