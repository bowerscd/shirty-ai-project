#!/usr/bin/env bash
# Run the full bench matrix against the current checkout.
#
# Each scenario script is independent — you can invoke them individually too.
# This wrapper exists so CI and local "give me all the numbers" runs are
# one command.

set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$HERE/lib/common.sh"
ensure_results_dir

root="$(bench_workspace_root)"
log "building release artifacts (yggdrasil, yggdrasilctl, bench-tools)…"
( cd "$root" && cargo build --release -p yggdrasil -p yggdrasilctl -p bench-tools ) >&2

log "capturing host env"
"$HERE/collect-env.sh"

declare -a SCENARIOS=(
    udp-pps
    udp-flows
    udp-flowchurn
    tcp-latency
    tcp-throughput
    tcp-connrate
    tcp-idle-conns
    reload-latency
)

# Allow callers to override via env var: BENCH_SCENARIOS="udp-pps tcp-latency"
if [[ -n "${BENCH_SCENARIOS:-}" ]]; then
    # shellcheck disable=SC2206
    SCENARIOS=( ${BENCH_SCENARIOS} )
fi

for s in "${SCENARIOS[@]}"; do
    if [[ ! -x "$HERE/$s.sh" ]]; then
        die "no script for scenario $s (looked for $HERE/$s.sh)"
    fi
    log "=== $s ==="
    "$HERE/$s.sh"
done

log "all scenarios complete: $(bench_results_dir)"
