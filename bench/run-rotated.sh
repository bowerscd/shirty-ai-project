#!/usr/bin/env bash
# Run the full bench matrix N times with the subject order shuffled per
# run. Each rotation lands in `bench/results/<sha>-rotN/`. Use
# `bench/compare.py --rotations bench/results/<sha>-rot*` to aggregate
# the results into a position-corrected view.
#
# Why this exists: every scenario script has a fixed canonical subject
# order. Running on a contended host (typical of self-hosted runners),
# the first subject in the list gets a structural advantage of 25-70%
# from cleaner kernel state (TIME_WAIT, scheduler bias, thermal
# headroom). Averaging across rotations cancels that out — every
# subject runs in every position with roughly equal probability.
#
# Knobs:
#   BENCH_ROTATIONS  : number of full-matrix runs (default 5)
#   BENCH_DURATION   : per-leg duration (forwarded to scenario scripts)
#   BENCH_SCENARIOS  : subset of scenarios (forwarded to run-all.sh)
#
# Seeds are 1..N so a re-run with the same N reproduces the same
# permutations (rotation logs include the order each scenario picked).

set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$HERE/lib/common.sh"

readonly ROTATIONS="${BENCH_ROTATIONS:-5}"
if ! [[ "$ROTATIONS" =~ ^[0-9]+$ ]] || (( ROTATIONS < 1 )); then
    die "BENCH_ROTATIONS must be a positive integer (got $ROTATIONS)"
fi

base_sha="${BENCH_SHA:-$(git -C "$(bench_workspace_root)" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
root="$(bench_workspace_root)"

log "rotated bench: $ROTATIONS rotations of $base_sha"
log "tip: --shuffle is on; each scenario picks a fresh order per rotation"

for i in $(seq 1 "$ROTATIONS"); do
    rot_sha="${base_sha}-rot${i}"
    log "=== rotation $i/$ROTATIONS (seed=$i, dir=$rot_sha) ==="
    BENCH_SHA="$rot_sha" \
    BENCH_SHUFFLE=1 \
    BENCH_SHUFFLE_SEED="$i" \
        "$HERE/run-all.sh"
    # Brief settle between rotations so the per-host state doesn't
    # accumulate too badly. Not a substitute for the TIME_WAIT drain
    # — the shuffle within each rotation is what averages run-order
    # out, this just keeps the box from melting between rotations.
    sleep 5
done

log "aggregated results in $root/bench/results/${base_sha}-rot{1..$ROTATIONS}"
log "aggregate with: python3 bench/compare.py --rotations $root/bench/results/${base_sha}-rot*"
