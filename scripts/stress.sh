#!/usr/bin/env bash
# scripts/stress.sh — surface flaky tests by running the workspace suite
# repeatedly under high parallelism.
#
# Most flake patterns (timing races, ordering assumptions across tasks,
# port-reuse windows) only show up when tests run in parallel under
# CPU contention. A single `cargo test` run almost never reproduces
# them. This script runs the workspace suite N times in a row with
# `--test-threads=$(nproc * 2)` and bails on the first red run.
#
# Use it before pushing any change that touches:
#   - the proxy supervisor (reconcile / route hot-reload)
#   - the heartbeat / chain client task plumbing
#   - the UDP frontend's batching path
#   - any test that uses `tokio::time::sleep` for synchronisation
#
# Usage:
#   scripts/stress.sh           # default: 10 runs
#   STRESS_RUNS=25 scripts/stress.sh
#   STRESS_THREADS=16 scripts/stress.sh
#
# Exit codes:
#   0  all runs green
#   1  at least one run failed (the failed run's output is on the
#      console; rerun the specific failed test with --nocapture for
#      detail)
#   2  setup error (cargo not found, etc.)
set -euo pipefail

RUNS="${STRESS_RUNS:-10}"
NPROC="$(nproc 2>/dev/null || echo 4)"
THREADS="${STRESS_THREADS:-$((NPROC * 2))}"

if ! command -v cargo >/dev/null 2>&1; then
    echo "FAIL: cargo not found on PATH" >&2
    exit 2
fi

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

echo "==> stress: $RUNS runs of \`cargo test --workspace\` with --test-threads=$THREADS"

# Build once up front so the timing of each run reflects the test
# execution itself, not compile time.
echo "==> building tests (cache warm-up; not timed)"
cargo build --workspace --tests --quiet

for i in $(seq 1 "$RUNS"); do
    echo "==> run $i/$RUNS"
    start=$(date +%s)
    if ! cargo test --workspace --quiet -- --test-threads="$THREADS"; then
        echo
        echo "FAIL: run $i failed. Reproduce with:"
        echo "  cargo test --workspace -- --test-threads=$THREADS --nocapture"
        exit 1
    fi
    end=$(date +%s)
    echo "    [ok] run $i passed in $((end - start))s"
done

echo
echo "ALL $RUNS RUNS PASSED"
