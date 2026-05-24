#!/usr/bin/env bash
# Capture a CPU profile of yggdrasil while a single bench scenario runs.
#
# Builds the daemon with `--features profile`, sets
# `YGGDRASIL_PROFILE_OUTPUT` so the daemon installs the SIGPROF-based
# sampler, runs the scenario once, and lands a flamegraph SVG (or a
# pprof binary if you pass `--pprof`) alongside the bench result.
#
# Why this exists: the bench harness can tell you yggdrasil is N%
# slower than nginx on a workload, but it can't tell you *why*. This
# script answers "where is the time going" with a real CPU profile,
# without needing root (pprof-rs is pure-userspace SIGPROF) and
# without needing perf installed.
#
# Usage:
#   bench/profile.sh tcp-connrate              # default — flamegraph SVG
#   bench/profile.sh tcp-latency --pprof       # pprof binary instead
#   bench/profile.sh udp-pps --duration 30s    # longer capture
#
# The output lands in bench/results/<sha>-profile/<scenario>.{svg,pb}.

set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$HERE/lib/common.sh"

scenario="${1:-}"
[[ -n "$scenario" ]] || die "usage: $0 <scenario> [--pprof] [--duration <humantime>]"
shift

format="svg"
duration=""
while (( $# )); do
    case "$1" in
        --pprof)     format="pb"; shift;;
        --svg)       format="svg"; shift;;
        --duration)  duration="$2"; shift 2;;
        *)           die "unknown arg: $1";;
    esac
done

scenario_script="$HERE/${scenario}.sh"
[[ -x "$scenario_script" ]] || die "no scenario script: $scenario_script (expected $HERE/${scenario}.sh)"

root="$(bench_workspace_root)"
sha="${BENCH_SHA:-$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
profile_dir="$root/bench/results/${sha}-profile"
mkdir -p "$profile_dir"

profile_output="$profile_dir/${scenario}.${format}"
# Make absolute so the spawned daemon (which may run with a different
# cwd via bench_spin_yggdrasil_*) writes to the right place.
profile_output="$(readlink -f "$profile_output" 2>/dev/null || echo "$profile_output")"

log "building yggdrasil with --features profile + frame pointers"
# `force-frame-pointers=yes` is required: pprof-rs's signal-based
# unwinder (we use the `frame-pointer` feature) walks `%rbp` chains
# directly. Without it, release optimisations omit the frame pointer
# and the unwinder gives up after the leaf frame. With it, leaf
# attribution (`epoll_wait` / `recvmmsg` / `sendmmsg` / …) is
# reliable; deeper Rust frames are best-effort and may still be
# missing for samples that land inside a syscall.
( cd "$root" && RUSTFLAGS="-C force-frame-pointers=yes" \
    cargo build --release -p yggdrasil --features profile ) >&2

log "profiling target: $profile_output"
log "running scenario: $scenario"
export YGGDRASIL_PROFILE_OUTPUT="$profile_output"
export YGGDRASIL_PROFILE_FREQUENCY="${YGGDRASIL_PROFILE_FREQUENCY:-99}"
if [[ -n "$duration" ]]; then
    export YGGDRASIL_PROFILE_DURATION="$duration"
fi

# Run only the yggdrasil-* subjects (no point profiling nginx via this
# path — it just slows the run down). The scenario script picks the
# subjects via bench_subjects_for, which honors BENCH_SUBJECTS.
export BENCH_SUBJECTS="${BENCH_SUBJECTS:-yggdrasil-terminal yggdrasil-chain}"

# Keep the run short by default — a 30-second profile produces a
# representative flamegraph without spending all afternoon on it.
export BENCH_DURATION="${BENCH_DURATION:-30s}"

"$scenario_script"

# IMPORTANT: the profile only lands on daemon shutdown (or at the
# YGGDRASIL_PROFILE_DURATION deadline). bench_spin_yggdrasil_*'s
# teardown sends SIGTERM which triggers the flush. If the file
# doesn't appear, the profile-feature build probably wasn't picked
# up (check `cargo build --release -p yggdrasil --features profile`).
if [[ -f "$profile_output" ]]; then
    log "profile written: $profile_output"
    case "$format" in
        svg) log "  open in any browser: file://$profile_output";;
        pb)  log "  inspect with: go tool pprof $profile_output";;
    esac
else
    die "profile file not produced — was the daemon built with --features profile?"
fi

# Rebuild without the feature so subsequent non-profiled bench runs
# don't accidentally carry the SIGPROF handler.
log "rebuilding yggdrasil without --features profile (restore default binary)"
( cd "$root" && cargo build --release -p yggdrasil ) >&2
