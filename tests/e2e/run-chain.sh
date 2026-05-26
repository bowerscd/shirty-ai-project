#!/usr/bin/env bash
# tests/e2e/run-chain.sh — end-to-end smoke for the 3-level chain control
# plane. Brings up `docker/compose.e2e.chain.yml` (vps-chain, midbox,
# home-chain, client-chain) and exercises:
#
#   1. predicate flow:  home publishes -> midbox derives -> traffic flows
#   2. chain diff:      `yggdrasilctl chain diff` from home, no drift
#
# Usage:
#   ./tests/e2e/run-chain.sh                # build + run + verify + teardown
#   KEEP_STACK=1 ./tests/e2e/run-chain.sh   # leave stack up at the end
set -euo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
COMPOSE_FILE="$REPO_ROOT/docker/compose.e2e.chain.yml"
COMPOSE_ARGS=(-f "$COMPOSE_FILE" -p yggdrasil-e2e-chain)

if command -v podman-compose >/dev/null 2>&1; then
    DC=(podman-compose)
elif podman compose version >/dev/null 2>&1; then
    DC=(podman compose)
else
    echo "FAIL: need podman-compose (preferred) or \`podman compose\` available" >&2
    exit 2
fi

teardown() {
    if [[ "${KEEP_STACK:-0}" == "1" ]]; then
        echo "==> KEEP_STACK=1 set; leaving stack up"
        return
    fi
    echo "==> tearing down chain stack"
    "${DC[@]}" "${COMPOSE_ARGS[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap teardown EXIT

cd "$REPO_ROOT"

echo "==> building images"
"${DC[@]}" "${COMPOSE_ARGS[@]}" build

echo "==> running chain bootstrap (init-chain service)"
if ! "${DC[@]}" "${COMPOSE_ARGS[@]}" run --rm init-chain; then
    echo "FAIL: chain bootstrap (init-chain) exited non-zero" >&2
    exit 1
fi

echo "==> bringing chain daemons up"
"${DC[@]}" "${COMPOSE_ARGS[@]}" up -d vps-chain midbox home-chain client-chain

# -------- helpers -----------------------------------------------------------

dc_exec() {
    "${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T "$@"
}

ctl_on() {
    local node="$1"; shift
    dc_exec "$node" \
        yggdrasilctl local --socket /run/yggdrasil/control.sock "$@"
}

ctl_json_on() {
    local node="$1"; shift
    dc_exec "$node" \
        yggdrasilctl --json local --socket /run/yggdrasil/control.sock "$@"
}

wait_for() {
    local desc="$1"; shift
    local timeout="${WAIT_TIMEOUT:-30}"
    local start; start=$(date +%s)
    while ! "$@" >/dev/null 2>&1; do
        local now; now=$(date +%s)
        if (( now - start > timeout )); then
            echo "FAIL: timed out waiting for $desc"
            return 1
        fi
        sleep 0.5
    done
    echo "    [ok] $desc"
}

fail() {
    echo "FAIL: $*"
    "${DC[@]}" "${COMPOSE_ARGS[@]}" logs --no-color --tail 100 vps-chain  || true
    "${DC[@]}" "${COMPOSE_ARGS[@]}" logs --no-color --tail 100 midbox     || true
    "${DC[@]}" "${COMPOSE_ARGS[@]}" logs --no-color --tail 100 home-chain || true
    exit 1
}

# -------- gating: wait for both heartbeat hops to enrol --------------------

echo "==> waiting for home-chain to enrol at midbox"
home_enrolled_at_midbox() {
    local out; out=$(ctl_json_on midbox status 2>/dev/null || true)
    echo "$out" | grep -q '"downstream_enrolled": true' && \
        echo "$out" | grep -q '"downstream_ip": "172.30.1.30"'
}
WAIT_TIMEOUT=60 wait_for "home-chain enrolled at midbox" home_enrolled_at_midbox

echo "==> waiting for midbox to enrol at vps-chain"
midbox_enrolled_at_vps() {
    local out; out=$(ctl_json_on vps-chain status 2>/dev/null || true)
    echo "$out" | grep -q '"downstream_enrolled": true' && \
        echo "$out" | grep -q '"downstream_ip": "172.30.1.20"'
}
WAIT_TIMEOUT=60 wait_for "midbox enrolled at vps-chain" midbox_enrolled_at_vps

# -------- gating: wait for home's predicate to land at midbox --------------

echo "==> waiting for home-chain's predicate push to land at midbox"
predicate_landed_at_midbox() {
    # `derived-rules` is exposed over the loopback control socket via
    # yggdrasilctl `local derived-rules --json`.
    local body
    body=$(ctl_json_on midbox derived-rules 2>/dev/null || true)
    echo "$body" | grep -q '"name": "home-tcp-echo"' && \
        echo "$body" | grep -q '"listen_port": 7200'
}
WAIT_TIMEOUT=30 wait_for "home-tcp-echo predicate visible at midbox" predicate_landed_at_midbox

# -------- predicate flow: traffic through the derived chain ----------------

echo "==> [predicate-flow] TCP through midbox:7200 -> home:7200 -> home:7100"

# midbox should have derived a listener on midbox:7200 that forwards to
# 172.30.1.30:7200 (home), which is home's terminal-mode rule, which
# forwards to home's 127.0.0.1:7100 loopback echo. Wait for midbox's
# supervisor to bind the listener (derived asynchronously after the
# predicate ack) before sending traffic.
midbox_listener_bound() {
    ctl_on midbox rules list | grep -q '^home-tcp-echo '
}
WAIT_TIMEOUT=15 wait_for "midbox derived listener for home-tcp-echo" midbox_listener_bound

run_chain_tcp_echo() {
    dc_exec client-chain python3 - <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(("172.30.1.20", 7200))
payload = b"chain-predicate-flow-" + b"a" * 200
s.sendall(payload)
got = b""
while len(got) < len(payload):
    chunk = s.recv(4096)
    if not chunk:
        break
    got += chunk
s.close()
sys.exit(0 if got == payload else 1)
PY
}
WAIT_TIMEOUT=15 wait_for "TCP echo round-trips through the derived chain" run_chain_tcp_echo

# -------- chain diff from home: in-sync, exit 0 ---------------------------

echo "==> [chain-diff] yggdrasilctl chain diff from home (full traversal)"

# `chain diff` walks home -> midbox -> vps. With mid-chain predicate
# forwarding, every relay hop forwards the verbatim predicate set
# upstream after applying it locally, so all three hops should converge
# to the same view (drift_detected=false). Exit code 0 == in sync.
run_chain_diff() {
    rc=0
    dc_exec home-chain yggdrasilctl \
        chain --socket /run/yggdrasil/control.sock \
        diff >/dev/null 2>&1 || rc=$?
    [[ $rc -eq 0 ]]
}
WAIT_TIMEOUT=15 wait_for "chain diff (human) reachable and returns rc=0" run_chain_diff

echo "==> [chain-diff] yggdrasilctl --json chain diff structured output"
diff_json=$(dc_exec home-chain yggdrasilctl \
    --json chain --socket /run/yggdrasil/control.sock \
    diff || true)
echo "$diff_json" | python3 -c '
import json, sys
report = json.load(sys.stdin)
hops = report["hops"]
# Three hops: home (hop 0), midbox (hop 1), vps (hop 2). With mid-chain
# predicate forwarding enabled, all three see the same predicate set.
assert len(hops) == 3, f"expected 3 hops, got {len(hops)}: {hops}"
for i, hop in enumerate(hops):
    names = [p["name"] for p in hop["view"]["predicates"]]
    assert "home-tcp-echo" in names, f"hop {i} missing home-tcp-echo: {names}"
assert report["drift_detected"] is False, "expected no drift across forwarded chain"
print(f"[chain-diff] 3 hops reached; all see home-tcp-echo; drift_detected=False")
' || fail "chain diff --json output did not match expectations"

# -------- chain canary from home: arm walks all 3 hops, probe echoes ------

echo "==> [chain-canary] yggdrasilctl chain canary --port 7200 --proto tcp from home"

# Run from home (the terminal hop). The arm phase recurses upstream
# along home -> midbox -> vps, so the JSON report should carry three
# hops. The probe data connects to home's local rule listener; the
# canary intercept at home short-circuits it to in-process echo
# without touching home's 127.0.0.1:7100 backend, so the rule under
# test would still pass even if that backend were down.
canary_json=$(dc_exec home-chain yggdrasilctl \
    --json chain --socket /run/yggdrasil/control.sock \
    canary --port 7200 --proto tcp --timeout 5s \
    || true)
echo "$canary_json" | python3 -c '
import json, sys
reports = json.load(sys.stdin)
assert isinstance(reports, list), f"expected JSON array, got {type(reports).__name__}"
assert len(reports) == 1, f"expected one report for tcp/7200, got {len(reports)}"
report = reports[0]
assert report["status"] == "ok", f"unexpected status: {report}"
assert report["rule_name"] == "home-tcp-echo", f"unexpected rule_name: {report}"
chain = report["chain"]
assert len(chain) == 3, f"expected 3 chain hops, got {len(chain)}: {chain}"
assert chain[0]["echo_armed"] is True, \
    f"home hop should be echo_armed (terminal): {chain[0]}"
assert chain[0]["rule_present"] is True, \
    f"home hop should have rule_present: {chain[0]}"
# Probe ran, observed at least some bytes in each direction.
probe = report["probe_results"]
assert probe is not None, f"missing probe_results: {report}"
assert probe["c_to_s"]["sent"] > 0, f"no bytes sent: {probe}"
print(f"[chain-canary] 3 hops armed, probe OK, "
      f"sent={probe['c_to_s']['sent']} bytes, "
      f"received={probe['s_to_c']['sent']} bytes")
' || fail "chain canary --json output did not match expectations"

# -------- done -------------------------------------------------------------

echo
echo "ALL CHAIN E2E TESTS PASSED"
