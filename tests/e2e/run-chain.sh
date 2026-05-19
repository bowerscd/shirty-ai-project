#!/usr/bin/env bash
# tests/e2e/run-chain.sh — end-to-end smoke for the 3-level chain control
# plane. Brings up `docker/compose.e2e.chain.yml` (vps-chain, midbox,
# home-chain, client-chain) and exercises:
#
#   1. predicate flow:  home publishes -> midbox derives -> traffic flows
#   2. chain tunnel:    home -> midbox (forward) -> vps-chain (terminate)
#                       through `yggdrasilctl chain tunnel open`
#   3. chain diff:      `yggdrasilctl chain diff` from home, no drift
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
        yggdrasilctl --socket /run/yggdrasil/control.sock local "$@"
}

ctl_json_on() {
    local node="$1"; shift
    dc_exec "$node" \
        yggdrasilctl --socket /run/yggdrasil/control.sock --json local "$@"
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
    # `/internal/derived-rules` is loopback-only — we query it from
    # inside the midbox container.
    local body
    body=$(dc_exec midbox python3 - <<'PY' 2>/dev/null || true
import urllib.request, sys
try:
    with urllib.request.urlopen("http://127.0.0.1:9090/internal/derived-rules", timeout=3) as r:
        if r.status != 200:
            sys.exit(2)
        sys.stdout.write(r.read().decode("utf-8", "replace"))
except Exception:
    sys.exit(3)
PY
)
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

# -------- chain tunnel: home -> midbox (forward) -> vps (terminate) --------

echo "==> [chain-tunnel] open from home, forward through midbox, terminate at vps"

# Extract vps-chain's tagged pubkey. midbox's [chain.upstream] block holds
# it (written by `identity add-upstream` during bootstrap). awk walks the
# TOML to extract the pubkey under that specific section, ignoring the
# downstream block which holds a different pubkey.
VPS_PK=$(dc_exec midbox awk '
    /^\[chain\.upstream\]/ { f=1; next }
    /^\[/                   { f=0 }
    f && /^pubkey *=/       { gsub(/"/,"",$3); print $3; exit }
' /etc/yggdrasil/config.toml | tr -d '\r\n')
[[ -n "$VPS_PK" ]] || fail "could not extract vps tagged pubkey from midbox config"
[[ "$VPS_PK" == x25519:* ]] || fail "extracted vps pubkey is not tagged: $VPS_PK"
echo "    [info] vps-chain pubkey: $VPS_PK"

# Drive `yggdrasilctl chain tunnel open` from inside home-chain. The CLI
# splices stdin↔tunnel and stdout↔tunnel with a tokio `select!`; if stdin
# EOFs before the echoed bytes are read back, the select cancels the
# read side prematurely. To avoid that race we drive the CLI via a small
# Python script with a reader thread: write the payload, wait for the
# echoed bytes to appear on stdout, then close stdin to terminate.
run_chain_tunnel_echo() {
    dc_exec -e PUBKEY="$VPS_PK" home-chain python3 - <<'PY'
import os, subprocess, sys, threading, time

PUBKEY = os.environ["PUBKEY"]
payload = f"chain-tunnel-payload-{time.time_ns()}".encode()

p = subprocess.Popen(
    [
        "yggdrasilctl",
        "--socket", "/run/yggdrasil/control.sock",
        "chain", "tunnel", "open",
        "--pubkey", PUBKEY,
        "--dest", "127.0.0.1:7100",
    ],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

got = bytearray()
def reader():
    while True:
        try:
            chunk = p.stdout.read(4096)
        except Exception:
            break
        if not chunk:
            break
        got.extend(chunk)

t = threading.Thread(target=reader, daemon=True)
t.start()

p.stdin.write(payload)
p.stdin.flush()

deadline = time.time() + 5
while len(got) < len(payload) and time.time() < deadline:
    time.sleep(0.02)

# Close stdin only AFTER the response has arrived. The CLI's select!
# will then unwind cleanly.
try:
    p.stdin.close()
except BrokenPipeError:
    pass
try:
    p.wait(timeout=3)
except subprocess.TimeoutExpired:
    p.terminate()
    try:
        p.wait(timeout=2)
    except subprocess.TimeoutExpired:
        p.kill()

ok = bytes(got[: len(payload)]) == payload
if not ok:
    err = p.stderr.read().decode("utf-8", "replace") if p.stderr else ""
    sys.stderr.write(f"chain tunnel echo mismatch\n  sent: {payload!r}\n  got:  {bytes(got)!r}\n  stderr: {err}\n")
sys.exit(0 if ok else 1)
PY
}
WAIT_TIMEOUT=15 wait_for "chain tunnel echoes through home -> midbox -> vps" run_chain_tunnel_echo

# -------- chain diff from home: in-sync, exit 0 ---------------------------

echo "==> [chain-diff] yggdrasilctl chain diff from home (full traversal)"

# `chain diff` walks home -> midbox -> vps. v1 relays do not re-project
# predicates downstream → upstream (see bootstrap-chain.sh comment), so
# vps's local /internal/derived-rules view is empty and the diff WILL
# report drift at hop 2. What this milestone verifies is that the chain
# tunnel through midbox to vps works end-to-end: the CLI successfully
# fetches /internal/derived-rules from BOTH upstream hops via the chain
# tunnel forwarding path (the TCP-style half-close primitive). Exit code
# 1 == drift detected (expected here). Exit codes 2+ indicate a
# transport failure and are still treated as failure.
run_chain_diff() {
    # `set -e` allowed because we run the CLI in a subshell that maps
    # rc=0|1 → success and anything else → failure.
    rc=0
    dc_exec home-chain yggdrasilctl \
        --socket /run/yggdrasil/control.sock \
        chain diff >/dev/null 2>&1 || rc=$?
    # 0 == in sync, 1 == drift detected (legitimate here); anything
    # else is a transport / CLI failure.
    [[ $rc -eq 0 || $rc -eq 1 ]]
}
WAIT_TIMEOUT=15 wait_for "chain diff (human) reachable and returns rc<=1" run_chain_diff

echo "==> [chain-diff] yggdrasilctl --json chain diff structured output"
diff_json=$(dc_exec home-chain yggdrasilctl \
    --socket /run/yggdrasil/control.sock --json \
    chain diff || true)
echo "$diff_json" | python3 -c '
import json, sys
report = json.load(sys.stdin)
hops = report["hops"]
# Three hops: home (hop 0), midbox (hop 1), vps (hop 2). The fetch for
# hops 1 and 2 goes through the chain tunnel forwarding path; reaching
# both confirms the half-close splice works at every layer.
assert len(hops) == 3, f"expected 3 hops, got {len(hops)}: {hops}"
# Hop 0 is the local node. Its view must contain the predicate we
# published.
preds = hops[0]["view"]["predicates"]
names = [p["name"] for p in preds]
assert "home-tcp-echo" in names, names
# Hop 1 (midbox) accepted home-chains push, so it sees the same
# predicate set as hop 0 (in sync).
preds1 = hops[1]["view"]["predicates"]
names1 = [p["name"] for p in preds1]
assert "home-tcp-echo" in names1, names1
# Hop 2 (vps) is the chain root; v1 relays do not re-project
# downstream predicate sets upward, so vps sees an empty set. This is
# the expected v1 behaviour and explains the legitimate drift at hop 2.
preds2 = hops[2]["view"]["predicates"]
assert preds2 == [], f"expected empty predicate set at hop 2, got {preds2}"
assert report["drift_detected"] is True, "expected drift between hop 1 and hop 2 (v1 relays do not re-project)"
print(f"[chain-diff] 3 hops reached; hop 0={names}, hop 1={names1}, hop 2=[]; drift_detected=True (expected)")
' || fail "chain diff --json output did not match expectations"

# -------- done -------------------------------------------------------------

echo
echo "ALL CHAIN E2E TESTS PASSED"
