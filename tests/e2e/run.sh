#!/usr/bin/env bash
# tests/e2e/run.sh — end-to-end test for the compose-based network stack.
#
# Runs from the host (or a CI runner). Brings up the compose stack, exercises
# real TCP + UDP traffic through the proxy, verifies the control plane, and
# tears down cleanly.
#
# Usage:
#   ./tests/e2e/run.sh               # build + run + verify + teardown
#   KEEP_STACK=1 ./tests/e2e/run.sh  # leave the stack up at the end for poking
set -euo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
COMPOSE_FILE="$REPO_ROOT/docker/compose.e2e.yml"
COMPOSE_ARGS=(-f "$COMPOSE_FILE" -p yggdrasil-e2e)

# Prefer `podman-compose` (the native podman tool) over `podman compose`
# (which delegates to whatever external compose-provider podman finds).
# The compose file is plain v3 syntax — both honour it identically.
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
    echo "==> tearing down stack"
    "${DC[@]}" "${COMPOSE_ARGS[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap teardown EXIT

cd "$REPO_ROOT"

echo "==> building images"
"${DC[@]}" "${COMPOSE_ARGS[@]}" build

echo "==> running bootstrap (init service)"
# podman-compose 1.5 doesn't reliably honour
# `depends_on.condition: service_completed_successfully`, so we run the
# one-shot init service explicitly before bringing up the daemons. `run`
# attaches and propagates the container's exit code.
if ! "${DC[@]}" "${COMPOSE_ARGS[@]}" run --rm init; then
    echo "FAIL: bootstrap (init) exited non-zero" >&2
    exit 1
fi

echo "==> bringing daemons up"
# podman-compose has no `--wait`; the wait_for loops below poll the actual
# readiness condition (control socket + first authenticated heartbeat).
"${DC[@]}" "${COMPOSE_ARGS[@]}" up -d vps home client

# -------- helpers -----------------------------------------------------------

ctl() {
    "${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T vps \
        yggdrasilctl --socket /run/yggdrasil/control.sock "$@"
}

ctl_json() {
    ctl --json "$@"
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
    "${DC[@]}" "${COMPOSE_ARGS[@]}" logs --no-color --tail 80 vps  || true
    "${DC[@]}" "${COMPOSE_ARGS[@]}" logs --no-color --tail 80 home || true
    exit 1
}

# -------- gating: wait for first authenticated heartbeat --------------------

echo "==> waiting for ratatoskr to enrol and heartbeat"
peer_enrolled() {
    local out; out=$(ctl_json status 2>/dev/null || true)
    echo "$out" | grep -q '"peer_enrolled": true' && \
        echo "$out" | grep -q '"peer_ip": "172.30.0.20"'
}
WAIT_TIMEOUT=60 wait_for "peer enrolled + heartbeat seen from 172.30.0.20" peer_enrolled

# -------- test 1: TCP echo --------------------------------------------------

echo "==> [tcp-echo] proxied TCP forwarding"

run_tcp_echo() {
    "${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T client python3 - <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(("172.30.0.10", 7000))
payload = b"hello-tcp-" + b"x" * 200
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
run_tcp_echo || fail "TCP echo did not round-trip through the proxy"
echo "    [ok] TCP echo via 172.30.0.10:7000 → home:7100"

# -------- test 2: UDP echo --------------------------------------------------

echo "==> [udp-echo] proxied UDP forwarding"

run_udp_echo() {
    "${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T client python3 - <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
payload = b"hello-udp-" + b"y" * 200
s.sendto(payload, ("172.30.0.10", 7001))
got, _ = s.recvfrom(4096)
s.close()
sys.exit(0 if got == payload else 1)
PY
}
run_udp_echo || fail "UDP echo did not round-trip through the proxy"
echo "    [ok] UDP echo via 172.30.0.10:7001 → home:7101"

# -------- test 3: branch hot reload -----------------------------------------

echo "==> [hot-reload] dropping a new branch file"

"${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T vps bash -c "cat >/etc/yggdrasil/branches/tcp-echo-alt.toml" <<'EOF'
[[rule]]
name          = "tcp-echo-alt"
listen        = "0.0.0.0:7010"
protocol      = "tcp"
upstream_port = 7100
EOF

branch_visible() {
    ctl branches list | grep -q '^tcp-echo-alt '
}
WAIT_TIMEOUT=10 wait_for "supervisor picked up tcp-echo-alt rule" branch_visible

# Now drive traffic through the freshly-added rule.
run_alt_tcp_echo() {
    "${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T client python3 - <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(("172.30.0.10", 7010))
s.sendall(b"reloaded")
got = s.recv(4096)
s.close()
sys.exit(0 if got == b"reloaded" else 1)
PY
}
run_alt_tcp_echo || fail "hot-reloaded rule did not forward traffic"
echo "    [ok] traffic flows through hot-reloaded rule"

# -------- test 4: unchanged rule is undisturbed by reload -------------------

echo "==> [invariance] removing one rule does not break another"

# Remove the alt rule and verify the supervisor picks it up.
"${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T vps rm -f /etc/yggdrasil/branches/tcp-echo-alt.toml

branch_gone() {
    ! ctl branches list | grep -q '^tcp-echo-alt '
}
WAIT_TIMEOUT=10 wait_for "supervisor removed tcp-echo-alt rule" branch_gone

# Original rule must still forward — its listener should never have been
# touched. (Proper in-flight-connection invariance is covered by the
# heartbeat_invariance_tcp.rs / hot_reload.rs integration tests.)
run_tcp_echo || fail "original tcp-echo rule broke after unrelated reload"
echo "    [ok] original rule still works post-reload"

# -------- test 5: control plane status --------------------------------------

echo "==> [status] yggdrasilctl status returns sensible data"
status_json=$(ctl_json status)
echo "$status_json" | grep -q '"peer_enrolled": true'      || fail "status: peer_enrolled not true"
echo "$status_json" | grep -q '"branch_count": 2'          || fail "status: expected 2 branches (tcp-echo + udp-echo)"
echo "$status_json" | grep -q '"peer_ip": "172.30.0.20"'   || fail "status: peer_ip wrong"
echo "    [ok] status JSON consistent"

# -------- done --------------------------------------------------------------

echo
echo "ALL E2E TESTS PASSED"
