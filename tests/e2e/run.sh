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
        yggdrasilctl --socket /run/yggdrasil/control.sock local "$@"
}

ctl_json() {
    "${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T vps \
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
    "${DC[@]}" "${COMPOSE_ARGS[@]}" logs --no-color --tail 80 vps  || true
    "${DC[@]}" "${COMPOSE_ARGS[@]}" logs --no-color --tail 80 home || true
    exit 1
}

# -------- gating: wait for first authenticated heartbeat --------------------

echo "==> waiting for home to enrol and heartbeat"
downstream_enrolled() {
    local out; out=$(ctl_json status 2>/dev/null || true)
    echo "$out" | grep -q '"downstream_enrolled": true' && \
        echo "$out" | grep -q '"downstream_ip": "172.30.0.20"'
}
WAIT_TIMEOUT=60 wait_for "downstream enrolled + heartbeat seen from 172.30.0.20" downstream_enrolled

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

"${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T home bash -c "cat >/etc/yggdrasil/rules/tcp-echo-alt.toml" <<'EOF'
[[rule]]
name        = "tcp-echo-alt"
listen      = "0.0.0.0:7010"
protocol    = "tcp"
target_addr = "127.0.0.1:7100"
EOF

rule_visible() {
    ctl rules list | grep -q '^tcp-echo-alt '
}
WAIT_TIMEOUT=10 wait_for "supervisor picked up tcp-echo-alt rule" rule_visible

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
"${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T home rm -f /etc/yggdrasil/rules/tcp-echo-alt.toml

rule_gone() {
    ! ctl rules list | grep -q '^tcp-echo-alt '
}
WAIT_TIMEOUT=10 wait_for "supervisor removed tcp-echo-alt rule" rule_gone

# Original rule must still forward — its listener should never have been
# touched. (Proper in-flight-connection invariance is covered by the
# heartbeat_invariance_tcp.rs / hot_reload.rs integration tests.)
run_tcp_echo || fail "original tcp-echo rule broke after unrelated reload"
echo "    [ok] original rule still works post-reload"

# -------- test 5: control plane status --------------------------------------

echo "==> [status] yggdrasilctl status returns sensible data"
status_json=$(ctl_json status)
echo "$status_json" | grep -q '"downstream_enrolled": true'   || fail "status: downstream_enrolled not true"
echo "$status_json" | grep -q '"rule_count": 3'              || fail "status: expected 3 rules (tcp-echo + udp-echo + dns-echo)"
echo "$status_json" | grep -q '"downstream_ip": "172.30.0.20"' || fail "status: downstream_ip wrong"
echo "    [ok] status JSON consistent"

# -------- test 6: health + metrics HTTP listener ----------------------------

echo "==> [health] /healthz, /readyz, /, /metrics, 404"

# All endpoints share the [metrics].listen socket (0.0.0.0:9090 in the e2e
# config). Reachable from the `client` container via the wan network; not
# exposed to the host.
http_probe() {
    local path="$1"
    "${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T client python3 - "$path" <<'PY'
import sys, urllib.request, urllib.error
url = "http://172.30.0.10:9090" + sys.argv[1]
req = urllib.request.Request(url, method="GET")
try:
    with urllib.request.urlopen(req, timeout=5) as r:
        sys.stdout.write(f"{r.status}\n")
        sys.stdout.write(r.read().decode("utf-8", "replace"))
except urllib.error.HTTPError as e:
    sys.stdout.write(f"{e.code}\n")
    sys.stdout.write(e.read().decode("utf-8", "replace"))
PY
}

# /healthz: always 200, body "ok\n".
healthz=$(http_probe /healthz) || fail "/healthz request failed"
[[ "$(echo "$healthz" | head -n 1)" == "200" ]] || fail "/healthz status: $(echo "$healthz" | head -n 1)"
[[ "$(echo "$healthz" | tail -n +2)" == "ok" ]] || fail "/healthz body: $(echo "$healthz" | tail -n +2)"
echo "    [ok] /healthz 200 ok"

# /readyz: 200 once the daemon has marked itself ready (post-subsystem-bind).
# The peer-enrolled gate above guarantees the daemon is well past that point.
readyz=$(http_probe /readyz) || fail "/readyz request failed"
[[ "$(echo "$readyz" | head -n 1)" == "200" ]] || fail "/readyz status: $(echo "$readyz" | head -n 1)"
[[ "$(echo "$readyz" | tail -n +2)" == "ready" ]] || fail "/readyz body: $(echo "$readyz" | tail -n +2)"
echo "    [ok] /readyz 200 ready"

# /: HTML index listing the routes.
root=$(http_probe /) || fail "/ request failed"
[[ "$(echo "$root" | head -n 1)" == "200" ]] || fail "/ status: $(echo "$root" | head -n 1)"
echo "$root" | grep -q '/metrics' || fail "/ body missing /metrics link"
echo "$root" | grep -q '/healthz' || fail "/ body missing /healthz link"
echo "$root" | grep -q '/readyz'  || fail "/ body missing /readyz link"
echo "    [ok] / 200 with route index"

# /nope: 404.
nope=$(http_probe /nope) || fail "/nope request failed"
[[ "$(echo "$nope" | head -n 1)" == "404" ]] || fail "/nope status: $(echo "$nope" | head -n 1)"
echo "    [ok] /nope 404"

# -------- test 7: /metrics scrape -------------------------------------------

echo "==> [metrics] /metrics exposes build_info + last_heartbeat gauge"
metrics=$(http_probe /metrics) || fail "/metrics request failed"
[[ "$(echo "$metrics" | head -n 1)" == "200" ]] || fail "/metrics status: $(echo "$metrics" | head -n 1)"
metrics_body=$(echo "$metrics" | tail -n +2)

# Sanity: build_info gauge is always exported.
echo "$metrics_body" | grep -q 'yggdrasil_build_info' \
    || fail "/metrics missing yggdrasil_build_info"

# The heartbeat gauge is set on every accepted heartbeat. home beats once
# a second in this stack, so it must be present and within ~30s of now.
heartbeat_line=$(echo "$metrics_body" | grep -E '^yggdrasil_last_heartbeat_timestamp_seconds ' || true)
[[ -n "$heartbeat_line" ]] || fail "/metrics missing yggdrasil_last_heartbeat_timestamp_seconds"
heartbeat_ts=$(echo "$heartbeat_line" | awk '{print $2}')
now_ts=$(date +%s)
# Floor the floating-point timestamp to an integer.
heartbeat_int=${heartbeat_ts%.*}
age=$(( now_ts - heartbeat_int ))
if (( age < 0 || age > 30 )); then
    fail "yggdrasil_last_heartbeat_timestamp_seconds=$heartbeat_ts is stale (age ${age}s)"
fi
echo "    [ok] yggdrasil_last_heartbeat_timestamp_seconds fresh (age ${age}s)"

# -------- test 8: DNS-resolved target_host (terminal mode) ------------------

echo "==> [dns-upstream] terminal-mode rule with target_host"

# home hosts a TCP rule on :7200 whose upstream is `home-echo-dns:7100`.
# `home-echo-dns` is pinned to home's own IP (172.30.0.20) via
# `extra_hosts:` in compose.e2e.yml, so the OS resolver returns home's
# IP and the rule TCP-connects back to the python TCP echo running in
# the same network namespace. The DNS resolver converges within ~ms of
# the supervisor binding the rule, but on a cold container start the
# listener may accept before the first resolution lands — `wait_for`
# polls until at least one connection round-trips.

run_dns_echo() {
    "${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T client python3 - <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(("172.30.0.20", 7200))
payload = b"dns-resolved-" + b"z" * 200
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
WAIT_TIMEOUT=15 wait_for "DNS-resolved upstream echo via home:7200" run_dns_echo

# -------- done --------------------------------------------------------------

echo
echo "ALL E2E TESTS PASSED"
