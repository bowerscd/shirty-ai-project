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
        yggdrasilctl local --socket /run/yggdrasil/control.sock "$@"
}

ctl_json() {
    "${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T vps \
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
name     = "tcp-echo-alt"
listen   = "0.0.0.0:7010"
protocol = "tcp"
target   = "127.0.0.1:7100"
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

# -------- test 6: health + metrics over UDS ---------------------------------

echo "==> [health] yggdrasilctl local health"
health_out=$(ctl health) || fail "local health request failed"
echo "$health_out" | grep -q '^ready:[[:space:]]*true' \
    || fail "local health: ready not true ($health_out)"
echo "    [ok] local health reports ready=true"

echo "==> [derived-rules] yggdrasilctl local derived-rules"
# Terminal-mode home owns the predicate publisher, so the snapshot must
# contain its three rules. vps (gateway) receives the same predicates
# via the chain control plane and surfaces them too. We query vps here
# because all ctl helpers run inside the vps container.
derived_json=$(ctl derived-rules) || fail "local derived-rules request failed"
echo "$derived_json" | grep -q '"name": "tcp-echo"' \
    || fail "derived-rules missing tcp-echo predicate"
echo "$derived_json" | grep -q '"predicate_version"' \
    || fail "derived-rules missing chain.predicate_version"
echo "    [ok] derived-rules snapshot contains pushed predicates"

# -------- test 6b: chain summary 2-hop fanout (home -> vps) -----------------

echo "==> [chain-summary] yggdrasilctl chain diff --json from home (2 hops)"

# `chain diff` issues a Request::ChainSummary which fans out over the
# chain control plane: home is the terminal (hop 0) and walks one
# upstream step to vps (hop 1). With predicate forwarding both hops
# converge to the same view (drift_detected=false).
chain_summary_2hop=$("${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T home \
    yggdrasilctl --json chain --socket /run/yggdrasil/control.sock diff) \
    || fail "chain diff --json from home failed"
echo "$chain_summary_2hop" | python3 -c '
import json, sys
report = json.load(sys.stdin)
hops = report["hops"]
assert len(hops) == 2, f"expected 2 hops (home + vps), got {len(hops)}: {hops}"
for i, hop in enumerate(hops):
    names = [p["name"] for p in hop["view"]["predicates"]]
    assert "tcp-echo" in names, f"hop {i} missing tcp-echo: {names}"
assert report["drift_detected"] is False, f"unexpected drift: {report}"
print(f"[chain-summary] 2 hops; both see tcp-echo; drift_detected=False")
' || fail "chain diff --json output did not match 2-hop expectations"
echo "    [ok] chain diff --json reports 2 hops in sync"

# -------- test 6c: chain ping per-hop RTT (home -> vps) ---------------------

echo "==> [chain-ping] yggdrasilctl chain ping --json from home (2 hops)"

# `chain ping` reuses the same Request::ChainSummary RPC and projects
# the per-hop query_rtt_ms field. Hop 0 (local) has rtt=null; hop 1
# (vps) is RTT-stamped by home as it forwards upstream.
chain_ping_2hop=$("${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T home \
    yggdrasilctl --json chain --socket /run/yggdrasil/control.sock ping) \
    || fail "chain ping --json from home failed"
echo "$chain_ping_2hop" | python3 -c '
import json, sys
report = json.load(sys.stdin)
hops = report["hops"]
assert len(hops) == 2, f"expected 2 hops (home + vps), got {len(hops)}: {hops}"
assert hops[0]["query_rtt_ms"] is None, f"local hop must have null rtt: {hops[0]}"
rtt = hops[1]["query_rtt_ms"]
assert isinstance(rtt, int) and rtt >= 0, f"upstream rtt missing or invalid: {hops[1]}"
print(f"[chain-ping] hop1 rtt={rtt}ms")
' || fail "chain ping --json output did not match 2-hop expectations"
echo "    [ok] chain ping --json stamps RTT on the upstream hop"

# -------- test 7: metrics scrape over UDS -----------------------------------

echo "==> [metrics] yggdrasilctl local metrics exposes build_info + last_heartbeat gauge"
metrics_body=$(ctl metrics) || fail "local metrics request failed"

# Sanity: build_info gauge is always exported.
echo "$metrics_body" | grep -q 'yggdrasil_build_info' \
    || fail "metrics missing yggdrasil_build_info"

# The heartbeat gauge is set on every accepted heartbeat. home beats once
# a second in this stack, so it must be present and within ~30s of now.
heartbeat_line=$(echo "$metrics_body" | grep -E '^yggdrasil_last_heartbeat_timestamp_seconds ' || true)
[[ -n "$heartbeat_line" ]] || fail "metrics missing yggdrasil_last_heartbeat_timestamp_seconds"
heartbeat_ts=$(echo "$heartbeat_line" | awk '{print $2}')
now_ts=$(date +%s)
# Floor the floating-point timestamp to an integer.
heartbeat_int=${heartbeat_ts%.*}
age=$(( now_ts - heartbeat_int ))
if (( age < 0 || age > 30 )); then
    fail "yggdrasil_last_heartbeat_timestamp_seconds=$heartbeat_ts is stale (age ${age}s)"
fi
echo "    [ok] yggdrasil_last_heartbeat_timestamp_seconds fresh (age ${age}s)"

# -------- test 8: DNS-resolved target (terminal mode) ----------------------

echo "==> [dns-upstream] terminal-mode rule with DNS-resolved target"

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

# -------- test 9: runtime tracing-filter swap -------------------------------

echo "==> [trace] yggdrasilctl local trace round-trips a directive"
trace_json=$(ctl_json trace debug) || fail "local trace debug failed"
echo "$trace_json" | grep -q '"active": "debug"' \
    || fail "trace response missing active=debug"
trace_reset_json=$(ctl_json trace --reset) || fail "local trace --reset failed"
echo "$trace_reset_json" | grep -q '"active": "info"' \
    || fail "trace --reset did not restore startup directive (got $trace_reset_json)"
echo "    [ok] trace directive applied + reset round-trip"

# -------- done --------------------------------------------------------------

echo
echo "ALL E2E TESTS PASSED"
