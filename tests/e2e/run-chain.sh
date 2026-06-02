#!/usr/bin/env bash
# tests/e2e/run-chain.sh — end-to-end smoke for the 3-node chain
# quickstart deployment (terminal -> relay -> gateway).
#
# Topology (per docker/compose.e2e.chain.yml):
#
#   client ─client_wan─► gateway ─inet_link─► relay ─chain_link─► terminal ─home_lan─► {nginx, nginx-alt, tcp-echo, udp-echo}
#
# Same scenario suite as run-quickstart.sh, with the extra hop:
#   - Predicate propagation must traverse two hops (terminal -> relay -> gateway).
#   - `chain diff` from terminal must report 3 hops, no drift.
#   - `chain canary` must report 3 chain hops armed.
#
# Usage:
#   ./tests/e2e/run-chain.sh                # build + run + verify + teardown
#   KEEP_STACK=1 ./tests/e2e/run-chain.sh   # leave stack up for poking
set -euo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
COMPOSE_FILE="$REPO_ROOT/docker/compose.e2e.chain.yml"
RUNTIME_DIR="$REPO_ROOT/tests/e2e/runtime/chain"
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
        echo "==> KEEP_STACK=1 set; leaving stack up (runtime tree at $RUNTIME_DIR)"
        return
    fi
    echo "==> tearing down stack"
    "${DC[@]}" "${COMPOSE_ARGS[@]}" down --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$RUNTIME_DIR" 2>/dev/null || true
}
trap teardown EXIT

cd "$REPO_ROOT"

echo "==> preparing fresh runtime tree at tests/e2e/runtime/chain"
rm -rf "$RUNTIME_DIR"
mkdir -p "$RUNTIME_DIR"/{gateway,relay,terminal}/{etc,run,state}
# Separate dir for the client's trust store; see run-quickstart.sh
# for why this is split from the terminal's live cert dir.
mkdir -p "$RUNTIME_DIR/client-trust"

echo "==> building images"
"${DC[@]}" "${COMPOSE_ARGS[@]}" build

echo "==> running bootstrap (init-chain)"
if ! "${DC[@]}" "${COMPOSE_ARGS[@]}" run --rm init-chain; then
    echo "FAIL: init-chain exited non-zero" >&2
    exit 1
fi

cp "$RUNTIME_DIR/terminal/etc/certs/server.pem" "$RUNTIME_DIR/client-trust/server.pem"

echo "==> bringing app + daemons up"
"${DC[@]}" "${COMPOSE_ARGS[@]}" up -d \
    app-nginx app-nginx-alt app-tcp app-udp \
    gateway relay terminal client

# -------- helpers -----------------------------------------------------------

# `container_name:` prefix from compose.e2e.chain.yml. Used by the
# detached-exec helper below to bypass podman-compose 1.5's broken
# `exec -d` (it blocks until the inner command finishes, defeating
# the whole point of detach — verified directly: a 5s sleep makes the
# `exec -dT` call take 5s, not return immediately).
CTR_PREFIX="e2e-chain"

dc_exec() {
    "${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T "$@"
}

# Detached exec, used when the inner command MUST run in the background
# (e.g. a slow client we want to be in-flight while the runner script
# performs a SIGTERM). Goes around podman-compose by calling
# `podman exec -d` directly against the well-known container name.
# Returns immediately (does not wait for the inner command).
dc_exec_detached() {
    local svc="$1"; shift
    podman exec -d "${CTR_PREFIX}-${svc}" "$@" >/dev/null
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
    "${DC[@]}" "${COMPOSE_ARGS[@]}" logs --tail 120 gateway  || true
    "${DC[@]}" "${COMPOSE_ARGS[@]}" logs --tail 120 relay    || true
    "${DC[@]}" "${COMPOSE_ARGS[@]}" logs --tail 120 terminal || true
    exit 1
}

# -------- enrollment gating (both hops) ------------------------------------

echo "==> waiting for terminal to enrol at relay"
terminal_enrolled_at_relay() {
    local out; out=$(ctl_json_on relay status 2>/dev/null || true)
    echo "$out" | grep -q '"downstream_enrolled": true' && \
        echo "$out" | grep -q '"downstream_ip": "172.31.12.20"'
}
WAIT_TIMEOUT=60 wait_for "terminal enrolled at relay" terminal_enrolled_at_relay

echo "==> waiting for relay to enrol at gateway"
relay_enrolled_at_gateway() {
    local out; out=$(ctl_json_on gateway status 2>/dev/null || true)
    echo "$out" | grep -q '"downstream_enrolled": true' && \
        echo "$out" | grep -q '"downstream_ip": "172.31.11.20"'
}
WAIT_TIMEOUT=60 wait_for "relay enrolled at gateway" relay_enrolled_at_gateway

# -------- predicate propagation (terminal -> relay -> gateway) -------------

echo "==> waiting for tcp-echo + udp-echo + https-app predicates at gateway"
predicates_landed() {
    local body; body=$(ctl_json_on gateway derived-rules 2>/dev/null || true)
    echo "$body" | grep -q '"name": "tcp-echo"' && \
        echo "$body" | grep -q '"name": "udp-echo"' && \
        echo "$body" | grep -q '"listen_port": 8443'
}
WAIT_TIMEOUT=30 wait_for "all three predicates derived at gateway" predicates_landed

# -------- chain diff (3 hops, no drift) ------------------------------------

echo "==> [chain-diff] yggdrasilctl chain diff from terminal (3 hops)"
diff_json=$(dc_exec terminal yggdrasilctl \
    --json chain --socket /run/yggdrasil/control.sock \
    diff || true)
echo "$diff_json" | python3 -c '
import json, sys
report = json.load(sys.stdin)
hops = report["hops"]
assert len(hops) == 3, f"expected 3 hops, got {len(hops)}: {hops}"
for i, hop in enumerate(hops):
    names = [p["name"] for p in hop["view"]["predicates"]]
    for required in ("tcp-echo", "udp-echo"):
        assert required in names, f"hop {i} missing {required}: {names}"
assert report["drift_detected"] is False, f"unexpected drift: {report}"
print(f"[chain-diff] 3 hops in sync; all see tcp-echo + udp-echo")
' || fail "chain diff --json output did not match 3-hop expectations"

# -------- chain canary (each rule, 3 hops armed) ---------------------------

run_canary() {
    local port="$1" proto="$2" expected_rule="$3"
    local report; report=$(dc_exec terminal yggdrasilctl \
        --json chain --socket /run/yggdrasil/control.sock \
        canary --port "$port" --proto "$proto" --timeout 5s || true)
    echo "$report" | python3 -c "
import json, sys
reports = json.load(sys.stdin)
assert isinstance(reports, list), f'expected array, got {type(reports).__name__}'
assert len(reports) == 1, f'expected one report, got {len(reports)}'
r = reports[0]
assert r['status'] == 'ok', f'status not ok: {r}'
assert r['rule_name'] == '${expected_rule}', f'rule_name mismatch: {r}'
chain = r['chain']
assert len(chain) == 3, f'expected 3 chain hops, got {len(chain)}: {chain}'
print(f'[canary] ${expected_rule}/${proto}: 3 hops armed, status=ok')
" || fail "chain canary for ${expected_rule}/${proto} did not match expectations"
}

echo "==> [chain-canary] tcp-echo (port 7100)"
run_canary 7100 tcp tcp-echo
echo "==> [chain-canary] udp-echo (port 7101)"
run_canary 7101 udp udp-echo
# Note: `chain canary` for HTTPS routes uses a different invocation
# (auto-probes TCP + UDP on [server].https_listen, no --port/--proto
# flags) per docs/operations.md. The HTTPS surface is exercised
# directly by the three HTTPS GET phases below.

# -------- TCP echo end-to-end ----------------------------------------------

echo "==> [tcp-echo] client -> gateway:7100 -> chain -> app-tcp:7100"
run_tcp_echo() {
    dc_exec client python3 - <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(("172.31.10.20", 7100))
payload = b"chain-tcp-" + b"a" * 200
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
WAIT_TIMEOUT=15 wait_for "TCP echo round-trips through the 3-hop chain" run_tcp_echo

# -------- UDP echo end-to-end ----------------------------------------------

echo "==> [udp-echo] client -> gateway:7101 -> chain -> app-udp:7101"
run_udp_echo() {
    dc_exec client python3 - <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
payload = b"chain-udp-" + b"b" * 200
s.sendto(payload, ("172.31.10.20", 7101))
got, _ = s.recvfrom(65536)
s.close()
sys.exit(0 if got == payload else 1)
PY
}
WAIT_TIMEOUT=15 wait_for "UDP echo round-trips through the 3-hop chain" run_udp_echo

# -------- HTTPS GETs (SNI dispatch) ----------------------------------------

https_probe() {
    local sni="$1"
    dc_exec client python3 - "$sni" <<'PY'
import hashlib, http.client, json, socket, ssl, sys
sni = sys.argv[1]
addr = ("172.31.10.20", 8443)
ctx = ssl.create_default_context(cafile="/etc/ssl/yggdrasil-test/server.pem")
sock = socket.create_connection(addr, timeout=5)
ssock = ctx.wrap_socket(sock, server_hostname=sni)
leaf_der = ssock.getpeercert(binary_form=True)
fp = hashlib.sha256(leaf_der).hexdigest()
conn = http.client.HTTPSConnection(sni, 8443, context=ctx, timeout=5)
conn.sock = ssock
conn.request("GET", "/", headers={"Host": sni})
resp = conn.getresponse()
body = resp.read(1024).decode("utf-8", "replace").strip()
print(json.dumps({"status": resp.status, "body": body, "fp": fp}))
conn.close()
PY
}

echo "==> [https-primary] SNI=app.test.local -> app-nginx"
# Give the HTTPS frontend a moment to bind (predicate apply -> rule
# reconcile -> rustls handshake setup); subsequent probes are immediate.
sleep 1
probe_primary=$(https_probe app.test.local) || fail "HTTPS probe to app.test.local failed"
status1=$(echo "$probe_primary" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
body1=$(echo "$probe_primary"   | python3 -c "import json,sys; print(json.load(sys.stdin)['body'])")
fp1=$(echo "$probe_primary"     | python3 -c "import json,sys; print(json.load(sys.stdin)['fp'])")
[[ "$status1" == "200" ]] || fail "primary SNI: expected 200, got $status1"
[[ "$body1" == "primary backend (app-nginx)" ]] \
    || fail "primary SNI: expected primary body, got '$body1'"
echo "    [ok] primary SNI dispatched to app-nginx (leaf fp ${fp1:0:16}…)"

echo "==> [https-alt] SNI=alt.test.local -> app-nginx-alt"
probe_alt=$(https_probe alt.test.local) || fail "HTTPS probe to alt.test.local failed"
status2=$(echo "$probe_alt" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
body2=$(echo "$probe_alt"   | python3 -c "import json,sys; print(json.load(sys.stdin)['body'])")
fp2=$(echo "$probe_alt"     | python3 -c "import json,sys; print(json.load(sys.stdin)['fp'])")
[[ "$status2" == "200" ]] || fail "alt SNI: expected 200, got $status2"
[[ "$body2" == "alternate backend (app-nginx-alt)" ]] \
    || fail "alt SNI: expected alt body, got '$body2' — SNI dispatch landed wrong backend"
[[ "$fp2" == "$fp1" ]] || fail "alt SNI: leaf cert fingerprint differs from primary; same cert should cover both SANs"
echo "    [ok] alt SNI dispatched to app-nginx-alt (same cert)"

# -------- HSTS + custom response headers on primary route ------------------

echo "==> [https-headers] HSTS + [route.headers] stamped on primary route only"
headers_for_sni() {
    local sni="$1"
    dc_exec client python3 - "$sni" <<'PY'
import http.client, json, ssl, sys
sni = sys.argv[1]
ctx = ssl.create_default_context(cafile="/etc/ssl/yggdrasil-test/server.pem")
conn = http.client.HTTPSConnection(sni, 8443, context=ctx, timeout=5)
conn.request("GET", "/")
resp = conn.getresponse()
hdrs = {k.lower(): v for k, v in resp.getheaders()}
print(json.dumps(hdrs))
conn.close()
PY
}
hdrs_primary=$(headers_for_sni app.test.local) \
    || fail "header probe to primary SNI failed"
hdrs_alt=$(headers_for_sni alt.test.local) \
    || fail "header probe to alt SNI failed"
echo "$hdrs_primary" | python3 -c '
import json, sys
h = json.load(sys.stdin)
assert "strict-transport-security" in h, f"HSTS missing on primary: {h}"
assert h.get("x-robots-tag") == "noindex, nofollow", \
    f"X-Robots-Tag wrong on primary: {h}"
assert h.get("x-custom-e2e") == "primary-backend", \
    f"X-Custom-E2E wrong on primary: {h}"
' || fail "primary route missing HSTS or custom headers"
echo "$hdrs_alt" | python3 -c '
import json, sys
h = json.load(sys.stdin)
assert "x-custom-e2e" not in h, \
    f"X-Custom-E2E leaked from primary route into alt: {h}"
assert "x-robots-tag" not in h, \
    f"X-Robots-Tag leaked from primary route into alt: {h}"
' || fail "alt route is leaking primary route's headers"
echo "    [ok] HSTS + custom headers present on primary, absent on alt"

echo "==> [https-unknown] SNI=bogus.test.local rejected at TLS handshake"
unknown_sni_rejected() {
    dc_exec client python3 - <<'PY'
import socket, ssl, sys
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = socket.create_connection(("172.31.10.20", 8443), timeout=5)
try:
    ctx.wrap_socket(sock, server_hostname="bogus.test.local")
    sys.exit(1)
except ssl.SSLError:
    sys.exit(0)
finally:
    sock.close()
PY
}
unknown_sni_rejected || fail "unknown SNI: TLS handshake should have been rejected, but the connection succeeded"
echo "    [ok] unknown SNI rejected at TLS handshake (no [[route]] matched, cert resolver returned nothing)"

# -------- Cert hot-reload (in-place re-mint) -------------------------------

CERT_HOST_DIR="$RUNTIME_DIR/terminal/etc/certs"

remint_cert() {
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$CERT_HOST_DIR/server.key" \
        -out    "$CERT_HOST_DIR/server.pem" \
        -days   1 \
        -subj   "/CN=app.test.local" \
        -addext "subjectAltName=DNS:app.test.local,DNS:alt.test.local" \
        >/dev/null 2>&1
    chmod 0644 "$CERT_HOST_DIR/server.pem"
    chmod 0600 "$CERT_HOST_DIR/server.key"
}

echo "==> [cert-reload] re-minting cert on host (terminal watcher should pick it up)"
sleep 0.3
remint_cert
# Update trust to the new cert BEFORE polling, so probes during the
# polling window verify successfully once the watcher catches up.
cp "$RUNTIME_DIR/terminal/etc/certs/server.pem" "$RUNTIME_DIR/client-trust/server.pem"

deadline=$(( $(date +%s) + 4 ))
fp3="$fp1"
while (( $(date +%s) < deadline )); do
    sleep 0.25
    cur=$(https_probe app.test.local | python3 -c "import json,sys; print(json.load(sys.stdin)['fp'])" 2>/dev/null || true)
    if [[ -n "$cur" && "$cur" != "$fp1" ]]; then
        fp3="$cur"
        break
    fi
done
[[ "$fp3" != "$fp1" ]] || fail "leaf fingerprint did not change after on-disk cert swap"
echo "    [ok] cert reloaded; new leaf fp ${fp3:0:16}…"

probe_after=$(https_probe app.test.local)
status_after=$(echo "$probe_after" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
[[ "$status_after" == "200" ]] || fail "HTTPS broke after cert reload (got $status_after)"

# -------- Concurrent flow survival across cert reload ----------------------
#
# Same shape as run-quickstart.sh; here the in-flight TLS sessions
# traverse the full 3-hop chain. See the comment block there.

echo "==> [concurrent-cert-reload] 6 long-lived HTTPS keep-alive sessions across reload"
dc_exec client bash -c 'rm -f /tmp/hsess-*.done /tmp/hsess-*.log'

SESSIONS=6
for i in $(seq 1 "$SESSIONS"); do
    dc_exec_detached client \
        bash -c "python3 /tests/concurrent_https_session.py \
            --sni app.test.local --id $i --requests 12 --interval 0.4 \
            > /tmp/hsess-$i.log 2>&1"
done

sleep 1
remint_cert
cp "$RUNTIME_DIR/terminal/etc/certs/server.pem" "$RUNTIME_DIR/client-trust/server.pem"

deadline=$(( $(date +%s) + 30 ))
while (( $(date +%s) < deadline )); do
    done_count=$(dc_exec client bash -c 'ls /tmp/hsess-*.done 2>/dev/null | wc -l' | tr -d '[:space:]')
    [[ "$done_count" == "$SESSIONS" ]] && break
    sleep 0.5
done
done_count=$(dc_exec client bash -c 'ls /tmp/hsess-*.done 2>/dev/null | wc -l' | tr -d '[:space:]')
[[ "$done_count" == "$SESSIONS" ]] || fail "only $done_count/$SESSIONS sessions completed within timeout"

failed_sessions=0
for i in $(seq 1 "$SESSIONS"); do
    last=$(dc_exec client bash -c "tail -1 /tmp/hsess-$i.log" | tr -d '[:space:]')
    if [[ "$last" != OK* ]]; then
        echo "    session $i did not complete cleanly: $(dc_exec client cat /tmp/hsess-$i.log | tail -3)"
        failed_sessions=$(( failed_sessions + 1 ))
    fi
done
(( failed_sessions == 0 )) || fail "$failed_sessions/$SESSIONS HTTPS sessions broke across cert reload"
echo "    [ok] all $SESSIONS HTTPS keep-alive sessions completed across reload"

# -------- Malformed-cert rollback ------------------------------------------

# Capture the current fingerprint right before writing garbage —
# the concurrent-reload phase above advanced it past the original
# `fp3` captured during the simple cert-reload phase.
fp_pre_malformed=$(https_probe app.test.local | python3 -c "import json,sys; print(json.load(sys.stdin)['fp'])")

echo "==> [malformed-cert] writing garbage PEM over working cert"
echo "this is not a PEM file" > "$CERT_HOST_DIR/server.pem"
sleep 1.5

probe_bad=$(https_probe app.test.local) || fail "HTTPS broke after malformed write (should have kept old cert)"
status_bad=$(echo "$probe_bad" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
fp_bad=$(echo "$probe_bad"     | python3 -c "import json,sys; print(json.load(sys.stdin)['fp'])")
[[ "$status_bad" == "200" ]] || fail "expected 200 with old cert, got $status_bad"
[[ "$fp_bad" == "$fp_pre_malformed" ]] || fail "expected pre-malformed fp ${fp_pre_malformed:0:16}… still serving, got ${fp_bad:0:16}…"
echo "    [ok] old cert still serving after malformed PEM rejected"

# -------- Recovery: restore valid cert -------------------------------------

echo "==> [cert-recovery] writing valid cert; expect another reload"
sleep 0.3
remint_cert
cp "$RUNTIME_DIR/terminal/etc/certs/server.pem" "$RUNTIME_DIR/client-trust/server.pem"
fp_pre_recovery="$fp_pre_malformed"
deadline=$(( $(date +%s) + 4 ))
fp4="$fp_pre_recovery"
while (( $(date +%s) < deadline )); do
    sleep 0.25
    cur=$(https_probe app.test.local | python3 -c "import json,sys; print(json.load(sys.stdin)['fp'])" 2>/dev/null || true)
    if [[ -n "$cur" && "$cur" != "$fp_pre_recovery" ]]; then
        fp4="$cur"
        break
    fi
done
[[ "$fp4" != "$fp_pre_recovery" ]] || fail "cert did not reload after recovery"
echo "    [ok] recovery reload succeeded; new leaf fp ${fp4:0:16}…"

# -------- L4 rule hot-add/remove (inotify-driven, through the relay) --------
#
# Same as run-quickstart.sh — but here the predicate has to traverse
# terminal -> relay -> gateway, exercising the mid-chain predicate
# forwarding path on every add/remove.

echo "==> [hot-reload] dropping tcp-echo-hot.toml; expect gateway to derive + serve"
cat > "$RUNTIME_DIR/terminal/etc/rules/tcp-echo-hot.toml" <<EOF
[[rule]]
name     = "tcp-echo-hot"
listen   = "0.0.0.0:7110"
protocol = "tcp"
target   = "172.31.13.40:7100"
EOF

hot_rule_present() {
    ctl_json_on gateway derived-rules 2>/dev/null | grep -q '"name": "tcp-echo-hot"'
}
hot_rule_absent() {
    ! ctl_json_on gateway derived-rules 2>/dev/null | grep -q '"name": "tcp-echo-hot"'
}
WAIT_TIMEOUT=15 wait_for "tcp-echo-hot derived at gateway (via relay forwarding)" \
    hot_rule_present

run_tcp_echo_hot() {
    dc_exec client python3 - <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(("172.31.10.20", 7110))
payload = b"hot-reload-tcp-" + b"h" * 200
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
WAIT_TIMEOUT=10 wait_for "TCP echo through hot-added rule" run_tcp_echo_hot

echo "==> [hot-reload] removing tcp-echo-hot.toml; expect gateway to drop it"
rm "$RUNTIME_DIR/terminal/etc/rules/tcp-echo-hot.toml"
WAIT_TIMEOUT=15 wait_for "tcp-echo-hot removed from gateway (via relay forwarding)" \
    hot_rule_absent
if run_tcp_echo_hot 2>/dev/null; then
    fail "removed rule is still accepting traffic"
fi
echo "    [ok] hot-removed rule no longer serving"

# -------- Init re-run idempotency ------------------------------------------

echo "==> [init-idempotent] re-running init-chain container mid-test"
init_out=$("${DC[@]}" "${COMPOSE_ARGS[@]}" run --rm init-chain 2>&1) \
    || fail "init-chain re-run exited non-zero: $init_out"
echo "$init_out" | grep -q "already bootstrapped; skipping" \
    || fail "init re-run did not detect existing bootstrap: $init_out"

run_tcp_echo || fail "TCP echo broke after init re-run"
probe_after_init=$(https_probe app.test.local) \
    || fail "HTTPS probe failed after init re-run"
[[ $(echo "$probe_after_init" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])") == "200" ]] \
    || fail "HTTPS not 200 after init re-run"
echo "    [ok] init re-run was a no-op and live traffic kept flowing"

# -------- Restart / rehydration -------------------------------------------
#
# Restart each yggdrasil node in turn. Implicitly tests state_dir
# persistence + Noise rekey-on-reconnect + the daemon's startup path
# at each node. See run-quickstart.sh for the deeper rationale.
#
# Chain-specific notes:
#
#   - The relay is the most interesting restart target: when it goes
#     down, BOTH the gateway (its downstream) and the terminal (its
#     upstream) lose their chain session. The recovery exercises
#     re-handshake on both sides.
#
#   - Gateway and relay restarts both wipe in-memory predicate state
#     of the node that holds the "applied" snapshot the terminal's
#     publisher believes is current. The terminal's publisher dedupes
#     against its own `last_sent` snapshot, so it won't auto-re-push.
#     Same sentinel-rule workaround as run-quickstart.sh applies.
#     See the comment block there + the FINDING note about a deeper
#     fix in the publisher.

restart_and_reprobe() {
    local service="$1" role_desc="$2"
    echo "==> [restart-$role_desc] restart $service, expect chain recovers"

    sentinel_present() {
        ctl_json_on gateway derived-rules 2>/dev/null | grep -q '"name": "post-restart-sentinel"'
    }
    sentinel_absent() {
        ! ctl_json_on gateway derived-rules 2>/dev/null | grep -q '"name": "post-restart-sentinel"'
    }

    "${DC[@]}" "${COMPOSE_ARGS[@]}" restart "$service" >/dev/null

    # Re-wait for full chain enrollment. For relay restart, both
    # hops re-handshake; wait for both gating predicates.
    WAIT_TIMEOUT=60 wait_for "terminal re-enrolled at relay after $role_desc restart" terminal_enrolled_at_relay
    WAIT_TIMEOUT=60 wait_for "relay re-enrolled at gateway after $role_desc restart" relay_enrolled_at_gateway

    # Sentinel workaround for gateway and relay restarts; see the
    # block comment above. Terminal restart re-loads from disk on
    # its startup path, so no workaround needed there.
    if [[ "$role_desc" == "gateway" || "$role_desc" == "relay" ]]; then
        local sentinel="$RUNTIME_DIR/terminal/etc/rules/post-restart-sentinel.toml"
        cat > "$sentinel" <<EOF
[[rule]]
name     = "post-restart-sentinel"
listen   = "0.0.0.0:7199"
protocol = "tcp"
target   = "172.31.13.40:7100"
EOF
        WAIT_TIMEOUT=20 wait_for "sentinel landed at gateway (forces full set re-push through chain)" \
            sentinel_present
        rm "$sentinel"
        WAIT_TIMEOUT=20 wait_for "sentinel cleared from gateway" sentinel_absent
    fi

    WAIT_TIMEOUT=15 wait_for "predicates re-derived at gateway after $role_desc restart" \
        predicates_landed

    WAIT_TIMEOUT=15 wait_for "TCP echo recovers after $role_desc restart" run_tcp_echo
    WAIT_TIMEOUT=15 wait_for "UDP echo recovers after $role_desc restart" run_udp_echo

    local deadline=$(( $(date +%s) + 10 ))
    local status_after=""
    while (( $(date +%s) < deadline )); do
        local probe; probe=$(https_probe app.test.local 2>/dev/null || true)
        if [[ -n "$probe" ]]; then
            status_after=$(echo "$probe" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])" 2>/dev/null || true)
            [[ "$status_after" == "200" ]] && break
        fi
        sleep 0.5
    done
    [[ "$status_after" == "200" ]] || fail "HTTPS not 200 after $role_desc restart (got '$status_after')"
    echo "    [ok] TCP/UDP/HTTPS all recover after $role_desc restart"
}

# Order: edge nodes first, mid-chain hop last — covers the "both
# sides survive a middle restart" case.
restart_and_reprobe gateway  gateway
restart_and_reprobe terminal terminal
restart_and_reprobe relay    relay

# -------- Negative isolation check -----------------------------------------

echo "==> [isolation] client cannot reach home_lan app IPs directly"
isolation_probe_from() {
    local from_container="$1" target_ip="$2" target_port="$3" proto="$4"
    dc_exec "$from_container" python3 - "$target_ip" "$target_port" "$proto" <<'PY'
import socket, sys
ip, port, proto = sys.argv[1], int(sys.argv[2]), sys.argv[3]
fam = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
s = socket.socket(socket.AF_INET, fam)
s.settimeout(2)
try:
    if proto == "tcp":
        s.connect((ip, port))
        sys.exit(1)
    else:
        s.sendto(b"isolation-probe", (ip, port))
        try:
            s.recvfrom(4096)
            sys.exit(1)
        except (socket.timeout, OSError):
            sys.exit(0)
except (socket.timeout, ConnectionRefusedError, OSError):
    sys.exit(0)
finally:
    s.close()
PY
}
isolation_probe_from client 172.31.13.20 80   tcp || fail "isolation: client could reach app-nginx directly"
isolation_probe_from client 172.31.13.30 80   tcp || fail "isolation: client could reach app-nginx-alt directly"
isolation_probe_from client 172.31.13.40 7100 tcp || fail "isolation: client could reach app-tcp directly"
isolation_probe_from client 172.31.13.50 7101 udp || fail "isolation: client could reach app-udp directly"
echo "    [ok] all four home_lan app endpoints unreachable from client"

# -------- Two-way isolation: gateway + relay also can't bypass the chain ---
#
# Stronger version: neither the gateway nor the mid-chain relay
# should have a route to home_lan. If either did, a regression could
# let the data plane skip the chain entirely while the client-side
# isolation check still passed.

echo "==> [isolation] gateway cannot reach home_lan app IPs directly"
isolation_probe_from gateway 172.31.13.20 80   tcp || fail "isolation: gateway could reach app-nginx directly"
isolation_probe_from gateway 172.31.13.30 80   tcp || fail "isolation: gateway could reach app-nginx-alt directly"
isolation_probe_from gateway 172.31.13.40 7100 tcp || fail "isolation: gateway could reach app-tcp directly"
isolation_probe_from gateway 172.31.13.50 7101 udp || fail "isolation: gateway could reach app-udp directly"
echo "    [ok] all four home_lan app endpoints unreachable from gateway"

echo "==> [isolation] relay cannot reach home_lan app IPs directly"
isolation_probe_from relay 172.31.13.20 80   tcp || fail "isolation: relay could reach app-nginx directly"
isolation_probe_from relay 172.31.13.30 80   tcp || fail "isolation: relay could reach app-nginx-alt directly"
isolation_probe_from relay 172.31.13.40 7100 tcp || fail "isolation: relay could reach app-tcp directly"
isolation_probe_from relay 172.31.13.50 7101 udp || fail "isolation: relay could reach app-udp directly"
echo "    [ok] all four home_lan app endpoints unreachable from relay"

# -------- Key rotation (mid-chain relay) -----------------------------------
#
# Rotate the RELAY's identity (the most interesting target in a
# 3-node chain — it's the only node whose key change affects both
# the upstream-side and downstream-side enrollments). The full
# operator workflow per docs/operations.md is:
#
#   1. Relay rotates its own identity.
#   2. Re-enrol relay->gateway (relay exports request, gateway
#      add-accept, relay add-dial). Updates the gateway's
#      [accept].pubkey and the relay's [dial].pubkey.
#   3. Re-enrol terminal->relay (terminal exports request, relay
#      add-accept). Updates the relay's [accept].pubkey. The
#      terminal's [dial].pubkey already pins the relay's NEW key
#      because the relay rotated, so the terminal also needs to
#      add-dial against a fresh grant from the new-identity relay.
#   4. Restart all three nodes so the new identities + [dial]/[accept]
#      pubkeys take effect.
#
# Files shuttle through host bind mounts.

echo "==> [key-rotation] rotate relay identity, redo both ceremonies, expect recovery"
run_tcp_echo || fail "baseline TCP broken before rotation"

relay_pubkey_before=$(dc_exec relay yggdrasilctl identity show 2>/dev/null \
    | grep '^pubkey:' | awk '{print $2}')
[[ -n "$relay_pubkey_before" ]] || fail "could not read relay's pre-rotation pubkey"

dc_exec relay yggdrasilctl identity rotate \
    --identity-file /etc/yggdrasil/identity.key \
    --force \
    --yes-i-understand-this-breaks-existing-chains >/dev/null \
    || fail "relay identity rotate failed"

relay_pubkey_after=$(dc_exec relay yggdrasilctl identity show 2>/dev/null \
    | grep '^pubkey:' | awk '{print $2}')
[[ "$relay_pubkey_after" != "$relay_pubkey_before" ]] || fail "relay rotation did not change pubkey"
echo "    [ok] relay identity rotated (${relay_pubkey_before:0:24}… -> ${relay_pubkey_after:0:24}…)"

# Restart relay; both chain links are now broken.
"${DC[@]}" "${COMPOSE_ARGS[@]}" restart relay >/dev/null
sleep 5

# --- Ceremony 1: relay -> gateway (re-bind gateway's [accept].pubkey)
local_req1="$RUNTIME_DIR/relay/etc/rotation-request.txt"
local_grant1="$RUNTIME_DIR/gateway/etc/rotation-grant-to-relay.txt"

dc_exec relay yggdrasilctl --config /etc/yggdrasil/config.toml \
    identity export-request \
    --identity-file /etc/yggdrasil/identity.key \
    --out /etc/yggdrasil/rotation-request.txt \
    --note "post-rotation relay->gateway" >/dev/null \
    || fail "relay failed to export request after rotation"

cp "$local_req1" "$RUNTIME_DIR/gateway/etc/rotation-request-from-relay.txt"

dc_exec gateway yggdrasilctl --config /etc/yggdrasil/config.toml \
    identity add-accept \
    --identity-file /etc/yggdrasil/identity.key \
    --from /etc/yggdrasil/rotation-request-from-relay.txt \
    --my-endpoint "${GATEWAY_INET_ENDPOINT:-gateway:51820}" \
    --out /etc/yggdrasil/rotation-grant-to-relay.txt \
    --note "post-rotation gateway->relay" >/dev/null \
    || fail "gateway add-accept failed after relay rotation"

cp "$local_grant1" "$RUNTIME_DIR/relay/etc/rotation-grant-from-gateway.txt"

dc_exec relay yggdrasilctl --config /etc/yggdrasil/config.toml \
    identity add-dial \
    --identity-file /etc/yggdrasil/identity.key \
    --from /etc/yggdrasil/rotation-grant-from-gateway.txt >/dev/null \
    || fail "relay add-dial failed after rotation"

# --- Ceremony 2: terminal -> relay (re-bind relay's [accept].pubkey
#     AND terminal's [dial].pubkey, which now needs to pin the
#     relay's NEW key)
local_req2="$RUNTIME_DIR/terminal/etc/rotation-request.txt"
local_grant2="$RUNTIME_DIR/relay/etc/rotation-grant-to-terminal.txt"

dc_exec terminal yggdrasilctl --config /etc/yggdrasil/config.toml \
    identity export-request \
    --identity-file /etc/yggdrasil/identity.key \
    --out /etc/yggdrasil/rotation-request.txt \
    --note "post-rotation terminal->relay" >/dev/null \
    || fail "terminal failed to export request after relay rotation"

cp "$local_req2" "$RUNTIME_DIR/relay/etc/rotation-request-from-terminal.txt"

dc_exec relay yggdrasilctl --config /etc/yggdrasil/config.toml \
    identity add-accept \
    --identity-file /etc/yggdrasil/identity.key \
    --from /etc/yggdrasil/rotation-request-from-terminal.txt \
    --my-endpoint "${RELAY_CHAIN_ENDPOINT:-relay:51820}" \
    --out /etc/yggdrasil/rotation-grant-to-terminal.txt \
    --note "post-rotation relay->terminal" >/dev/null \
    || fail "relay add-accept failed after rotation"

cp "$local_grant2" "$RUNTIME_DIR/terminal/etc/rotation-grant-from-relay.txt"

dc_exec terminal yggdrasilctl --config /etc/yggdrasil/config.toml \
    identity add-dial \
    --identity-file /etc/yggdrasil/identity.key \
    --from /etc/yggdrasil/rotation-grant-from-relay.txt >/dev/null \
    || fail "terminal add-dial failed after relay rotation"

# Restart terminal AND gateway sequentially (not in parallel) so
# podman-compose's `restart` doesn't trip the "dependency not started"
# race when two services are bouncing at once.
"${DC[@]}" "${COMPOSE_ARGS[@]}" restart gateway >/dev/null
sleep 3
"${DC[@]}" "${COMPOSE_ARGS[@]}" restart terminal >/dev/null

WAIT_TIMEOUT=60 wait_for "post-rotation terminal->relay re-enrollment" terminal_enrolled_at_relay
WAIT_TIMEOUT=60 wait_for "post-rotation relay->gateway re-enrollment" relay_enrolled_at_gateway
# Publisher dedup workaround (see restart phase comment block).
sentinel="$RUNTIME_DIR/terminal/etc/rules/post-rotation-sentinel.toml"
cat > "$sentinel" <<EOF
[[rule]]
name     = "post-rotation-sentinel"
listen   = "0.0.0.0:7198"
protocol = "tcp"
target   = "172.31.13.40:7100"
EOF
sentinel_post_rot_present() {
    ctl_json_on gateway derived-rules 2>/dev/null | grep -q '"name": "post-rotation-sentinel"'
}
sentinel_post_rot_absent() {
    ! ctl_json_on gateway derived-rules 2>/dev/null | grep -q '"name": "post-rotation-sentinel"'
}
WAIT_TIMEOUT=20 wait_for "post-rotation sentinel landed at gateway" sentinel_post_rot_present
rm "$sentinel"
WAIT_TIMEOUT=20 wait_for "post-rotation sentinel cleared" sentinel_post_rot_absent

WAIT_TIMEOUT=15 wait_for "TCP echo recovers post-rotation" run_tcp_echo
echo "    [ok] relay key rotation + dual-ceremony recovery succeeded"

# Cleanup transit files.
rm -f "$local_req1" "$local_grant1" "$local_req2" "$local_grant2" \
      "$RUNTIME_DIR/gateway/etc/rotation-request-from-relay.txt" \
      "$RUNTIME_DIR/relay/etc/rotation-grant-from-gateway.txt" \
      "$RUNTIME_DIR/relay/etc/rotation-request-from-terminal.txt" \
      "$RUNTIME_DIR/terminal/etc/rotation-grant-from-relay.txt"

# -------- graceful_drain_timeout (gateway SIGTERM mid-flight) --------------
#
# The gateway's bootstrap sets `[server].graceful_drain_timeout = "5s"`. A
# 7-second slow-drip TCP echo is started against gateway:7100 (which
# forwards through relay -> terminal -> app-tcp). After 3 seconds (so ~4s
# of in-flight work remains), we SIGTERM the gateway with `stop -t 10`
# (giving 5s drain + 5s slack before SIGKILL). The gateway should:
#   (a) take ~4-5s to exit (not <1s as it would with drain disabled)
#   (b) keep the in-flight TCP forwarding alive long enough for the
#       slow-drip client to receive all 7 bytes back.
# This proves the drain knob is wired through the full forwarding path
# (accept loop stops, in-flight `copy_bidirectional` tasks continue).

echo "==> [graceful-drain] slow-drip TCP through chain across gateway SIGTERM"
dc_exec client bash -c 'rm -f /tmp/slow-tcp.done /tmp/slow-tcp.log'

# Spawn the slow-drip client in background. Use the detached helper
# (NOT `dc_exec ... &`) — see CTR_PREFIX comment.
dc_exec_detached client \
    bash -c "python3 /tests/slow_tcp_echo.py \
        --host 172.31.10.20 --port 7100 \
        --bytes 7 --interval 1.0 \
        > /tmp/slow-tcp.log 2>&1"

# Let the connection establish + the slow-drip get well into its
# send loop (we want several bytes mid-flight when SIGTERM fires).
# 3 seconds gets us ~4 bytes sent of 7.
sleep 3

# SIGTERM gateway. --time 10 gives 5s drain + 5s slack before SIGKILL.
t0=$(date +%s)
"${DC[@]}" "${COMPOSE_ARGS[@]}" stop -t 10 gateway >/dev/null
t1=$(date +%s)
drain_elapsed=$(( t1 - t0 ))

echo "    gateway exit took ${drain_elapsed}s (configured drain = 5s)"
# Drain should be roughly 4s (drain starts 3s into a 7s slow-drip;
# ~4s of work remains). Accept [3s, 8s]. Too short means the drain
# didn't honor in-flight; too long means SIGKILL fallback fired.
(( drain_elapsed >= 3 && drain_elapsed <= 8 )) \
    || fail "drain elapsed ${drain_elapsed}s outside [3,8] window"

# Wait for the slow client to drop its done marker.
dc_done=$(( $(date +%s) + 15 ))
while (( $(date +%s) < dc_done )); do
    if dc_exec client bash -c '[ -f /tmp/slow-tcp.done ]' 2>/dev/null; then
        break
    fi
    sleep 0.5
done

# The client either completed naturally (all 7 bytes round-tripped
# within the drain window) or its connection was cancelled (drain
# timed out before all bytes were exchanged). Both are observable
# outcomes; we want it to have COMPLETED, which proves the drain
# preserved the in-flight conversation.
last=$(dc_exec client bash -c 'tail -1 /tmp/slow-tcp.log' | tr -d '[:space:]')
[[ "$last" == "OK7" ]] || fail "slow-drip client did not complete cleanly: $(dc_exec client cat /tmp/slow-tcp.log | tail -5)"
echo "    [ok] slow-drip TCP client round-tripped all 7 bytes across SIGTERM"

# Restart gateway for the post-drain re-enrollment check (and to leave
# the stack healthy for `KEEP_STACK=1` debugging).
"${DC[@]}" "${COMPOSE_ARGS[@]}" start gateway >/dev/null
WAIT_TIMEOUT=90 wait_for "relay re-enrolled at gateway after graceful-drain restart" \
    relay_enrolled_at_gateway

# Publisher dedup workaround (same shape as restart/rotation phases):
# the terminal's predicate publisher dedupes against in-memory
# `last_sent`. After gateway restart, the upstream chain rehandshakes
# but the publisher sees "same set, skip push" and the gateway stays
# empty. Drop a real-delta rule file to force the publisher to push
# the full set again, then clean it up.
sentinel_drain="$RUNTIME_DIR/terminal/etc/rules/post-drain-sentinel.toml"
cat > "$sentinel_drain" <<EOF
[[rule]]
name     = "post-drain-sentinel"
listen   = "0.0.0.0:7197"
protocol = "tcp"
target   = "172.31.13.40:7100"
EOF
sentinel_drain_present() {
    ctl_json_on gateway derived-rules 2>/dev/null | grep -q '"name": "post-drain-sentinel"'
}
sentinel_drain_absent() {
    ! ctl_json_on gateway derived-rules 2>/dev/null | grep -q '"name": "post-drain-sentinel"'
}
WAIT_TIMEOUT=20 wait_for "post-drain sentinel landed at gateway" sentinel_drain_present
rm "$sentinel_drain"
WAIT_TIMEOUT=20 wait_for "post-drain sentinel cleared" sentinel_drain_absent
echo "    [ok] gateway re-enrolled after graceful-drain SIGTERM"

# -------- chain apply --file (ephemeral rule push) -------------------------
#
# `yggdrasilctl chain apply --file <path>` pushes a pre-validated rule
# set into the running terminal daemon's supervisor without touching
# rules_dir. The pushed set REPLACES the in-memory current set; it
# lives only until the next rules_dir reload, at which point the
# disk state wins again (see docs/configuration.md:543-546).
#
# The on-disk rules are *temporarily* clobbered while the ephemeral
# set is active. That's the documented behaviour ("apply REPLACES the
# set"); the clobber-sentinel write+remove in steps 4-5 restores them.

echo "==> [chain-apply] push ephemeral rule via chain apply, then clobber via rules_dir reload"

dc_exec terminal bash -c 'cat > /tmp/candidate-rules.toml' <<'EOF'
[[rule]]
name     = "ephemeral-tcp"
listen   = "0.0.0.0:7120"
protocol = "tcp"
target   = "172.31.13.40:7100"
EOF

dc_exec terminal yggdrasilctl chain --socket /run/yggdrasil/control.sock \
    apply --file /tmp/candidate-rules.toml >/dev/null \
    || fail "chain apply rejected the candidate rule set"

ephemeral_derived() {
    ctl_json_on gateway derived-rules 2>/dev/null | grep -q '"name": "ephemeral-tcp"'
}
WAIT_TIMEOUT=15 wait_for "ephemeral-tcp derived at gateway" ephemeral_derived

# Independent probe: TCP round-trip through the new port via the
# 3-hop chain (client -> gateway:7120 -> relay -> terminal:7120 ->
# app-tcp:7100).
ephemeral_tcp_echo() {
    dc_exec client python3 - <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(("172.31.10.20", 7120))
except (ConnectionRefusedError, socket.timeout, OSError):
    sys.exit(1)
s.settimeout(5)
payload = b"chain-apply-ephemeral-" + b"e" * 100
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
WAIT_TIMEOUT=60 wait_for "TCP echo through ephemeral-tcp rule" ephemeral_tcp_echo

# `chain apply` lives until the next rules_dir reload. The watcher
# only re-emits when the rescanned RuleSet semantically differs from
# its own in-memory copy (rule_watcher's no-op check, watcher.rs:116),
# so `touch` alone is insufficient — comments / mtimes don't count.
# We force a real disk delta by writing a clobber-sentinel rule file
# (one new rule = guaranteed diff). The supervisor reloads the full
# disk state (originals + sentinel), clobbering the ephemeral. We
# then remove the sentinel and the next reload settles back to the
# original disk state.
clobber_sentinel="$RUNTIME_DIR/terminal/etc/rules/chain-apply-clobber.toml"
cat > "$clobber_sentinel" <<EOF
[[rule]]
name     = "chain-apply-clobber-sentinel"
listen   = "0.0.0.0:7198"
protocol = "tcp"
target   = "172.31.13.40:7100"
EOF

ephemeral_absent() {
    ! ctl_json_on gateway derived-rules 2>/dev/null | grep -q '"name": "ephemeral-tcp"'
}
WAIT_TIMEOUT=15 wait_for "ephemeral-tcp clobbered by rules_dir reload" ephemeral_absent
rm "$clobber_sentinel"
clobber_sentinel_absent() {
    ! ctl_json_on gateway derived-rules 2>/dev/null | grep -q '"name": "chain-apply-clobber-sentinel"'
}
WAIT_TIMEOUT=15 wait_for "clobber sentinel removed from gateway" clobber_sentinel_absent

# And the port itself no longer accepts. Connection-refused is the
# success signal (port unbound after the rule was torn down).
ephemeral_tcp_dead() {
    dc_exec client python3 - <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect(("172.31.10.20", 7120))
    s.close()
    sys.exit(1)
except (ConnectionRefusedError, socket.timeout, OSError):
    sys.exit(0)
PY
}
WAIT_TIMEOUT=10 wait_for "ephemeral-tcp port no longer accepts" ephemeral_tcp_dead

# Confirm the disk-defined rules are back online (one of them suffices).
WAIT_TIMEOUT=15 wait_for "original tcp-echo rule restored after reload" run_tcp_echo
echo "    [ok] chain apply ephemeral lifetime (push -> serve -> clobber) verified"

# -------- done -------------------------------------------------------------

echo
echo "ALL CHAIN E2E TESTS PASSED"
