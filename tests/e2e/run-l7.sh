#!/usr/bin/env bash
# tests/e2e/run-l7.sh — end-to-end test for the L7 HTTPS frontend.
#
# Exercises:
#   1. Disk-backed HTTPS rule routes SNI traffic to a backend HTTP server.
#   2. Cert hot-reload picks up an on-disk PEM swap within the debounce
#      window (the leaf fingerprint must change).
#   3. A malformed PEM written on top of a working cert is rejected and
#      the old cert keeps serving (no TLS outage).
#   4. Restoring a good PEM reloads cleanly.
#
# Reuses the same compose project as run.sh; tear-down purges volumes.
set -euo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
COMPOSE_FILE="$REPO_ROOT/docker/compose.e2e.yml"
COMPOSE_ARGS=(-f "$COMPOSE_FILE" -p yggdrasil-e2e)

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
if ! "${DC[@]}" "${COMPOSE_ARGS[@]}" run --rm init; then
    echo "FAIL: bootstrap (init) exited non-zero" >&2
    exit 1
fi

echo "==> bringing daemons up"
"${DC[@]}" "${COMPOSE_ARGS[@]}" up -d vps home client

# -------- helpers -----------------------------------------------------------

ctl() {
    "${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T vps \
        yggdrasilctl --socket /run/yggdrasil/control.sock "$@"
}

vps_sh() {
    "${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T vps bash -c "$1"
}

client_py() {
    "${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T client python3 - "$@"
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
    "${DC[@]}" "${COMPOSE_ARGS[@]}" logs --no-color --tail 120 vps  || true
    "${DC[@]}" "${COMPOSE_ARGS[@]}" logs --no-color --tail 120 home || true
    exit 1
}

# -------- gating: wait for first authenticated heartbeat --------------------

echo "==> waiting for huginn to enrol and heartbeat"
peer_enrolled() {
    local out; out=$(ctl --json status 2>/dev/null || true)
    echo "$out" | grep -q '"peer_enrolled": true' && \
        echo "$out" | grep -q '"peer_ip": "172.30.0.20"'
}
WAIT_TIMEOUT=60 wait_for "peer enrolled + heartbeat seen from 172.30.0.20" peer_enrolled

# Wait for the home box's HTTP backend to come up too — it's a sidecar in
# home-entrypoint.sh and races with huginn's first heartbeat.
echo "==> waiting for home HTTP backend on 172.30.0.20:7180"
http_backend_up() {
    "${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T client python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
s.connect(("172.30.0.20", 7180))
s.close()
' 2>/dev/null
}
WAIT_TIMEOUT=15 wait_for "home HTTP backend reachable" http_backend_up

# -------- L7 setup: mint a self-signed cert + drop the HTTPS rule ----------

HOST="app.test.local"
CERT_PATH="/etc/yggdrasil/certs/${HOST}.crt"
KEY_PATH="/etc/yggdrasil/certs/${HOST}.key"

mint_cert() {
    # Generates a fresh self-signed cert+key in-place. The CN/SAN is the
    # SNI hostname clients use. Each invocation produces a new key so the
    # leaf fingerprint is guaranteed to change.
    vps_sh "openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout '$KEY_PATH' \
            -out '$CERT_PATH' \
            -days 1 \
            -subj '/CN=${HOST}' \
            -addext 'subjectAltName=DNS:${HOST}' \
            >/dev/null 2>&1"
}

echo "==> minting initial cert for ${HOST}"
mint_cert
vps_sh "test -s '$CERT_PATH' && test -s '$KEY_PATH'" || fail "cert files missing after openssl run"

echo "==> dropping https rule pointing at home:7180"
vps_sh "cat >/etc/yggdrasil/rules/https-app.toml" <<EOF
[[rule]]
name     = "https-app"
listen   = "0.0.0.0:8443"
protocol = "https"

[[rule.route]]
hostname = "${HOST}"
upstream = "http://172.30.0.20:7180"
cert     = "${CERT_PATH}"
key      = "${KEY_PATH}"
EOF

https_rule_loaded() {
    ctl rules list | grep -q '^https-app '
}
WAIT_TIMEOUT=10 wait_for "supervisor loaded https-app rule" https_rule_loaded

# -------- test 1: HTTPS request flows end-to-end ---------------------------

# Drives an HTTPS request from the client at 172.30.0.10:8443 with the
# correct SNI, returning the body + the SHA-256 fingerprint of the leaf
# cert the server presented. Self-signed, so verification is skipped.
do_https_probe() {
    "${DC[@]}" "${COMPOSE_ARGS[@]}" exec -T client python3 - <<PY
import hashlib, http.client, json, socket, ssl, sys

HOST = "${HOST}"
ADDR = ("172.30.0.10", 8443)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

sock = socket.create_connection(ADDR, timeout=5)
ssock = ctx.wrap_socket(sock, server_hostname=HOST)
leaf_der = ssock.getpeercert(binary_form=True)
fp = hashlib.sha256(leaf_der).hexdigest()

conn = http.client.HTTPSConnection(HOST, 8443, context=ctx, timeout=5)
conn.sock = ssock
conn.request("GET", "/", headers={"Host": HOST})
resp = conn.getresponse()
body = resp.read()
print(json.dumps({"status": resp.status, "body": body.decode("utf-8", "replace"), "fp": fp}))
conn.close()
PY
}

echo "==> [https-200] proxied HTTPS request"
probe1=$(do_https_probe) || fail "HTTPS probe failed before reload"
status1=$(echo "$probe1" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
body1=$(echo "$probe1" | python3 -c "import json,sys; print(json.load(sys.stdin)['body'].strip())")
fp1=$(echo "$probe1" | python3 -c "import json,sys; print(json.load(sys.stdin)['fp'])")
[[ "$status1" == "200" ]] || fail "expected 200, got $status1"
[[ "$body1"  == "OK"   ]] || fail "expected 'OK' body, got '$body1'"
echo "    [ok] HTTPS 200 with body 'OK' (leaf fp ${fp1:0:16}…)"

# -------- test 2: cert hot-reload --------------------------------------

echo "==> [cert-reload] swapping PEM on disk"
sleep 0.2  # ensure mtime changes vs. initial write
mint_cert

# Poll for fp change up to ~3s (debounce + worker latency).
deadline=$(( $(date +%s) + 3 ))
fp2="$fp1"
while (( $(date +%s) < deadline )); do
    sleep 0.25
    cur=$(do_https_probe | python3 -c "import json,sys; print(json.load(sys.stdin)['fp'])" 2>/dev/null || true)
    if [[ -n "$cur" && "$cur" != "$fp1" ]]; then
        fp2="$cur"
        break
    fi
done
[[ "$fp2" != "$fp1" ]] || fail "leaf fingerprint did not change after on-disk cert swap"
echo "    [ok] cert reloaded; new leaf fp ${fp2:0:16}…"

# Reloaded cert must still serve 200.
probe_after=$(do_https_probe) || fail "HTTPS broke after reload"
status_after=$(echo "$probe_after" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
[[ "$status_after" == "200" ]] || fail "expected 200 after reload, got $status_after"
echo "    [ok] HTTPS still 200 after reload"

# -------- test 3: malformed cert keeps old cert serving --------------------

echo "==> [malformed-reload] writing garbage PEM on top of working cert"
vps_sh "echo 'this is not a PEM file' > '$CERT_PATH'"

# Give the watcher debounce window + reject latency to kick in.
sleep 1.2

probe_bad=$(do_https_probe) || fail "HTTPS broke after malformed write (should have kept old cert)"
status_bad=$(echo "$probe_bad" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
fp_bad=$(echo "$probe_bad" | python3 -c "import json,sys; print(json.load(sys.stdin)['fp'])")
[[ "$status_bad" == "200" ]] || fail "expected 200 with old cert, got $status_bad"
[[ "$fp_bad"     == "$fp2" ]] || fail "expected old fp ${fp2:0:16}…, got ${fp_bad:0:16}…"
echo "    [ok] old cert still serving after malformed PEM rejected"

# -------- test 4: restoring a good cert reloads cleanly --------------------

echo "==> [recovery] restoring good cert"
sleep 0.2
mint_cert

deadline=$(( $(date +%s) + 3 ))
fp3="$fp2"
while (( $(date +%s) < deadline )); do
    sleep 0.25
    cur=$(do_https_probe | python3 -c "import json,sys; print(json.load(sys.stdin)['fp'])" 2>/dev/null || true)
    if [[ -n "$cur" && "$cur" != "$fp2" ]]; then
        fp3="$cur"
        break
    fi
done
[[ "$fp3" != "$fp2" ]] || fail "cert did not reload after recovery"
echo "    [ok] recovery reload succeeded; new leaf fp ${fp3:0:16}…"

# -------- done --------------------------------------------------------------

echo
echo "ALL L7 E2E TESTS PASSED"
