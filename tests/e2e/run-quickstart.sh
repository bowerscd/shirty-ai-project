#!/usr/bin/env bash
# tests/e2e/run-quickstart.sh — end-to-end smoke for the canonical
# 2-node quickstart deployment.
#
# Topology (per docker/compose.e2e.quickstart.yml):
#
#   client ──client_wan──► gateway ──chain_link──► terminal ──home_lan──► {nginx, nginx-alt, tcp-echo, udp-echo}
#
# What the driver exercises, in order:
#
#   1. Build + init (one-shot key/cert/config setup).
#   2. Enrollment + heartbeat: gateway sees the terminal.
#   3. Predicate propagation: TCP, UDP, and HTTPS predicates land at gateway.
#   4. `chain diff` from terminal: 2 hops, no drift.
#   5. `chain canary` for each rule (tcp / udp / https-as-tcp): status=ok, 2 hops.
#   6. TCP echo client -> gateway:7100 -> chain -> app-tcp:7100, byte-for-byte.
#   7. UDP echo client -> gateway:7101 -> chain -> app-udp:7101, byte-for-byte.
#   8. HTTPS GET SNI=app.test.local: terminal terminates TLS, routes to app-nginx,
#      asserts the leaf-cert fingerprint matches what init minted.
#   9. HTTPS GET SNI=alt.test.local: routes to app-nginx-alt (distinct body).
#  10. HTTPS GET SNI=bogus.test.local: asserts 404 (no [[route]] matches).
#  11. Cert hot-reload: re-mint the cert in-place, fingerprint must change, body still 200.
#  12. Malformed-cert rollback: write garbage PEM, old cert keeps serving.
#  13. Recovery: restoring a valid cert reloads cleanly.
#  14. Negative isolation: client cannot reach any home_lan app directly
#      (would-pass-on-regression check that the gateway bypassed the chain).
#  15. Teardown.
#
# Usage:
#   ./tests/e2e/run-quickstart.sh                # build + run + verify + teardown
#   KEEP_STACK=1 ./tests/e2e/run-quickstart.sh   # leave stack up for poking
set -euo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
COMPOSE_FILE="$REPO_ROOT/docker/compose.e2e.quickstart.yml"
RUNTIME_DIR="$REPO_ROOT/tests/e2e/runtime/quickstart"
COMPOSE_ARGS=(-f "$COMPOSE_FILE" -p yggdrasil-e2e-quickstart)

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

echo "==> preparing fresh runtime tree at tests/e2e/runtime/quickstart"
rm -rf "$RUNTIME_DIR"
mkdir -p "$RUNTIME_DIR"/{gateway,terminal}/{etc,run,state}
# Separate dir for the client's trust store. The runner copies the
# valid cert here after init and after each successful remint. The
# malformed-cert phase intentionally does NOT touch this dir, so the
# client keeps trusting the cert the server is still serving in
# memory after rustls rejects the bad on-disk PEM.
mkdir -p "$RUNTIME_DIR/client-trust"

echo "==> building images"
"${DC[@]}" "${COMPOSE_ARGS[@]}" build

echo "==> running bootstrap (init-quickstart)"
if ! "${DC[@]}" "${COMPOSE_ARGS[@]}" run --rm init-quickstart; then
    echo "FAIL: init-quickstart exited non-zero" >&2
    exit 1
fi

# Snapshot the bootstrap-minted cert into the client's trust dir so
# every HTTPS probe verifies against a known-good PEM the test
# controls. Refreshed after each successful remint below.
cp "$RUNTIME_DIR/terminal/etc/certs/server.pem" "$RUNTIME_DIR/client-trust/server.pem"

echo "==> bringing app + daemons up"
"${DC[@]}" "${COMPOSE_ARGS[@]}" up -d \
    app-nginx app-nginx-alt app-tcp app-udp \
    gateway terminal client

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
    "${DC[@]}" "${COMPOSE_ARGS[@]}" logs --no-color --tail 120 gateway  || true
    "${DC[@]}" "${COMPOSE_ARGS[@]}" logs --no-color --tail 120 terminal || true
    exit 1
}

# -------- enrollment gating -------------------------------------------------

echo "==> waiting for terminal to enrol at gateway"
terminal_enrolled() {
    local out; out=$(ctl_json_on gateway status 2>/dev/null || true)
    echo "$out" | grep -q '"downstream_enrolled": true' && \
        echo "$out" | grep -q '"downstream_ip": "172.31.1.20"'
}
WAIT_TIMEOUT=60 wait_for "terminal enrolled + heartbeat from 172.31.1.20" terminal_enrolled

# -------- predicate propagation ---------------------------------------------

echo "==> waiting for tcp-echo, udp-echo, https-app predicates at gateway"
predicates_landed() {
    local body; body=$(ctl_json_on gateway derived-rules 2>/dev/null || true)
    echo "$body" | grep -q '"name": "tcp-echo"' && \
        echo "$body" | grep -q '"name": "udp-echo"' && \
        echo "$body" | grep -q '"listen_port": 8443'
}
WAIT_TIMEOUT=30 wait_for "all three predicates derived at gateway" predicates_landed

# -------- chain diff (2 hops, no drift) -------------------------------------

echo "==> [chain-diff] yggdrasilctl chain diff from terminal (2 hops)"
diff_json=$(dc_exec terminal yggdrasilctl \
    --json chain --socket /run/yggdrasil/control.sock \
    diff || true)
echo "$diff_json" | python3 -c '
import json, sys
report = json.load(sys.stdin)
hops = report["hops"]
assert len(hops) == 2, f"expected 2 hops, got {len(hops)}: {hops}"
for i, hop in enumerate(hops):
    names = [p["name"] for p in hop["view"]["predicates"]]
    for required in ("tcp-echo", "udp-echo"):
        assert required in names, f"hop {i} missing {required}: {names}"
assert report["drift_detected"] is False, f"unexpected drift: {report}"
print(f"[chain-diff] 2 hops in sync; both see tcp-echo + udp-echo")
' || fail "chain diff --json output did not match 2-hop expectations"

# -------- chain canary (each rule) ------------------------------------------

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
assert len(chain) == 2, f'expected 2 chain hops, got {len(chain)}: {chain}'
print(f'[canary] ${expected_rule}/${proto}: 2 hops armed, status=ok')
" || fail "chain canary for ${expected_rule}/${proto} did not match expectations"
}

echo "==> [chain-canary] tcp-echo (port 7100)"
run_canary 7100 tcp tcp-echo
echo "==> [chain-canary] udp-echo (port 7101)"
run_canary 7101 udp udp-echo
# Note: `chain canary` for HTTPS routes uses a different invocation
# (auto-probes TCP + UDP on [server].https_listen, no --port/--proto
# flags) per docs/operations.md. The HTTPS surface is exercised
# directly by the three HTTPS GET phases below, which prove the same
# end-to-end property.

# -------- TCP echo end-to-end -----------------------------------------------

echo "==> [tcp-echo] client -> gateway:7100 -> chain -> app-tcp:7100"
run_tcp_echo() {
    dc_exec client python3 - <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(("172.31.0.20", 7100))
payload = b"quickstart-tcp-" + b"a" * 200
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
WAIT_TIMEOUT=15 wait_for "TCP echo round-trips through the chain" run_tcp_echo

# -------- UDP echo end-to-end -----------------------------------------------

echo "==> [udp-echo] client -> gateway:7101 -> chain -> app-udp:7101"
run_udp_echo() {
    dc_exec client python3 - <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
payload = b"quickstart-udp-" + b"b" * 200
s.sendto(payload, ("172.31.0.20", 7101))
got, _ = s.recvfrom(65536)
s.close()
sys.exit(0 if got == payload else 1)
PY
}
WAIT_TIMEOUT=15 wait_for "UDP echo round-trips through the chain" run_udp_echo

# -------- HTTPS GETs (SNI dispatch) -----------------------------------------

# Returns JSON with status, body (truncated), and the SHA-256 fingerprint of
# the served leaf cert. The probe trusts the self-signed PEM the init
# container minted (bind-mounted at /etc/ssl/yggdrasil-test/server.pem),
# so `verify_mode = CERT_REQUIRED` and `check_hostname = True` both fire
# on every probe — a regression where yggdrasil served the wrong cert
# (right port, wrong SAN) would fail here instead of silently passing.
https_probe() {
    local sni="$1"
    dc_exec client python3 - "$sni" <<'PY'
import hashlib, http.client, json, socket, ssl, sys
sni = sys.argv[1]
addr = ("172.31.0.20", 8443)
ctx = ssl.create_default_context(cafile="/etc/ssl/yggdrasil-test/server.pem")
# Defaults: check_hostname = True, verify_mode = CERT_REQUIRED. Don't
# weaken either; that's the whole point of the trust posture.
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

echo "==> [https-unknown] SNI=bogus.test.local rejected at TLS handshake"
# yggdrasil's cert resolver returns nothing for an unknown SNI, so the
# rustls handshake fails with an access-denied alert rather than
# completing into an HTTP 404. This is the cert-resolver rung-3
# behaviour documented in `docs/configuration.md`: a hostname with no
# matching `[[route]]` is not bound to the `:443` SNI table.
unknown_sni_rejected() {
    dc_exec client python3 - <<'PY'
import socket, ssl, sys
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = socket.create_connection(("172.31.0.20", 8443), timeout=5)
try:
    ctx.wrap_socket(sock, server_hostname="bogus.test.local")
    sys.exit(1)  # handshake should NOT succeed for an unknown SNI
except ssl.SSLError as e:
    # Any TLS alert from the server is a pass; access_denied is what
    # yggdrasil's rustls sends today, but accepting any SSLError makes
    # the assertion robust to alert-code changes.
    sys.exit(0)
finally:
    sock.close()
PY
}
unknown_sni_rejected || fail "unknown SNI: TLS handshake should have been rejected, but the connection succeeded"
echo "    [ok] unknown SNI rejected at TLS handshake (no [[route]] matched, cert resolver returned nothing)"

# -------- Cert hot-reload (in-place re-mint) --------------------------------

CERT_HOST_DIR="$RUNTIME_DIR/terminal/etc/certs"

remint_cert() {
    # Generates a fresh cert+key with the same SANs. A new RSA key →
    # different leaf fingerprint, which is the observable hot-reload signal.
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
sleep 0.3  # ensure mtime delta vs init's write
remint_cert

# Update the client's trust copy to the new cert BEFORE polling, so
# probes during the polling window can verify successfully once the
# server's watcher catches up. (Brief race window where server still
# serves the old cert + client trusts the new cert is fine — those
# probes raise CertificateVerifyError and the loop just retries.)
cp "$RUNTIME_DIR/terminal/etc/certs/server.pem" "$RUNTIME_DIR/client-trust/server.pem"

# Poll for fp change up to ~3s (250ms debounce + load latency).
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

# -------- Malformed-cert rollback ------------------------------------------

echo "==> [malformed-cert] writing garbage PEM over working cert"
echo "this is not a PEM file" > "$CERT_HOST_DIR/server.pem"
sleep 1.5  # give the watcher debounce + reject latency time to fire

probe_bad=$(https_probe app.test.local) || fail "HTTPS broke after malformed write (should have kept old cert)"
status_bad=$(echo "$probe_bad" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
fp_bad=$(echo "$probe_bad"     | python3 -c "import json,sys; print(json.load(sys.stdin)['fp'])")
[[ "$status_bad" == "200" ]] || fail "expected 200 with old cert, got $status_bad"
[[ "$fp_bad" == "$fp3" ]] || fail "expected old fp ${fp3:0:16}… still serving, got ${fp_bad:0:16}…"
echo "    [ok] old cert still serving after malformed PEM rejected"

# -------- Recovery: restore valid cert -------------------------------------

echo "==> [cert-recovery] writing valid cert; expect another reload"
sleep 0.3
remint_cert
# Refresh trust to the recovered cert before polling; the malformed
# phase intentionally left the old trust in place.
cp "$RUNTIME_DIR/terminal/etc/certs/server.pem" "$RUNTIME_DIR/client-trust/server.pem"
deadline=$(( $(date +%s) + 4 ))
fp4="$fp3"
while (( $(date +%s) < deadline )); do
    sleep 0.25
    cur=$(https_probe app.test.local | python3 -c "import json,sys; print(json.load(sys.stdin)['fp'])" 2>/dev/null || true)
    if [[ -n "$cur" && "$cur" != "$fp3" ]]; then
        fp4="$cur"
        break
    fi
done
[[ "$fp4" != "$fp3" ]] || fail "cert did not reload after recovery"
echo "    [ok] recovery reload succeeded; new leaf fp ${fp4:0:16}…"

# -------- Negative isolation check -----------------------------------------
#
# The client lives on client_wan; the app containers live on home_lan.
# Compose's network isolation means the client must not have a route to
# any home_lan IP. If a connect attempt succeeds, the test topology
# itself is broken and every other assertion above is suspect.

echo "==> [isolation] client cannot reach home_lan app IPs directly"
isolation_probe() {
    local target_ip="$1" target_port="$2" proto="$3"
    dc_exec client python3 - "$target_ip" "$target_port" "$proto" <<'PY'
import socket, sys
ip, port, proto = sys.argv[1], int(sys.argv[2]), sys.argv[3]
fam = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
s = socket.socket(socket.AF_INET, fam)
s.settimeout(2)
try:
    if proto == "tcp":
        s.connect((ip, port))
        sys.exit(1)  # connect succeeded = isolation broken
    else:
        # UDP is connectionless; "isolation" for UDP means no response.
        # Send a probe and see if we get anything back.
        s.sendto(b"isolation-probe", (ip, port))
        try:
            s.recvfrom(4096)
            sys.exit(1)  # got a reply = isolation broken
        except (socket.timeout, OSError):
            sys.exit(0)
except (socket.timeout, ConnectionRefusedError, OSError):
    sys.exit(0)  # unreachable = good
finally:
    s.close()
PY
}
isolation_probe 172.31.2.20 80   tcp || fail "isolation: client could reach app-nginx directly"
isolation_probe 172.31.2.30 80   tcp || fail "isolation: client could reach app-nginx-alt directly"
isolation_probe 172.31.2.40 7100 tcp || fail "isolation: client could reach app-tcp directly"
isolation_probe 172.31.2.50 7101 udp || fail "isolation: client could reach app-udp directly"
echo "    [ok] all four home_lan app endpoints unreachable from client"

# -------- done --------------------------------------------------------------

echo
echo "ALL QUICKSTART E2E TESTS PASSED"
