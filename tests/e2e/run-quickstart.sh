#!/usr/bin/env bash
# tests/e2e/run-quickstart.sh — end-to-end smoke for the canonical
# 2-node quickstart deployment.
#
# Topology (per docker/compose.e2e.quickstart.yml):
#
#   client ──client_wan──► gateway ──chain_link──► terminal ──home_lan──► {nginx, nginx-alt, tcp-echo, udp-echo}
#
# Phases, in order (each ~1-15s; whole suite ~3-5 min cold):
#
#   1.  Build + init (one-shot key/cert/config setup).
#   2.  Enrollment + heartbeat: gateway sees the terminal.
#   3.  Predicate propagation: TCP, UDP, and HTTPS predicates land at gateway.
#   4.  `chain diff` from terminal: 2 hops, no drift.
#   5.  `chain canary` per rule (tcp / udp / https-as-tcp): status=ok, 2 hops.
#   6.  TCP echo client -> gateway:7100 -> chain -> app-tcp:7100, byte-for-byte.
#   7.  UDP echo client -> gateway:7101 -> chain -> app-udp:7101, byte-for-byte.
#   8.  HTTPS GET trio over h1: SNI=app.test.local (-> app-nginx, fp matches
#       init-minted cert), SNI=alt.test.local (-> app-nginx-alt, distinct
#       body, same multi-SAN cert), SNI=bogus.test.local (rejected at
#       TLS handshake — no [[route]] matches and no cert covers the SNI).
#   9.  HSTS + [route.headers] stamped on the primary route only (the
#       alt route stays bare for comparison).
#  10.  Cert hot-reload (in-place re-mint): fp must change, body still 200.
#  11.  Concurrent flow survival: 6 long-lived HTTPS keep-alive sessions
#       complete cleanly across a mid-stream cert reload.
#  12.  Malformed-cert rollback: garbage PEM lands on disk, rustls
#       rejects it, the in-memory cert keeps serving.
#  13.  Recovery: restoring a valid cert reloads cleanly.
#  14.  L4 rule hot-add/remove (inotify-driven; gateway derives + drops
#       the new rule without restart).
#  15.  Route-only hot-reload (regression for finding `route-only-reload-noop`):
#       rewriting `https-routes.toml` without touching `[[rule]]` blocks
#       must still flip the supervisor's HTTPS route table.
#  16.  Cert-less route (regression for finding `default-cert-bypasses-cert-less`):
#       a route whose hostname is outside the default cert's SANs serves
#       plaintext on the companion :80 to lan_cidrs peers, and is absent
#       from BOTH the :8443/tcp (h1) and :8443/udp (h3) SNI dispatch tables.
#  17.  Init re-run idempotency: re-running the init container mid-test
#       skips and live traffic keeps flowing.
#  18.  Restart / rehydration: each yggdrasil node restarts in turn;
#       chain reconverges. Covers config-backed re-enrollment + Noise
#       rekey on reconnect.
#  19.  Negative isolation: client cannot reach any home_lan app directly
#       (regression check that the gateway hadn't bypassed the chain).
#  20.  Two-way isolation: the gateway also cannot bypass the chain.
#  21.  Key rotation (gateway): rotate identity, redo the request/grant
#       ceremony, expect recovery on restart.
#  22.  graceful_drain_timeout: slow-drip TCP across gateway SIGTERM
#       completes within the configured drain window (proves the knob
#       is wired through the full forwarding path).
#  23.  chain apply --file: push an ephemeral rule into the supervisor
#       without touching rules_dir; verify the next rules_dir reload
#       clobbers it (documented "apply REPLACES the set" semantics).
#  24.  chain reconnect RPC: operator nudge to short-circuit the
#       liveness-detection wait; succeeds on terminal, refused on
#       gateway, chain stays healthy across the implicit re-handshake.
#  25.  IPv6 path: hot-load a `[::]:7102` rule, probe over v6 on client_wan.
#  26.  HTTP/3 SNI dispatch trio + h3-only body limit: end-to-end QUIC
#       from client through the gateway's :8443/udp listener; h3 POST
#       over the limit returns 413, same POST over h1 reaches the
#       backend uncapped.
#  27.  Teardown.
#
# Usage:
#   ./tests/e2e/run-quickstart.sh                # build + run + verify + teardown
#   KEEP_STACK=1 ./tests/e2e/run-quickstart.sh   # leave stack up for poking
set -euo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
COMPOSE_FILE="$REPO_ROOT/docker/compose.e2e.quickstart.yml"
RUNTIME_DIR="$REPO_ROOT/tests/e2e/runtime/quickstart"
# Diagnostic packet captures (udp/51820) are written inside each node to
# its bind-mounted state dir, then copied here on failure for CI upload.
# ARTIFACT_DIR lives OUTSIDE RUNTIME_DIR so the teardown `rm -rf` of the
# runtime tree does not delete the collected pcaps.
ARTIFACT_DIR="$REPO_ROOT/tests/e2e/artifacts/quickstart"
CAPTURE_NODES=(gateway terminal)
CAPTURES_STARTED=0
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
    local ec=$?
    # On a failing exit, dump every service's logs BEFORE removing the
    # stack. This trap fires for both explicit fail() calls and bare
    # `wait_for` timeouts (which return non-zero under `set -e`), so it is
    # the single reliable place to capture a daemon-log trail. The CI
    # workflow cannot do this itself: this teardown removes the containers,
    # so any post-job "dump logs" step would find nothing left.
    if (( ec != 0 )) && [[ "${KEEP_STACK:-0}" != "1" ]]; then
        echo "==> [teardown] run failed (exit $ec); dumping container logs"
        for svc in gateway terminal app-nginx app-nginx-alt app-tcp app-udp init-quickstart; do
            echo "----- logs: $svc -----"
            "${DC[@]}" "${COMPOSE_ARGS[@]}" logs --tail 200 "$svc" 2>&1 || true
        done
        collect_captures
    fi
    if [[ "${KEEP_STACK:-0}" == "1" ]]; then
        echo "==> KEEP_STACK=1 set; leaving stack up (runtime tree at $RUNTIME_DIR)"
        return
    fi
    echo "==> tearing down stack"
    "${DC[@]}" "${COMPOSE_ARGS[@]}" down --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$RUNTIME_DIR" 2>/dev/null || true
}
trap teardown EXIT

# Start a UDP :51820 packet capture inside each yggdrasil node. Purpose:
# when a re-enrollment stalls, the pcap shows whether the dialer's
# Handshake1 physically reaches the receiver's netns (=> app-level drop)
# or never arrives (=> transport). tcpdump taps at the interface (AF_PACKET,
# before netfilter), so "seen in pcap but not in the daemon log" pinpoints
# an app/netfilter drop. Needs CAP_NET_RAW (granted via cap_add in the
# compose file). Non-fatal: a capture that fails to start only loses its
# pcap; the test still runs and reports its real result.
start_captures() {
    echo "==> starting diagnostic packet captures (udp/51820) on: ${CAPTURE_NODES[*]}"
    local node
    for node in "${CAPTURE_NODES[@]}"; do
        # `echo $$` then `exec tcpdump` makes tcpdump inherit the shell PID,
        # so the pidfile holds tcpdump's own PID and teardown can SIGINT it
        # for a clean flush without needing pgrep/pkill (absent in slim).
        podman exec -d "${CTR_PREFIX}-${node}" sh -c \
            'echo $$ > /var/lib/yggdrasil/tcpdump.pid; exec tcpdump -p -i any -n -U -w /var/lib/yggdrasil/e2e-capture.pcap udp port 51820' \
            >/dev/null 2>&1 || true
    done
    CAPTURES_STARTED=1
    sleep 1
    for node in "${CAPTURE_NODES[@]}"; do
        if podman exec "${CTR_PREFIX}-${node}" sh -c \
            'kill -0 "$(cat /var/lib/yggdrasil/tcpdump.pid 2>/dev/null)" 2>/dev/null'; then
            echo "    [ok] capture running in $node"
        else
            echo "    WARN: capture did NOT start in $node (tcpdump/NET_RAW?); continuing without its pcap" >&2
        fi
    done
}

# Flush + collect the pcaps into ARTIFACT_DIR. Called from teardown on a
# failing run, before the stack is removed.
collect_captures() {
    [[ "${CAPTURES_STARTED:-0}" == "1" ]] || return 0
    echo "==> [teardown] collecting diagnostic packet captures"
    mkdir -p "$ARTIFACT_DIR"
    local node src
    for node in "${CAPTURE_NODES[@]}"; do
        podman exec "${CTR_PREFIX}-${node}" sh -c \
            'kill -INT "$(cat /var/lib/yggdrasil/tcpdump.pid 2>/dev/null)" 2>/dev/null' \
            >/dev/null 2>&1 || true
    done
    sleep 1
    for node in "${CAPTURE_NODES[@]}"; do
        src="$RUNTIME_DIR/$node/state/e2e-capture.pcap"
        if [[ -f "$src" ]]; then
            cp "$src" "$ARTIFACT_DIR/${node}.pcap" 2>/dev/null || true
            chmod +r "$ARTIFACT_DIR/${node}.pcap" 2>/dev/null || true
            echo "    saved $ARTIFACT_DIR/${node}.pcap"
        else
            echo "    (no pcap for $node — capture may not have started)"
        fi
    done
}
trap teardown EXIT

cd "$REPO_ROOT"

echo "==> preparing fresh runtime tree at tests/e2e/runtime/quickstart"
rm -rf "$RUNTIME_DIR"
rm -rf "$ARTIFACT_DIR"
mkdir -p "$RUNTIME_DIR"/{gateway,terminal}/{etc,run,state}
# Separate dir for the client's trust store. The runner copies the
# valid cert here after init and after each successful remint. The
# malformed-cert phase intentionally does NOT touch this dir, so the
# client keeps trusting the cert the server is still serving in
# memory after rustls rejects the bad on-disk PEM.
mkdir -p "$RUNTIME_DIR/client-trust"

echo "==> building the shared e2e image (once)"
# Every yggdrasil-role service uses the same image (`yggdrasil-e2e:latest`,
# pinned on the compose anchor). Build it exactly once via a single service.
# `podman-compose build` (no args) would build it once PER service and in
# parallel — 6+ concurrent cold `cargo build --release` runs that thrash a
# CI runner and blow the job timeout. See finding
# `e2e-chain-redundant-parallel-builds`.
"${DC[@]}" "${COMPOSE_ARGS[@]}" build init-quickstart

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
# --no-build: the shared image was already built above; without this,
# `up` would trigger the same per-service parallel rebuild.
"${DC[@]}" "${COMPOSE_ARGS[@]}" up -d --no-build \
    app-nginx app-nginx-alt app-tcp app-udp \
    gateway terminal client

# -------- helpers -----------------------------------------------------------

# `container_name:` prefix from compose.e2e.quickstart.yml. Used by the
# detached-exec helper below to bypass podman-compose 1.5's broken
# `exec -d` (it blocks until the inner command finishes, defeating
# the whole point of detach — verified directly: a 5s sleep makes the
# `exec -dT` call take 5s, not return immediately).
CTR_PREFIX="e2e-quickstart"

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
    # Container logs are dumped by the teardown trap on non-zero exit,
    # so a failing wait_for and an explicit fail() produce the same trail.
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

# Containers are confirmed up and enrolled; start the diagnostic packet
# captures now (before the restart/rotation/drain phases that intermittently
# fail to re-enroll). Steady-state heartbeats also give a baseline of what a
# healthy handshake looks like on the wire.
start_captures

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

# -------- HSTS + custom response headers on primary route ------------------
#
# The primary [[route]] in the bootstrap declares `hsts = true` and a
# [route.headers] table. Probe the headers directly to assert they
# fired. Alt route is bare; spot-check that it does NOT carry the
# custom headers (proves the table is route-scoped, not global).

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
# Bare route — must NOT carry the primary route'\''s custom headers.
assert "x-custom-e2e" not in h, \
    f"X-Custom-E2E leaked from primary route into alt: {h}"
assert "x-robots-tag" not in h, \
    f"X-Robots-Tag leaked from primary route into alt: {h}"
' || fail "alt route is leaking primary route's headers"
echo "    [ok] HSTS + custom headers present on primary, absent on alt"

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

# -------- Concurrent flow survival across cert reload ----------------------
#
# `CertStore::reload_host` (per docs/configuration.md:520-524) is
# documented as per-hostname, in-memory cert swap that should NOT
# disturb existing TLS sessions. Spawn N HTTPS keep-alive sessions
# in background; trigger a cert remint mid-stream; assert all N
# complete cleanly. This is the inverse-property test of route
# hot-add (which DOES kill in-flight HTTPS per the same docs).
#
# Independent observer: the Python script in each background
# session runs the full request loop in-process; its OK/ERR
# summary line is what we check after, externally.

echo "==> [concurrent-cert-reload] 6 long-lived HTTPS keep-alive sessions across reload"
# Clean any previous done markers from earlier in this run.
dc_exec client bash -c 'rm -f /tmp/hsess-*.done /tmp/hsess-*.log'

# Spawn 6 background sessions, each doing 12 requests with 0.4s
# spacing → ~5s wall time per session. Cert reload fires ~1s in,
# so most requests on each session straddle the swap.
SESSIONS=6
for i in $(seq 1 "$SESSIONS"); do
    dc_exec_detached client \
        bash -c "python3 /tests/concurrent_https_session.py \
            --sni app.test.local --id $i --requests 12 --interval 0.4 \
            > /tmp/hsess-$i.log 2>&1"
done

# Let sessions warm up + complete their TLS handshake against the
# CURRENT cert before the reload fires.
sleep 1

# Trigger the cert reload mid-stream. Same remint mechanism as the
# existing cert-reload phase above; here the reload is incidental
# to the test (we don't poll for fingerprint change — the existing
# phase already proved that works). The point is that the in-flight
# sessions don't die.
remint_cert
cp "$RUNTIME_DIR/terminal/etc/certs/server.pem" "$RUNTIME_DIR/client-trust/server.pem"

# Wait for all sessions to drop their done markers (~5s + slack).
deadline=$(( $(date +%s) + 30 ))
while (( $(date +%s) < deadline )); do
    done_count=$(dc_exec client bash -c 'ls /tmp/hsess-*.done 2>/dev/null | wc -l' | tr -d '[:space:]')
    [[ "$done_count" == "$SESSIONS" ]] && break
    sleep 0.5
done
done_count=$(dc_exec client bash -c 'ls /tmp/hsess-*.done 2>/dev/null | wc -l' | tr -d '[:space:]')
[[ "$done_count" == "$SESSIONS" ]] || fail "only $done_count/$SESSIONS sessions completed within timeout"

# Each session writes its final line ending in either "OK <n>" or
# "ERR ...". Independent: we inspect the captured stdout, not any
# yggdrasil signal.
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

# Capture the current fingerprint immediately before writing garbage —
# previous phases (including concurrent-cert-reload above) may have
# advanced it from the value fp3 captured during the initial reload.
fp_pre_malformed=$(https_probe app.test.local | python3 -c "import json,sys; print(json.load(sys.stdin)['fp'])")

echo "==> [malformed-cert] writing garbage PEM over working cert"
echo "this is not a PEM file" > "$CERT_HOST_DIR/server.pem"
sleep 1.5  # give the watcher debounce + reject latency time to fire

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
# Refresh trust to the recovered cert before polling; the malformed
# phase intentionally left the old trust in place.
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

# -------- L4 rule hot-add/remove (inotify-driven) --------------------------
#
# Drop a new tcp-echo-hot.toml directly into the host-side bind mount.
# The terminal's inotify watcher (250 ms debounce per
# docs/configuration.md hot-reload semantics) picks it up; the
# predicate publisher emits a new predicate set; the gateway's chain
# client acks and derives a matching listener. Independent client
# probe to the new port verifies the whole flow. Then `rm` the file
# and verify the listener stops accepting.

echo "==> [hot-reload] dropping tcp-echo-hot.toml; expect gateway to derive + serve"
cat > "$RUNTIME_DIR/terminal/etc/rules/tcp-echo-hot.toml" <<EOF
[[rule]]
name     = "tcp-echo-hot"
listen   = "0.0.0.0:7110"
protocol = "tcp"
target   = "172.31.2.40:7100"
EOF

hot_rule_present() {
    ctl_json_on gateway derived-rules 2>/dev/null | grep -q '"name": "tcp-echo-hot"'
}
hot_rule_absent() {
    ! ctl_json_on gateway derived-rules 2>/dev/null | grep -q '"name": "tcp-echo-hot"'
}
WAIT_TIMEOUT=10 wait_for "tcp-echo-hot derived at gateway" \
    hot_rule_present

run_tcp_echo_hot() {
    dc_exec client python3 - <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(("172.31.0.20", 7110))
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
WAIT_TIMEOUT=10 wait_for "tcp-echo-hot removed from gateway" \
    hot_rule_absent
# Re-probe must now fail — the listener stopped, kernel returns ECONNREFUSED
# (or in the wait-and-retry case, the test would time out).
if run_tcp_echo_hot 2>/dev/null; then
    fail "removed rule is still accepting traffic"
fi
echo "    [ok] hot-removed rule no longer serving"

# -------- Route-only hot-reload --------------------------------------------
#
# Regression for finding `route-only-reload-noop`: rewrite the
# https-routes.toml file to swap the primary route's target from
# app-nginx -> app-nginx-alt WITHOUT touching any [[rule]] block. Pre-
# fix, RuleSet::diff only looked at the L4 rules collection, so a
# route-only change tripped the watcher's is_noop gate and was
# silently dropped — the supervisor never reconciled HTTPS routes
# after the modification. With the fix, the diff's `routes_changed`
# flag flips and the supervisor's HTTPS route table is hot-swapped.
#
# Independent probe: SNI=app.test.local should now return alt-nginx's
# body. Restore the file at end-of-phase so subsequent phases see the
# original mapping.

echo "==> [route-hot-reload] rewrite https-routes.toml to swap primary target without touching [[rule]]"
routes_path="$RUNTIME_DIR/terminal/etc/rules/https-routes.toml"
# Snapshot the original file so we can restore it cleanly.
cp "$routes_path" "$routes_path.original"
cat > "$routes_path" <<'EOF'
[[route]]
hostname = "app.test.local"
target   = "http://app-nginx-alt:80"
hsts     = true
[route.headers]
"X-Robots-Tag" = "noindex, nofollow"
"X-Custom-E2E" = "primary-backend"

[[route]]
hostname = "alt.test.local"
target   = "http://app-nginx-alt:80"
EOF

# Wait for the new target to take effect. We poll the probe rather
# than introspecting because (a) the route swap is an L7 thing not
# visible in derived-rules and (b) probes are the independent-
# observer signal we prefer.
route_swap_landed() {
    local out; out=$(https_probe app.test.local 2>/dev/null) || return 1
    echo "$out" | python3 -c "
import json, sys
d = json.load(sys.stdin)
sys.exit(0 if d.get('body') == 'alternate backend (app-nginx-alt)' else 1)
" 2>/dev/null
}
WAIT_TIMEOUT=15 wait_for "primary route's new target serves alt backend" route_swap_landed
echo "    [ok] route-only change to https-routes.toml hot-reloaded; new target observed by probe"

# Restore the original file and confirm the original mapping comes
# back. Same is_noop semantic: this is a route-only diff that must
# re-fire the route reconcile.
cp "$routes_path.original" "$routes_path"
rm "$routes_path.original"
route_restore_landed() {
    local out; out=$(https_probe app.test.local 2>/dev/null) || return 1
    echo "$out" | python3 -c "
import json, sys
d = json.load(sys.stdin)
sys.exit(0 if d.get('body') == 'primary backend (app-nginx)' else 1)
" 2>/dev/null
}
WAIT_TIMEOUT=15 wait_for "primary route restored to original target" route_restore_landed
echo "    [ok] route file restored; original mapping back online"

# -------- Cert-less route ---------------------------------------------------
#
# Regression for finding `default-cert-bypasses-cert-less`: a route
# whose hostname isn't covered by any loaded cert (no convention-dir
# match, no default_cert SAN match) should fall through to the
# **cert-less** rung. Cert-less routes do NOT register on the :443
# SNI dispatch table; they're served as plain HTTP on the companion
# :80 listener to peers in `[server].lan_cidrs`.
#
# The default cert minted at init covers `app.test.local` and
# `alt.test.local`. A hot-loaded route for `internal.test.local`
# falls outside both SANs, so it must be cert-less. We probe from
# the terminal's own loopback (127.0.0.1 is in the default
# `lan_cidrs` of `127.0.0.0/8`) — that's the only available
# in-lan_cidrs probe point in this topology since the client lives
# on `client_wan` (172.31.0.0/24), which is also in lan_cidrs by
# the 172.16/12 catch-all but doesn't naturally reach the
# terminal's :80 listener (no chain rule forwards :80).
#
# Pre-fix, `load_route_cert` returned the default cert as a
# fallback for ANY hostname regardless of SAN coverage; the
# cert-less serving path was effectively dead in any config with
# `default_cert` set.

echo "==> [cert-less] hot-load a route for a hostname outside the default cert's SANs"
cert_less_rule="$RUNTIME_DIR/terminal/etc/rules/cert-less.toml"
cat > "$cert_less_rule" <<'EOF'
[[route]]
hostname = "internal.test.local"
target   = "http://app-nginx:80"
EOF

# Wait for the cert-less route to land on the companion :80
# listener. We poll the actual probe (the cert-less route isn't in
# the derived-rules view, which is L4-only) using the terminal's
# own loopback as a lan_cidrs peer.
cert_less_serves() {
    dc_exec terminal sh -c '
        curl --max-time 3 --silent --fail \
            -H "Host: internal.test.local" \
            http://127.0.0.1:80/ | grep -q "primary backend (app-nginx)"
    '
}
WAIT_TIMEOUT=15 wait_for "internal.test.local served plaintext on :80 to loopback (lan_cidrs)" \
    cert_less_serves
echo "    [ok] cert-less route serving plaintext on companion :80"

# HTTPS to the same hostname must be REJECTED at the TLS handshake:
# cert-less routes don't register on the :443 SNI dispatch table,
# and there's no covering cert in the store. The client gets a
# handshake failure (cert resolver returns None).
cert_less_https_rejected() {
    dc_exec client python3 - <<'PY'
import socket, ssl, sys
ctx = ssl.create_default_context(cafile="/etc/ssl/yggdrasil-test/server.pem")
try:
    sock = socket.create_connection(("172.31.0.20", 8443), timeout=3)
    ssock = ctx.wrap_socket(sock, server_hostname="internal.test.local")
    ssock.close()
    sys.exit(1)  # accepted = test fail
except (ssl.SSLError, ConnectionResetError, ConnectionAbortedError, OSError):
    sys.exit(0)  # rejected = pass
PY
}
WAIT_TIMEOUT=10 wait_for "cert-less route HTTPS rejected at SNI (not in :443 dispatch table)" \
    cert_less_https_rejected
echo "    [ok] cert-less route correctly absent from :8443/tcp h1 SNI dispatch"

# h3 path: cert-less routes must ALSO be absent from the :8443/udp
# QUIC SNI dispatch table. The cert resolver returns None for the
# uncovered SNI, so the QUIC TLS handshake fails before any HTTP/3
# stream opens. h3_probe.py exits 1 on handshake reject (which is
# the success signal here); we invert via `!`.
cert_less_h3_rejected() {
    ! dc_exec client python3 /tests/h3_probe.py \
        --sni internal.test.local --host 172.31.0.20 --port 8443 \
        2>/dev/null
}
WAIT_TIMEOUT=15 wait_for "cert-less route h3 rejected at SNI (not in :8443/udp dispatch table)" \
    cert_less_h3_rejected
echo "    [ok] cert-less route correctly absent from :8443/udp h3 SNI dispatch"

# Hot-remove the cert-less rule file and verify the companion :80
# stops serving (route-only reload also exercises the
# `route-only-reload-noop` fix on the removal direction).
rm "$cert_less_rule"
cert_less_gone() {
    ! dc_exec terminal sh -c '
        curl --max-time 3 --silent --fail \
            -H "Host: internal.test.local" \
            http://127.0.0.1:80/ >/dev/null 2>&1
    '
}
WAIT_TIMEOUT=15 wait_for "cert-less route removed after rule deletion" cert_less_gone
echo "    [ok] cert-less route torn down cleanly"

# -------- Init re-run idempotency ------------------------------------------
#
# init-quickstart is idempotent at the bash level (skips when all
# expected files exist). Verify the compose-level re-run also works:
# nothing is broken by re-running init mid-test, and the existing
# live traffic continues unaffected.

echo "==> [init-idempotent] re-running init-quickstart container mid-test"
init_out=$("${DC[@]}" "${COMPOSE_ARGS[@]}" run --rm init-quickstart 2>&1) \
    || fail "init-quickstart re-run exited non-zero: $init_out"
echo "$init_out" | grep -q "already bootstrapped; skipping" \
    || fail "init re-run did not detect existing bootstrap: $init_out"

# Live probes must still succeed.
run_tcp_echo || fail "TCP echo broke after init re-run"
probe_after_init=$(https_probe app.test.local) \
    || fail "HTTPS probe failed after init re-run"
[[ $(echo "$probe_after_init" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])") == "200" ]] \
    || fail "HTTPS not 200 after init re-run"
echo "    [ok] init re-run was a no-op and live traffic kept flowing"

# -------- Restart / rehydration -------------------------------------------
#
# Restart each yggdrasil node in turn; assert the chain re-converges
# and probes succeed against the same surface. Implicitly tests:
#
#   - Config-backed enrollment survives a process restart: the daemon
#     comes back up with the same [accept]/[dial] pubkey it had before,
#     not as an unenrolled fresh node.
#   - Noise rekey on reconnection (the chain client's handshake
#     re-runs against the surviving peer; same for the chain acceptor
#     when the dialing peer reconnects).
#   - The daemon's startup path itself (a regression that broke
#     `yggdrasil run` would surface here).
#
# Independent: probes are run by the client, not yggdrasil. The
# restart mechanism is `podman compose restart`, which sends SIGTERM
# and starts a fresh container with the same bind mounts.

restart_and_reprobe() {
    local service="$1" role_desc="$2"
    echo "==> [restart-$role_desc] restart $service, expect chain recovers"

    # Restart and let the daemon come back up. Default --time is 10s.
    "${DC[@]}" "${COMPOSE_ARGS[@]}" restart "$service" >/dev/null

    # Nudge the terminal (which dials the gateway) after a gateway restart so
    # its chain client drops the now-dead session and re-handshakes
    # immediately instead of coasting ~15-20s on heartbeat-liveness detection.
    # The nudge also resets the reconnect backoff to its minimum
    # (chain/client/mod.rs: ReconnectRequested => backoff = BACKOFF_MIN), so
    # retries stay frequent through the ~30s post-restart UDP delivery gap.
    # NOTE: contrary to an earlier belief that "the UDP control plane is
    # unaffected", the control plane IS affected — measured, the gateway's
    # yggdrasil_heartbeat_datagrams_received_total stays flat for ~30s after
    # `podman-compose restart gateway`, then the first arriving datagram
    # completes the handshake instantly. A terminal restart needs no nudge —
    # its own client restarts fresh.
    #
    # The data-plane TCP/UDP echo probes below still bump into the SEPARATE
    # client -> gateway:client_wan conntrack floor for ~30-60s (finding
    # `forwarding-broken-after-handshake-on-fresh-gateway`, a
    # container-networking artifact, not a yggdrasil bug); the nudge speeds
    # the control-plane re-enroll, not those.
    if [[ "$service" == "gateway" ]]; then
        dc_exec terminal yggdrasilctl chain reconnect >/dev/null 2>&1 \
            || echo "    [warn] chain reconnect nudge on terminal failed (continuing)"
    fi

    # Re-wait for enrollment. The gating predicate is the same one
    # used at startup — what we want to assert is that the post-
    # restart state matches the pre-restart state, not that some
    # restart-specific signal fires.
    # 90s (up from 60s) gives margin over the nudged recovery (~30-35s: the
    # ~30s delivery gap + a couple of low-backoff retries) plus CI variance.
    WAIT_TIMEOUT=90 wait_for "chain re-enrolled after $role_desc restart" terminal_enrolled

    # The terminal's predicate publisher now subscribes to the chain
    # client's session-epoch watch and automatically resyncs on each
    # fresh handshake, so an upstream restart no longer leaves the
    # gateway in a "session re-established but no predicates" state.
    # No sentinel-rule workaround needed.

    # Wait for predicates to land at the gateway.
    WAIT_TIMEOUT=15 wait_for "predicates re-derived at gateway after $role_desc restart" \
        predicates_landed

    # Same independent probes that passed pre-restart.
    WAIT_TIMEOUT=60 wait_for "TCP echo recovers after $role_desc restart" run_tcp_echo
    WAIT_TIMEOUT=15 wait_for "UDP echo recovers after $role_desc restart" run_udp_echo

    # HTTPS needs the frontend to come back up; poll briefly. Also
    # refresh trust in case the terminal re-minted the cert during
    # its restart path (it doesn't currently, but defensive).
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

restart_and_reprobe gateway gateway
restart_and_reprobe terminal terminal

# -------- Negative isolation check -----------------------------------------
#
# The client lives on client_wan; the app containers live on home_lan.
# Compose's network isolation means the client must not have a route to
# any home_lan IP. If a connect attempt succeeds, the test topology
# itself is broken and every other assertion above is suspect.

echo "==> [isolation] client cannot reach home_lan app IPs directly"
# Run all probes for a container in a single Python invocation with
# threading so the per-probe 2s socket timeout overlaps. With 4
# probes per phase, this turns ~8s of sequential timeouts plus 4×
# dc_exec overhead into ~2s of overlapped timeouts plus 1× exec.
# Probes argv shape: ip port proto [ip port proto ...]; the helper
# returns non-zero with reachable destinations on stderr if any
# probe completed successfully (which would mean isolation broke).
isolation_probes_all_isolated() {
    local from_container="$1"; shift
    dc_exec "$from_container" python3 - "$@" <<'PY'
import socket, sys, threading
args = sys.argv[1:]
assert len(args) % 3 == 0, "expected ip port proto triples"
probes = [(args[i], int(args[i+1]), args[i+2]) for i in range(0, len(args), 3)]
results = [None] * len(probes)

def check(idx, ip, port, proto):
    fam = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    s = socket.socket(socket.AF_INET, fam)
    s.settimeout(2)
    try:
        if proto == "tcp":
            s.connect((ip, port))
            results[idx] = f"{ip}:{port}/{proto} REACHABLE (connect succeeded)"
        else:
            s.sendto(b"isolation-probe", (ip, port))
            try:
                s.recvfrom(4096)
                results[idx] = f"{ip}:{port}/{proto} REACHABLE (UDP reply received)"
            except (socket.timeout, OSError):
                results[idx] = None
    except (socket.timeout, ConnectionRefusedError, OSError):
        results[idx] = None
    finally:
        s.close()

threads = [threading.Thread(target=check, args=(i, *p)) for i, p in enumerate(probes)]
for t in threads: t.start()
for t in threads: t.join()
reachable = [r for r in results if r is not None]
if reachable:
    for r in reachable: print(r, file=sys.stderr)
    sys.exit(1)
sys.exit(0)
PY
}
isolation_probes_all_isolated client \
    172.31.2.20 80   tcp \
    172.31.2.30 80   tcp \
    172.31.2.40 7100 tcp \
    172.31.2.50 7101 udp \
    || fail "isolation: client reached one or more home_lan endpoints (see stderr)"
echo "    [ok] all four home_lan app endpoints unreachable from client"

# -------- Two-way isolation: gateway also can't bypass the chain -----------
#
# The strong version of the property: the gateway, which sits between
# the client and the chain, must ALSO have no route to home_lan. If
# the gateway accidentally got connectivity to the app containers
# (network misconfig, host IP-forwarding leak, etc.), a future
# regression could let it dial them directly and skip the chain
# entirely — and the client-side isolation check above would still
# pass.

echo "==> [isolation] gateway cannot reach home_lan app IPs directly"
isolation_probes_all_isolated gateway \
    172.31.2.20 80   tcp \
    172.31.2.30 80   tcp \
    172.31.2.40 7100 tcp \
    172.31.2.50 7101 udp \
    || fail "isolation: gateway reached one or more home_lan endpoints (see stderr)"
echo "    [ok] all four home_lan app endpoints unreachable from gateway"

# -------- Key rotation -----------------------------------------------------
#
# Rotate the gateway's identity, redo the request/grant ceremony from
# inside the running containers (the same flow an operator would
# follow per docs/operations.md → Key rotation), restart both nodes,
# and verify the chain recovers.
#
# The rotation is the canonical "I think my key is compromised"
# operator action. Exercises:
#
#   - `yggdrasilctl identity rotate --force
#       --yes-i-understand-this-breaks-existing-chains` (the literal
#     flag name documented in operations.md)
#   - `identity export-request` from the downstream
#   - `identity add-accept` from the new upstream (re-binds
#     [accept].pubkey to the terminal's existing pubkey, but mints
#     a fresh grant signed by the NEW upstream identity)
#   - `identity add-dial` on the downstream (rewrites [dial].pubkey
#     to the new upstream key)
#   - Independent probes verify the chain is back online afterwards
#
# Files shuttle through the host's bind-mounted runtime tree rather
# than `podman cp`, because every container's /etc/yggdrasil is
# already a bind mount the host can write to directly.

echo "==> [key-rotation] rotate gateway identity, redo ceremony, expect recovery"

# Baseline (already passing). The rotation is destructive — if we
# fail mid-rotation, the chain stays broken until the next test run
# wipes the runtime tree.
run_tcp_echo || fail "baseline TCP broken before rotation"

# Snapshot the gateway's pre-rotation pubkey so we can verify the
# rotation actually changed it.
gw_pubkey_before=$(dc_exec gateway yggdrasilctl identity show 2>/dev/null \
    | grep '^pubkey:' | awk '{print $2}')
[[ -n "$gw_pubkey_before" ]] || fail "could not read gateway's pre-rotation pubkey"

# Rotate. The daemon process is still running; the new identity is
# written to disk but won't take effect until restart.
dc_exec gateway yggdrasilctl identity rotate \
    --identity-file /etc/yggdrasil/identity.key \
    --force \
    --yes-i-understand-this-breaks-existing-chains >/dev/null \
    || fail "identity rotate failed"

gw_pubkey_after=$(dc_exec gateway yggdrasilctl identity show 2>/dev/null \
    | grep '^pubkey:' | awk '{print $2}')
[[ -n "$gw_pubkey_after" ]] || fail "could not read gateway's post-rotation pubkey"
[[ "$gw_pubkey_after" != "$gw_pubkey_before" ]] || fail "rotation did not change the pubkey"
echo "    [ok] gateway identity rotated (${gw_pubkey_before:0:24}… -> ${gw_pubkey_after:0:24}…)"

# Restart gateway so the new identity is loaded. Chain will be DOWN
# because the terminal's [dial].pubkey still pins the OLD key.
"${DC[@]}" "${COMPOSE_ARGS[@]}" restart gateway >/dev/null
# Wait for the gateway's control socket to come back so the
# subsequent rotation ceremony (add-accept RPC) lands cleanly.
# Replaces a `sleep 5` placeholder. `ctl_on gateway status` is
# the cheapest "daemon ready" observable.
WAIT_TIMEOUT=15 wait_for "gateway control socket responsive after rotation+restart" \
    ctl_on gateway status

# Confirm the chain is genuinely down (handshakes against the new
# gateway should fail; TCP echo should not work). We don't fail the
# test if it happens to still work — that'd be a different kind of
# bug — but log the state for debugging.
if run_tcp_echo 2>/dev/null; then
    echo "    [note] chain still functional immediately after rotation+restart"
    echo "    [note] (probably the heartbeat hasn't expired yet)"
fi

# Redo the request/grant ceremony from inside the running containers.
# Files shuttle through the host's bind-mounted runtime tree.
local_req="$RUNTIME_DIR/terminal/etc/rotation-request.txt"
local_grant="$RUNTIME_DIR/gateway/etc/rotation-grant.txt"

dc_exec terminal yggdrasilctl --config /etc/yggdrasil/config.toml \
    identity export-request \
    --identity-file /etc/yggdrasil/identity.key \
    --out /etc/yggdrasil/rotation-request.txt \
    --note "post-rotation re-enroll" >/dev/null \
    || fail "terminal failed to export request after rotation"

# Move request file into the gateway's view via the host filesystem.
cp "$local_req" "$RUNTIME_DIR/gateway/etc/rotation-request.txt"

dc_exec gateway yggdrasilctl --config /etc/yggdrasil/config.toml \
    identity add-accept \
    --identity-file /etc/yggdrasil/identity.key \
    --from /etc/yggdrasil/rotation-request.txt \
    --my-endpoint "${GATEWAY_CHAIN_ENDPOINT:-gateway:51820}" \
    --out /etc/yggdrasil/rotation-grant.txt \
    --note "post-rotation gateway->terminal" >/dev/null \
    || fail "gateway add-accept failed after rotation"

# Move grant back to the terminal's view.
cp "$local_grant" "$RUNTIME_DIR/terminal/etc/rotation-grant.txt"

dc_exec terminal yggdrasilctl --config /etc/yggdrasil/config.toml \
    identity add-dial \
    --identity-file /etc/yggdrasil/identity.key \
    --from /etc/yggdrasil/rotation-grant.txt >/dev/null \
    || fail "terminal add-dial failed after rotation"

# [dial] is read at startup; restart the terminal so the new pubkey
# takes effect. Gateway is already restarted above.
"${DC[@]}" "${COMPOSE_ARGS[@]}" restart terminal >/dev/null

# Re-wait for enrollment. The publisher's session-epoch watch
# auto-resyncs on the fresh handshake post-restart (fix for finding
# `publisher-dedup-after-upstream-restart`), so no sentinel-rule
# workaround is needed here.
WAIT_TIMEOUT=90 wait_for "post-rotation re-enrollment" terminal_enrolled
WAIT_TIMEOUT=15 wait_for "predicates re-derived at gateway post-rotation" predicates_landed
WAIT_TIMEOUT=60 wait_for "TCP echo recovers post-rotation" run_tcp_echo
echo "    [ok] gateway key rotation + re-enrollment cycle succeeded"

# Cleanup transit files (operator-equivalent of `rm /tmp/*.{request,grant}`).
rm -f "$local_req" "$local_grant" \
      "$RUNTIME_DIR/gateway/etc/rotation-request.txt" \
      "$RUNTIME_DIR/terminal/etc/rotation-grant.txt"

# -------- graceful_drain_timeout ------------------------------------------
#
# [server].graceful_drain_timeout = "5s" was set in the gateway's
# seed config. Per docs/configuration.md:42, on SIGTERM the daemon
# stops accepting new TCP connections immediately but waits up to
# the configured duration for in-flight conversations to finish
# naturally before cancelling them.
#
# We test by:
#   1. Spawning a slow-drip TCP client (1 byte/sec for 7 bytes ≈ 7s
#      wall) that connects through gateway:7100 → chain → app-tcp.
#   2. After ~1s (one byte sent), SIGTERM the gateway with
#      `podman stop --time 10`.
#   3. Wait for both: the client to finish, and the gateway process
#      to exit.
#   4. Assert the client got all 7 bytes echoed back (drain worked).
#   5. Assert the gateway exit took ~5s (drain window respected,
#      not killed abruptly nor stuck indefinitely).
#
# Independent observer: the slow-drip client writes OK/ERR to a log
# file the runner inspects, and we time `podman stop` ourselves.

echo "==> [graceful-drain] slow-drip TCP through chain across gateway SIGTERM"
dc_exec client bash -c 'rm -f /tmp/slow-tcp.done /tmp/slow-tcp.log'

# Spawn the slow-drip client in background. Use the detached helper
# (NOT `dc_exec ... &`) — see CTR_PREFIX comment.
dc_exec_detached client \
    bash -c "python3 /tests/slow_tcp_echo.py \
        --host 172.31.0.20 --port 7100 \
        --bytes 7 --interval 1.0 \
        > /tmp/slow-tcp.log 2>&1"

# Let the connection establish + the slow-drip get well into its
# send loop (we want several bytes mid-flight when SIGTERM fires).
# 3 seconds gets us to ~byte 3 of 7.
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

# Restart gateway for the negative-isolation phase that follows.
"${DC[@]}" "${COMPOSE_ARGS[@]}" start gateway >/dev/null
# Nudge the terminal to re-handshake immediately (resets reconnect backoff to
# its minimum) instead of coasting on the drained session; same rationale as
# restart_and_reprobe above. The control plane sees the same ~30s post-restart
# UDP delivery gap, so a low, frequently-retried backoff recovers fastest.
dc_exec terminal yggdrasilctl chain reconnect >/dev/null 2>&1 \
    || echo "    [warn] chain reconnect nudge on terminal failed (continuing)"
WAIT_TIMEOUT=90 wait_for "gateway re-enrolled after graceful-drain restart" terminal_enrolled
# The publisher's session-epoch watch auto-resyncs after the gateway
# comes back, so no post-restart sentinel is needed here.
WAIT_TIMEOUT=15 wait_for "predicates re-derived at gateway post-drain" \
    predicates_landed
echo "    [ok] gateway re-enrolled after graceful-drain SIGTERM"

# -------- chain apply --file (ephemeral rule push) -------------------------
#
# `yggdrasilctl chain apply --file <path>` pushes a pre-validated rule
# set into the running terminal daemon's supervisor without touching
# rules_dir. The pushed set REPLACES the in-memory current set; it
# lives only until the next rules_dir reload, at which point the
# disk state wins again (see docs/configuration.md:543-546).
#
# This phase exercises that lifetime:
#   1. push an ephemeral-tcp rule on a fresh port (7120),
#   2. observe it derive at the gateway,
#   3. round-trip a TCP echo through the new port (independent probe),
#   4. `touch` an on-disk rule file to fire the rules_dir watcher,
#   5. observe the ephemeral rule disappear from derived-rules,
#   6. confirm the ephemeral port no longer accepts.
#
# The on-disk rules (tcp-echo, udp-echo, https-routes) are
# *temporarily* clobbered while the ephemeral set is active. That's
# the documented behaviour ("apply REPLACES the set"); the
# rules_dir touch in step 4 restores them.

echo "==> [chain-apply] push ephemeral rule via chain apply, then clobber via rules_dir reload"

dc_exec terminal bash -c 'cat > /tmp/candidate-rules.toml' <<'EOF'
[[rule]]
name     = "ephemeral-tcp"
listen   = "0.0.0.0:7120"
protocol = "tcp"
target   = "172.31.2.40:7100"
EOF

dc_exec terminal yggdrasilctl chain --socket /run/yggdrasil/control.sock \
    apply --file /tmp/candidate-rules.toml >/dev/null \
    || fail "chain apply rejected the candidate rule set"

ephemeral_derived() {
    ctl_json_on gateway derived-rules 2>/dev/null | grep -q '"name": "ephemeral-tcp"'
}
WAIT_TIMEOUT=10 wait_for "ephemeral-tcp derived at gateway" ephemeral_derived

# Independent probe: TCP round-trip through the new port.
ephemeral_tcp_echo() {
    dc_exec client python3 - <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(("172.31.0.20", 7120))
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
target   = "172.31.2.40:7100"
EOF

ephemeral_absent() {
    ! ctl_json_on gateway derived-rules 2>/dev/null | grep -q '"name": "ephemeral-tcp"'
}
WAIT_TIMEOUT=10 wait_for "ephemeral-tcp clobbered by rules_dir reload" ephemeral_absent
rm "$clobber_sentinel"
clobber_sentinel_absent() {
    ! ctl_json_on gateway derived-rules 2>/dev/null | grep -q '"name": "chain-apply-clobber-sentinel"'
}
WAIT_TIMEOUT=10 wait_for "clobber sentinel removed from gateway" clobber_sentinel_absent

# And the port itself no longer accepts. Connection-refused is the
# success signal (port unbound after the rule was torn down).
ephemeral_tcp_dead() {
    dc_exec client python3 - <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect(("172.31.0.20", 7120))
    s.close()
    sys.exit(1)
except (ConnectionRefusedError, socket.timeout, OSError):
    sys.exit(0)
PY
}
WAIT_TIMEOUT=10 wait_for "ephemeral-tcp port no longer accepts" ephemeral_tcp_dead

# Confirm the disk-defined rules are back online (one of them suffices).
WAIT_TIMEOUT=10 wait_for "original tcp-echo rule restored after reload" run_tcp_echo
echo "    [ok] chain apply ephemeral lifetime (push -> serve -> clobber) verified"

# -------- chain reconnect RPC (operator-triggered re-handshake) ------------
#
# Mechanically exercises `yggdrasilctl chain reconnect`. The RPC's
# real operational value is the speedup baked into the restart-gateway
# and graceful-drain phases above (a `chain reconnect` right after
# the upstream comes back skips ~15-30s of fast-probe / backstop
# detection); this phase proves the RPC itself works on a healthy
# chain — refuses on gateway-mode daemons, succeeds on the terminal,
# and the chain stays healthy across the implicit re-handshake.

echo "==> [chain-reconnect] operator nudge: rpc fires re-handshake, traffic survives"

# Issue the nudge from the terminal. Returns sub-second on success.
reconnect_out=$(dc_exec terminal yggdrasilctl chain reconnect 2>&1) \
    || fail "chain reconnect rpc failed on terminal: $reconnect_out"
echo "$reconnect_out" | grep -q "reconnect signal delivered" \
    || fail "chain reconnect did not produce the expected ack line: $reconnect_out"
echo "    [ok] terminal accepted chain reconnect RPC"

# The same RPC against the gateway must be refused client-side
# (gateway has no chain client). The CLI mode-probe catches this
# before the RPC even ships, returning a clean exit-non-zero.
if dc_exec gateway yggdrasilctl chain reconnect 2>/dev/null; then
    fail "chain reconnect on gateway should have been refused (no chain client)"
fi
echo "    [ok] gateway correctly refuses chain reconnect"

# The re-handshake fires async on the chain-client task. Observe
# externally that the chain stays healthy: enrollment and traffic
# probes must keep passing without any wait beyond a normal
# scheduler tick + handshake RTT.
WAIT_TIMEOUT=15 wait_for "chain still enrolled after reconnect rpc" terminal_enrolled
WAIT_TIMEOUT=15 wait_for "predicates still derived at gateway after reconnect rpc" \
    predicates_landed
WAIT_TIMEOUT=15 wait_for "TCP echo still round-trips after reconnect rpc" run_tcp_echo
echo "    [ok] chain reconnect rpc completed without disturbing live traffic"

# -------- IPv6 path (hot-load v6 rule, probe over v6) ----------------------
#
# Exercises the "added rule spawns a fresh listener on a new address
# family" code path. The terminal's rule binds [::]:7102 (the
# predicate carries protocol+port, and the gateway derives a rule
# with the same listen spec — so both nodes bind a v6 socket). The
# client connects to the gateway's v6 address on client_wan; the
# gateway then forwards over the IPv4 chain transport to the
# terminal, which targets the IPv4 echo on home_lan. Only client_wan
# is dual-stack; chain_link and home_lan stay IPv4-only, which is
# realistic (most homelabs have v6 client-facing but IPv4 internally).

echo "==> [ipv6] hot-load tcp-echo-v6 rule, probe via IPv6"

v6_rule="$RUNTIME_DIR/terminal/etc/rules/tcp-echo-v6.toml"
cat > "$v6_rule" <<'EOF'
[[rule]]
name     = "tcp-echo-v6"
listen   = "[::]:7102"
protocol = "tcp"
target   = "172.31.2.40:7100"
EOF

v6_derived() {
    ctl_json_on gateway derived-rules 2>/dev/null | grep -q '"name": "tcp-echo-v6"'
}
WAIT_TIMEOUT=15 wait_for "tcp-echo-v6 derived at gateway" v6_derived

# Independent v6 probe — `AF_INET6` socket against the gateway's v6
# address. The literal address is parsed as v6 (not a hostname lookup)
# so no DNS path is involved.
ipv6_tcp_echo() {
    dc_exec client python3 - <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(("fd00:31::20", 7102, 0, 0))
except (ConnectionRefusedError, socket.timeout, OSError) as e:
    print(f"connect failed: {e}", file=sys.stderr)
    sys.exit(1)
payload = b"quickstart-v6-" + b"6" * 100
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
WAIT_TIMEOUT=15 wait_for "TCP echo round-trips over IPv6" ipv6_tcp_echo
echo "    [ok] IPv6 TCP rule hot-loaded and serving over v6"

# Hygiene: remove the v6 rule so subsequent phases (none yet, but
# guards against drift) see a clean set.
rm "$v6_rule"
v6_absent() {
    ! ctl_json_on gateway derived-rules 2>/dev/null | grep -q '"name": "tcp-echo-v6"'
}
WAIT_TIMEOUT=15 wait_for "tcp-echo-v6 removed from gateway" v6_absent

# -------- HTTP/3 SNI dispatch trio + body limit ----------------------------
#
# These phases probe the gateway's h3 frontend over QUIC end-to-end:
# client (over client_wan) -> gateway:8443/udp -> chain transport ->
# terminal's h3 frontend -> backend.
#
# Previously these phases probed the terminal's loopback directly
# because the gateway's supervisor rejected the HTTPS-derived UDP
# rule as conflicting with the TCP rule on the same port (finding
# `gateway-udp-claim-conflict`, fixed in supervisor reconcile.rs:
# claim key is now (SocketAddr, Protocol)). Now both 8443/tcp and
# 8443/udp listeners coexist on the gateway and h3 traverses the
# full chain.

echo "==> [https-h3-primary] h3 SNI=app.test.local -> app-nginx (via gateway + chain)"
h3_probe_via_gw() {
    dc_exec client python3 /tests/h3_probe.py \
        --sni "$1" --host 172.31.0.20 --port 8443 \
        "${@:2}"
}
probe_h3_primary=$(h3_probe_via_gw app.test.local) \
    || fail "h3 probe to app.test.local failed: $probe_h3_primary"
status_h3_p=$(echo "$probe_h3_primary" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
body_h3_p=$(echo "$probe_h3_primary"   | python3 -c "import json,sys; print(json.load(sys.stdin)['body'])")
fp_h3_p=$(echo "$probe_h3_primary"     | python3 -c "import json,sys; print(json.load(sys.stdin)['fp'])")
[[ "$status_h3_p" == "200" ]] || fail "h3 primary: expected 200, got $status_h3_p"
[[ "$body_h3_p" == "primary backend (app-nginx)" ]] \
    || fail "h3 primary: expected primary body, got '$body_h3_p'"
echo "    [ok] h3 primary SNI dispatched to app-nginx (leaf fp ${fp_h3_p:0:16}…)"

echo "==> [https-h3-alt] h3 SNI=alt.test.local -> app-nginx-alt"
probe_h3_alt=$(h3_probe_via_gw alt.test.local) \
    || fail "h3 probe to alt.test.local failed: $probe_h3_alt"
status_h3_a=$(echo "$probe_h3_alt" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
body_h3_a=$(echo "$probe_h3_alt"   | python3 -c "import json,sys; print(json.load(sys.stdin)['body'])")
fp_h3_a=$(echo "$probe_h3_alt"     | python3 -c "import json,sys; print(json.load(sys.stdin)['fp'])")
[[ "$status_h3_a" == "200" ]] || fail "h3 alt: expected 200, got $status_h3_a"
[[ "$body_h3_a" == "alternate backend (app-nginx-alt)" ]] \
    || fail "h3 alt: expected alt body, got '$body_h3_a'"
[[ "$fp_h3_a" == "$fp_h3_p" ]] \
    || fail "h3 alt: leaf cert fingerprint differs from primary; same multi-SAN cert should cover both"
echo "    [ok] h3 alt SNI dispatched to app-nginx-alt (same cert)"

echo "==> [https-h3-unknown] h3 SNI=bogus.test.local rejected at TLS handshake"
# aioquic raises (returns exit 1) on an unknown SNI because the
# server's no_cert_for_sni response trips its handshake. We assert
# that the probe DOES fail.
if dc_exec client python3 /tests/h3_probe.py \
        --sni bogus.test.local --host 172.31.0.20 --port 8443 2>/dev/null; then
    fail "h3 unknown SNI: probe unexpectedly succeeded; should have been rejected"
fi
echo "    [ok] h3 unknown SNI rejected at TLS handshake"

echo "==> [https-body-limit] h3 POST > limit -> 413; same POST over h1 -> 200/405"
# Bootstrap set https_request_body_limit = 1024. Send 2048 bytes
# (well over the limit) over h3; expect 413 Payload Too Large.
probe_h3_big=$(dc_exec client python3 /tests/h3_probe.py \
    --sni app.test.local --host 172.31.0.20 --port 8443 \
    --method POST --body-bytes 2048) \
    || fail "h3 body-limit probe failed at transport: $probe_h3_big"
status_h3_big=$(echo "$probe_h3_big" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
[[ "$status_h3_big" == "413" ]] || fail "h3 body-limit: expected 413, got $status_h3_big"
echo "    [ok] h3 2048-byte POST rejected with 413 (limit=1024)"

# Same body over h1 must succeed reaching the backend — limit is
# h3-only per docs. nginx returns 405 for POST on a static-file
# location, which is the proof the request reached the backend
# uncapped (yggdrasil didn't enforce 1024).
probe_h1_big=$(dc_exec client python3 - <<'PY'
import http.client, json, socket, ssl
ctx = ssl.create_default_context(cafile="/etc/ssl/yggdrasil-test/server.pem")
conn = http.client.HTTPSConnection("app.test.local", 8443, context=ctx, timeout=5)
sock = socket.create_connection(("172.31.0.20", 8443), timeout=5)
ssock = ctx.wrap_socket(sock, server_hostname="app.test.local")
conn.sock = ssock
body = b"x" * 2048
conn.request("POST", "/", body=body,
    headers={"Host": "app.test.local", "Content-Type": "application/octet-stream"})
resp = conn.getresponse()
print(json.dumps({"status": resp.status}))
conn.close()
PY
) || fail "h1 body-limit probe failed at transport"
status_h1_big=$(echo "$probe_h1_big" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
[[ "$status_h1_big" == "200" || "$status_h1_big" == "405" ]] \
    || fail "h1 body-limit: expected 200/405 (uncapped reached backend), got $status_h1_big — h1 path incorrectly enforced h3-only body limit"
echo "    [ok] same 2048-byte POST over h1 reached backend (status $status_h1_big), h3-only limit honoured"

# Note: cert-less h3 dispatch-absence coverage lives in the
# Cert-less route phase above (companion :80 serves + :8443/tcp and
# :8443/udp SNI both reject), which exercises the same finding
# `default-cert-bypasses-cert-less` regression on the h3 path.

# -------- done --------------------------------------------------------------

echo
echo "ALL QUICKSTART E2E TESTS PASSED"
