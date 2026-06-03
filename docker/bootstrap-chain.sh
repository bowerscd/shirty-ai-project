#!/usr/bin/env bash
# bootstrap-chain.sh — one-shot key + cert + config setup for the
# 3-node chain compose stack (terminal -> relay -> gateway).
#
# Runs in the `init-chain` service. Mounts each daemon's etc volume at
# /etc/yggdrasil-<role> (init's view); the daemons mount the same
# volume at /etc/yggdrasil (their view).
#
# What this script does:
#   1. Generates 3 identities (gateway, relay, terminal).
#   2. Drives two request/grant ceremonies in sequence:
#        - terminal exports request -> relay add-accept -> terminal add-dial
#        - relay     exports request -> gateway add-accept -> relay add-dial
#   3. Mints a self-signed cert with two SANs covering both HTTPS
#      hostnames the test uses.
#   4. Writes the terminal's `conf.d/*.toml` rule + route files using
#      the post-fadac5d schema. Relay holds no rule files.
#
# Idempotent: re-running after a partial failure is a no-op.
set -euo pipefail

# ---- env from compose ------------------------------------------------------

: "${GATEWAY_INET_ENDPOINT:?missing}"
: "${RELAY_CHAIN_ENDPOINT:?missing}"
: "${PRIMARY_SNI:?missing}"        ; : "${ALT_SNI:?missing}"
: "${APP_NGINX_HOST:?missing}"     ; : "${APP_NGINX_ALT_HOST:?missing}"
: "${APP_TCP_IP:?missing}"         ; : "${APP_UDP_HOST:?missing}"

# ---- paths (init container's view) -----------------------------------------

GW_CFG=/etc/yggdrasil-gateway/config.toml
GW_KEY=/etc/yggdrasil-gateway/identity.key

RL_CFG=/etc/yggdrasil-relay/config.toml
RL_KEY=/etc/yggdrasil-relay/identity.key

TM_CFG=/etc/yggdrasil-terminal/config.toml
TM_KEY=/etc/yggdrasil-terminal/identity.key
TM_CERT=/etc/yggdrasil-terminal/certs/server.pem
TM_PKEY=/etc/yggdrasil-terminal/certs/server.key

TM_REQUEST=/tmp/terminal-request.txt
TM_GRANT=/tmp/terminal-grant.txt
RL_REQUEST=/tmp/relay-request.txt
RL_GRANT=/tmp/relay-grant.txt

if [[ -f "$GW_KEY" && -f "$GW_CFG" \
   && -f "$RL_KEY" && -f "$RL_CFG" \
   && -f "$TM_KEY" && -f "$TM_CFG" \
   && -f "$TM_CERT" && -f "$TM_PKEY" ]]; then
    echo "[init-chain] already bootstrapped; skipping"
    exit 0
fi

# ---- gateway (accept-only) -------------------------------------------------

echo "[init-chain] preparing gateway dirs"
mkdir -p /etc/yggdrasil-gateway/rules /etc/yggdrasil-gateway/certs

echo "[init-chain] writing gateway seed config"
cat >"$GW_CFG" <<'EOF'
[server]
rules_dir     = "/etc/yggdrasil/rules"
cert_dir      = "/etc/yggdrasil/certs"
identity_file = "/etc/yggdrasil/identity.key"
# Bind all derived rules dual-stack (v4 + v6) so the IPv6 e2e
# phase has a v6 ingress at the gateway. Realistic homelab posture
# for an operator who wants v6 client-facing while keeping
# internal LAN forwarding on v4. With kernel
# `/proc/sys/net/ipv6/bindv6only = 0` (default on most distros),
# Linux accepts both v4 and v6 connections on a `[::]:port` socket.
default_bind = "::"
# Honour SIGTERM by draining in-flight TCP / HTTPS for up to 5s
# before cancelling. Exercised by the graceful-drain e2e phase.
graceful_drain_timeout = "5s"

[control]
socket = "/run/yggdrasil/control.sock"

[accept]
listen = "0.0.0.0:51820"
EOF

echo "[init-chain] generating gateway identity"
yggdrasilctl --config "$GW_CFG" identity rotate \
    --identity-file "$GW_KEY" --force >/dev/null

# ---- relay (mid-chain: dial + accept) --------------------------------------

echo "[init-chain] preparing relay dirs"
mkdir -p /etc/yggdrasil-relay/rules /etc/yggdrasil-relay/certs

echo "[init-chain] writing relay seed config"
# Relay's [accept] listen is the address terminals dial; its [dial]
# is filled in by add-dial after the gateway mints its grant.
cat >"$RL_CFG" <<'EOF'
[server]
rules_dir     = "/etc/yggdrasil/rules"
cert_dir      = "/etc/yggdrasil/certs"
identity_file = "/etc/yggdrasil/identity.key"

[control]
socket = "/run/yggdrasil/control.sock"

[accept]
listen = "0.0.0.0:51820"
EOF

echo "[init-chain] generating relay identity"
yggdrasilctl --config "$RL_CFG" identity rotate \
    --identity-file "$RL_KEY" --force >/dev/null

# ---- terminal (dial-only) --------------------------------------------------

echo "[init-chain] preparing terminal dirs"
mkdir -p /etc/yggdrasil-terminal/rules /etc/yggdrasil-terminal/certs

echo "[init-chain] writing terminal seed config"
cat >"$TM_CFG" <<'EOF'
[server]
rules_dir     = "/etc/yggdrasil/rules"
cert_dir      = "/etc/yggdrasil/certs"
identity_file = "/etc/yggdrasil/identity.key"
default_cert  = "/etc/yggdrasil/certs/server.pem"
default_key   = "/etc/yggdrasil/certs/server.key"
https_listen  = "0.0.0.0:8443"
# Cap inbound HTTP/3 request bodies at 1 KiB. Exercised by the
# h3-body-limit e2e phase: an h3 POST over the limit must come back
# 413, while the same POST over h1 (which streams uncapped per
# docs/configuration.md:45) must come back 200.
https_request_body_limit = 1024

[control]
socket = "/run/yggdrasil/control.sock"
EOF

echo "[init-chain] generating terminal identity"
yggdrasilctl --config "$TM_CFG" identity rotate \
    --identity-file "$TM_KEY" --force >/dev/null

# ---- handshake 1: terminal <-> relay --------------------------------------

echo "[init-chain] terminal exports request"
yggdrasilctl --config "$TM_CFG" identity export-request \
    --identity-file "$TM_KEY" \
    --out "$TM_REQUEST" \
    --note "chain e2e terminal" >/dev/null

echo "[init-chain] relay add-accept (writes relay's [accept].pubkey)"
yggdrasilctl --config "$RL_CFG" identity add-accept \
    --identity-file "$RL_KEY" \
    --from "$TM_REQUEST" \
    --my-endpoint "${RELAY_CHAIN_ENDPOINT}" \
    --out "$TM_GRANT" \
    --note "chain e2e relay->terminal" >/dev/null

echo "[init-chain] terminal add-dial (writes terminal's [dial])"
yggdrasilctl --config "$TM_CFG" identity add-dial \
    --identity-file "$TM_KEY" \
    --from "$TM_GRANT" >/dev/null

# ---- handshake 2: relay <-> gateway ---------------------------------------

echo "[init-chain] relay exports request"
yggdrasilctl --config "$RL_CFG" identity export-request \
    --identity-file "$RL_KEY" \
    --out "$RL_REQUEST" \
    --note "chain e2e relay" >/dev/null

echo "[init-chain] gateway add-accept (writes gateway's [accept].pubkey)"
yggdrasilctl --config "$GW_CFG" identity add-accept \
    --identity-file "$GW_KEY" \
    --from "$RL_REQUEST" \
    --my-endpoint "${GATEWAY_INET_ENDPOINT}" \
    --out "$RL_GRANT" \
    --note "chain e2e gateway->relay" >/dev/null

echo "[init-chain] relay add-dial (writes relay's [dial])"
yggdrasilctl --config "$RL_CFG" identity add-dial \
    --identity-file "$RL_KEY" \
    --from "$RL_GRANT" >/dev/null

rm -f "$TM_REQUEST" "$TM_GRANT" "$RL_REQUEST" "$RL_GRANT"

# ---- self-signed cert with multi-SAN ---------------------------------------

echo "[init-chain] minting self-signed cert covering both SNIs"
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$TM_PKEY" \
    -out    "$TM_CERT" \
    -days   1 \
    -subj   "/CN=${PRIMARY_SNI}" \
    -addext "subjectAltName=DNS:${PRIMARY_SNI},DNS:${ALT_SNI}" \
    >/dev/null 2>&1
chmod 0644 "$TM_CERT"
chmod 0600 "$TM_PKEY"

# ---- terminal rules + routes -----------------------------------------------

echo "[init-chain] writing terminal rules: tcp-echo, udp-echo"
# tcp-echo's target is a LITERAL IP — exercises the static-resolver
# code path. udp-echo's target is a hostname so the same harness
# exercises the DNS-resolver path as well.
cat >/etc/yggdrasil-terminal/rules/tcp-echo.toml <<EOF
[[rule]]
name     = "tcp-echo"
listen   = "0.0.0.0:7100"
protocol = "tcp"
target   = "${APP_TCP_IP}:7100"
EOF

cat >/etc/yggdrasil-terminal/rules/udp-echo.toml <<EOF
[[rule]]
name         = "udp-echo"
listen       = "0.0.0.0:7101"
protocol     = "udp"
target       = "${APP_UDP_HOST}:7101"
idle_timeout = "30s"
EOF

echo "[init-chain] writing terminal https routes: primary + alt SNI"
# Same shape as bootstrap-quickstart.sh — primary exercises HSTS +
# [route.headers] injection; alt stays bare for body-comparison.
cat >/etc/yggdrasil-terminal/rules/https-routes.toml <<EOF
[[route]]
hostname = "${PRIMARY_SNI}"
target   = "http://${APP_NGINX_HOST}:80"
hsts     = true
[route.headers]
"X-Robots-Tag" = "noindex, nofollow"
"X-Custom-E2E" = "primary-backend"

[[route]]
hostname = "${ALT_SNI}"
target   = "http://${APP_NGINX_ALT_HOST}:80"
EOF

echo "[init-chain] done"
