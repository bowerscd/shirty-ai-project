#!/usr/bin/env bash
# bootstrap-quickstart.sh — one-shot key + cert + config setup for the
# 2-node quickstart compose stack (terminal -> gateway).
#
# Runs in the `init-quickstart` service. Mounts each daemon's etc
# volume at /etc/yggdrasil-<role> (init's view); the daemons mount the
# same volume at /etc/yggdrasil (their view). All path fields in the
# generated configs use the *daemon's* view.
#
# What this script does:
#   1. Generates 2 identities (gateway, terminal).
#   2. Drives the request/grant ceremony: terminal exports a request,
#      gateway mints a grant, terminal applies the grant.
#   3. Mints a self-signed cert with two SANs covering both HTTPS
#      hostnames the test uses.
#   4. Writes the terminal's `conf.d/*.toml` rule + route files using
#      the post-fadac5d schema (top-level `[[route]]`, node-wide
#      `default_cert` / `default_key`).
#
# Idempotent: re-running after a partial failure is a no-op.
set -euo pipefail

# ---- env from compose ------------------------------------------------------

: "${GATEWAY_CHAIN_ENDPOINT:?missing}"
: "${PRIMARY_SNI:?missing}"        ; : "${ALT_SNI:?missing}"
: "${APP_NGINX_HOST:?missing}"     ; : "${APP_NGINX_ALT_HOST:?missing}"
: "${APP_TCP_IP:?missing}"         ; : "${APP_UDP_HOST:?missing}"

# ---- paths (init container's view) -----------------------------------------

GW_CFG=/etc/yggdrasil-gateway/config.toml
GW_KEY=/etc/yggdrasil-gateway/identity.key

TM_CFG=/etc/yggdrasil-terminal/config.toml
TM_KEY=/etc/yggdrasil-terminal/identity.key
TM_CERT=/etc/yggdrasil-terminal/certs/server.pem
TM_PKEY=/etc/yggdrasil-terminal/certs/server.key

REQUEST_PATH=/tmp/terminal-request.txt
GRANT_PATH=/tmp/terminal-grant.txt

if [[ -f "$GW_KEY" && -f "$GW_CFG" \
   && -f "$TM_KEY" && -f "$TM_CFG" \
   && -f "$TM_CERT" && -f "$TM_PKEY" ]]; then
    echo "[init-quickstart] already bootstrapped; skipping"
    exit 0
fi

# ---- gateway (accept-only) -------------------------------------------------

echo "[init-quickstart] preparing gateway dirs"
mkdir -p /etc/yggdrasil-gateway/rules /etc/yggdrasil-gateway/certs

echo "[init-quickstart] writing gateway seed config"
cat >"$GW_CFG" <<EOF
[server]
rules_dir     = "/etc/yggdrasil/rules"
cert_dir      = "/etc/yggdrasil/certs"
state_dir     = "/var/lib/yggdrasil"
identity_file = "/etc/yggdrasil/identity.key"

[control]
socket = "/run/yggdrasil/control.sock"

[accept]
# Hard-coded :51820 here; the operator-facing endpoint string is
# GATEWAY_CHAIN_ENDPOINT, which is the host:port the terminal dials.
listen = "0.0.0.0:51820"
EOF

echo "[init-quickstart] generating gateway identity"
yggdrasilctl --config "$GW_CFG" identity rotate \
    --identity-file "$GW_KEY" --force >/dev/null

# ---- terminal (dial-only) --------------------------------------------------

echo "[init-quickstart] preparing terminal dirs"
mkdir -p /etc/yggdrasil-terminal/rules /etc/yggdrasil-terminal/certs

echo "[init-quickstart] writing terminal seed config"
# https_listen on 8443 because the daemon may not run as root in
# downstream container images and 443 needs CAP_NET_BIND_SERVICE.
# default_cert + default_key point at the PEMs this script mints below.
cat >"$TM_CFG" <<EOF
[server]
rules_dir     = "/etc/yggdrasil/rules"
cert_dir      = "/etc/yggdrasil/certs"
state_dir     = "/var/lib/yggdrasil"
identity_file = "/etc/yggdrasil/identity.key"
default_cert  = "/etc/yggdrasil/certs/server.pem"
default_key   = "/etc/yggdrasil/certs/server.key"
https_listen  = "0.0.0.0:8443"

[control]
socket = "/run/yggdrasil/control.sock"
EOF

echo "[init-quickstart] generating terminal identity"
yggdrasilctl --config "$TM_CFG" identity rotate \
    --identity-file "$TM_KEY" --force >/dev/null

# ---- request/grant handshake -----------------------------------------------

echo "[init-quickstart] terminal exports request"
yggdrasilctl --config "$TM_CFG" identity export-request \
    --identity-file "$TM_KEY" \
    --out "$REQUEST_PATH" \
    --note "quickstart e2e terminal" >/dev/null

echo "[init-quickstart] gateway add-accept (writes [accept].pubkey)"
yggdrasilctl --config "$GW_CFG" identity add-accept \
    --identity-file "$GW_KEY" \
    --from "$REQUEST_PATH" \
    --my-endpoint "${GATEWAY_CHAIN_ENDPOINT}" \
    --out "$GRANT_PATH" \
    --note "quickstart e2e gateway->terminal" >/dev/null

echo "[init-quickstart] terminal add-dial (writes [dial])"
yggdrasilctl --config "$TM_CFG" identity add-dial \
    --identity-file "$TM_KEY" \
    --from "$GRANT_PATH" >/dev/null

rm -f "$REQUEST_PATH" "$GRANT_PATH"

# ---- self-signed cert with multi-SAN ---------------------------------------

echo "[init-quickstart] minting self-signed cert covering both SNIs"
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
#
# Post-fadac5d schema:
#   * `[[rule]]` is L4-only (TCP / UDP).
#   * `[[route]]` is top-level (sibling of `[[rule]]`), not nested.
#   * Cert resolution is node-wide; routes do NOT carry cert/key.

echo "[init-quickstart] writing terminal rules: tcp-echo, udp-echo"
# tcp-echo's target is a LITERAL IP — exercises the static-resolver
# code path (parsed once, no re-resolution). udp-echo's target is a
# hostname so the same harness also exercises the DNS-resolver path
# (periodic re-resolution via the OS resolver).
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

echo "[init-quickstart] writing terminal https routes: primary + alt SNI"
# Primary route exercises HSTS + the [route.headers] static-injection
# surface (mirrors nginx's `add_header NAME VALUE always` posture per
# docs/configuration.md). Alt route stays bare so the comparison
# between the two response shapes is meaningful.
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

echo "[init-quickstart] done"
