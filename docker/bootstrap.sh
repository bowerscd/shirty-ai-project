#!/usr/bin/env bash
# bootstrap.sh — one-shot key-and-config setup for the compose e2e stack.
#
# Runs in the `init` service (entrypoint = this script). Mounts both daemons'
# state volumes; generates fresh identities, mints an enrolment token, writes
# both configs, and applies the token via `ratatoskr enroll`. Yggdrasil and
# ratatoskr `depends_on: { init: condition: service_completed_successfully }`
# so they don't start until this finishes.
set -euo pipefail

YGG_CFG=/etc/yggdrasil/config.toml
YGG_KEY=/etc/yggdrasil/identity.key
RAT_CFG=/etc/ratatoskr/config.toml
RAT_KEY=/etc/ratatoskr/identity.key
TOKEN_PATH=/tmp/ratatoskr.token

# Re-running the init service should be idempotent so `podman compose up`
# after a partial failure works without manual cleanup.
if [[ -f "$YGG_KEY" && -f "$RAT_KEY" && -f "$YGG_CFG" && -f "$RAT_CFG" ]]; then
    echo "[init] already bootstrapped; skipping"
    exit 0
fi

echo "[init] generating yggdrasil identity"
yggdrasil keygen --identity-file "$YGG_KEY" --force >/dev/null

echo "[init] generating ratatoskr identity"
ratatoskr keygen --identity-file "$RAT_KEY" --force >/dev/null
RAT_PUB=$(ratatoskr pubkey --identity-file "$RAT_KEY")

echo "[init] writing yggdrasil server config"
cat >"$YGG_CFG" <<EOF
[server]
heartbeat_listen = "0.0.0.0:51820"
branches_dir     = "/etc/yggdrasil/branches"
state_dir        = "/var/lib/yggdrasil"
identity_file    = "$YGG_KEY"

[metrics]
listen = "0.0.0.0:9090"

[control]
socket = "/run/yggdrasil/control.sock"

[peer]
public_key_hex = ""
rekey_interval = "1h"
EOF

echo "[init] writing default branch rules"
cat >/etc/yggdrasil/branches/tcp-echo.toml <<'EOF'
[[rule]]
name          = "tcp-echo"
listen        = "0.0.0.0:7000"
protocol      = "tcp"
upstream_port = 7100
EOF

cat >/etc/yggdrasil/branches/udp-echo.toml <<'EOF'
[[rule]]
name          = "udp-echo"
listen        = "0.0.0.0:7001"
protocol      = "udp"
upstream_port = 7101
idle_timeout  = "30s"
EOF

echo "[init] minting enrolment token (peer=$RAT_PUB, endpoint=vps:51820)"
yggdrasil enroll-token \
    --peer-pubkey "$RAT_PUB" \
    --endpoint vps:51820 \
    --config "$YGG_CFG" \
    --output "$TOKEN_PATH" \
    --force >/dev/null

echo "[init] seeding ratatoskr config (placeholders overwritten by 'enroll')"
cat >"$RAT_CFG" <<EOF
[client]
yggdrasil_endpoint   = "placeholder:1"
yggdrasil_pubkey_hex = "0000000000000000000000000000000000000000000000000000000000000000"
identity_file        = "$RAT_KEY"
heartbeat_interval   = "1s"
rekey_interval       = "5m"
EOF

echo "[init] applying enrolment token on ratatoskr side"
ratatoskr enroll "$TOKEN_PATH" --config "$RAT_CFG" >/dev/null
rm -f "$TOKEN_PATH"

echo "[init] done"
