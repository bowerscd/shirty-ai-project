#!/usr/bin/env bash
# bootstrap.sh — one-shot key-and-config setup for the compose e2e stack.
#
# Runs in the `init` service (entrypoint = this script). Mounts the state
# volumes for vps (gateway-mode acceptor) and home (terminal-mode dialer);
# provisions identities, writes configs, and runs the offline
# intro/invite handshake via `yggdrasilctl identity`. vps/home
# `depends_on: { init: ... }` so they don't start until this completes.
#
# Note: in three-mode design, proxy rules are owned by the terminal and
# pushed to the gateway via the chain predicate. Hence rules go in home's
# rules dir, not vps's.
set -euo pipefail

# ---- paths -----------------------------------------------------------------

# vps: gateway-mode acceptor. Accepts the chain dial from home and binds
# the listeners that home pushes via the chain predicate.
VPS_CFG=/etc/yggdrasil/config.toml
VPS_KEY=/etc/yggdrasil/identity.key

# home: terminal-mode dialer. Owns the rule set + runs the python echo
# backends in the same network namespace so the rule targets terminate
# locally on home.
HOME_CFG=/etc/yggdrasil-home/config.toml
HOME_KEY=/etc/yggdrasil-home/identity.key

INTRO_PATH=/tmp/home-intro.txt
INVITE_PATH=/tmp/home-invite.txt

# Re-running the init service should be idempotent so `podman compose up`
# after a partial failure works without manual cleanup.
if [[ -f "$VPS_KEY"  && -f "$VPS_CFG"  \
   && -f "$HOME_KEY" && -f "$HOME_CFG" ]]; then
    echo "[init] already bootstrapped; skipping"
    exit 0
fi

# ---- vps (relay) -----------------------------------------------------------

echo "[init] preparing vps dirs"
mkdir -p /etc/yggdrasil/rules /etc/yggdrasil/certs
# vps owns no rules; the chain predicate from home dictates the rule set.
# An empty rules_dir is fine (the supervisor only complains on parse errors).

echo "[init] writing vps seed config"
cat >"$VPS_CFG" <<EOF
[server]
rules_dir     = "/etc/yggdrasil/rules"
cert_dir      = "/etc/yggdrasil/certs"
state_dir     = "/var/lib/yggdrasil"
identity_file = "$VPS_KEY"

[metrics]
listen = "0.0.0.0:9090"

[control]
socket = "/run/yggdrasil/control.sock"

[accept]
listen = "0.0.0.0:51820"
EOF

echo "[init] generating vps identity"
yggdrasilctl --config "$VPS_CFG" identity rotate \
    --identity-file "$VPS_KEY" --force >/dev/null

# ---- home (terminal-mode downstream) ---------------------------------------
#
# The home volume is mounted at /etc/yggdrasil-home in this init container,
# but the home daemon container mounts it at /etc/yggdrasil. So the config
# file's path fields refer to the home container's view (/etc/yggdrasil/*),
# while the bash variables that init uses to read/write files use the
# init container's view (/etc/yggdrasil-home/*).

echo "[init] preparing home dirs"
mkdir -p /etc/yggdrasil-home/rules /etc/yggdrasil-home/certs

echo "[init] writing home seed config"
cat >"$HOME_CFG" <<EOF
[server]
rules_dir     = "/etc/yggdrasil/rules"
cert_dir      = "/etc/yggdrasil/certs"
state_dir     = "/var/lib/yggdrasil"
identity_file = "/etc/yggdrasil/identity.key"

[control]
socket = "/run/yggdrasil/control.sock"
EOF

echo "[init] generating home identity"
yggdrasilctl --config "$HOME_CFG" identity rotate \
    --identity-file "$HOME_KEY" --force >/dev/null

# ---- offline intro/invite handshake ---------------------------------------

echo "[init] home exports intro"
yggdrasilctl --config "$HOME_CFG" identity export-intro \
    --identity-file "$HOME_KEY" \
    --out "$INTRO_PATH" \
    --note "e2e home downstream" >/dev/null

echo "[init] vps mints invite for home (writes [accept])"
yggdrasilctl --config "$VPS_CFG" identity add-downstream \
    --identity-file "$VPS_KEY" \
    --from "$INTRO_PATH" \
    --my-endpoint vps:51820 \
    --out "$INVITE_PATH" \
    --note "e2e vps→home" >/dev/null

echo "[init] home applies invite (writes [dial])"
yggdrasilctl --config "$HOME_CFG" identity add-upstream \
    --identity-file "$HOME_KEY" \
    --from "$INVITE_PATH" >/dev/null

rm -f "$INTRO_PATH" "$INVITE_PATH"

# ---- home rules ------------------------------------------------------------
#
# All proxy rules live on the terminal in three-mode design and are pushed
# up to the gateway (vps) via the chain predicate. The gateway binds the
# listeners; traffic tunnels back to the terminal which delivers it locally.

echo "[init] writing home rules: tcp-echo, udp-echo, dns-echo"
cat >/etc/yggdrasil-home/rules/tcp-echo.toml <<'EOF'
[[rule]]
name        = "tcp-echo"
listen      = "0.0.0.0:7000"
protocol    = "tcp"
target_addr = "127.0.0.1:7100"
EOF

cat >/etc/yggdrasil-home/rules/udp-echo.toml <<'EOF'
[[rule]]
name         = "udp-echo"
listen       = "0.0.0.0:7001"
protocol     = "udp"
target_addr  = "127.0.0.1:7101"
idle_timeout = "30s"
EOF

# DNS-resolved target_host: pinned via home's `extra_hosts:` entry to the
# home container's own IP. Exercises the OS-resolver path on the terminal.
cat >/etc/yggdrasil-home/rules/dns-echo.toml <<'EOF'
[[rule]]
name        = "dns-echo"
listen      = "0.0.0.0:7200"
protocol    = "tcp"
target_host = "home-echo-dns:7100"
EOF

echo "[init] done"
