#!/usr/bin/env bash
# bootstrap.sh — one-shot key-and-config setup for the compose e2e stack.
#
# Runs in the `init` service (entrypoint = this script). Mounts the state
# volumes for vps (upstream relay), home (downstream terminal), and the
# standalone terminal-mode yggdrasil; provisions identities, writes
# configs, and runs the offline intro/invite handshake via
# `yggdrasilctl identity`. vps/home/terminal `depends_on: { init: ... }`
# so they don't start until this completes.
set -euo pipefail

# ---- paths -----------------------------------------------------------------

# vps: relay-mode upstream. Owns rules + accepts heartbeats from home.
VPS_CFG=/etc/yggdrasil/config.toml
VPS_KEY=/etc/yggdrasil/identity.key

# home: terminal-mode downstream. Heartbeats up to vps. Runs the echo
# backends in the same network namespace so vps's rule targets
# `downstream_ip:upstream_port` land on the python echo servers.
HOME_CFG=/etc/yggdrasil-home/config.toml
HOME_KEY=/etc/yggdrasil-home/identity.key

# terminal: standalone terminal-mode yggdrasil. No chain config; exists
# only to exercise the DNS-resolved `upstream_host` proxy path.
YGT_CFG=/etc/yggdrasil-terminal/config.toml
YGT_KEY=/etc/yggdrasil-terminal/identity.key

INTRO_PATH=/tmp/home-intro.txt
INVITE_PATH=/tmp/home-invite.txt

# Re-running the init service should be idempotent so `podman compose up`
# after a partial failure works without manual cleanup.
if [[ -f "$VPS_KEY"  && -f "$VPS_CFG"  \
   && -f "$HOME_KEY" && -f "$HOME_CFG" \
   && -f "$YGT_KEY"  && -f "$YGT_CFG" ]]; then
    echo "[init] already bootstrapped; skipping"
    exit 0
fi

# ---- vps (relay) -----------------------------------------------------------

echo "[init] preparing vps dirs"
mkdir -p /etc/yggdrasil/rules /etc/yggdrasil/certs

echo "[init] writing vps seed config"
cat >"$VPS_CFG" <<EOF
[server]
mode          = "relay"
rules_dir     = "/etc/yggdrasil/rules"
cert_dir      = "/etc/yggdrasil/certs"
state_dir     = "/var/lib/yggdrasil"
identity_file = "$VPS_KEY"

[metrics]
listen = "0.0.0.0:9090"

[control]
socket = "/run/yggdrasil/control.sock"

[chain.listener]
listen = "0.0.0.0:51820"
EOF

echo "[init] generating vps identity"
yggdrasilctl --config "$VPS_CFG" identity rotate \
    --identity-file "$VPS_KEY" --force >/dev/null

echo "[init] writing default rules (vps)"
cat >/etc/yggdrasil/rules/tcp-echo.toml <<'EOF'
[[rule]]
name          = "tcp-echo"
listen        = "0.0.0.0:7000"
protocol      = "tcp"
upstream_port = 7100
EOF

cat >/etc/yggdrasil/rules/udp-echo.toml <<'EOF'
[[rule]]
name          = "udp-echo"
listen        = "0.0.0.0:7001"
protocol      = "udp"
upstream_port = 7101
idle_timeout  = "30s"
EOF

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
mode          = "terminal"
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

echo "[init] vps mints invite for home (writes [chain.downstream])"
yggdrasilctl --config "$VPS_CFG" identity add-downstream \
    --identity-file "$VPS_KEY" \
    --from "$INTRO_PATH" \
    --my-endpoint vps:51820 \
    --out "$INVITE_PATH" \
    --note "e2e vps→home" >/dev/null

echo "[init] home applies invite (writes [chain.upstream])"
yggdrasilctl --config "$HOME_CFG" identity add-upstream \
    --identity-file "$HOME_KEY" \
    --from "$INVITE_PATH" >/dev/null

rm -f "$INTRO_PATH" "$INVITE_PATH"

# ---- terminal (standalone, DNS-upstream test) ------------------------------
#
# Separate identity + config + rules dir for the `terminal` container. The
# rule listens on :7200 and forwards to `home-echo-dns:7100`. That hostname
# is pinned to the home box's IP via the terminal container's `extra_hosts:`
# entry, so the DNS resolver path exercises both the resolution loop and
# the dial-after-resolve hot path in tcp.rs. No chain config on this side —
# the daemon runs purely as a local proxy.

echo "[init] preparing terminal dirs"
mkdir -p /etc/yggdrasil-terminal/rules /etc/yggdrasil-terminal/certs

echo "[init] writing terminal seed config"
cat >"$YGT_CFG" <<'EOF'
[server]
mode          = "terminal"
rules_dir     = "/etc/yggdrasil/rules"
cert_dir      = "/etc/yggdrasil/certs"
state_dir     = "/var/lib/yggdrasil"
identity_file = "/etc/yggdrasil/identity.key"

[control]
socket = "/run/yggdrasil/control.sock"
EOF

echo "[init] generating terminal identity"
yggdrasilctl --config "$YGT_CFG" identity rotate \
    --identity-file "$YGT_KEY" --force >/dev/null

echo "[init] writing terminal DNS-upstream rule"
cat >/etc/yggdrasil-terminal/rules/dns-echo.toml <<'EOF'
[[rule]]
name          = "dns-echo"
listen        = "0.0.0.0:7200"
protocol      = "tcp"
upstream_host = "home-echo-dns:7100"
EOF

echo "[init] done"
