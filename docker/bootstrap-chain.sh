#!/usr/bin/env bash
# bootstrap-chain.sh — one-shot key-and-config setup for the 3-level chain
# compose e2e stack (terminal -> midbox -> vps).
#
# Runs in the `init-chain` service. Mounts the state volumes for vps_chain
# (the chain root relay), midbox (mid-chain forwarder), and home_chain
# (the publishing terminal); provisions three identities, writes configs,
# and runs the offline request/grant handshake via `yggdrasilctl identity`
# twice (home<->midbox, midbox<->vps).
#
# Idempotent: re-running after a partial failure is a no-op.
set -euo pipefail

# ---- paths (init container's view) -----------------------------------------
#
# Each daemon container mounts its volume at the canonical /etc/yggdrasil.
# This init container mounts each one at /etc/yggdrasil-<role> so config +
# rules can be written without collision. Config file path fields refer to
# the *consumer* container's view (/etc/yggdrasil/*); bash variables use
# init's view (/etc/yggdrasil-<role>/*).

VPS_CFG=/etc/yggdrasil-vps/config.toml
VPS_KEY=/etc/yggdrasil-vps/identity.key

MIDBOX_CFG=/etc/yggdrasil-midbox/config.toml
MIDBOX_KEY=/etc/yggdrasil-midbox/identity.key

HOME_CFG=/etc/yggdrasil-home/config.toml
HOME_KEY=/etc/yggdrasil-home/identity.key

HOME_REQUEST=/tmp/home-request.txt
HOME_GRANT=/tmp/home-grant.txt
MIDBOX_REQUEST=/tmp/midbox-request.txt
MIDBOX_GRANT=/tmp/midbox-grant.txt

if [[ -f "$VPS_KEY"     && -f "$VPS_CFG"    \
   && -f "$MIDBOX_KEY"  && -f "$MIDBOX_CFG" \
   && -f "$HOME_KEY"    && -f "$HOME_CFG" ]]; then
    echo "[init-chain] already bootstrapped; skipping"
    exit 0
fi

# ---- vps (chain root relay) ------------------------------------------------

echo "[init-chain] preparing vps-chain dirs"
mkdir -p /etc/yggdrasil-vps/rules /etc/yggdrasil-vps/certs

echo "[init-chain] writing vps-chain seed config"
cat >"$VPS_CFG" <<EOF
[server]
rules_dir     = "/etc/yggdrasil/rules"
cert_dir      = "/etc/yggdrasil/certs"
state_dir     = "/var/lib/yggdrasil"
identity_file = "/etc/yggdrasil/identity.key"

[control]
socket = "/run/yggdrasil/control.sock"

[accept]
listen = "0.0.0.0:51820"
EOF

echo "[init-chain] generating vps-chain identity"
yggdrasilctl --config "$VPS_CFG" identity rotate \
    --identity-file "$VPS_KEY" --force >/dev/null

# ---- midbox (mid-chain relay + forwarder) ----------------------------------

echo "[init-chain] preparing midbox dirs"
mkdir -p /etc/yggdrasil-midbox/rules /etc/yggdrasil-midbox/certs

echo "[init-chain] writing midbox seed config"
cat >"$MIDBOX_CFG" <<EOF
[server]
rules_dir     = "/etc/yggdrasil/rules"
cert_dir      = "/etc/yggdrasil/certs"
state_dir     = "/var/lib/yggdrasil"
identity_file = "/etc/yggdrasil/identity.key"

[control]
socket = "/run/yggdrasil/control.sock"

[accept]
listen = "0.0.0.0:51820"
EOF

echo "[init-chain] generating midbox identity"
yggdrasilctl --config "$MIDBOX_CFG" identity rotate \
    --identity-file "$MIDBOX_KEY" --force >/dev/null

# ---- home-chain (publishing terminal) --------------------------------------

echo "[init-chain] preparing home-chain dirs"
mkdir -p /etc/yggdrasil-home/rules /etc/yggdrasil-home/certs

echo "[init-chain] writing home-chain seed config"
cat >"$HOME_CFG" <<EOF
[server]
rules_dir     = "/etc/yggdrasil/rules"
cert_dir      = "/etc/yggdrasil/certs"
state_dir     = "/var/lib/yggdrasil"
identity_file = "/etc/yggdrasil/identity.key"

[control]
socket = "/run/yggdrasil/control.sock"
EOF

echo "[init-chain] generating home-chain identity"
yggdrasilctl --config "$HOME_CFG" identity rotate \
    --identity-file "$HOME_KEY" --force >/dev/null

# home-chain publishes a single TCP predicate. midbox derives a matching
# listener AND forwards the verbatim predicate set upstream to vps, so
# vps applies the same predicate against home's origin pubkey.
# The terminal-mode rule needs a target_addr because terminal-mode
# rules can't use peer-relative target_port. We point it at home's own
# loopback echo (started by the chain entrypoint).
echo "[init-chain] writing home-chain predicate-publishing rule"
cat >/etc/yggdrasil-home/rules/home-tcp-echo.toml <<'EOF'
[[rule]]
name          = "home-tcp-echo"
listen        = "0.0.0.0:7200"
protocol      = "tcp"
target_addr   = "127.0.0.1:7100"
EOF

# ---- handshake 1: home-chain <-> midbox -----------------------------------

echo "[init-chain] home-chain exports request"
yggdrasilctl --config "$HOME_CFG" identity export-request \
    --identity-file "$HOME_KEY" \
    --out "$HOME_REQUEST" \
    --note "chain e2e home" >/dev/null

echo "[init-chain] midbox add-accept from home-chain (writes midbox's [accept])"
yggdrasilctl --config "$MIDBOX_CFG" identity add-accept \
    --identity-file "$MIDBOX_KEY" \
    --from "$HOME_REQUEST" \
    --my-endpoint midbox:51820 \
    --out "$HOME_GRANT" \
    --note "chain e2e midbox->home" >/dev/null

echo "[init-chain] home-chain add-dial from midbox grant"
yggdrasilctl --config "$HOME_CFG" identity add-dial \
    --identity-file "$HOME_KEY" \
    --from "$HOME_GRANT" >/dev/null

# ---- handshake 2: midbox <-> vps-chain -------------------------------------

echo "[init-chain] midbox exports request"
yggdrasilctl --config "$MIDBOX_CFG" identity export-request \
    --identity-file "$MIDBOX_KEY" \
    --out "$MIDBOX_REQUEST" \
    --note "chain e2e midbox" >/dev/null

echo "[init-chain] vps-chain add-accept from midbox (writes vps's [accept])"
yggdrasilctl --config "$VPS_CFG" identity add-accept \
    --identity-file "$VPS_KEY" \
    --from "$MIDBOX_REQUEST" \
    --my-endpoint vps-chain:51820 \
    --out "$MIDBOX_GRANT" \
    --note "chain e2e vps->midbox" >/dev/null

echo "[init-chain] midbox add-dial from vps-chain grant"
yggdrasilctl --config "$MIDBOX_CFG" identity add-dial \
    --identity-file "$MIDBOX_KEY" \
    --from "$MIDBOX_GRANT" >/dev/null

rm -f "$HOME_REQUEST" "$HOME_GRANT" "$MIDBOX_REQUEST" "$MIDBOX_GRANT"

echo "[init-chain] done"
