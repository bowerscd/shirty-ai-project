#!/usr/bin/env bash
# chain-loopback-echo-entrypoint.sh — runs a loopback TCP echo backend
# alongside the yggdrasil daemon. Used by the 3-level chain compose stack
# for two nodes:
#
#   * home-chain: the echo on 127.0.0.1:$ECHO_TCP_PORT is the local backend
#     for home's terminal-mode rule (listen=:7200, upstream_addr=127.0.0.1:
#     7100). Without it, traffic that arrives at home via midbox's derived
#     listener would have nothing to forward to.
#
#   * vps-chain: the echo on 127.0.0.1:$ECHO_TCP_PORT is the destination of
#     the chain-tunnel test. The tunnel terminator on vps dials this
#     loopback address; the smoke driver sends bytes through the tunnel
#     from home and asserts they echo back.
#
# Loopback-only bind keeps the echo off the wan interface — only yggdrasil
# (proxy or tunnel terminator) on the same netns can reach it.
set -euo pipefail

ECHO_TCP_PORT="${ECHO_TCP_PORT:-7100}"

python3 /usr/local/bin/echo-server.py \
    --bind 127.0.0.1 \
    --tcp-port "$ECHO_TCP_PORT" \
    --udp-port "$ECHO_TCP_PORT" &
ECHO_PID=$!

shutdown() {
    kill -TERM "$ECHO_PID" 2>/dev/null || true
    kill -TERM "$YGG_PID"  2>/dev/null || true
    wait "$YGG_PID"  2>/dev/null || true
    wait "$ECHO_PID" 2>/dev/null || true
    exit 0
}
trap shutdown TERM INT

yggdrasil run --config /etc/yggdrasil/config.toml &
YGG_PID=$!
wait "$YGG_PID"
