#!/usr/bin/env bash
# chain-loopback-echo-entrypoint.sh — runs a loopback TCP echo backend
# alongside the yggdrasil daemon. Used by the 3-level chain compose stack
# for two nodes:
#
#   * home-chain: the echo on 127.0.0.1:$ECHO_TCP_PORT is the local backend
#     for home's terminal-mode rule (listen=:7200, target_addr=127.0.0.1:
#     7100). Without it, traffic that arrives at home via midbox's derived
#     listener would have nothing to forward to.
#
#   * vps-chain: the echo on 127.0.0.1:$ECHO_TCP_PORT is a residual
#     loopback backend kept alongside the daemon. The chain wire no
#     longer carries tunnel frames, so nothing currently dials it; it
#     remains as a harmless sidecar to keep the entrypoint shared with
#     home-chain. The chain stack now exercises only predicate-flow and
#     `chain diff` (see tests/e2e/run-chain.sh).
#
# Loopback-only bind keeps the echo off the wan interface — only the
# yggdrasil proxy on the same netns can reach it.
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
