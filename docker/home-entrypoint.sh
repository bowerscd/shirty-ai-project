#!/usr/bin/env bash
# home-entrypoint.sh — runs the python echo backend in the background and
# ratatoskr in the foreground. They must share a network namespace because
# yggdrasil dials peer_ip:upstream_port, where peer_ip is the source of
# ratatoskr's heartbeats and upstream_port is whatever the rule says — so
# the upstream service must be listening on ratatoskr's IP.
set -euo pipefail

python3 /usr/local/bin/echo-server.py &
ECHO_PID=$!

# Forward SIGTERM/SIGINT to both processes so `podman compose down` is clean.
shutdown() {
    kill -TERM "$ECHO_PID" 2>/dev/null || true
    kill -TERM "$RAT_PID"  2>/dev/null || true
    wait "$RAT_PID"  2>/dev/null || true
    wait "$ECHO_PID" 2>/dev/null || true
    exit 0
}
trap shutdown TERM INT

exec ratatoskr run --config /etc/ratatoskr/config.toml &
RAT_PID=$!
wait "$RAT_PID"
