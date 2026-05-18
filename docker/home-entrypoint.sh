#!/usr/bin/env bash
# home-entrypoint.sh — runs the python echo backend in the background and
# huginn in the foreground. They must share a network namespace because
# yggdrasil dials peer_ip:upstream_port, where peer_ip is the source of
# huginn's heartbeats and upstream_port is whatever the rule says — so
# the upstream service must be listening on huginn's IP.
set -euo pipefail

python3 /usr/local/bin/echo-server.py &
ECHO_PID=$!

# Tiny HTTP backend used by the L7 (HTTPS) e2e test. Always replies "OK\n"
# at 200, regardless of method or path, so SNI-routed requests through the
# yggdrasil HTTPS frontend land somewhere deterministic.
HTTP_PORT="${HOME_HTTP_PORT:-7180}"
python3 - "$HTTP_PORT" <<'PY' &
import http.server, socketserver, sys, threading
PORT = int(sys.argv[1])
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"OK\n"
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_a, **_kw):
        return
class TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
with TS(("0.0.0.0", PORT), H) as srv:
    print(f"[http-backend] listening on 0.0.0.0:{PORT}", flush=True)
    srv.serve_forever()
PY
HTTP_PID=$!

# Forward SIGTERM/SIGINT to both processes so `podman compose down` is clean.
shutdown() {
    kill -TERM "$ECHO_PID" 2>/dev/null || true
    kill -TERM "$HTTP_PID" 2>/dev/null || true
    kill -TERM "$RAT_PID"  2>/dev/null || true
    wait "$RAT_PID"  2>/dev/null || true
    wait "$ECHO_PID" 2>/dev/null || true
    wait "$HTTP_PID" 2>/dev/null || true
    exit 0
}
trap shutdown TERM INT

exec huginn run --config /etc/huginn/config.toml &
RAT_PID=$!
wait "$RAT_PID"
