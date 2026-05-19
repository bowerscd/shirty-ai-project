#!/usr/bin/env bash
# home-entrypoint.sh — runs the python echo backends in the background and
# the yggdrasil terminal-mode daemon in the foreground. They must share a
# network namespace because the upstream relay (vps) dials
# downstream_ip:upstream_port, where downstream_ip is the source of this
# node's heartbeats and upstream_port is whatever the relay's rule says —
# so the echo backends must be listening on this container's IP.
set -euo pipefail

python3 /usr/local/bin/echo-server.py &
ECHO_PID=$!

# Tiny HTTP backend used by the L7 (HTTPS) e2e test. Always replies "OK\n"
# at 200, regardless of method or path, so SNI-routed requests through the
# yggdrasil HTTPS frontend land somewhere deterministic.
HTTP_PORT="${HOME_HTTP_PORT:-7180}"
python3 - "$HTTP_PORT" <<'PY' &
import http.server, socketserver, sys
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

# Forward SIGTERM/SIGINT to all children so `podman compose down` is clean.
shutdown() {
    kill -TERM "$ECHO_PID" 2>/dev/null || true
    kill -TERM "$HTTP_PID" 2>/dev/null || true
    kill -TERM "$YGG_PID"  2>/dev/null || true
    wait "$YGG_PID"  2>/dev/null || true
    wait "$ECHO_PID" 2>/dev/null || true
    wait "$HTTP_PID" 2>/dev/null || true
    exit 0
}
trap shutdown TERM INT

# Run yggdrasil in terminal mode with [chain.upstream] pointing at vps.
# The config + identity were provisioned by the init container.
yggdrasil run --config /etc/yggdrasil/config.toml &
YGG_PID=$!
wait "$YGG_PID"
