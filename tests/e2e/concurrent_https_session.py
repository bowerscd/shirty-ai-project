#!/usr/bin/env python3
"""Long-lived HTTPS keep-alive session for the cert-reload concurrent-flow test.

Drives N requests over a single HTTPS connection with keep-alive, sleeping
briefly between each. The runner triggers a cert hot-reload mid-stream; we
must complete all N requests without an error, proving that
`CertStore::reload_host` (per-hostname, in-memory cert swap) doesn't
disturb existing TLS sessions.

Distinction documented in `docs/configuration.md:520-524`:
  - `[[rule]]` (L4) changes — reconciled per-rule, in-flight TCP survives
  - `[[route]]` (HTTPS) changes — full stop+respawn of HTTPS frontend,
    in-flight HTTPS dies
  - cert PEM contents (this test) — CertStore::reload_host swaps the cert
    in-place; existing TLS sessions keep using their negotiated keys until
    they close

Writes one line per successful request to stdout (for debugging) and a
final `OK <n>` or `ERR <traceback>` summary line. Exits 0 on success.
Touches /tmp/hsess-<id>.done as a completion marker the runner polls.
"""

from __future__ import annotations

import argparse
import http.client
import ssl
import sys
import time
import traceback


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--sni", required=True, help="SNI hostname (also used for Host: header)")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument(
        "--ca",
        default="/etc/ssl/yggdrasil-test/server.pem",
        help="path to the trust anchor",
    )
    p.add_argument("--requests", type=int, default=30, help="number of requests on this session")
    p.add_argument(
        "--interval",
        type=float,
        default=0.5,
        help="seconds to sleep between requests",
    )
    p.add_argument(
        "--id",
        required=True,
        help="session id, used in the /tmp/hsess-<id>.done marker",
    )
    args = p.parse_args()

    done_marker = f"/tmp/hsess-{args.id}.done"

    try:
        ctx = ssl.create_default_context(cafile=args.ca)
        # ctx.check_hostname = True, ctx.verify_mode = CERT_REQUIRED are
        # the defaults; the cert-reload phase refreshes the trust anchor
        # before re-minting, so verification stays valid across the swap.

        conn = http.client.HTTPSConnection(
            args.sni, args.port, context=ctx, timeout=5
        )
        # Force connect now so the TLS handshake happens before any
        # mid-stream cert reload. The point of the test is that this
        # session — once established — survives a reload happening AFTER
        # the handshake.
        conn.connect()

        for i in range(args.requests):
            conn.request("GET", "/", headers={"Host": args.sni, "Connection": "keep-alive"})
            resp = conn.getresponse()
            body = resp.read()
            if resp.status != 200:
                print(f"ERR request {i}: status={resp.status}", flush=True)
                return _finish(done_marker, ok=False)
            time.sleep(args.interval)

        conn.close()
        print(f"OK {args.requests}", flush=True)
        return _finish(done_marker, ok=True)
    except Exception:  # noqa: BLE001
        print(f"ERR\n{traceback.format_exc()}", flush=True)
        return _finish(done_marker, ok=False)


def _finish(marker: str, *, ok: bool) -> int:
    try:
        open(marker, "w").close()
    except OSError:
        pass
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
