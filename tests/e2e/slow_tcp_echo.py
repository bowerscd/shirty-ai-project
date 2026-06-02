#!/usr/bin/env python3
"""Slow-drip TCP echo client for the graceful_drain_timeout test.

Connects to a TCP server, sends `--bytes` bytes one at a time with a
`--interval` second pause between each, then reads them all back. The
slow drip ensures the connection is in-flight when the runner SIGTERMs
the daemon; we expect the daemon's graceful_drain_timeout to keep the
connection alive long enough to complete.

On success, prints `OK <bytes-received>` and touches /tmp/slow-tcp.done.
On failure, prints `ERR <traceback>` and still touches the done marker
so the runner doesn't block.
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
import traceback


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument(
        "--bytes",
        type=int,
        default=7,
        help="number of bytes to send (one per --interval)",
    )
    p.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="seconds between bytes",
    )
    p.add_argument(
        "--done-marker",
        default="/tmp/slow-tcp.done",
        help="path to touch when finished (success or failure)",
    )
    args = p.parse_args()

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(args.bytes * args.interval + 15.0)
        s.connect((args.host, args.port))

        sent = b""
        for i in range(args.bytes):
            payload = bytes([0x30 + (i % 10)])  # ASCII digit, easy to eyeball
            s.sendall(payload)
            sent += payload
            time.sleep(args.interval)

        # Half-close our write side so the echo server knows to close
        # back. Read everything until EOF.
        s.shutdown(socket.SHUT_WR)
        recv = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            recv += chunk
        s.close()

        if recv == sent:
            print(f"OK {len(recv)}", flush=True)
            _touch(args.done_marker)
            return 0
        print(f"ERR mismatch: sent={sent!r} recv={recv!r}", flush=True)
        _touch(args.done_marker)
        return 1
    except Exception:  # noqa: BLE001
        print(f"ERR\n{traceback.format_exc()}", flush=True)
        _touch(args.done_marker)
        return 1


def _touch(path: str) -> None:
    try:
        open(path, "w").close()
    except OSError:
        pass


if __name__ == "__main__":
    sys.exit(main())
