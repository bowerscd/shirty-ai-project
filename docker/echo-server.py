#!/usr/bin/env python3
"""Minimal TCP + UDP echo server used as the upstream behind huginn.

Listens on two configurable ports (defaults: TCP 7100, UDP 7101) bound to
0.0.0.0. Per connection, echoes back whatever bytes arrive until the peer
half-closes (TCP) or for the lifetime of the process (UDP).

Kept dependency-free so it runs against the python stdlib that ships with
debian-slim — no pip install step required.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import threading


def serve_tcp(bind: str, port: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, port))
    s.listen(64)
    print(f"[echo] tcp listening on {bind}:{port}", flush=True)

    def handle(conn: socket.socket, addr: tuple[str, int]) -> None:
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    return
                conn.sendall(data)
        except OSError:
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


def serve_udp(bind: str, port: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, port))
    print(f"[echo] udp listening on {bind}:{port}", flush=True)

    while True:
        data, peer = s.recvfrom(65536)
        s.sendto(data, peer)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--tcp-port", type=int, default=int(os.environ.get("ECHO_TCP_PORT", "7100")))
    p.add_argument("--udp-port", type=int, default=int(os.environ.get("ECHO_UDP_PORT", "7101")))
    args = p.parse_args()

    threading.Thread(target=serve_tcp, args=(args.bind, args.tcp_port), daemon=True).start()
    serve_udp(args.bind, args.udp_port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
