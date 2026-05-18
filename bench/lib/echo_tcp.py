#!/usr/bin/env python3
"""Minimal TCP echo for bench harness.

Each accepted connection is handled on its own thread; per-connection we just
shuttle bytes until EOF. Buffer size matches loadgen's request size for cheap
ping-pong tests.
"""
import socket
import sys
import threading


def serve(conn: socket.socket) -> None:
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        while True:
            data = conn.recv(65536)
            if not data:
                return
            conn.sendall(data)
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: echo_tcp.py <port>", file=sys.stderr)
        return 2
    port = int(sys.argv[1])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(4096)
    while True:
        conn, _addr = s.accept()
        t = threading.Thread(target=serve, args=(conn,), daemon=True)
        t.start()


if __name__ == "__main__":
    sys.exit(main())
