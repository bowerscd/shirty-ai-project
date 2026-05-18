#!/usr/bin/env python3
"""Minimal UDP echo for bench harness.

Echoes every datagram on 127.0.0.1:<port> straight back to the sender.
Single-threaded blocking recvfrom/sendto loop — good enough for sub-saturating
loadgen, and noted in bench/README.md as a known bottleneck for true line-rate
testing (swap in a Rust echo if you need >200k pps).
"""
import socket
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: echo_udp.py <port>", file=sys.stderr)
        return 2
    port = int(sys.argv[1])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    # Larger socket buffer helps when bursts exceed the kernel default.
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    except OSError:
        pass
    while True:
        data, addr = s.recvfrom(2048)
        s.sendto(data, addr)


if __name__ == "__main__":
    sys.exit(main())
