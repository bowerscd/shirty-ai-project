#!/usr/bin/env python3
"""HTTP/3 probe for the h3 SNI dispatch + body-limit e2e phases.

Uses aioquic to send a single HTTP/3 request over QUIC and emit the
response shape the runner expects (JSON `{status, body, fp}`) — the
same shape the existing inline h1 probe emits, so phase assertions
work over both transports without two assertion variants.

Pinning the cert via aioquic's `cafile` mirrors the h1 probe's
`ctx.load_verify_locations(cafile=...)`. Hostname verification is
on by default (`QuicConfiguration.verify_mode = CERT_REQUIRED`).

Usage examples
--------------

    # GET to the gateway's v4 address (default), SNI=app.test.local:
    python3 h3_probe.py --sni app.test.local

    # POST with a body of N bytes:
    python3 h3_probe.py --sni app.test.local --method POST --body-bytes 2048

    # Override the gateway address (e.g. for the chain harness):
    python3 h3_probe.py --sni app.test.local --host 172.31.10.20

Exit codes
----------

* 0 — handshake + request completed; status / body / fp written to
  stdout as JSON. Caller decides whether the status is a pass.
* 1 — any failure before a complete response: TLS handshake reject,
  QUIC timeout, ALPN mismatch, etc. A short error line goes to stderr.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import ssl
import sys
import traceback
from typing import List, Optional

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent


class _H3Client(QuicConnectionProtocol):
    """Minimal HTTP/3 client that fires one request and signals
    completion via an asyncio.Event when the response stream ends.

    Body chunks and headers are accumulated on the instance for the
    caller to read after `done` fires.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h3: Optional[H3Connection] = None
        self.done = asyncio.Event()
        self.received_headers: List[tuple] = []
        self.received_body = bytearray()

    def attach_h3(self) -> None:
        """Construct the HTTP/3 layer over the live QUIC connection.

        Called by the driver after `wait_connected()` resolves — at
        that point the TLS handshake is complete and the QuicConnection
        is ready to multiplex streams.
        """
        self._h3 = H3Connection(self._quic)

    def quic_event_received(self, event: QuicEvent) -> None:
        # Don't call super(): the base class's stream_reader bookkeeping
        # is for raw QUIC stream use (asyncio.StreamReader / Writer
        # patterns) and is unneeded when we drive an H3 layer ourselves.
        # See aioquic's examples/http3_client.py for the same pattern.
        if self._h3 is None:
            return
        for h3_event in self._h3.handle_event(event):
            if isinstance(h3_event, HeadersReceived):
                self.received_headers.extend(h3_event.headers)
                if h3_event.stream_ended:
                    self.done.set()
            elif isinstance(h3_event, DataReceived):
                self.received_body.extend(h3_event.data)
                if h3_event.stream_ended:
                    self.done.set()
        # Content-length fallback: aioquic <-> h3-rs interop quirk on
        # the FIRST stream of an h3 connection. h3-rs's
        # `RequestStream::finish()` sends a per-connection GREASE
        # frame (RFC 9114 §7.2.8) between the response body and the
        # QUIC FIN — once-per-connection, only on the first stream.
        # aioquic's H3 layer handles GREASE silently (no event
        # emitted), and because end_stream is attached to the LAST
        # carried frame, the FIN ends up on the silent GREASE frame
        # rather than the DataReceived event. Wire-level trace
        # confirms QUIC StreamDataReceived has end_stream=True but
        # the DataReceived loses it. Second + subsequent requests on
        # the same connection don't trigger the bug (no more
        # GREASE). Verified against yggdrasil's h3 frontend with
        # h3=0.0.8 / h3-quinn=0.0.10 / aioquic=1.x; see finding
        # `h3-fin-flush-delay` for the full trace.
        #
        # Workaround: complete when we've received the full body
        # declared by `content-length`. The `stream_ended=True`
        # path remains the preferred completion signal when the
        # server flushes FIN visibly (e.g. via h3 clients that
        # handle GREASE differently).
        cl = self._content_length_header()
        if cl is not None and len(self.received_body) >= cl:
            self.done.set()

    def _content_length_header(self) -> Optional[int]:
        for name, value in self.received_headers:
            if name == b"content-length":
                try:
                    return int(value.decode())
                except (UnicodeDecodeError, ValueError):
                    return None
        return None

    def send_request(
        self,
        sni: str,
        method: str,
        path: str,
        body: bytes,
    ) -> None:
        assert self._h3 is not None, "attach_h3() must be called first"
        stream_id = self._quic.get_next_available_stream_id()
        headers = [
            (b":method", method.encode()),
            (b":scheme", b"https"),
            (b":authority", sni.encode()),
            (b":path", path.encode()),
            (b"user-agent", b"yggdrasil-e2e-h3-probe/1"),
        ]
        if body:
            headers.append((b"content-length", str(len(body)).encode()))
            headers.append((b"content-type", b"application/octet-stream"))
        self._h3.send_headers(stream_id, headers, end_stream=not body)
        if body:
            self._h3.send_data(stream_id, body, end_stream=True)
        self.transmit()


def _leaf_fingerprint(proto: _H3Client) -> str:
    """Best-effort sha256 of the peer's leaf cert in DER form.

    aioquic verifies the cert chain itself before `wait_connected`
    resolves; this fingerprint is just for the runner's compare-leaf
    assertion (parity with the h1 probe). Returns empty string if
    we can't reach into the internals.
    """
    try:
        leaf = proto._quic.tls._peer_certificate  # noqa: SLF001
    except AttributeError:
        return ""
    if leaf is None:
        return ""
    try:
        from cryptography.hazmat.primitives.serialization import Encoding

        leaf_der = leaf.public_bytes(encoding=Encoding.DER)
        return hashlib.sha256(leaf_der).hexdigest()
    except Exception:  # noqa: BLE001
        return ""


async def _run(args: argparse.Namespace) -> int:
    cfg = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        verify_mode=ssl.CERT_REQUIRED,
        server_name=args.sni,
    )
    cfg.load_verify_locations(cafile=args.ca)

    if args.body_bytes is not None:
        body = b"x" * args.body_bytes
    elif args.body is not None:
        body = args.body.encode("utf-8")
    else:
        body = b""

    async with connect(
        args.host,
        args.port,
        configuration=cfg,
        create_protocol=_H3Client,
        wait_connected=True,
    ) as proto:
        assert isinstance(proto, _H3Client)
        proto.attach_h3()
        proto.send_request(args.sni, args.method, args.path, body)

        try:
            await asyncio.wait_for(proto.done.wait(), timeout=args.timeout)
        except asyncio.TimeoutError:
            raise asyncio.TimeoutError(
                f"h3 probe deadline exceeded after {args.timeout}s"
            ) from None

        fp = _leaf_fingerprint(proto)

    status = 0
    for name, value in proto.received_headers:
        if name == b":status":
            status = int(value.decode())
            break

    print(
        json.dumps(
            {
                "status": status,
                "body": proto.received_body.decode("utf-8", errors="replace"),
                "fp": fp,
            }
        )
    )
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--sni", required=True, help="TLS SNI + HTTP :authority")
    p.add_argument("--host", default="172.31.0.20", help="literal IP to dial")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--method", default="GET")
    p.add_argument("--path", default="/")
    p.add_argument("--body", default=None, help="explicit utf-8 body")
    p.add_argument(
        "--body-bytes",
        type=int,
        default=None,
        help="auto-generate body of N bytes (mutually exclusive with --body)",
    )
    p.add_argument(
        "--ca",
        default="/etc/ssl/yggdrasil-test/server.pem",
        help="trust anchor PEM",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="overall wall clock budget for the request",
    )
    args = p.parse_args()

    if args.body is not None and args.body_bytes is not None:
        print("--body and --body-bytes are mutually exclusive", file=sys.stderr)
        return 2

    try:
        return asyncio.run(_run(args))
    except Exception as e:  # noqa: BLE001
        print(f"h3 probe failed: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
