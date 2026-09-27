#!/usr/bin/env python3
"""Probe a Talos GraphQL WebSocket past the HTTP upgrade (used by smoke.sh).

A `101 Switching Protocols` proves only that `/ws` reached the controller. The
controller refuses a disallowed `Origin` AFTER the upgrade, with an immediate
close frame, and a browser shows that as "WebSocket connection failed". This is
the failure CLAUDE.md records for a handler passing no Origin. A status-only
check passes it.

So the probe completes the upgrade with `Origin: <base URL>`, sends graphql-ws
`connection_init` with no session cookie, and reads the first server frame:

  auth-required   a `connection_error` text frame — the origin was accepted and
                  the socket reached authentication (the expected answer for a
                  cookieless probe)
  acked           `connection_ack` — accepted and authenticated
  closed          a close frame with no text first — the ORIGIN was refused
                  (or the handshake was refused before authentication)
  http <code>     the upgrade was answered with a non-101 status
  error <reason>  no answer, or a transport failure

Exit status: 0 for auth-required/acked, 1 otherwise. Standard library only.
"""

import base64
import json
import os
import socket
import ssl
import struct
import sys
from urllib.parse import urlsplit


def _read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed mid-frame")
        buf += chunk
    return buf


def _read_http_head(sock):
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("connection closed during the upgrade response")
        head += chunk
        if len(head) > 16384:
            raise ConnectionError("upgrade response head exceeds 16 KiB")
    return head.decode("latin-1")


def _masked_text_frame(text):
    payload = text.encode("utf-8")
    mask = os.urandom(4)
    length = len(payload)
    if length < 126:
        header = struct.pack("!BB", 0x81, 0x80 | length)
    elif length < 65536:
        header = struct.pack("!BBH", 0x81, 0x80 | 126, length)
    else:
        header = struct.pack("!BBQ", 0x81, 0x80 | 127, length)
    body = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return header + mask + body


def _read_frame(sock):
    first, second = _read_exact(sock, 2)
    opcode = first & 0x0F
    length = second & 0x7F
    if length == 126:
        (length,) = struct.unpack("!H", _read_exact(sock, 2))
    elif length == 127:
        (length,) = struct.unpack("!Q", _read_exact(sock, 8))
    if length > 1 << 20:
        raise ConnectionError("server frame exceeds 1 MiB")
    if second & 0x80:
        _read_exact(sock, 4)  # a server must not mask; tolerate and discard
    return opcode, _read_exact(sock, length)


def probe(base_url, timeout=5.0):
    parts = urlsplit(base_url)
    secure = parts.scheme == "https"
    host = parts.hostname
    port = parts.port or (443 if secure else 80)
    host_header = parts.netloc
    key = base64.b64encode(os.urandom(16)).decode()

    raw = socket.create_connection((host, port), timeout=timeout)
    sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host) if secure else raw
    try:
        sock.sendall(
            (
                "GET /ws HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Protocol: graphql-ws\r\n"
                f"Origin: {base_url.rstrip('/')}\r\n"
                "\r\n"
            ).encode("latin-1")
        )
        status_line = _read_http_head(sock).split("\r\n", 1)[0]
        code = status_line.split(" ")[1] if " " in status_line else "000"
        if code != "101":
            return f"http {code}"
        sock.sendall(_masked_text_frame(json.dumps({"type": "connection_init", "payload": {}})))
        while True:
            opcode, payload = _read_frame(sock)
            if opcode == 0x8:
                return "closed"
            if opcode == 0x1:
                kind = json.loads(payload.decode("utf-8")).get("type")
                if kind == "connection_error":
                    return "auth-required"
                if kind == "connection_ack":
                    return "acked"
                return f"error unexpected frame type {kind!r}"
            # ping/pong/continuation: keep reading
    except (OSError, ValueError, ConnectionError) as exc:
        return f"error {type(exc).__name__}: {exc}"
    finally:
        sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("usage: ws_probe.py <base-url>\n")
        sys.exit(2)
    verdict = probe(sys.argv[1])
    print(verdict)
    sys.exit(0 if verdict in ("auth-required", "acked") else 1)
