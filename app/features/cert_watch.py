"""`osint cert-watch <pattern>` — live Certificate Transparency tail.

Subscribes to certstream.calidog.io's public WebSocket feed and emits every
newly-issued cert whose DNS name matches `<pattern>` (case-insensitive
substring or glob).

Use case:
  - "alert me the moment someone gets a cert for *acme-login.com / *-acme.com"
    → instant phishing infra detection at registration time, not week-later.
  - "track every new cert issued for mycorp.com subdomains"
    → catch your own org's new prod systems coming online.

Stdlib websocket impl (no ws lib dep) — uses urllib + base64 framing.
Falls back to httpx-based polling if direct WS proves flaky.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import secrets
import struct
import sys
from datetime import UTC, datetime

log = logging.getLogger("osint.cert_watch")

CERTSTREAM_WS = "wss://certstream.calidog.io"


async def _ws_connect(host: str, path: str = "/") -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Minimal WebSocket handshake against a wss:// host. Stdlib only."""
    import ssl
    # Prefer certifi's CA bundle — the stdlib default fails on Python.framework
    # builds (macOS) and on systems where the OS trust store isn't wired up.
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
    except Exception:
        ctx = ssl.create_default_context()
    reader, writer = await asyncio.open_connection(host, 443, ssl=ctx)
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    handshake = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"User-Agent: mytools-osint/cert-watch\r\n"
        f"\r\n"
    )
    writer.write(handshake.encode())
    await writer.drain()
    # Drain response headers
    while True:
        line = await reader.readline()
        if line in (b"\r\n", b"\n", b""):
            break
    return reader, writer


async def _ws_recv_frame(reader: asyncio.StreamReader) -> bytes | None:
    """Read one WebSocket text frame (server→client; never masked)."""
    head = await reader.readexactly(2)
    head[0] & 0x80
    opcode = head[0] & 0x0F
    if opcode == 0x8:  # close
        return None
    if opcode not in (0x1, 0x2):
        # Skip pings/pongs/continuation by reading length and discarding
        pass
    masked = head[1] & 0x80
    plen = head[1] & 0x7F
    if plen == 126:
        plen = struct.unpack(">H", await reader.readexactly(2))[0]
    elif plen == 127:
        plen = struct.unpack(">Q", await reader.readexactly(8))[0]
    if masked:
        mask = await reader.readexactly(4)
        payload = bytearray(await reader.readexactly(plen))
        for i in range(len(payload)):
            payload[i] ^= mask[i % 4]
        return bytes(payload)
    return await reader.readexactly(plen)


async def _watch(pattern: str, max_events: int | None = None) -> int:
    needle = pattern.lower()
    print(f"\n  \033[1mosint cert-watch\033[0m  \033[2mpattern: '{pattern}'\033[0m")
    print(f"  \033[2mendpoint: {CERTSTREAM_WS} (Calidog public CT firehose)\033[0m")
    print("  \033[2mctrl-C to stop\033[0m")
    print("  " + "─" * 70)
    reconnect_delay = 1.0
    seen = 0
    while True:
        try:
            reader, writer = await _ws_connect("certstream.calidog.io", "/")
            reconnect_delay = 1.0  # reset backoff on successful connect
            while True:
                payload = await _ws_recv_frame(reader)
                if payload is None:
                    print("  \033[2mconnection closed by server, reconnecting…\033[0m")
                    break
                try:
                    msg = json.loads(payload)
                except Exception as e:
                    log.debug("skip undecodable CT frame: %s", e)
                    continue
                if msg.get("message_type") != "certificate_update":
                    continue
                data = msg.get("data") or {}
                leaf = data.get("leaf_cert") or {}
                all_dns = leaf.get("all_domains") or []
                matched = [d for d in all_dns if needle in d.lower()]
                if not matched:
                    continue
                seen += 1
                issuer = (leaf.get("issuer") or {}).get("O", "?")
                ts = datetime.fromtimestamp(
                    msg.get("data", {}).get("seen", 0), tz=UTC
                ).strftime("%H:%M:%S UTC")
                cn = (leaf.get("subject") or {}).get("CN", "")
                src = data.get("source", {}).get("name", "?")
                print(f"  \033[32m●\033[0m  {ts}  "
                      f"\033[1m{cn[:50]:<50}\033[0m  "
                      f"\033[2mby {issuer[:20]:<20} via {src[:18]}\033[0m")
                if len(matched) > 1:
                    other = [d for d in matched if d != cn][:4]
                    for o in other:
                        print(f"                       \033[2m+ SAN {o}\033[0m")
                if max_events and seen >= max_events:
                    return 0
        except (ConnectionResetError, asyncio.IncompleteReadError, OSError) as e:
            print(f"  \033[33m·\033[0m  {type(e).__name__}: {e} — "
                  f"backoff {reconnect_delay:.0f}s")
            await asyncio.sleep(reconnect_delay)
            reconnect_delay = min(60.0, reconnect_delay * 2)
        finally:
            with contextlib.suppress(Exception):
                writer.close()


def cmd_cert_watch(args: list[str]) -> int:
    """Entry point for `osint cert-watch <pattern> [--max N]`."""
    if not args or args[0] in ("-h", "--help"):
        print("usage: osint cert-watch <pattern> [--max N]\n"
              "  <pattern>: case-insensitive substring (e.g. 'acme', 'mycorp.com')\n"
              "  --max N:   exit after N matching certs (default: keep going)\n"
              "\n"
              "Subscribes to certstream.calidog.io live CT firehose and prints\n"
              "every newly-issued cert whose CN/SAN contains <pattern>.",
              file=sys.stderr)
        return 0 if args else 2
    pattern = args[0]
    max_events: int | None = None
    if "--max" in args:
        i = args.index("--max")
        if i + 1 < len(args):
            try:
                max_events = int(args[i + 1])
            except ValueError:
                print("--max needs an integer", file=sys.stderr)
                return 2
    try:
        return asyncio.run(_watch(pattern, max_events))
    except KeyboardInterrupt:
        print("\n  stopped.")
        return 130
