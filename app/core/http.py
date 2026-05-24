"""Shared async HTTP client. HTTP/2, connection pooling, randomised UA, retry on 5xx.

OPSEC mode (env `OSINT_OPSEC=1`):
  - routes all requests through SOCKS5 (default 127.0.0.1:9050)
  - adds 200-800ms random jitter before each request
  - rotates the User-Agent on every request (the static UA header is dropped
    and re-set per-call in the request() helper)
  - logs nothing externally (no DNS-leaking direct lookups — httpx + httpx-socks
    resolves DNS through the SOCKS proxy when scheme is socks5h://)
"""
from __future__ import annotations

import asyncio
import os
import random
from typing import Any

import httpx
import ua_generator

from .config import settings

_client: httpx.AsyncClient | None = None
_lock = asyncio.Lock()


def _opsec_on() -> bool:
    return os.getenv("OSINT_OPSEC", "").strip().lower() in {"1", "true", "yes", "on"}


def _ua() -> str:
    try:
        return ua_generator.generate(device="desktop").text
    except Exception:
        return (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        )


def _build_transport() -> httpx.AsyncBaseTransport | None:
    """Return a SOCKS-aware transport when OPSEC is on, else None (httpx default)."""
    if not _opsec_on():
        return None
    proxy = os.getenv("HTTPX_PROXY") or os.getenv("TOR_SOCKS") or "socks5://127.0.0.1:9050"
    # Force socks5h:// so DNS resolves through Tor — avoid leaks.
    if proxy.startswith("socks5://"):
        proxy = "socks5h://" + proxy[len("socks5://"):]
    try:
        # Prefer httpx-socks if installed; fall back to httpx's built-in proxy.
        from httpx_socks import AsyncProxyTransport
        return AsyncProxyTransport.from_url(proxy)
    except ImportError:
        # httpx 0.27+ supports proxy= directly on AsyncClient (HTTP CONNECT
        # for socks5 only via httpx-socks). If unavailable, fall back to env
        # so the user sees an error rather than a silent leak.
        os.environ["HTTPS_PROXY"] = proxy
        os.environ["HTTP_PROXY"] = proxy
        return None


async def get_client() -> httpx.AsyncClient:
    """Singleton client. Reuses connections across module lookups."""
    global _client
    if _client is not None and not _client.is_closed:
        return _client
    async with _lock:
        if _client is not None and not _client.is_closed:
            return _client
        s = settings()
        limits = httpx.Limits(
            max_connections=max(64, s.http_concurrency * 2),
            max_keepalive_connections=max(32, s.http_concurrency),
        )
        timeout = httpx.Timeout(s.http_timeout_sec, connect=min(5.0, s.http_timeout_sec))
        transport = _build_transport()
        kwargs: dict[str, Any] = {
            "http2": True,
            "limits": limits,
            "timeout": timeout,
            "follow_redirects": True,
            "headers": {
                "User-Agent": _ua(),
                "Accept-Language": "en-US,en;q=0.9",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Cache-Control": "no-cache",
            },
            "verify": True,
        }
        if transport is not None:
            kwargs["transport"] = transport
        _client = httpx.AsyncClient(**kwargs)
        return _client


async def close_client() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


async def _opsec_jitter() -> None:
    if _opsec_on():
        await asyncio.sleep(random.uniform(0.2, 0.8))


async def request(
    method: str,
    url: str,
    *,
    retries: int = 1,
    backoff: float = 0.4,
    **kwargs: Any,
) -> httpx.Response | None:
    """One-shot request with light retry. Returns None on terminal failure."""
    client = await get_client()
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        await _opsec_jitter()
        # In OPSEC mode, rotate UA per request.
        if _opsec_on():
            headers = dict(kwargs.get("headers") or {})
            headers["User-Agent"] = _ua()
            kwargs["headers"] = headers
        try:
            resp = await client.request(method, url, **kwargs)
            if resp.status_code >= 500 and attempt < retries:
                await asyncio.sleep(backoff * (2**attempt) + random.uniform(0, 0.2))
                continue
            return resp
        except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError) as e:
            last_exc = e
            if attempt < retries:
                await asyncio.sleep(backoff * (2**attempt) + random.uniform(0, 0.2))
                continue
            return None
        except Exception as e:  # pragma: no cover
            last_exc = e
            return None
    if last_exc:
        return None
    return None


async def get(url: str, **kwargs: Any) -> httpx.Response | None:
    return await request("GET", url, **kwargs)


async def head(url: str, **kwargs: Any) -> httpx.Response | None:
    return await request("HEAD", url, **kwargs)
