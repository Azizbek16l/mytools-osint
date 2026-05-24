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


class _CacheTransport(httpx.AsyncBaseTransport):
    """Wrap a base transport with the SQLite cache.

    GET responses inside the cache TTL skip the wire entirely; everything else
    passes through. Errors in the cache layer never block the real request.
    """

    def __init__(self, inner: httpx.AsyncBaseTransport):
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        # Local import to avoid circular at module load
        from app.core import cache as _cache
        url = str(request.url)
        if request.method == "GET" and _cache.is_enabled():
            try:
                cached = await _cache.get("GET", url)
            except Exception:
                cached = None
            if cached is not None:
                return httpx.Response(
                    status_code=cached["status"],
                    headers=cached["headers"],
                    content=cached["body"],
                    request=request,
                )
        resp = await self._inner.handle_async_request(request)
        if request.method == "GET" and 200 <= resp.status_code < 400 and _cache.is_enabled():
            try:
                # Read body so we can cache it; httpx caches on the response.
                await resp.aread()
                await _cache.put("GET", url, resp.status_code,
                                 dict(resp.headers), resp.content)
            except Exception:
                pass
        return resp

    async def aclose(self) -> None:
        await self._inner.aclose()


def _build_transport() -> httpx.AsyncBaseTransport | None:
    """Return a transport stack: optional SOCKS + optional cache wrapper."""
    # Start with the SOCKS-aware transport when OPSEC is on, else the default
    # HTTP transport. Then wrap with cache when OSINT_CACHE is on.
    base: httpx.AsyncBaseTransport | None = None
    if _opsec_on():
        proxy = os.getenv("HTTPX_PROXY") or os.getenv("TOR_SOCKS") or "socks5://127.0.0.1:9050"
        if proxy.startswith("socks5://"):
            proxy = "socks5h://" + proxy[len("socks5://"):]
        try:
            from httpx_socks import AsyncProxyTransport
            base = AsyncProxyTransport.from_url(proxy)
        except ImportError:
            os.environ["HTTPS_PROXY"] = proxy
            os.environ["HTTP_PROXY"] = proxy
    # Wrap base with cache transport if OSINT_CACHE is on.
    from app.core import cache as _cache
    if _cache.is_enabled():
        if base is None:
            base = httpx.AsyncHTTPTransport(http2=True)
        return _CacheTransport(base)
    return base


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
    """One-shot request with light retry. Returns None on terminal failure.

    GET requests are served from the SQLite HTTP cache when OSINT_CACHE=1.
    """
    # Cache lookup (GET only, when enabled)
    if method.upper() == "GET":
        try:
            from app.core import cache as _cache
            if _cache.is_enabled():
                cached = await _cache.get(method, url)
                if cached is not None:
                    return httpx.Response(
                        status_code=cached["status"],
                        headers=cached["headers"],
                        content=cached["body"],
                        request=httpx.Request(method, url),
                    )
        except Exception:
            pass

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
            # Cache successful GET responses
            if method.upper() == "GET" and 200 <= resp.status_code < 400:
                try:
                    from app.core import cache as _cache
                    if _cache.is_enabled():
                        await _cache.put(method, url, resp.status_code,
                                         dict(resp.headers), resp.content)
                except Exception:
                    pass
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
