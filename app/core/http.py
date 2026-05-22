"""Shared async HTTP client. HTTP/2, connection pooling, randomised UA, retry on 5xx."""
from __future__ import annotations

import asyncio
import random
from typing import Any

import httpx
import ua_generator

from .config import settings

_client: httpx.AsyncClient | None = None
_lock = asyncio.Lock()


def _ua() -> str:
    try:
        return ua_generator.generate(device="desktop").text
    except Exception:
        return (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        )


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
        _client = httpx.AsyncClient(
            http2=True,
            limits=limits,
            timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": _ua(),
                "Accept-Language": "en-US,en;q=0.9",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Cache-Control": "no-cache",
            },
            verify=True,
        )
        return _client


async def close_client() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


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
