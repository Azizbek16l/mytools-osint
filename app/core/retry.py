"""Per-source retry policies and a single fetch helper.

Centralises the operational knowledge — "ThreatMiner 500 never recovers, don't
pound it; crt.sh is slow but reliable, retry once at 90s; subdomain.center
521-flaps, retry 3× with backoff" — into one table.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx

from app.core.classify import classify_exception, classify_http
from app.core.http import get_client
from app.core.types import HitStatus


@dataclass(frozen=True)
class RetryPolicy:
    attempts: int = 2
    timeout_s: float = 20.0
    backoff_s: float = 2.0
    # Statuses that justify a retry; all others fall through immediately.
    retry_on: tuple[int, ...] = field(default=(502, 503, 504, 521, 522, 524))


POLICIES: dict[str, RetryPolicy] = {
    "crt.sh":           RetryPolicy(attempts=2, timeout_s=90, backoff_s=5),
    "Certspotter":      RetryPolicy(attempts=2, timeout_s=25, backoff_s=2),
    "HackerTarget":     RetryPolicy(attempts=1, timeout_s=15, backoff_s=0),    # quota — no retry
    "AlienVault OTX":   RetryPolicy(attempts=2, timeout_s=25, backoff_s=2),
    "subdomain.center": RetryPolicy(attempts=3, timeout_s=20, backoff_s=2),    # 521-flap
    "RapidDNS":         RetryPolicy(attempts=2, timeout_s=25, backoff_s=3),
    "Wayback CDX":      RetryPolicy(attempts=2, timeout_s=40, backoff_s=5),
    "ThreatMiner":      RetryPolicy(attempts=1, timeout_s=15, backoff_s=0),    # 500 = dead
    # Defaults for any other source name
    "default":          RetryPolicy(),
}


async def fetch_with_policy(
    source: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
) -> tuple[httpx.Response | None, HitStatus, str]:
    """Fetch with the source's retry policy. Returns (response_or_None, status, detail)."""
    p = POLICIES.get(source, POLICIES["default"])
    client = await get_client()
    last_status = HitStatus.UNAVAILABLE
    last_detail = ""
    for attempt in range(p.attempts):
        try:
            r = await client.get(
                url, headers=headers, params=params,
                timeout=p.timeout_s, follow_redirects=True,
            )
            if r.status_code == 200:
                return r, HitStatus.FOUND, ""
            # Honor 429 Retry-After (capped) before treating it as terminal.
            if r.status_code == 429 and attempt < p.attempts - 1:
                ra = _retry_after_seconds(r)
                await asyncio.sleep(min(ra if ra is not None else p.backoff_s * (attempt + 1), 30.0))
                continue
            if r.status_code in p.retry_on and attempt < p.attempts - 1:
                await asyncio.sleep(p.backoff_s * (attempt + 1))
                continue
            return None, classify_http(r.status_code), f"HTTP {r.status_code}"
        except asyncio.CancelledError:
            raise  # never swallow cancellation — keeps Ctrl-C / shutdown responsive
        except Exception as e:
            last_status = classify_exception(e)
            last_detail = f"{type(e).__name__}: {e}"[:120]
            if attempt < p.attempts - 1:
                await asyncio.sleep(p.backoff_s * (attempt + 1))
    return None, last_status, last_detail


def _retry_after_seconds(r: httpx.Response) -> float | None:
    """Parse a Retry-After header (delta-seconds form). None if absent/unparseable."""
    raw = r.headers.get("retry-after", "").strip()
    return float(raw) if raw.isdigit() else None
