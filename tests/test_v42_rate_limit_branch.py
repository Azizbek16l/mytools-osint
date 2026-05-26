"""Lock-in regression: every v4.2 module's rate-limit branch must be reachable
without throwing AttributeError on HitStatus enum (typo guard)."""
import asyncio
from unittest.mock import AsyncMock, patch

from app.core.types import HitStatus, Query, QueryKind


def test_hitstatus_ratelimited_exists():
    """The canonical enum name (no underscore between RATE and LIMITED)."""
    assert HitStatus.RATELIMITED.value == "ratelimited"
    # Negative — the typo'd form does NOT exist.
    assert not hasattr(HitStatus, "RATE_LIMITED")


def _fake_response(status_code: int, body: str = "", content_type="text/plain"):
    class _R:
        def __init__(self):
            self.status_code = status_code
            self.text = body
            self.headers = {"content-type": content_type}
        def json(self):
            import json
            return json.loads(self.text)
    return _R()


def _collect(coro_gen):
    async def go():
        out = []
        async for h in coro_gen:
            out.append(h)
        return out
    return asyncio.run(go())


def test_hackertarget_quota_body_does_not_crash():
    """HackerTarget returns 200 with 'API count exceeded' body — must NOT raise."""
    with patch("app.modules.hackertarget.get_client", new=AsyncMock()) as m:
        client = AsyncMock()
        client.get = AsyncMock(return_value=_fake_response(
            200, body="error: API count exceeded\n"))
        m.return_value = client
        from app.modules.hackertarget import _run
        hits = _collect(_run(Query(value="example.com", kind=QueryKind.DOMAIN)))
    # Exactly one RATELIMITED hit, no crash.
    assert any(h.status == HitStatus.RATELIMITED for h in hits)


def test_certspotter_429_does_not_crash():
    """CertSpotter 429 path — must NOT raise."""
    with patch("app.modules.certspotter.get_client", new=AsyncMock()) as m:
        client = AsyncMock()
        client.get = AsyncMock(return_value=_fake_response(429))
        m.return_value = client
        from app.modules.certspotter import _run
        hits = _collect(_run(Query(value="example.com", kind=QueryKind.DOMAIN)))
    assert any(h.status == HitStatus.RATELIMITED for h in hits)
