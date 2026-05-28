"""Core async engine tests — runner dispatch, retry policy, and HTTP cache.

Hermetic: no network, no real sleeps. `asyncio.sleep` is monkeypatched to a
no-op in the retry tests so backoff is instant; the cache TTL tests drive a
fake `time.time()` clock so expiry is deterministic and zero-wait.

`asyncio_mode = auto` (pytest.ini) — `async def test_...` runs without a marker.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import httpx
import pytest

from app.core import cache as cache_mod
from app.core import retry as retry_mod
from app.core.retry import RetryPolicy, fetch_with_policy
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind

from .factories import make_hit, make_query

# --------------------------------------------------------------------------- #
# helpers                                                                      #
# --------------------------------------------------------------------------- #

def _patch_client(monkeypatch, handler, *targets: str) -> httpx.AsyncClient:
    """Install a MockTransport-backed client behind get_client.

    Modules import `get_client` into their own namespace at import time, so we
    patch every consumer namespace, not just `app.core.http`.
    """
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)

    async def _fake_get_client() -> httpx.AsyncClient:
        return client

    monkeypatch.setattr("app.core.http.get_client", _fake_get_client)
    for tgt in targets:
        monkeypatch.setattr(tgt, _fake_get_client)
    return client


# --------------------------------------------------------------------------- #
# Runner                                                                       #
# --------------------------------------------------------------------------- #

class TestRunner:
    async def test_raising_module_does_not_kill_the_run(self) -> None:
        """A module that raises is converted to one ERROR hit; siblings still arrive."""
        r = Runner()

        async def good(_q: Query) -> AsyncIterator[Hit]:
            yield make_hit(module="good", status=HitStatus.FOUND, detail="alive")

        async def boom(_q: Query) -> AsyncIterator[Hit]:
            raise RuntimeError("kaboom")
            yield  # pragma: no cover — generator marker

        r.register("good", [QueryKind.DOMAIN], good)
        r.register("boom", [QueryKind.DOMAIN], boom)

        result = await r.run(make_query("acme.com"))

        by_mod = {h.module: h for h in result.hits}
        # sibling survived
        assert by_mod["good"].status == HitStatus.FOUND
        assert by_mod["good"].detail == "alive"
        # the raiser is surfaced as a structured ERROR hit, not a crash
        assert by_mod["boom"].status == HitStatus.ERROR
        assert "RuntimeError" in by_mod["boom"].detail
        assert "kaboom" in by_mod["boom"].detail

    async def test_results_aggregate_across_modules(self) -> None:
        """Hits from every matching module land in one QueryResult; counters add up."""
        r = Runner()

        async def m_a(_q: Query) -> AsyncIterator[Hit]:
            yield make_hit(module="a", source="a1", status=HitStatus.FOUND)
            yield make_hit(module="a", source="a2", status=HitStatus.NOT_FOUND)

        async def m_b(_q: Query) -> AsyncIterator[Hit]:
            yield make_hit(module="b", source="b1", status=HitStatus.FOUND)

        r.register("a", [QueryKind.DOMAIN], m_a)
        r.register("b", [QueryKind.DOMAIN], m_b)

        result = await r.run(make_query("acme.com"))

        assert result.total == 3
        assert result.found == 2  # two FOUND hits
        assert {h.source for h in result.hits} == {"a1", "a2", "b1"}
        # on_hit callback fires for every hit as it streams
        seen: list[str] = []

        async def on_hit(h: Hit) -> None:
            seen.append(h.source)

        result2 = await r.run(make_query("acme.com"), on_hit=on_hit)
        assert sorted(seen) == ["a1", "a2", "b1"]
        assert result2.total == 3

    async def test_no_matching_modules_returns_empty(self) -> None:
        r = Runner()

        async def only_email(_q: Query) -> AsyncIterator[Hit]:
            yield make_hit(module="email")

        r.register("email", [QueryKind.EMAIL], only_email)
        result = await r.run(make_query("1.2.3.4", kind=QueryKind.IP))
        assert result.hits == []
        assert result.total == 0

    async def test_self_bounded_module_completes_while_siblings_aggregate(self) -> None:
        """A module that bounds its own slow work with a per-module timeout must not
        stall the run; the fast sibling's hit still aggregates and the whole run
        finishes well inside a tight wall-clock budget.

        This is the contract that lives at the module layer (the Runner itself
        applies no timeout): each producer is responsible for bounding its I/O,
        exactly as the real modules do via httpx `timeout=` / dns `lifetime=`.
        """
        r = Runner()

        async def slow_but_self_bounded(_q: Query) -> AsyncIterator[Hit]:
            try:
                # inner work would hang forever; the module bounds it itself
                await asyncio.wait_for(asyncio.Event().wait(), timeout=0.05)
            except TimeoutError:
                yield make_hit(
                    module="slow", source="slow",
                    status=HitStatus.UNAVAILABLE, detail="self-timeout",
                )

        async def fast(_q: Query) -> AsyncIterator[Hit]:
            yield make_hit(module="fast", source="fast", status=HitStatus.FOUND)

        r.register("slow", [QueryKind.DOMAIN], slow_but_self_bounded)
        r.register("fast", [QueryKind.DOMAIN], fast)

        # Hard external ceiling: if a hang leaked through, this would raise.
        result = await asyncio.wait_for(r.run(make_query("acme.com")), timeout=1.0)

        by_mod = {h.module: h for h in result.hits}
        assert by_mod["fast"].status == HitStatus.FOUND
        assert by_mod["slow"].status == HitStatus.UNAVAILABLE
        assert by_mod["slow"].detail == "self-timeout"
        assert result.duration_ms < 1000


# --------------------------------------------------------------------------- #
# Retry policy                                                                 #
# --------------------------------------------------------------------------- #

class TestRetry:
    @pytest.fixture(autouse=True)
    def _no_sleep(self, monkeypatch):
        """Never actually sleep — backoff is instant for the test."""
        async def _instant(_seconds: float) -> None:
            return None

        monkeypatch.setattr(retry_mod.asyncio, "sleep", _instant)

    async def test_retries_on_5xx_up_to_attempts_then_gives_up(self, monkeypatch) -> None:
        """503 every time: with attempts=3 we make exactly 3 GETs, then give up."""
        calls = {"n": 0}

        def handler(_req: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(503)

        _patch_client(monkeypatch, handler, "app.core.retry.get_client")
        # inject a fast, deterministic policy for the "TestSrc" source
        monkeypatch.setitem(
            retry_mod.POLICIES, "TestSrc",
            RetryPolicy(attempts=3, timeout_s=1, backoff_s=0.01),
        )

        resp, status, detail = await fetch_with_policy("TestSrc", "https://x.test/api")

        assert calls["n"] == 3, "should retry up to the configured attempt count"
        assert resp is None
        assert status == HitStatus.UNAVAILABLE  # 503 → upstream down
        assert "503" in detail

    async def test_succeeds_on_retry_after_transient_5xx(self, monkeypatch) -> None:
        """First call 502, second call 200 → returns FOUND on the 2nd attempt."""
        seq = [httpx.Response(502), httpx.Response(200, text="ok")]
        calls = {"n": 0}

        def handler(_req: httpx.Request) -> httpx.Response:
            r = seq[calls["n"]]
            calls["n"] += 1
            return r

        _patch_client(monkeypatch, handler, "app.core.retry.get_client")
        monkeypatch.setitem(
            retry_mod.POLICIES, "Flappy",
            RetryPolicy(attempts=3, timeout_s=1, backoff_s=0.01),
        )

        resp, status, detail = await fetch_with_policy("Flappy", "https://x.test/")

        assert calls["n"] == 2
        assert resp is not None and resp.status_code == 200
        assert status == HitStatus.FOUND

    async def test_non_retryable_4xx_does_not_retry(self, monkeypatch) -> None:
        """404 is terminal — exactly one GET, no retries."""
        calls = {"n": 0}

        def handler(_req: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(404)

        _patch_client(monkeypatch, handler, "app.core.retry.get_client")
        monkeypatch.setitem(
            retry_mod.POLICIES, "NoRetry4xx",
            RetryPolicy(attempts=3, timeout_s=1, backoff_s=0.01),
        )

        resp, status, _detail = await fetch_with_policy("NoRetry4xx", "https://x.test/")

        assert calls["n"] == 1, "4xx must not be retried"
        assert resp is None
        # 404 from an upstream source = "no record for this target", not a tool
        # bug — classified NO_DATA (see classify_http). The no-retry behaviour
        # (exactly one GET) is what this test guards and is unchanged.
        assert status == HitStatus.NO_DATA

    async def test_reraises_cancelled_error(self, monkeypatch) -> None:
        """CRITICAL: a cancel during fetch must propagate, never be swallowed as a
        normal failure. Swallowing CancelledError breaks cooperative shutdown."""
        def handler(_req: httpx.Request) -> httpx.Response:
            raise asyncio.CancelledError()

        _patch_client(monkeypatch, handler, "app.core.retry.get_client")
        monkeypatch.setitem(
            retry_mod.POLICIES, "CancelSrc",
            RetryPolicy(attempts=3, timeout_s=1, backoff_s=0.01),
        )

        with pytest.raises(asyncio.CancelledError):
            await fetch_with_policy("CancelSrc", "https://x.test/")


# --------------------------------------------------------------------------- #
# HTTP cache (TTL roundtrip with a fake clock)                                 #
# --------------------------------------------------------------------------- #

class TestCache:
    @pytest.fixture
    def cache_env(self, tmp_path, monkeypatch):
        """Enable the cache, point it at a tmp sqlite db, and hand back a fake clock.

        The fake clock drives both `cache.time.time()` (TTL stamping/reads). Tests
        advance it explicitly — no real sleeping.
        """
        monkeypatch.setenv("OSINT_CACHE", "1")

        # Isolate the sqlite file under tmp and reset the one-shot init flag so the
        # schema is (re)created against the fresh db.
        db_path = tmp_path / "http.sqlite"
        monkeypatch.setattr(cache_mod, "cache_path", lambda: str(db_path))
        monkeypatch.setattr(cache_mod, "_INIT_DONE", False, raising=False)

        clock = {"now": 1_000_000}

        def _fake_time() -> int:
            return clock["now"]

        monkeypatch.setattr(cache_mod.time, "time", _fake_time)
        return clock

    async def test_miss_then_hit_roundtrip(self, cache_env) -> None:
        url = "https://crt.sh/?q=acme"
        # cold cache → miss
        assert await cache_mod.get("GET", url) is None
        # store
        await cache_mod.put("GET", url, 200, {"content-type": "application/json"}, b'{"k":1}')
        # warm cache → hit, body + status + headers round-trip intact
        hit = await cache_mod.get("GET", url)
        assert hit is not None
        assert hit["status"] == 200
        assert hit["body"] == b'{"k":1}'
        assert hit["headers"]["content-type"] == "application/json"

    async def test_expiry_after_ttl(self, cache_env) -> None:
        """crt.sh TTL is 6h. Advancing the clock past it turns a hit into a miss."""
        url = "https://crt.sh/?q=acme"
        assert cache_mod.ttl_for(url) == 6 * 3600
        await cache_mod.put("GET", url, 200, {}, b"body")

        # still fresh 1s before expiry
        cache_env["now"] += 6 * 3600 - 1
        assert await cache_mod.get("GET", url) is not None

        # one tick past expiry → miss
        cache_env["now"] += 2
        assert await cache_mod.get("GET", url) is None

    async def test_disabled_cache_is_a_noop(self, cache_env, monkeypatch) -> None:
        """With OSINT_CACHE off, put is a no-op and get returns None even if stored."""
        url = "https://crt.sh/?q=acme"
        await cache_mod.put("GET", url, 200, {}, b"x")  # enabled here
        monkeypatch.setenv("OSINT_CACHE", "0")
        assert await cache_mod.get("GET", url) is None  # reads disabled

    async def test_non_get_method_is_not_cached(self, cache_env) -> None:
        url = "https://crt.sh/?q=acme"
        await cache_mod.put("POST", url, 200, {}, b"x")
        assert await cache_mod.get("POST", url) is None

    def test_ttl_per_host_overrides(self) -> None:
        assert cache_mod.ttl_for("https://internetdb.shodan.io/1.2.3.4") == 24 * 3600
        assert cache_mod.ttl_for("https://gravatar.com/avatar/abc") == 30 * 60
        # unknown host → default 6h
        assert cache_mod.ttl_for("https://nope.example/whatever") == 6 * 3600
