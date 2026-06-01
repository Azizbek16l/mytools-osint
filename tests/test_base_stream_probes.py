"""Hermetic tests for app/modules/base.stream_probes concurrency/timeout gates.

These drive the fan-out logic with an httpx MockTransport whose handler can
sleep, so we can assert the hard-timeout ceiling, per-host gating, and
error-isolation deterministically — no real network, sub-second runtime.
"""
from __future__ import annotations

import asyncio
import time

import httpx

from app.core.types import HitStatus
from app.modules import base as base_mod


def _patch_client(monkeypatch, handler):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=30.0)

    async def _fake_get_client() -> httpx.AsyncClient:
        return client

    monkeypatch.setattr("app.core.http.get_client", _fake_get_client)
    monkeypatch.setattr(base_mod, "get_client", _fake_get_client, raising=False)
    return client


async def _consume(agen):
    return [h async for h in agen]


def _site(name: str, host: str) -> dict:
    return {"name": name, "url": f"https://{host}/{{}}", "category": "social",
            "check": "status", "good_status": [200], "bad_status": [404]}


class TestHardTimeout:
    async def test_hard_timeout_bounds_a_slow_probe(self, monkeypatch):
        """A probe that would hang far past the ceiling is cut to UNAVAILABLE,
        while fast probes on other hosts still return their real status."""
        async def handler(req: httpx.Request) -> httpx.Response:
            if "slowhost" in str(req.url):
                await asyncio.sleep(5.0)        # would blow any sane ceiling
                return httpx.Response(200)
            return httpx.Response(404)          # fast → NOT_FOUND

        _patch_client(monkeypatch, handler)
        sites = [_site("Slow", "slowhost.test"), _site("Fast", "fasthost.test")]
        t0 = time.perf_counter()
        hits = await _consume(base_mod.stream_probes(
            sites, "octocat", "username",
            concurrency=10, timeout=10.0, retries=0, hard_timeout=0.5,
        ))
        elapsed = time.perf_counter() - t0
        # The hard ceiling (0.5s) must dominate the 5s sleep.
        assert elapsed < 3.0, f"hard timeout did not bound the slow probe ({elapsed:.1f}s)"
        by_src = {h.source: h for h in hits}
        assert by_src["Slow"].status == HitStatus.UNAVAILABLE
        assert "hard timeout" in by_src["Slow"].detail
        # never ERROR — a slow upstream is not our bug
        assert by_src["Slow"].status != HitStatus.ERROR
        assert by_src["Fast"].status == HitStatus.NOT_FOUND

    async def test_no_hard_timeout_lets_probe_complete(self, monkeypatch):
        """Default (hard_timeout=None) must preserve old behaviour: a probe that
        finishes within its phase timeout returns its real status."""
        async def handler(req: httpx.Request) -> httpx.Response:
            await asyncio.sleep(0.2)
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        sites = [_site("S", "host.test")]
        hits = await _consume(base_mod.stream_probes(
            sites, "octocat", "username", concurrency=5, timeout=10.0, retries=0,
        ))
        assert hits[0].status == HitStatus.NOT_FOUND


class TestErrorIsolation:
    async def test_bad_site_signature_does_not_kill_fanout(self, monkeypatch):
        """A malformed site (invalid valid_chars regex) is a data-quality bug,
        not a runtime error: the broken constraint is ignored + logged at debug,
        the probe still runs, and the fan-out completes. The bad site is named
        (not an anonymous "?") and isolation holds — one bad entry never aborts
        the others nor spams ERRORs across 1000+ sites. (A compile-time test on
        data/sites.json guards against bad regexes shipping in the dataset.)"""
        _patch_client(monkeypatch, lambda r: httpx.Response(404))
        bad = {"name": "Bad", "url": "https://b.test/{}", "valid_chars": "("}  # unbalanced
        good = _site("Good", "g.test")
        hits = await _consume(base_mod.stream_probes(
            [bad, good], "octocat", "username", concurrency=5, timeout=5.0,
        ))
        by_src = {h.source: h for h in hits}
        assert by_src["Bad"].status == HitStatus.NOT_FOUND   # named + still probed (404)
        assert by_src["Good"].status == HitStatus.NOT_FOUND  # sibling still ran
        assert "?" not in by_src                             # no anonymous crash hit


class TestPerHostGate:
    async def test_per_host_serialises_same_host(self, monkeypatch):
        """The per-host gate (=1 here) must serialise probes that share a host,
        proving it is still applied (we must NOT remove it)."""
        in_flight = 0
        max_in_flight = 0

        async def handler(req: httpx.Request) -> httpx.Response:
            nonlocal in_flight, max_in_flight
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
            await asyncio.sleep(0.1)
            in_flight -= 1
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        # 4 distinct subdomains that collapse to the SAME registrable host.
        sites = [_site(f"S{i}", f"s{i}.shared.test") for i in range(4)]
        await _consume(base_mod.stream_probes(
            sites, "octocat", "username",
            concurrency=10, per_host=1, timeout=5.0,
        ))
        assert max_in_flight == 1, f"per-host gate not enforced (saw {max_in_flight} concurrent)"
