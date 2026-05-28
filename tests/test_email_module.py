"""Hermetic tests for app/modules/email.py.

The email module fans out to many sources (validate, MX, Gravatar, HIBP,
XposedOrNot, HudsonRock, ProxyNova, username-derivation, holehe). We mock all
HTTP at `get_client` (in both the module and its `base` helper, which the
derived-username/holehe probes use) and kill DNS so MX never escapes. Each test
asserts on a specific source's status/severity/parsed fields.
"""
from __future__ import annotations

import dns.resolver
import httpx

from app.core.types import HitStatus, QueryKind, Severity
from app.modules import base as base_mod
from app.modules import email as email_mod

from .factories import make_query


def _patch_client(monkeypatch, handler) -> None:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)

    async def _fake_get_client() -> httpx.AsyncClient:
        return client

    monkeypatch.setattr("app.core.http.get_client", _fake_get_client)
    monkeypatch.setattr(email_mod, "get_client", _fake_get_client, raising=False)
    monkeypatch.setattr(base_mod, "get_client", _fake_get_client, raising=False)


def _kill_dns(monkeypatch) -> None:
    async def _no(*_a, **_k):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr("dns.asyncresolver.resolve", _no)


async def _consume(agen) -> list:
    return [h async for h in agen]


def _make_handler(extra=None):
    """Base handler: everything 404 by default; `extra(req)` may override."""
    def handler(req: httpx.Request) -> httpx.Response:
        if extra is not None:
            r = extra(req)
            if r is not None:
                return r
        return httpx.Response(404)
    return handler


class TestEmailFormatAndValidation:
    async def test_invalid_email_is_noop(self) -> None:
        assert await _consume(email_mod.run(make_query("garbage", kind=QueryKind.EMAIL))) == []

    async def test_valid_format_hit(self, monkeypatch) -> None:
        _kill_dns(monkeypatch)
        _patch_client(monkeypatch, _make_handler())
        hits = await _consume(email_mod.run(make_query("user@example.com", kind=QueryKind.EMAIL)))
        fmt = next(h for h in hits if h.source == "format")
        assert fmt.status == HitStatus.FOUND
        assert fmt.extra["local"] == "user"
        assert fmt.extra["domain"] == "example.com"


class TestEmailBreachSources:
    async def test_xposedornot_found_high(self, monkeypatch) -> None:
        _kill_dns(monkeypatch)

        def extra(req: httpx.Request):
            url = str(req.url)
            if "xposedornot" in url:
                return httpx.Response(200, json={"breaches": [["Adobe", "LinkedIn"]]})
            return None

        _patch_client(monkeypatch, _make_handler(extra))
        hits = await _consume(email_mod.run(make_query("user@example.com", kind=QueryKind.EMAIL)))
        xon = [h for h in hits if h.source.startswith("XposedOrNot:")]
        assert {h.title for h in xon} == {"Adobe", "LinkedIn"}
        assert all(h.status == HitStatus.FOUND and h.severity == Severity.HIGH for h in xon)

    async def test_xposedornot_no_breaches(self, monkeypatch) -> None:
        _kill_dns(monkeypatch)

        def extra(req: httpx.Request):
            if "xposedornot" in str(req.url):
                return httpx.Response(200, json={"breaches": [[]]})
            return None

        _patch_client(monkeypatch, _make_handler(extra))
        hits = await _consume(email_mod.run(make_query("user@example.com", kind=QueryKind.EMAIL)))
        xon = next(h for h in hits if h.source == "XposedOrNot")
        assert xon.status == HitStatus.NOT_FOUND

    async def test_hudson_rock_infostealer_critical(self, monkeypatch) -> None:
        _kill_dns(monkeypatch)

        def extra(req: httpx.Request):
            if "hudsonrock" in str(req.url):
                return httpx.Response(200, json={"stealers": [{
                    "stealer_family": "RedLine", "date_compromised": "2025-01-02",
                    "computer_name": "DESKTOP-X", "operating_system": "Windows 11",
                }]})
            return None

        _patch_client(monkeypatch, _make_handler(extra))
        hits = await _consume(email_mod.run(make_query("victim@example.com", kind=QueryKind.EMAIL)))
        hr = next(h for h in hits if h.source.startswith("HudsonRock:"))
        assert hr.status == HitStatus.FOUND
        assert hr.severity == Severity.CRITICAL
        assert "RedLine" in hr.title
        assert "Windows 11" in hr.detail

    async def test_proxynova_exact_match_critical(self, monkeypatch) -> None:
        _kill_dns(monkeypatch)
        target = "leak@example.com"

        def extra(req: httpx.Request):
            if "proxynova" in str(req.url):
                # one exact-match combo + one unrelated fuzzy line
                return httpx.Response(200, json={"lines": [
                    f"{target}:Hunter2pw", "other@x.com:zzz",
                ]})
            return None

        _patch_client(monkeypatch, _make_handler(extra))
        hits = await _consume(email_mod.run(make_query(target, kind=QueryKind.EMAIL)))
        pn = [h for h in hits if h.source == "ProxyNova ComB" and h.status == HitStatus.FOUND]
        assert len(pn) == 1
        assert pn[0].severity == Severity.CRITICAL
        # password is masked, never leaked verbatim
        assert "Hunter2pw" not in pn[0].detail
        assert pn[0].extra["line"].startswith(target)

    async def test_proxynova_no_exact_match(self, monkeypatch) -> None:
        _kill_dns(monkeypatch)

        def extra(req: httpx.Request):
            if "proxynova" in str(req.url):
                return httpx.Response(200, json={"lines": ["someone@else.com:pw"]})
            return None

        _patch_client(monkeypatch, _make_handler(extra))
        hits = await _consume(email_mod.run(make_query("me@example.com", kind=QueryKind.EMAIL)))
        pn = next(h for h in hits if h.source == "ProxyNova ComB")
        assert pn.status == HitStatus.NOT_FOUND

    async def test_breach_source_5xx_uncertain(self, monkeypatch) -> None:
        _kill_dns(monkeypatch)

        def extra(req: httpx.Request):
            if "xposedornot" in str(req.url):
                return httpx.Response(503)
            return None

        _patch_client(monkeypatch, _make_handler(extra))
        hits = await _consume(email_mod.run(make_query("user@example.com", kind=QueryKind.EMAIL)))
        xon = next(h for h in hits if h.source == "XposedOrNot")
        assert xon.status == HitStatus.UNCERTAIN
        assert "503" in xon.detail

    async def test_hibp_skipped_without_key(self, monkeypatch) -> None:
        _kill_dns(monkeypatch)
        monkeypatch.delenv("HIBP_API_KEY", raising=False)
        from app.core import config
        config.load_settings()
        _patch_client(monkeypatch, _make_handler())
        hits = await _consume(email_mod.run(make_query("user@example.com", kind=QueryKind.EMAIL)))
        hibp = next(h for h in hits if h.source == "HIBP")
        assert hibp.status == HitStatus.SKIPPED
        config.load_settings()
