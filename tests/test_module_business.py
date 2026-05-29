"""Hermetic tests for app/modules/business.py (OpenCorporates)."""
from __future__ import annotations

import httpx

from app.core.types import HitStatus, QueryKind, Severity
from app.modules import business as biz_mod

from .factories import make_query


def _patch_client(monkeypatch, handler):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)

    async def _fake_get_client() -> httpx.AsyncClient:
        return client

    monkeypatch.setattr("app.core.http.get_client", _fake_get_client)
    monkeypatch.setattr(biz_mod, "get_client", _fake_get_client, raising=False)


async def _consume(agen):
    return [h async for h in agen]


_SAMPLE_OK = {
    "results": {"companies": [
        {"company": {
            "name": "Acme Holdings Ltd",
            "jurisdiction_code": "gb",
            "incorporation_date": "2010-04-15",
            "current_status": "Active",
            "registered_address_in_full": "1 Some Street, London, UK",
            "opencorporates_url": "https://opencorporates.com/companies/gb/1",
            "officers": [
                {"officer": {"name": "Alice Smith"}},
                {"officer": {"name": "Bob Jones"}},
                {"officer": {"name": "Nominee Services Ltd"}},
            ],
        }},
        {"company": {
            "name": "Acme Old Co Ltd",
            "jurisdiction_code": "gb",
            "incorporation_date": "2005-01-01",
            "current_status": "Dissolved",
            "registered_address_in_full": "Gone Street",
            "opencorporates_url": "https://opencorporates.com/companies/gb/2",
            "officers": [],
        }},
    ]}
}


class TestRunHappyPath:
    async def test_active_and_dissolved_emitted(self, monkeypatch):
        def handler(req: httpx.Request) -> httpx.Response:
            if "opencorporates" in str(req.url):
                return httpx.Response(200, json=_SAMPLE_OK)
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            biz_mod.run(make_query("Acme Holdings", kind=QueryKind.COMPANY))
        )
        titles = [h.title for h in hits if h.source.startswith("opencorporates:")]
        assert "Acme Holdings Ltd" in titles
        assert "Acme Old Co Ltd" in titles
        active = next(h for h in hits
                      if h.title == "Acme Holdings Ltd"
                      and h.source.startswith("opencorporates:"))
        assert active.severity == Severity.MEDIUM
        assert "Alice Smith" in active.detail
        dissolved = next(h for h in hits if h.title == "Acme Old Co Ltd"
                         and h.source.startswith("opencorporates:"))
        assert dissolved.severity == Severity.LOW

    async def test_nominee_director_flagged(self, monkeypatch):
        def handler(req: httpx.Request) -> httpx.Response:
            if "opencorporates" in str(req.url):
                return httpx.Response(200, json=_SAMPLE_OK)
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            biz_mod.run(make_query("Acme Holdings", kind=QueryKind.COMPANY))
        )
        flags = [h for h in hits if h.source.startswith("nominee:")]
        assert len(flags) >= 1
        assert flags[0].severity == Severity.MEDIUM
        assert "Nominee Services Ltd" in flags[0].source
        summary = next(h for h in hits if h.source == "summary")
        assert summary.extra["nominee_flags"] >= 1
        assert summary.extra["active"] == 1


class TestRunFailureModes:
    async def test_429_emits_unavailable_with_hint(self, monkeypatch):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(429)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            biz_mod.run(make_query("acme", kind=QueryKind.COMPANY))
        )
        assert hits and hits[0].status == HitStatus.UNAVAILABLE
        assert "OPENCORPORATES_API_KEY" in hits[0].detail

    async def test_5xx_classified_unavailable(self, monkeypatch):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(503)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            biz_mod.run(make_query("acme", kind=QueryKind.COMPANY))
        )
        assert hits and hits[0].status == HitStatus.UNAVAILABLE

    async def test_no_results_no_data(self, monkeypatch):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"results": {"companies": []}})

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            biz_mod.run(make_query("nosuchcorp", kind=QueryKind.COMPANY))
        )
        assert hits[0].status == HitStatus.NO_DATA

    async def test_short_name_rejected(self, monkeypatch):
        _patch_client(monkeypatch, lambda r: httpx.Response(404))
        hits = await _consume(
            biz_mod.run(make_query("ab", kind=QueryKind.COMPANY))
        )
        assert hits[0].status == HitStatus.NO_DATA
        assert "too short" in hits[0].detail

    async def test_non_company_kind_noop(self, monkeypatch):
        _patch_client(monkeypatch, lambda r: httpx.Response(404))
        hits = await _consume(
            biz_mod.run(make_query("acme.com", kind=QueryKind.DOMAIN))
        )
        assert hits == []


class TestNomineeHeuristic:
    def test_obvious_nominee_names_match(self):
        assert biz_mod._has_nominee("Acme Nominee Services Ltd")
        assert biz_mod._has_nominee("Director Services Limited")
        assert biz_mod._has_nominee("OCRA (Mauritius)")

    def test_normal_names_dont_match(self):
        assert not biz_mod._has_nominee("Alice Smith")
        assert not biz_mod._has_nominee("Bob's Auto Repair")
        assert not biz_mod._has_nominee("")
