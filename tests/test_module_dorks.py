"""Hermetic tests for app/modules/dorks.py.

Drives DuckDuckGo + Bing through MockTransport; asserts result parsing,
SERP-layout drift behaviour, and per-engine request counting.
"""
from __future__ import annotations

import httpx

from app.core.types import HitStatus, QueryKind, Severity
from app.modules import dorks as dorks_mod

from .factories import make_query


def _patch_client(monkeypatch, handler):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)

    async def _fake_get_client() -> httpx.AsyncClient:
        return client

    monkeypatch.setattr("app.core.http.get_client", _fake_get_client)
    monkeypatch.setattr(dorks_mod, "get_client", _fake_get_client, raising=False)


async def _consume(agen):
    return [h async for h in agen]


_DDG_HTML_OK = """
<html><body>
<div class="result">
  <h2><a class="result__a" href="https://acme.com/admin/login">Admin login | acme</a></h2>
  <span>snippet</span>
</div>
<div class="result">
  <h2><a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Facme.com%2Freport.pdf">Acme PDF report</a></h2>
</div>
</body></html>
"""

_BING_HTML_OK = """
<html><body>
<ol id="b_results">
  <li class="b_algo">
    <h2><a href="https://github.com/acme/secret-repo">acme/secret-repo · GitHub</a></h2>
    <p>code …</p>
  </li>
  <li class="b_algo">
    <h2><a href="https://pastebin.com/raw/aaaa">leaked credentials acme</a></h2>
  </li>
</ol>
</body></html>
"""

_EMPTY_BUT_VALID = "<html><body><div>nothing here</div></body></html>"


class TestDorkGeneration:
    def test_domain_dorks_include_pdf_filetype(self):
        out = dorks_mod._dorks_for(QueryKind.DOMAIN, "acme.com")
        assert any("filetype:pdf" in d for d in out)
        assert any("intitle:" in d for d in out)
        assert len(out) <= 6

    def test_email_dorks_include_pastebin_and_github(self):
        out = dorks_mod._dorks_for(QueryKind.EMAIL, "x@acme.com")
        assert any("pastebin" in d for d in out)
        assert any("github" in d for d in out)

    def test_username_dorks(self):
        out = dorks_mod._dorks_for(QueryKind.USERNAME, "temur")
        assert any("reddit" in d for d in out)
        assert len(out) >= 3

    def test_unsupported_kind_returns_empty(self):
        out = dorks_mod._dorks_for(QueryKind.IP, "8.8.8.8")
        assert out == []


class TestParsers:
    def test_parse_ddg_extracts_uddg_unwrap(self):
        results = dorks_mod._parse_ddg(_DDG_HTML_OK)
        assert len(results) == 2
        titles = {t for t, _ in results}
        urls = {u for _, u in results}
        assert any("admin login" in t.lower() for t in titles)
        assert "https://acme.com/admin/login" in urls
        # uddg= wrapper unwrapped
        assert "https://acme.com/report.pdf" in urls

    def test_parse_bing_extracts_titles_and_urls(self):
        results = dorks_mod._parse_bing(_BING_HTML_OK)
        assert len(results) == 2
        urls = [u for _, u in results]
        assert "https://github.com/acme/secret-repo" in urls
        assert "https://pastebin.com/raw/aaaa" in urls


class TestRunDomain:
    async def test_happy_path_emits_results_per_engine(self, monkeypatch):
        # Track per-engine request count to enforce "one query per engine per dork".
        per_engine: dict[str, int] = {"ddg": 0, "bing": 0}

        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "duckduckgo" in url:
                per_engine["ddg"] += 1
                return httpx.Response(200, text=_DDG_HTML_OK)
            if "bing.com" in url:
                per_engine["bing"] += 1
                return httpx.Response(200, text=_BING_HTML_OK)
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            dorks_mod.run(make_query("acme.com", kind=QueryKind.DOMAIN))
        )
        # FOUND hits come from both engines
        ddg = [h for h in hits if h.source == "DuckDuckGo" and h.status == HitStatus.FOUND]
        bing = [h for h in hits if h.source == "Bing" and h.status == HitStatus.FOUND]
        assert ddg and bing
        # 4 dorks × 2 engines = 8 SERP fetches max
        n_dorks = len(dorks_mod._dorks_for(QueryKind.DOMAIN, "acme.com"))
        assert per_engine["ddg"] == n_dorks
        assert per_engine["bing"] == n_dorks
        # severity / confidence
        assert ddg[0].severity == Severity.MEDIUM
        assert 0 < ddg[0].confidence <= 1.0
        # summary at end
        summary = next(h for h in hits if h.source == "summary")
        assert summary.status == HitStatus.FOUND

    async def test_serp_layout_drift_returns_no_data_with_hint(self, monkeypatch):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=_EMPTY_BUT_VALID)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            dorks_mod.run(make_query("acme.com", kind=QueryKind.DOMAIN))
        )
        no_data = [h for h in hits
                   if h.status == HitStatus.NO_DATA and h.source in ("DuckDuckGo", "Bing")]
        assert no_data
        assert any("file an issue" in (h.detail or "").lower() for h in no_data)
        # Should NOT classify as ERROR
        assert not [h for h in hits if h.status == HitStatus.ERROR]

    async def test_429_classified_ratelimited(self, monkeypatch):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(429, text="too many")

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            dorks_mod.run(make_query("acme.com", kind=QueryKind.DOMAIN))
        )
        assert any(h.status == HitStatus.RATELIMITED for h in hits)

    async def test_unsupported_kind_noop(self, monkeypatch):
        _patch_client(monkeypatch, lambda r: httpx.Response(404))
        hits = await _consume(
            dorks_mod.run(make_query("8.8.8.8", kind=QueryKind.IP))
        )
        assert hits == []
