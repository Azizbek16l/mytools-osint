"""Hermetic tests for app/modules/leaks.py."""
from __future__ import annotations

import httpx

from app.core.types import HitStatus, QueryKind, Severity
from app.modules import leaks as leaks_mod

from .factories import make_query


def _patch_client(monkeypatch, handler):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)

    async def _fake_get_client() -> httpx.AsyncClient:
        return client

    monkeypatch.setattr("app.core.http.get_client", _fake_get_client)
    monkeypatch.setattr(leaks_mod, "get_client", _fake_get_client, raising=False)


async def _consume(agen):
    return [h async for h in agen]


def _clear_cache():
    leaks_mod._RL_CACHE.clear()


class TestPastebin:
    async def test_pastebin_unwhitelisted_emits_skipped(self, monkeypatch):
        _clear_cache()

        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "pastebin" in url:
                return httpx.Response(200, text="YOUR IP IS NOT REGISTERED")
            if "ransomware.live" in url:
                return httpx.Response(200, json=[])
            return httpx.Response(404)

        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GITHUB_PAT", raising=False)
        _patch_client(monkeypatch, handler)
        hits = await _consume(
            leaks_mod.run(make_query("acme.com", kind=QueryKind.DOMAIN))
        )
        pb = next(h for h in hits if h.source == "pastebin")
        assert pb.status == HitStatus.SKIPPED
        assert "PRO" in pb.detail


class TestGithubGists:
    async def test_no_token_emits_skipped(self, monkeypatch):
        _clear_cache()
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GITHUB_PAT", raising=False)

        def handler(req: httpx.Request) -> httpx.Response:
            if "pastebin" in str(req.url):
                return httpx.Response(403)
            if "ransomware.live" in str(req.url):
                return httpx.Response(200, json=[])
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            leaks_mod.run(make_query("victim@acme.com", kind=QueryKind.EMAIL))
        )
        gh = next(h for h in hits if h.source == "github-gists")
        assert gh.status == HitStatus.SKIPPED
        assert "GITHUB_TOKEN" in gh.detail

    async def test_with_token_finds_gist_matches(self, monkeypatch):
        _clear_cache()
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_fake")

        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "api.github.com/search/code" in url:
                assert req.headers.get("Authorization", "").startswith("Bearer ")
                return httpx.Response(200, json={"items": [
                    {"path": "creds.txt", "html_url": "https://github.com/x/y/blob/main/creds.txt",
                     "repository": {"full_name": "x/y"}},
                ]})
            if "pastebin" in url:
                return httpx.Response(403)
            if "ransomware.live" in url:
                return httpx.Response(200, json=[])
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            leaks_mod.run(make_query("victim@acme.com", kind=QueryKind.EMAIL))
        )
        gh = [h for h in hits if h.source.startswith("github:") and h.status == HitStatus.FOUND]
        assert gh and "creds.txt" in gh[0].title
        assert gh[0].severity == Severity.HIGH


class TestRansomwareLive:
    async def test_clean_run_no_matches(self, monkeypatch):
        _clear_cache()
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)

        def handler(req: httpx.Request) -> httpx.Response:
            if "pastebin" in str(req.url):
                return httpx.Response(403)
            if "ransomware.live" in str(req.url):
                return httpx.Response(200, json=[
                    {"victim": "other-corp", "group_name": "LockBit",
                     "discovered": "2025-05-01"},
                ])
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            leaks_mod.run(make_query("acme.com", kind=QueryKind.DOMAIN))
        )
        rl = next(h for h in hits if h.source == "ransomware.live")
        assert rl.status == HitStatus.NO_DATA

    async def test_matched_victim_emits_critical(self, monkeypatch):
        _clear_cache()
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)

        def handler(req: httpx.Request) -> httpx.Response:
            if "pastebin" in str(req.url):
                return httpx.Response(403)
            if "ransomware.live" in str(req.url):
                return httpx.Response(200, json=[
                    {"victim": "Acme Inc", "domain": "acme.com",
                     "group_name": "LockBit", "discovered": "2025-05-01",
                     "post_url": "https://ransomware.live/post/123"},
                ])
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            leaks_mod.run(make_query("acme.com", kind=QueryKind.DOMAIN))
        )
        match = next(h for h in hits if h.source.startswith("ransomware.live:"))
        assert match.status == HitStatus.FOUND
        assert match.severity == Severity.CRITICAL
        assert "LockBit" in match.source

    async def test_5xx_marks_unavailable_not_error(self, monkeypatch):
        _clear_cache()
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)

        def handler(req: httpx.Request) -> httpx.Response:
            if "pastebin" in str(req.url):
                return httpx.Response(403)
            if "ransomware.live" in str(req.url):
                return httpx.Response(502)
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            leaks_mod.run(make_query("acme.com", kind=QueryKind.DOMAIN))
        )
        rl = next(h for h in hits if h.source == "ransomware.live")
        assert rl.status == HitStatus.UNAVAILABLE
        assert all(h.status != HitStatus.ERROR for h in hits)

    async def test_cache_dedupes_requests(self, monkeypatch):
        _clear_cache()
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        request_count = {"n": 0}

        def handler(req: httpx.Request) -> httpx.Response:
            if "pastebin" in str(req.url):
                return httpx.Response(403)
            if "ransomware.live" in str(req.url):
                request_count["n"] += 1
                return httpx.Response(200, json=[])
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        await _consume(leaks_mod.run(make_query("acme.com", kind=QueryKind.DOMAIN)))
        await _consume(leaks_mod.run(make_query("acme.com", kind=QueryKind.DOMAIN)))
        assert request_count["n"] == 1


class TestApex:
    def test_email_apex_extracts_domain(self):
        assert leaks_mod._apex("user@acme.com") == "acme.com"
        assert leaks_mod._apex("user@mail.acme.co.uk") == "acme.co.uk"

    def test_unsupported_kind_noop(self, monkeypatch):
        import asyncio
        async def go():
            return await _consume(
                leaks_mod.run(make_query("8.8.8.8", kind=QueryKind.IP))
            )
        loop = asyncio.new_event_loop()
        try:
            assert loop.run_until_complete(go()) == []
        finally:
            loop.close()
