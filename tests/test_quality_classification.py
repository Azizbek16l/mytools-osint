"""Hermetic tests for the v4 output-quality classification fixes.

Covers the five "the tool mislabels transient/expected conditions" bugs:

  1. base.probe_site: timeout / network error → UNAVAILABLE (not ERROR), and
     classify_exception agrees.
  2. github_leaks.run: no GITHUB_TOKEN → ONE concise SKIPPED hit (not an
     error per endpoint).
  3. classify_http: upstream 404/410 → NO_DATA, 401/403 → UNAVAILABLE,
     429 → RATELIMITED; 400/422 stay ERROR (our request shape).
  4. discovery._wayback: timeout / empty → UNAVAILABLE / NO_DATA with a real
     detail (never a blank ERROR).
  5. cloud_buckets: bulk negatives collapse into ONE summary row instead of
     one row per non-existent bucket permutation.

Pattern: patch get_client with httpx.AsyncClient(MockTransport(handler)) in
every consumer namespace; assertions are on status / detail, never "no raise".
"""
from __future__ import annotations

import httpx

from app.core.classify import classify_exception, classify_http
from app.core.types import HitStatus, Severity
from app.modules import base as base_mod
from app.modules import cloud_buckets as cb_mod
from app.modules import discovery as discovery_mod
from app.modules import github_leaks as gh_mod

from .factories import make_query


def _patch_client(monkeypatch, handler, *modules) -> httpx.AsyncClient:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)

    async def _fake_get_client() -> httpx.AsyncClient:
        return client

    monkeypatch.setattr("app.core.http.get_client", _fake_get_client)
    for m in modules:
        monkeypatch.setattr(m, "get_client", _fake_get_client, raising=False)
    return client


async def _consume(agen) -> list:
    return [h async for h in agen]


# --------------------------------------------------------------------------- #
# 1. classify_exception + base.probe_site                                      #
# --------------------------------------------------------------------------- #

class TestExceptionClassification:
    def test_timeout_is_unavailable(self) -> None:
        assert classify_exception(httpx.ConnectTimeout("t")) == HitStatus.UNAVAILABLE
        assert classify_exception(httpx.ReadTimeout("t")) == HitStatus.UNAVAILABLE

    def test_connect_error_is_unavailable(self) -> None:
        assert classify_exception(httpx.ConnectError("refused")) == HitStatus.UNAVAILABLE

    def test_genuine_bug_stays_error(self) -> None:
        # A real code bug (e.g. a parse failure) must STILL be ERROR.
        assert classify_exception(ValueError("bad parse")) == HitStatus.ERROR
        assert classify_exception(KeyError("missing")) == HitStatus.ERROR


class TestProbeSiteTransient:
    async def test_connect_timeout_is_unavailable(self, monkeypatch) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("connect timed out", request=req)

        _patch_client(monkeypatch, handler, base_mod)
        site = {"name": "TikTok", "url": "https://tiktok.com/@{}",
                "category": "social", "good_status": [200]}
        hit = await base_mod.probe_site(site, "someuser", "email")
        # Evidence regression: TikTok ConnectTimeout used to render as ERROR.
        assert hit.status == HitStatus.UNAVAILABLE
        assert "ConnectTimeout" in hit.detail  # detail preserved

    async def test_network_error_is_unavailable(self, monkeypatch) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("dns failure", request=req)

        _patch_client(monkeypatch, handler, base_mod)
        site = {"name": "Example", "url": "https://example.com/{}",
                "good_status": [200]}
        hit = await base_mod.probe_site(site, "u", "username")
        assert hit.status == HitStatus.UNAVAILABLE
        assert "ConnectError" in hit.detail


# --------------------------------------------------------------------------- #
# 2. github_leaks: no token → SKIPPED                                          #
# --------------------------------------------------------------------------- #

class TestGithubLeaksSkip:
    async def test_no_token_skips_once(self, monkeypatch) -> None:
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GITHUB_PAT", raising=False)

        called = {"n": 0}

        def handler(req: httpx.Request) -> httpx.Response:
            called["n"] += 1
            return httpx.Response(200, json={"total_count": 0, "items": []})

        _patch_client(monkeypatch, handler, gh_mod)
        hits = await _consume(gh_mod.run(make_query("acme.com")))
        # Exactly one concise SKIPPED hit, and NO HTTP calls fired.
        assert len(hits) == 1
        assert hits[0].status == HitStatus.SKIPPED
        assert "GITHUB_TOKEN" in hits[0].detail
        assert called["n"] == 0
        # Crucially: not an ERROR.
        assert not [h for h in hits if h.status == HitStatus.ERROR]

    async def test_with_token_runs_search(self, monkeypatch) -> None:
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_faketoken")

        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "total_count": 7,
                "items": [{"repository": {"full_name": "x/y"}, "path": "c.yml",
                           "html_url": "https://github.com/x/y", "score": 1}],
            })

        _patch_client(monkeypatch, handler, gh_mod)
        hits = await _consume(gh_mod.run(make_query("acme.com")))
        assert any(h.status == HitStatus.FOUND for h in hits)


# --------------------------------------------------------------------------- #
# 3. classify_http upstream-4xx mapping                                        #
# --------------------------------------------------------------------------- #

class TestClassifyHttp:
    def test_404_410_are_no_data(self) -> None:
        assert classify_http(404) == HitStatus.NO_DATA
        assert classify_http(410) == HitStatus.NO_DATA

    def test_auth_geofence_is_unavailable(self) -> None:
        assert classify_http(401) == HitStatus.UNAVAILABLE
        assert classify_http(403) == HitStatus.UNAVAILABLE

    def test_429_is_ratelimited(self) -> None:
        assert classify_http(429) == HitStatus.RATELIMITED

    def test_bad_request_shape_stays_error(self) -> None:
        # 400/422 are genuinely our request shape — keep ERROR detection.
        assert classify_http(400) == HitStatus.ERROR
        assert classify_http(422) == HitStatus.ERROR

    def test_other_4xx_unavailable(self) -> None:
        assert classify_http(451) == HitStatus.UNAVAILABLE  # legal block, upstream
        assert classify_http(405) == HitStatus.UNAVAILABLE

    def test_5xx_unavailable_and_200_found(self) -> None:
        assert classify_http(503) == HitStatus.UNAVAILABLE
        assert classify_http(200) == HitStatus.FOUND


# --------------------------------------------------------------------------- #
# 4. discovery._wayback: no blank ERROR                                        #
# --------------------------------------------------------------------------- #

class TestDiscoveryWayback:
    async def test_timeout_is_unavailable_with_detail(self, monkeypatch) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("", request=req)  # str(e) == ""

        _patch_client(monkeypatch, handler, discovery_mod)
        hits = await _consume(discovery_mod._wayback("acme.com"))
        assert len(hits) == 1
        wb = hits[0]
        assert wb.status == HitStatus.UNAVAILABLE  # was a blank ERROR
        assert wb.detail.strip(), "detail must never be blank"
        assert "ConnectTimeout" in wb.detail

    async def test_no_snapshots_is_no_data(self, monkeypatch) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=[["timestamp", "original"]])  # header only

        _patch_client(monkeypatch, handler, discovery_mod)
        hits = await _consume(discovery_mod._wayback("acme.com"))
        assert hits and hits[0].status == HitStatus.NO_DATA
        assert hits[0].detail

    async def test_upstream_5xx_is_unavailable(self, monkeypatch) -> None:
        _patch_client(monkeypatch, lambda r: httpx.Response(503), discovery_mod)
        hits = await _consume(discovery_mod._wayback("acme.com"))
        assert hits and hits[0].status == HitStatus.UNAVAILABLE
        assert "503" in hits[0].detail

    async def test_found_snapshots(self, monkeypatch) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=[
                ["timestamp", "original"],
                ["20200101", "https://acme.com/x"],
            ])

        _patch_client(monkeypatch, handler, discovery_mod)
        hits = await _consume(discovery_mod._wayback("acme.com"))
        assert any(h.status == HitStatus.FOUND for h in hits)


# --------------------------------------------------------------------------- #
# 5. cloud_buckets: collapse bulk negatives into ONE summary                   #
# --------------------------------------------------------------------------- #

class TestCloudBucketsCollapse:
    async def test_all_negative_collapses_to_summary(self, monkeypatch) -> None:
        # Every bucket guess 404s (none exist) — historically this flooded the
        # output with ~one no_data/uncertain row per permutation.
        _patch_client(monkeypatch, lambda r: httpx.Response(404), cb_mod)
        hits = await _consume(cb_mod.run(make_query("acme.com")))
        # Exactly ONE row: the summary. No per-permutation noise.
        assert len(hits) == 1
        summary = hits[0]
        assert summary.source == "summary"
        assert summary.status == HitStatus.NO_DATA
        assert summary.extra["found"] == 0
        # Summary reports how many candidate names were checked.
        assert summary.extra["candidates"] > 0

    async def test_ambiguous_403_does_not_emit_noise(self, monkeypatch) -> None:
        # A bare 403 with no exists-marker is UNCERTAIN — must NOT spam a row
        # per permutation; it collapses into the summary like a negative.
        _patch_client(monkeypatch, lambda r: httpx.Response(403, text="nope"),
                      cb_mod)
        hits = await _consume(cb_mod.run(make_query("acme.com")))
        assert len(hits) == 1
        assert hits[0].source == "summary"
        assert hits[0].status == HitStatus.NO_DATA

    async def test_real_finding_still_surfaces(self, monkeypatch) -> None:
        # A genuinely public bucket must still produce a per-bucket FOUND hit
        # alongside the summary — collapse must not hide real findings.
        def handler(req: httpx.Request) -> httpx.Response:
            if "s3.amazonaws.com/acme" in str(req.url):
                return httpx.Response(200,
                    text="<ListBucketResult><Contents><Key>x</Key>"
                         "</Contents></ListBucketResult>")
            return httpx.Response(404)

        _patch_client(monkeypatch, handler, cb_mod)
        hits = await _consume(cb_mod.run(make_query("acme.com")))
        found = [h for h in hits if h.status == HitStatus.FOUND
                 and h.source != "summary"]
        assert found, "a real public bucket must still surface"
        assert any(h.severity == Severity.CRITICAL for h in found)
        summary = next(h for h in hits if h.source == "summary")
        assert summary.extra["found"] >= 1
