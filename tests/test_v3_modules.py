"""Offline tests for v0.3.0 modules — github_leaks, cloud_buckets, hibp_passwords,
malware_bazaar, web_hardening, well_known, subdomain_brute."""
from __future__ import annotations

import asyncio
import hashlib

import httpx

from app.core.types import HitStatus, Query, QueryKind
from app.modules import (
    cloud_buckets,
    github_leaks,
    hibp_passwords,
    malware_bazaar,
    subdomain_brute,
    web_hardening,
    well_known,
)


def _consume(agen) -> list:
    async def _go():
        return [h async for h in agen]
    return asyncio.run(_go())


def _patch_client(monkeypatch, handler):
    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport, timeout=5.0)

    async def _fake_get_client():
        return client

    monkeypatch.setattr("app.core.http.get_client", _fake_get_client)
    for mod in (github_leaks, cloud_buckets, hibp_passwords, malware_bazaar,
                web_hardening, well_known):
        monkeypatch.setattr(f"app.modules.{mod.__name__.split('.')[-1]}.get_client",
                            _fake_get_client)


class TestGithubLeaks:
    def test_domain_search_hit(self, monkeypatch) -> None:
        # code/commit search requires auth — provide a token so we exercise the
        # real search path rather than the no-token SKIP.
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_faketoken")

        def handler(req):
            url = str(req.url)
            if "api.github.com/search/code" in url:
                return httpx.Response(200, json={
                    "total_count": 42,
                    "items": [{"repository": {"full_name": "x/y"},
                               "path": "config.yml",
                               "html_url": "https://github.com/x/y/blob/main/config.yml",
                               "score": 0.5}],
                })
            return httpx.Response(404, json={"total_count": 0, "items": []})
        _patch_client(monkeypatch, handler)
        hits = _consume(github_leaks.run(Query(kind=QueryKind.DOMAIN, value="acme.corp")))
        assert any(h.status == HitStatus.FOUND for h in hits)
        assert any("42" in h.detail for h in hits if h.status == HitStatus.FOUND)


class TestCloudBuckets:
    def test_anonymous_list_critical(self, monkeypatch) -> None:
        def handler(req):
            url = str(req.url)
            # Make ONE candidate return a public ListBucketResult
            if "s3.amazonaws.com/acme" in url:
                return httpx.Response(200,
                    text="<?xml version='1.0'?><ListBucketResult>"
                         "<Contents><Key>x</Key></Contents></ListBucketResult>")
            return httpx.Response(404)
        _patch_client(monkeypatch, handler)
        hits = _consume(cloud_buckets.run(Query(kind=QueryKind.DOMAIN, value="acme.com")))
        # Should have at least one CRITICAL severity hit
        criticals = [h for h in hits if h.severity.value == "critical"]
        assert criticals, "expected a CRITICAL hit for the anonymous-list bucket"


class TestHibpPasswords:
    def test_known_breached_password(self, monkeypatch) -> None:
        # Build a fake range response containing the suffix for "password"
        sha = hashlib.sha1(b"password").hexdigest().upper()
        prefix, suffix = sha[:5], sha[5:]

        def handler(req):
            assert prefix in str(req.url)
            return httpx.Response(200, text=f"{suffix}:9659365\nOTHER:1\n")
        _patch_client(monkeypatch, handler)
        hits = _consume(hibp_passwords.run(Query(kind=QueryKind.PASSWORD, value="password")))
        assert hits and hits[0].status == HitStatus.FOUND
        assert hits[0].severity.value == "critical"
        assert "9,659,365" in hits[0].detail or "9659365" in hits[0].detail

    def test_unbreached_password(self, monkeypatch) -> None:
        def handler(req):
            return httpx.Response(200, text="NOTHERESUFFIX:1\n")
        _patch_client(monkeypatch, handler)
        hits = _consume(hibp_passwords.run(Query(kind=QueryKind.PASSWORD, value="0r1g!nal-Pa$$word!#")))
        assert hits[0].status == HitStatus.FOUND
        assert hits[0].extra["breach_count"] == 0


class TestMalwareBazaar:
    def test_hash_not_in_db(self, monkeypatch) -> None:
        monkeypatch.setenv("ABUSE_CH_API_KEY", "fake")
        _patch_client(monkeypatch, lambda r: httpx.Response(200,
            json={"query_status": "hash_not_found"}))
        hits = _consume(malware_bazaar.run(Query(kind=QueryKind.HASH,
                                                  value="a"*32)))
        assert hits[0].status == HitStatus.NO_DATA

    def test_invalid_hash(self, monkeypatch) -> None:
        monkeypatch.setenv("ABUSE_CH_API_KEY", "fake")
        hits = _consume(malware_bazaar.run(Query(kind=QueryKind.HASH,
                                                  value="not-a-hash")))
        assert hits[0].status == HitStatus.ERROR


class TestWebHardening:
    def test_wildcard_cors_with_credentials_critical(self, monkeypatch) -> None:
        def handler(req):
            if req.method == "OPTIONS":
                return httpx.Response(200, headers={"Allow": "GET, POST, OPTIONS"})
            url = str(req.url)
            if url.endswith(("/robots.txt", "/sitemap.xml")):
                return httpx.Response(404)
            return httpx.Response(200, headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            })
        _patch_client(monkeypatch, handler)
        hits = _consume(web_hardening.run(Query(kind=QueryKind.DOMAIN, value="acme.com")))
        cors_hits = [h for h in hits if h.source == "cors"]
        assert cors_hits and cors_hits[0].severity.value == "critical"

    def test_dangerous_http_methods(self, monkeypatch) -> None:
        def handler(req):
            if req.method == "OPTIONS":
                return httpx.Response(200, headers={
                    "Allow": "GET, POST, PUT, DELETE, TRACE, OPTIONS"})
            return httpx.Response(404)
        _patch_client(monkeypatch, handler)
        hits = _consume(web_hardening.run(Query(kind=QueryKind.DOMAIN, value="acme.com")))
        m_hits = [h for h in hits if h.source == "http-methods"]
        assert m_hits and m_hits[0].status == HitStatus.FOUND
        assert m_hits[0].severity.value == "high"  # TRACE present


class TestWellKnown:
    def test_security_txt_found(self, monkeypatch) -> None:
        def handler(req):
            url = str(req.url)
            if "/.well-known/security.txt" in url:
                return httpx.Response(200,
                    text="Contact: mailto:sec@acme.com\nExpires: 2027-01-01T00:00:00Z\n")
            return httpx.Response(404)
        _patch_client(monkeypatch, handler)
        hits = _consume(well_known.run(Query(kind=QueryKind.DOMAIN, value="acme.com")))
        # Find the security.txt hit
        sec = [h for h in hits if h.source == "security.txt"]
        assert sec and sec[0].status == HitStatus.FOUND
        assert "sec@acme.com" in sec[0].detail


class TestSubdomainBrute:
    def test_wordlist_size(self) -> None:
        assert len(subdomain_brute.WORDLIST) >= 200
        # No duplicates
        assert len(set(subdomain_brute.WORDLIST)) == len(subdomain_brute.WORDLIST)

    def test_no_op_on_non_domain(self) -> None:
        q = Query(kind=QueryKind.IP, value="1.2.3.4")
        assert _consume(subdomain_brute.run(q)) == []
