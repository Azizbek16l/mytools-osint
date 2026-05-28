"""Hermetic tests for the headline recon modules.

Pattern (canonical, per test_v3_modules / test_sources_new): patch `get_client`
in every consumer namespace with an `httpx.AsyncClient(MockTransport(handler))`.
DNS-touching modules additionally get `dns.asyncresolver.resolve[/_address]`
stubbed so nothing escapes to the network — we drive the HTTP code paths only.

For each module: one FOUND/happy path, one error/5xx path, one empty/no-data
path. Assertions are on status / severity / parsed fields, never "no exception".
"""
from __future__ import annotations

import dns.resolver
import httpx

from app.core.types import HitStatus, QueryKind, Severity
from app.modules import (
    domain as domain_mod,
)
from app.modules import (
    ip as ip_mod,
)
from app.modules import (
    passive_dns as pdns_mod,
)
from app.modules import (
    ssl_tls as ssl_mod,
)
from app.modules import (
    subdomain_takeover as takeover_mod,
)
from app.modules import (
    tech_fingerprint as tech_mod,
)
from app.modules import (
    wayback_urls as wayback_mod,
)

from .factories import make_query

# --------------------------------------------------------------------------- #
# harness                                                                      #
# --------------------------------------------------------------------------- #

def _patch_client(monkeypatch, handler, *modules) -> httpx.AsyncClient:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)

    async def _fake_get_client() -> httpx.AsyncClient:
        return client

    monkeypatch.setattr("app.core.http.get_client", _fake_get_client)
    for m in modules:
        monkeypatch.setattr(m, "get_client", _fake_get_client, raising=False)
    return client


def _kill_dns(monkeypatch) -> None:
    """Make every DNS lookup fail cleanly (NXDOMAIN) so no real resolver runs."""
    async def _no_resolve(*_a, **_k):
        raise dns.resolver.NXDOMAIN()

    async def _no_resolve_addr(*_a, **_k):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr("dns.asyncresolver.resolve", _no_resolve)
    monkeypatch.setattr("dns.asyncresolver.resolve_address", _no_resolve_addr)


async def _consume(agen) -> list:
    return [h async for h in agen]


# --------------------------------------------------------------------------- #
# domain.py — subdomain enumeration fan-out                                    #
# --------------------------------------------------------------------------- #

class TestDomain:
    async def test_found_subdomain_from_crtsh(self, monkeypatch) -> None:
        _kill_dns(monkeypatch)

        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "crt.sh" in url:
                return httpx.Response(200, json=[
                    {"name_value": "api.acme.com\nwww.acme.com", "common_name": "acme.com"},
                ])
            # every other source returns empty so crt.sh is the sole signal
            if "hackertarget" in url:
                return httpx.Response(200, text="")
            return httpx.Response(200, json=[])

        _patch_client(monkeypatch, handler, domain_mod)
        hits = await _consume(domain_mod.run(make_query("acme.com")))

        subs = {h.source for h in hits if h.category == "subdomain"}
        assert "api.acme.com" in subs
        assert "www.acme.com" in subs
        # single-source confidence → LOW severity
        api_hit = next(h for h in hits if h.source == "api.acme.com")
        assert api_hit.status == HitStatus.FOUND
        assert api_hit.severity == Severity.LOW
        assert api_hit.extra["confidence"] == 1
        # crt.sh summary should be FOUND
        crt_summary = next(h for h in hits if h.source == "crt.sh (summary)")
        assert crt_summary.status == HitStatus.FOUND

    async def test_5xx_source_marked_unavailable(self, monkeypatch) -> None:
        _kill_dns(monkeypatch)

        # crt.sh sleeps 2s between retries on 5xx — neutralise the backoff so the
        # test stays sub-second (we assert the classification, not the timing).
        async def _instant(_s):
            return None

        monkeypatch.setattr(domain_mod.asyncio, "sleep", _instant)

        def handler(req: httpx.Request) -> httpx.Response:
            # crt.sh 503 twice (it retries on 5xx), everything else empty
            if "crt.sh" in str(req.url):
                return httpx.Response(503)
            if "hackertarget" in str(req.url):
                return httpx.Response(200, text="")
            return httpx.Response(200, json=[])

        _patch_client(monkeypatch, handler, domain_mod)
        hits = await _consume(domain_mod.run(make_query("acme.com")))
        crt = next(h for h in hits if h.source == "crt.sh (summary)")
        assert crt.status == HitStatus.UNAVAILABLE
        assert "503" in crt.detail or "unavailable" in crt.detail.lower()

    async def test_empty_yields_no_subdomains(self, monkeypatch) -> None:
        _kill_dns(monkeypatch)

        def handler(req: httpx.Request) -> httpx.Response:
            if "hackertarget" in str(req.url):
                return httpx.Response(200, text="")
            if "urlscan" in str(req.url):
                return httpx.Response(200, json={"results": []})
            return httpx.Response(200, json=[])

        _patch_client(monkeypatch, handler, domain_mod)
        hits = await _consume(domain_mod.run(make_query("acme.com")))
        assert not [h for h in hits if h.category == "subdomain"]
        # urlscan with no results → NOT_FOUND
        us = next(h for h in hits if h.source == "urlscan.io")
        assert us.status == HitStatus.NOT_FOUND

    async def test_non_domain_input_is_noop(self) -> None:
        assert await _consume(domain_mod.run(make_query("not-a-domain"))) == []


# --------------------------------------------------------------------------- #
# ip.py                                                                        #
# --------------------------------------------------------------------------- #

class TestIp:
    async def test_ipinfo_found(self, monkeypatch) -> None:
        _kill_dns(monkeypatch)  # rDNS fails → NOT it
        monkeypatch.setenv("IPINFO_API_TOKEN", "tok")
        # rebuild settings so has_ipinfo is True
        from app.core import config
        config.load_settings()

        def handler(req: httpx.Request) -> httpx.Response:
            if "ipinfo.io" in str(req.url):
                assert req.headers.get("Authorization") == "Bearer tok"
                return httpx.Response(200, json={
                    "city": "Berlin", "country": "DE", "org": "AS3320 Telekom",
                })
            return httpx.Response(404)

        _patch_client(monkeypatch, handler, ip_mod)
        hits = await _consume(ip_mod.run(make_query("8.8.8.8", kind=QueryKind.IP)))
        info = next(h for h in hits if h.source == "IPinfo")
        assert info.status == HitStatus.FOUND
        assert info.severity == Severity.MEDIUM
        assert "Berlin" in info.detail and "Telekom" in info.detail
        config.load_settings()  # reset memoised settings for sibling tests

    async def test_ipinfo_skipped_without_token(self, monkeypatch) -> None:
        _kill_dns(monkeypatch)
        monkeypatch.delenv("IPINFO_API_TOKEN", raising=False)
        from app.core import config
        config.load_settings()
        _patch_client(monkeypatch, lambda r: httpx.Response(500), ip_mod)
        hits = await _consume(ip_mod.run(make_query("8.8.8.8", kind=QueryKind.IP)))
        info = next(h for h in hits if h.source == "IPinfo")
        assert info.status == HitStatus.SKIPPED
        assert "IPINFO_API_TOKEN" in info.detail
        config.load_settings()

    async def test_ipinfo_5xx_uncertain(self, monkeypatch) -> None:
        _kill_dns(monkeypatch)
        monkeypatch.setenv("IPINFO_API_TOKEN", "tok")
        from app.core import config
        config.load_settings()
        _patch_client(monkeypatch, lambda r: httpx.Response(503), ip_mod)
        hits = await _consume(ip_mod.run(make_query("8.8.8.8", kind=QueryKind.IP)))
        info = next(h for h in hits if h.source == "IPinfo")
        assert info.status == HitStatus.UNCERTAIN
        assert "503" in info.detail
        config.load_settings()


# --------------------------------------------------------------------------- #
# ssl_tls.py — _grab_cert mocked at the connection layer                       #
# --------------------------------------------------------------------------- #

class TestSslTls:
    async def test_found_healthy_cert(self, monkeypatch) -> None:
        from datetime import UTC, datetime, timedelta

        async def _fake_grab(host, port, timeout=20.0):
            return {
                "subject": "CN=acme.com", "issuer": "CN=R3, O=Let's Encrypt",
                "not_after": datetime.now(UTC) + timedelta(days=60),
                "not_before": datetime.now(UTC) - timedelta(days=30),
                "version": "TLSv1.3", "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
                "sig_alg": "sha256WithRSAEncryption", "key_alg": "RSA", "key_size": 2048,
                "sha256": "ab", "sha1": "cd", "sans": ["acme.com", "www.acme.com"],
            }

        monkeypatch.setattr(ssl_mod, "_grab_cert", _fake_grab)
        hits = await _consume(ssl_mod.run(make_query("acme.com")))
        main = next(h for h in hits if h.category == "tls")
        assert main.status == HitStatus.FOUND
        assert main.severity == Severity.INFO  # healthy → no issue bump
        assert "TLS TLSv1.3" in main.detail
        assert main.extra["key_size"] == 2048
        assert main.extra["sans"] == ["acme.com", "www.acme.com"]

    async def test_expired_cert_is_high_severity(self, monkeypatch) -> None:
        from datetime import UTC, datetime, timedelta

        async def _fake_grab(host, port, timeout=20.0):
            return {
                "subject": "CN=old.acme.com", "issuer": "CN=R3",
                "not_after": datetime.now(UTC) - timedelta(days=5),  # EXPIRED
                "not_before": datetime.now(UTC) - timedelta(days=400),
                "version": "TLSv1.2", "cipher": ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128),
                "sig_alg": "sha256WithRSAEncryption", "key_alg": "RSA", "key_size": 2048,
                "sha256": "x", "sha1": "y", "sans": [],
            }

        monkeypatch.setattr(ssl_mod, "_grab_cert", _fake_grab)
        hits = await _consume(ssl_mod.run(make_query("old.acme.com")))
        main = next(h for h in hits if h.category == "tls")
        assert main.severity == Severity.HIGH
        assert "EXPIRED" in main.detail
        assert main.extra["days_left"] < 0

    async def test_connect_failure_unavailable(self, monkeypatch) -> None:
        async def _fake_grab(host, port, timeout=20.0):
            return {"error": "TimeoutError: timed out"}

        monkeypatch.setattr(ssl_mod, "_grab_cert", _fake_grab)
        hits = await _consume(ssl_mod.run(make_query("dead.acme.com")))
        assert hits and hits[0].status == HitStatus.UNAVAILABLE
        assert "Timeout" in hits[0].detail

    async def test_non_domain_input_noop(self) -> None:
        q = make_query("1.2.3.4", kind=QueryKind.IP)
        assert await _consume(ssl_mod.run(q)) == []


# --------------------------------------------------------------------------- #
# tech_fingerprint.py                                                          #
# --------------------------------------------------------------------------- #

class TestTechFingerprint:
    async def test_found_cloudflare_and_nginx(self, monkeypatch) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={
                "server": "cloudflare", "cf-ray": "abc123-FRA",
                "content-type": "text/html",
            }, text="<html></html>")

        _patch_client(monkeypatch, handler, tech_mod)
        hits = await _consume(tech_mod.run(make_query("acme.com")))
        names = {h.source for h in hits}
        assert "Cloudflare" in names
        stack = next(h for h in hits if h.source == "stack")
        assert stack.status == HitStatus.FOUND
        assert any(m["name"] == "Cloudflare" for m in stack.extra["matches"])

    async def test_no_signatures_not_found(self, monkeypatch) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"content-type": "text/html"},
                                  text="<html><body>plain</body></html>")

        _patch_client(monkeypatch, handler, tech_mod)
        hits = await _consume(tech_mod.run(make_query("acme.com")))
        assert len(hits) == 1
        assert hits[0].status == HitStatus.NOT_FOUND

    async def test_transport_error_classified(self, monkeypatch) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=req)

        _patch_client(monkeypatch, handler, tech_mod)
        hits = await _consume(tech_mod.run(make_query("acme.com")))
        assert hits and hits[0].status == HitStatus.UNAVAILABLE  # connect error → upstream
        assert "ConnectError" in hits[0].detail


# --------------------------------------------------------------------------- #
# subdomain_takeover.py                                                        #
# --------------------------------------------------------------------------- #

class TestSubdomainTakeover:
    async def test_critical_takeover_on_fingerprint_match(self, monkeypatch) -> None:
        # apex itself ends with a known-vuln suffix → fallback path triggers,
        # then body fingerprint confirms a claimable dangling host.
        monkeypatch.delenv("OSINT_OPSEC", raising=False)

        async def _no_cname(_host):
            return []  # no CNAME → exercises the host-suffix fallback

        monkeypatch.setattr(takeover_mod, "_resolve_cname", _no_cname)

        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="The deployment could not be found")

        _patch_client(monkeypatch, handler, takeover_mod)
        q = make_query("ghost.vercel.app")
        hits = await _consume(takeover_mod._run(q))
        crit = [h for h in hits if h.severity == Severity.CRITICAL]
        assert crit, "expected a CRITICAL takeover hit"
        assert crit[0].status == HitStatus.FOUND
        assert "TAKEOVER" in crit[0].title
        summary = next(h for h in hits if h.source == "summary")
        assert summary.extra["critical"] >= 1

    async def test_no_match_only_summary(self, monkeypatch) -> None:
        monkeypatch.delenv("OSINT_OPSEC", raising=False)

        async def _no_cname(_host):
            return []

        monkeypatch.setattr(takeover_mod, "_resolve_cname", _no_cname)
        _patch_client(monkeypatch, lambda r: httpx.Response(200, text="hello"),
                      takeover_mod)
        # plain domain, no vuln suffix → no per-host hit, just the summary
        hits = await _consume(takeover_mod._run(make_query("acme.com")))
        assert len(hits) == 1
        assert hits[0].source == "summary"
        assert hits[0].extra["found"] == 0

    async def test_opsec_mode_skips(self, monkeypatch) -> None:
        monkeypatch.setenv("OSINT_OPSEC", "1")
        monkeypatch.delenv("OSINT_SUBDOMAIN_TAKEOVER_OVER_TOR", raising=False)
        hits = await _consume(takeover_mod._run(make_query("acme.com")))
        assert hits and hits[0].status == HitStatus.SKIPPED


# --------------------------------------------------------------------------- #
# passive_dns.py                                                               #
# --------------------------------------------------------------------------- #

class TestPassiveDns:
    async def test_found_records_from_hackertarget(self, monkeypatch) -> None:
        monkeypatch.delenv("CIRCL_PDNS_AUTH", raising=False)

        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "hackertarget" in url:
                return httpx.Response(200, text="acme.com,1.2.3.4\nwww.acme.com,1.2.3.5")
            if "otx.alienvault.com" in url:
                return httpx.Response(200, json={"passive_dns": []})
            return httpx.Response(404)

        _patch_client(monkeypatch, handler, pdns_mod)
        hits = await _consume(pdns_mod.run(make_query("acme.com")))
        ht = [h for h in hits if h.source == "HackerTarget" and h.status == HitStatus.FOUND]
        assert len(ht) == 2
        assert any(h.title == "acme.com" for h in ht)
        assert all(h.severity == Severity.LOW for h in ht)

    async def test_5xx_classified_unavailable(self, monkeypatch) -> None:
        monkeypatch.delenv("CIRCL_PDNS_AUTH", raising=False)

        def handler(req: httpx.Request) -> httpx.Response:
            if "hackertarget" in str(req.url):
                return httpx.Response(503)
            if "otx" in str(req.url):
                return httpx.Response(200, json={"passive_dns": []})
            return httpx.Response(404)

        _patch_client(monkeypatch, handler, pdns_mod)
        hits = await _consume(pdns_mod.run(make_query("acme.com")))
        ht = next(h for h in hits if h.source == "HackerTarget")
        assert ht.status == HitStatus.UNAVAILABLE

    async def test_empty_is_no_data(self, monkeypatch) -> None:
        monkeypatch.delenv("CIRCL_PDNS_AUTH", raising=False)

        def handler(req: httpx.Request) -> httpx.Response:
            if "hackertarget" in str(req.url):
                return httpx.Response(200, text="")
            if "otx" in str(req.url):
                return httpx.Response(200, json={"passive_dns": []})
            return httpx.Response(404)

        _patch_client(monkeypatch, handler, pdns_mod)
        hits = await _consume(pdns_mod.run(make_query("acme.com")))
        ht = next(h for h in hits if h.source == "HackerTarget")
        otx = next(h for h in hits if h.source == "OTX passive-dns")
        assert ht.status == HitStatus.NO_DATA
        assert otx.status == HitStatus.NO_DATA
        circl = next(h for h in hits if h.source == "CIRCL pDNS")
        assert circl.status == HitStatus.SKIPPED  # no creds


# --------------------------------------------------------------------------- #
# wayback_urls.py                                                              #
# --------------------------------------------------------------------------- #

class TestWaybackUrls:
    async def test_found_interesting_urls_and_subdomains(self, monkeypatch) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=[
                ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"],
                ["k1", "2020", "https://acme.com/admin/login", "text/html", "200", "d1", "10"],
                ["k2", "2021", "https://staging.acme.com/", "text/html", "200", "d2", "10"],
                ["k3", "2021", "https://acme.com/about", "text/html", "200", "d3", "10"],
            ])

        _patch_client(monkeypatch, handler, wayback_mod)
        hits = await _consume(wayback_mod._run(make_query("acme.com")))
        interesting = [h for h in hits if h.title.startswith("historical URL")]
        assert any("/admin/login" in h.url for h in interesting)
        subs = [h for h in hits if h.title.startswith("subdomain (historical)")]
        assert any("staging.acme.com" in h.url for h in subs)
        summary = next(h for h in hits if h.severity == Severity.INFO
                       and h.extra.get("total_urls") is not None)
        assert summary.extra["total_urls"] == 3
        # /admin/login AND staging.acme.com/ (matches "/staging") are interesting
        assert summary.extra["interesting"] == 2

    async def test_no_archived_urls_is_no_data(self, monkeypatch) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=[
                ["urlkey", "timestamp", "original"],  # header only, no rows
            ])

        _patch_client(monkeypatch, handler, wayback_mod)
        hits = await _consume(wayback_mod._run(make_query("acme.com")))
        assert len(hits) == 1
        assert hits[0].status == HitStatus.NO_DATA

    async def test_non200_is_no_data(self, monkeypatch) -> None:
        _patch_client(monkeypatch, lambda r: httpx.Response(503), wayback_mod)
        hits = await _consume(wayback_mod._run(make_query("acme.com")))
        assert hits and hits[0].status == HitStatus.NO_DATA
        assert "503" in hits[0].detail
