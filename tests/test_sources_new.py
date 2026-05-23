"""Coverage for the new free OSINT sources added in this sprint.

Network is mocked at the httpx layer via `httpx.MockTransport`. Each module
imports `get_client` into its own namespace at import time, so we patch the
name *in every consumer module* — not just `app.core.http` — to redirect all
HTTP traffic deterministically.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Callable

import httpx
import pytest

from app.core import http as http_mod
from app.core.types import HitStatus, Query, QueryKind, Severity
from app.modules import email_extras, ip_extras

# Modules under test that captured `get_client` at import time.
_PATCH_TARGETS = (http_mod, email_extras, ip_extras)


# ---- shared mock-client harness -------------------------------------------

@pytest.fixture
def mock_client(monkeypatch: pytest.MonkeyPatch) -> Callable[[Callable[[httpx.Request], httpx.Response]], None]:
    """Yield a setter that installs a MockTransport-backed client.

    Usage:
        def test_x(mock_client):
            mock_client(lambda req: httpx.Response(200, json={...}))
            ...
    """

    def install(handler: Callable[[httpx.Request], httpx.Response]) -> None:
        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport, timeout=5)

        async def _get_client() -> httpx.AsyncClient:
            return client

        for tgt in _PATCH_TARGETS:
            monkeypatch.setattr(tgt, "get_client", _get_client, raising=False)

    yield install


# ---- HIBP breach catalog (free, no key) -----------------------------------

@pytest.mark.asyncio
async def test_hibp_catalog_returns_breaches(mock_client):
    captured: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        url = str(req.url)
        if "haveibeenpwned" in url:
            captured["url"] = url
            return httpx.Response(200, json=[
                {"Name": "Adobe", "Title": "Adobe", "BreachDate": "2013-10-04",
                 "DataClasses": ["Email addresses", "Password hints"]},
                {"Name": "LinkedIn", "Title": "LinkedIn", "BreachDate": "2012-05-05",
                 "DataClasses": ["Email addresses", "Passwords"], "IsSensitive": False},
            ])
        # EmailRep — return a minimal valid dict so it doesn't trip up the
        # downstream parser.
        return httpx.Response(200, json={
            "reputation": "none", "suspicious": False, "details": {"profiles": []},
        })

    mock_client(handler)
    q = Query(kind=QueryKind.EMAIL, value="user@example.com")
    hits = [h async for h in email_extras.run(q)]

    assert "domain=example.com" in captured["url"]
    # 1 summary hit + 2 individual hits
    sources = [h.source for h in hits]
    assert "HIBP catalog" in sources
    assert any(s.startswith("HIBP catalog:Adobe") for s in sources)
    assert any(s.startswith("HIBP catalog:LinkedIn") for s in sources)
    # the summary hit is severity MEDIUM, individual ones LOW or MEDIUM
    summary_hits = [h for h in hits if h.source == "HIBP catalog"]
    assert summary_hits[0].status == HitStatus.FOUND
    assert summary_hits[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_hibp_catalog_no_data(mock_client):
    def handler(req: httpx.Request) -> httpx.Response:
        if "haveibeenpwned" in str(req.url):
            return httpx.Response(200, json=[])
        return httpx.Response(200, json={"reputation": "none", "suspicious": False,
                                         "details": {"profiles": []}})

    mock_client(handler)
    q = Query(kind=QueryKind.EMAIL, value="user@example.com")
    hits = [h async for h in email_extras.run(q) if h.module == "email_extras"]
    catalog = [h for h in hits if h.source == "HIBP catalog"]
    assert catalog and catalog[0].status == HitStatus.NO_DATA


@pytest.mark.asyncio
async def test_hibp_catalog_handles_5xx(mock_client):
    mock_client(lambda req: httpx.Response(503))
    q = Query(kind=QueryKind.EMAIL, value="user@example.com")
    hits = [h async for h in email_extras.run(q)]
    cat = [h for h in hits if h.source == "HIBP catalog"]
    assert cat and cat[0].status == HitStatus.UNAVAILABLE


# ---- EmailRep -------------------------------------------------------------

@pytest.mark.asyncio
async def test_emailrep_clean_account(mock_client):
    def handler(req: httpx.Request) -> httpx.Response:
        if "haveibeenpwned" in str(req.url):
            return httpx.Response(200, json=[])
        return httpx.Response(200, json={
            "email": "good@example.com",
            "reputation": "high",
            "suspicious": False,
            "details": {"blacklisted": False, "malicious_activity": False,
                        "profiles": ["github", "twitter"], "references": 12},
        })

    mock_client(handler)
    q = Query(kind=QueryKind.EMAIL, value="good@example.com")
    hits = [h async for h in email_extras.run(q)]
    er = [h for h in hits if h.source == "emailrep.io"]
    assert er and er[0].status == HitStatus.FOUND
    assert er[0].severity == Severity.LOW
    # both linked profiles surface as their own LOW hits
    profile_sources = [h.source for h in hits if h.source.startswith("emailrep:")]
    assert "emailrep:github" in profile_sources
    assert "emailrep:twitter" in profile_sources


@pytest.mark.asyncio
async def test_emailrep_suspicious(mock_client):
    def handler(req: httpx.Request) -> httpx.Response:
        if "haveibeenpwned" in str(req.url):
            return httpx.Response(200, json=[])
        return httpx.Response(200, json={
            "reputation": "low", "suspicious": True,
            "details": {"blacklisted": True, "profiles": []},
        })

    mock_client(handler)
    q = Query(kind=QueryKind.EMAIL, value="sus@example.com")
    hits = [h async for h in email_extras.run(q)]
    er = next(h for h in hits if h.source == "emailrep.io")
    assert er.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_emailrep_ratelimit(mock_client):
    def handler(req: httpx.Request) -> httpx.Response:
        if "haveibeenpwned" in str(req.url):
            return httpx.Response(200, json=[])
        return httpx.Response(429)

    mock_client(handler)
    q = Query(kind=QueryKind.EMAIL, value="a@example.com")
    hits = [h async for h in email_extras.run(q)]
    er = next(h for h in hits if h.source == "emailrep.io")
    assert er.status == HitStatus.RATELIMITED


# ---- GreyNoise community --------------------------------------------------

@pytest.mark.asyncio
async def test_greynoise_malicious_ip(mock_client):
    def handler(req: httpx.Request) -> httpx.Response:
        url = str(req.url)
        if "greynoise" in url:
            return httpx.Response(200, json={
                "ip": "1.2.3.4", "noise": True, "riot": False,
                "classification": "malicious", "name": "Mirai", "last_seen": "2026-05-22",
                "link": "https://viz.greynoise.io/ip/1.2.3.4",
            })
        if "spamhaus" in url:
            return httpx.Response(200, text="; comment\n5.6.7.0/24 ; SBL1\n")
        return httpx.Response(404)

    mock_client(handler)
    q = Query(kind=QueryKind.IP, value="1.2.3.4")
    hits = [h async for h in ip_extras.run(q)]
    gn = next(h for h in hits if h.source == "GreyNoise community")
    assert gn.status == HitStatus.FOUND
    assert gn.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_greynoise_unknown_ip(mock_client):
    def handler(req: httpx.Request) -> httpx.Response:
        if "greynoise" in str(req.url):
            return httpx.Response(404)
        if "spamhaus" in str(req.url):
            return httpx.Response(200, text="; header\n")
        return httpx.Response(404)

    mock_client(handler)
    q = Query(kind=QueryKind.IP, value="9.9.9.9")
    hits = [h async for h in ip_extras.run(q)]
    gn = next(h for h in hits if h.source == "GreyNoise community")
    assert gn.status == HitStatus.NOT_FOUND


# ---- Spamhaus DROP --------------------------------------------------------

@pytest.mark.asyncio
async def test_spamhaus_ip_in_drop(mock_client, monkeypatch):
    # Bust the in-memory cache so the second test isn't polluted.
    monkeypatch.setattr(ip_extras, "_DROP_CACHE",
                        {"expires": 0.0, "networks": []})

    def handler(req: httpx.Request) -> httpx.Response:
        url = str(req.url)
        if "spamhaus" in url:
            return httpx.Response(200, text=(
                "; comment\n"
                "1.2.3.0/24 ; SBL00001\n"
                "10.10.0.0/16 ; SBL00002\n"
            ))
        if "greynoise" in url:
            return httpx.Response(404)
        return httpx.Response(404)

    mock_client(handler)
    q = Query(kind=QueryKind.IP, value="10.10.5.5")
    hits = [h async for h in ip_extras.run(q)]
    sp = next(h for h in hits if h.source == "Spamhaus DROP")
    assert sp.status == HitStatus.FOUND
    assert sp.severity == Severity.HIGH
    assert "10.10.0.0/16" in sp.title


@pytest.mark.asyncio
async def test_spamhaus_ipv6_skipped(mock_client, monkeypatch):
    monkeypatch.setattr(ip_extras, "_DROP_CACHE",
                        {"expires": 0.0, "networks": []})

    def handler(req: httpx.Request) -> httpx.Response:
        if "greynoise" in str(req.url):
            return httpx.Response(404)
        return httpx.Response(200, text="; empty\n")

    mock_client(handler)
    q = Query(kind=QueryKind.IP, value="2001:db8::1")
    hits = [h async for h in ip_extras.run(q)]
    sp = next(h for h in hits if h.source == "Spamhaus DROP")
    assert sp.status == HitStatus.SKIPPED


# ---- AbuseIPDB ------------------------------------------------------------

@pytest.mark.asyncio
async def test_abuseipdb_skipped_without_key(mock_client, monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.setattr(ip_extras, "_DROP_CACHE",
                        {"expires": 0.0, "networks": []})

    def handler(req: httpx.Request) -> httpx.Response:
        if "abuseipdb" in str(req.url):
            # If we reach here, the module didn't skip — fail the test.
            return httpx.Response(500)
        return httpx.Response(404)

    mock_client(handler)
    q = Query(kind=QueryKind.IP, value="8.8.8.8")
    hits = [h async for h in ip_extras.run(q)]
    ab = next(h for h in hits if h.source == "AbuseIPDB")
    assert ab.status == HitStatus.SKIPPED
    assert "ABUSEIPDB_API_KEY" in ab.detail


@pytest.mark.asyncio
async def test_abuseipdb_high_confidence(mock_client, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setattr(ip_extras, "_DROP_CACHE",
                        {"expires": 0.0, "networks": []})

    def handler(req: httpx.Request) -> httpx.Response:
        url = str(req.url)
        if "abuseipdb" in url:
            assert req.headers.get("Key") == "test-key"
            return httpx.Response(200, json={"data": {
                "abuseConfidenceScore": 95, "totalReports": 42,
                "countryCode": "RU", "isp": "Evil Corp", "usageType": "Data Center",
            }})
        if "spamhaus" in url:
            return httpx.Response(200, text="; nothing\n")
        return httpx.Response(404)  # greynoise

    mock_client(handler)
    q = Query(kind=QueryKind.IP, value="6.6.6.6")
    hits = [h async for h in ip_extras.run(q)]
    ab = next(h for h in hits if h.source == "AbuseIPDB")
    assert ab.status == HitStatus.FOUND
    assert ab.severity == Severity.HIGH
    assert "95/100" in ab.title


# ---- non-IP input is a no-op ---------------------------------------------

@pytest.mark.asyncio
async def test_ip_extras_skips_non_ip_input():
    """No HTTP fixture needed — the module short-circuits before any I/O."""
    q = Query(kind=QueryKind.IP, value="not.an.ip")
    hits = [h async for h in ip_extras.run(q)]
    assert hits == []


def test_module_registers():
    """Smoke check — both new modules implement the `register` contract."""
    from app.core.runner import Runner
    r = Runner()
    email_extras.register(r)
    ip_extras.register(r)
    names = [m.name for m in r.all_modules()]
    assert "email_extras" in names
    assert "ip_extras" in names


@pytest.mark.asyncio
async def test_spamhaus_cache_loads_v4_only(mock_client, monkeypatch):
    """Parser drops malformed CIDRs and tolerates the comment-prefix lines."""
    monkeypatch.setattr(ip_extras, "_DROP_CACHE",
                        {"expires": 0.0, "networks": []})
    mock_client(lambda req: httpx.Response(200, text=(
        "; this is a comment\n"
        "192.0.2.0/24 ; SBL1\n"
        "garbage line\n"
        "203.0.113.0/24 ; SBL2\n"
    )))
    networks, detail = await ip_extras._load_spamhaus_drop()
    assert ipaddress.ip_network("192.0.2.0/24") in networks
    assert ipaddress.ip_network("203.0.113.0/24") in networks
    assert len(networks) == 2
    assert "loaded" in detail
