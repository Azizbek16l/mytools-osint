"""Offline unit tests for the red-team module additions.

Network is mocked via httpx.MockTransport where we exercise the HTTP path,
otherwise we test the pure-Python helpers (typosquat candidate generation,
favicon mmh3 hash, profile dispatch).
"""
from __future__ import annotations

import asyncio

import httpx
import pytest

from app.core.profiles import PROFILES, apply_profile, list_profiles
from app.core.runner import Runner
from app.core.types import HitStatus, Query, QueryKind
from app.modules import (
    email_security,
    internetdb,
    pgp_keys,
    takeover,
    threat_intel,
    tor_check,
    typosquat,
    web_recon,
)

# ---------- helpers ---------------------------------------------------------

def _consume(agen) -> list:
    async def _go():
        out = []
        async for h in agen:
            out.append(h)
        return out
    return asyncio.run(_go())


def _patch_client(monkeypatch, handler):
    """Install a mocked httpx.AsyncClient for the duration of one test."""
    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport, timeout=5.0)

    async def _fake_get_client():
        return client

    monkeypatch.setattr("app.core.http.get_client", _fake_get_client)
    monkeypatch.setattr("app.modules.internetdb.get_client", _fake_get_client)
    monkeypatch.setattr("app.modules.threat_intel.get_client", _fake_get_client)
    monkeypatch.setattr("app.modules.takeover.get_client", _fake_get_client)
    monkeypatch.setattr("app.modules.web_recon.get_client", _fake_get_client)
    monkeypatch.setattr("app.modules.pgp_keys.get_client", _fake_get_client)
    monkeypatch.setattr("app.modules.tor_check.get_client", _fake_get_client)
    monkeypatch.setattr("app.modules.email_security.get_client", _fake_get_client)
    return client


# ---------- typosquat -------------------------------------------------------

class TestTyposquat:
    def test_generator_returns_capped_sane_list(self) -> None:
        cands = typosquat.generate_candidates("example.com")
        assert 50 < len(cands) <= 160
        # Must NOT include the original.
        assert "example.com" not in cands
        # Must include some obvious typos.
        assert "examle.com" in cands or "exampl.com" in cands or "example.co" in cands

    def test_generator_idn_safe(self) -> None:
        # Non-ASCII root should be rejected gracefully.
        assert typosquat.generate_candidates("hellö.com") == []

    def test_no_op_on_non_domain(self) -> None:
        q = Query(kind=QueryKind.USERNAME, value="torvalds")
        assert _consume(typosquat.run(q)) == []


# ---------- profiles --------------------------------------------------------

class TestProfiles:
    def test_known_profiles_exist(self) -> None:
        for name in ("quick", "deep", "red-team", "blue-team",
                     "person", "domain-recon", "ioc", "default"):
            assert name in PROFILES, f"missing profile {name}"

    def test_apply_unknown_profile_raises(self) -> None:
        r = Runner()
        r.register("dummy", [QueryKind.USERNAME],
                   lambda q: (yield from ()))
        with pytest.raises(ValueError):
            apply_profile(r, "nope")

    def test_list_profiles_shape(self) -> None:
        rows = list_profiles()
        assert all(len(row) == 3 for row in rows)
        names = [r[0] for r in rows]
        assert "red-team" in names

    def test_apply_red_team_disables_unrelated(self) -> None:
        r = Runner()

        async def fake(q):
            if False:  # type: ignore
                yield

        r.register("typosquat", [QueryKind.DOMAIN], fake)
        r.register("phone", [QueryKind.PHONE], fake)
        enabled, disabled = apply_profile(r, "red-team")
        assert "typosquat" in enabled
        assert "phone" in disabled


# ---------- internetdb ------------------------------------------------------

class TestInternetDB:
    def test_ip_with_ports_and_vulns(self, monkeypatch) -> None:
        def handler(req):
            assert "internetdb.shodan.io/8.8.8.8" in str(req.url)
            return httpx.Response(200, json={
                "ip": "8.8.8.8",
                "ports": [53, 443],
                "hostnames": ["dns.google"],
                "cpes": [],
                "vulns": ["CVE-2024-0001"],
                "tags": ["dns"],
            })
        _patch_client(monkeypatch, handler)
        hits = _consume(internetdb.run(Query(kind=QueryKind.IP, value="8.8.8.8")))
        assert len(hits) == 1
        h = hits[0]
        assert h.status == HitStatus.FOUND
        assert "CVE-2024-0001" in h.detail
        assert h.extra["vulns"] == ["CVE-2024-0001"]

    def test_ip_not_indexed_returns_no_data(self, monkeypatch) -> None:
        _patch_client(monkeypatch, lambda req: httpx.Response(404))
        hits = _consume(internetdb.run(Query(kind=QueryKind.IP, value="1.2.3.4")))
        assert hits[0].status == HitStatus.NO_DATA

    def test_skips_non_ip_non_domain(self, monkeypatch) -> None:
        _patch_client(monkeypatch, lambda req: httpx.Response(200, json={}))
        hits = _consume(internetdb.run(Query(kind=QueryKind.USERNAME, value="x")))
        assert hits == []


# ---------- threat_intel ----------------------------------------------------

class TestThreatIntel:
    def test_skips_when_no_key(self, monkeypatch) -> None:
        monkeypatch.delenv("ABUSE_CH_API_KEY", raising=False)
        _patch_client(monkeypatch, lambda req: httpx.Response(200))
        hits = _consume(threat_intel.run(Query(kind=QueryKind.IP, value="1.1.1.1")))
        # URLhaus + ThreatFox both SKIPPED (no key); no PhishTank for IP.
        statuses = [h.status for h in hits]
        assert HitStatus.SKIPPED in statuses

    def test_urlhaus_hit_with_key(self, monkeypatch) -> None:
        monkeypatch.setenv("ABUSE_CH_API_KEY", "fake")

        def handler(req):
            if "urlhaus-api" in str(req.url):
                return httpx.Response(200, json={
                    "query_status": "ok",
                    "urls": [{"url_status": "online", "threat": "malware_download",
                              "tags": ["emotet"]}],
                })
            if "threatfox-api" in str(req.url):
                return httpx.Response(200, json={"query_status": "no_result"})
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = _consume(threat_intel.run(Query(kind=QueryKind.IP, value="1.1.1.1")))
        urlhaus_hits = [h for h in hits if h.source == "URLhaus"]
        assert urlhaus_hits and urlhaus_hits[0].status == HitStatus.FOUND
        assert urlhaus_hits[0].severity.value == "critical"


# ---------- takeover --------------------------------------------------------

class TestTakeover:
    def test_fingerprint_match(self) -> None:
        fp = takeover._match_service(["x.s3.amazonaws.com"])
        assert fp and fp["service"] == "AWS S3"
        fp = takeover._match_service(["app.vercel.app"])
        assert fp and fp["service"] == "Vercel"
        assert takeover._match_service(["example.com"]) is None


# ---------- web_recon -------------------------------------------------------

class TestWebRecon:
    def test_secret_pattern_detects_aws(self) -> None:
        text = 'const k = "AKIAIOSFODNN7EXAMPLE"; // not real'
        found = web_recon._scan_text(text, "test")
        names = [n for n, _ in found]
        assert "AWS Access Key" in names

    def test_secret_pattern_detects_github_pat(self) -> None:
        text = "token = ghp_" + "A" * 36
        names = [n for n, _ in web_recon._scan_text(text, "x")]
        assert "GitHub PAT" in names

    def test_favicon_hash_deterministic(self) -> None:
        # Sanity test against canonical mmh3.hash(seed=0) outputs.
        # Computed via reference C++ implementation; pinning so a future
        # tweak to _mmh3_x86_32 can't silently change the hash.
        assert web_recon._mmh3_x86_32(b"hello world") == 1586663183
        assert web_recon._mmh3_x86_32(b"") == 0
        assert web_recon._mmh3_x86_32(b"hello world") == web_recon._mmh3_x86_32(b"hello world")
        assert web_recon._mmh3_x86_32(b"a") != web_recon._mmh3_x86_32(b"b")


# ---------- email_security --------------------------------------------------

class TestEmailSecurity:
    def test_spf_grading(self) -> None:
        g, _, _ = email_security._grade_spf(["v=spf1 -all"])
        assert g == "A"
        g, _, _ = email_security._grade_spf(["v=spf1 +all"])
        assert g == "F"
        g, _, _ = email_security._grade_spf([])
        assert g == "F"
        g, _, _ = email_security._grade_spf(["v=spf1 ~all", "v=spf1 -all"])
        assert g == "D"  # multiple SPFs

    def test_dmarc_grading(self) -> None:
        g, _, _ = email_security._grade_dmarc(["v=DMARC1; p=reject;"])
        assert g == "A"
        g, _, _ = email_security._grade_dmarc(["v=DMARC1; p=quarantine; pct=100;"])
        assert g == "B"
        g, _, _ = email_security._grade_dmarc(["v=DMARC1; p=none;"])
        assert g == "D"
        g, _, _ = email_security._grade_dmarc([])
        assert g == "F"


# ---------- pgp_keys --------------------------------------------------------

class TestPgpKeys:
    def test_openpgp_found(self, monkeypatch) -> None:
        def handler(req):
            if "keys.openpgp.org" in str(req.url):
                return httpx.Response(200, text="-----BEGIN PGP PUBLIC KEY BLOCK-----\nkey\n-----END PGP PUBLIC KEY BLOCK-----")
            if "keyserver.ubuntu.com" in str(req.url):
                return httpx.Response(200, text="No results found")
            return httpx.Response(404)
        _patch_client(monkeypatch, handler)
        hits = _consume(pgp_keys.run(Query(kind=QueryKind.EMAIL, value="x@y.z")))
        openpgp_hits = [h for h in hits if h.source == "keys.openpgp.org"]
        assert openpgp_hits and openpgp_hits[0].status == HitStatus.FOUND


# ---------- tor_check -------------------------------------------------------

class TestTor:
    def test_known_relay(self, monkeypatch) -> None:
        _patch_client(monkeypatch, lambda r: httpx.Response(200, json={
            "relays": [{"nickname": "TestRelay", "flags": ["Exit", "Fast"],
                        "country": "us", "last_seen": "2026-01-01"}]
        }))
        hits = _consume(tor_check.run(Query(kind=QueryKind.IP, value="1.2.3.4")))
        assert hits[0].status == HitStatus.FOUND
        assert hits[0].extra["is_exit"] is True

    def test_unknown_ip(self, monkeypatch) -> None:
        _patch_client(monkeypatch, lambda r: httpx.Response(200, json={"relays": []}))
        hits = _consume(tor_check.run(Query(kind=QueryKind.IP, value="1.2.3.4")))
        assert hits[0].status == HitStatus.NO_DATA
