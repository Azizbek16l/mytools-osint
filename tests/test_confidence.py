"""Confidence scoring + provenance — hermetic.

Tests the pure scoring helpers and verifies `probe_site` produces
high-confidence hits on strong matches and low-confidence on bare 2xx.
"""
from __future__ import annotations

import httpx
import pytest

from app.core.confidence import (
    score_breach_hit,
    score_domain_dns_hit,
    score_email_format_hit,
    score_subdomain_hit,
    score_username_hit,
)
from app.core.json_schema import (
    JSON_SCHEMA_VERSION,
    serialize_query_result,
    validate_schema,
)
from app.core.types import Hit, HitStatus, Query, QueryKind, QueryResult, Severity

# --------------------------------------------------------------------------- #
# Pure scoring helpers
# --------------------------------------------------------------------------- #

def test_score_username_strong_match_high():
    s = score_username_hit(code=200, soft_404=False, strong_match=True, has_og=True)
    assert s >= 0.9


def test_score_username_bare_200_low():
    """Bare 200 with no metadata is uncertain — not a confident FOUND."""
    s = score_username_hit(code=200, soft_404=False, strong_match=False, has_og=False)
    assert s < 0.5


def test_score_username_soft_404_near_zero():
    s = score_username_hit(code=200, soft_404=True, strong_match=False, has_og=True)
    assert s <= 0.1


def test_score_username_4xx_low():
    assert score_username_hit(code=404, soft_404=False, strong_match=False,
                              has_og=False) <= 0.2


def test_score_dns_a_record_high():
    assert score_domain_dns_hit("A", present=True) >= 0.95


def test_score_dns_absent_zero():
    assert score_domain_dns_hit("A", present=False) == 0.0


def test_score_dns_unknown_record_default():
    assert 0.5 < score_domain_dns_hit("SRV", present=True) < 1.0


def test_score_subdomain_more_sources_higher():
    a = score_subdomain_hit(num_sources=1)
    b = score_subdomain_hit(num_sources=3)
    assert a < b <= 1.0


def test_score_subdomain_zero_sources():
    assert score_subdomain_hit(num_sources=0) == 0.0


def test_score_breach_authoritative_with_password_top():
    assert score_breach_hit(source_authoritative=True, has_password=True) >= 0.95


def test_score_breach_uncertain_default_midrange():
    s = score_breach_hit(source_authoritative=False, has_password=False)
    assert 0.3 < s < 0.7


def test_score_email_invalid_format_near_zero():
    assert score_email_format_hit(format_valid=False, mx_present=False) <= 0.1


def test_score_email_valid_mx_high():
    assert score_email_format_hit(format_valid=True, mx_present=True) >= 0.9


# --------------------------------------------------------------------------- #
# probe_site: confidence drops on bare 200, climbs on strong match
# --------------------------------------------------------------------------- #

def _patch_http(monkeypatch, handler):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)

    async def _fake():
        return client

    monkeypatch.setattr("app.core.http.get_client", _fake)
    from app.modules import base as base_mod
    monkeypatch.setattr(base_mod, "get_client", _fake)
    return client


@pytest.mark.asyncio
async def test_probe_site_strong_match_high_confidence(monkeypatch):
    from app.modules.base import probe_site

    def handler(req: httpx.Request) -> httpx.Response:
        # 200 with a profile-style og:title that mentions the target
        body = '<html><head><meta property="og:title" content="alice on Example">'\
               '</head></html>'
        return httpx.Response(200, content=body.encode(),
                              headers={"content-type": "text/html"})

    _patch_http(monkeypatch, handler)
    hit = await probe_site(
        {"name": "Example", "url": "https://example.com/{}", "good_status": [200]},
        target="alice", module="username",
    )
    assert hit.status == HitStatus.FOUND
    assert hit.confidence >= 0.9
    assert hit.evidence
    assert hit.evidence["http_status"] == "200"
    assert hit.evidence["strong_match"] == "true"


@pytest.mark.asyncio
async def test_probe_site_bare_200_uncertain(monkeypatch):
    from app.modules.base import probe_site

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html><body>hi</body></html>",
                              headers={"content-type": "text/html"})

    _patch_http(monkeypatch, handler)
    hit = await probe_site(
        {"name": "Example", "url": "https://example.com/{}"},
        target="alice", module="username",
    )
    assert hit.status == HitStatus.UNCERTAIN
    assert hit.confidence < 0.5
    assert hit.evidence["strong_match"] == "false"


# --------------------------------------------------------------------------- #
# JSON serialisation roundtrip — v1.1
# --------------------------------------------------------------------------- #

def test_schema_version_bumped():
    assert JSON_SCHEMA_VERSION == "1.1"


def test_hit_serialises_confidence_and_provenance():
    h = Hit(
        module="m", source="s", status=HitStatus.FOUND,
        confidence=0.87, evidence={"http_status": "200", "matched": "og:title"},
    )
    q = Query(kind=QueryKind.USERNAME, value="x")
    payload = serialize_query_result(QueryResult(query=q, hits=[h]))
    validate_schema(payload)
    h0 = payload["hits"][0]
    assert h0["confidence"] == 0.87
    assert h0["provenance"] == {"http_status": "200", "matched": "og:title"}


def test_sort_orders_by_confidence_within_severity():
    hits = [
        Hit(module="m", source="a", status=HitStatus.FOUND, severity=Severity.HIGH,
            confidence=0.50),
        Hit(module="m", source="b", status=HitStatus.FOUND, severity=Severity.HIGH,
            confidence=0.95),
    ]
    q = Query(kind=QueryKind.USERNAME, value="x")
    payload = serialize_query_result(QueryResult(query=q, hits=hits))
    # Same severity → higher confidence first
    assert payload["hits"][0]["source"] == "b"
    assert payload["hits"][1]["source"] == "a"
