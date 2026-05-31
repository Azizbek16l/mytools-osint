"""Hermetic UX tests for the local web dashboard + HTML report (WP-B).

No network, no asyncio server — we exercise the pure render/serialisation
helpers directly:

  * html_report.render_report() must surface confidence + evidence, a severity
    glyph (non-colour cue), a print stylesheet, and responsive breakpoints.
  * web.py's option builders must list every QueryKind (incl. Wave C) and every
    user-selectable profile (incl. dossier + active-recon), imported from the
    real registries — never hand-drifted literals.
  * the SSE hit payload must carry confidence + evidence.
"""
from __future__ import annotations

import json

from app.core.profiles import PROFILES
from app.core.types import (
    Hit,
    HitStatus,
    Query,
    QueryKind,
    QueryResult,
    Severity,
)
from app.ui import web
from app.ui.html_report import render_report


def _sample_result() -> tuple[Query, QueryResult]:
    q = Query(kind=QueryKind.DOMAIN, value="example.com")
    hits = [
        Hit(
            module="dns",
            source="dns-a",
            category="infra",
            status=HitStatus.FOUND,
            severity=Severity.CRITICAL,
            title="A record",
            detail="resolves to 93.184.216.34",
            url="https://example.com",
            latency_ms=42,
            confidence=0.93,
            evidence={"http_status": "200", "matched": "og:title contains target"},
        ),
        Hit(
            module="dns",
            source="dns-mx",
            category="infra",
            status=HitStatus.NO_DATA,
            severity=Severity.INFO,
            detail="no MX",
            latency_ms=11,
            confidence=0.2,
        ),
    ]
    return q, QueryResult(query=q, hits=hits)


# --------------------------------------------------------------------------- #
# HTML report
# --------------------------------------------------------------------------- #

def test_report_renders_confidence_value_and_bar():
    q, result = _sample_result()
    html = render_report(q, result, elapsed_ms=1234)
    # 0.93 -> 93%, 0.20 -> 20% confidence cells must appear.
    assert "93%" in html
    assert "20%" in html
    assert 'class="confidence"' in html
    assert 'role="meter"' in html


def test_report_renders_evidence_signals():
    q, result = _sample_result()
    html = render_report(q, result, elapsed_ms=10)
    assert "evidence" in html
    assert "http_status" in html
    assert "og:title contains target" in html


def test_report_severity_not_colour_only():
    """Each severity carries a distinct glyph so colour is not the sole cue."""
    q, result = _sample_result()
    html = render_report(q, result, elapsed_ms=10)
    assert 'class="sev-g"' in html
    # critical glyph (◆) present for the critical hit.
    assert "◆" in html


def test_report_is_responsive_and_printable():
    q, result = _sample_result()
    html = render_report(q, result, elapsed_ms=10)
    assert "@media (max-width:720px)" in html
    assert "@media print" in html
    assert "print-color-adjust:exact" in html
    # KPI grid must collapse off the fixed 6-col layout on narrow viewports.
    assert "auto-fit" in html


def test_report_has_sort_and_filter_controls():
    q, result = _sample_result()
    html = render_report(q, result, elapsed_ms=10)
    assert 'class="th-sort"' in html
    assert 'id="flt-pos"' in html
    assert 'id="flt-crit"' in html
    assert 'data-sevrank=' in html


def test_report_rejects_non_http_url_as_link():
    q = Query(kind=QueryKind.USERNAME, value="bob")
    bad = Hit(
        module="m",
        source="s",
        status=HitStatus.FOUND,
        severity=Severity.LOW,
        url="javascript:alert(1)",
        detail="x",
    )
    html = render_report(q, QueryResult(query=q, hits=[bad]), elapsed_ms=1)
    # the scheme-checked href must never embed a javascript: anchor.
    assert 'href="javascript:' not in html
    assert "<script>alert" not in html


# --------------------------------------------------------------------------- #
# Dashboard option builders (no hand-drift from the real registries)
# --------------------------------------------------------------------------- #

def test_dashboard_kind_select_lists_every_kind_incl_wave_c():
    opts = web._kind_options()
    for kind in QueryKind:
        assert f">{kind.value}<" in opts, f"missing kind {kind.value}"
    # Wave C kinds explicitly reachable.
    assert "wallet" in opts
    assert "image" in opts
    assert "company" in opts
    assert 'optgroup label="Wave C"' in opts


def test_dashboard_profile_select_lists_dossier_and_active_recon():
    opts = web._profile_options()
    assert ">dossier<" in opts
    assert ">active-recon<" in opts
    # every user-selectable profile present; aliases hidden.
    for name in PROFILES:
        if name in ("default", "all"):
            assert f">{name}<" not in opts
        else:
            assert f">{name}<" in opts, f"missing profile {name}"


def test_index_html_injects_options_and_token():
    web._TOKEN = "test-token-123"
    body = (
        web._HTML.replace("__KIND_OPTIONS__", web._kind_options())
        .replace("__PROFILE_OPTIONS__", web._profile_options())
        .replace("__TOKEN__", web._TOKEN)
    )
    assert "__KIND_OPTIONS__" not in body
    assert "__PROFILE_OPTIONS__" not in body
    assert "__TOKEN__" not in body
    assert "company" in body
    assert "active-recon" in body
    # dashboard renders confidence + evidence client-side.
    assert "confidence" in body
    assert "evidence" in body


# --------------------------------------------------------------------------- #
# SSE hit payload
# --------------------------------------------------------------------------- #

def test_hit_event_carries_confidence_and_evidence():
    q, result = _sample_result()
    h = result.hits[0]
    raw = web._hit_event(h, q)
    assert raw.startswith(b"event: hit\ndata: ")
    payload = json.loads(raw.split(b"data: ", 1)[1].strip())
    assert payload["confidence"] == 0.93
    assert payload["evidence"]["http_status"] == "200"
    assert payload["status"] == "found"
    assert payload["severity"] == "critical"
