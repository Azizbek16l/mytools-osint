"""Producer-side confidence scoring helpers.

Confidence is a per-Hit float in ``[0.0, 1.0]`` capturing the producer's belief
that the finding is real. It is intentionally orthogonal to ``Severity``:

  * severity   — *if true*, how bad is this for the target?
  * confidence — how sure are we that it *is* true?

A high-severity / low-confidence hit (e.g. "maybe leaked password") deserves a
different downstream response from a high-severity / high-confidence hit
("the password hash matches an HIBP record"). Renderers use both.

The defaults are tuned to be slightly conservative: signals that could be
explained by a misconfiguration on the target side score below 1.0 even when
present.
"""
from __future__ import annotations


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


def score_username_hit(
    *,
    code: int,
    soft_404: bool,
    strong_match: bool,
    has_og: bool,
) -> float:
    """Confidence for a username-site probe.

    Rationale:
      * ``soft_404`` body — body literally says "user not found" → 0.05.
      * ``strong_match`` (og:title / <title> contains the target) is the
        single strongest signal we get on the open web → 0.95.
      * Any 2xx with og metadata but no target string → 0.55 (likely real
        page but could be a landing/redirect).
      * Bare 2xx with no metadata at all → 0.40 (uncertain — typical SPA).
      * 4xx/5xx → close to 0 (we shouldn't call this FOUND).
    """
    if soft_404:
        return 0.05
    if strong_match:
        return 0.95
    if 200 <= code < 300:
        if has_og:
            return 0.55
        return 0.40
    if 300 <= code < 400:
        return 0.35
    return 0.10


def score_domain_dns_hit(record_type: str, present: bool) -> float:
    """Confidence for a DNS lookup result.

    DNS answers are authoritative when ``present`` is true, but the
    confidence varies by record type — an A record means the host genuinely
    exists; an SOA/CAA only confirms the zone, not the host of interest.
    """
    if not present:
        return 0.0
    rt = (record_type or "").upper()
    if rt in ("A", "AAAA"):
        return 0.99
    if rt in ("MX", "NS"):
        return 0.95
    if rt in ("CNAME",):
        return 0.90
    if rt in ("TXT",):
        return 0.80
    return 0.70


def score_subdomain_hit(*, num_sources: int) -> float:
    """Confidence for a passively-discovered subdomain.

    Cross-source agreement is the single biggest tell that a subdomain is
    real and not a stale CT entry. Saturates fast — three sources is plenty.
    """
    if num_sources <= 0:
        return 0.0
    return _clamp(0.55 + 0.18 * num_sources)


def score_breach_hit(*, source_authoritative: bool, has_password: bool) -> float:
    """Confidence for a breach / leaked credential hit.

    Authoritative breach APIs (HIBP, ProxyNova exact match) are extremely
    reliable. Substring / fuzzy matches against combo lists need the caller
    to verify the email side is an exact match before bumping confidence.
    """
    if source_authoritative and has_password:
        return 0.98
    if source_authoritative:
        return 0.90
    if has_password:
        return 0.70
    return 0.50


def score_email_format_hit(*, format_valid: bool, mx_present: bool) -> float:
    """Confidence that an address can plausibly receive mail."""
    if not format_valid:
        return 0.05
    return 0.95 if mx_present else 0.55
