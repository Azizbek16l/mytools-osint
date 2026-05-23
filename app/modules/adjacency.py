"""Adjacent-search hook — surface follow-up queries after username lookups.

After the primary username scan, this module re-probes a tiny set of
high-signal sites (GitHub HTML profile + Keybase `proofs.json`) directly,
looking for "what should we look up NEXT?" pivots:

  * GitHub profile page often advertises an email or a personal blog URL.
  * Keybase publishes a machine-readable list of linked accounts (Twitter,
    Reddit, HN, web, BTC address, etc.) — each one is a candidate pivot.

We DO NOT auto-fire follow-up scans — emitted hits carry source/category
labels that the UI/CLI can later expose as one-click suggestions.

Output rules (per Item 5 of the sprint):
  * source = "adjacent suggestion · <where-from>"
  * severity = LOW (or UNCERTAIN status for low-confidence finds)
  * `extra.suggested_kind` = the QueryKind the human should look up next
  * `extra.suggested_value` = the candidate value
  * total emitted per query ≤ 3
"""
from __future__ import annotations

import re
from collections.abc import AsyncIterator
from typing import Any

from app.core.classify import classify_exception, classify_http
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

from .base import clean_username

NAME = "adjacency"
MAX_ADJACENT_HITS = 3

# A handful of robust extractors for GitHub's server-rendered profile page.
# GitHub HTML can change without notice; each pattern is independently optional.
_GH_EMAIL_PATTERNS = (
    re.compile(r'<a[^>]+href=["\']mailto:([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'<li\b[^>]*itemprop=["\']email["\'][^>]*>\s*<a[^>]+>([^<]+)</a>',
               re.IGNORECASE | re.DOTALL),
)
_GH_BLOG_PATTERN = re.compile(
    r'<li\b[^>]*itemprop=["\']url["\'][^>]*>\s*<a[^>]+href=["\']([^"\']+)["\']',
    re.IGNORECASE | re.DOTALL,
)
_GH_TWITTER_PATTERN = re.compile(
    r'<a\b[^>]+href=["\']https?://twitter\.com/([A-Za-z0-9_]{1,15})["\']',
    re.IGNORECASE,
)


def _adjacency_hit(
    *,
    where: str,
    kind: QueryKind,
    value: str,
    detail: str,
    url: str,
    confidence: str = "low",
) -> Hit:
    """Build a stable, labelled 'adjacent suggestion' Hit."""
    status = HitStatus.UNCERTAIN if confidence == "low" else HitStatus.FOUND
    return Hit(
        module=NAME,
        source=f"adjacent suggestion · {where}",
        category="adjacency",
        status=status,
        title=f"follow-up: {kind.value} = {value}",
        detail=detail,
        url=url,
        severity=Severity.LOW,
        extra={
            "suggested_kind": kind.value,
            "suggested_value": value,
            "origin": where,
            "confidence": confidence,
        },
    )


async def _github_profile_html(username: str) -> tuple[str, HitStatus, str]:
    """Fetch the GitHub HTML profile page. Returns (html, status, detail)."""
    url = f"https://github.com/{username}"
    client = await get_client()
    try:
        r = await client.get(
            url,
            headers={"Accept": "text/html,application/xhtml+xml",
                     "User-Agent": "mytools-osint"},
            timeout=10, follow_redirects=True,
        )
    except BaseException as e:
        return "", classify_exception(e), f"{type(e).__name__}: {e}"[:120]
    if r.status_code == 404:
        return "", HitStatus.NOT_FOUND, "user not found"
    if r.status_code != 200:
        return "", classify_http(r.status_code), f"HTTP {r.status_code}"
    return r.text or "", HitStatus.FOUND, ""


async def _keybase_proofs(username: str) -> tuple[dict[str, Any] | None, HitStatus, str]:
    """Pull Keybase's machine-readable proofs JSON for a username.

    Note: Keybase publishes `https://keybase.io/<u>/proofs.json` for active users.
    Anonymous endpoint, no key.
    """
    url = f"https://keybase.io/{username}/proofs.json"
    client = await get_client()
    try:
        r = await client.get(
            url,
            headers={"Accept": "application/json", "User-Agent": "mytools-osint"},
            timeout=10,
        )
    except BaseException as e:
        return None, classify_exception(e), f"{type(e).__name__}: {e}"[:120]
    if r.status_code == 404:
        return None, HitStatus.NOT_FOUND, "user not on Keybase"
    if r.status_code != 200:
        return None, classify_http(r.status_code), f"HTTP {r.status_code}"
    try:
        return r.json() or {}, HitStatus.FOUND, ""
    except Exception:
        return None, HitStatus.ERROR, "unparseable JSON"


def _harvest_from_github(html: str, username: str) -> list[Hit]:
    """Extract up to 3 adjacency candidates from a GitHub HTML profile."""
    out: list[Hit] = []
    seen_values: set[str] = set()
    profile_url = f"https://github.com/{username}"

    # Email — strongest signal.
    for pat in _GH_EMAIL_PATTERNS:
        m = pat.search(html)
        if not m:
            continue
        candidate = m.group(1).strip()
        if "@" in candidate and candidate not in seen_values:
            seen_values.add(candidate)
            out.append(_adjacency_hit(
                where="github profile",
                kind=QueryKind.EMAIL,
                value=candidate,
                detail=f"email exposed on github.com/{username}",
                url=profile_url,
                confidence="medium",
            ))
            break

    # Blog / website — may be a personal domain worth pivoting.
    m = _GH_BLOG_PATTERN.search(html)
    if m:
        blog = m.group(1).strip()
        # Only surface as a domain pivot when it looks like a clean URL.
        if blog.startswith(("http://", "https://")) and blog not in seen_values:
            host = blog.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
            if host and "." in host and host not in seen_values:
                seen_values.add(host)
                out.append(_adjacency_hit(
                    where="github profile · blog",
                    kind=QueryKind.DOMAIN,
                    value=host,
                    detail=f"personal site linked from github.com/{username}",
                    url=blog,
                ))

    # Linked Twitter account.
    m = _GH_TWITTER_PATTERN.search(html)
    if m:
        twitter = m.group(1).strip()
        if twitter and twitter.lower() != username.lower() and twitter not in seen_values:
            seen_values.add(twitter)
            out.append(_adjacency_hit(
                where="github profile · twitter",
                kind=QueryKind.USERNAME,
                value=twitter,
                detail=f"twitter handle linked from github.com/{username}",
                url=f"https://twitter.com/{twitter}",
            ))
    return out


def _harvest_from_keybase(data: dict[str, Any], username: str) -> list[Hit]:
    """Promote Keybase's proven third-party accounts into adjacency hits."""
    out: list[Hit] = []
    proofs = (data.get("them") or {}).get("proofs_summary", {}).get("all") or []
    if not proofs:
        # Older / alternate response shape.
        proofs = data.get("proofs_summary", {}).get("all") or []
    base = f"https://keybase.io/{username}"
    for entry in proofs:
        proof_type = (entry.get("proof_type") or "").lower()
        nametag = entry.get("nametag") or entry.get("service_url") or ""
        if not nametag:
            continue
        # Map Keybase proof types to our QueryKinds.
        if proof_type in ("twitter", "github", "reddit", "hackernews",
                          "mastodon", "facebook"):
            kind = QueryKind.USERNAME
            value = nametag
        elif proof_type in ("dns", "generic_web_site"):
            kind = QueryKind.DOMAIN
            value = nametag.split("://", 1)[-1].split("/", 1)[0]
        else:
            continue
        if not value:
            continue
        out.append(_adjacency_hit(
            where=f"keybase · {proof_type}",
            kind=kind,
            value=value,
            detail=f"keybase proof of {proof_type} ownership",
            url=entry.get("service_url") or base,
            confidence="medium",
        ))
    return out


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.USERNAME:
        return
    username = clean_username(query.value)
    if not username:
        return

    emitted = 0

    # GitHub HTML profile
    html, gh_status, gh_detail = await _github_profile_html(username)
    if gh_status == HitStatus.FOUND and html:
        for hit in _harvest_from_github(html, username):
            if emitted >= MAX_ADJACENT_HITS:
                return
            yield hit
            emitted += 1
    elif gh_status not in (HitStatus.NOT_FOUND, HitStatus.FOUND):
        # Surface upstream outage so the user knows we tried.
        yield Hit(
            module=NAME, source="adjacency · github fetch",
            category="adjacency",
            status=gh_status,
            detail=gh_detail or "github fetch failed",
            severity=Severity.INFO,
        )

    if emitted >= MAX_ADJACENT_HITS:
        return

    # Keybase proofs.json
    data, kb_status, kb_detail = await _keybase_proofs(username)
    if kb_status == HitStatus.FOUND and isinstance(data, dict):
        for hit in _harvest_from_keybase(data, username):
            if emitted >= MAX_ADJACENT_HITS:
                return
            yield hit
            emitted += 1
    elif kb_status not in (HitStatus.NOT_FOUND, HitStatus.FOUND):
        yield Hit(
            module=NAME, source="adjacency · keybase fetch",
            category="adjacency",
            status=kb_status,
            detail=kb_detail or "keybase fetch failed",
            severity=Severity.INFO,
        )


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.USERNAME], run)
