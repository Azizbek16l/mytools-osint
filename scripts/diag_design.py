"""Render each redesigned screen against mock data to verify the layout draws."""
from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rich.console import Console

from app.core.types import Hit, HitStatus, Query, QueryKind, Severity
from app.ui.interactive import (
    ModProgress,
    _render_domain_report,
    _render_streaming_layout,
    _render_summary_card,
)

console = Console(force_terminal=True, width=120)


def mock_hits() -> list[Hit]:
    now = datetime.now(UTC)
    base = [
        ("username", "GitHub", "tech", "torvalds — Linus Torvalds",
         "https://github.com/torvalds", HitStatus.FOUND, Severity.HIGH),
        ("username", "Twitter/X", "social", "torvalds",
         "https://x.com/torvalds", HitStatus.FOUND, Severity.MEDIUM),
        ("username", "Keybase", "tech", "torvalds · 4 proofs",
         "https://keybase.io/torvalds", HitStatus.FOUND, Severity.MEDIUM),
        ("discovery", "GitHub:user", "profile", "id=1024025 repos=10 followers=200k",
         "https://github.com/torvalds", HitStatus.FOUND, Severity.HIGH),
        ("discovery", "Wayback", "archive", "snapshot 20070406093258",
         "https://web.archive.org/...", HitStatus.FOUND, Severity.LOW),
        ("patterns", "variation:torv", "suggestion", "-> torv  (re-query: osint torv)",
         "", HitStatus.FOUND, Severity.INFO),
        ("username", "ThreatMiner", "subdomain", "service unavailable — HTTP 500",
         "", HitStatus.UNAVAILABLE, Severity.INFO),
    ]
    hits = []
    for i, (mod, src, cat, det, url, st, sev) in enumerate(base):
        h = Hit(module=mod, source=src, category=cat, title=src, detail=det,
                url=url, status=st, severity=sev, latency_ms=120 + i * 30)
        h.found_at = now - timedelta(seconds=10 - i)
        hits.append(h)
    return hits


def main() -> int:
    hits = mock_hits()
    q = Query(kind=QueryKind.USERNAME, value="torvalds")

    progress = {
        "username":  ModProgress(name="username",  state="done", hits=8, positives=4),
        "discovery": ModProgress(name="discovery", state="running", hits=3, positives=2),
        "patterns":  ModProgress(name="patterns",  state="done", hits=1, positives=1),
        "email":     ModProgress(name="email",     state="idle"),
        "phone":     ModProgress(name="phone",     state="idle"),
    }

    console.print("\n[bold]=== streaming layout ===[/]\n")
    console.print(_render_streaming_layout(q, hits, progress, 4823, False))

    console.print("\n[bold]=== summary card ===[/]\n")
    console.print(_render_summary_card(q, hits, 4823))

    console.print("\n[bold]=== domain report (with mock domain hits) ===[/]\n")
    q2 = Query(kind=QueryKind.DOMAIN, value="marsits.uz")
    dh = [
        Hit(module="domain", source="adminslide.marsits.uz", category="subdomain",
            status=HitStatus.FOUND, detail="seen by Certspotter, HackerTarget"),
        Hit(module="domain", source="git.marsits.uz", category="subdomain",
            status=HitStatus.FOUND),
        Hit(module="domain", source="audit.marsits.uz", category="subdomain",
            status=HitStatus.FOUND),
        Hit(module="domain", source="DNS:A", category="dns",
            status=HitStatus.FOUND, detail="195.158.30.13"),
        Hit(module="domain", source="DNS:MX", category="dns",
            status=HitStatus.FOUND, detail="1 smtp.google.com"),
        Hit(module="ssl_tls", source="marsits.uz:443", category="tls",
            status=HitStatus.FOUND,
            detail="subject=CN=marsits.uz · expires in 28d · TLS TLSv1.3 · cipher TLS_AES_256_GCM_SHA384"),
        Hit(module="http_headers", source="SUMMARY", category="security-header",
            status=HitStatus.FOUND, title="grade A · 85/100", detail="5 positives"),
        Hit(module="http_headers", source="HSTS", category="security-header",
            status=HitStatus.FOUND, detail="+10 max-age 6mo"),
        Hit(module="tech_fingerprint", source="Vercel", category="tech:hosting",
            status=HitStatus.FOUND, detail="hosting"),
        Hit(module="tech_fingerprint", source="Cloudflare", category="tech:cdn",
            status=HitStatus.FOUND, detail="cdn"),
    ]
    console.print(_render_domain_report(q2, dh))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
