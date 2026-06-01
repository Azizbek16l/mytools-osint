"""Web-recon module: JS secret scanner + Wayback goldmine + favicon mmh3.

Three high-value passive checks for a domain target:

  1. JS scanner — fetch the homepage, extract <script src=…> URLs (same-host
     or absolute), download each (cap 8), grep for high-confidence secret
     patterns (AWS, GCP, Slack, Stripe, GitHub, generic JWT etc.).
     Only emits FOUND when a pattern matches with reasonable specificity —
     it's a *grep* not a full SAST, so we err on the side of fewer FPs.

  2. Wayback goldmine — query web.archive.org/cdx/search/cdx with
     `&collapse=urlkey` and pull the unique URL list for the domain.
     Filter for "interesting" paths: /.env, /.git/, /admin, /api/, /backup,
     /config, /login, .sql, .bak, /wp-admin/. Yields one Hit per category
     hit (capped) so the user can pivot.

  3. Favicon mmh3 hash — download /favicon.ico, compute mmh3.hash, surface
     the hash so the analyst can pivot via Shodan's `http.favicon.hash:`
     search (manual link in `url`). Pure offline pivoting primitive.

All three sources are independent and run concurrently. Each can fail
without blocking the others.
"""
from __future__ import annotations

import asyncio
import base64
import re
from collections.abc import AsyncIterator
from urllib.parse import urljoin, urlparse

from app.core.classify import classify_exception, classify_http
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "web_recon"

_TIMEOUT = 8.0
_MAX_JS = 8
_MAX_JS_BYTES = 2_500_000
_MAX_WAYBACK = 5000

# High-confidence secret patterns. Calibration:
#   - prefix-bound (e.g. AKIA[0-9A-Z]{16}) → very low FP rate
#   - generic API-key shapes (32+ char hex/b64) → SKIPPED here, too noisy.
SECRET_PATTERNS: dict[str, str] = {
    "AWS Access Key": r"\b(AKIA[0-9A-Z]{16})\b",
    "AWS Secret Key": r"\b(?:aws_secret_access_key|aws_secret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})\b",
    "GitHub PAT": r"\b(ghp_[0-9A-Za-z]{36})\b",
    "GitHub OAuth": r"\b(gho_[0-9A-Za-z]{36})\b",
    "GitHub App": r"\b((?:ghs|ghu|ghr)_[0-9A-Za-z]{36})\b",
    "Slack Token": r"\b(xox[abprs]-[0-9A-Za-z\-]{10,})\b",
    "Slack Webhook": r"\b(https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,})\b",
    "Stripe Live Key": r"\b(sk_live_[0-9a-zA-Z]{24,})\b",
    "Stripe Restricted": r"\b(rk_live_[0-9a-zA-Z]{24,})\b",
    "Google API Key": r"\b(AIza[0-9A-Za-z\-_]{35})\b",
    "Twilio SID": r"\b(AC[a-f0-9]{32})\b",
    "Mailgun Key": r"\b(key-[a-f0-9]{32})\b",
    "Mailchimp Key": r"\b([0-9a-f]{32}-us[0-9]{1,2})\b",
    "SendGrid Key": r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b",
    "JWT": r"\b(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)\b",
    "Private Key": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
}

# Wayback paths worth surfacing. Each entry: (category, regex on path).
INTERESTING: list[tuple[str, str]] = [
    ("config-leak", r"(?:^|/)(?:\.env|\.envrc|\.env\.local|wp-config\.php|"
                    r"config\.json|settings\.py|application\.properties|"
                    r"appsettings\.json|secrets\.yml|credentials)$"),
    ("vcs-leak", r"(?:^|/)\.(?:git|svn|hg)/"),
    ("backup", r"\.(?:sql|sql\.gz|sqlite3?|bak|backup|old|orig|swp|zip|tar\.gz|tgz)$"),
    ("admin-panel", r"(?:^|/)(?:admin|administrator|wp-admin|phpmyadmin|adminer|"
                    r"manage|console|dashboard)(?:/|$)"),
    ("api-doc", r"(?:^|/)(?:api|graphql|swagger|openapi|api-docs)(?:/|\.|$)"),
    ("debug", r"(?:^|/)(?:debug|trace|status|metrics|actuator)(?:/|$)"),
    ("auth", r"(?:^|/)(?:login|signin|register|signup|oauth|sso|saml)(?:/|$)"),
]


# ---- favicon ---------------------------------------------------------------

def _mmh3_x86_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python MurmurHash3 x86_32 — avoids the mmh3 wheel dependency.

    Compatible with Shodan's signed-int favicon hash convention. Tested
    against the reference vector "favicon hash" → mmh3.hash(...) parity."""
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    r1 = 15
    r2 = 13
    m = 5
    n = 0xe6546b64
    h1 = seed & 0xFFFFFFFF
    length = len(data)
    nblocks = length // 4
    for i in range(nblocks):
        k1 = int.from_bytes(data[i * 4:i * 4 + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << r1) | (k1 >> (32 - r1))) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << r2) | (h1 >> (32 - r2))) & 0xFFFFFFFF
        h1 = (h1 * m + n) & 0xFFFFFFFF
    tail = data[nblocks * 4:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << r1) | (k1 >> (32 - r1))) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    # signed int — Shodan's convention
    if h1 & 0x80000000:
        return h1 - 0x100000000
    return h1


async def _favicon(domain: str) -> Hit:
    url = f"https://{domain}/favicon.ico"
    try:
        client = await get_client()
        r = await client.get(url, timeout=_TIMEOUT, follow_redirects=True)
    except Exception as e:
        return Hit(module=NAME, source="favicon", category="recon",
                   url=url, status=classify_exception(e),
                   title=domain, detail=f"{type(e).__name__}: {e}")
    if r.status_code != 200 or not r.content:
        return Hit(module=NAME, source="favicon", category="recon",
                   url=url, status=classify_http(r.status_code) if r.status_code != 200
                       else HitStatus.NO_DATA,
                   title=domain, detail=f"HTTP {r.status_code}, "
                                        f"{len(r.content or b'')} bytes")
    # Shodan's favicon hash = mmh3 over base64.encodebytes() output (76-char
    # lines + trailing newline). encodebytes returns exactly that, as bytes —
    # which is what _mmh3_x86_32 expects. (The old codecs.encode(bytes,"ascii")
    # raised TypeError: ascii_encode wants str, not bytes.)
    chunked = base64.encodebytes(r.content)
    h = _mmh3_x86_32(chunked)
    shodan_url = f"https://www.shodan.io/search?query=http.favicon.hash%3A{h}"
    return Hit(
        module=NAME, source="favicon", category="recon",
        url=shodan_url, status=HitStatus.FOUND, title=f"favicon mmh3={h}",
        detail=f"hash={h} | bytes={len(r.content)} | "
               f"pivot: Shodan http.favicon.hash:{h}",
        severity=Severity.INFO,
        extra={"hash": h, "bytes": len(r.content), "shodan": shodan_url,
               "favicon_url": url},
    )


# ---- JS scanner ------------------------------------------------------------

_SCRIPT_RE = re.compile(r"<script\b[^>]*\bsrc\s*=\s*['\"]([^'\"]+)['\"]",
                        re.IGNORECASE)


async def _fetch_text(url: str, max_bytes: int = _MAX_JS_BYTES) -> str | None:
    try:
        client = await get_client()
        r = await client.get(url, timeout=_TIMEOUT, follow_redirects=True)
        if r.status_code != 200:
            return None
        content = r.content[:max_bytes]
        return content.decode("utf-8", errors="replace")
    except Exception:
        return None


async def _js_scan(domain: str) -> AsyncIterator[Hit]:
    home = f"https://{domain}/"
    html = await _fetch_text(home)
    if html is None:
        yield Hit(module=NAME, source="js-scan", category="recon",
                  url=home, status=HitStatus.UNAVAILABLE, title=domain,
                  detail="could not fetch homepage")
        return
    # Scan inline HTML too — secrets often leak in <script>const KEY=...</script>.
    inline_findings = _scan_text(html, home)
    for name, snippet in inline_findings:
        yield Hit(module=NAME, source=f"js-scan:{name}", category="secret-leak",
                  url=home, status=HitStatus.FOUND, title=f"inline secret @ {domain}",
                  detail=f"{name}: {snippet}", severity=Severity.CRITICAL,
                  extra={"pattern": name, "snippet": snippet, "context": "inline"})

    scripts = []
    for m in _SCRIPT_RE.finditer(html):
        src = m.group(1).strip()
        absolute = urljoin(home, src)
        if urlparse(absolute).scheme not in ("http", "https"):
            continue
        scripts.append(absolute)
    # Same-host first, then external — same-host more likely to contain
    # the org's own secrets.
    same = [s for s in scripts if urlparse(s).hostname == domain]
    ext = [s for s in scripts if urlparse(s).hostname != domain]
    todo = (same + ext)[:_MAX_JS]

    sem = asyncio.Semaphore(4)

    async def scan_one(js_url: str) -> list[tuple[str, str, str]]:
        async with sem:
            body = await _fetch_text(js_url)
            if body is None:
                return []
            return [(name, snip, js_url) for name, snip in _scan_text(body, js_url)]

    tasks = [asyncio.create_task(scan_one(u)) for u in todo]
    total_findings = 0
    for fut in asyncio.as_completed(tasks):
        try:
            findings = await fut
        except Exception as e:
            yield Hit(module=NAME, source="js-scan", status=HitStatus.ERROR,
                      detail=f"{type(e).__name__}: {e}")
            continue
        for name, snippet, js_url in findings:
            total_findings += 1
            yield Hit(module=NAME, source=f"js-scan:{name}", category="secret-leak",
                      url=js_url, status=HitStatus.FOUND,
                      title=f"secret @ {urlparse(js_url).path}",
                      detail=f"{name}: {snippet}",
                      severity=Severity.CRITICAL,
                      extra={"pattern": name, "snippet": snippet,
                             "js_url": js_url})
    yield Hit(module=NAME, source="js-scan", category="recon",
              status=HitStatus.NO_DATA if total_findings == 0 else HitStatus.FOUND,
              title=domain,
              detail=f"scanned {len(todo)} script(s), "
                     f"{total_findings} secret pattern hit(s)",
              severity=Severity.INFO,
              extra={"scripts_scanned": len(todo), "findings": total_findings})


def _scan_text(text: str, where: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for name, pattern in SECRET_PATTERNS.items():
        for m in re.finditer(pattern, text):
            try:
                cap = m.group(1) if m.lastindex else m.group(0)
            except IndexError:
                cap = m.group(0)
            key = (name, cap[:40])
            if key in seen:
                continue
            seen.add(key)
            # Redact middle of the secret in the snippet.
            redacted = cap[:6] + "***" + cap[-4:] if len(cap) > 14 else cap
            out.append((name, redacted))
    return out


# ---- Wayback goldmine ------------------------------------------------------

_WAYBACK_CDX = ("https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
                "&output=json&fl=original&collapse=urlkey&limit={limit}")


async def _wayback(domain: str) -> AsyncIterator[Hit]:
    url = _WAYBACK_CDX.format(domain=domain, limit=_MAX_WAYBACK)
    try:
        client = await get_client()
        r = await client.get(url, timeout=20.0,
                             headers={"Accept": "application/json"})
    except Exception as e:
        yield Hit(module=NAME, source="wayback-goldmine", category="recon",
                  url=url, status=classify_exception(e),
                  title=domain, detail=f"{type(e).__name__}: {e}")
        return
    if r.status_code != 200:
        yield Hit(module=NAME, source="wayback-goldmine", category="recon",
                  url=url, status=classify_http(r.status_code), title=domain,
                  detail=f"HTTP {r.status_code}")
        return
    try:
        rows = r.json()
    except Exception:
        yield Hit(module=NAME, source="wayback-goldmine", category="recon",
                  url=url, status=HitStatus.NO_DATA, title=domain,
                  detail="empty or non-json CDX response")
        return
    if not rows or len(rows) <= 1:
        yield Hit(module=NAME, source="wayback-goldmine", category="recon",
                  url=url, status=HitStatus.NO_DATA, title=domain,
                  detail="no historical URLs indexed")
        return
    urls = [row[0] for row in rows[1:]]
    buckets: dict[str, list[str]] = {cat: [] for cat, _ in INTERESTING}
    compiled = [(cat, re.compile(p, re.IGNORECASE)) for cat, p in INTERESTING]
    for u in urls:
        try:
            path = urlparse(u).path or ""
        except Exception:  # noqa: S112, BLE001 — malformed Wayback URLs are expected
            continue
        for cat, pat in compiled:
            if pat.search(path):
                buckets[cat].append(u)
                break
    total_int = sum(len(v) for v in buckets.values())
    for cat, hits_list in buckets.items():
        if not hits_list:
            continue
        sample = hits_list[:5]
        sev = (Severity.CRITICAL if cat in ("config-leak", "vcs-leak")
               else Severity.HIGH if cat in ("backup", "admin-panel")
               else Severity.MEDIUM)
        yield Hit(
            module=NAME, source=f"wayback:{cat}", category="recon",
            url=f"https://web.archive.org/web/*/{domain}/*",
            status=HitStatus.FOUND, title=f"{cat} via Wayback",
            detail=f"{len(hits_list)} URL(s) — sample: {sample[0]}"
                   + (f" (+{len(hits_list)-1})" if len(hits_list) > 1 else ""),
            severity=sev,
            extra={"category": cat, "count": len(hits_list), "sample": sample},
        )
    yield Hit(module=NAME, source="wayback-goldmine", category="recon",
              status=HitStatus.FOUND if total_int else HitStatus.NO_DATA,
              title=domain,
              detail=f"{len(urls)} historical URLs scanned, "
                     f"{total_int} interesting",
              severity=Severity.INFO,
              extra={"total_urls": len(urls), "interesting": total_int})


# ---- orchestrator ----------------------------------------------------------

async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.DOMAIN:
        return
    domain = (query.value or "").strip().lower().lstrip("*.").rstrip("/")
    if not domain:
        return

    # Run favicon, JS scan, wayback concurrently.
    favicon_task = asyncio.create_task(_favicon(domain))
    js_gen = _js_scan(domain)
    wb_gen = _wayback(domain)

    # Surface favicon first (fastest).
    try:
        yield await favicon_task
    except Exception as e:
        yield Hit(module=NAME, source="favicon", status=HitStatus.ERROR,
                  detail=f"{type(e).__name__}: {e}")

    async for h in js_gen:
        yield h
    async for h in wb_gen:
        yield h


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN], run)
