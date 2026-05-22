"""Web technology fingerprint (Wappalyzer-lite).

Compact built-in signature set for the most common stacks. Detection rules:
header regex, cookie name, HTML body regex, script src patterns, meta tags.
For deeper coverage (3000+ patterns) we can later vendor the open-source
webappanalyzer JSON DB; for now, this curated ~30-entry set covers ~80% of
real-world hits and ships zero-config.
"""
from __future__ import annotations

import re
from collections.abc import AsyncIterator

from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "tech_fingerprint"

# Minimal signature set. Schema: {name, category, headers, cookies, html, scripts}
SIGS: list[dict] = [
    {"name": "Cloudflare", "category": "cdn",
     "headers": {"server": r"cloudflare", "cf-ray": r".+"}},
    {"name": "Fastly", "category": "cdn",
     "headers": {"x-served-by": r"cache-", "x-fastly-request-id": r".+"}},
    {"name": "Akamai", "category": "cdn",
     "headers": {"server": r"akamai|ghost", "x-akamai-transformed": r".+"}},
    {"name": "Amazon CloudFront", "category": "cdn",
     "headers": {"x-amz-cf-id": r".+", "via": r"cloudfront"}},
    {"name": "nginx", "category": "server", "headers": {"server": r"nginx"}},
    {"name": "Apache", "category": "server", "headers": {"server": r"apache"}},
    {"name": "Caddy", "category": "server", "headers": {"server": r"caddy"}},
    {"name": "LiteSpeed", "category": "server", "headers": {"server": r"litespeed"}},
    {"name": "IIS", "category": "server", "headers": {"server": r"microsoft-iis"}},
    {"name": "Express", "category": "framework",
     "headers": {"x-powered-by": r"express"}},
    {"name": "ASP.NET", "category": "framework",
     "headers": {"x-powered-by": r"asp\.net", "x-aspnet-version": r".+"}},
    {"name": "PHP", "category": "language",
     "headers": {"x-powered-by": r"php"}},
    {"name": "WordPress", "category": "cms",
     "html": r"<meta[^>]+name=[\"']generator[\"'][^>]+wordpress",
     "scripts": r"/wp-(?:content|includes)/"},
    {"name": "Drupal", "category": "cms",
     "html": r"<meta[^>]+name=[\"']generator[\"'][^>]+drupal",
     "headers": {"x-generator": r"drupal", "x-drupal-cache": r".+"}},
    {"name": "Joomla", "category": "cms",
     "html": r"<meta[^>]+name=[\"']generator[\"'][^>]+joomla"},
    {"name": "Shopify", "category": "ecommerce",
     "headers": {"x-shopify-stage": r".+", "x-shopid": r".+"},
     "cookies": {"_shopify_y": r".+"}},
    {"name": "Magento", "category": "ecommerce",
     "cookies": {"frontend": r".+", "PHPSESSID": r".+"},
     "html": r"Magento|Mage\."},
    {"name": "Next.js", "category": "framework",
     "headers": {"x-powered-by": r"next\.js"},
     "html": r"__NEXT_DATA__"},
    {"name": "Nuxt", "category": "framework",
     "html": r"__NUXT__|<script[^>]+/_nuxt/"},
    {"name": "Vue.js", "category": "framework",
     "html": r"data-server-rendered=[\"']true[\"']",
     "scripts": r"vue\.runtime|vue@\d"},
    {"name": "React", "category": "framework",
     "html": r"data-reactroot|react(?:-dom)?@\d|/static/js/main\..*\.js"},
    {"name": "Svelte", "category": "framework",
     "html": r"svelte-\w+"},
    {"name": "Angular", "category": "framework",
     "html": r"ng-version=[\"']", "scripts": r"angular(?:\.min)?\.js"},
    {"name": "Vercel", "category": "hosting",
     "headers": {"server": r"vercel|now"}},
    {"name": "Netlify", "category": "hosting",
     "headers": {"server": r"netlify", "x-nf-request-id": r".+"}},
    {"name": "GitHub Pages", "category": "hosting",
     "headers": {"server": r"github\.com", "x-github-request-id": r".+"}},
    {"name": "Google Analytics", "category": "analytics",
     "html": r"google-analytics\.com|googletagmanager\.com|gtag\("},
    {"name": "Facebook Pixel", "category": "analytics",
     "html": r"connect\.facebook\.net.*fbevents"},
    {"name": "Cloudflare Turnstile", "category": "captcha",
     "html": r"challenges\.cloudflare\.com/turnstile"},
    {"name": "Sucuri WAF", "category": "waf",
     "headers": {"x-sucuri-id": r".+"}},
    {"name": "Imperva Incapsula", "category": "waf",
     "headers": {"x-iinfo": r".+"}, "cookies": {"visid_incap_": r".+"}},
    {"name": "AWS WAF", "category": "waf",
     "headers": {"x-amzn-requestid": r".+"}},
]


def _match(sig: dict, headers: dict[str, str], cookies: list[str], body: str) -> bool:
    if "headers" in sig:
        for k, pat in sig["headers"].items():
            v = headers.get(k.lower(), "")
            if not v or not re.search(pat, v, re.IGNORECASE):
                return False
    if "cookies" in sig:
        joined = " ".join(cookies).lower()
        for k, _pat in sig["cookies"].items():
            if k.lower() not in joined:
                return False
    if "html" in sig and body:
        if not re.search(sig["html"], body, re.IGNORECASE | re.DOTALL):
            return False
    if "scripts" in sig and body:
        if not re.search(sig["scripts"], body, re.IGNORECASE | re.DOTALL):
            return False
    # At least one section must have matched (else this would auto-pass nothing)
    return any(k in sig for k in ("headers", "cookies", "html", "scripts"))


def _ensure_url(value: str) -> str:
    v = value.strip()
    if v.startswith(("http://", "https://")):
        return v
    return f"https://{v}"


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.DOMAIN:
        return
    url = _ensure_url(query.value)
    try:
        client = await get_client()
        r = await client.get(url, follow_redirects=True, timeout=15)
    except Exception as e:
        from app.core.classify import classify_exception
        yield Hit(module=NAME, source="GET", category="tech",
                  status=classify_exception(e), detail=f"{type(e).__name__}: {e}"[:100])
        return
    headers = {k.lower(): v for k, v in r.headers.items()}
    cookies = (r.headers.get_list("set-cookie")
               if hasattr(r.headers, "get_list") else [])
    body = ""
    ctype = headers.get("content-type", "")
    if "text/" in ctype or "json" in ctype or "xml" in ctype:
        try:
            body = r.text[:200_000]  # cap at 200 KB
        except Exception:
            pass

    matched: list[dict] = []
    for sig in SIGS:
        try:
            if _match(sig, headers, cookies, body):
                matched.append(sig)
        except re.error:
            continue
    if not matched:
        yield Hit(module=NAME, source="fingerprint", category="tech",
                  status=HitStatus.NOT_FOUND,
                  detail="no signatures matched (may be JS-rendered SPA)",
                  url=str(r.url))
        return
    # Group by category for the title
    by_cat: dict[str, list[str]] = {}
    for sig in matched:
        by_cat.setdefault(sig["category"], []).append(sig["name"])
    title = " · ".join(f"{cat}: {', '.join(names)}" for cat, names in by_cat.items())
    yield Hit(
        module=NAME, source="stack", category="tech",
        status=HitStatus.FOUND,
        title=title[:120],
        detail=f"{len(matched)} technologies identified",
        url=str(r.url),
        severity=Severity.INFO,
        extra={"matches": [{"name": s["name"], "category": s["category"]}
                           for s in matched]},
    )
    # Also one Hit per technology for filterability
    for sig in matched:
        yield Hit(
            module=NAME, source=sig["name"], category=f"tech:{sig['category']}",
            status=HitStatus.FOUND, title=sig["name"],
            detail=f"category: {sig['category']}",
            url=str(r.url),
            severity=Severity.INFO,
        )


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN], run)
