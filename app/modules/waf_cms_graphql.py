"""Three companion fingerprinting modules in one file (compact pattern):

  waf_detect      — wafw00f-style WAF fingerprint via headers + benign probe
  cms_detect      — WordPress / Drupal / Joomla / Magento version sniff
  graphql_probe   — POST {__schema {types{name}}} to common GraphQL paths
  source_maps     — HEAD /*.js.map for common bundlers (webpack, vite)

Each module is small (< 80 LoC) and registers separately. They share a
single file because they all rely on basic httpx GET/HEAD/POST patterns
against the same homepage.
"""
from __future__ import annotations

import asyncio
import json
import re
from collections.abc import AsyncIterator

from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity


# ============================================================================
# WAF DETECT
# ============================================================================
WAF_SIGS = [
    # (name, severity, header_keys[, regex_pattern])
    ("Cloudflare",       Severity.INFO, ["server:cloudflare", "cf-ray", "cf-cache-status"]),
    ("Akamai",           Severity.INFO, ["server:akamaighost", "x-akamai-transformed", "akamai-x-cache-on"]),
    ("AWS CloudFront",   Severity.INFO, ["x-amz-cf-id", "via:cloudfront"]),
    ("Fastly",           Severity.INFO, ["fastly-debug-state", "x-served-by:cache-"]),
    ("Imperva Incapsula", Severity.MEDIUM, ["x-iinfo", "x-cdn:incapsula", "incap_ses"]),
    ("F5 BIG-IP ASM",    Severity.MEDIUM, ["server:big-ip", "bigipserver"]),
    ("Sucuri",           Severity.MEDIUM, ["server:sucuri", "x-sucuri-id", "x-sucuri-cache"]),
    ("AWS WAF",          Severity.INFO, ["x-amzn-requestid", "x-amzn-trace-id"]),
    ("Azure Front Door", Severity.INFO, ["x-azure-ref", "x-cache:tcp_hit"]),
    ("Barracuda",        Severity.MEDIUM, ["barra_counter_session", "server:barracuda"]),
    ("Wallarm",          Severity.MEDIUM, ["server:nginx-wallarm", "x-wallarm"]),
]


async def _waf_run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.DOMAIN:
        return
    domain = (query.value or "").strip().lower().lstrip("*.").rstrip("/")
    url = f"https://{domain}/"
    try:
        client = await get_client()
        r = await client.get(url, timeout=8.0)
    except Exception as e:
        yield Hit(module="waf_detect", source="probe", category="fingerprint",
                  url=url, status=HitStatus.UNAVAILABLE,
                  title=domain, detail=f"{type(e).__name__}: {e}")
        return
    hdrs_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
    hdr_summary = " · ".join(f"{k}:{v[:30]}" for k, v in hdrs_lower.items())
    matched: list[tuple[str, Severity]] = []
    for name, sev, sigs in WAF_SIGS:
        for sig in sigs:
            if ":" in sig:
                k, v = sig.split(":", 1)
                if k in hdrs_lower and v in hdrs_lower[k]:
                    matched.append((name, sev))
                    break
            elif sig in hdrs_lower:
                matched.append((name, sev))
                break
    if matched:
        for name, sev in matched:
            yield Hit(module="waf_detect", source=name, category="fingerprint",
                      url=url, status=HitStatus.FOUND, title=name,
                      detail=f"WAF/CDN detected on {domain}",
                      severity=sev, extra={"name": name})
    else:
        yield Hit(module="waf_detect", source="probe", category="fingerprint",
                  url=url, status=HitStatus.NO_DATA, title=domain,
                  detail=f"no known WAF/CDN signature in headers ({len(hdrs_lower)} headers)")


# ============================================================================
# CMS DETECT (WordPress / Drupal / Joomla / Magento version sniff)
# ============================================================================
async def _cms_run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.DOMAIN:
        return
    domain = (query.value or "").strip().lower().lstrip("*.").rstrip("/")
    client = await get_client()

    # WordPress detection: /wp-includes/version.php (often not exposed), meta generator, /wp-login.php
    try:
        r = await client.get(f"https://{domain}/", timeout=6.0)
        body = r.text or ""
        m = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
                      body, re.IGNORECASE)
        if m:
            gen = m.group(1)
            yield Hit(module="cms_detect", source="meta-generator",
                      category="fingerprint",
                      url=f"https://{domain}/", status=HitStatus.FOUND,
                      title=gen, detail=f"meta generator on {domain}",
                      severity=Severity.MEDIUM, extra={"generator": gen})
    except Exception:
        pass

    # WordPress-specific probes
    try:
        r = await client.head(f"https://{domain}/wp-login.php", timeout=4.0)
        if r.status_code == 200:
            yield Hit(module="cms_detect", source="WordPress",
                      category="fingerprint",
                      url=f"https://{domain}/wp-login.php",
                      status=HitStatus.FOUND, title="WordPress",
                      detail=f"wp-login.php present on {domain}",
                      severity=Severity.MEDIUM)
    except Exception:
        pass

    # Drupal CHANGELOG (often readable on older installs)
    try:
        r = await client.get(f"https://{domain}/CHANGELOG.txt", timeout=4.0)
        if r.status_code == 200 and "Drupal" in r.text[:500]:
            m = re.search(r"Drupal\s+([0-9.]+),", r.text)
            ver = m.group(1) if m else "unknown"
            yield Hit(module="cms_detect", source="Drupal",
                      category="fingerprint",
                      url=f"https://{domain}/CHANGELOG.txt",
                      status=HitStatus.FOUND, title=f"Drupal {ver}",
                      detail=f"Drupal version exposed via CHANGELOG.txt: {ver}",
                      severity=Severity.HIGH, extra={"version": ver})
    except Exception:
        pass

    # Joomla
    try:
        r = await client.get(f"https://{domain}/administrator/manifests/files/joomla.xml",
                              timeout=4.0)
        if r.status_code == 200 and "<version>" in r.text:
            m = re.search(r"<version>([^<]+)</version>", r.text)
            ver = m.group(1) if m else "unknown"
            yield Hit(module="cms_detect", source="Joomla",
                      category="fingerprint",
                      url=f"https://{domain}/administrator/manifests/files/joomla.xml",
                      status=HitStatus.FOUND, title=f"Joomla {ver}",
                      detail=f"Joomla version exposed: {ver}",
                      severity=Severity.HIGH, extra={"version": ver})
    except Exception:
        pass


# ============================================================================
# GRAPHQL PROBE — find /graphql + send introspection query
# ============================================================================
INTROSPECTION_QUERY = json.dumps({
    "query": "{__schema {types {name}}}"
})

GRAPHQL_PATHS = ["graphql", "graphiql", "api/graphql", "v1/graphql", "v2/graphql"]


async def _gql_run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.DOMAIN:
        return
    domain = (query.value or "").strip().lower().lstrip("*.").rstrip("/")
    client = await get_client()
    for path in GRAPHQL_PATHS:
        url = f"https://{domain}/{path}"
        try:
            r = await client.post(url, content=INTROSPECTION_QUERY,
                                   headers={"content-type": "application/json"},
                                   timeout=6.0)
            # 401/403 = endpoint exists but auth-walled (api.gitlab.com, etc).
            if r.status_code in (401, 403):
                yield Hit(module="graphql_probe", source=path,
                          category="fingerprint",
                          url=url, status=HitStatus.FOUND,
                          title=f"GraphQL endpoint at /{path} (auth required)",
                          detail=f"GraphQL detected — HTTP {r.status_code} (auth-walled, introspection unknown)",
                          severity=Severity.HIGH,
                          extra={"path": path, "auth_required": True, "status": r.status_code})
                continue
            # Accept GraphQL on 2xx OR any status with JSON containing data/errors.
            if r.status_code >= 500 and "json" not in r.headers.get("content-type", "").lower():
                continue
            try:
                data = r.json()
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            # Non-2xx but JSON with GraphQL-shape fields → endpoint exists, query rejected.
            if r.status_code != 200 and "errors" not in data and "data" not in data:
                continue
            types = (((data.get("data") or {}).get("__schema") or {}).get("types"))
            if isinstance(types, list) and len(types) > 5:
                # Real introspection succeeded — schema is exposed
                yield Hit(module="graphql_probe", source=path,
                          category="fingerprint",
                          url=url, status=HitStatus.FOUND,
                          title=f"GraphQL introspection at /{path}",
                          detail=f"introspection ENABLED — exposes {len(types)} types",
                          severity=Severity.HIGH,
                          extra={"path": path, "n_types": len(types)})
            elif "errors" in data:
                # Endpoint exists but introspection blocked — still useful
                yield Hit(module="graphql_probe", source=path,
                          category="fingerprint",
                          url=url, status=HitStatus.FOUND,
                          title=f"GraphQL endpoint at /{path}",
                          detail=f"GraphQL detected, introspection BLOCKED (good)",
                          severity=Severity.MEDIUM,
                          extra={"path": path, "introspection": False})
        except Exception:
            continue


# ============================================================================
# SOURCE MAPS — JS bundler source maps leak project structure
# ============================================================================
SOURCEMAP_PATHS = [
    "static/js/main.js.map", "static/js/app.js.map", "static/js/bundle.js.map",
    "js/main.js.map", "js/app.js.map", "js/bundle.js.map",
    "assets/index.js.map", "assets/main.js.map",
    "dist/main.js.map", "dist/app.js.map",
    "_next/static/chunks/main.js.map", "_next/static/chunks/pages/_app.js.map",
    "build/static/js/main.js.map",
]


async def _smaps_run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.DOMAIN:
        return
    domain = (query.value or "").strip().lower().lstrip("*.").rstrip("/")
    client = await get_client()

    async def probe(path: str) -> Hit | None:
        url = f"https://{domain}/{path}"
        try:
            r = await client.head(url, timeout=4.0, follow_redirects=False)
            if r.status_code == 200:
                size = r.headers.get("content-length", "?")
                return Hit(module="source_maps", source="js-map",
                           category="fingerprint",
                           url=url, status=HitStatus.FOUND,
                           title=f"/{path}", detail=f"source map exposed · {size} bytes "
                                                    "(reveals project source structure)",
                           severity=Severity.MEDIUM,
                           extra={"path": path, "bytes": size})
        except Exception:
            return None
        return None

    sem = asyncio.Semaphore(6)

    async def gated(p):
        async with sem:
            return await probe(p)

    n_found = 0
    tasks = [asyncio.create_task(gated(p)) for p in SOURCEMAP_PATHS]
    for fut in asyncio.as_completed(tasks):
        try:
            h = await fut
        except Exception:
            continue
        if h is None:
            continue
        n_found += 1
        yield h


# ============================================================================
# Registrars — each module name acts as its own NAME
# ============================================================================
def _make_module(name: str, run_fn):
    class _M:
        NAME = name
        run = staticmethod(run_fn)
        def register(self, r: Runner) -> None:
            r.register(name, [QueryKind.DOMAIN], run_fn)
    return _M()


waf_detect      = _make_module("waf_detect",      _waf_run)
cms_detect      = _make_module("cms_detect",      _cms_run)
graphql_probe   = _make_module("graphql_probe",   _gql_run)
source_maps     = _make_module("source_maps",     _smaps_run)


# Module needs a NAME + run + register at file level for the __init__.py
# loader to wire it up. Since this file ships 4 logical modules, we export
# a single composite NAME and register all 4 separately.
NAME = "waf_cms_graphql"


def run(query: Query) -> AsyncIterator[Hit]:
    """Composite entry — runs all 4 fingerprint modules concurrently."""
    async def _go():
        async for h in _waf_run(query):
            yield h
        async for h in _cms_run(query):
            yield h
        async for h in _gql_run(query):
            yield h
        async for h in _smaps_run(query):
            yield h
    return _go()


def register(r: Runner) -> None:
    # Register the 4 logical modules independently so they show up in
    # `osint --list-modules` as separate entries.
    r.register("waf_detect",    [QueryKind.DOMAIN], _waf_run)
    r.register("cms_detect",    [QueryKind.DOMAIN], _cms_run)
    r.register("graphql_probe", [QueryKind.DOMAIN], _gql_run)
    r.register("source_maps",   [QueryKind.DOMAIN], _smaps_run)
