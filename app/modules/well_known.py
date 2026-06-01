"""`.well-known/*` discovery — auto-fetch the standard metadata endpoints.

For a DOMAIN, fetch the well-known URIs registered with IANA + the most
commonly-deployed convention paths:

  /.well-known/security.txt              RFC 9116 — security contact
  /.well-known/openid-configuration       OIDC provider metadata
  /.well-known/oauth-authorization-server RFC 8414 — OAuth metadata
  /.well-known/host-meta                 RFC 6415 — XRD discovery
  /.well-known/webfinger                 RFC 7033 — user discovery
  /.well-known/change-password           browser autofill hint
  /.well-known/apple-app-site-association  iOS deep-link manifest
  /.well-known/assetlinks.json            Android Digital Asset Links
  /.well-known/matrix/server              Matrix homeserver delegation
  /.well-known/nodeinfo                  ActivityPub / Mastodon
  /.well-known/host-meta.json
  /.well-known/dnt-policy.txt
  /.well-known/gpc.json                  Global Privacy Control
  /.well-known/discord                   Discord domain verification
  /sitemap.xml                           covered by web_hardening
  /humans.txt                            community convention
  /security.txt                          legacy location
  /BingSiteAuth.xml, /google-site-verification.html   ownership proofs

Each found endpoint becomes one Hit with a tiny preview of the body.
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

from app.core.classify import classify_exception
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "well_known"

_TIMEOUT = 6.0

PATHS: list[tuple[str, str, str]] = [
    ("/.well-known/security.txt",              "security.txt", "RFC 9116 security contact"),
    ("/.well-known/openid-configuration",      "openid-config", "OIDC provider metadata"),
    ("/.well-known/oauth-authorization-server","oauth-as", "OAuth 2.0 AS metadata"),
    ("/.well-known/jwks.json",                 "jwks", "JSON Web Key Set"),
    ("/.well-known/host-meta",                 "host-meta", "XRD discovery"),
    ("/.well-known/webfinger",                 "webfinger", "user discovery"),
    ("/.well-known/change-password",           "change-password", "browser hint"),
    ("/.well-known/apple-app-site-association","aasa", "iOS deep-link manifest"),
    ("/.well-known/assetlinks.json",           "assetlinks", "Android digital-asset links"),
    ("/.well-known/matrix/server",             "matrix-server", "Matrix delegation"),
    ("/.well-known/matrix/client",             "matrix-client", "Matrix delegation"),
    ("/.well-known/nodeinfo",                  "nodeinfo", "ActivityPub / Fediverse"),
    ("/.well-known/host-meta.json",            "host-meta.json", "XRD JSON"),
    ("/.well-known/gpc.json",                  "gpc", "Global Privacy Control"),
    ("/.well-known/discord",                   "discord", "Discord domain verification"),
    ("/.well-known/traffic-advice",            "traffic-advice", "Chrome prefetch policy"),
    ("/.well-known/dnt-policy.txt",            "dnt-policy", "Do-Not-Track policy"),
    ("/security.txt",                          "security.txt (legacy)", "RFC 9116 legacy location"),
    ("/humans.txt",                            "humans.txt", "community convention"),
    ("/.well-known/saml-metadata.xml",         "saml-metadata", "SAML metadata"),
    ("/.well-known/idp-metadata.xml",          "idp-metadata", "SAML IdP metadata"),
    ("/.well-known/openpgpkey/policy",         "openpgp-policy", "OpenPGP delegation"),
    ("/.well-known/ai.txt",                    "ai.txt", "AI scraping policy"),
    ("/.well-known/llms.txt",                  "llms.txt", "LLM-friendly site description"),
]


def _is_interesting(content_preview: str) -> bool:
    # Looks like JSON or XML or a structured txt — true positive.
    cp = content_preview.strip()
    if not cp:
        return False
    return (cp.startswith(("{", "[", "<?xml", "<")) or
            any(k in cp.lower() for k in ("contact:", "expires:", "policy:",
                                          "issuer", "authorization_endpoint",
                                          "version=", "namespaces", "uri=")))


async def _probe(domain: str, path: str, label: str, hint: str) -> Hit | None:
    url = f"https://{domain}{path}"
    try:
        client = await get_client()
        r = await client.get(url, timeout=_TIMEOUT,
                             follow_redirects=True)
    except Exception as e:
        return Hit(module=NAME, source=label, category="well-known",
                   url=url, status=classify_exception(e),
                   title=domain, detail=f"{type(e).__name__}: {e}")
    if r.status_code != 200:
        return None  # silent on 4xx — too many domains to spam negatives
    body = (r.text or "")[:1500]
    if not _is_interesting(body):
        return None
    # Pretty-print JSON preview if applicable
    preview = body.replace("\n", " ").strip()[:140]
    sev = Severity.INFO
    extra: dict[str, Any] = {"bytes": len(r.text or ""), "preview": preview}
    if label.startswith("security.txt") or label == "ai.txt" or label == "llms.txt":
        sev = Severity.LOW
    if label == "saml-metadata" or label == "idp-metadata":
        sev = Severity.MEDIUM
        extra["note"] = "SAML metadata often reveals internal IdP names + entity IDs"
    if "openid" in label or "oauth" in label:
        sev = Severity.LOW
        try:
            data = json.loads(body) if body.lstrip().startswith("{") else {}
            extra["issuer"] = data.get("issuer", "")
            extra["endpoints"] = [k for k in data if k.endswith("_endpoint")]
        except Exception:
            pass
    return Hit(module=NAME, source=label, category="well-known",
               url=url, status=HitStatus.FOUND, title=f"{hint} @ {domain}",
               detail=f"{label}: {preview}", severity=sev, extra=extra)


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.DOMAIN:
        return
    domain = (query.value or "").strip().lower().lstrip("*.").rstrip("/")
    if not domain:
        return
    sem = asyncio.Semaphore(8)

    async def gated(path: str, label: str, hint: str) -> Hit | None:
        async with sem:
            return await _probe(domain, path, label, hint)

    tasks = [asyncio.create_task(gated(p, l, h)) for p, l, h in PATHS]
    n_found = 0
    for fut in asyncio.as_completed(tasks):
        try:
            hit = await fut
        except Exception as e:
            yield Hit(module=NAME, source=NAME, status=HitStatus.ERROR,
                      detail=f"{type(e).__name__}: {e}")
            continue
        if hit is None:
            continue
        n_found += 1
        yield hit
    yield Hit(module=NAME, source="summary", category="well-known",
              status=HitStatus.FOUND if n_found else HitStatus.NO_DATA,
              title=domain,
              detail=f"checked {len(PATHS)} well-known paths, {n_found} found",
              severity=Severity.INFO,
              extra={"checked": len(PATHS), "found": n_found})


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN], run)
