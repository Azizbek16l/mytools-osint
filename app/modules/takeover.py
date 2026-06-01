"""Subdomain takeover detector — subjack/can-i-take-over-xyz style.

For each subdomain discovered via crt.sh, resolve CNAME and check whether
it points to a known-orphanable cloud service. If yes, fetch the host and
match the response body/headers against the service's "this name is
available — claim it" fingerprint.

A positive Hit means: an attacker who registers the CNAME target can
serve traffic at the subdomain. **Treat as CRITICAL.**

Fingerprints are kept small and curated; the canonical full set lives in
EdOverflow/can-i-take-over-xyz. Add new entries as needed.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import dns.asyncresolver
import httpx

from app.core.classify import classify_exception
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "takeover"

_CRTSH = "https://crt.sh/?q={domain}&output=json"
_MAX_SUBS = 40            # cap to keep this module under ~30s
_HTTP_TIMEOUT = 6.0
_DNS_TIMEOUT = 4.0

# Subjack-style fingerprints. Keep narrow — false positives are worse than
# missed detections; an SSRF/admin-panel scan is the user's next step.
FINGERPRINTS: list[dict[str, Any]] = [
    {"service": "AWS S3", "cname": [".s3.amazonaws.com", ".s3-website"],
     "body": ["NoSuchBucket", "The specified bucket does not exist"]},
    {"service": "GitHub Pages", "cname": [".github.io"],
     "body": ["There isn't a GitHub Pages site here."]},
    {"service": "Heroku", "cname": [".herokuapp.com"],
     "body": ["No such app", "herokucdn.com/error-pages/no-such-app.html"]},
    {"service": "Shopify", "cname": [".myshopify.com"],
     "body": ["Sorry, this shop is currently unavailable."]},
    {"service": "Tumblr", "cname": [".tumblr.com"],
     "body": ["Whatever you were looking for doesn't currently exist at this address."]},
    {"service": "Fastly", "cname": [".fastly.net"],
     "body": ["Fastly error: unknown domain"]},
    {"service": "Pantheon", "cname": [".pantheonsite.io"],
     "body": ["The gods are wise, but do not know of the site which you seek."]},
    {"service": "Unbounce", "cname": [".unbouncepages.com"],
     "body": ["The requested URL was not found on this server."]},
    {"service": "Surge.sh", "cname": [".surge.sh"],
     "body": ["project not found"]},
    {"service": "Bitbucket", "cname": [".bitbucket.io"],
     "body": ["Repository not found"]},
    {"service": "Cargo", "cname": [".cargocollective.com"],
     "body": ["404 Not Found"]},
    {"service": "Smugmug", "cname": [".smugmug.com"],
     "body": ["page not found"]},
    {"service": "Tilda", "cname": [".tilda.ws", ".tildacdn.com"],
     "body": ["Please renew your subscription"]},
    {"service": "Wordpress.com", "cname": [".wordpress.com"],
     "body": ["Do you want to register"]},
    {"service": "Help Scout", "cname": [".helpscoutdocs.com"],
     "body": ["No settings were found for this company"]},
    {"service": "Vercel", "cname": [".vercel.app", ".now.sh"],
     "body": ["The deployment could not be found on Vercel.",
              "DEPLOYMENT_NOT_FOUND"]},
    {"service": "Netlify", "cname": [".netlify.app", ".netlify.com"],
     "body": ["Not Found - Request ID:"]},
    {"service": "Webflow", "cname": [".webflow.io"],
     "body": ["The page you are looking for doesn't exist or has been moved."]},
    {"service": "Ghost", "cname": [".ghost.io"],
     "body": ["The thing you were looking for is no longer here, or never was"]},
    {"service": "Azure", "cname": [".azurewebsites.net", ".cloudapp.net", ".trafficmanager.net"],
     "body": ["404 Web Site not found"]},
]


async def _list_subs(domain: str) -> set[str]:
    out: set[str] = set()
    try:
        client = await get_client()
        r = await client.get(_CRTSH.format(domain=domain), timeout=12.0,
                             headers={"Accept": "application/json"})
        if r.status_code == 200:
            for row in r.json() or []:
                for name in str(row.get("name_value") or "").splitlines():
                    n = name.strip().lower().lstrip("*.")
                    if n and n.endswith(domain) and n != domain:
                        out.add(n)
    except Exception:
        pass
    return out


async def _cname_chain(host: str) -> list[str]:
    chain: list[str] = []
    current = host
    for _ in range(6):
        try:
            ans = await dns.asyncresolver.resolve(current, "CNAME", lifetime=_DNS_TIMEOUT)
        except Exception:
            break
        targets = [r.to_text().rstrip(".").lower() for r in ans]
        if not targets:
            break
        next_hop = targets[0]
        chain.append(next_hop)
        if next_hop == current:
            break
        current = next_hop
    return chain


def _match_service(chain: list[str]) -> dict[str, Any] | None:
    for hop in chain:
        for fp in FINGERPRINTS:
            for marker in fp["cname"]:
                if marker.lower() in hop:
                    return fp
    return None


async def _check_one(sub: str) -> Hit | None:
    chain = await _cname_chain(sub)
    fp = _match_service(chain)
    if not fp:
        return None
    target_url = f"https://{sub}/"
    try:
        client = await get_client()
        r = await client.get(target_url, timeout=_HTTP_TIMEOUT,
                             follow_redirects=True)
    except httpx.HTTPError as e:
        # CNAME points to known service but host unreachable — still worth
        # flagging as a *candidate* for takeover (defender should claim it).
        return Hit(
            module=NAME, source=fp["service"], category="takeover",
            url=target_url, status=HitStatus.UNCERTAIN,
            title=sub,
            detail=f"CNAME → {chain[-1] if chain else '?'} ({fp['service']}); "
                   f"host unreachable: {type(e).__name__}",
            severity=Severity.HIGH,
            extra={"cname_chain": chain, "service": fp["service"]},
        )
    except Exception as e:
        return Hit(
            module=NAME, source=fp["service"], category="takeover",
            url=target_url, status=classify_exception(e),
            title=sub, detail=f"{type(e).__name__}: {e}",
            extra={"cname_chain": chain, "service": fp["service"]},
        )
    body_l = (r.text or "").lower()
    matched = next((b for b in fp["body"] if b.lower() in body_l), None)
    if matched:
        return Hit(
            module=NAME, source=fp["service"], category="takeover",
            url=target_url, status=HitStatus.FOUND, title=sub,
            detail=f"TAKEOVER → CNAME → {chain[-1]}; body matches '{matched[:40]}'",
            severity=Severity.CRITICAL,
            extra={"cname_chain": chain, "service": fp["service"],
                   "http_status": r.status_code, "marker": matched},
        )
    return Hit(
        module=NAME, source=fp["service"], category="takeover",
        url=target_url, status=HitStatus.NO_DATA, title=sub,
        detail=f"CNAME → {chain[-1]} ({fp['service']}) but no takeover marker — claimed",
        severity=Severity.INFO,
        extra={"cname_chain": chain, "service": fp["service"],
               "http_status": r.status_code},
    )


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.DOMAIN:
        return
    domain = (query.value or "").strip().lower().lstrip("*.")
    if not domain:
        return
    subs = await _list_subs(domain)
    if not subs:
        yield Hit(module=NAME, source="crt.sh", category="takeover",
                  status=HitStatus.NO_DATA, title=domain,
                  detail="no subdomains found via crt.sh")
        return
    # Bias towards likely-vulnerable subdomains: short names like 'staging',
    # 'old', 'beta', 'dev', 'test' are most often forgotten cloud apps.
    bias = {"old", "staging", "dev", "test", "beta", "preview", "demo",
            "uat", "qa", "stage", "blog", "shop", "support", "help"}
    ranked = sorted(subs, key=lambda s: (
        0 if any(b == s.split(".", 1)[0] for b in bias) else 1, s
    ))
    sample = ranked[:_MAX_SUBS]
    sem = asyncio.Semaphore(8)

    async def gated(s: str) -> Hit | None:
        async with sem:
            return await _check_one(s)

    tasks = [asyncio.create_task(gated(s)) for s in sample]
    findings = 0
    for fut in asyncio.as_completed(tasks):
        try:
            hit = await fut
        except Exception as e:
            yield Hit(module=NAME, source=NAME, status=HitStatus.ERROR,
                      detail=f"{type(e).__name__}: {e}")
            continue
        if hit is not None:
            findings += 1
            yield hit
    if findings == 0:
        yield Hit(module=NAME, source="summary", category="takeover",
                  status=HitStatus.NO_DATA, title=domain,
                  detail=f"checked {len(sample)} subdomain(s), 0 takeover candidates")


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN], run)
