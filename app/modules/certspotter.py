"""CertSpotter — CT-log subdomain enumeration (v4.2).

crt.sh is the canonical free CT-log source but famously flaky (DB timeouts,
sporadic 500s, slow queries on big domains). CertSpotter publishes the same
data via JSON API with a generous unauthenticated quota (100 req/hr/IP).

We hit them in parallel with crt.sh in the discovery flow. Either source
returning subdomains is enough; dedup happens at the entity-graph layer.

Endpoint: https://api.certspotter.com/v1/issuances
  ?domain={target}
  &include_subdomains=true
  &expand=dns_names
"""
from __future__ import annotations

from collections.abc import AsyncIterator

from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "certspotter"
_TIMEOUT = 15.0
_MAX_RESULTS = 1000        # CertSpotter pages at 1000


async def _run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.DOMAIN:
        return
    domain = (query.value or "").strip().lower().lstrip("*.").rstrip("/")
    url = (f"https://api.certspotter.com/v1/issuances"
           f"?domain={domain}&include_subdomains=true&expand=dns_names")
    client = await get_client()
    try:
        r = await client.get(url, timeout=_TIMEOUT,
                             headers={"accept": "application/json"})
    except Exception as e:
        yield Hit(module=NAME, source="CertSpotter", category="dns",
                  url=url, status=HitStatus.ERROR,
                  detail=f"{type(e).__name__}: {e}")
        return
    if r.status_code == 429:
        yield Hit(module=NAME, source="CertSpotter", category="dns",
                  url=url, status=HitStatus.RATE_LIMITED,
                  detail="100 req/hour free quota exceeded — falls back to crt.sh")
        return
    if r.status_code != 200:
        yield Hit(module=NAME, source="CertSpotter", category="dns",
                  url=url, status=HitStatus.NO_DATA,
                  detail=f"HTTP {r.status_code}")
        return
    try:
        rows = r.json()
    except Exception as e:
        yield Hit(module=NAME, source="CertSpotter", category="dns",
                  url=url, status=HitStatus.ERROR,
                  detail=f"bad json: {e}")
        return
    if not isinstance(rows, list) or not rows:
        yield Hit(module=NAME, source="CertSpotter", category="dns",
                  url=url, status=HitStatus.NO_DATA,
                  detail="0 CT entries")
        return
    # Collect unique dns_names across all issuances.
    seen: set[str] = set()
    for issuance in rows[:_MAX_RESULTS]:
        for name in issuance.get("dns_names") or []:
            name = name.strip().lower().lstrip("*.")
            if not name or not name.endswith(domain):
                continue
            seen.add(name)
    for sub in sorted(seen):
        if sub == domain:
            continue  # skip apex
        yield Hit(module=NAME, source="CertSpotter", category="dns",
                  url=f"https://{sub}",
                  status=HitStatus.FOUND,
                  title=f"subdomain: {sub}",
                  detail="surfaced from CT logs (CertSpotter)",
                  severity=Severity.LOW,
                  extra={"subdomain": sub})
    yield Hit(module=NAME, source="CertSpotter", category="dns",
              url=url, status=HitStatus.FOUND,
              title=f"{len(seen)} unique subdomains across {len(rows)} certs",
              detail="independent CT-log corroboration of crt.sh",
              severity=Severity.INFO,
              extra={"unique_subdomains": len(seen), "certs": len(rows)})


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN], _run)
