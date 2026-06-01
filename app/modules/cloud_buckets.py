"""Public cloud-bucket enumerator — S3 / Azure Blob / GCS / R2 / DO Spaces.

Generates likely bucket names from the target (`domain`, `domain-backups`,
`acme-prod-logs` etc.) and probes each cloud's public endpoint for a 200
or a "bucket-exists-but-private" response. Anonymous LIST is attempted on
hits — if the bucket allows it, that's an instant data-exposure flag.

Why this matters: forgotten `acme-backups` / `acme-staging-logs` / `acme-dev`
S3 buckets are the #1 source of public-data leaks in incident retros.
There's no cloud_enum maintained on PyPI; this is a curated minimal version.

No API keys. Pure HTTP HEAD/GET against the cloud's public anonymous endpoint.
"""
from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator

from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "cloud_buckets"

_TIMEOUT = 6.0
_CONCURRENCY = 12

PERMUTATIONS = [
    "{base}", "{base}-backups", "{base}-backup", "{base}-prod", "{base}-staging",
    "{base}-dev", "{base}-test", "{base}-logs", "{base}-data", "{base}-uploads",
    "{base}-public", "{base}-private", "{base}-archive", "{base}-config",
    "{base}-assets", "{base}-static", "{base}-media", "{base}-files",
    "{base}-secrets", "{base}-db", "{base}-database", "{base}-images",
    "backup-{base}", "prod-{base}", "logs-{base}", "data-{base}",
]

# Cloud probe templates. Each returns (provider, url, anon_list_url).
CLOUDS = [
    ("AWS S3 (path)",      "https://s3.amazonaws.com/{name}",
                            "https://s3.amazonaws.com/{name}?list-type=2"),
    ("AWS S3 (virtual)",   "https://{name}.s3.amazonaws.com",
                            "https://{name}.s3.amazonaws.com/?list-type=2"),
    ("DigitalOcean Spaces","https://{name}.nyc3.digitaloceanspaces.com",
                            "https://{name}.nyc3.digitaloceanspaces.com/?list-type=2"),
    ("Azure Blob",         "https://{name}.blob.core.windows.net/?comp=list",
                            "https://{name}.blob.core.windows.net/?comp=list"),
    ("Google Cloud Storage","https://storage.googleapis.com/{name}",
                            "https://storage.googleapis.com/{name}?list-type=2"),
    ("Backblaze B2",       "https://f000.backblazeb2.com/file/{name}/",
                            "https://f000.backblazeb2.com/file/{name}/"),
]


def _candidates(base: str) -> list[str]:
    base_clean = re.sub(r"[^a-z0-9-]", "-", base.lower())
    base_clean = re.sub(r"-+", "-", base_clean).strip("-")
    return list({tpl.format(base=base_clean) for tpl in PERMUTATIONS})


def _classify_response(code: int, body: str, provider: str) -> tuple[HitStatus, Severity, str]:
    if code == 200:
        # S3-style: 200 + ListBucketResult → ANONYMOUS LIST allowed (CRITICAL)
        if "<ListBucketResult" in body or "<EnumerationResults" in body or '"items":' in body:
            return (HitStatus.FOUND, Severity.CRITICAL,
                    "PUBLIC BUCKET + ANONYMOUS LIST ALLOWED — data exposure")
        return (HitStatus.FOUND, Severity.HIGH,
                "bucket responds 200 anonymously")
    if code == 403:
        # 403 usually = bucket exists but no public list/read
        if any(m in body for m in ("AccessDenied", "AuthenticationRequired",
                                    "All access to this object has been disabled")):
            return (HitStatus.FOUND, Severity.MEDIUM,
                    "bucket EXISTS but no anonymous access (HTTP 403)")
        return (HitStatus.UNCERTAIN, Severity.LOW, "HTTP 403 — ambiguous")
    if code == 404 or code == 0:
        return (HitStatus.NOT_FOUND, Severity.INFO, "no such bucket")
    if code == 400:
        # Azure returns 400 for invalid names — usually means name doesn't match
        # their naming rules, not that it's vulnerable
        return (HitStatus.NOT_FOUND, Severity.INFO, "HTTP 400 (invalid name)")
    return (HitStatus.UNCERTAIN, Severity.LOW, f"HTTP {code}")


async def _probe(provider: str, url: str, name: str) -> Hit | None:
    """Probe one (provider, bucket-name) pair.

    Returns a Hit ONLY for an actionable finding (a bucket that EXISTS — FOUND).
    Negatives (NOT_FOUND) and low-signal noise (UNCERTAIN 403-ambiguous / odd
    status / transport error against a non-existent name) return None so the
    caller can collapse them into a single summary row instead of emitting one
    row per permutation (~360 probes per domain otherwise).
    """
    try:
        client = await get_client()
        r = await client.get(url, timeout=_TIMEOUT,
                             follow_redirects=False)
        code = r.status_code
        body = r.text[:2000] if r.text else ""
    except Exception:
        # A transport error against a *guessed* bucket name is just "name doesn't
        # resolve / not reachable" — not actionable. Collapse into the summary.
        return None
    status, sev, detail = _classify_response(code, body, provider)
    if status != HitStatus.FOUND:
        # NOT_FOUND and UNCERTAIN are non-findings for a brute-force enumerator.
        return None
    return Hit(
        module=NAME, source=provider, category="cloud-leak",
        url=url, status=status, title=name,
        detail=detail, severity=sev,
        extra={"http_status": code, "provider": provider, "name": name},
    )


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.DOMAIN:
        return
    domain = (query.value or "").strip().lower().lstrip("*.").rstrip("/")
    if not domain:
        return
    # Derive multiple bases: full domain, root label, label-without-tld
    root = domain.split(".")[0] if "." in domain else domain
    bases: set[str] = {root}
    if "." in domain:
        bases.add(domain.replace(".", "-"))
    bases.add(root.replace("-", ""))
    cand: set[str] = set()
    for b in bases:
        cand.update(_candidates(b))
    candidates = sorted(cand)[:60]  # cap to keep latency in check

    sem = asyncio.Semaphore(_CONCURRENCY)

    async def gated(provider: str, url_tpl: str, name: str) -> Hit | None:
        async with sem:
            return await _probe(provider, url_tpl.format(name=name), name)

    tasks: list[asyncio.Task[Hit | None]] = []
    for c in candidates:
        for provider, url_tpl, _ in CLOUDS:
            tasks.append(asyncio.create_task(gated(provider, url_tpl, c)))

    n_found = 0
    n_critical = 0
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
        if hit.severity == Severity.CRITICAL:
            n_critical += 1
        yield hit
    yield Hit(module=NAME, source="summary", category="cloud-leak",
              status=HitStatus.FOUND if n_found else HitStatus.NO_DATA,
              title=domain,
              detail=f"checked {len(candidates)} candidate names × {len(CLOUDS)} clouds, "
                     f"{n_found} hits, {n_critical} critical anonymous-list",
              severity=Severity.INFO,
              extra={"candidates": len(candidates), "found": n_found,
                     "critical": n_critical})


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN], run)
