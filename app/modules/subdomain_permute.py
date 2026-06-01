"""Subdomain permutation generator — altdns-style word mixing.

After `domain` + `subdomain_brute` modules discover real subdomains,
this module generates likely-existing permutations and DNS-checks each.
Inspired by OneForAll + altdns. Pure DNS — no traffic to webservers.

Strategy:
  1. Query the persisted entity graph for SUBDOMAIN entities of this DOMAIN.
  2. Take each discovered label (e.g. "api", "admin", "blog") + mix with
     mutation patterns: dev-X, X-dev, X.dev, X-staging, X-uat, etc.
  3. Generate <= 250 candidates per scan.
  4. Concurrent DNS A-record check via dns.asyncresolver.
  5. Any candidate that resolves → SUBDOMAIN entity + IN-graph edge.

Why this is high-leverage: passive crt.sh enumeration finds prod sites,
but pre-production environments (staging/uat/qa) are often:
  - Missing CDN protection
  - Authenticated only by HTTP Basic + weak creds
  - Running newer/buggier code paths
  - Indexable by Google because nobody set up robots.txt

These are exactly the holes a red team would target.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import dns.asyncresolver

from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "subdomain_permute"

MAX_CANDIDATES = 250
DNS_TIMEOUT = 3.5
CONCURRENCY = 30

# Mutation patterns. {} = the original label.
MUTATIONS = [
    # prefixed envs
    "dev-{}", "staging-{}", "stg-{}", "uat-{}", "qa-{}", "test-{}",
    "preprod-{}", "prod-{}", "beta-{}", "alpha-{}", "demo-{}",
    "internal-{}", "private-{}", "secure-{}", "new-{}", "old-{}",
    "next-{}", "v2-{}", "v3-{}",
    # suffixed envs
    "{}-dev", "{}-staging", "{}-stg", "{}-uat", "{}-qa", "{}-test",
    "{}-preprod", "{}-prod", "{}-beta", "{}-alpha", "{}-demo",
    "{}-internal", "{}-private", "{}-secure", "{}-new", "{}-old",
    "{}-next", "{}-v2", "{}-v3",
    # dot-prefixed envs (real subdomain hierarchy)
    "dev.{}", "staging.{}", "stg.{}", "uat.{}", "qa.{}", "test.{}",
    "preprod.{}", "beta.{}", "demo.{}", "internal.{}", "new.{}",
]

# Common single-word complements to seed labels (in case nothing else found)
SEED_LABELS = [
    "api", "app", "auth", "admin", "dev", "test", "staging", "qa",
    "internal", "vpn", "git", "build", "ci", "deploy",
]


async def _resolve(host: str) -> tuple[str, list[str]]:
    try:
        ans = await dns.asyncresolver.resolve(host, "A", lifetime=DNS_TIMEOUT)
        return host, [r.to_text() for r in ans]
    except Exception:
        return host, []


def _extract_labels(known_subdomains: list[str], domain: str) -> set[str]:
    """Extract the first-label slugs (admin, api, blog…) from a list of
    known subdomains of `domain`.
    """
    labels: set[str] = set()
    suffix = "." + domain
    for sub in known_subdomains:
        if not sub.endswith(suffix):
            continue
        # Strip the apex; take the leftmost label
        rest = sub[:-len(suffix)]
        if not rest:
            continue
        # If subdomain is "api.v1.acme.com", we want "api" as the seed
        first = rest.split(".")[0]
        if first and len(first) <= 40 and first.isascii():
            labels.add(first.lower())
    return labels


async def _known_subdomains(domain: str) -> list[str]:
    """Pull already-discovered subdomains from the persisted entity graph."""
    try:
        from app.core.config import settings
        from app.core.db import Database
        db = Database(settings().db_path)
        await db.connect()
        try:
            assert db._conn is not None
            async with db._conn.execute(
                """SELECT value FROM entities
                   WHERE type IN ('subdomain', 'hostname', 'domain')
                     AND value LIKE ?""",
                (f"%.{domain}",),
            ) as cur:
                return [r["value"] for r in await cur.fetchall()
                        if r["value"].endswith("." + domain) and r["value"] != domain]
        finally:
            await db.close()
    except Exception:
        return []


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.DOMAIN:
        return
    domain = (query.value or "").strip().lower().lstrip("*.").rstrip("/")
    if not domain or "." not in domain:
        return

    known = await _known_subdomains(domain)
    labels = _extract_labels(known, domain)
    # If we have no discovered labels yet, seed from a small common set
    if not labels:
        labels = set(SEED_LABELS)

    yield Hit(module=NAME, source="seed", category="subdomain",
              status=HitStatus.NO_DATA, title=domain,
              detail=f"seeded from {len(labels)} known label(s): "
                     + ", ".join(sorted(labels)[:10])
                     + (" …" if len(labels) > 10 else ""),
              severity=Severity.INFO,
              extra={"labels": sorted(labels)})

    # Generate candidates
    candidates: set[str] = set()
    for lab in labels:
        for pattern in MUTATIONS:
            cand = pattern.format(lab) + "." + domain
            cand = cand.strip(".").lower()
            if cand not in known and cand != domain and len(cand) < 100:
                candidates.add(cand)
            if len(candidates) >= MAX_CANDIDATES:
                break
        if len(candidates) >= MAX_CANDIDATES:
            break

    cands = sorted(candidates)[:MAX_CANDIDATES]
    if not cands:
        return

    sem = asyncio.Semaphore(CONCURRENCY)

    async def gated(host: str) -> tuple[str, list[str]]:
        async with sem:
            return await _resolve(host)

    tasks = [asyncio.create_task(gated(c)) for c in cands]
    n_found = 0
    for fut in asyncio.as_completed(tasks):
        try:
            host, ips = await fut
        except Exception as e:
            yield Hit(module=NAME, source=NAME, status=HitStatus.ERROR,
                      detail=f"{type(e).__name__}: {e}")
            continue
        if not ips:
            continue
        n_found += 1
        yield Hit(
            module=NAME, source="permutation", category="subdomain",
            url=f"https://{host}/",
            status=HitStatus.FOUND, title=host,
            detail=f"permutation hit → {', '.join(ips[:3])}",
            severity=Severity.MEDIUM,
            extra={"host": host, "ips": ips, "labels_seeded": sorted(labels)[:5]},
        )

    yield Hit(module=NAME, source="summary", category="subdomain",
              status=HitStatus.FOUND if n_found else HitStatus.NO_DATA,
              title=domain,
              detail=f"generated {len(cands)} permutations from {len(labels)} "
                     f"seed labels, {n_found} resolve",
              severity=Severity.INFO,
              extra={"candidates": len(cands), "found": n_found,
                     "seed_labels_count": len(labels)})


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN], run)
