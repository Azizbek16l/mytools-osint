"""Hit → (entities, edges) derivation engine.

Per the backend reviewer's recommendation, each module SHOULD ideally expose
its own `derive_entities(hit)` callable. Until we migrate all 32 modules to
that pattern, this central engine handles known module shapes via pattern
matching on (hit.module, hit.source, hit.category, hit.extra).

Strategy:
  1. Always derive the QUERY ROOT entity from query.kind + query.value.
  2. Per-module derivers: dict[module_name → callable(query, hit) -> (entities, edges)]
  3. Fallback derivers: heuristic regex matches on hit.detail / hit.url for
     anything not handled explicitly.
  4. Cap derivation output per-hit (MAX_DERIVED) so a wide cert/SAN response
     doesn't drown the DB. Log when truncated.

Each per-module deriver function returns (list[Entity], list[Edge]). Edges
reference src/dst by entity_id; entities are upserted before edges by the
caller (db.entity_upsert → db.edge_upsert).
"""
from __future__ import annotations

import logging
import re
from collections.abc import Callable
from typing import Any

from app.core.entities import (
    EDGE_COST,
    DEFAULT_EDGE_COST,
    Edge,
    EdgeType,
    Entity,
    EntityType,
    canonical_key,
    entity_id,
    is_noisy,
)
from app.core.types import Hit, HitStatus, Query, QueryKind

log = logging.getLogger("mytools-osint.correlation")

MAX_DERIVED_ENTITIES_PER_HIT = 50
MAX_DERIVED_EDGES_PER_HIT = 100


# ---- helpers -------------------------------------------------------------

_EMAIL_RE  = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IP_RE     = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
                        re.IGNORECASE)
_CVE_RE    = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_ASN_RE    = re.compile(r"\bAS\d+\b", re.IGNORECASE)
_HASH_RE   = re.compile(r"\b[a-fA-F0-9]{32,128}\b")


def _query_root_entity(query: Query) -> Entity | None:
    """Map a Query into its root entity."""
    kind_to_type = {
        QueryKind.EMAIL:    EntityType.EMAIL,
        QueryKind.DOMAIN:   EntityType.DOMAIN,
        QueryKind.IP:       EntityType.IP,
        QueryKind.USERNAME: EntityType.USERNAME,
        QueryKind.PHONE:    EntityType.PHONE,
        QueryKind.TELEGRAM: EntityType.TELEGRAM,
        QueryKind.WHATSAPP: EntityType.PHONE,
        QueryKind.PASSWORD: None,    # never store passwords as entities
        QueryKind.HASH:     EntityType.HASH,
    }
    et = kind_to_type.get(query.kind)
    if et is None:
        return None
    return Entity(type=et, value=query.value)


def _edge(src: Entity, dst: Entity, etype: EdgeType, hit: Hit,
          hit_id: int | None) -> Edge:
    return Edge(
        src_id=src.id, dst_id=dst.id, type=etype,
        source=hit.module, hit_id=hit_id,
        confidence=1.0 if hit.status == HitStatus.FOUND else 0.5,
        extra={"detail": (hit.detail or "")[:240]},
    )


# ---- per-module derivers -------------------------------------------------

def _derive_domain_module(query: Query, hit: Hit, hit_id: int | None) -> tuple[list[Entity], list[Edge]]:
    """For modules in the `domain` module — subdomain enum, DNS records."""
    root = _query_root_entity(query)
    if root is None or hit.status != HitStatus.FOUND:
        return [], []
    entities: list[Entity] = [root]
    edges: list[Edge] = []
    # source is the FQDN of the found subdomain (per domain.py convention)
    sub_value = hit.source or hit.title
    if sub_value and "." in sub_value and sub_value != query.value:
        sub = Entity(type=EntityType.SUBDOMAIN, value=sub_value)
        entities.append(sub)
        edges.append(_edge(sub, root, EdgeType.SUBDOMAIN_OF, hit, hit_id))
    return entities, edges


def _derive_internetdb(query: Query, hit: Hit, hit_id: int | None) -> tuple[list[Entity], list[Edge]]:
    """Shodan InternetDB ports + CVEs + hostnames per IP."""
    root = _query_root_entity(query)
    if root is None:
        return [], []
    entities: list[Entity] = [root]
    edges: list[Edge] = []
    # hit.title is the IP we resolved; might differ from root if root is DOMAIN
    ip_value = hit.title or ""
    ip = None
    if _IP_RE.match(ip_value):
        ip = Entity(type=EntityType.IP, value=ip_value)
        entities.append(ip)
        if root.type == EntityType.DOMAIN and ip.id != root.id:
            edges.append(_edge(root, ip, EdgeType.RESOLVES_TO, hit, hit_id))
    pivot = ip or root
    if pivot.type != EntityType.IP:
        return entities, edges
    extra = hit.extra or {}
    for port in (extra.get("ports") or [])[:20]:
        port_value = f"{pivot.value}:{port}"
        port_ent = Entity(type=EntityType.PORT, value=port_value)
        entities.append(port_ent)
        edges.append(_edge(pivot, port_ent, EdgeType.EXPOSES_PORT, hit, hit_id))
    for hostname in (extra.get("hostnames") or [])[:10]:
        h = Entity(type=EntityType.HOSTNAME, value=hostname)
        entities.append(h)
        edges.append(_edge(pivot, h, EdgeType.REVERSE_DNS_TO, hit, hit_id))
    for cve in (extra.get("vulns") or [])[:20]:
        c = Entity(type=EntityType.CVE, value=cve)
        entities.append(c)
        edges.append(_edge(pivot, c, EdgeType.HAS_CVE, hit, hit_id))
    return entities, edges


def _derive_asn(query: Query, hit: Hit, hit_id: int | None) -> tuple[list[Entity], list[Edge]]:
    """asn_bgp module produces ASN entities for an IP."""
    root = _query_root_entity(query)
    if root is None:
        return [], []
    extra = hit.extra or {}
    asn_no = extra.get("asn") or _ASN_RE.search(hit.detail or "")
    if asn_no is None:
        return [], []
    asn_value = asn_no if isinstance(asn_no, str) else asn_no.group(0)
    asn = Entity(type=EntityType.ASN, value=asn_value)
    return [root, asn], [_edge(root, asn, EdgeType.IN_ASN, hit, hit_id)]


def _derive_takeover(query: Query, hit: Hit, hit_id: int | None) -> tuple[list[Entity], list[Edge]]:
    """takeover module → flag subdomain as takeover candidate for a service."""
    root = _query_root_entity(query)
    if root is None or hit.status != HitStatus.FOUND:
        return [], []
    sub_value = hit.title or hit.source
    if not sub_value or "." not in sub_value:
        return [], []
    sub = Entity(type=EntityType.SUBDOMAIN, value=sub_value)
    return [root, sub], [_edge(sub, root, EdgeType.TAKEOVER_CANDIDATE, hit, hit_id)]


def _derive_threat_intel(query: Query, hit: Hit, hit_id: int | None) -> tuple[list[Entity], list[Edge]]:
    """URLhaus / ThreatFox / PhishTank — root is blacklisted on a source."""
    root = _query_root_entity(query)
    if root is None or hit.status != HitStatus.FOUND:
        return [], []
    src_label = Entity(type=EntityType.ORG, value=hit.source or "threat-intel")
    return [root, src_label], [_edge(root, src_label, EdgeType.BLACKLISTED_ON, hit, hit_id)]


def _derive_typosquat(query: Query, hit: Hit, hit_id: int | None) -> tuple[list[Entity], list[Edge]]:
    root = _query_root_entity(query)
    if root is None or hit.status != HitStatus.FOUND:
        return [], []
    candidate = hit.title or ""
    if not candidate or "." not in candidate:
        return [], []
    sub = Entity(type=EntityType.DOMAIN, value=candidate)
    return [root, sub], [_edge(sub, root, EdgeType.TYPOSQUAT_OF, hit, hit_id)]


def _derive_email_extras(query: Query, hit: Hit, hit_id: int | None) -> tuple[list[Entity], list[Edge]]:
    """email_extras → root is seen in a breach catalog source."""
    root = _query_root_entity(query)
    if root is None or hit.status != HitStatus.FOUND:
        return [], []
    src = Entity(type=EntityType.ORG, value=hit.source or "breach-source")
    return [root, src], [_edge(root, src, EdgeType.SEEN_IN_BREACH, hit, hit_id)]


def _derive_pgp(query: Query, hit: Hit, hit_id: int | None) -> tuple[list[Entity], list[Edge]]:
    root = _query_root_entity(query)
    if root is None or hit.status != HitStatus.FOUND:
        return [], []
    extra = hit.extra or {}
    fp = extra.get("fingerprint") or extra.get("hash") or ""
    if not fp:
        return [], []
    keyhash = Entity(type=EntityType.HASH, value=fp, tags=["pgp"])
    return [root, keyhash], [_edge(root, keyhash, EdgeType.PGP_KEY, hit, hit_id)]


def _derive_github_leaks(query: Query, hit: Hit, hit_id: int | None) -> tuple[list[Entity], list[Edge]]:
    root = _query_root_entity(query)
    if root is None or hit.status != HitStatus.FOUND:
        return [], []
    extra = hit.extra or {}
    repos = extra.get("repos") or ([extra["repo"]] if extra.get("repo") else [])
    entities = [root]
    edges = []
    for repo_name in repos[:10]:
        if not repo_name:
            continue
        r = Entity(type=EntityType.REPO, value=repo_name)
        entities.append(r)
        edges.append(_edge(r, root, EdgeType.REPO_MENTIONS, hit, hit_id))
    return entities, edges


def _derive_cloud_buckets(query: Query, hit: Hit, hit_id: int | None) -> tuple[list[Entity], list[Edge]]:
    root = _query_root_entity(query)
    if root is None or hit.status != HitStatus.FOUND:
        return [], []
    bucket_name = (hit.extra or {}).get("name") or hit.title
    if not bucket_name:
        return [], []
    b = Entity(type=EntityType.BUCKET, value=bucket_name,
               extra={"provider": hit.source})
    return [root, b], [_edge(b, root, EdgeType.BUCKET_OWNED_BY, hit, hit_id)]


def _derive_username(query: Query, hit: Hit, hit_id: int | None) -> tuple[list[Entity], list[Edge]]:
    """username module — root username has profile URL on a site."""
    root = _query_root_entity(query)
    if root is None or hit.status != HitStatus.FOUND:
        return [], []
    url = hit.url
    if not url:
        return [], []
    u = Entity(type=EntityType.URL, value=url, extra={"site": hit.source})
    return [root, u], [_edge(root, u, EdgeType.MENTIONS, hit, hit_id)]


def _derive_tor(query: Query, hit: Hit, hit_id: int | None) -> tuple[list[Entity], list[Edge]]:
    root = _query_root_entity(query)
    if root is None or hit.status != HitStatus.FOUND:
        return [], []
    return [root], [_edge(root, root, EdgeType.TOR_RELAY, hit, hit_id)]


def _derive_malware_bazaar(query: Query, hit: Hit, hit_id: int | None) -> tuple[list[Entity], list[Edge]]:
    root = _query_root_entity(query)
    if root is None or hit.status != HitStatus.FOUND:
        return [], []
    extra = hit.extra or {}
    family = extra.get("family")
    if not family:
        return [], []
    f = Entity(type=EntityType.ORG, value=family, tags=["malware-family"])
    return [root, f], [_edge(root, f, EdgeType.KNOWN_MALWARE, hit, hit_id)]


# ---- registry -----------------------------------------------------------

_DERIVERS: dict[str, Callable[[Query, Hit, int | None], tuple[list[Entity], list[Edge]]]] = {
    "domain":        _derive_domain_module,
    "internetdb":    _derive_internetdb,
    "asn_bgp":       _derive_asn,
    "takeover":      _derive_takeover,
    "threat_intel":  _derive_threat_intel,
    "typosquat":     _derive_typosquat,
    "email_extras":  _derive_email_extras,
    "pgp_keys":      _derive_pgp,
    "github_leaks":  _derive_github_leaks,
    "cloud_buckets": _derive_cloud_buckets,
    "username":      _derive_username,
    "tor_check":     _derive_tor,
    "malware_bazaar":_derive_malware_bazaar,
}


def _fallback_derive(query: Query, hit: Hit, hit_id: int | None) -> tuple[list[Entity], list[Edge]]:
    """Heuristic last-resort derivation for modules without a custom deriver.

    Extract any email/IP/domain/CVE/hash from hit.detail + hit.url and link
    each back to the root via a low-confidence MENTIONS edge.
    """
    root = _query_root_entity(query)
    if root is None or hit.status != HitStatus.FOUND:
        return [], []
    entities: list[Entity] = [root]
    edges: list[Edge] = []
    text = " ".join(filter(None, [hit.detail or "", hit.url or "", hit.title or ""]))
    seen: set[str] = {root.id}

    def add(etype: EntityType, value: str, rel: EdgeType = EdgeType.MENTIONS) -> None:
        if not value:
            return
        try:
            ent = Entity(type=etype, value=value)
        except Exception:
            return
        if ent.id in seen:
            return
        if is_noisy(etype, ent.value):
            return
        seen.add(ent.id)
        entities.append(ent)
        e = _edge(root, ent, rel, hit, hit_id)
        e.confidence = 0.5
        edges.append(e)

    for m in _EMAIL_RE.findall(text)[:8]:
        add(EntityType.EMAIL, m)
    for m in _IP_RE.findall(text)[:8]:
        add(EntityType.IP, m)
    for m in _CVE_RE.findall(text)[:8]:
        add(EntityType.CVE, m)
    for m in _HASH_RE.findall(text)[:4]:
        # tag as hash only if 32/40/64/128 hex; entity_id normaliser handles rest
        if len(m) in (32, 40, 64, 128):
            add(EntityType.HASH, m)
    return entities, edges


def derive(query: Query, hit: Hit, hit_id: int | None = None) -> tuple[list[Entity], list[Edge]]:
    """Public entry point — pick the right deriver, cap output, return."""
    fn = _DERIVERS.get(hit.module, _fallback_derive)
    try:
        entities, edges = fn(query, hit, hit_id)
    except Exception as exc:
        log.debug("deriver failed for %s: %s", hit.module, exc)
        return [], []
    if len(entities) > MAX_DERIVED_ENTITIES_PER_HIT:
        log.warning("truncating %d → %d entities for hit %s/%s",
                    len(entities), MAX_DERIVED_ENTITIES_PER_HIT,
                    hit.module, hit.source)
        entities = entities[:MAX_DERIVED_ENTITIES_PER_HIT]
    if len(edges) > MAX_DERIVED_EDGES_PER_HIT:
        log.warning("truncating %d → %d edges for hit %s/%s",
                    len(edges), MAX_DERIVED_EDGES_PER_HIT,
                    hit.module, hit.source)
        edges = edges[:MAX_DERIVED_EDGES_PER_HIT]
    return entities, edges
