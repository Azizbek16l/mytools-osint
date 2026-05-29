"""Entity graph layer — v4.0 cornerstone.

A Hit captures "module M reported finding X about source S". An Entity is the
*thing the finding is about* — an Email, a Domain, an IP, a Username, etc.
Same entity discovered by N modules becomes ONE node in the graph; the N
discoveries become N edges (typed by relationship) with N pieces of evidence.

This module defines:
  - EntityType / EdgeType   : enums of canonical taxonomy
  - Entity / Edge           : dataclasses with canonical-key normalisation
  - canonical_key()         : per-type normaliser
  - entity_id()             : sha1-based stable short id (used as PK)
  - PIVOT_PROFILE           : map entity-type → (query-kind, profile) for auto-pivot

Schema, persistence: see app/core/db.py migration v3 + DAO methods on Database.
Derivation: see app/core/correlation.py.
Graph queries / export: see app/features/graph.py.

We deliberately use a small, OSINT-focused taxonomy (~18 types) over STIX 2.1's
full SDO/SRO surface — STIX is for sharing IOCs across vendors, this is for
single-analyst pivot work. Mapping notes to OCCRP's followthemoney are in
docstrings on each EntityType so the user can later export to FtM if needed.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class EntityType(StrEnum):
    EMAIL     = "email"      # FtM: Email
    DOMAIN    = "domain"     # FtM: Domain (apex)
    SUBDOMAIN = "subdomain"  # FtM: Domain (non-apex)
    IP        = "ip"         # FtM: IpAddress
    URL       = "url"        # FtM: Page
    USERNAME  = "username"   # FtM: UserAccount
    PHONE     = "phone"      # FtM: Phone
    TELEGRAM  = "telegram"   # FtM: UserAccount[service=telegram]
    PERSON    = "person"     # FtM: Person
    ORG       = "org"        # FtM: Organization
    HASH      = "hash"       # FtM: Document (hash sidecar)
    CERT      = "cert"       # SHA-256 fingerprint of a cert
    ASN       = "asn"        # AS number
    BUCKET    = "bucket"     # cloud-storage bucket name
    REPO      = "repo"       # github/gitlab/etc repo
    CVE       = "cve"        # T1190 etc.
    HOSTNAME  = "hostname"   # generic host (unresolved CNAMEs)
    PORT      = "port"       # ip:port — service-graph node
    SOFTWARE  = "software"   # fingerprinted tech-stack entry


class EdgeType(StrEnum):
    # Identity
    HAS_EMAIL          = "has_email"
    USES_USERNAME      = "uses_username"
    HAS_PHONE          = "has_phone"
    HAS_TELEGRAM       = "has_telegram"
    OWNS_REPO          = "owns_repo"
    MEMBER_OF          = "member_of"
    PGP_KEY            = "pgp_key"

    # DNS / Network
    MX_FOR             = "mx_for"
    NS_FOR             = "ns_for"
    RESOLVES_TO        = "resolves_to"
    REVERSE_DNS_TO     = "reverse_dns_to"
    SUBDOMAIN_OF       = "subdomain_of"
    CNAME_TO           = "cname_to"
    OWNS_ASN           = "owns_asn"
    IN_ASN             = "in_asn"
    PEER_ASN           = "peer_asn"

    # Web / app
    CERT_FOR           = "cert_for"
    SAME_FAVICON       = "same_favicon"
    RUNS_SOFTWARE      = "runs_software"
    EXPOSES_PORT       = "exposes_port"
    HAS_CVE            = "has_cve"
    HOSTED_AT          = "hosted_at"

    # Cloud / repo / leak
    CONTAINS_LEAK      = "contains_leak"
    REPO_MENTIONS      = "repo_mentions"
    BUCKET_OWNED_BY    = "bucket_owned_by"

    # Threat intel
    BLACKLISTED_ON     = "blacklisted_on"
    SEEN_IN_BREACH     = "seen_in_breach"
    KNOWN_MALWARE      = "known_malware"
    TOR_RELAY          = "tor_relay"
    TYPOSQUAT_OF       = "typosquat_of"
    TAKEOVER_CANDIDATE = "takeover_candidate"

    # Generic
    MENTIONS           = "mentions"
    RELATED_TO         = "related_to"


# Per-edge traversal cost used by auto-pivot's bounded BFS budget. Edges that
# explode the surface (one cert → 800 SANs) get higher cost so the BFS budget
# runs out before fan-out drowns the analyst.
EDGE_COST: dict[EdgeType, float] = {
    EdgeType.HAS_EMAIL:          1.0,
    EdgeType.USES_USERNAME:      1.0,
    EdgeType.HAS_PHONE:          1.0,
    EdgeType.HAS_TELEGRAM:       1.0,
    EdgeType.OWNS_REPO:          2.0,
    EdgeType.MEMBER_OF:          1.0,
    EdgeType.PGP_KEY:            2.0,
    EdgeType.MX_FOR:             2.0,
    EdgeType.NS_FOR:             3.0,
    EdgeType.RESOLVES_TO:        2.0,
    EdgeType.REVERSE_DNS_TO:     3.0,
    EdgeType.SUBDOMAIN_OF:       1.5,
    EdgeType.CNAME_TO:           2.0,
    EdgeType.OWNS_ASN:           4.0,
    EdgeType.IN_ASN:             4.0,
    EdgeType.PEER_ASN:           5.0,
    EdgeType.CERT_FOR:           5.0,    # high-fanout
    EdgeType.SAME_FAVICON:       4.0,
    EdgeType.RUNS_SOFTWARE:      3.0,
    EdgeType.EXPOSES_PORT:       1.0,
    EdgeType.HAS_CVE:            1.0,
    EdgeType.HOSTED_AT:          2.0,
    EdgeType.CONTAINS_LEAK:      2.0,
    EdgeType.REPO_MENTIONS:      3.0,
    EdgeType.BUCKET_OWNED_BY:    2.0,
    EdgeType.BLACKLISTED_ON:     1.0,
    EdgeType.SEEN_IN_BREACH:     1.0,
    EdgeType.KNOWN_MALWARE:      1.0,
    EdgeType.TOR_RELAY:          1.0,
    EdgeType.TYPOSQUAT_OF:       1.5,
    EdgeType.TAKEOVER_CANDIDATE: 1.0,
    EdgeType.MENTIONS:           3.0,
    EdgeType.RELATED_TO:         3.0,
}
DEFAULT_EDGE_COST = 3.0


# ---- Canonical-key normalisation -----------------------------------------

def _norm_email(v: str) -> str:
    return v.strip().lower()


def _norm_domain(v: str) -> str:
    return v.strip().lower().lstrip("*.").rstrip(".").rstrip("/")


def _norm_ip(v: str) -> str:
    try:
        return str(ipaddress.ip_address(v.strip().split("/", 1)[0]))
    except (ValueError, IndexError):
        return v.strip()


def _norm_url(v: str) -> str:
    return v.strip().rstrip("/")


def _norm_hash(v: str) -> str:
    return v.strip().lower()


def _norm_username(v: str) -> str:
    return v.strip().lstrip("@").lower()


def _norm_phone(v: str) -> str:
    s = v.strip()
    return "+" + re.sub(r"\D", "", s[1:]) if s.startswith("+") else re.sub(r"\D", "", s)


def _norm_asn(v: str) -> str:
    s = re.sub(r"[^0-9]", "", str(v))
    return f"AS{int(s)}" if s else str(v).upper()


def _norm_default(v: str) -> str:
    return v.strip().lower()


_NORMALISERS: dict[EntityType, Any] = {
    EntityType.EMAIL:     _norm_email,
    EntityType.DOMAIN:    _norm_domain,
    EntityType.SUBDOMAIN: _norm_domain,
    EntityType.HOSTNAME:  _norm_domain,
    EntityType.IP:        _norm_ip,
    EntityType.URL:       _norm_url,
    EntityType.USERNAME:  _norm_username,
    EntityType.TELEGRAM:  _norm_username,
    EntityType.PHONE:     _norm_phone,
    EntityType.HASH:      _norm_hash,
    EntityType.CERT:      _norm_hash,
    EntityType.ASN:       _norm_asn,
}


def canonical_key(etype: EntityType, value: str) -> str:
    """Return the normalised key used for dedup. Stable across discoveries."""
    return _NORMALISERS.get(etype, _norm_default)(value)


def entity_id(etype: EntityType, value: str) -> str:
    """Stable short id (sha1 first 16 hex). Used as DB primary key."""
    key = canonical_key(etype, value)
    return hashlib.sha1(f"{etype.value}:{key}".encode()).hexdigest()[:16]


# ---- Dataclasses ---------------------------------------------------------

@dataclass(slots=True)
class Entity:
    type: EntityType
    value: str                            # will be canonicalised in __post_init__
    id: str = ""                          # auto-derived
    first_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    confidence: float = 1.0
    tags: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.value:
            return
        self.value = canonical_key(self.type, self.value)
        if not self.id:
            self.id = entity_id(self.type, self.value)


@dataclass(slots=True)
class Edge:
    src_id: str
    dst_id: str
    type: EdgeType
    source: str = ""                      # module name / data source
    hit_id: int | None = None
    confidence: float = 1.0
    first_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    extra: dict[str, Any] = field(default_factory=dict)

    def cost(self) -> float:
        return EDGE_COST.get(self.type, DEFAULT_EDGE_COST)


# ---- Auto-pivot routing -------------------------------------------------
PIVOT_PROFILE: dict[EntityType, tuple[str, str]] = {
    EntityType.EMAIL:    ("email",    "person"),
    EntityType.DOMAIN:   ("domain",   "ioc"),       # 'ioc' is lighter than 'domain-recon' for pivot
    EntityType.SUBDOMAIN:("domain",   "ioc"),
    EntityType.HOSTNAME: ("domain",   "ioc"),       # a resolved hostname is just another domain
    EntityType.IP:       ("ip",       "ioc"),
    EntityType.USERNAME: ("username", "person"),
    EntityType.TELEGRAM: ("telegram", "person"),
    EntityType.PHONE:    ("phone",    "person"),
    EntityType.HASH:     ("hash",     "ioc"),
}


# ---- Noisy-value guard (SpiderFoot-pattern) -----------------------------
# Values that show up in >10% of typical hits are low-signal; skip pivoting
# into them. The list is curated, not learned — adding to it is cheap.
NOISY_VALUES: dict[EntityType, set[str]] = {
    EntityType.IP: {
        "0.0.0.0", "127.0.0.1", "1.1.1.1", "8.8.8.8", "8.8.4.4",
        "1.0.0.1", "9.9.9.9", "208.67.222.222",
    },
    EntityType.DOMAIN: {
        "gmail.com", "googlemail.com", "outlook.com", "hotmail.com",
        "yahoo.com", "icloud.com", "proton.me", "protonmail.com",
        "github.com", "gitlab.com", "bitbucket.org",
        "google.com", "amazonaws.com", "cloudflare.com",
        "github.io", "vercel.app", "netlify.app", "herokuapp.com",
    },
    EntityType.EMAIL: set(),
    EntityType.USERNAME: {
        "admin", "root", "user", "test", "guest", "info", "support",
        "github", "git", "noreply", "no-reply",
    },
}


def is_noisy(etype: EntityType, value: str) -> bool:
    """Should this entity be SKIPPED for auto-pivot (low signal)?"""
    return canonical_key(etype, value) in NOISY_VALUES.get(etype, set())
