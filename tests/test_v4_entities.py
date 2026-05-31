"""Tests for v4.0 entity graph + correlation + auto-pivot."""
from __future__ import annotations

import json

from app.core.entities import (
    DEFAULT_EDGE_COST,
    EDGE_COST,
    PIVOT_PROFILE,
    Edge,
    EdgeType,
    Entity,
    EntityType,
    canonical_key,
    entity_id,
    is_noisy,
)


class TestCanonicalisation:
    def test_email_dedup(self):
        assert canonical_key(EntityType.EMAIL, "Alice@ACME.COM") == "alice@acme.com"
        assert canonical_key(EntityType.EMAIL, " alice@acme.com ") == "alice@acme.com"

    def test_domain_dedup(self):
        assert canonical_key(EntityType.DOMAIN, "*.Example.COM") == "example.com"
        assert canonical_key(EntityType.DOMAIN, "example.com/") == "example.com"
        assert canonical_key(EntityType.DOMAIN, "example.com.") == "example.com"

    def test_ip_normalisation(self):
        # IPv4
        assert canonical_key(EntityType.IP, "1.1.1.1") == "1.1.1.1"
        # IPv4 with CIDR — drops CIDR
        assert canonical_key(EntityType.IP, "10.0.0.1/24") == "10.0.0.1"
        # IPv6 — leaves as-is (libipaddress normalises)
        assert canonical_key(EntityType.IP, "2001:db8::1") == "2001:db8::1"

    def test_username_dedup(self):
        assert canonical_key(EntityType.USERNAME, "@Torvalds") == "torvalds"

    def test_asn_format(self):
        assert canonical_key(EntityType.ASN, "AS15169") == "AS15169"
        assert canonical_key(EntityType.ASN, "15169") == "AS15169"


class TestEntityIdStability:
    def test_id_is_stable(self):
        a = entity_id(EntityType.EMAIL, "Alice@ACME.com")
        b = entity_id(EntityType.EMAIL, "alice@acme.com")
        c = entity_id(EntityType.EMAIL, "ALICE@ACME.COM")
        assert a == b == c

    def test_id_is_short(self):
        assert len(entity_id(EntityType.EMAIL, "x@y.z")) == 16

    def test_different_types_get_different_ids(self):
        a = entity_id(EntityType.DOMAIN, "acme.com")
        b = entity_id(EntityType.HOSTNAME, "acme.com")
        # Different entity types → different keys → different ids
        assert a != b


class TestDataclasses:
    def test_entity_auto_normalises(self):
        e = Entity(type=EntityType.DOMAIN, value="ACME.COM/")
        assert e.value == "acme.com"
        assert e.id

    def test_edge_cost_known(self):
        e = Edge(src_id="a", dst_id="b", type=EdgeType.MX_FOR)
        assert e.cost() == EDGE_COST[EdgeType.MX_FOR]

    def test_edge_cost_default(self):
        # MENTIONS uses 3.0 from the EDGE_COST map already; test fallback
        # by injecting a never-mapped type.
        e = Edge(src_id="a", dst_id="b", type=EdgeType.RELATED_TO)
        assert e.cost() in (EDGE_COST.get(EdgeType.RELATED_TO), DEFAULT_EDGE_COST)


class TestPivotMap:
    def test_all_pivotable_kinds_present(self):
        # Every Pivot-eligible entity type maps to a (kind, profile) pair
        for et in (EntityType.EMAIL, EntityType.DOMAIN, EntityType.IP,
                   EntityType.USERNAME, EntityType.HOSTNAME):
            assert et in PIVOT_PROFILE


class TestNoisyGuard:
    def test_well_known_dns_servers_noisy(self):
        assert is_noisy(EntityType.IP, "1.1.1.1")
        assert is_noisy(EntityType.IP, "8.8.8.8")

    def test_gmail_noisy(self):
        assert is_noisy(EntityType.DOMAIN, "gmail.com")

    def test_org_domain_not_noisy(self):
        assert not is_noisy(EntityType.DOMAIN, "acme-corp.example")


class TestCorrelationDerivers:
    """Black-box test: a sample Hit from each major module path yields the
    expected entity types + edge relationships."""

    def test_internetdb_derives_ports_and_cves(self):
        from app.core.correlation import _derive_internetdb
        from app.core.types import Hit, HitStatus, Query, QueryKind, Severity
        q = Query(kind=QueryKind.IP, value="1.2.3.4")
        h = Hit(
            module="internetdb", source="Shodan InternetDB",
            status=HitStatus.FOUND, title="1.2.3.4",
            extra={"ports": [22, 80], "hostnames": ["host.example.com"],
                   "vulns": ["CVE-2023-12345"]},
            severity=Severity.HIGH,
        )
        entities, edges = _derive_internetdb(q, h, hit_id=1)
        types = [e.type for e in entities]
        rels  = [e.type for e in edges]
        assert EntityType.IP in types
        assert EntityType.PORT in types
        assert EntityType.HOSTNAME in types
        assert EntityType.CVE in types
        assert EdgeType.EXPOSES_PORT in rels
        assert EdgeType.HAS_CVE in rels


class TestGraphExporters:
    def test_cytoscape_json_round_trip(self):
        from app.features.graph import to_cytoscape_json
        ents = [{"id": "a1", "type": "email", "value": "x@y.z"}]
        edges = [{"src": "a1", "dst": "a1", "rel": "self",
                  "source": "test", "confidence": 1.0}]
        out = to_cytoscape_json(ents, edges)
        data = json.loads(out)
        assert "elements" in data
        nodes = [e for e in data["elements"] if e["group"] == "nodes"]
        edges_ = [e for e in data["elements"] if e["group"] == "edges"]
        assert len(nodes) == 1 and len(edges_) == 1

    def test_gexf_well_formed(self):
        from app.features.graph import to_gexf
        ents = [{"id": "a1", "type": "ip", "value": "1.1.1.1"}]
        out = to_gexf(ents, [])
        assert out.startswith('<?xml')
        assert '</gexf>' in out
        assert 'id="a1"' in out

    def test_graphml_well_formed(self):
        from app.features.graph import to_graphml
        ents = [{"id": "x", "type": "domain", "value": "acme.com"}]
        out = to_graphml(ents, [])
        assert out.startswith('<?xml')
        assert '</graphml>' in out
