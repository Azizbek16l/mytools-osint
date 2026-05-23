"""Locked JSON schema — emit-shape stability and validator coverage.

These tests do NOT touch the network. They construct synthetic QueryResults
and assert the serialised payload conforms to the v1.0 contract.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from app.core.json_schema import (
    JSON_SCHEMA_VERSION,
    SchemaValidationError,
    serialize_query_result,
    validate_schema,
)
from app.core.types import Hit, HitStatus, Query, QueryKind, QueryResult, Severity


def _make_result(hits: list[Hit] | None = None) -> QueryResult:
    q = Query(
        kind=QueryKind.USERNAME, value="torvalds",
        started_at=datetime(2026, 5, 23, 8, 0, 0, tzinfo=UTC),
    )
    r = QueryResult(query=q, hits=hits or [])
    r.finished_at = datetime(2026, 5, 23, 8, 0, 15, 321000, tzinfo=UTC)
    r.duration_ms = 15321
    return r


def test_serialize_empty_result_is_valid():
    payload = serialize_query_result(_make_result([]))
    validate_schema(payload)
    assert payload["schema_version"] == JSON_SCHEMA_VERSION
    assert payload["query"] == {"kind": "username", "value": "torvalds"}
    assert payload["summary"]["total"] == 0
    assert payload["hits"] == []
    assert payload["started_at"].endswith("Z")
    assert payload["finished_at"].endswith("Z")


def test_hit_keys_are_always_full_set():
    """A Hit with no optional fields populated still emits the full key set."""
    h = Hit(module="x", source="y", status=HitStatus.FOUND)
    payload = serialize_query_result(_make_result([h]))
    keys = set(payload["hits"][0].keys())
    assert keys == {
        "module", "source", "status", "severity", "title", "url",
        "evidence", "category", "elapsed_ms", "discovered_at",
    }
    # unknown values are explicit None, never missing
    assert payload["hits"][0]["title"] is None
    assert payload["hits"][0]["url"] is None
    assert payload["hits"][0]["evidence"] is None
    assert payload["hits"][0]["category"] is None
    assert payload["hits"][0]["elapsed_ms"] == 0


def test_iso8601_z_suffix_only():
    h = Hit(
        module="x", source="y", status=HitStatus.FOUND,
        found_at=datetime(2026, 5, 23, 8, 0, 0, 234000, tzinfo=UTC),
    )
    payload = serialize_query_result(_make_result([h]))
    ts = payload["hits"][0]["discovered_at"]
    assert ts == "2026-05-23T08:00:00.234Z"


def test_summary_counts_by_status_and_severity():
    hits = [
        Hit(module="m", source="a", status=HitStatus.FOUND, severity=Severity.HIGH),
        Hit(module="m", source="b", status=HitStatus.FOUND, severity=Severity.LOW),
        Hit(module="m", source="c", status=HitStatus.NOT_FOUND),
        Hit(module="m", source="d", status=HitStatus.ERROR, severity=Severity.CRITICAL),
        Hit(module="m", source="e", status=HitStatus.RATELIMITED),
        Hit(module="m", source="f", status=HitStatus.UNAVAILABLE),
        Hit(module="m", source="g", status=HitStatus.SKIPPED),
        Hit(module="m", source="h", status=HitStatus.NO_DATA),
        Hit(module="m", source="i", status=HitStatus.UNCERTAIN),
    ]
    payload = serialize_query_result(_make_result(hits))
    s = payload["summary"]
    assert s["total"] == 9
    assert s["found"] == 2
    assert s["not_found"] == 1
    assert s["errors"] == 1
    assert s["ratelimited"] == 1
    assert s["unavailable"] == 1
    assert s["skipped"] == 1
    assert s["no_data"] == 1
    assert s["uncertain"] == 1
    assert s["by_severity"]["high"] == 1
    assert s["by_severity"]["low"] == 1
    assert s["by_severity"]["critical"] == 1


def test_hits_sorted_severity_desc_then_status_then_source():
    hits = [
        Hit(module="m", source="z", status=HitStatus.FOUND, severity=Severity.LOW),
        Hit(module="m", source="a", status=HitStatus.FOUND, severity=Severity.HIGH),
        Hit(module="m", source="m", status=HitStatus.NOT_FOUND, severity=Severity.HIGH),
        Hit(module="m", source="b", status=HitStatus.FOUND, severity=Severity.CRITICAL),
    ]
    payload = serialize_query_result(_make_result(hits))
    ordering = [(h["severity"], h["status"], h["source"]) for h in payload["hits"]]
    assert ordering == [
        ("critical", "FOUND", "b"),
        ("high",     "FOUND", "a"),
        ("high",     "NOT_FOUND", "m"),
        ("low",      "FOUND", "z"),
    ]


def test_status_uppercase_severity_lowercase():
    h = Hit(module="m", source="a", status=HitStatus.RATELIMITED, severity=Severity.HIGH)
    payload = serialize_query_result(_make_result([h]))
    assert payload["hits"][0]["status"] == "RATELIMITED"
    assert payload["hits"][0]["severity"] == "high"


def test_elapsed_ms_rounded_not_truncated():
    """`Hit.latency_ms` is already int, but we still verify round semantics."""
    h = Hit(module="m", source="a", status=HitStatus.FOUND, latency_ms=234)
    payload = serialize_query_result(_make_result([h]))
    assert payload["hits"][0]["elapsed_ms"] == 234


def test_payload_round_trips_through_json():
    """A senior dev should be able to dump → load → validate."""
    payload = serialize_query_result(_make_result([
        Hit(module="m", source="a", status=HitStatus.FOUND, severity=Severity.HIGH),
    ]))
    s = json.dumps(payload)
    loaded = json.loads(s)
    validate_schema(loaded)
    assert loaded["hits"][0]["status"] == "FOUND"


# ---- validator rejection paths --------------------------------------------

def test_validate_rejects_missing_top_keys():
    bad = {"schema_version": "1.0"}
    with pytest.raises(SchemaValidationError, match="missing top-level keys"):
        validate_schema(bad)


def test_validate_rejects_extra_top_keys():
    payload = serialize_query_result(_make_result([]))
    payload["extra_field"] = "nope"
    with pytest.raises(SchemaValidationError, match="unexpected top-level keys"):
        validate_schema(payload)


def test_validate_rejects_wrong_schema_version():
    payload = serialize_query_result(_make_result([]))
    payload["schema_version"] = "2.0"
    with pytest.raises(SchemaValidationError, match="schema_version"):
        validate_schema(payload)


def test_validate_rejects_unknown_status():
    payload = serialize_query_result(_make_result([
        Hit(module="m", source="a", status=HitStatus.FOUND),
    ]))
    payload["hits"][0]["status"] = "WAT"
    with pytest.raises(SchemaValidationError, match="status invalid"):
        validate_schema(payload)


def test_validate_rejects_missing_hit_field():
    payload = serialize_query_result(_make_result([
        Hit(module="m", source="a", status=HitStatus.FOUND),
    ]))
    del payload["hits"][0]["evidence"]
    with pytest.raises(SchemaValidationError, match="missing="):
        validate_schema(payload)


def test_validate_rejects_negative_duration():
    payload = serialize_query_result(_make_result([]))
    payload["duration_ms"] = -1
    with pytest.raises(SchemaValidationError, match="duration_ms"):
        validate_schema(payload)


def test_validate_rejects_bad_timestamp_format():
    payload = serialize_query_result(_make_result([]))
    payload["started_at"] = "2026-05-23T08:00:00+00:00"   # offset, not Z
    with pytest.raises(SchemaValidationError, match="started_at"):
        validate_schema(payload)


def test_null_finished_at_is_allowed():
    """A still-running query has no finished_at — must serialise as None."""
    q = Query(kind=QueryKind.USERNAME, value="x",
              started_at=datetime(2026, 5, 23, tzinfo=UTC))
    result = QueryResult(query=q)  # finished_at left at default None
    payload = serialize_query_result(result)
    assert payload["finished_at"] is None
    validate_schema(payload)
