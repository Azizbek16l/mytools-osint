"""Locked JSON output schema for `osint --format json`.

The serialised shape is contractual — clients (scripts, dashboards, dump-diffs)
depend on stable keys and types. Bump `JSON_SCHEMA_VERSION` on any breaking
change and add a migration note in CHANGELOG.

Rules (enforced by `validate_schema`):
  * Every Hit object emits the FULL key set; unknown values are `null`, never
    omitted. This makes the schema parser-stable across versions.
  * Timestamps are ISO-8601 UTC with the literal `Z` suffix — no offsets.
  * Status values are `HitStatus.name` (UPPERCASE).
  * Severity values are lowercase (`low|medium|high|critical|info`).
  * `*_ms` fields are non-negative integers (`round()`, not truncation).
  * `hits` is sorted by (severity DESC, status ASC, source ASC) for stable
    diffs between runs.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app import __version__ as TOOL_VERSION  # single source of truth (was "0.1.0")
from app.core.types import Hit, HitStatus, QueryResult, Severity

JSON_SCHEMA_VERSION = "1.1"
TOOL_NAME = "mytools-osint"

# Ranking used for stable sort. Higher = more important.
_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

_ALL_STATUSES: tuple[str, ...] = tuple(s.name for s in HitStatus)
_ALL_SEVERITIES: tuple[str, ...] = tuple(s.value.lower() for s in Severity)


def _to_iso_z(dt: datetime | None) -> str | None:
    """Format a datetime as ISO-8601 UTC with a literal `Z`. None → None."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    else:
        dt = dt.astimezone(UTC)
    # `isoformat()` would give `+00:00`; we want `Z` for parser parity with JS Date.
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _serialize_hit(hit: Hit) -> dict[str, Any]:
    """Emit the locked Hit shape. Always the same keys.

    v1.1 adds ``confidence`` (float 0.0–1.0) and ``provenance`` (the
    producer's structured evidence dict). ``evidence`` keeps its historical
    meaning — the free-form ``detail`` string the analyst sees on screen —
    so we don't break existing JSON consumers parsing v1.0 hits.
    """
    return {
        "module": hit.module or None,
        "source": hit.source or None,
        "status": hit.status.name,
        "severity": hit.severity.value.lower(),
        "title": hit.title or None,
        "url": hit.url or None,
        "evidence": hit.detail or None,
        "category": hit.category or None,
        "elapsed_ms": int(round(hit.latency_ms)) if hit.latency_ms else 0,
        "discovered_at": _to_iso_z(hit.found_at),
        "confidence": round(float(hit.confidence), 3),
        "provenance": dict(hit.evidence) if hit.evidence else None,
    }


def _summarize(hits: list[Hit]) -> dict[str, Any]:
    """Roll counts up by status + severity."""
    by_status: dict[str, int] = dict.fromkeys(
        ("found", "not_found", "uncertain", "errors", "ratelimited",
         "unavailable", "no_data", "skipped"), 0,
    )
    # Map HitStatus → summary key.
    status_to_key = {
        HitStatus.FOUND: "found",
        HitStatus.NOT_FOUND: "not_found",
        HitStatus.UNCERTAIN: "uncertain",
        HitStatus.ERROR: "errors",
        HitStatus.RATELIMITED: "ratelimited",
        HitStatus.UNAVAILABLE: "unavailable",
        HitStatus.NO_DATA: "no_data",
        HitStatus.SKIPPED: "skipped",
    }
    by_severity: dict[str, int] = dict.fromkeys(("low", "medium", "high", "critical"), 0)
    for h in hits:
        k = status_to_key.get(h.status)
        if k:
            by_status[k] += 1
        sev = h.severity.value.lower()
        if sev in by_severity:
            by_severity[sev] += 1
    return {
        "total": len(hits),
        **by_status,
        "by_severity": by_severity,
    }


def _sort_key(hit_dict: dict[str, Any]) -> tuple[int, float, str, str]:
    """Stable, diff-friendly sort: severity DESC → confidence DESC → status → source.

    Adding confidence as a secondary key (v1.1) makes the top of the list more
    actionable — within a given severity, the analyst sees the most certain
    findings first.
    """
    sev_rank = _SEVERITY_RANK.get(hit_dict.get("severity") or "", 0)
    conf = float(hit_dict.get("confidence") or 0.0)
    return (-sev_rank, -conf, hit_dict.get("status") or "",
            hit_dict.get("source") or "")


def serialize_query_result(result: QueryResult) -> dict[str, Any]:
    """Serialise a QueryResult to the locked JSON v1.0 schema.

    The returned dict is always the same shape — keys never disappear; unknown
    values are `null`. Pass it to `json.dumps(..., indent=2, sort_keys=False)`.
    """
    hit_dicts = [_serialize_hit(h) for h in result.hits]
    hit_dicts.sort(key=_sort_key)
    started = result.query.started_at
    finished = result.finished_at
    duration_ms = int(round(result.duration_ms)) if result.duration_ms else 0
    return {
        "schema_version": JSON_SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "query": {
            "kind": result.query.kind.value,
            "value": result.query.value,
        },
        "started_at": _to_iso_z(started),
        "finished_at": _to_iso_z(finished),
        "duration_ms": duration_ms,
        "summary": _summarize(result.hits),
        "hits": hit_dicts,
    }


# ---- hand-rolled validator -------------------------------------------------
# We deliberately don't pull in `jsonschema` as a dependency — the shape is
# small and the rules are specific enough that a focused checker is clearer.

class SchemaValidationError(ValueError):
    """Raised when a serialised payload violates the locked schema."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise SchemaValidationError(msg)


def _is_iso_z(value: str) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        # strptime is strict; this is the only format we ever emit.
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return False
    return True


def validate_schema(payload: dict[str, Any]) -> None:
    """Validate a serialised QueryResult against the locked schema. Raises on drift.

    Used in tests and as a self-check in production callers — cheap (<1ms) and
    catches refactors that silently break the contract.
    """
    _require(isinstance(payload, dict), "payload must be a dict")

    # Top-level keys
    expected_top = {
        "schema_version", "tool", "tool_version", "query",
        "started_at", "finished_at", "duration_ms", "summary", "hits",
    }
    missing = expected_top - payload.keys()
    extra = payload.keys() - expected_top
    _require(not missing, f"missing top-level keys: {sorted(missing)}")
    _require(not extra, f"unexpected top-level keys: {sorted(extra)}")

    _require(payload["schema_version"] == JSON_SCHEMA_VERSION,
             f"schema_version != {JSON_SCHEMA_VERSION}")
    _require(payload["tool"] == TOOL_NAME, "tool name mismatch")
    _require(isinstance(payload["tool_version"], str), "tool_version must be str")

    q = payload["query"]
    _require(isinstance(q, dict) and set(q.keys()) == {"kind", "value"},
             "query must have exactly {kind, value}")
    _require(isinstance(q["kind"], str) and isinstance(q["value"], str),
             "query.kind and query.value must be strings")

    _require(payload["started_at"] is None or _is_iso_z(payload["started_at"]),
             "started_at must be ISO-8601 UTC with Z suffix")
    _require(payload["finished_at"] is None or _is_iso_z(payload["finished_at"]),
             "finished_at must be ISO-8601 UTC with Z suffix or null")

    _require(isinstance(payload["duration_ms"], int) and payload["duration_ms"] >= 0,
             "duration_ms must be a non-negative integer")

    summary = payload["summary"]
    expected_summary = {
        "total", "found", "not_found", "uncertain", "errors",
        "ratelimited", "unavailable", "no_data", "skipped", "by_severity",
    }
    _require(isinstance(summary, dict) and set(summary.keys()) == expected_summary,
             f"summary keys must be exactly {sorted(expected_summary)}")
    for k in expected_summary - {"by_severity"}:
        _require(isinstance(summary[k], int) and summary[k] >= 0,
                 f"summary.{k} must be non-negative int")
    bs = summary["by_severity"]
    _require(isinstance(bs, dict)
             and set(bs.keys()) == {"low", "medium", "high", "critical"},
             "by_severity keys must be {low, medium, high, critical}")
    for k, v in bs.items():
        _require(isinstance(v, int) and v >= 0,
                 f"by_severity.{k} must be non-negative int")

    hits = payload["hits"]
    _require(isinstance(hits, list), "hits must be a list")
    expected_hit_keys = {
        "module", "source", "status", "severity", "title", "url",
        "evidence", "category", "elapsed_ms", "discovered_at",
        "confidence", "provenance",
    }
    for i, h in enumerate(hits):
        _require(isinstance(h, dict), f"hits[{i}] must be a dict")
        keys = set(h.keys())
        _require(keys == expected_hit_keys,
                 f"hits[{i}] keys must be {sorted(expected_hit_keys)}, "
                 f"got extra={sorted(keys - expected_hit_keys)} "
                 f"missing={sorted(expected_hit_keys - keys)}")
        _require(h["status"] in _ALL_STATUSES,
                 f"hits[{i}].status invalid: {h['status']!r}")
        _require(h["severity"] in _ALL_SEVERITIES,
                 f"hits[{i}].severity invalid: {h['severity']!r}")
        _require(isinstance(h["elapsed_ms"], int) and h["elapsed_ms"] >= 0,
                 f"hits[{i}].elapsed_ms must be non-negative int")
        _require(h["discovered_at"] is None or _is_iso_z(h["discovered_at"]),
                 f"hits[{i}].discovered_at must be ISO-Z or null")
        conf = h["confidence"]
        _require(isinstance(conf, (int, float)) and 0.0 <= float(conf) <= 1.0,
                 f"hits[{i}].confidence must be a float in [0.0, 1.0], got {conf!r}")
        prov = h["provenance"]
        _require(prov is None or isinstance(prov, dict),
                 f"hits[{i}].provenance must be a dict or null")
        if isinstance(prov, dict):
            for k, v in prov.items():
                _require(isinstance(k, str) and isinstance(v, str),
                         f"hits[{i}].provenance keys/values must be strings")
