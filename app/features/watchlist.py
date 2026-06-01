"""Saved searches + periodic re-scan ("watchlist").

A watchlist entry is a (kind, value, label?, interval_h) tuple. `run_due` walks
every entry whose interval has elapsed, runs the Runner against it, computes
the diff against the previous scan, and (if there are *new informative* hits)
returns them so the caller can notify.

Notifications themselves live in app.features.notify — this module orchestrates
DB + Runner + diff, but does not import notify (avoids a dependency cycle and
keeps the unit tests trivially mockable).
"""
from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.db import Database
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

logger = logging.getLogger(__name__)

# Statuses that are "informative" — used by the diff filter. We compare these,
# ignore the rest (NOT_FOUND / NO_DATA / SKIPPED are noise for an alert channel).
_INFORMATIVE: frozenset[HitStatus] = frozenset(
    {
        HitStatus.FOUND,
        HitStatus.UNCERTAIN,
        HitStatus.RATELIMITED,
        HitStatus.UNAVAILABLE,
        HitStatus.ERROR,
    }
)

# Only these are *worth notifying* about. FOUND always; everything else only
# when it's HIGH severity or above. This is the "be quiet by default" rule.
_NOTIFY_STATUSES: frozenset[HitStatus] = frozenset({HitStatus.FOUND})


@dataclass(slots=True)
class WatchlistEntry:
    id: int | None
    kind: str
    value: str
    label: str | None
    interval_h: int
    enabled: bool
    created_at: datetime
    last_run_at: datetime | None
    last_query_id: int | None

    @property
    def query_kind(self) -> QueryKind:
        return QueryKind(self.kind)

    def is_due(self, now: datetime | None = None) -> bool:
        if not self.enabled:
            return False
        if self.last_run_at is None:
            return True
        ref = now or datetime.now(UTC)
        return (ref - self.last_run_at) >= timedelta(hours=self.interval_h)


# ---- (de)serialisation -----------------------------------------------------


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _row_to_entry(row: dict[str, Any]) -> WatchlistEntry:
    created = _parse_dt(row.get("created_at") if isinstance(row.get("created_at"), str) else None)
    if created is None:
        # Should never happen — created_at has NOT NULL. Fall back defensively.
        created = datetime.now(UTC)
    return WatchlistEntry(
        id=int(row["id"]) if row.get("id") is not None else None,
        kind=str(row["kind"]),
        value=str(row["value"]),
        label=(str(row["label"]) if row.get("label") is not None else None),
        interval_h=int(row["interval_h"]),
        enabled=bool(row["enabled"]),
        created_at=created,
        last_run_at=_parse_dt(
            row.get("last_run_at") if isinstance(row.get("last_run_at"), str) else None
        ),
        last_query_id=(
            int(row["last_query_id"]) if row.get("last_query_id") is not None else None
        ),
    )


# ---- CRUD ------------------------------------------------------------------


async def add(
    db: Database,
    kind: str,
    value: str,
    label: str | None = None,
    interval_h: int = 24,
) -> WatchlistEntry:
    """Create a watchlist entry. Validates kind and clamps interval.

    Raises ValueError if `kind` isn't a known QueryKind. The (kind, value)
    UNIQUE constraint may surface as sqlite3.IntegrityError — let it propagate
    so the CLI can show a clean error.
    """
    if not value or not value.strip():
        raise ValueError("value must be non-empty")
    # Validate kind. This raises ValueError on unknown kinds.
    QueryKind(kind)
    if interval_h < 1:
        raise ValueError("interval_h must be >= 1")

    created_at = datetime.now(UTC).isoformat()
    new_id = await db.watchlist_insert(
        kind=kind,
        value=value.strip(),
        label=(label.strip() if label else None) or None,
        interval_h=interval_h,
        created_at=created_at,
    )
    row = await db.watchlist_get(new_id)
    assert row is not None  # just inserted
    return _row_to_entry(row)


async def remove(db: Database, id_or_label: int | str) -> bool:
    """Remove a watchlist entry by numeric id or label string. Returns True if deleted."""
    target_id: int | None = None
    if isinstance(id_or_label, int):
        target_id = id_or_label
    elif isinstance(id_or_label, str) and id_or_label.isdigit():
        target_id = int(id_or_label)
    else:
        row = await db.watchlist_get_by_label(str(id_or_label))
        if row is None:
            return False
        target_id = int(row["id"])
    return await db.watchlist_delete(target_id)


async def list_all(db: Database, only_due: bool = False) -> list[WatchlistEntry]:
    rows = await db.watchlist_list()
    entries = [_row_to_entry(r) for r in rows]
    if only_due:
        now = datetime.now(UTC)
        entries = [e for e in entries if e.is_due(now)]
    return entries


async def disable(db: Database, id_: int) -> None:
    await db.watchlist_set_enabled(id_, False)


async def enable(db: Database, id_: int) -> None:
    await db.watchlist_set_enabled(id_, True)


# ---- run + diff ------------------------------------------------------------


def _new_informative_hits(prior: list[Hit], current: list[Hit]) -> list[Hit]:
    """Hits in `current` that were not in `prior`, restricted to informative statuses.

    Identity: (source, status, title, url) quadruple, as specified by the agent
    contract. NOT_FOUND / NO_DATA / SKIPPED are excluded from the comparison
    entirely — they're noise for the watchlist's purpose.
    """
    def key(h: Hit) -> tuple[str, str, str, str]:
        return (h.source, h.status.value, h.title, h.url)

    prior_keys = {key(h) for h in prior if h.status in _INFORMATIVE}
    out: list[Hit] = []
    for h in current:
        if h.status not in _INFORMATIVE:
            continue
        if key(h) in prior_keys:
            continue
        out.append(h)
    return out


def _notifiable(hits: list[Hit]) -> list[Hit]:
    """Filter for what's actually worth sending to the user — FOUND or HIGH+ severity."""
    high_or_above = {Severity.HIGH, Severity.CRITICAL}
    return [
        h for h in hits
        if h.status in _NOTIFY_STATUSES or h.severity in high_or_above
    ]


async def run_due(
    db: Database,
    runner: Runner,
    on_new_finding: Callable[[WatchlistEntry, list[Hit]], Awaitable[None]] | None = None,
    *,
    force_all: bool = False,
) -> list[tuple[WatchlistEntry, list[Hit]]]:
    """Re-scan every due (or every enabled, if `force_all`) entry.

    Returns the list of (entry, new_notifiable_hits) for entries that produced
    new informative findings. `on_new_finding` is awaited per such entry — its
    failure does not abort the loop.
    """
    now = datetime.now(UTC)
    entries = await list_all(db, only_due=False)
    due = [e for e in entries if e.enabled and (force_all or e.is_due(now))]

    results: list[tuple[WatchlistEntry, list[Hit]]] = []
    for entry in due:
        assert entry.id is not None  # entries from DB always have id
        try:
            prior_hits: list[Hit] = []
            if entry.last_query_id is not None:
                prior_hits = await db.hits_for(entry.last_query_id)

            query = Query(kind=entry.query_kind, value=entry.value)
            result = await runner.run(query)
            qid = await db.save_result(result)
            await db.watchlist_mark_run(
                entry.id, qid, datetime.now(UTC).isoformat()
            )

            # diff vs prior
            new_hits = _new_informative_hits(prior_hits, result.hits)
            notify_hits = _notifiable(new_hits)

            if notify_hits:
                results.append((entry, notify_hits))
                # persist a 'pending' notification row regardless of channel
                # success — the caller updates it after dispatch.
                await db.notifications_insert(
                    watchlist_id=entry.id,
                    query_id=qid,
                    new_hits_json=json.dumps(
                        [h.model_dump(mode="json") for h in notify_hits],
                        default=str,
                    ),
                    channel="telegram",
                    status="pending",
                )
                if on_new_finding is not None:
                    try:
                        await on_new_finding(entry, notify_hits)
                    except Exception as e:
                        logger.warning(
                            "watchlist: on_new_finding raised for entry %s: %s",
                            entry.id, e,
                        )
        except Exception as e:
            # Per-entry isolation — never let one bad entry kill the whole sweep.
            logger.warning("watchlist: entry %s failed: %s", entry.id, e)
            continue

    return results
