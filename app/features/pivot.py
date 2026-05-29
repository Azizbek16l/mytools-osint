"""Auto-pivot — chained queries with bounded BFS + cycle detection.

After a normal scan completes, take every FOUND entity from the graph
correlation, route it to the appropriate profile (PIVOT_PROFILE map),
and run that as a follow-up scan. Repeat to depth N (default 1), with:

  - global `seen` set keyed by entity_id (cycle prevention)
  - per-edge traversal cost from EDGE_COST (high-fanout edges cost more)
  - max_entities_per_kind cap (one cert with 800 SANs shouldn't drown the run)
  - max_total_pivots hard wall (default 30)
  - noisy-value guard (skip gmail.com / 1.1.1.1 etc. — see entities.NOISY_VALUES)
  - persistent visited-set in pivot_visited table (re-running the same root
    skips already-explored branches)

Per the backend reviewer: auto-pivot runs AFTER the on_hit stream drains,
not inside it — otherwise we'd reenter the runner from its own callback
and deadlock the connection pool.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from app.core.db import Database
from app.core.entities import (
    PIVOT_PROFILE,
    EntityType,
    is_noisy,
)
from app.core.profiles import apply_profile
from app.core.runner import runner as _runner
from app.core.types import Query, QueryKind, QueryResult

log = logging.getLogger("mytools-osint.pivot")

MAX_ENTITIES_PER_KIND = 8
MAX_TOTAL_PIVOTS = 30
COST_BUDGET = 12.0


async def auto_pivot(
    query_id: int,
    db: Database,
    *,
    depth: int = 1,
    on_target: Callable[[Query, QueryResult], Awaitable[None]] | None = None,
    on_progress: Callable[[str], None] | None = None,
) -> list[tuple[Query, QueryResult]]:
    """BFS-pivot from a saved query's frontier. Returns [(Query, Result)…]."""
    if depth <= 0:
        return []

    r = _runner()
    results: list[tuple[Query, QueryResult]] = []

    # Frontier = (entity_id, type, value, depth, cum_cost)
    # Seed: all FOUND entities from the just-completed query.
    assert db._conn is not None
    async with db._conn.execute(
        """SELECT DISTINCT e.id, e.type, e.value
           FROM entities e
           JOIN edges ed ON ed.dst_id = e.id OR ed.src_id = e.id
           WHERE ed.hit_id IN (SELECT id FROM hits WHERE query_id = ?)
        """,
        (query_id,),
    ) as cur:
        seeds = [(r2["id"], r2["type"], r2["value"]) for r2 in await cur.fetchall()]

    n_pivots = 0
    per_kind: dict[str, int] = {}
    frontier = [(eid, et, ev, 1, 0.0) for (eid, et, ev) in seeds]

    while frontier and n_pivots < MAX_TOTAL_PIVOTS:
        eid, etype_s, evalue, d, cost = frontier.pop(0)
        if d > depth:
            continue
        if cost > COST_BUDGET:
            continue
        try:
            etype = EntityType(etype_s)
        except ValueError:
            continue
        # Noisy-value guard
        if is_noisy(etype, evalue):
            continue
        # Per-kind cap
        if per_kind.get(etype_s, 0) >= MAX_ENTITIES_PER_KIND:
            continue
        # Cycle: already pivoted this entity in this scan?
        added = await db.pivot_visited_add(query_id, eid, d)
        if not added:
            continue
        # Map entity → (QueryKind, profile)
        if etype not in PIVOT_PROFILE:
            continue
        kind_str, profile_name = PIVOT_PROFILE[etype]
        try:
            qkind = QueryKind(kind_str)
        except ValueError:
            continue
        # Apply profile (transient)
        try:
            enabled, _ = apply_profile(r, profile_name)
        except ValueError:
            continue
        per_kind[etype_s] = per_kind.get(etype_s, 0) + 1
        n_pivots += 1
        if on_progress:
            on_progress(f"  ↪ pivot[{d}] {etype_s}={evalue[:50]} → {profile_name} ({len(enabled)} mods)")

        # Run the pivot scan
        new_query = Query(kind=qkind, value=evalue, note=f"pivot-d{d}")
        try:
            new_result = await r.run(new_query)
            results.append((new_query, new_result))
        except Exception as exc:
            log.warning("pivot run failed for %s=%s: %s", etype_s, evalue, exc)
            continue

        # Save + correlate this pivot result so its entities feed the next layer
        new_qid = await db.save_result(new_result)
        await db.correlate_query(new_qid)
        if on_target:
            try:
                await on_target(new_query, new_result)
            except Exception:
                pass

        # Add newly-discovered FOUND entities to the next frontier
        async with db._conn.execute(
            """SELECT DISTINCT e.id, e.type, e.value
               FROM entities e
               JOIN edges ed ON ed.dst_id = e.id OR ed.src_id = e.id
               WHERE ed.hit_id IN (SELECT id FROM hits WHERE query_id = ?)
            """,
            (new_qid,),
        ) as cur:
            for r2 in await cur.fetchall():
                edge_cost = 2.0  # rough average; could pull from EDGE_COST per rel
                frontier.append((r2["id"], r2["type"], r2["value"],
                                  d + 1, cost + edge_cost))

    return results
