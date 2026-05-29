"""Correlation rules engine (Wave D2).

A *rule* is a small YAML declaration that says "look at the entity graph,
group / filter it in a specific way, and emit a synthesized :class:`Hit`
for every match". The intent is to surface multi-finding patterns the
analyst would otherwise have to find by hand — "this IP hosts 12 of your
subdomains", "this password hash appears in 4 of your emails' breach
reports", etc.

Why a tiny YAML over a full DSL? Two reasons:
  1. We're not SpiderFoot — adding a rule should be diffing one short YAML
     file, not learning a query language.
  2. The DSL surface in this file is intentionally small (4 ``match``
     predicates). Anything beyond that is better expressed in Python in
     the next refactor than smuggled into YAML.

The 4 supported ``match`` predicates:

* ``entities`` — pick all entities of one ``type``, optionally filtered by
  ``has_edge`` / ``value_regex`` / ``where``, optionally ``group_by`` an
  attribute (an edge rel name, e.g. ``resolves_to``). Emit one finding per
  group whose size >= ``min_group_size``.
* ``cross_kind`` — emit one finding per entity that has BOTH of two named
  inbound/outbound edges. (e.g. an IP that's both ``mx_for`` and
  ``dns_a_for_target``.)
* ``password_reuse`` — find HASH entities reachable from >= ``min_emails``
  distinct EMAIL entities through a SEEN_IN_BREACH neighbourhood.
* (implicitly) the regex sub-mode of ``entities``.

All emitted Hits use:
  * ``module="correlation"``
  * ``source=<rule_id>``
  * ``category="rule"``
  * ``severity`` from the rule
  * ``extra={"rule_id": …, "rule_name": …, "evidence": [...], "match_kind": ...}``

``run_rules`` is awaitable (it talks to ``Database``) and returns the new
Hit list — it does NOT persist anything by itself. ``cmd_rules`` (the CLI
dispatcher in this module) is the one that, with ``--case <slug>``, attaches
the synthesized hits to that case's most recent run.
"""
from __future__ import annotations

import json
import logging
import re
import sys
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from app.core.db import Database
from app.core.types import Hit, HitStatus, Severity

log = logging.getLogger("osint.correlation_rules")

_VALID_SEVERITIES = {s.value for s in Severity}
_BUILTIN_DIR = Path(__file__).resolve().parent / "rules_builtin"


@dataclass(slots=True)
class Rule:
    """One rule loaded from YAML or built in code.

    Validation happens in ``from_dict`` — once you have a Rule, fields are
    trusted by the runner. Unknown ``match`` keys raise ValueError at load.
    """

    id: str
    name: str
    severity: str
    description: str
    match: dict[str, Any]
    output: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Rule:
        if not isinstance(raw, dict):
            raise ValueError("rule must be a mapping at the top level")
        rid = str(raw.get("id") or "").strip()
        if not rid or not re.match(r"^[a-z0-9][a-z0-9_\-]{1,63}$", rid):
            raise ValueError(f"rule id missing/invalid: {rid!r}")
        sev = str(raw.get("severity") or "info").strip().lower()
        if sev not in _VALID_SEVERITIES:
            raise ValueError(f"rule {rid!r}: bad severity {sev!r}")
        match = raw.get("match") or {}
        if not isinstance(match, dict) or not match:
            raise ValueError(f"rule {rid!r}: 'match' must be a non-empty mapping")
        # Allowed top-level match predicates. Anything else is a typo.
        allowed = {"entities", "cross_kind", "password_reuse"}
        unknown = set(match.keys()) - allowed
        if unknown:
            raise ValueError(
                f"rule {rid!r}: unknown match predicate(s) {sorted(unknown)}; "
                f"allowed: {sorted(allowed)}"
            )
        return cls(
            id=rid,
            name=str(raw.get("name") or rid),
            severity=sev,
            description=str(raw.get("description") or "").strip(),
            match=match,
            output=raw.get("output") or {},
        )


def load_rules(
    *,
    builtins: bool = True,
    user_dir: Path | str | None = None,
) -> list[Rule]:
    """Load YAML rule files. Bad files are skipped with a log warning.

    Order: builtins first, then user_dir. Same-id later wins (so users can
    override a builtin without editing the package).
    """
    rules: dict[str, Rule] = {}
    dirs: list[Path] = []
    if builtins:
        dirs.append(_BUILTIN_DIR)
    if user_dir:
        dirs.append(Path(user_dir))
    for d in dirs:
        if not d.exists() or not d.is_dir():
            continue
        for p in sorted(d.glob("*.yaml")) + sorted(d.glob("*.yml")):
            try:
                raw = yaml.safe_load(p.read_text(encoding="utf-8"))
                rule = Rule.from_dict(raw)
            except (yaml.YAMLError, ValueError, OSError) as exc:
                log.warning("rule load skipped %s: %s", p, exc)
                continue
            rules[rule.id] = rule
    return list(rules.values())


# ---------------------------------------------------------------------------
# Match engine
# ---------------------------------------------------------------------------


async def _all_entities_of_type(
    db: Database, etype: str, case_id: int | None
) -> list[dict[str, Any]]:
    assert db._conn is not None
    if case_id is None:
        sql = "SELECT id, type, value, tags, extra_json FROM entities WHERE type = ?"
        params: tuple[Any, ...] = (etype,)
    else:
        sql = (
            "SELECT e.id, e.type, e.value, e.tags, e.extra_json FROM entities e "
            "JOIN case_entities ce ON ce.entity_id = e.id "
            "WHERE ce.case_id = ? AND e.type = ?"
        )
        params = (case_id, etype)
    async with db._conn.execute(sql, params) as cur:
        return [dict(r) for r in await cur.fetchall()]


async def _edges_for(
    db: Database, src_id: str, rel: str | None = None
) -> list[dict[str, Any]]:
    assert db._conn is not None
    if rel:
        async with db._conn.execute(
            "SELECT src_id, dst_id, rel FROM edges WHERE src_id = ? AND rel = ?",
            (src_id, rel),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]
    async with db._conn.execute(
        "SELECT src_id, dst_id, rel FROM edges WHERE src_id = ?", (src_id,)
    ) as cur:
        return [dict(r) for r in await cur.fetchall()]


async def _has_edge_anywhere(
    db: Database, entity_id: str, rel: str
) -> bool:
    """True if `entity_id` is on either end of an edge of relation `rel`."""
    assert db._conn is not None
    async with db._conn.execute(
        "SELECT 1 FROM edges WHERE rel = ? AND (src_id = ? OR dst_id = ?) LIMIT 1",
        (rel, entity_id, entity_id),
    ) as cur:
        return (await cur.fetchone()) is not None


def _make_hit(rule: Rule, title: str, evidence: Any, match_kind: str) -> Hit:
    """Build the synthesized Hit that represents one rule match."""
    return Hit(
        module="correlation",
        source=rule.id,
        category="rule",
        status=HitStatus.FOUND,
        title=title[:300],
        url="",
        detail=rule.description[:240],
        severity=Severity(rule.severity),
        extra={
            "rule_id": rule.id,
            "rule_name": rule.name,
            "match_kind": match_kind,
            "evidence": evidence,
        },
        found_at=datetime.now(UTC),
        confidence=0.9,
    )


def _format_title(template: str, **kw: Any) -> str:
    """str.format wrapper that survives missing keys."""
    class _D(dict):
        def __missing__(self, k):  # type: ignore[override]
            return "{" + k + "}"

    try:
        return template.format_map(_D(**kw))
    except Exception:
        return template


# ---- predicate: entities --------------------------------------------------


async def _run_entities_match(
    db: Database, rule: Rule, spec: dict[str, Any], case_id: int | None
) -> list[Hit]:
    etype = spec.get("type")
    if not etype:
        return []
    candidates = await _all_entities_of_type(db, str(etype), case_id)
    # value_regex filter
    rx_src = spec.get("value_regex")
    if rx_src:
        try:
            rx = re.compile(str(rx_src))
            candidates = [c for c in candidates if rx.search(c["value"] or "")]
        except re.error as exc:
            log.warning("rule %s: bad value_regex %r: %s", rule.id, rx_src, exc)
            return []
    # has_edge filter
    has_edge = spec.get("has_edge")
    if has_edge:
        filtered = []
        for c in candidates:
            if await _has_edge_anywhere(db, c["id"], str(has_edge)):
                filtered.append(c)
        candidates = filtered
    # `where` predicate — simple equality on tags/extra
    where = spec.get("where") or {}
    if where and isinstance(where, dict):
        def ok(c: dict[str, Any]) -> bool:
            tags = json.loads(c.get("tags") or "[]") if isinstance(c.get("tags"), str) else []
            extra = json.loads(c.get("extra_json") or "{}") if isinstance(c.get("extra_json"), str) else {}
            for k, v in where.items():
                if k == "tag" and v not in tags:
                    return False
                if k != "tag" and extra.get(k) != v:
                    return False
            return True

        candidates = [c for c in candidates if ok(c)]

    min_n = int(spec.get("min_group_size") or 1)
    group_by = spec.get("group_by")
    title_tpl = str(rule.output.get("title") or rule.name)
    ev_field = str(rule.output.get("evidence_field") or "matches")
    hits: list[Hit] = []
    if not group_by:
        # One hit per matching candidate.
        if len(candidates) < min_n:
            return []
        if min_n == 1:
            for c in candidates:
                title = _format_title(title_tpl, value=c["value"], count=1)
                hits.append(_make_hit(rule, title, {ev_field: c["value"]}, "entities"))
        else:
            # No grouping but min_group_size > 1 → emit one aggregate hit.
            title = _format_title(title_tpl, count=len(candidates))
            hits.append(_make_hit(
                rule, title,
                {ev_field: [c["value"] for c in candidates[:200]]},
                "entities",
            ))
        return hits

    # group_by an edge relation: bucket entities by the dst they share
    # over that relation.
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for c in candidates:
        edges = await _edges_for(db, c["id"], str(group_by))
        for e in edges:
            groups[e["dst_id"]].append(c)
    # Look up the dst values for nicer titles.
    for dst_id, members in groups.items():
        if len(members) < min_n:
            continue
        async with db._conn.execute(  # type: ignore[union-attr]
            "SELECT value FROM entities WHERE id = ?", (dst_id,)
        ) as cur:
            row = await cur.fetchone()
        group_value = row["value"] if row else dst_id
        title = _format_title(
            title_tpl, group=group_value, count=len(members), value=group_value,
        )
        hits.append(_make_hit(
            rule, title,
            {
                "group_value": group_value,
                "group_by": group_by,
                "count": len(members),
                ev_field: [m["value"] for m in members[:200]],
            },
            "entities-group",
        ))
    return hits


# ---- predicate: cross_kind ------------------------------------------------


async def _run_cross_kind_match(
    db: Database, rule: Rule, spec: dict[str, Any], case_id: int | None
) -> list[Hit]:
    """Emit hits for entities that have BOTH of the named relations (incoming
    or outgoing — direction-agnostic, matching SpiderFoot's notion of "tagged
    with two facts").
    """
    rels = spec.get("rels") or []
    if not isinstance(rels, list) or len(rels) < 2:
        return []
    rels_s = [str(r).strip() for r in rels if r]
    if len(rels_s) < 2:
        return []
    assert db._conn is not None
    # Pull all entity ids that have at least one of each rel.
    by_rel: list[set[str]] = []
    for rel in rels_s:
        async with db._conn.execute(
            "SELECT src_id, dst_id FROM edges WHERE rel = ?", (rel,)
        ) as cur:
            ids: set[str] = set()
            for r in await cur.fetchall():
                ids.add(r["src_id"])
                ids.add(r["dst_id"])
            by_rel.append(ids)
    common = set.intersection(*by_rel) if by_rel else set()
    if case_id is not None:
        # Restrict to entities tracked in this case.
        async with db._conn.execute(
            "SELECT entity_id FROM case_entities WHERE case_id = ?", (case_id,)
        ) as cur:
            case_ids = {r["entity_id"] for r in await cur.fetchall()}
        common &= case_ids
    if not common:
        return []
    title_tpl = str(rule.output.get("title") or rule.name)
    out: list[Hit] = []
    for eid in common:
        async with db._conn.execute(
            "SELECT type, value FROM entities WHERE id = ?", (eid,)
        ) as cur:
            row = await cur.fetchone()
        if not row:
            continue
        d = dict(row)
        title = _format_title(title_tpl, value=d["value"], type=d["type"], count=len(rels_s))
        out.append(_make_hit(
            rule, title,
            {"entity_id": eid, "type": d["type"], "value": d["value"], "rels": rels_s},
            "cross_kind",
        ))
    return out


# ---- predicate: password_reuse -------------------------------------------


async def _run_password_reuse_match(
    db: Database, rule: Rule, spec: dict[str, Any], case_id: int | None
) -> list[Hit]:
    """Heuristic: a HASH entity that's reachable from >= N distinct EMAILs
    via any edge path of length 1 (i.e. shares an edge endpoint).

    The rationale: when ``email_extras`` finds a breach for an email, the
    correlation engine attaches a HASH (or breach-source) entity to the
    email. Two emails sharing the same downstream HASH ≈ password reuse
    candidate. False-positives possible — severity is calibrated by the
    rule, not by us.
    """
    min_n = int(spec.get("min_emails") or 2)
    assert db._conn is not None
    # Collect emails (optionally scoped to a case).
    if case_id is None:
        sql = "SELECT id, value FROM entities WHERE type = 'email'"
        params: tuple[Any, ...] = ()
    else:
        sql = (
            "SELECT e.id, e.value FROM entities e "
            "JOIN case_entities ce ON ce.entity_id = e.id "
            "WHERE ce.case_id = ? AND e.type = 'email'"
        )
        params = (case_id,)
    async with db._conn.execute(sql, params) as cur:
        emails = [dict(r) for r in await cur.fetchall()]
    if len(emails) < min_n:
        return []
    # Build hash -> set(email_id)
    hash_to_emails: dict[str, set[str]] = defaultdict(set)
    hash_to_value: dict[str, str] = {}
    for em in emails:
        async with db._conn.execute(
            """SELECT e.id, e.value FROM entities e
               JOIN edges ed ON ed.dst_id = e.id OR ed.src_id = e.id
               WHERE e.type = 'hash' AND (ed.src_id = ? OR ed.dst_id = ?)""",
            (em["id"], em["id"]),
        ) as cur:
            for r in await cur.fetchall():
                hash_to_emails[r["id"]].add(em["id"])
                hash_to_value[r["id"]] = r["value"]
    hits: list[Hit] = []
    title_tpl = str(rule.output.get("title") or rule.name)
    for hid, em_ids in hash_to_emails.items():
        if len(em_ids) < min_n:
            continue
        em_values = [e["value"] for e in emails if e["id"] in em_ids]
        title = _format_title(title_tpl, count=len(em_ids), value=hash_to_value.get(hid, hid))
        hits.append(_make_hit(
            rule, title,
            {"hash": hash_to_value.get(hid, hid), "emails": em_values},
            "password_reuse",
        ))
    return hits


# ---- public entry point ---------------------------------------------------


async def run_rules(
    db: Database,
    *,
    case_id: int | None = None,
    rules: Iterable[Rule] | None = None,
) -> list[Hit]:
    """Run every rule, return the synthesized Hits. Failures are logged + skipped.

    When ``case_id`` is given, predicates restrict entity sets to
    ``case_entities`` of that case — gives the analyst a per-case view.
    """
    rule_list = list(rules) if rules is not None else load_rules()
    out: list[Hit] = []
    for rule in rule_list:
        try:
            if "entities" in rule.match:
                out.extend(await _run_entities_match(db, rule, rule.match["entities"], case_id))
            if "cross_kind" in rule.match:
                out.extend(await _run_cross_kind_match(db, rule, rule.match["cross_kind"], case_id))
            if "password_reuse" in rule.match:
                out.extend(await _run_password_reuse_match(db, rule, rule.match["password_reuse"], case_id))
        except Exception as exc:
            log.warning("rule %s failed: %s", rule.id, exc)
            continue
    return out


# ---------------------------------------------------------------------------
# CLI dispatch — `osint rules ...`
# ---------------------------------------------------------------------------


def cmd_rules(argv: list[str]) -> int:
    """Dispatcher for ``osint rules list|run`` — see CLI."""
    import asyncio

    if not argv or argv[0] in ("-h", "--help"):
        print(
            "usage: osint rules <list|run> [opts]\n\n"
            "  list                 show all loaded rules\n"
            "  run [--case SLUG] [--id RULE]\n"
            "                       evaluate rules; attach hits to case if --case",
            file=sys.stderr,
        )
        return 0 if argv else 2

    sub = argv[0]

    if sub == "list":
        rules = load_rules()
        if not rules:
            print("  (no rules loaded)")
            return 0
        print()
        print(f"  {'ID':<24} {'SEVERITY':<9} {'NAME':<48}  DESCRIPTION")
        print("  " + "─" * 96)
        for r in rules:
            desc = (r.description or "").split("\n", 1)[0][:80]
            print(f"  {r.id:<24} {r.severity:<9} {r.name[:48]:<48}  {desc}")
        print()
        return 0

    if sub == "run":
        rest = argv[1:]
        case_slug: str | None = None
        only_id: str | None = None
        i = 0
        while i < len(rest):
            if rest[i] == "--case" and i + 1 < len(rest):
                case_slug = rest[i + 1]; i += 2; continue
            if rest[i] == "--id" and i + 1 < len(rest):
                only_id = rest[i + 1]; i += 2; continue
            i += 1

        async def _run() -> int:
            from app.core.config import load_settings, settings
            from app.features import cases as cases_mod
            load_settings()
            db = Database(settings().db_path)
            await db.connect()
            try:
                rules = load_rules()
                if only_id:
                    rules = [r for r in rules if r.id == only_id]
                    if not rules:
                        print(f"  no rule with id {only_id!r}", file=sys.stderr)
                        return 1
                case_obj = None
                case_id_int: int | None = None
                if case_slug:
                    case_obj = await cases_mod.get(db, case_slug)
                    if case_obj is None:
                        print(f"  case {case_slug!r} not found", file=sys.stderr)
                        return 1
                    case_id_int = case_obj.id
                hits = await run_rules(db, case_id=case_id_int, rules=rules)
                if not hits:
                    print("  (no rule matches)")
                    return 0
                for h in hits:
                    print(f"  [{h.severity.value:<8}] {h.source:<22}  {h.title}")
                # Attach to case's most recent run if requested.
                if case_obj is not None:
                    assert db._conn is not None
                    async with db._conn.execute(
                        "SELECT query_id FROM case_runs WHERE case_id = ? "
                        "ORDER BY started_at DESC LIMIT 1",
                        (case_obj.id,),
                    ) as cur:
                        row = await cur.fetchone()
                    if row:
                        qid = int(row["query_id"])
                        import json as _json
                        await db._conn.executemany(
                            """INSERT INTO hits
                               (query_id, module, source, category, status, title, url,
                                detail, extra_json, severity, found_at, latency_ms)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            [
                                (
                                    qid, h.module, h.source, h.category,
                                    h.status.value, h.title, h.url, h.detail,
                                    _json.dumps(h.extra, default=str),
                                    h.severity.value, h.found_at.isoformat(),
                                    h.latency_ms,
                                )
                                for h in hits
                            ],
                        )
                        await db._conn.commit()
                        print(
                            f"  attached {len(hits)} synthesized hits to "
                            f"case {case_slug!r} (q={qid})"
                        )
                    else:
                        print(
                            f"  case {case_slug!r} has no runs yet — "
                            "scan something first then re-run with --case",
                            file=sys.stderr,
                        )
                return 0
            finally:
                await db.close()

        return asyncio.run(_run())

    print(f"unknown rules subcommand: {sub!r}", file=sys.stderr)
    return 2
