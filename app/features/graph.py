"""`osint graph` — query and export the entity graph (v4.0).

Sub-commands:
  osint graph show <kind> <value> [--depth N]
      Pretty-print the BFS-explored subgraph rooted at this entity.
  osint graph export <kind> <value> [--format gexf|graphml|cytoscape] [--out FILE]
      Emit the subgraph in Gephi/Maltego/Cytoscape-compatible format.
  osint graph rebuild
      Re-derive entities + edges from every stored Hit.
  osint graph stats
      Total entities + edges per type.
  osint graph forget <kind> <value>
      Erase an entity + its edges (GDPR-style).
"""
from __future__ import annotations

import asyncio
import json
import sys
import xml.sax.saxutils as xml_esc
from collections import deque
from pathlib import Path

from app.core.config import load_settings, settings
from app.core.db import Database
from app.core.entities import EntityType, canonical_key, entity_id


# ---------------- BFS over the graph ----------------------------------

async def bfs_subgraph(
    db: Database, root_type: EntityType, root_value: str,
    *, max_depth: int = 2, max_total: int = 500,
) -> tuple[list[dict], list[dict]]:
    """Return (entities, edges) of the connected component around root,
    bounded by depth and total node count. Backend reviewer's chunked-IN
    pattern."""
    root_id = entity_id(root_type, root_value)
    root_row = await db.entity_get(root_type.value, root_value)
    if not root_row:
        return [], []
    seen: dict[str, dict] = {root_id: root_row}
    edges: list[dict] = []
    frontier: deque[tuple[str, int]] = deque([(root_id, 0)])
    while frontier and len(seen) < max_total:
        # Drain one whole depth level at a time so we hit the chunk-batch
        layer_ids = [eid for eid, d in list(frontier) if d <= max_depth]
        next_layer: list[tuple[str, int]] = []
        # Lift this layer out of the queue
        for _ in range(len(frontier)):
            eid, d = frontier.popleft()
            if d < max_depth:
                next_layer.append((eid, d + 1))
        if not layer_ids:
            break
        rows = await db.neighbours_batch(layer_ids)
        for r in rows:
            edges.append({
                "src": r["src_id"], "dst": r["dst_id"], "rel": r["rel"],
                "source": r["source"], "confidence": r["confidence"],
            })
            if r["dst_id"] not in seen:
                seen[r["dst_id"]] = {
                    "id": r["dst_id"], "type": r["dst_type"],
                    "value": r["dst_value"],
                }
                # Enqueue for next depth, respecting cap
                if len(seen) < max_total:
                    for el in next_layer:
                        if el[0] == r["dst_id"]:
                            break
                    else:
                        # Only enqueue if we haven't already
                        next_layer.append((r["dst_id"], next_layer[0][1] if next_layer else 1))
        # Push the next depth layer onto frontier
        for item in next_layer:
            frontier.append(item)
    return list(seen.values()), edges


# ---------------- export formats ---------------------------------------

def to_cytoscape_json(entities: list[dict], edges: list[dict]) -> str:
    """Cytoscape.js JSON format (elements: [{data:{...}, group:'nodes'|'edges'}])."""
    elements = []
    for e in entities:
        elements.append({
            "group": "nodes",
            "data": {
                "id": e["id"], "type": e["type"], "label": e["value"][:60],
                "value": e["value"],
            },
        })
    for e in edges:
        elements.append({
            "group": "edges",
            "data": {
                "id": f"{e['src']}-{e['rel']}-{e['dst']}",
                "source": e["src"], "target": e["dst"],
                "rel": e["rel"], "source_module": e["source"],
                "confidence": e["confidence"],
            },
        })
    return json.dumps({"elements": elements}, indent=2)


def to_gexf(entities: list[dict], edges: list[dict]) -> str:
    """GEXF 1.3 — opens directly in Gephi. Hand-rolled, no NetworkX dep."""
    def esc(s):
        return xml_esc.escape(str(s))
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<gexf xmlns="http://gexf.net/1.3" version="1.3">',
           '<graph mode="static" defaultedgetype="directed">',
           '<attributes class="node">',
           '  <attribute id="0" title="type" type="string"/>',
           '  <attribute id="1" title="value" type="string"/>',
           '</attributes>',
           '<attributes class="edge">',
           '  <attribute id="0" title="rel" type="string"/>',
           '  <attribute id="1" title="confidence" type="float"/>',
           '</attributes>',
           '<nodes>']
    for n in entities:
        out.append(f'<node id="{esc(n["id"])}" label="{esc(n["value"][:60])}">')
        out.append('  <attvalues>')
        out.append(f'    <attvalue for="0" value="{esc(n["type"])}"/>')
        out.append(f'    <attvalue for="1" value="{esc(n["value"])}"/>')
        out.append('  </attvalues></node>')
    out.append('</nodes><edges>')
    for i, e in enumerate(edges):
        out.append(f'<edge id="{i}" source="{esc(e["src"])}" target="{esc(e["dst"])}" '
                   f'label="{esc(e["rel"])}">')
        out.append('  <attvalues>')
        out.append(f'    <attvalue for="0" value="{esc(e["rel"])}"/>')
        out.append(f'    <attvalue for="1" value="{e["confidence"]}"/>')
        out.append('  </attvalues></edge>')
    out.append('</edges></graph></gexf>')
    return "\n".join(out)


def to_graphml(entities: list[dict], edges: list[dict]) -> str:
    """GraphML — Maltego / yEd-compatible."""
    def esc(s):
        return xml_esc.escape(str(s))
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
           '<key id="d0" for="node" attr.name="type" attr.type="string"/>',
           '<key id="d1" for="node" attr.name="value" attr.type="string"/>',
           '<key id="d2" for="edge" attr.name="rel" attr.type="string"/>',
           '<graph id="g" edgedefault="directed">']
    for n in entities:
        out.append(f'<node id="{esc(n["id"])}">')
        out.append(f'  <data key="d0">{esc(n["type"])}</data>')
        out.append(f'  <data key="d1">{esc(n["value"])}</data>')
        out.append('</node>')
    for i, e in enumerate(edges):
        out.append(f'<edge id="e{i}" source="{esc(e["src"])}" target="{esc(e["dst"])}">')
        out.append(f'  <data key="d2">{esc(e["rel"])}</data>')
        out.append('</edge>')
    out.append('</graph></graphml>')
    return "\n".join(out)


# ---------------- ASCII pretty-print ----------------------------------

def render_ascii(entities: list[dict], edges: list[dict], root_id: str) -> str:
    """Compact analyst-friendly view rooted at root_id."""
    by_src: dict[str, list[dict]] = {}
    for e in edges:
        by_src.setdefault(e["src"], []).append(e)
    by_id: dict[str, dict] = {e["id"]: e for e in entities}
    lines: list[str] = []
    visited: set[str] = set()

    def render(eid: str, depth: int = 0) -> None:
        if eid in visited:
            return
        visited.add(eid)
        ent = by_id.get(eid)
        if not ent:
            return
        prefix = "  " * depth + ("└─ " if depth else "● ")
        type_tag = f"[\033[36m{ent['type']:<10}\033[0m]"
        lines.append(f"{prefix}{type_tag} \033[1m{ent['value'][:60]}\033[0m")
        for e in by_src.get(eid, []):
            edge_line = "  " * (depth + 1) + f"\033[2m─({e['rel']})→\033[0m"
            lines.append(edge_line)
            render(e["dst"], depth + 1)

    render(root_id)
    return "\n".join(lines)


# ---------------- CLI dispatcher --------------------------------------

def cmd_graph(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(
            "usage: osint graph <show|export|rebuild|stats|forget> ...\n\n"
            "  graph show    <kind> <value> [--depth N]\n"
            "  graph export  <kind> <value> [--format gexf|graphml|cytoscape] [--out FILE]\n"
            "  graph rebuild           — derive entities from every stored hit\n"
            "  graph stats             — totals per type\n"
            "  graph forget  <kind> <value>\n",
            file=sys.stderr,
        )
        return 0 if argv else 2

    sub = argv[0]

    async def _run() -> int:
        load_settings()
        s = settings()
        db = Database(s.db_path)
        await db.connect()
        try:
            if sub == "stats":
                ent_count = await db.entity_count()
                edge_count = await db.edge_count()
                print(f"  entities: {ent_count:,}")
                print(f"  edges:    {edge_count:,}")
                print(f"  db:       {s.db_path}")
                return 0

            if sub == "rebuild":
                # iterate every query, re-derive
                assert db._conn is not None
                async with db._conn.execute("SELECT id FROM queries") as cur:
                    qids = [r["id"] for r in await cur.fetchall()]
                total_e = total_x = 0
                for qid in qids:
                    e, x = await db.correlate_query(qid)
                    total_e += e
                    total_x += x
                print(f"  rebuilt: {len(qids):,} queries → "
                      f"{total_e:,} entity touches / {total_x:,} edge touches")
                return 0

            if sub in ("show", "export") and len(argv) >= 3:
                kind_str, value = argv[1], argv[2]
                try:
                    etype = EntityType(kind_str)
                except ValueError:
                    print(f"unknown kind {kind_str!r}; valid: "
                          + ", ".join(e.value for e in EntityType), file=sys.stderr)
                    return 2
                depth = 2
                fmt = "ascii"
                out: str | None = None
                i = 3
                while i < len(argv):
                    a = argv[i]
                    if a == "--depth" and i + 1 < len(argv):
                        depth = int(argv[i + 1]); i += 2; continue
                    if a == "--format" and i + 1 < len(argv):
                        fmt = argv[i + 1]; i += 2; continue
                    if a == "--out" and i + 1 < len(argv):
                        out = argv[i + 1]; i += 2; continue
                    i += 1
                entities, edges = await bfs_subgraph(db, etype, value, max_depth=depth)
                if not entities:
                    print(f"  no entity matching ({kind_str}, {value}) — "
                          "scan it first then `osint graph rebuild`?")
                    return 1
                if sub == "show":
                    print(render_ascii(entities, edges,
                                       root_id=entity_id(etype, value)))
                    print(f"\n  {len(entities)} entities · {len(edges)} edges "
                          f"(depth ≤ {depth})")
                    return 0
                # export
                payload: str
                if fmt in ("cyto", "cytoscape", "json"):
                    payload = to_cytoscape_json(entities, edges)
                    default_ext = ".cyto.json"
                elif fmt == "gexf":
                    payload = to_gexf(entities, edges)
                    default_ext = ".gexf"
                elif fmt in ("graphml", "xml"):
                    payload = to_graphml(entities, edges)
                    default_ext = ".graphml"
                else:
                    print(f"unknown format {fmt!r}; valid: gexf, graphml, cytoscape",
                          file=sys.stderr); return 2
                if out:
                    Path(out).write_text(payload, encoding="utf-8")
                    print(f"  wrote {len(payload):,} bytes → {out}")
                else:
                    sys.stdout.write(payload + "\n")
                return 0

            if sub == "forget" and len(argv) >= 3:
                kind_str, value = argv[1].lower(), argv[2]
                from app.core.entities import EntityType
                try:
                    EntityType(kind_str)
                except ValueError:
                    valid = ", ".join(sorted(t.value for t in EntityType))
                    print(f"  unknown entity kind '{argv[1]}'.\n  valid: {valid}",
                          file=sys.stderr)
                    return 2
                n = await db.entity_forget(kind_str, value)
                print(f"  forgot {n} entity (cascade-deleted edges)")
                return 0

            print("usage: osint graph <show|export|rebuild|stats|forget> ...",
                  file=sys.stderr)
            return 2
        finally:
            await db.close()

    return asyncio.run(_run())
