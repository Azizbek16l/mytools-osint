"""SIEM exporters — push findings into Splunk / Elastic / syslog / MISP.

Usage:
  osint export <kind> <value> --to splunk
  osint export <kind> <value> --to elastic [--es-url http://x:9200] [--es-index osint]
  osint export <kind> <value> --to syslog [--syslog host:port] [--proto udp|tcp]
  osint export <kind> <value> --to misp   --misp-url … --misp-key …

Each target reads its connection params from CLI flags OR env vars:
  SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN
  ELASTICSEARCH_URL, ELASTICSEARCH_INDEX, ELASTICSEARCH_API_KEY
  SYSLOG_HOST, SYSLOG_PORT, SYSLOG_PROTO
  MISP_URL, MISP_API_KEY

If params missing → polite SKIPPED message, no crash.

Why not a daemon: SOC analysts want one-shot exports of a specific scan,
not an always-on stream. For that, see `osint watch run --notify-splunk` (TODO).
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
from datetime import UTC, datetime
from typing import Any

from app.core.config import load_settings, settings
from app.core.db import Database
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity


def _hit_to_event(query: Query, hit: Hit) -> dict[str, Any]:
    """Canonical event shape — works for HEC / Elastic / MISP."""
    return {
        "@timestamp": (hit.found_at or datetime.now(UTC)).isoformat(),
        "source": "mytools-osint",
        "kind": query.kind.value,
        "target": query.value,
        "module": hit.module,
        "src": hit.source,
        "category": hit.category,
        "status": hit.status.value,
        "severity": hit.severity.value,
        "title": hit.title,
        "detail": hit.detail,
        "url": hit.url,
        "latency_ms": hit.latency_ms,
        "extra": hit.extra or {},
    }


# ---------------------------------------------------------------- Splunk HEC
async def _push_splunk(events: list[dict]) -> tuple[int, str]:
    """Push to Splunk HEC. Returns (count_sent, detail)."""
    url = os.getenv("SPLUNK_HEC_URL", "").rstrip("/")
    token = os.getenv("SPLUNK_HEC_TOKEN", "")
    if not url or not token:
        return 0, "set SPLUNK_HEC_URL + SPLUNK_HEC_TOKEN"
    endpoint = f"{url}/services/collector/event"
    from app.core.http import get_client
    client = await get_client()
    # Splunk HEC accepts newline-delimited JSON or one event per request.
    # NDJSON is more efficient — wrap each event in {"event": …}.
    body = "\n".join(json.dumps({"event": ev, "sourcetype": "osint"})
                     for ev in events)
    try:
        r = await client.post(endpoint, content=body,
                              headers={"Authorization": f"Splunk {token}",
                                       "Content-Type": "application/json"},
                              timeout=15.0)
        if r.status_code in (200, 201):
            return len(events), f"HTTP {r.status_code}"
        return 0, f"HTTP {r.status_code} — {r.text[:120]}"
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"


# ---------------------------------------------------------------- Elasticsearch
async def _push_elastic(events: list[dict], index: str | None = None) -> tuple[int, str]:
    """Bulk-index to Elasticsearch."""
    url = os.getenv("ELASTICSEARCH_URL", "").rstrip("/")
    api_key = os.getenv("ELASTICSEARCH_API_KEY", "")
    if not url:
        return 0, "set ELASTICSEARCH_URL"
    idx = index or os.getenv("ELASTICSEARCH_INDEX", "osint")
    endpoint = f"{url}/_bulk"
    # Bulk API: alternating action + source lines.
    body_lines: list[str] = []
    for ev in events:
        body_lines.append(json.dumps({"index": {"_index": idx}}))
        body_lines.append(json.dumps(ev, default=str))
    body = "\n".join(body_lines) + "\n"
    headers = {"Content-Type": "application/x-ndjson"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    from app.core.http import get_client
    client = await get_client()
    try:
        r = await client.post(endpoint, content=body, headers=headers, timeout=15.0)
        if r.status_code == 200:
            data = r.json()
            errors = data.get("errors")
            return (len(events), f"HTTP 200, errors={errors}")
        return 0, f"HTTP {r.status_code} — {r.text[:120]}"
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"


# ---------------------------------------------------------------- syslog (RFC 5424)
def _push_syslog(events: list[dict], host: str | None = None,
                 port: int | None = None, proto: str = "udp") -> tuple[int, str]:
    """RFC 5424 syslog over UDP or TCP. Synchronous (small enough)."""
    h = host or os.getenv("SYSLOG_HOST", "localhost")
    p = port or int(os.getenv("SYSLOG_PORT", "514"))
    pr = (proto or os.getenv("SYSLOG_PROTO", "udp")).lower()
    fac_sev = "<134>"   # local0.info
    sent = 0
    sock = None
    try:
        if pr == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((h, p))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
        host_hdr = socket.gethostname()
        for ev in events:
            ts = ev.get("@timestamp", datetime.now(UTC).isoformat())
            msg_id = f"{ev.get('module','?')}/{ev.get('src','?')}"
            structured = json.dumps(ev, default=str)
            line = f"{fac_sev}1 {ts} {host_hdr} mytools-osint - {msg_id} - {structured}"
            data = line.encode("utf-8")
            if pr == "tcp":
                sock.sendall(data + b"\n")
            else:
                sock.sendto(data, (h, p))
            sent += 1
        return sent, f"{pr}://{h}:{p}"
    except Exception as e:
        return sent, f"{type(e).__name__}: {e}"
    finally:
        if sock:
            sock.close()


# ---------------------------------------------------------------- MISP Event
async def _push_misp(events: list[dict], misp_url: str | None = None,
                     api_key: str | None = None,
                     info: str | None = None) -> tuple[int, str]:
    """Create a MISP Event with one Attribute per hit."""
    url = (misp_url or os.getenv("MISP_URL", "")).rstrip("/")
    key = api_key or os.getenv("MISP_API_KEY", "")
    if not url or not key:
        return 0, "set MISP_URL + MISP_API_KEY"
    if not events:
        return 0, "no events"

    # Pick attribute type per OSINT severity / category. MISP categories:
    #   Network activity, External analysis, Other
    def attrib(ev: dict) -> dict | None:
        cat = ev.get("category", "")
        url_val = ev.get("url") or ""
        val_map = [
            ("ip-src", lambda e: e.get("title") if (e.get("kind") == "ip") else None),
            ("domain", lambda e: e.get("title") if (e.get("kind") == "domain") else None),
            ("email-src", lambda e: e.get("title") if (e.get("kind") == "email") else None),
            ("url", lambda e: url_val),
        ]
        for atype, fn in val_map:
            v = fn(ev)
            if v:
                return {"type": atype, "value": v,
                        "category": "External analysis",
                        "comment": ev.get("detail", "")[:200]}
        return None

    body = {
        "Event": {
            "info": info or f"osint scan: {events[0].get('kind')}={events[0].get('target')}",
            "distribution": 0,   # your-org only
            "analysis": 2,       # complete
            "threat_level_id": 3,  # low
            "Attribute": [a for a in (attrib(ev) for ev in events) if a],
        }
    }
    endpoint = f"{url}/events"
    from app.core.http import get_client
    client = await get_client()
    try:
        r = await client.post(endpoint, json=body,
                              headers={"Authorization": key,
                                       "Accept": "application/json"},
                              timeout=20.0)
        if r.status_code in (200, 201):
            data = r.json()
            eid = (data.get("Event") or {}).get("id", "?")
            return len(body["Event"]["Attribute"]), f"created event #{eid}"
        return 0, f"HTTP {r.status_code} — {r.text[:120]}"
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"


# ---------------------------------------------------------------- CLI
def cmd_export(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(
            "usage: osint export <kind> <value> --to <target> [opts]\n\n"
            "  --to splunk        env: SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN\n"
            "  --to elastic       env: ELASTICSEARCH_URL [ELASTICSEARCH_API_KEY]\n"
            "                     opt: --es-index NAME (default: osint)\n"
            "  --to syslog        env: SYSLOG_HOST, SYSLOG_PORT, SYSLOG_PROTO\n"
            "                     opt: --syslog HOST:PORT  --proto udp|tcp\n"
            "  --to misp          env: MISP_URL, MISP_API_KEY  opt: --info STR\n"
            "  --last             use the most recent saved scan of <kind>/<value>\n"
            "                     (default: re-run the scan now)\n",
            file=sys.stderr,
        )
        return 0 if argv else 2

    if len(argv) < 2 or "--to" not in argv:
        print("usage: osint export <kind> <value> --to <target>", file=sys.stderr)
        return 2

    kind_str, value = argv[0], argv[1]
    to_idx = argv.index("--to")
    target = argv[to_idx + 1] if to_idx + 1 < len(argv) else ""

    async def _run() -> int:
        load_settings()
        s = settings()
        db = Database(s.db_path)
        await db.connect()
        try:
            # Find the most recent matching saved scan.
            assert db._conn is not None
            async with db._conn.execute(
                "SELECT id FROM queries WHERE kind = ? AND value = ? "
                "ORDER BY id DESC LIMIT 1",
                (kind_str, value),
            ) as cur:
                row = await cur.fetchone()
            if not row:
                print(f"  no saved scan found for {kind_str}={value} — "
                      f"run `osint <value>` first.", file=sys.stderr)
                return 1
            qid = row["id"]
            # Load query + hits
            async with db._conn.execute(
                "SELECT * FROM queries WHERE id = ?", (qid,),
            ) as cur:
                qrow = await cur.fetchone()
            async with db._conn.execute(
                "SELECT * FROM hits WHERE query_id = ?", (qid,),
            ) as cur:
                hrows = await cur.fetchall()
            from datetime import datetime as _dt
            query = Query(kind=QueryKind(qrow["kind"]), value=qrow["value"],
                          note=qrow["note"],
                          started_at=_dt.fromisoformat(qrow["started_at"]))
            events = []
            for hr in hrows:
                hit = Hit(
                    module=hr["module"], source=hr["source"], category=hr["category"],
                    status=HitStatus(hr["status"]), title=hr["title"], url=hr["url"],
                    detail=hr["detail"], severity=Severity(hr["severity"]),
                    extra=json.loads(hr["extra_json"] or "{}"),
                    found_at=_dt.fromisoformat(hr["found_at"]),
                    latency_ms=hr["latency_ms"],
                )
                events.append(_hit_to_event(query, hit))

            print(f"  exporting {len(events)} events to {target}…", file=sys.stderr)
            if target == "splunk":
                n, msg = await _push_splunk(events)
            elif target == "elastic":
                idx = None
                if "--es-index" in argv:
                    idx = argv[argv.index("--es-index") + 1]
                n, msg = await _push_elastic(events, index=idx)
            elif target == "syslog":
                host = port = None
                proto = "udp"
                if "--syslog" in argv:
                    hp = argv[argv.index("--syslog") + 1]
                    if ":" in hp:
                        host, p = hp.split(":", 1)
                        port = int(p)
                if "--proto" in argv:
                    proto = argv[argv.index("--proto") + 1]
                n, msg = _push_syslog(events, host=host, port=port, proto=proto)
            elif target == "misp":
                info = None
                if "--info" in argv:
                    info = argv[argv.index("--info") + 1]
                n, msg = await _push_misp(events, info=info)
            else:
                print(f"unknown --to {target!r}; valid: splunk, elastic, syslog, misp",
                      file=sys.stderr)
                return 2
            print(f"  → {n}/{len(events)} sent · {msg}")
            return 0 if n > 0 else 1
        finally:
            await db.close()

    return asyncio.run(_run())
