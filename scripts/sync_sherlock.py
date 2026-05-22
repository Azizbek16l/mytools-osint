"""Sync app/../data/sites.json from upstream Sherlock data.json (canonical 400+ sites).

Run with: python scripts/sync_sherlock.py
Pulls the latest data from https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json
and converts it to our minimal schema. The result is merged into data/sites.json (existing
hand-curated entries are preserved if the site name matches).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

UPSTREAM = (
    "https://raw.githubusercontent.com/sherlock-project/sherlock/master/"
    "sherlock_project/resources/data.json"
)

OUT = Path(__file__).resolve().parents[1] / "data" / "sites.json"


def fetch() -> dict:
    req = Request(UPSTREAM, headers={"User-Agent": "mytools-osint/0.1"})
    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except URLError as e:
        print(f"fetch failed: {e}", file=sys.stderr)
        raise


def convert(name: str, entry: object) -> dict | None:
    if not isinstance(entry, dict):
        return None
    url = entry.get("url")
    if not isinstance(url, str) or "{}" not in url:
        return None
    site: dict = {"name": name, "url": url, "category": "social"}
    err_type = entry.get("errorType") or "status_code"
    if err_type == "status_code":
        site["check"] = "status"
        site["good_status"] = [200]
        site["bad_status"] = [int(entry.get("errorCode") or 404)]
    elif err_type == "message":
        site["check"] = "regex"
        msg = entry.get("errorMsg")
        if isinstance(msg, list):
            msg = msg[0] if msg else ""
        if msg:
            site["bad_regex"] = msg
    elif err_type == "response_url":
        site["check"] = "url"
        site["bad_url_contains"] = entry.get("errorUrl", "")
    else:
        return None
    if "regexCheck" in entry:
        site["valid_chars"] = entry["regexCheck"]
    return site


def main() -> int:
    data = fetch()
    new_sites: list[dict] = []
    for name, entry in data.items():
        s = convert(name, entry)
        if s:
            new_sites.append(s)
    existing: dict = {"schema": 1, "sites": []}
    if OUT.exists():
        existing = json.loads(OUT.read_text(encoding="utf-8"))
    seen = {s["name"].lower() for s in existing.get("sites", [])}
    merged = list(existing.get("sites", []))
    for s in new_sites:
        if s["name"].lower() not in seen:
            merged.append(s)
            seen.add(s["name"].lower())
    out = {
        "schema": 1,
        "_": "Synced from sherlock-project/sherlock + curated additions.",
        "sites": merged,
    }
    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {len(merged)} sites to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
