"""Sync data/sites.json with the WhatsMyName project's curated 600+ site signatures.

WhatsMyName (github.com/WebBreacher/WhatsMyName) has stricter signatures than
Sherlock: every entry has a known username, a 'e_string' (expected text on
positive match) and 'm_string' (text present on negative match). We convert
these into our internal schema.

Run: python scripts/sync_whatsmyname.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

UPSTREAM = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
OUT = Path(__file__).resolve().parents[1] / "data" / "sites.json"


def fetch() -> dict:
    req = Request(UPSTREAM, headers={"User-Agent": "mytools-osint/0.1"})
    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except URLError as e:
        print(f"fetch failed: {e}", file=sys.stderr)
        raise


def convert(site: dict) -> dict | None:
    name = site.get("name")
    uri_check = site.get("uri_check")
    if not name or not uri_check:
        return None
    url = uri_check.replace("{account}", "{}")
    if "{}" not in url:
        return None
    out: dict = {
        "name": name,
        "url": url,
        "category": site.get("cat", "social") or "social",
        "check": "regex",
    }
    if "e_string" in site:
        out["good_regex"] = site["e_string"]
    if "m_string" in site:
        out["bad_regex"] = site["m_string"]
    if "e_code" in site:
        out["good_status"] = [int(site["e_code"])]
    if "m_code" in site:
        out["bad_status"] = [int(site["m_code"])]
    if "headers" in site and isinstance(site["headers"], dict):
        out["headers"] = site["headers"]
    if "post_body" in site and site["post_body"]:
        out["method"] = "POST"
        # leave raw — base.probe_site doesn't handle arbitrary post bodies; skip these
        return None
    return out


def main() -> int:
    data = fetch()
    sites = data.get("sites") or []
    converted: list[dict] = []
    for s in sites:
        c = convert(s)
        if c:
            converted.append(c)
    existing: dict = {"schema": 1, "sites": []}
    if OUT.exists():
        existing = json.loads(OUT.read_text(encoding="utf-8"))
    seen_url = {s["url"].lower() for s in existing.get("sites", [])}
    seen_name = {s["name"].lower() for s in existing.get("sites", [])}
    merged = list(existing.get("sites", []))
    added = 0
    for c in converted:
        key_url = c["url"].lower()
        key_name = c["name"].lower()
        if key_url in seen_url or key_name in seen_name:
            continue
        merged.append(c)
        seen_url.add(key_url)
        seen_name.add(key_name)
        added += 1
    out = {
        "schema": 1,
        "_": "Synced from sherlock-project + WhatsMyName + curated additions.",
        "sites": merged,
    }
    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"added {added} new sites from WhatsMyName ({len(merged)} total) -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
