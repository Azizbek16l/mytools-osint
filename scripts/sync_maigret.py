"""Sync data/sites.json with Maigret's curated 3000+ site signatures.

Maigret (github.com/soxoj/maigret) is the deepest publicly-curated set of
username probes available — Sherlock-derived and steadily refined since
2020. We map its schema onto our internal one:

  Maigret entry                                Our entry
  ──────────────                               ─────────
  urlMain / url           →  url (template, {username} → {})
  checkType="status_code" →  check="status"
  presenseStrs            →  good_regex (joined alternation)
  absenceStrs             →  bad_regex
  errors / disabled / ... →  skipped silently

Run: python scripts/sync_maigret.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

UPSTREAM = ("https://raw.githubusercontent.com/soxoj/maigret/main/"
            "maigret/resources/data.json")
OUT = Path(__file__).resolve().parents[1] / "data" / "sites.json"


def fetch() -> dict:
    req = Request(UPSTREAM, headers={"User-Agent": "mytools-osint/0.1"})
    try:
        with urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except URLError as e:
        print(f"fetch failed: {e}", file=sys.stderr)
        raise


def convert(name: str, site: dict) -> dict | None:
    if site.get("disabled") or site.get("type") not in (None, "username"):
        return None
    url_tpl = site.get("url") or site.get("urlMain")
    if not url_tpl:
        return None
    # Maigret uses {username}; we use {}.
    url = url_tpl.replace("{username}", "{}")
    if "{}" not in url:
        return None
    out: dict = {
        "name": name,
        "url": url,
        "category": (site.get("tags") or [None])[0] or "social",
    }
    check_type = (site.get("checkType") or "status_code").lower()
    presence = site.get("presenseStrs") or []
    absence = site.get("absenceStrs") or []
    if check_type == "status_code":
        out["check"] = "status"
    elif check_type in ("message", "response_url"):
        out["check"] = "regex"
        if presence:
            out["good_regex"] = "|".join(re.escape(s) for s in presence[:8])
        if absence:
            out["bad_regex"] = "|".join(re.escape(s) for s in absence[:8])
    else:
        out["check"] = "status"
    # Maigret usually uses 200 OK as the positive code unless overridden.
    if "statusCodeForUsernameExists" in site:
        out["good_status"] = [int(site["statusCodeForUsernameExists"])]
    if site.get("absenceStatusCode"):
        try:
            out["bad_status"] = [int(site["absenceStatusCode"])]
        except (ValueError, TypeError):
            pass
    if isinstance(site.get("headers"), dict):
        out["headers"] = site["headers"]
    if site.get("regexCheck"):
        out["valid_chars"] = site["regexCheck"]
    return out


def main() -> int:
    data = fetch()
    sites = data.get("sites") or {}
    converted: list[dict] = []
    for name, entry in sites.items():
        c = convert(name, entry)
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
        if c["url"].lower() in seen_url or c["name"].lower() in seen_name:
            continue
        merged.append(c)
        seen_url.add(c["url"].lower())
        seen_name.add(c["name"].lower())
        added += 1
    out = {
        "schema": 1,
        "_": "Synced from sherlock + WhatsMyName + Maigret + curated additions.",
        "sites": merged,
    }
    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"added {added} new sites from Maigret ({len(merged)} total) -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
