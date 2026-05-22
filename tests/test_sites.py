"""Sites dataset sanity — every entry has the fields we rely on at probe time."""
from __future__ import annotations

import json
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data"


def _load(name: str) -> list[dict]:
    return json.loads((DATA / name).read_text(encoding="utf-8")).get("sites", [])


def test_sites_minimal_schema():
    sites = _load("sites.json")
    assert len(sites) >= 50, "expected at least 50 username probe targets"
    seen = set()
    for s in sites:
        assert "name" in s and "url" in s, s
        assert "{}" in s["url"] or "{md5}" in s["url"], s
        assert s["name"] not in seen, f"duplicate site: {s['name']}"
        seen.add(s["name"])


def test_holehe_sites_minimal_schema():
    sites = _load("holehe_sites.json")
    assert len(sites) >= 5
    for s in sites:
        assert "name" in s and "url" in s, s
        # at least one signal expected
        assert any(k in s for k in ("good_regex", "bad_regex", "good_status", "bad_status")), s
