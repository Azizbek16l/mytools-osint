"""Golden contract for the username site dataset.

A site silently changing its detection signature (good_status / bad_status /
check / url) would otherwise produce wrong FOUND/NOT_FOUND with zero test
failure. These tests lock the count and a content checksum so any change to
`data/sites.json` forces an intentional update here (and thus review).

When you legitimately change the dataset: run this test, copy the new count
and DIGEST from the failure message into the constants below.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

_DATA = Path(__file__).resolve().parents[1] / "data" / "sites.json"

EXPECTED_COUNT = 1008
EXPECTED_DIGEST = "94c9310033dcc6a8721e4523156ebc96d07f6073ad668a9a34cd2c6d4eee5517"


def _sites() -> list[dict]:
    d = json.loads(_DATA.read_text(encoding="utf-8"))
    return d["sites"] if isinstance(d, dict) else d


def test_site_count_locked() -> None:
    sites = _sites()
    assert len(sites) == EXPECTED_COUNT, (
        f"site count changed: {len(sites)} (was {EXPECTED_COUNT}). "
        "If intentional, update EXPECTED_COUNT."
    )


def test_site_dataset_checksum() -> None:
    norm = sorted(json.dumps(s, sort_keys=True, ensure_ascii=False) for s in _sites())
    digest = hashlib.sha256("\n".join(norm).encode("utf-8")).hexdigest()
    assert digest == EXPECTED_DIGEST, (
        "data/sites.json content changed — a detection signature may have drifted. "
        f"If intentional, set EXPECTED_DIGEST = {digest!r}"
    )
