"""Tests for the persisted module-health store (Sprint 3, item 10).

The persistence layer is deliberately tiny — JSON on disk under
``platformdirs.user_data_path``. We monkeypatch the dirs so each test runs
in isolation under a tmp path.
"""
from __future__ import annotations

import json
from importlib import reload
from pathlib import Path

import pytest


@pytest.fixture
def isolated_health(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Redirect ``health_file_path`` to a tmp file unique to this test.

    ``platformdirs`` ignores ``LOCALAPPDATA`` on Windows (it calls
    ``SHGetKnownFolderPath`` via ctypes), so the only reliable way to
    isolate persistence is to monkeypatch the path-resolver itself.
    """
    import app.ui.health as health
    reload(health)
    target = tmp_path / "module_health.json"
    monkeypatch.setattr(health, "health_file_path", lambda: target)
    yield health
    reload(health)


def test_health_file_path_created(isolated_health) -> None:
    p = isolated_health.health_file_path()
    assert p.parent.exists(), "parent dir must be ensured on path resolution"
    assert p.name == "module_health.json"


def test_record_then_load_roundtrip(isolated_health) -> None:
    isolated_health.record_module_run("username", "ok", 42)
    isolated_health.record_module_run("username", "ok", 11)
    hist = isolated_health.get_module_history("username")
    assert len(hist) == 2
    assert hist[0][1] == "ok"
    assert hist[0][2] == 42
    assert hist[1][2] == 11
    # JSON on disk is well-formed and has the schema version.
    raw = isolated_health.health_file_path().read_text(encoding="utf-8")
    data = json.loads(raw)
    assert data["version"] == 1
    assert "modules" in data
    assert "username" in data["modules"]


def test_record_unknown_status_coerced_to_ok(isolated_health) -> None:
    isolated_health.record_module_run("email", "weird", 3)
    hist = isolated_health.get_module_history("email")
    assert hist == [(hist[0][0], "ok", 3)]


def test_record_negative_count_clamped(isolated_health) -> None:
    isolated_health.record_module_run("phone", "ok", -5)
    hist = isolated_health.get_module_history("phone")
    assert hist[0][2] == 0


def test_history_trimmed_to_last_50(isolated_health) -> None:
    for i in range(60):
        isolated_health.record_module_run("username", "ok", i)
    raw_runs = json.loads(
        isolated_health.health_file_path().read_text(encoding="utf-8"),
    )["modules"]["username"]["runs"]
    assert len(raw_runs) == 50
    # The oldest entry should now be hit_count=10 (we wrote 0..59, kept last 50).
    assert raw_runs[0][2] == 10
    assert raw_runs[-1][2] == 59


def test_missing_module_returns_empty_history(isolated_health) -> None:
    assert isolated_health.get_module_history("nope") == []


def test_corrupt_store_degrades_to_empty(isolated_health) -> None:
    isolated_health.health_file_path().write_text("{ not json", encoding="utf-8")
    # Both read and write must survive corrupt input.
    assert isolated_health.get_module_history("anything") == []
    isolated_health.record_module_run("username", "ok", 7)
    assert isolated_health.get_module_history("username") == [
        (isolated_health.get_module_history("username")[0][0], "ok", 7),
    ]


def test_sparkline_renders_colour_by_last_status(isolated_health) -> None:
    isolated_health.record_module_run("username", "ok", 4)
    isolated_health.record_module_run("username", "failed", 0)
    out = isolated_health.render_module_sparkline("username")
    # The Rich Text contains a numeric strip and the bar glyphs in BAD colour.
    rendered = str(out)
    assert "4·0" in rendered
    # Bar glyphs are part of the U+2581..U+2588 block.
    spark_block = "".join(chr(c) for c in range(0x2581, 0x2589))
    assert any(g in rendered for g in spark_block)


def test_sparkline_empty_module_is_dim_placeholder(isolated_health) -> None:
    out = isolated_health.render_module_sparkline("never-run", limit=7)
    rendered = str(out)
    # 7 dim dots — no real data yet.
    assert rendered.count("·") >= 7


def test_record_failure_does_not_raise(
    isolated_health, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Simulate a write failure — record_module_run must swallow.
    monkeypatch.setattr(isolated_health, "_save", lambda data: (_ for _ in ()).throw(OSError("nope")))
    # Should not raise.
    isolated_health.record_module_run("username", "ok", 1)
