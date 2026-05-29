"""Fabric-style externalised patterns — hermetic.

Each test points ``XDG_CONFIG_HOME`` at a tmp dir so we never touch the user's
real ``~/.config/mytools-osint/`` and never read each other's state.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.features.patterns import (
    Pattern,
    list_patterns,
    load_pattern,
    pattern_dirs,
)


@pytest.fixture
def user_dir(tmp_path, monkeypatch) -> Path:
    """Isolated XDG dir; patterns/ created on demand by the helper."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    target = tmp_path / "mytools-osint" / "patterns"
    target.mkdir(parents=True, exist_ok=True)
    return target


def test_builtin_exec_summary_loads(user_dir):
    p = load_pattern("exec-summary")
    assert isinstance(p, Pattern)
    assert p.name == "exec-summary"
    assert p.identity.strip()
    assert p.steps.strip()
    assert p.output.strip()
    # Render must substitute {{PAYLOAD}} into the body
    rendered = p.render({"PAYLOAD": "FINDINGS_GO_HERE"})
    assert "FINDINGS_GO_HERE" in rendered


def test_builtin_phishing_triage_loads(user_dir):
    p = load_pattern("phishing-triage")
    assert "ESCALATE" in p.output or "ESCALATE" in p.body


def test_builtin_dossier_loads(user_dir):
    p = load_pattern("dossier")
    assert "Subject" in p.body


def test_list_patterns_returns_all_builtins(user_dir):
    names = list_patterns()
    for expected in ("exec-summary", "phishing-triage", "dossier"):
        assert expected in names


def test_user_pattern_overrides_builtin(user_dir):
    """A user-edited pattern with the same name wins."""
    (user_dir / "exec-summary.md").write_text(
        "# IDENTITY\nuser-override\n\n# STEPS\nstep\n\n# OUTPUT\nUSER_OVERRIDE_BODY\n",
        encoding="utf-8",
    )
    p = load_pattern("exec-summary")
    assert p.source.parent == user_dir
    assert "USER_OVERRIDE_BODY" in p.body
    assert p.identity.strip() == "user-override"


def test_missing_pattern_raises(user_dir):
    with pytest.raises(FileNotFoundError):
        load_pattern("does-not-exist")


def test_invalid_pattern_name_rejected(user_dir):
    """Path traversal must be rejected before touching disk."""
    with pytest.raises(FileNotFoundError):
        load_pattern("../../etc/passwd")
    with pytest.raises(FileNotFoundError):
        load_pattern(".secret")


def test_render_leaves_unknown_placeholder_alone(user_dir):
    (user_dir / "demo.md").write_text(
        "# IDENTITY\nx\n# STEPS\ny\n# OUTPUT\nz\nbody {{KNOWN}} {{UNKNOWN}}\n",
        encoding="utf-8",
    )
    p = load_pattern("demo")
    rendered = p.render({"KNOWN": "yes"})
    assert "yes" in rendered
    assert "{{UNKNOWN}}" in rendered  # surfaced literally for debugging


def test_render_tolerates_whitespace_in_placeholder(user_dir):
    (user_dir / "ws.md").write_text(
        "# IDENTITY\nx\n# STEPS\ny\n# OUTPUT\nz\nhi {{ NAME }}\n",
        encoding="utf-8",
    )
    p = load_pattern("ws")
    assert "hi world" in p.render({"NAME": "world"})


def test_pattern_dirs_returns_pair(user_dir):
    builtin, user = pattern_dirs()
    assert builtin.exists()
    assert user == user_dir


def test_system_block_concatenates_three_sections(user_dir):
    p = load_pattern("exec-summary")
    block = p.system_block()
    assert "# IDENTITY" in block
    assert "# STEPS" in block
    assert "# OUTPUT" in block


def test_list_dedups_user_and_builtin(user_dir):
    """Same name on both sides → appears once in list_patterns()."""
    (user_dir / "exec-summary.md").write_text(
        "# IDENTITY\nx\n# STEPS\ny\n# OUTPUT\nz\nbody\n", encoding="utf-8",
    )
    names = list_patterns()
    assert names.count("exec-summary") == 1
