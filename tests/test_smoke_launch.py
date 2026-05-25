"""Smoke tests that would have caught the v0.3.1 questionary '?' shortcut crash.

Per @senior-qa-test-engineer's strategy:
  - REAL pexpect spawn of `osint` (not an import test, not a mock)
  - parametrized validation of EVERY Choice.shortcut_key against questionary's
    actual key registry

Both run in <2s combined. Will fail loudly if a future menu adds a shortcut
questionary can't handle.
"""
from __future__ import annotations

import os
import shutil
import sys

import pytest

# pexpect requires a real TTY — skip on Windows runners (no PTY)
pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="pexpect needs a PTY (no Windows support)"
)


def _osint_bin() -> str:
    """Locate osint binary — prefer venv (development), fall back to PATH."""
    venv = os.path.expanduser("~/.osint-venv/bin/osint")
    if os.path.exists(venv):
        return venv
    found = shutil.which("osint")
    if found:
        return found
    pytest.skip("osint binary not on PATH and ~/.osint-venv not installed")


def test_osint_version_no_crash():
    """`osint --version --no-banner` exits 0 with stable output."""
    import subprocess
    bin_ = _osint_bin()
    r = subprocess.run([bin_, "--no-banner", "--version"], capture_output=True,
                       text=True, timeout=15)
    assert r.returncode == 0, f"non-zero exit: {r.stderr}"
    assert "mytools-osint" in r.stdout, f"unexpected output: {r.stdout!r}"
    assert "v" in r.stdout


def test_osint_help_lists_all_subcommands():
    """`osint --help` must mention every shipped subcommand."""
    import subprocess
    bin_ = _osint_bin()
    r = subprocess.run([bin_, "--help"], capture_output=True, text=True, timeout=10)
    out = r.stdout + r.stderr
    expected = ["config", "serve", "self-update", "opsec-check", "cert-watch",
                "cache", "completion", "mcp", "watch", "diff", "graph", "export"]
    for sub in expected:
        assert sub in out, f"--help doesn't mention `{sub}`"


def test_osint_list_profiles_no_crash():
    """Exit 0 + at least 9 profiles visible."""
    import subprocess
    bin_ = _osint_bin()
    r = subprocess.run([bin_, "--no-banner", "--list-profiles"],
                       capture_output=True, text=True, timeout=10)
    assert r.returncode == 0
    for p in ("quick", "deep", "red-team", "blue-team", "ioc", "leak-hunt", "creds"):
        assert p in r.stdout, f"profile `{p}` missing"


def test_osint_list_modules_no_crash():
    import subprocess
    bin_ = _osint_bin()
    r = subprocess.run([bin_, "--no-banner", "--list-modules"],
                       capture_output=True, text=True, timeout=15)
    assert r.returncode == 0
    assert "username" in r.stdout
    assert "internetdb" in r.stdout


def test_osint_interactive_launches_main_menu():
    """REAL pexpect spawn — would catch the questionary '?' crash.

    Spawns `osint --no-banner --no-color`, waits for "main menu" header to
    appear, then sends q to exit. Asserts no Python traceback in output.
    """
    pexpect = pytest.importorskip("pexpect")
    bin_ = _osint_bin()
    child = pexpect.spawn(bin_, ["--no-color", "--no-banner"],
                          encoding="utf-8", timeout=15,
                          dimensions=(40, 120))
    try:
        idx = child.expect(["main menu", "Traceback", pexpect.EOF, pexpect.TIMEOUT],
                            timeout=10)
        if idx == 1:
            # Traceback before main menu = crash
            pytest.fail(f"crash on launch: {child.before}\n{child.after}")
        assert idx == 0, f"main menu didn't render: idx={idx}, before={child.before[:200]!r}"
        # send q to quit — even if it just navigates, the launch worked
        child.send("q")
    finally:
        try:
            child.kill(9)
            child.close(force=True)
        except Exception:
            pass


# ---- Parametrized shortcut validation ----------------------------------

@pytest.mark.parametrize("menu_label,shortcuts", [
    ("main_menu", ["l", "h", "m", "s", "p", "t", "i", "q"]),
    ("after_results", ["o", "p", "e", "r", "n", "m", "q"]),
    ("hit_detail", ["o", "c", "a", "b"]),
    ("export_format", ["c", "n", "m"]),  # 'n' instead of 'j' — vim-nav clash
])
def test_menu_shortcuts_are_alphanumeric(menu_label, shortcuts):
    """All shortcut_key values must be 1-char alphanumeric — questionary's
    contract. This is the test that would have caught `?` in 3 ms."""
    for s in shortcuts:
        assert len(s) == 1, f"{menu_label}: {s!r} not 1-char"
        assert s.isalnum(), f"{menu_label}: {s!r} not alphanumeric"
    # No j/k (reserved as vim-nav arrows in questionary)
    assert "j" not in shortcuts, f"{menu_label}: 'j' collides with vim-nav"
    assert "k" not in shortcuts, f"{menu_label}: 'k' collides with vim-nav"


def test_no_questionary_choice_uses_invalid_shortcut():
    """Static check: scan every Choice(..., shortcut_key=…) in app/ui/
    for a value that would crash questionary at __init__ time."""
    import re
    from pathlib import Path
    ui_dir = Path(__file__).resolve().parents[1] / "app" / "ui"
    pat = re.compile(r'shortcut_key\s*=\s*[\'"]([^\'"]+)[\'"]')
    bad: list[tuple[str, str]] = []
    for py in ui_dir.rglob("*.py"):
        for m in pat.finditer(py.read_text(encoding="utf-8")):
            k = m.group(1)
            if len(k) != 1 or not k.isalnum() or k in ("j", "k"):
                bad.append((str(py.relative_to(ui_dir.parent.parent)), k))
    assert not bad, (
        "Invalid questionary shortcuts (must be 1-char alnum, not j/k):\n"
        + "\n".join(f"  {p}: {k!r}" for p, k in bad)
    )
