"""WP-E — CLI + chat-shell UX regressions.

Covers the user-facing contracts fixed in WP-E:

  * ``osint --help`` lists every subcommand, including ``agent`` and ``doctor``
    (they were dispatched but undocumented).
  * ``--no-color`` (and a piped, non-TTY stdout) strips ANSI from --help/usage
    output — argparse 3.14 colourises help during parse_args, before the old
    Style check ran.
  * The Wave D chat-shell slash commands (/case /rules /playbook /schedule
    /diff /watch /doctor) are registered in the dispatcher and reachable from
    tab-completion.
  * ``schedule install --apply`` from the chat shell requires an inline
    confirmation before it can write a real OS job.
  * ``cli.infer_kind`` is the single canonical inferer (no forked copy).
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
from prompt_toolkit.completion import CompleteEvent
from prompt_toolkit.document import Document
from prompt_toolkit.history import FileHistory

from app.ui.lookup_input import (
    ALL_SLASH_TOKENS,
    SLASH_ALIASES,
    SLASH_DESCRIPTIONS,
    build_completer,
    dispatch_slash,
)

_ROOT = Path(__file__).resolve().parents[1]
_CLI = _ROOT / "cli.py"
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    """Run the real CLI as a subprocess (non-TTY pipe) and capture stdout."""
    return subprocess.run(
        [sys.executable, str(_CLI), *args],
        capture_output=True, text=True, timeout=60, cwd=str(_ROOT),
        env={**_clean_env()},
    )


def _clean_env() -> dict[str, str]:
    import os
    env = dict(os.environ)
    # Don't let an inherited NO_COLOR mask the --no-color path under test.
    env.pop("NO_COLOR", None)
    return env


# --------------------------------------------------------------------------- #
# 1. --help lists agent + doctor (and the other Wave verbs)
# --------------------------------------------------------------------------- #

def test_help_lists_agent_and_doctor() -> None:
    cp = _run_cli("--help")
    assert cp.returncode == 0
    out = _ANSI_RE.sub("", cp.stdout)
    assert re.search(r"^\s+agent\b", out, re.MULTILINE), \
        "`agent` missing from --help subcommand list"
    assert re.search(r"^\s+doctor\b", out, re.MULTILINE), \
        "`doctor` missing from --help subcommand list"
    # The other Wave D verbs must also be discoverable.
    for verb in ("case", "rules", "playbook", "schedule"):
        assert verb in out, f"{verb} missing from --help"


# --------------------------------------------------------------------------- #
# 2. --no-color (and piped stdout) strips ANSI from --help
# --------------------------------------------------------------------------- #

def test_help_piped_is_ansi_free() -> None:
    """A non-TTY pipe alone should already disable colour in help output."""
    cp = _run_cli("--help")
    assert cp.returncode == 0
    assert _ANSI_RE.search(cp.stdout) is None, \
        "piped --help still contains ANSI escapes"


def test_no_color_strips_ansi_from_help() -> None:
    cp = _run_cli("--no-color", "--help")
    assert cp.returncode == 0
    assert _ANSI_RE.search(cp.stdout) is None, \
        "--no-color --help still contains ANSI escapes"


# --------------------------------------------------------------------------- #
# 3. Wave D slash commands are registered + dispatch + tab-completable
# --------------------------------------------------------------------------- #

WAVE_D_SLASH = ("case", "rules", "playbook", "schedule", "diff", "watch", "doctor")


@pytest.mark.parametrize("name", WAVE_D_SLASH)
def test_wave_d_slash_registered(name: str) -> None:
    assert name in SLASH_ALIASES, f"/{name} not in SLASH_ALIASES"
    assert name in SLASH_DESCRIPTIONS, f"/{name} has no description"
    primary = SLASH_ALIASES[name][0]  # type: ignore[index]
    assert primary == f"/{name}"


@pytest.mark.parametrize(
    "line,expected",
    [
        ("/case new acme", "case"),
        ("/cases list", "case"),
        ("/rules run --case acme", "rules"),
        ("/playbook list", "playbook"),
        ("/pb run 1 acme", "playbook"),
        ("/schedule install acme --every 24h", "schedule"),
        ("/diff domain acme.com", "diff"),
        ("/watch list", "watch"),
        ("/doctor", "doctor"),
        ("/diag", "doctor"),
    ],
)
def test_wave_d_slash_dispatch(line: str, expected: str) -> None:
    action = dispatch_slash(line)
    assert action.action == expected, f"{line!r} -> {action.action!r}"


def _completions_for(completer, text: str) -> list[str]:
    doc = Document(text=text, cursor_position=len(text))
    return [c.text for c in completer.get_completions(doc, CompleteEvent())]


def test_wave_d_slash_tab_completable(tmp_path: Path) -> None:
    history = FileHistory(str(tmp_path / "h.txt"))
    completer = build_completer(history)
    completions = _completions_for(completer, "/")
    for name in WAVE_D_SLASH:
        assert f"/{name}" in completions, f"/{name} not tab-completable"
    # Flat token list (used by the completer + did-you-mean) must contain them.
    for name in WAVE_D_SLASH:
        assert f"/{name}" in ALL_SLASH_TOKENS


# --------------------------------------------------------------------------- #
# 4. schedule install from the chat shell requires confirmation
# --------------------------------------------------------------------------- #

def test_chat_schedule_install_requires_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    """`/schedule install … --apply` must prompt y/N; a rejection must strip
    --apply so the underlying handler only previews (writes nothing)."""
    import asyncio

    from app.ui import interactive

    captured: dict[str, list[str]] = {}

    def _fake_cmd_schedule(argv: list[str]) -> int:
        captured["argv"] = list(argv)
        return 0

    # The handler is imported lazily inside _resolve(); patch at the source.
    monkeypatch.setattr(
        "app.features.scheduler.cmd_schedule", _fake_cmd_schedule, raising=True,
    )

    # A confirm() that records it was asked and returns False (reject).
    asked: list[bool] = []

    class _FakeConfirm:
        def __init__(self, *a, **k):
            asked.append(True)

        async def ask_async(self):
            return False

    monkeypatch.setattr(interactive.questionary, "confirm",
                        lambda *a, **k: _FakeConfirm(*a, **k))

    asyncio.run(interactive._slash_cli_verb(
        "schedule", "install acme --every 24h --apply",
    ))

    assert asked, "confirmation was not requested for `schedule install --apply`"
    # The rejected --apply must have been stripped before reaching the handler.
    assert "argv" in captured
    assert "--apply" not in captured["argv"], \
        "rejected confirmation still passed --apply (would write a real job)"
    assert "--confirm" not in captured["argv"]


def test_chat_schedule_list_does_not_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-mutating subcommands (list) must never trigger the confirm gate."""
    import asyncio

    from app.ui import interactive

    monkeypatch.setattr(
        "app.features.scheduler.cmd_schedule", lambda argv: 0, raising=True,
    )

    def _boom(*a, **k):
        raise AssertionError("confirm() must not be called for `schedule list`")

    monkeypatch.setattr(interactive.questionary, "confirm", _boom)
    asyncio.run(interactive._slash_cli_verb("schedule", "list"))


# --------------------------------------------------------------------------- #
# 5. cli.infer_kind is the canonical inferer (no forked copy)
# --------------------------------------------------------------------------- #

def test_cli_infer_kind_is_canonical() -> None:
    import cli
    from app.core.infer import infer_kind as canonical
    from app.core.types import QueryKind

    # Same routing decisions as the canonical inferer for representative inputs
    # that the OLD forked cli.infer_kind also had to get right.
    samples = [
        "satya@microsoft.com",
        "0x" + "a" * 40,          # ETH wallet — must NOT be a username probe blast
        "8.8.8.8",
        "2001:db8::1",            # IPv6 — must NOT fall through to username
        "github.com",
        "@durov",
        "d41d8cd98f00b204e9800998ecf8427e",  # md5 hash IOC
        "torvalds",
    ]
    for s in samples:
        assert cli.infer_kind(s) == canonical(s), f"forked behaviour for {s!r}"

    # The canonical returns None only for empty input; cli's wrapper keeps the
    # historical non-None contract (callers don't guard the empty case).
    assert canonical("") is None
    assert cli.infer_kind("") == QueryKind.USERNAME  # cli wrapper never returns None


@pytest.mark.parametrize(
    "argv",
    [
        ["--no-color", "playbook", "list"],
        ["--no-color", "--no-banner", "rules", "list"],
        ["--no-splash", "--no-color", "playbook", "list"],
    ],
)
def test_global_flags_before_subcommand_dispatch(argv, capsys) -> None:
    """Position-independent subcommands: leading global toggle flags must not
    break dispatch. `osint --no-color playbook list` used to argparse-error
    (exit 2, 'unrecognized arguments'); it must now route to the subcommand."""
    import cli
    rc = cli.main(argv)
    assert rc == 0, f"{argv} should dispatch the subcommand, got rc={rc}"
    out = capsys.readouterr().out
    assert "unrecognized arguments" not in out


def test_route_leading_toggles_helper() -> None:
    """The pure re-point helper: skip leading toggles before a verb, but leave a
    bare scan value intact so main scans aren't mis-routed."""
    import cli
    assert cli._route_leading_toggles(["--no-color", "playbook", "list"]) == ["playbook", "list"]
    assert cli._route_leading_toggles(["--no-color", "--no-banner", "rules", "list"]) == ["rules", "list"]
    # bare value after toggles → NOT a subcommand → unchanged (main scan path)
    assert cli._route_leading_toggles(["--no-color", "octocat"]) == ["--no-color", "octocat"]
    # subcommand already first → unchanged
    assert cli._route_leading_toggles(["doctor"]) == ["doctor"]
    # no leading toggles, value first → unchanged
    assert cli._route_leading_toggles(["github.com"]) == ["github.com"]
