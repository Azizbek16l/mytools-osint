"""Fabric-style externalised report patterns.

A pattern is a single Markdown file with three sections — ``# IDENTITY``,
``# STEPS``, ``# OUTPUT`` — followed by a free-form body that references
``{{var}}`` placeholders. The shape is identical to the Fabric project's
conventions; that makes existing Fabric patterns drop in with no changes.

Why externalise these?
  * Lets analysts edit prompts without touching code (or losing their work on
    every upgrade).
  * Built-ins ship with the package; user overrides live under
    ``~/.config/mytools-osint/patterns/`` and win by name.
  * Substitution is a dumb ``{{var}}`` — keeps the runtime dependency count
    at zero (no jinja, no template engines).

The module is sync on purpose — patterns load once and live in memory.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from app.core.config import APP_NAME

_BUILTIN_DIR = Path(__file__).resolve().parent / "patterns_builtin"


def _user_pattern_dir() -> Path:
    """Per-user pattern directory. Honors ``XDG_CONFIG_HOME``.

    We deliberately use ``~/.config/<app>/patterns/`` on every platform
    (including macOS) — analysts editing patterns live want a path they
    can `cd` to without spelunking Library/Application Support.
    """
    import os
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / APP_NAME / "patterns"


def pattern_dirs() -> tuple[Path, Path]:
    """Return ``(builtin_dir, user_dir)`` for inspection / display."""
    return _BUILTIN_DIR, _user_pattern_dir()


@dataclass(frozen=True, slots=True)
class Pattern:
    """A parsed pattern. Immutable so it's safe to cache."""

    name: str
    source: Path
    identity: str
    steps: str
    output: str
    body: str   # the full file text (for clean re-render)

    def system_block(self) -> str:
        """Return the IDENTITY + STEPS + OUTPUT joined as one system prompt.

        Most providers behave better when role / process / format live in the
        system message and the user message only carries data. Empty if no
        section was parsed (legacy plain-text patterns).
        """
        parts = [s for s in (self.identity, self.steps, self.output) if s.strip()]
        if not parts:
            return ""
        labelled = []
        for label, text in (("IDENTITY", self.identity),
                            ("STEPS", self.steps),
                            ("OUTPUT", self.output)):
            if text.strip():
                labelled.append(f"# {label}\n\n{text.strip()}")
        return "\n\n".join(labelled)

    def render(self, context: dict[str, str]) -> str:
        """Substitute ``{{var}}`` placeholders in the body.

        Unknown placeholders are left untouched — surfacing the literal
        ``{{FOO}}`` is more debuggable than silently swallowing it.
        Whitespace around the variable name is tolerated.
        """
        def _sub(m: re.Match[str]) -> str:
            key = m.group(1).strip()
            return context.get(key, m.group(0))
        return re.sub(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}", _sub, self.body)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

_SECTION_RE = re.compile(r"(?m)^#\s+(IDENTITY|STEPS|OUTPUT)\s*$")


def _split_sections(text: str) -> dict[str, str]:
    """Slice the markdown into the three named sections.

    Anything before the first heading is ignored; anything after the last
    section runs to EOF.
    """
    matches = list(_SECTION_RE.finditer(text))
    if not matches:
        return {}
    out: dict[str, str] = {}
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        out[m.group(1).upper()] = text[start:end].strip()
    return out


def _parse(name: str, path: Path) -> Pattern:
    raw = path.read_text(encoding="utf-8")
    sections = _split_sections(raw)
    return Pattern(
        name=name,
        source=path,
        identity=sections.get("IDENTITY", ""),
        steps=sections.get("STEPS", ""),
        output=sections.get("OUTPUT", ""),
        body=raw,
    )


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def _candidate_paths(name: str) -> list[Path]:
    """User dir wins over built-in. Allow extensions implicitly."""
    user_dir = _user_pattern_dir()
    return [
        user_dir / f"{name}.md",
        user_dir / name,
        _BUILTIN_DIR / f"{name}.md",
        _BUILTIN_DIR / name,
    ]


def load_pattern(name: str) -> Pattern:
    """Resolve a pattern by name. Raises :class:`FileNotFoundError`.

    Name is lower-cased and must be filename-safe — any slash or backslash
    is rejected before hitting disk to keep this trivially path-traversal-proof.
    """
    safe = (name or "").strip().lower()
    if not safe or "/" in safe or "\\" in safe or safe.startswith("."):
        raise FileNotFoundError(f"invalid pattern name: {name!r}")
    for p in _candidate_paths(safe):
        if p.is_file():
            return _parse(safe, p)
    raise FileNotFoundError(
        f"pattern {safe!r} not found (looked in {_user_pattern_dir()} "
        f"and {_BUILTIN_DIR})",
    )


def list_patterns() -> list[str]:
    """Return unique pattern names from built-ins + user dir, sorted.

    Pattern stems are returned (no ``.md`` extension); duplicate names mean
    the user-version wins (and shows up exactly once).
    """
    names: set[str] = set()
    user_dir = _user_pattern_dir()
    for d in (_BUILTIN_DIR, user_dir):
        if not d.is_dir():
            continue
        for f in d.iterdir():
            if f.is_file() and f.suffix.lower() == ".md":
                names.add(f.stem.lower())
    return sorted(names)
