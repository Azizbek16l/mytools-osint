"""Per-module health tracking — last-N runs persisted to a small JSON file.

Powers the k9s-style sparkline column in the modules screen. Storage lives at
``<user_data_dir>/mytools-osint/module_health.json``. The schema is a flat,
human-inspectable JSON document::

    {
      "version": 1,
      "modules": {
        "username": {
          "runs": [
            ["2026-05-23T08:00:00Z", "ok", 342],
            ["2026-05-23T09:14:00Z", "degraded", 17]
          ]
        },
        ...
      }
    }

Each entry is ``[iso_ts_utc, status, hits_count]`` where status ∈
``{"ok", "degraded", "failed"}``. The file is truncated to the last 50 runs
per module on every write so it stays small.

Concurrency: write-replace using ``Path.replace`` so the on-disk view is
always either the previous good blob or the new one — never a half-written
file. Read failures (missing / corrupt) degrade gracefully to an empty store.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from platformdirs import user_data_path
from rich.text import Text

from app.ui import tokens

_MAX_RUNS_PER_MODULE: Final = 50
_SPARK_GLYPHS: Final = "▁▂▃▄▅▆▇█"  # U+2581 .. U+2588
_SCHEMA_VERSION: Final = 1


# --------------------------------------------------------------------------- #
# File path
# --------------------------------------------------------------------------- #

def health_file_path() -> Path:
    """Return the on-disk path used for the module-health store.

    The parent directory is created on demand — safe to call from a cold
    install. Mirrors :func:`app.ui.lookup_input.history_file_path` so both
    persistence layers live under the same data dir.
    """
    base = user_data_path("mytools-osint", "MarsIT")
    base.mkdir(parents=True, exist_ok=True)
    return base / "module_health.json"


# --------------------------------------------------------------------------- #
# Load / save
# --------------------------------------------------------------------------- #

def _empty_store() -> dict[str, Any]:
    return {"version": _SCHEMA_VERSION, "modules": {}}


def _load() -> dict[str, Any]:
    path = health_file_path()
    if not path.exists():
        return _empty_store()
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError):
        return _empty_store()
    if not isinstance(data, dict):
        return _empty_store()
    data.setdefault("version", _SCHEMA_VERSION)
    mods = data.setdefault("modules", {})
    if not isinstance(mods, dict):
        data["modules"] = {}
    return data


def _save(data: dict[str, Any]) -> None:
    path = health_file_path()
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
    tmp.replace(path)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def record_module_run(module: str, status: str, hits_count: int) -> None:
    """Append one entry for ``module`` and trim to the most recent 50.

    * ``module`` — module name as registered with the Runner.
    * ``status`` — one of ``"ok" | "degraded" | "failed"`` (anything else is
      coerced to ``"ok"`` to keep the data minimal).
    * ``hits_count`` — non-negative int; clamped to ``>= 0``.

    Persistence errors are swallowed — health tracking is best-effort and
    must never crash a real run.
    """
    if status not in ("ok", "degraded", "failed"):
        status = "ok"
    hits_count = max(0, int(hits_count))
    ts = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    try:
        data = _load()
        mods = data.setdefault("modules", {})
        entry = mods.setdefault(module, {"runs": []})
        runs = entry.setdefault("runs", [])
        runs.append([ts, status, hits_count])
        # Trim — keep the most recent N.
        if len(runs) > _MAX_RUNS_PER_MODULE:
            entry["runs"] = runs[-_MAX_RUNS_PER_MODULE:]
        _save(data)
    except Exception:
        # never propagate — health is purely cosmetic
        pass


def get_module_history(module: str, limit: int = 7) -> list[tuple[str, str, int]]:
    """Return the last ``limit`` runs for ``module`` in chronological order.

    Each tuple is ``(iso_ts, status, hits_count)``. Missing modules return an
    empty list. Storage corruption returns an empty list too — by design,
    health is a soft signal.
    """
    if limit <= 0:
        return []
    try:
        data = _load()
        runs = (data.get("modules", {}).get(module, {}).get("runs", []) or [])
    except Exception:
        return []
    # Defensive — discard malformed rows.
    out: list[tuple[str, str, int]] = []
    for row in runs[-limit:]:
        if not isinstance(row, list) or len(row) != 3:
            continue
        ts, status, count = row
        if not isinstance(ts, str) or not isinstance(status, str):
            continue
        try:
            count_int = int(count)
        except (TypeError, ValueError):
            continue
        out.append((ts, status, count_int))
    return out


def _spark_glyph_for(value: int, peak: int) -> str:
    """Map ``value`` ∈ [0, peak] to one of :data:`_SPARK_GLYPHS`.

    Zero collapses to the smallest glyph so the strip has a visible baseline
    instead of gaps that change width.
    """
    if peak <= 0:
        return _SPARK_GLYPHS[0]
    idx = min(len(_SPARK_GLYPHS) - 1, int(round(value / peak * (len(_SPARK_GLYPHS) - 1))))
    return _SPARK_GLYPHS[idx]


def render_module_sparkline(module: str, limit: int = 7) -> Text:
    """Render a one-line sparkline + per-day count strip for ``module``.

    Layout::

        12·34·8·22·45·31·9
        ▂▄▁▃█▅▁

    Colour follows the *last* run's status:
      * ``ok``       → :data:`tokens.OK`
      * ``degraded`` → :data:`tokens.WARN`
      * ``failed``   → :data:`tokens.BAD`
      * unknown      → :data:`tokens.DIM`
    """
    history = get_module_history(module, limit=limit)
    if not history:
        return Text("·" * limit, style=tokens.DIM)

    counts = [count for _, _, count in history]
    peak = max(counts) if counts else 0
    last_status = history[-1][1]
    colour = {
        "ok":       tokens.OK,
        "degraded": tokens.WARN,
        "failed":   tokens.BAD,
    }.get(last_status, tokens.DIM)

    nums = "·".join(str(c) for c in counts)
    bars = "".join(_spark_glyph_for(c, peak) for c in counts)

    out = Text()
    out.append(nums, style=tokens.DIM)
    out.append("  ")
    out.append(bars, style=colour)
    return out


__all__ = (
    "health_file_path",
    "record_module_run",
    "get_module_history",
    "render_module_sparkline",
)
