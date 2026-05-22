"""Interactive CLI shell — arrow-key menus, live streaming, drill-down.

Modelled after Claude Code / lazygit / Vite scaffolders. Launches when:
  - `osint` is invoked with no value AND stdin is a TTY, OR
  - `osint --interactive` / `osint -i` is explicitly requested.

Design (per senior UX + designer review, 2026-05):
  - Big BLUETM.UZ figlet on cold start; single-line compact brandmark thereafter
  - Single-prompt input with live kind inference; only ambiguous → disambiguator
  - Sticky footer during streaming: hits-count, sites-probed, elapsed, shortcuts
  - Rounded boxes only; no double-line BBS chrome
  - Single accent (azure) — palette in app/ui/tokens
"""
from __future__ import annotations

import asyncio
import json
import re
import webbrowser
from collections import Counter
from datetime import datetime

import questionary
from prompt_toolkit.styles import Style as PStyle
from questionary import Choice
from rich.console import Console, Group
from rich.live import Live
from rich.table import Table
from rich.text import Text

from app.core.config import settings
from app.core.db import Database
from app.core.runner import runner
from app.core.types import Hit, HitStatus, Query, QueryKind
from app.ui import tokens
from app.ui.banner import BRAND
from app.ui.banner import render as render_banner

console = Console(highlight=False, force_terminal=tokens.colour_enabled() or None)

# questionary style — single accent
QSTYLE = PStyle([
    ("qmark", f"fg:{tokens.ACCENT} bold"),
    ("question", "bold"),
    ("answer", f"fg:{tokens.OK} bold"),
    ("pointer", f"fg:{tokens.ACCENT} bold"),
    ("highlighted", f"fg:{tokens.ACCENT} bold"),
    ("selected", f"fg:{tokens.OK}"),
    ("separator", f"fg:{tokens.DIM}"),
    ("instruction", f"fg:{tokens.DIM}"),
    ("text", ""),
    ("disabled", f"fg:{tokens.DIM} italic"),
])

KIND_LABELS = {
    QueryKind.USERNAME: f"{tokens.ICON_SEARCH}  username  — social profile enum across 1,000+ sites",
    QueryKind.EMAIL:    f"{tokens.ICON_EMAIL}  email     — breach + Holehe + Gravatar + derived",
    QueryKind.PHONE:    f"{tokens.ICON_PHONE}  phone     — libphonenumber + Telegram MTProto + WhatsApp",
    QueryKind.TELEGRAM: f"{tokens.ICON_TELEGRAM}  telegram  — @username via MTProto + t.me HTML",
    QueryKind.DOMAIN:   f"{tokens.ICON_WEB}  domain    — crt.sh + HackerTarget + urlscan.io + DNS",
    QueryKind.IP:       f"{tokens.ICON_IP}  ip / host — IPinfo + reverse DNS",
}

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_PHONE_RE = re.compile(r"^\+?[0-9 ()\-]{6,}$")
_DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$"
)


def _auto_kind(value: str) -> QueryKind | None:
    """Infer query kind from value. None if ambiguous."""
    v = value.strip()
    if not v:
        return None
    if _EMAIL_RE.match(v):
        return QueryKind.EMAIL
    digits = re.sub(r"\D", "", v)
    if _PHONE_RE.match(v) and 6 <= len(digits) <= 16:
        return QueryKind.PHONE
    if v.startswith("@"):
        return QueryKind.TELEGRAM
    if "." in v and _DOMAIN_RE.match(v):
        return QueryKind.DOMAIN
    if re.match(r"^[A-Za-z0-9_\-]{2,}$", v):
        return QueryKind.USERNAME
    return None  # ambiguous


def _print_compact() -> None:
    """Print the one-line brandmark at the top of every menu screen."""
    brand = f"[bold {tokens.ACCENT}]bluetm·uz[/]"
    rest = f"[{tokens.DIM}]  osint · v{__import__('app').__version__}[/]"
    console.print(f"\n{brand}{rest}")


# ---- live streaming layout --------------------------------------------------

def _status_marker(status: HitStatus) -> Text:
    table = {
        HitStatus.FOUND:       (tokens.ICON_OK,       f"bold {tokens.OK}"),
        HitStatus.NOT_FOUND:   (tokens.ICON_SKIP,     tokens.DIM),
        HitStatus.UNCERTAIN:   (tokens.ICON_QUESTION, tokens.WARN),
        HitStatus.ERROR:       (tokens.ICON_BAD,      tokens.BAD),
        HitStatus.RATELIMITED: (tokens.ICON_WARN,     tokens.WARN),
        HitStatus.UNAVAILABLE: ("~",                  tokens.DIM),
        HitStatus.NO_DATA:     (tokens.ICON_SKIP,     tokens.DIM),
        HitStatus.SKIPPED:     (tokens.ICON_SKIP,     tokens.DIM),
    }
    sym, style = table.get(status, ("?", ""))
    return Text(sym, style=style)


# Spinner frames for "still working" indicator
_SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_spin_idx = 0


def _spin_char() -> str:
    global _spin_idx
    c = _SPIN[_spin_idx % len(_SPIN)]
    _spin_idx += 1
    return c


def _render_header(query: Query, done: bool, elapsed_ms: int) -> Text:
    """Single-line header — kind · value · spinner/done."""
    spin = _spin_char() if not done else tokens.ICON_OK
    t = Text()
    t.append(f"  {spin}  ", style=f"bold {tokens.ACCENT}")
    t.append(query.kind.value, style=tokens.DIM)
    t.append("  ")
    t.append(query.value, style="bold")
    if done:
        t.append(f"   done in {elapsed_ms} ms", style=tokens.OK)
    return t


def _render_body(query: Query, hits: list[Hit]) -> Table:
    t = Table(expand=True, show_lines=False, header_style=f"bold {tokens.ACCENT}",
              border_style=tokens.DIM, box=None, padding=(0, 1))
    t.add_column("", width=3, no_wrap=True)
    t.add_column("module", style=tokens.DIM, width=12)
    t.add_column("source", width=24)
    t.add_column("evidence", overflow="fold")
    t.add_column("url", overflow="ellipsis", max_width=42, style=f"{tokens.ACCENT}")
    def _is_actionable(h: Hit) -> bool:
        if (h.category or "") == "summary":
            return False
        if h.status in (HitStatus.UNAVAILABLE, HitStatus.NO_DATA, HitStatus.SKIPPED):
            return False
        return h.status in (HitStatus.FOUND, HitStatus.RATELIMITED) or (
            h.status == HitStatus.NOT_FOUND and (h.category or "").startswith("breach")
        )

    visible = [h for h in hits if _is_actionable(h)]
    for h in visible[-40:]:
        t.add_row(_status_marker(h.status), h.module, h.source,
                  h.detail[:120], h.url or "")
    if not visible:
        t.add_row("", "", "", f"[{tokens.DIM}]no positives yet …[/]", "")
    return t


def _render_footer(query: Query, hits: list[Hit], elapsed_ms: int, done: bool) -> Text:
    """Single-line footer — state · counters · shortcuts hint."""
    found = sum(1 for h in hits if h.status == HitStatus.FOUND)
    rl = sum(1 for h in hits if h.status == HitStatus.RATELIMITED)
    errs = sum(1 for h in hits if h.status == HitStatus.ERROR)
    total = len(hits)
    t = Text("  ")
    if done:
        t.append("done", style=f"bold {tokens.OK}")
    else:
        t.append(f"{_spin_char()} streaming", style=f"bold {tokens.ACCENT}")
    t.append("   ")
    t.append(str(found), style=f"bold {tokens.OK}")
    t.append(" found")
    t.append(f"   {total} probes", style=tokens.DIM)
    if rl:
        t.append(f"   {rl} rate-limited", style=tokens.WARN)
    if errs:
        t.append(f"   {errs} errors", style=tokens.BAD)
    t.append(f"   {elapsed_ms / 1000:0.1f}s", style=tokens.DIM)
    if not done:
        t.append("   ·   Ctrl+C cancel", style=tokens.DIM)
    return t


# ---- per-run loop -----------------------------------------------------------

def _render_group(query: Query, hits: list[Hit], elapsed_ms: int, done: bool) -> Group:
    return Group(
        _render_header(query, done, elapsed_ms),
        Text(""),  # blank spacer
        _render_body(query, hits),
        Text(""),
        _render_footer(query, hits, elapsed_ms, done),
    )


async def run_query(db: Database, query: Query) -> tuple[list[Hit], int]:
    """Run a single query with a live-updating Rich Group (header + table + footer)."""
    r = runner()
    hits: list[Hit] = []
    started = asyncio.get_event_loop().time()

    async def on_hit(h: Hit) -> None:
        hits.append(h)

    with Live(
        _render_group(query, hits, 0, False),
        console=console, refresh_per_second=10, screen=False, transient=False,
    ) as live:
        task = asyncio.create_task(r.run(query, on_hit=on_hit))
        while not task.done():
            elapsed_ms = int((asyncio.get_event_loop().time() - started) * 1000)
            live.update(_render_group(query, hits, elapsed_ms, False))
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=0.1)
            except TimeoutError:
                continue
        result = await task
        elapsed_ms = int((asyncio.get_event_loop().time() - started) * 1000)
        live.update(_render_group(query, hits, elapsed_ms, True))
    try:
        await db.save_result(result)
    except Exception:
        pass
    return hits, elapsed_ms


# ---- menu actions -----------------------------------------------------------

async def action_lookup(db: Database) -> bool:
    """Single-prompt input — infer kind from value. Disambiguate only when needed."""
    value = await questionary.text(
        "lookup",
        instruction=" (username · email · +phone · @tg · domain · ip — Enter to run, Esc to back)",
        style=QSTYLE,
        validate=lambda s: True if s.strip() else "cannot be empty",
        qmark=">",
    ).ask_async()
    if not value:
        return True
    value = value.strip()
    kind = _auto_kind(value)
    if kind is None:
        # Ambiguous — short disambiguator
        kind = await questionary.select(
            "could not infer kind — pick one:",
            choices=[Choice(label, value=k) for k, label in KIND_LABELS.items()] +
                    [Choice("← back", value=None)],
            style=QSTYLE,
        ).ask_async()
        if kind is None:
            return True
    query = Query(kind=kind, value=value)
    hits, elapsed_ms = await run_query(db, query)
    return await after_results_menu(db, query, hits, elapsed_ms)


async def after_results_menu(db: Database, query: Query, hits: list[Hit],
                              elapsed_ms: int) -> bool:
    positives = [h for h in hits if h.status == HitStatus.FOUND]
    found = len(positives)
    total = len(hits)
    console.print(
        f"\n[bold {tokens.OK}]{found}[/] of {total} positive · "
        f"[{tokens.DIM}]{elapsed_ms} ms[/]\n"
    )
    while True:
        choice = await questionary.select(
            "next?",
            choices=[
                Choice("open a positive URL in browser", value="open", shortcut_key="o",
                       disabled=None if positives else "no positives"),
                Choice("export (csv / json / md)",       value="export", shortcut_key="e",
                       disabled=None if hits else "nothing to export"),
                Choice("new lookup",                      value="new",  shortcut_key="n"),
                Choice("main menu",                       value="main", shortcut_key="m"),
                Choice("quit",                            value="quit", shortcut_key="q"),
            ],
            style=QSTYLE,
            use_shortcuts=True,
            instruction="(↑↓ or o/e/n/m/q)",
        ).ask_async()
        if choice == "open":
            await drill_open(positives)
        elif choice == "export":
            await action_export(query, hits)
        elif choice == "new":
            return await action_lookup(db)
        elif choice in (None, "main"):
            return True
        elif choice == "quit":
            return False


async def drill_open(positives: list[Hit]) -> None:
    if not positives:
        return
    choices = [Choice(f"{h.source[:22]:22}  {h.detail[:70]}", value=h.url or "")
               for h in positives if h.url]
    if not choices:
        console.print(f"[{tokens.WARN}]no positives have URLs to open[/]")
        return
    choices.append(Choice("← cancel", value=""))
    url = await questionary.select(
        "open which?", choices=choices, style=QSTYLE,
    ).ask_async()
    if url:
        try:
            webbrowser.open(url)
            console.print(f"[{tokens.OK}]opened[/] {url}")
        except Exception as e:
            console.print(f"[{tokens.BAD}]failed:[/] {e}")


async def action_export(query: Query, hits: list[Hit]) -> None:
    fmt = await questionary.select(
        "format?",
        choices=[
            Choice("csv  (one row per hit)",     value="csv",  shortcut_key="c"),
            Choice("json (full payload)",        value="json", shortcut_key="j"),
            Choice("md   (positives only)",      value="md",   shortcut_key="m"),
            Choice("← cancel",                   value=""),
        ],
        style=QSTYLE, use_shortcuts=True,
    ).ask_async()
    if not fmt:
        return
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = settings().exports_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_value = re.sub(r"[^A-Za-z0-9_.+@-]", "_", query.value)[:60]
    path = out_dir / f"osint-{query.kind.value}-{safe_value}-{ts}.{fmt}"
    try:
        if fmt == "csv":
            import csv as _csv
            with path.open("w", encoding="utf-8", newline="") as f:
                w = _csv.writer(f)
                w.writerow(["module", "source", "category", "status", "title",
                            "detail", "url", "severity", "latency_ms"])
                for h in hits:
                    w.writerow([h.module, h.source, h.category, h.status.value,
                                h.title, h.detail, h.url, h.severity.value, h.latency_ms])
        elif fmt == "json":
            payload = {
                "query": query.model_dump(mode="json"),
                "hits": [h.model_dump(mode="json") for h in hits],
                "exported_at": datetime.now().isoformat(),
            }
            path.write_text(
                json.dumps(payload, indent=2, default=str, ensure_ascii=False),
                encoding="utf-8",
            )
        else:
            lines = [f"# OSINT report — {query.kind.value}: `{query.value}`", ""]
            lines.append(f"_Generated {datetime.now().isoformat(timespec='seconds')}_  \n")
            pos = [h for h in hits if h.status == HitStatus.FOUND]
            lines.append(f"**{len(pos)} positives / {len(hits)} probes**\n")
            lines.append("## Positives")
            for h in pos:
                lines.append(f"- **{h.source}** — {h.detail}  \n  {h.url}")
            path.write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[{tokens.OK}]saved →[/] [bold]{path}[/]")
    except Exception as e:
        console.print(f"[{tokens.BAD}]export failed:[/] {e}")


async def action_history(db: Database) -> None:
    rows = await db.list_history(50)
    if not rows:
        console.print(f"[{tokens.DIM}]no history yet[/]")
        return
    choices = []
    for row in rows:
        when = (row.get("started_at") or "").replace("T", " ").split(".")[0]
        choices.append(Choice(
            f"{when}  [{row['kind']:8}] {row['value']:30}  "
            f"found={row['found']:>3}/{row['total']:>3}",
            value=row["id"],
        ))
    choices.append(Choice("← back", value=None))
    qid = await questionary.select(
        "recent (pick to view):", choices=choices, style=QSTYLE,
    ).ask_async()
    if not qid:
        return
    q = await db.get_query(int(qid))
    hits = await db.hits_for(int(qid))
    if q is None:
        console.print(f"[{tokens.BAD}]query not found[/]")
        return
    t = Table(title=f"[bold]history #{qid}[/] · {q.kind.value} · {q.value}",
              expand=True, header_style=f"bold {tokens.ACCENT}",
              border_style=tokens.DIM, box=None)
    t.add_column("", width=2)
    t.add_column("module", style=tokens.DIM, width=12)
    t.add_column("source", width=24)
    t.add_column("evidence", overflow="fold")
    t.add_column("url", overflow="ellipsis", max_width=40, style=tokens.ACCENT)
    for h in hits:
        if h.status in (HitStatus.FOUND, HitStatus.RATELIMITED):
            t.add_row(_status_marker(h.status), h.module, h.source,
                      h.detail[:120], h.url or "")
    console.print(t)


async def action_modules() -> None:
    r = runner()
    t = Table(title=f"[bold]modules — by {BRAND}[/]", expand=False,
              border_style=tokens.DIM, header_style=f"bold {tokens.ACCENT}")
    t.add_column("", width=2)
    t.add_column("name", style=f"bold {tokens.ACCENT}")
    t.add_column("handles")
    for m in r.all_modules():
        mark = f"[{tokens.OK}]●[/]" if m.enabled else f"[{tokens.DIM}]○[/]"
        kinds = ", ".join(k.value for k in sorted(m.kinds, key=lambda k: k.value))
        glyph = tokens.MODULE_GLYPHS.get(m.name, "")
        t.add_row(mark, f"{glyph}  {m.name}".strip(), kinds)
    console.print(t)


async def action_stats() -> None:
    from app.modules.username import load_sites
    sites = load_sites()
    cats = Counter((s.get("category") or "uncategorised") for s in sites)
    total = sum(cats.values())
    t = Table(
        title=f"[bold]sites — by {BRAND}[/]  ([{tokens.ACCENT}]{total:,}[/] total)",
        expand=False, border_style=tokens.DIM, header_style=f"bold {tokens.ACCENT}",
    )
    t.add_column("category", style=tokens.FG)
    t.add_column("count", justify="right", style="bold")
    t.add_column("share")
    mx = max(cats.values())
    for cat, n in cats.most_common(25):
        bar = "█" * max(1, int(n / mx * 24))
        t.add_row(cat, str(n), f"[{tokens.ACCENT}]{bar}[/]")
    console.print(t)


async def action_settings_overview() -> None:
    s = settings()
    t = Table(title=f"[bold]settings — by {BRAND}[/]", expand=False,
              border_style=tokens.DIM, header_style=f"bold {tokens.ACCENT}")
    t.add_column("key")
    t.add_column("status")
    rows = [
        ("HIBP",            "set" if s.has_hibp else "not set (free: XposedOrNot, HudsonRock, ProxyNova)"),
        ("Numverify",       "set" if s.has_numverify else "not set (libphonenumber works offline)"),
        ("IPinfo",          "set" if s.has_ipinfo else "not set (rDNS still works)"),
        ("Telegram MTProto","configured" if s.has_telegram else "not set"),
        ("LeakCheck",       "set" if s.has_leakcheck else "not set"),
        ("Concurrency",     str(s.http_concurrency)),
        ("Timeout (sec)",   str(s.http_timeout_sec)),
        ("Data dir",        str(s.data_dir)),
    ]
    for k, v in rows:
        t.add_row(k, v)
    console.print(t)


# ---- main loop --------------------------------------------------------------

async def run_interactive() -> int:
    """Top-level interactive shell. Returns process exit code."""
    # Big banner once, on cold start
    console.print(render_banner())
    s = settings()
    db = Database(s.db_path)
    await db.connect()
    try:
        while True:
            _print_compact()  # one-line brandmark before each prompt
            choice = await questionary.select(
                "main menu",
                choices=[
                    Choice("new lookup  (single-prompt with auto-detect)", value="lookup",
                           shortcut_key="l"),
                    Choice("recent history",                                value="history",
                           shortcut_key="h"),
                    Choice("modules",                                       value="modules",
                           shortcut_key="m"),
                    Choice("sites    (1,000+ probe targets)",              value="stats",
                           shortcut_key="s"),
                    Choice("settings",                                      value="settings",
                           shortcut_key="t"),
                    Choice("exit",                                          value="exit",
                           shortcut_key="q"),
                ],
                style=QSTYLE,
                use_shortcuts=True,
                instruction="(↑↓ or single key · ? help)",
            ).ask_async()
            if choice in (None, "exit"):
                console.print(f"\n[{tokens.DIM}]bye — {BRAND}[/]\n")
                return 0
            if choice == "lookup":
                if not await action_lookup(db):
                    return 0
            elif choice == "history":
                await action_history(db)
            elif choice == "modules":
                await action_modules()
            elif choice == "stats":
                await action_stats()
            elif choice == "settings":
                await action_settings_overview()
    except (KeyboardInterrupt, EOFError):
        console.print(f"\n[{tokens.DIM}]bye — {BRAND}[/]\n")
        return 130
    finally:
        await db.close()
