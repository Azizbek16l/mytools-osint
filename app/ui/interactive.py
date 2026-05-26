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
import difflib
import ipaddress
import json
import re
import webbrowser
from collections import Counter
from dataclasses import dataclass
from datetime import datetime

import questionary
from prompt_toolkit.styles import Style as PStyle
from questionary import Choice
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from app.core.config import settings
from app.core.db import Database
from app.core.runner import runner
from app.core.types import Hit, HitStatus, Query, QueryKind
from app.ui import tokens
from app.ui.banner import BRAND
from app.ui.health import record_module_run

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
    # IPv4 / IPv6 first (otherwise IPv6 falls through to USERNAME).
    try:
        ipaddress.ip_address(v.split("/", 1)[0])
        return QueryKind.IP
    except ValueError:
        pass
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


def _print_keybindings(*pairs: tuple[str, str]) -> None:
    """Sticky keybinding hint — used at the bottom of every screen.

    Mirrors lazygit / k9s — a 1-line dim cheatsheet so the user never has to
    leave the screen to remember what `o`, `?`, `/`, `q` mean.
    """
    t = Text("   ")
    for i, (key, label) in enumerate(pairs):
        if i:
            t.append("  ·  ", style=tokens.DIM)
        t.append(key, style=f"bold {tokens.ACCENT}")
        t.append(" " + label, style=tokens.DIM)
    console.print(t)


# ---- Global ? help overlay ------------------------------------------------

_HELP_SCREENS: dict[str, list[tuple[str, str]]] = {
    "main": [
        ("L", "new lookup — single-prompt with auto-detect"),
        ("H", "recent history (last 50)"),
        ("M", "modules — k9s-style table + toggle"),
        ("S", "sites — Sherlock + WhatsMyName breakdown"),
        ("P", "command palette — fuzzy launcher for any action"),
        ("T", "settings — API keys · Telegram · paths"),
        ("I", "this info / help overlay"),
        ("Q", "exit"),
    ],
    "results": [
        ("1-9", "open positive #N directly"),
        ("O", "open positive in browser (picker)"),
        ("E", "export — csv · json · markdown"),
        ("R", "re-run (same query, fresh probes)"),
        ("N", "new lookup"),
        ("M", "main menu"),
        ("Q", "quit"),
    ],
    "modules": [
        ("↵", "toggle enable/disable of highlighted module"),
        ("↑↓", "navigate"),
        ("←", "back to main menu"),
    ],
    "streaming": [
        ("Ctrl+C", "cancel the in-flight run"),
    ],
}


async def show_help(screen: str = "main") -> None:
    """Show a `?`-style cheatsheet overlay for the current screen.

    Used by binding `?` on every menu where it's offered. Renders a rich
    Group with a section per topic.
    """
    bindings = _HELP_SCREENS.get(screen) or _HELP_SCREENS["main"]
    rows = Text("\n")
    rows.append(f"   {tokens.ICON_QUESTION}  help — {screen}\n",
                style=f"bold {tokens.ACCENT}")
    rows.append("   " + ("─" * 60) + "\n", style=tokens.DIM)
    for key, label in bindings:
        rows.append(f"   {key:<8}", style=f"bold {tokens.ACCENT}")
        rows.append(f"  {label}\n", style=tokens.FG)
    rows.append("   " + ("─" * 60) + "\n", style=tokens.DIM)
    rows.append("   Esc / ← always returns one level up\n", style=tokens.DIM)
    console.print(rows)


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


# ---- sparkline + categorisation helpers (from cli.zip design handoff) ------

_SPARK_CHARS = "▁▂▃▄▅▆▇█"


def _sparkline(data: list[int], colour: str | None = None) -> Text:
    """Convert a sequence of ints into a one-line ▁▂▃▅█ sparkline (Rich Text)."""
    if not data:
        return Text("·" * 7, style=tokens.DIM)
    mx = max(data) or 1
    out = Text()
    style = colour or tokens.ACCENT
    for v in data:
        if v == 0:
            out.append("·", style=tokens.DIM)
            continue
        idx = min(len(_SPARK_CHARS) - 1, int(v / mx * (len(_SPARK_CHARS) - 1)))
        out.append(_SPARK_CHARS[idx], style=style)
    return out


# Category mapping for the result summary card.
_CAT_RULES = (
    ("dev / code",     ("github", "gitlab", "bitbucket", "stackoverflow", "askubuntu",
                        "keybase", "hackerone", "bugcrowd", "codeberg", "sourceforge",
                        "replit", "npm", "pypi", "rubygems", "crates", "docker hub",
                        "hashnode", "dev.to", "medium")),
    ("social",         ("twitter", "x.com", "instagram", "tiktok", "snapchat", "pinterest",
                        "threads", "mastodon", "bluesky", "facebook", "linkedin", "tumblr",
                        "vk", "ok.ru", "quora", "disqus", "reddit")),
    ("media / video",  ("youtube", "twitch", "vimeo", "dailymotion", "rumble", "kick",
                        "soundcloud", "spotify", "bandcamp")),
    ("messaging",      ("telegram", "whatsapp", "discord", "skype", "wire", "protonmail")),
    ("breach / leak",  ("hibp", "xposedornot", "hudsonrock", "proxynova", "leakcheck")),
    ("dns / infra",    ("dns:", "crt.sh", "certspotter", "hackertarget", "alienvault",
                        "wayback", "threatminer", "subdomain.center", "rapiddns",
                        "asn", "bgpview", "team cymru")),
    ("tls / security", ("tls", "ssl", ":443", "hsts", "csp", "x-frame", "permissions-policy",
                        "referrer-policy", "x-content-type")),
    ("tech / stack",   ("cloudflare", "fastly", "akamai", "nginx", "apache", "caddy",
                        "vercel", "netlify", "wordpress", "drupal", "joomla",
                        "next.js", "nuxt", "react", "vue", "angular", "svelte")),
    ("dorks",          ("dork:",)),
    ("suggestions",    ("variation:", "username-variation", "email-local-variation")),
)


def _classify(hit: Hit) -> str:
    """Map a Hit to a presentational category for the summary card."""
    haystack = " ".join((hit.module, hit.source, hit.category, hit.title or "")).lower()
    for label, needles in _CAT_RULES:
        if any(n in haystack for n in needles):
            return label
    return "other"


# ---- per-module live progress (derived from the Hit stream) ----------------

@dataclass
class ModProgress:
    """Per-module live counters used by the streaming dashboard.

    ``state`` lifecycle:
      idle      → no hit observed yet
      running   → at least one hit observed
      done      → producer task completed cleanly
      errored   → producer task raised
      ratelimited → producer emitted only RATELIMITED status before finishing

    The derived states (errored / ratelimited) are tagged by the
    ``done`` callback in :func:`run_query`, which inspects hits-by-module
    at the moment the task finishes.
    """

    name: str
    state: str = "idle"
    hits: int = 0           # any Hit kind
    positives: int = 0      # only FOUND
    errors: int = 0
    ratelimited: int = 0
    last_ts: float = 0.0
    # Populated by run_query when the module's task wrapper finishes.
    finished: bool = False


def _update_module_progress(progress: dict[str, ModProgress], hit: Hit,
                            now: float) -> None:
    p = progress.setdefault(hit.module, ModProgress(name=hit.module))
    p.hits += 1
    if hit.status == HitStatus.FOUND:
        p.positives += 1
    elif hit.status == HitStatus.ERROR:
        p.errors += 1
    elif hit.status == HitStatus.RATELIMITED:
        p.ratelimited += 1
    p.last_ts = now
    if not p.finished:
        p.state = "running"


def _render_header(query: Query, done: bool, elapsed_ms: int,
                   n_modules: int = 0) -> Text:
    """Single-line header — Claude Code-style "tool indicator" with elapsed.

    Format::

        ● Scanning   torvalds          [USERNAME] · 6 modules · 18s elapsed

    On completion the spinner switches to ``ICON_OK`` and the label flips to
    ``Scanned``. The elapsed-time formatter keeps the digit count steady
    (``Xs`` up to 60s, then ``Xm Ys``) so the line doesn't reflow as the
    counter advances.
    """
    spin = _spin_char() if not done else tokens.ICON_OK
    label = "Scanned" if done else "Scanning"
    secs = elapsed_ms // 1000
    if secs < 60:
        elapsed = f"{secs}s"
    else:
        elapsed = f"{secs // 60}m {secs % 60}s"
    t = Text()
    t.append(f"  {spin} ", style=f"bold {tokens.ACCENT if not done else tokens.OK}")
    t.append(label, style=f"bold {tokens.FG}")
    t.append("   ")
    t.append(query.value, style="bold")
    t.append("   ")
    t.append(f"[{query.kind.value.upper()}]", style=f"bold {tokens.ACCENT}")
    t.append(f" · {n_modules} modules", style=tokens.DIM)
    t.append(f" · {elapsed} elapsed", style=tokens.DIM)
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


# ---- streaming dashboard (split-pane layout per design handoff) ------------

def _render_modules_rail(progress: dict[str, ModProgress], done: bool) -> Group:
    """Left rail — per-module status + counters. gh-style: no Panel chrome,
    just a bold-dim title and a separator rule above the table.

    Status mapping (Sprint 3 polish):
      ●  running       — accent, spinner
      ✓  done          — ok
      ⚠  ratelimited   — warn (any RATELIMITED hits, finished)
      ✗  errored       — bad (any ERROR hits, finished)
      ○  idle          — dim (no hits yet)
    """
    t = Table.grid(padding=(0, 1))
    t.add_column(width=2, no_wrap=True)
    t.add_column(width=14)
    t.add_column(width=14, no_wrap=True)
    t.add_column(justify="right", width=6)
    if not progress:
        t.add_row("", Text("waiting for modules…", style=tokens.DIM), "", "")
    for name in sorted(progress):
        p = progress[name]
        # Reconcile rolled-up state from `finished` flag + counters.
        if p.finished or done:
            if p.state == "running" or p.state == "idle":
                if p.errors and not p.positives:
                    p.state = "errored"
                elif p.ratelimited and not p.positives:
                    p.state = "ratelimited"
                else:
                    p.state = "done"

        if p.state == "idle":
            sym, colour, status_label = "○", tokens.DIM, "idle"
        elif p.state == "running":
            sym, colour, status_label = _spin_char(), tokens.ACCENT, "running"
        elif p.state == "done":
            sym, colour, status_label = tokens.ICON_OK, tokens.OK, "done"
        elif p.state == "ratelimited":
            sym, colour, status_label = tokens.ICON_WARN, tokens.WARN, "ratelimited"
        elif p.state == "errored":
            sym, colour, status_label = tokens.ICON_BAD, tokens.BAD, "errored"
        else:
            sym, colour, status_label = tokens.ICON_SKIP, tokens.DIM, p.state

        # Right-side badge: "<n> hits" colour-coded; status label dimmed.
        hits_cell = Text(
            f"{p.positives} hits",
            style=f"bold {tokens.OK}" if p.positives else tokens.DIM,
        )
        status_cell = Text(status_label, style=colour)
        t.add_row(
            Text(sym, style=f"bold {colour}"),
            Text(name, style=tokens.FG),
            status_cell,
            hits_cell,
        )
    active = sum(1 for p in progress.values() if p.state == "running")
    done_cnt = sum(
        1 for p in progress.values()
        if p.state in ("done", "errored", "ratelimited")
    )
    header = Text()
    header.append("modules", style=f"bold {tokens.FG}")
    header.append(f"   {active} active · {done_cnt} done", style=tokens.DIM)
    return Group(header, Text("─" * 40, style=tokens.DIM), t)


def _render_hits_feed(hits: list[Hit]) -> Group:
    """Right pane — live positives feed with timestamp prefix + status edge.
    gh / delta style: no Panel chrome, status colour on left rule per row."""
    t = Table.grid(padding=(0, 1), expand=True)
    t.add_column(width=1, no_wrap=True)          # delta-style left edge
    t.add_column(width=12, no_wrap=True)
    t.add_column(width=2, no_wrap=True)
    t.add_column(width=10, no_wrap=True)
    t.add_column(width=22, no_wrap=True)
    t.add_column(ratio=1, overflow="ellipsis", no_wrap=True)

    def _is_actionable(h: Hit) -> bool:
        if (h.category or "") == "summary":
            return False
        if h.status in (HitStatus.UNAVAILABLE, HitStatus.NO_DATA, HitStatus.SKIPPED):
            return False
        return h.status in (HitStatus.FOUND, HitStatus.RATELIMITED) or (
            h.status == HitStatus.NOT_FOUND and (h.category or "").startswith("breach")
        )

    def _edge_colour(status: HitStatus) -> str:
        return {
            HitStatus.FOUND: tokens.OK,
            HitStatus.RATELIMITED: tokens.WARN,
            HitStatus.ERROR: tokens.BAD,
            HitStatus.UNCERTAIN: tokens.WARN,
        }.get(status, tokens.DIM)

    visible = [h for h in hits if _is_actionable(h)]
    for h in visible[-22:]:
        ts = h.found_at.strftime("%H:%M:%S.%f")[:-3] if h.found_at else ""
        # OSC 8 hyperlink wrapping if URL present
        url_render: Text
        if h.url:
            url_render = Text(h.url, style=f"{tokens.ACCENT}")
            url_render.stylize(f"link {h.url}")
        else:
            url_render = Text(h.detail[:120] if h.detail else "", style=tokens.FG)
        t.add_row(
            Text("│", style=_edge_colour(h.status)),
            Text(ts, style=tokens.DIM),
            _status_marker(h.status),
            Text(h.module, style=tokens.DIM),
            Text(h.source[:22], style=tokens.FG),
            url_render,
        )
    if not visible:
        t.add_row("", "", "", "", "", Text("no positives yet …", style=tokens.DIM))
    header = Text()
    header.append("live hits", style=f"bold {tokens.FG}")
    header.append("   positives + rate-limited shown", style=tokens.DIM)
    return Group(header, Text("─" * 60, style=tokens.DIM), t)


def _render_streaming_layout(
    query: Query, hits: list[Hit], progress: dict[str, ModProgress],
    elapsed_ms: int, done: bool,
) -> Layout:
    """Header (1 line) · modules rail | hits feed · footer (1 line)."""
    root = Layout(name="root")
    root.split_column(
        Layout(name="header", size=2),
        Layout(name="body"),
        Layout(name="footer", size=2),
    )
    root["header"].update(_render_header(query, done, elapsed_ms, len(progress)))
    root["body"].split_row(
        Layout(name="rail", size=42),
        Layout(name="feed"),
    )
    root["body"]["rail"].update(_render_modules_rail(progress, done))
    root["body"]["feed"].update(_render_hits_feed(hits))
    root["footer"].update(_render_footer(query, hits, elapsed_ms, done))
    return root


async def run_query(db: Database, query: Query) -> tuple[list[Hit], int]:
    """Run a single query with a live split-pane (modules rail | hits feed).

    Runs in the terminal's **alternate screen buffer** (`screen=True`) — exactly
    like htop / k9s / lazygit. This eliminates the per-frame flicker we get on
    Windows Terminal when Rich redraws panel borders 12 times per second.
    Refresh is throttled to 6 Hz; on exit we transition back to the main screen
    and print a static snapshot so the result remains visible in scrollback.

    Sprint 3 polish: after the run completes, each registered module emits a
    health record (``ok | degraded | failed``) to ``app.ui.health`` so the
    modules screen sparkline reflects real activity, not a placeholder.
    """
    r = runner()
    hits: list[Hit] = []
    progress: dict[str, ModProgress] = {}
    routed = r.modules_for(query.kind)
    for m in routed:
        progress[m.name] = ModProgress(name=m.name, state="idle")
    started = asyncio.get_event_loop().time()

    async def on_hit(h: Hit) -> None:
        hits.append(h)
        _update_module_progress(progress, h, asyncio.get_event_loop().time())

    result = None
    try:
        with Live(
            _render_streaming_layout(query, hits, progress, 0, False),
            console=console,
            refresh_per_second=6,
            screen=True,          # alternate buffer — no flicker
            transient=False,
            vertical_overflow="visible",
            auto_refresh=True,
        ) as live:
            task = asyncio.create_task(r.run(query, on_hit=on_hit))
            try:
                while not task.done():
                    elapsed_ms = int(
                        (asyncio.get_event_loop().time() - started) * 1000,
                    )
                    live.update(_render_streaming_layout(
                        query, hits, progress, elapsed_ms, False,
                    ))
                    try:
                        await asyncio.wait_for(asyncio.shield(task), timeout=0.15)
                    except TimeoutError:
                        continue
            except (KeyboardInterrupt, asyncio.CancelledError):
                task.cancel()
                try:
                    await task
                except Exception:
                    pass
            result = await task
            elapsed_ms = int((asyncio.get_event_loop().time() - started) * 1000)
            for p in progress.values():
                p.finished = True
            live.update(_render_streaming_layout(
                query, hits, progress, elapsed_ms, True,
            ))
            # one final paint inside the alt buffer so the user sees done state
            await asyncio.sleep(0.4)
    except KeyboardInterrupt:
        pass

    elapsed_ms = int((asyncio.get_event_loop().time() - started) * 1000)
    # After the alt-screen Live closes, the main screen is restored — print a
    # static snapshot of the dashboard so the result lives on in scrollback.
    for p in progress.values():
        p.finished = True
    console.print(_render_streaming_layout(query, hits, progress, elapsed_ms, True))

    # Record per-module health entries — best-effort, never fatal.
    for m in routed:
        p = progress.get(m.name) or ModProgress(name=m.name)
        if p.errors and not p.positives:
            status = "failed"
        elif p.ratelimited and not p.positives:
            status = "degraded"
        else:
            status = "ok"
        try:
            record_module_run(m.name, status, p.positives)
        except Exception:
            pass

    if result is not None:
        try:
            await db.save_result(result)
        except Exception:
            pass
    return hits, elapsed_ms


# ---- domain report (3-column rich.Columns) per design handoff -------------

def _render_domain_report(query: Query, hits: list[Hit]) -> Group:
    """Three-column compact report for kind=domain: subdomains · DNS · TLS+headers."""
    from rich.columns import Columns
    subs: list[Hit] = []
    dns_records: list[Hit] = []
    tls: list[Hit] = []
    headers: list[Hit] = []
    tech: list[Hit] = []
    for h in hits:
        if h.status != HitStatus.FOUND:
            continue
        if h.category == "subdomain":
            subs.append(h)
        elif h.category == "dns":
            dns_records.append(h)
        elif h.module == "ssl_tls":
            tls.append(h)
        elif h.module == "http_headers":
            headers.append(h)
        elif h.module == "tech_fingerprint":
            tech.append(h)

    def _panel(title: str, rows: list[str], colour: str = tokens.ACCENT) -> Panel:
        body = Text()
        if not rows:
            body.append("(none)", style=tokens.DIM)
        for r in rows[:14]:
            body.append(r + "\n", style=tokens.FG)
        return Panel(
            body,
            title=Text(title, style=f"bold {colour}"),
            title_align="left",
            border_style=tokens.DIM,
            padding=(0, 1),
            width=42,
        )

    subs_rows = [f"{h.source}" for h in sorted(subs, key=lambda h: h.source)[:14]]
    dns_rows = [f"{h.source}  {h.detail[:32]}" for h in dns_records[:12]]
    tls_rows = []
    for h in tls:
        tls_rows.append(f"{h.source}")
        for chunk in (h.detail or "").split("·"):
            chunk = chunk.strip()
            if chunk:
                tls_rows.append(f"  {chunk[:36]}")
    hdr_rows = []
    summary_hits = [h for h in headers if h.source == "SUMMARY"]
    if summary_hits:
        hdr_rows.append(f"⌖ {summary_hits[0].title}")
    for h in headers:
        if h.source not in ("SUMMARY",) and h.category == "security-header":
            hdr_rows.append(f"{h.source}: {h.detail[:30]}")
    tech_rows = [f"{h.source}" for h in tech if h.source != "stack"][:10]

    cols = Columns([
        _panel("subdomains", subs_rows, tokens.ACCENT),
        _panel("DNS · TLS",
               dns_rows + ([""] + tls_rows if tls_rows else []),
               tokens.OK),
        _panel("headers · tech",
               hdr_rows + ([""] + tech_rows if tech_rows else []),
               tokens.WARN),
    ], padding=(0, 1), expand=False)

    return Group(Text(""), cols, Text(""))


# ---- result summary card (categorised findings + sparkline + actions) -----

def _render_summary_card(query: Query, hits: list[Hit], elapsed_ms: int) -> Group:
    positives = [h for h in hits if h.status == HitStatus.FOUND]

    # Header line
    header = Text("  ")
    header.append(f"{tokens.ICON_OK}  ", style=f"bold {tokens.OK}")
    header.append(query.kind.value + "  ", style=tokens.DIM)
    header.append(query.value, style="bold")
    header.append("   ·   completed in ", style=tokens.DIM)
    header.append(f"{elapsed_ms} ms", style=f"bold {tokens.OK}")
    header.append("   ·   ", style=tokens.DIM)
    header.append(f"{len(positives)}", style=f"bold {tokens.OK}")
    header.append(" / ", style=tokens.DIM)
    header.append(f"{len(hits)}", style=tokens.FG)
    header.append(" positive  ·  arrival ", style=tokens.DIM)

    # Sparkline of positive-arrival distribution across the run
    if positives and elapsed_ms > 0:
        buckets = [0] * 12
        t0 = positives[0].found_at.timestamp() if positives[0].found_at else 0
        span = max(0.001, elapsed_ms / 1000.0)
        for h in positives:
            if h.found_at:
                bucket = min(11, int((h.found_at.timestamp() - t0) / span * 12))
                buckets[bucket] += 1
        header += _sparkline(buckets)

    rule = Text("  " + "▔" * 70, style=tokens.OK if positives else tokens.DIM)

    # Categorise positives
    cat_counts: Counter[str] = Counter()
    cat_examples: dict[str, list[str]] = {}
    for h in positives:
        c = _classify(h)
        cat_counts[c] += 1
        cat_examples.setdefault(c, []).append(h.source)

    cat_table = Table.grid(padding=(0, 2))
    cat_table.add_column(width=18)
    cat_table.add_column(width=5, justify="right")
    cat_table.add_column(width=28)
    cat_table.add_column(ratio=1, overflow="ellipsis", no_wrap=True)
    if cat_counts:
        mx = max(cat_counts.values())
        for cat, n in cat_counts.most_common(8):
            bar = Text("█" * max(1, int(n / mx * 24)), style=tokens.ACCENT)
            examples = ", ".join(cat_examples[cat][:5])
            cat_table.add_row(
                Text(cat, style=f"bold {tokens.FG}"),
                Text(str(n), style=f"bold {tokens.OK}"),
                bar, Text(examples[:60], style=tokens.DIM),
            )
    else:
        cat_table.add_row("", "", "", Text("no positives — try a different query",
                                            style=tokens.DIM))

    # Numbered top-10 positives (so `o<n>` works in after_results_menu)
    pos_table = Table.grid(padding=(0, 2))
    pos_table.add_column(width=4, justify="right")
    pos_table.add_column(width=12)
    pos_table.add_column(width=24)
    pos_table.add_column(ratio=1, overflow="ellipsis", no_wrap=True)
    for i, h in enumerate(positives[:10], start=1):
        url_text = Text(h.url, style=tokens.ACCENT) if h.url else Text(
            h.detail[:90], style=tokens.DIM,
        )
        if h.url:
            url_text.stylize(f"link {h.url}")
        pos_table.add_row(
            Text(f"[{i}]", style=f"bold {tokens.ACCENT}"),
            Text(h.module, style=tokens.DIM),
            Text(h.source[:24], style=f"bold {tokens.FG}"),
            url_text,
        )

    parts = [
        Text(""),
        header,
        rule,
        Text(""),
        Text("   findings by category", style=tokens.DIM),
        Text(""),
        cat_table,
    ]
    if positives:
        hint = Text("   top ", style=tokens.DIM)
        hint.append(str(min(len(positives), 10)), style=f"bold {tokens.FG}")
        hint.append(" positives  ", style=tokens.DIM)
        # k9s-style per-hit hint — single-key actions on a numbered row.
        hint.append("[N]", style=f"bold {tokens.ACCENT}")
        hint.append(" open  ·  ", style=tokens.DIM)
        hint.append("[c]", style=f"bold {tokens.ACCENT}")
        hint.append(" copy  ·  ", style=tokens.DIM)
        hint.append("[a]", style=f"bold {tokens.ACCENT}")
        hint.append(" adjacent", style=tokens.DIM)
        parts += [
            Text(""),
            hint,
            Text(""),
            pos_table,
        ]
    parts += [
        Text(""),
        Text("   ─ what next ─", style=tokens.DIM),
        Text(""),
    ]
    return Group(*parts)


# ---- menu actions -----------------------------------------------------------

async def action_lookup(db: Database, *, kind_override: QueryKind | None = None) -> bool:
    """Single-prompt input with **live kind inference** in the bottom toolbar.

    Beyond the live toolbar (kept verbatim from the original), the prompt now
    offers Claude Code-class ergonomics:

    * fish-shell ghost-text auto-suggestions from a persistent ``FileHistory``
    * Tab completion across slash commands, the seven kinds, and recent history
    * Ctrl-R reverse history search (native prompt_toolkit)
    * inline ``/help`` ``/clear`` ``/history`` … slash command dispatcher
    * comma- or Alt+Enter-separated multi-target burst input

    ``kind_override`` short-circuits auto-detection for a single submission and
    is set by the ``/kind <k>`` slash command.
    """
    from prompt_toolkit import PromptSession
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.formatted_text import FormattedText

    from app.ui.lookup_input import (
        build_completer,
        build_history,
        build_key_bindings,
        dispatch_slash,
        split_multi_target,
        suggest_slash_for_typo,
    )

    console.print()
    hint = Text("   ")
    hint.append("what are you looking for?", style=f"bold {tokens.FG}")
    console.print(hint)
    examples = Text("   ")
    examples.append("examples:  ", style=tokens.DIM)
    for e in ("torvalds", "satya@microsoft.com", "+1 415 555 0143", "@durov", "github.com"):
        examples.append(e, style=tokens.ACCENT)
        examples.append("   ", style=tokens.DIM)
    console.print(examples)
    tips = Text("   ")
    tips.append("tab", style=f"bold {tokens.ACCENT}")
    tips.append(" complete  ·  ", style=tokens.DIM)
    tips.append("→", style=f"bold {tokens.ACCENT}")
    tips.append(" accept ghost text  ·  ", style=tokens.DIM)
    tips.append("Ctrl-R", style=f"bold {tokens.ACCENT}")
    tips.append(" search history  ·  ", style=tokens.DIM)
    tips.append("/help", style=f"bold {tokens.ACCENT}")
    tips.append(" for commands", style=tokens.DIM)
    console.print(tips)
    console.print()

    r = runner()
    history = build_history()

    # PromptSession bottom_toolbar — keep identical to the pre-existing
    # implementation so live kind inference and brand colours don't drift.
    def _toolbar_for(buf_text: str) -> FormattedText:
        v = (buf_text or "").strip()
        if not v:
            return FormattedText([
                ("fg:#6e7681", "  start typing — kind is inferred live"),
            ])
        if v.startswith("/"):
            return FormattedText([
                ("fg:#58a6ff bold", "  /command"),
                ("fg:#6e7681", " — Tab to complete, Enter to run"),
            ])
        kind = kind_override or _auto_kind(v)
        if kind is None:
            return FormattedText([
                ("fg:#d29922", "  AMBIGUOUS"),
                ("fg:#6e7681", " — disambiguator will appear after Enter"),
            ])
        n_modules = len(r.modules_for(kind))
        return FormattedText([
            ("fg:#3fb950 bold", f"  [{kind.value.upper()}]"),
            ("fg:#6e7681", "  routes to "),
            ("fg:#c9d1d9 bold", str(n_modules)),
            ("fg:#6e7681", " module(s)  ·  press "),
            ("fg:#58a6ff bold", "Enter"),
            ("fg:#6e7681", " to probe, "),
            ("fg:#58a6ff bold", "Ctrl-C"),
            ("fg:#6e7681", " to cancel"),
        ])

    session: PromptSession[str] = PromptSession(
        message=FormattedText([("fg:#58a6ff bold", "❯ ")]),
        bottom_toolbar=lambda: _toolbar_for(session.default_buffer.text),
        refresh_interval=0.15,
        history=history,
        auto_suggest=AutoSuggestFromHistory(),
        completer=build_completer(history),
        complete_while_typing=False,   # Tab-only — don't fight the ghost suggestion
        enable_history_search=True,    # binds Ctrl-R natively
        key_bindings=build_key_bindings(),
        multiline=False,
    )
    try:
        value = await session.prompt_async()
    except (KeyboardInterrupt, EOFError):
        return True
    if value is None:
        return True
    value = value.strip()
    if not value:
        return True

    # ---- Slash command branch -------------------------------------------- #
    if value.startswith("/"):
        action = dispatch_slash(value)
        if action.action == "quit":
            return False
        if action.action == "help":
            await show_help("main")
            return await action_lookup(db)
        if action.action == "clear":
            console.clear()
            return await action_lookup(db)
        if action.action == "history":
            await action_history(db)
            return await action_lookup(db)
        if action.action == "modules":
            await action_modules()
            return await action_lookup(db)
        if action.action == "sites":
            await action_stats()
            return await action_lookup(db)
        if action.action == "settings":
            # See above — cmd_wizard internally calls asyncio.run, so we
            # off-load it to a worker thread to avoid loop nesting.
            import asyncio as _asyncio
            from app.ui.config_cli import cmd_wizard
            try:
                await _asyncio.to_thread(cmd_wizard)
            except Exception as e:
                console.print(f"[{tokens.BAD}]settings wizard error:[/] {e}")
            return await action_lookup(db)
        if action.action == "version":
            from app import __version__ as _ver
            console.print(
                f"   [bold {tokens.ACCENT}]mytools-osint[/] "
                f"[{tokens.FG}]v{_ver}[/] [{tokens.DIM}]· by Bluetm.uz[/]",
            )
            return await action_lookup(db)
        if action.action == "kind":
            try:
                kind = QueryKind(action.arg.lower()) if action.arg else None
            except ValueError:
                kind = None
            if kind is None:
                console.print(
                    f"[{tokens.WARN}]usage:[/] /kind <"
                    + "|".join(k.value for k in QueryKind)
                    + ">",
                )
                return await action_lookup(db)
            return await action_lookup(db, kind_override=kind)
        # unknown — print the dispatcher's did-you-mean hint and loop
        if action.message:
            console.print(f"[{tokens.WARN}]{action.message}[/]")
        return await action_lookup(db)

    # ---- Multi-target burst input ---------------------------------------- #
    targets = split_multi_target(value)
    if len(targets) > 1:
        return await _run_multi_target(db, targets, kind_override=kind_override)

    # ---- Single-target path ---------------------------------------------- #
    kind = kind_override or _auto_kind(value)
    if kind is None:
        # Non-slash typo that looks like a slash command? Offer a hint first.
        hinted = suggest_slash_for_typo(value)
        if hinted:
            console.print(
                f"[{tokens.WARN}]no kind inferred[/] — did you mean "
                f"[{tokens.ACCENT}]{hinted}[/]?",
            )
        kind = await questionary.select(
            "could not infer kind — pick one:",
            choices=[Choice(label, value=k) for k, label in KIND_LABELS.items()] +
                    [Choice("← back", value="__BACK__")],
            style=QSTYLE,
        ).ask_async()
        # Treat None, sentinel, or literal label as "back" — questionary
        # version differences make value=None unreliable.
        if kind is None or kind == "__BACK__" or kind == "← back":
            return True
    query = Query(kind=kind, value=value)
    hits, elapsed_ms = await run_query(db, query)
    return await after_results_menu(db, query, hits, elapsed_ms)


async def _run_multi_target(
    db: Database, targets: list[str], *, kind_override: QueryKind | None = None,
) -> bool:
    """Run one query per target sequentially, then print one combined summary.

    Each target gets its own full streaming dashboard via :func:`run_query`;
    after all of them complete we render a small recap table so the user can
    see at a glance which targets yielded the most positives.
    """
    console.print()
    header = Text("   ")
    header.append("burst input", style=f"bold {tokens.ACCENT}")
    header.append(f"   {len(targets)} targets — running sequentially", style=tokens.DIM)
    console.print(header)
    console.print()

    recap: list[tuple[str, str, int, int, int]] = []  # value, kind, found, total, ms
    for idx, target in enumerate(targets, start=1):
        kind = kind_override or _auto_kind(target)
        if kind is None:
            console.print(
                f"[{tokens.WARN}]skipping[/] [{tokens.FG}]{target}[/] "
                f"[{tokens.DIM}](no kind inferred — pass /kind first)[/]",
            )
            recap.append((target, "—", 0, 0, 0))
            continue
        line = Text("   ")
        line.append(f"[{idx}/{len(targets)}] ", style=tokens.DIM)
        line.append(target, style=f"bold {tokens.FG}")
        line.append(f"   ({kind.value})", style=tokens.DIM)
        console.print(line)
        query = Query(kind=kind, value=target)
        hits, elapsed_ms = await run_query(db, query)
        found = sum(1 for h in hits if h.status == HitStatus.FOUND)
        recap.append((target, kind.value, found, len(hits), elapsed_ms))

    # Combined summary table.
    t = Table.grid(padding=(0, 2))
    t.add_column(width=4, justify="right")
    t.add_column(width=30, overflow="ellipsis", no_wrap=True)
    t.add_column(width=10)
    t.add_column(width=10, justify="right")
    t.add_column(width=10, justify="right")
    t.add_column(width=10, justify="right")
    t.add_row(
        Text("#",     style=f"bold {tokens.ACCENT}"),
        Text("TARGET", style=f"bold {tokens.ACCENT}"),
        Text("KIND",   style=f"bold {tokens.ACCENT}"),
        Text("FOUND",  style=f"bold {tokens.ACCENT}"),
        Text("TOTAL",  style=f"bold {tokens.ACCENT}"),
        Text("MS",     style=f"bold {tokens.ACCENT}"),
    )
    for i, (val, knd, found, total, ms) in enumerate(recap, start=1):
        t.add_row(
            Text(str(i), style=tokens.DIM),
            Text(val, style=tokens.FG),
            Text(knd, style=tokens.DIM),
            Text(str(found), style=f"bold {tokens.OK}" if found else tokens.DIM),
            Text(str(total), style=tokens.FG),
            Text(str(ms), style=tokens.DIM),
        )
    console.print()
    console.print(t)
    console.print()
    return True


async def after_results_menu(db: Database, query: Query, hits: list[Hit],
                              elapsed_ms: int) -> bool:
    """Post-run menu with the design summary card, did-you-mean for zero hits,
    and the k9s-style ``[N]/[c]/[a]`` per-hit action sub-menu (Sprint 3)."""
    positives = [h for h in hits if h.status == HitStatus.FOUND]

    # Zero-positive empty-state — render did-you-mean BEFORE the summary card
    # so the suggestion is the first thing the eye lands on.
    suggestions = build_did_you_mean(query, hits) if not positives else []
    if suggestions:
        console.print(_render_did_you_mean(query, len(hits), suggestions))

    # Render the design summary card (categorised findings + sparkline)
    console.print(_render_summary_card(query, hits, elapsed_ms))
    # For domain queries, also render the 3-column condensed report
    if query.kind == QueryKind.DOMAIN and positives:
        console.print(_render_domain_report(query, hits))

    while True:
        # Suggestion shortcut keys ``1/2/3`` are only attached when we have a
        # did-you-mean block — otherwise the same digits are used to open a
        # numbered positive via the per-hit branch.
        sug_choices: list[Choice] = []
        for i, (label, _sug_kind, _sug_val) in enumerate(suggestions, start=1):
            sug_choices.append(Choice(
                f"  try [{i}] — {label}", value=f"sug:{i - 1}",
                shortcut_key=str(i),
            ))

        choice = await questionary.select(
            "what next?",
            choices=[
                *sug_choices,
                Choice(f"  open positive in browser  ·  pick from {len(positives)} URLs",
                       value="open", shortcut_key="o",
                       disabled=None if positives else "no positives"),
                Choice("  per-hit actions  ·  open · copy · adjacent",
                       value="per-hit", shortcut_key="p",
                       disabled=None if positives else "no positives"),
                Choice("  export  ·  csv · json · md",
                       value="export", shortcut_key="e",
                       disabled=None if hits else "nothing to export"),
                Choice("  re-run (refresh)  ·  same query, fresh probes",
                       value="rerun", shortcut_key="r"),
                Choice("  new lookup  ·  back to prompt",
                       value="new",  shortcut_key="n"),
                Choice("  main menu", value="main", shortcut_key="m"),
                Choice("  quit",      value="quit", shortcut_key="q"),
            ],
            style=QSTYLE,
            use_shortcuts=True,
            instruction="(↑↓ or single key)",
        ).ask_async()
        if isinstance(choice, str) and choice.startswith("sug:"):
            idx = int(choice.split(":", 1)[1])
            _label, sug_kind, sug_value = suggestions[idx]
            new_query = Query(kind=sug_kind, value=sug_value)
            hits, elapsed_ms = await run_query(db, new_query)
            return await after_results_menu(db, new_query, hits, elapsed_ms)
        if choice == "open":
            await drill_open(positives)
        elif choice == "per-hit":
            await per_hit_actions(db, positives)
        elif choice == "export":
            await action_export(query, hits)
        elif choice == "rerun":
            hits, elapsed_ms = await run_query(db, query)
            positives = [h for h in hits if h.status == HitStatus.FOUND]
            suggestions = build_did_you_mean(query, hits) if not positives else []
            if suggestions:
                console.print(_render_did_you_mean(query, len(hits), suggestions))
            console.print(_render_summary_card(query, hits, elapsed_ms))
        elif choice == "new":
            return await action_lookup(db)
        elif choice in (None, "main"):
            return True
        elif choice == "quit":
            return False


async def drill_open(positives: list[Hit]) -> None:
    """Numbered picker — [1] [2] [3] etc. Mirrors the indices the summary card shows."""
    if not positives:
        return
    with_url = [h for h in positives if h.url]
    if not with_url:
        console.print(f"[{tokens.WARN}]no positives have URLs to open[/]")
        return
    choices = [
        Choice(f"  [{i}]  {h.source[:22]:22}  {h.detail[:70]}", value=h.url)
        for i, h in enumerate(with_url, start=1)
    ]
    choices.append(Choice("  ← cancel", value=""))
    url = await questionary.select(
        "open which?",
        choices=choices,
        style=QSTYLE,
        instruction="(↑↓ or 1-9)",
    ).ask_async()
    if url:
        try:
            webbrowser.open(url)
            console.print(f"[{tokens.OK}]opened[/] {url}")
        except Exception as e:
            console.print(f"[{tokens.BAD}]failed:[/] {e}")


# --------------------------------------------------------------------------- #
# Per-hit actions — k9s-style single-key sub-menu (Sprint 3, item 2)
# --------------------------------------------------------------------------- #

def _copy_to_clipboard(text: str) -> tuple[bool, str]:
    """Try to copy ``text`` to the OS clipboard via :mod:`pyperclip`.

    Returns ``(True, msg)`` on success. On any failure (module missing, no
    clipboard service on a headless box, OS mechanism refused) returns
    ``(False, "<reason>")`` and the caller falls back to printing the value
    so the user can select+copy manually. ``pyperclip`` is intentionally a
    soft dependency — never added to ``requirements.txt``.
    """
    try:
        import pyperclip  # type: ignore[import-not-found]
    except ImportError:
        return False, "pyperclip not installed"
    try:
        pyperclip.copy(text)
        return True, "copied"
    except Exception as e:  # pyperclip.PyperclipException, etc.
        return False, f"{type(e).__name__}: {e}"


async def per_hit_actions(db: Database, positives: list[Hit]) -> None:
    """Drill into a numbered positive and offer ``o/c/a/b`` single-key actions.

    Steps:
      1. Prompt for the hit index (1..N).
      2. Show a 4-row sub-menu — open, copy, adjacent, back.
      3. Each action returns control to the result-list (caller loops).

    Adjacency uses ``Hit.extra["suggested_kind"]`` + ``Hit.extra["suggested_value"]``
    emitted by Agent A's adjacency module. Missing keys produce a friendly
    "no suggestions" line rather than an error.
    """
    if not positives:
        return
    n = len(positives)
    raw = await questionary.text(
        f"pick a hit number to drill into [1-{n}]:",
        style=QSTYLE,
        instruction="(blank to cancel)",
    ).ask_async()
    if not raw:
        return
    try:
        idx = int(raw.strip()) - 1
    except ValueError:
        console.print(f"[{tokens.WARN}]not a number — '{raw}'[/]")
        return
    if not (0 <= idx < n):
        console.print(f"[{tokens.WARN}]out of range — pick 1..{n}[/]")
        return

    hit = positives[idx]
    summary = Text("   ")
    summary.append(f"[{idx + 1}]", style=f"bold {tokens.ACCENT}")
    summary.append(f"  {hit.source[:24]:24}", style=f"bold {tokens.FG}")
    summary.append("   ")
    summary.append((hit.url or hit.detail)[:80], style=tokens.DIM)
    console.print(summary)

    choice = await questionary.select(
        "action:",
        choices=[
            Choice("  o  open URL in browser", value="o", shortcut_key="o",
                   disabled=None if hit.url else "no URL on this hit"),
            Choice("  c  copy URL to clipboard", value="c", shortcut_key="c",
                   disabled=None if hit.url else "no URL on this hit"),
            Choice("  a  adjacent search (use suggested kind+value)",
                   value="a", shortcut_key="a"),
            Choice("  b  back to result list", value="b", shortcut_key="b"),
        ],
        style=QSTYLE,
        use_shortcuts=True,
        instruction="(single key)",
    ).ask_async()

    if choice == "o" and hit.url:
        try:
            webbrowser.open(hit.url)
            console.print(f"[{tokens.OK}]opened[/] {hit.url}")
        except Exception as e:
            console.print(f"[{tokens.BAD}]failed:[/] {e}")
    elif choice == "c" and hit.url:
        ok, msg = _copy_to_clipboard(hit.url)
        if ok:
            console.print(f"[{tokens.OK}]copied[/]  {hit.url}")
        else:
            console.print(
                f"[{tokens.WARN}]clipboard unavailable ({msg}) — select & copy manually:[/]\n"
                f"   {hit.url}",
            )
    elif choice == "a":
        extra = hit.extra or {}
        sug_kind = extra.get("suggested_kind")
        sug_value = extra.get("suggested_value")
        if not sug_kind or not sug_value:
            console.print(
                f"[{tokens.DIM}]no adjacency suggestions for this source[/]",
            )
            return
        try:
            kind = QueryKind(str(sug_kind))
        except ValueError:
            console.print(
                f"[{tokens.WARN}]adjacent kind unknown: {sug_kind!r}[/]",
            )
            return
        new_query = Query(kind=kind, value=str(sug_value))
        new_hits, ms = await run_query(db, new_query)
        await after_results_menu(db, new_query, new_hits, ms)
    # `b` / None — fall through and return


# --------------------------------------------------------------------------- #
# Did-you-mean for zero-hit results — Sprint 3 item 8
# --------------------------------------------------------------------------- #

_EMAIL_LIKE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_PHONE_LIKE = re.compile(r"^[+0-9 ()\-]{6,}$")
_DOMAIN_LIKE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$",
)


def _history_candidates() -> list[str]:
    """Newest-first deduplicated history values from the persistent FileHistory.

    Returns ``[]`` on any IO failure — did-you-mean is a soft hint, not a
    critical path.
    """
    try:
        from prompt_toolkit.history import FileHistory

        from app.ui.lookup_input import history_file_path
        h = FileHistory(str(history_file_path()))
        seen: set[str] = set()
        out: list[str] = []
        for entry in h.load_history_strings():
            if entry and entry not in seen:
                seen.add(entry)
                out.append(entry)
            if len(out) >= 200:
                break
        return out
    except Exception:
        return []


def build_did_you_mean(
    query: Query, hits: list[Hit],
) -> list[tuple[str, QueryKind, str]]:
    """Return up to 3 ``(label, kind, value)`` suggestions for a zero-hit run.

    Two sources:
      1. **closest historical match** — :func:`difflib.get_close_matches`
         against the user's persisted lookup history (cutoff 0.6).
      2. **type-misclassification** — if the value's shape *looks* like a
         different kind than was used (``@`` → telegram, ``+``/digits →
         phone, ``…@…`` → email, ``.`` → domain), suggest the alternative.

    Pure function — easy to unit-test without spinning up the runner.
    """
    if any(h.status == HitStatus.FOUND for h in hits):
        return []

    value = (query.value or "").strip()
    if not value:
        return []

    suggestions: list[tuple[str, QueryKind, str]] = []

    # Source 1: history fuzzy match (must differ from the current value).
    history = _history_candidates()
    hist_pool = [h for h in history if h != value]
    close = difflib.get_close_matches(value, hist_pool, n=1, cutoff=0.6)
    if close:
        label = f"{close[0]}  (closest match in your history)"
        suggestions.append((label, query.kind, close[0]))

    # Source 2: type-misclassification.
    lower = value.lower()
    if query.kind != QueryKind.EMAIL and _EMAIL_LIKE.match(lower):
        suggestions.append(
            (f"{lower} as email", QueryKind.EMAIL, lower),
        )
    if query.kind != QueryKind.TELEGRAM and value.startswith("@"):
        suggestions.append(
            (f"{value} as Telegram", QueryKind.TELEGRAM, value),
        )
    elif (
        query.kind == QueryKind.USERNAME
        and re.match(r"^[A-Za-z0-9_]{5,32}$", value)
    ):
        suggestions.append(
            (f"@{value} as Telegram", QueryKind.TELEGRAM, f"@{value}"),
        )

    digits = re.sub(r"\D", "", value)
    if (
        query.kind != QueryKind.PHONE
        and _PHONE_LIKE.match(value)
        and 6 <= len(digits) <= 16
        and not _EMAIL_LIKE.match(value)
    ):
        suggestions.append(
            (f"{value} as phone", QueryKind.PHONE, value),
        )

    if (
        query.kind != QueryKind.DOMAIN
        and "." in value
        and _DOMAIN_LIKE.match(value)
    ):
        suggestions.append(
            (f"{value} as domain", QueryKind.DOMAIN, value),
        )

    # Dedupe while preserving order (label, kind, value triples).
    seen: set[tuple[str, str]] = set()
    deduped: list[tuple[str, QueryKind, str]] = []
    for label, kind, val in suggestions:
        key = (kind.value, val)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((label, kind, val))
        if len(deduped) >= 3:
            break
    return deduped


def _render_did_you_mean(
    query: Query, probed: int,
    suggestions: list[tuple[str, QueryKind, str]],
) -> Group:
    """Render the zero-hit empty-state block. Sits ABOVE the summary card."""
    rule_top = Text("   ── no positives " + "─" * 56, style=tokens.DIM)
    line = Text("   ")
    line.append("Probed ", style=tokens.DIM)
    line.append(f"{probed} ", style=f"bold {tokens.FG}")
    line.append("sources for ", style=tokens.DIM)
    line.append(query.kind.value, style=tokens.DIM)
    line.append(" ")
    line.append(f"'{query.value}'", style=f"bold {tokens.FG}")
    line.append(" — nothing found.", style=tokens.DIM)

    intro = Text("   ")
    intro.append("Did you mean to search:", style=f"bold {tokens.FG}")

    rows = Table.grid(padding=(0, 1))
    rows.add_column(width=8)
    rows.add_column()
    for i, (label, _kind, _val) in enumerate(suggestions, start=1):
        rows.add_row(
            Text(f"   ◆ [{i}]", style=f"bold {tokens.ACCENT}"),
            Text(label, style=tokens.FG),
        )

    foot = Text("   ")
    foot.append("Press ", style=tokens.DIM)
    for i in range(1, len(suggestions) + 1):
        foot.append(f"[{i}]", style=f"bold {tokens.ACCENT}")
        if i < len(suggestions):
            foot.append("/", style=tokens.DIM)
    foot.append(" to switch & re-scan, or ", style=tokens.DIM)
    foot.append("[n]", style=f"bold {tokens.ACCENT}")
    foot.append(" for a new query.", style=tokens.DIM)

    return Group(
        Text(""),
        rule_top,
        Text(""),
        line,
        Text(""),
        intro,
        Text(""),
        rows,
        Text(""),
        foot,
        Text(""),
    )


async def action_export(query: Query, hits: list[Hit]) -> None:
    fmt = await questionary.select(
        "format?",
        choices=[
            Choice("csv  (one row per hit)",     value="csv",  shortcut_key="c"),
            Choice("json (full payload)",        value="json", shortcut_key="n"),  # 'j' is vim-nav
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

    # Heatmap header — last 28 days
    try:
        heat = await db.history_heatmap(days=28)
    except Exception:
        heat = []
    if heat:
        header = Text("   ")
        header.append("bluetm·uz", style=f"bold {tokens.ACCENT}")
        header.append("   history  ·  ", style=tokens.DIM)
        header.append(str(len(rows)), style=f"bold {tokens.FG}")
        header.append(" recent  ·  28d:  ", style=tokens.DIM)
        # reverse so oldest is left, today is right
        header += _sparkline(list(reversed(heat)))
        console.print()
        console.print(header)
        console.print()
    choices = []
    for row in rows:
        when = (row.get("started_at") or "").replace("T", " ").split(".")[0]
        choices.append(Choice(
            f"{when}  [{row['kind']:8}] {row['value']:30}  "
            f"found={row['found']:>3}/{row['total']:>3}",
            value=row["id"],
        ))
    choices.append(Choice("← back", value="__BACK__"))
    qid = await questionary.select(
        "recent (pick to view):", choices=choices, style=QSTYLE,
    ).ask_async()
    # Robust back-detection: questionary may return None, the sentinel string,
    # or the literal label depending on the version installed.
    if qid is None or qid == "__BACK__" or qid == "← back" or not isinstance(qid, int):
        return
    q = await db.get_query(qid)
    hits = await db.hits_for(qid)
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
    """k9s-style modules table — interactive: arrow-select to toggle enable/disable."""
    r = runner()
    await _render_modules_table(r)
    # Interactive toggle loop
    _BACK_LABEL = "  ← back to main menu"
    while True:
        mods = r.all_modules()
        # Use a sentinel string ("__BACK__") instead of None so questionary
        # versions that echo the label still let us detect "back".
        choices = []
        for m in mods:
            mark = "●" if m.enabled else "○"
            label = f"  {mark}  {m.name:<18}  {'on' if m.enabled else 'off'}"
            choices.append(Choice(label, value=m.name))
        # Reload + refresh sub-action so users can hot-refresh the table.
        choices.append(Choice("  ↻ refresh health view", value="__REFRESH__"))
        choices.append(Choice("  ⊕ enable all",  value="__ENABLE_ALL__"))
        choices.append(Choice("  ⊖ disable all", value="__DISABLE_ALL__"))
        choices.append(Choice(_BACK_LABEL,       value="__BACK__"))
        pick = await questionary.select(
            "toggle a module:",
            choices=choices,
            style=QSTYLE,
            qmark="",
            instruction="(↵ flip enabled/disabled  ·  ← back)",
        ).ask_async()
        # Robust back-detection: None (ctrl-C), the label string, or our sentinel.
        if pick is None or pick == "__BACK__" or pick == _BACK_LABEL or "back to main" in (pick or ""):
            break
        if pick == "__REFRESH__":
            await _render_modules_table(r)
            continue
        if pick == "__ENABLE_ALL__":
            for m in mods:
                r.set_enabled(m.name, True)
            console.print(f"[{tokens.OK}]✓ enabled all {len(mods)} modules[/]")
            continue
        if pick == "__DISABLE_ALL__":
            for m in mods:
                r.set_enabled(m.name, False)
            console.print(f"[{tokens.WARN}]✓ disabled all {len(mods)} modules[/]")
            continue
        # Toggle and refresh
        target = next((m for m in mods if m.name == pick), None)
        if target:
            r.set_enabled(pick, not target.enabled)
            console.print(
                f"[{tokens.OK if not target.enabled else tokens.WARN}]"
                f"{'enabled' if not target.enabled else 'disabled'}[/]  {pick}"
            )


async def _render_modules_table(r) -> None:
    """Render the k9s-style table (no questionary)."""

    # Header line
    mods = r.all_modules()
    n_active = sum(1 for m in mods if m.enabled)
    header = Text("   ")
    header.append("bluetm·uz", style=f"bold {tokens.ACCENT}")
    header.append("   modules  ·  ", style=tokens.DIM)
    header.append(str(n_active), style=f"bold {tokens.OK}")
    header.append(" active", style=tokens.DIM)
    try:
        from app.modules.username import load_sites
        n_sites = len(load_sites())
        header.append("  ·  ", style=tokens.DIM)
        header.append(f"{n_sites:,}", style=tokens.FG)
        header.append(" probe targets", style=tokens.DIM)
    except Exception:
        pass

    col_widths = (14, 38, 12, 8, 8, 30)
    t = Table.grid(padding=(0, 2))
    for w in col_widths:
        t.add_column(width=w, overflow="ellipsis", no_wrap=True)
    headers = ("NAME", "KINDS", "HEALTH", "STATE", "GLYPH", "7d")
    t.add_row(*[Text(h, style=f"bold {tokens.ACCENT}") for h in headers])
    t.add_row(*[Text("─" * max(2, w - 2), style=tokens.DIM) for w in col_widths])

    from app.ui.health import get_module_history, render_module_sparkline

    for i, m in enumerate(mods):
        kinds = ", ".join(k.value for k in sorted(m.kinds, key=lambda k: k.value))
        history = get_module_history(m.name, limit=7)
        if m.enabled:
            if history and history[-1][1] == "failed":
                health_text, dot, colour = "failed", "●", tokens.BAD
            elif history and history[-1][1] == "degraded":
                health_text, dot, colour = "degraded", "●", tokens.WARN
            elif history:
                health_text, dot, colour = "healthy", "●", tokens.OK
            else:
                health_text, dot, colour = "untested", "○", tokens.DIM
        else:
            health_text, dot, colour = "disabled", "○", tokens.DIM
        state = "ready" if m.enabled else "off"
        glyph = tokens.MODULE_GLYPHS.get(m.name, "") or "—"
        # Real 7-day sparkline from the persisted health store. Falls back to
        # dim dots when the module hasn't been exercised yet.
        spark = render_module_sparkline(m.name, limit=7)
        sel = i == 0
        pfx = "❯ " if sel else "  "
        name_cell = Text(pfx + m.name,
                         style=f"bold {tokens.ACCENT}" if sel else f"bold {tokens.FG}")
        t.add_row(
            name_cell,
            Text(kinds, style=tokens.DIM),
            Text(f"{dot} {health_text}", style=colour),
            Text(state, style=tokens.FG if m.enabled else tokens.DIM),
            Text(glyph, style=tokens.FG),
            spark,
        )

    console.print()
    console.print(header)
    console.print()
    console.print(t)
    console.print()


async def _action_theme_picker() -> None:
    """v4.2 theme switcher — pick from 7 palettes, persist to ~/.config."""
    from app.ui.tokens import THEMES, ACTIVE, persist_theme
    current = ACTIVE.name  # "dark" or "light" — we cross-ref by hex to find name
    current_name = next(
        (k for k, v in THEMES.items() if v.ACCENT == ACTIVE.ACCENT and v.BG_HINT == ACTIVE.BG_HINT),
        "github-dark",
    )
    choices = []
    for name, tk in THEMES.items():
        marker = "●" if name == current_name else "○"
        sample = f"[{tk.ACCENT}]██[/][{tk.OK}]██[/][{tk.WARN}]██[/][{tk.BAD}]██[/]"
        choices.append(Choice(f"  {marker}  {name:<22}  {sample}", value=name))
    choices.append(Choice("  ← back (keep current)", value="__BACK__"))
    pick = await questionary.select(
        "pick a theme (saved to ~/.config/mytools-osint/theme):",
        choices=choices, style=QSTYLE, qmark="",
        instruction="(↑↓ navigate · ↵ apply · ← back)",
    ).ask_async()
    if pick is None or pick == "__BACK__":
        return
    persist_theme(pick)
    console.print(
        f"[{tokens.OK}]✓ theme set to [b]{pick}[/]; "
        f"restart osint (or re-launch shell) to see it everywhere.[/]"
    )


async def _press_enter() -> None:
    """Pause until the user acknowledges — used after read-only screens."""
    try:
        await questionary.text(
            "press Enter to return", style=QSTYLE, qmark="", instruction="",
            default="",
        ).ask_async()
    except Exception:
        pass


async def action_stats() -> None:
    """Sites stats — categorised bar chart per design handoff."""
    from app.modules.username import load_sites
    sites = load_sites()
    cats = Counter((s.get("category") or "uncategorised") for s in sites)
    total = sum(cats.values())

    header = Text("   ")
    header.append("bluetm·uz", style=f"bold {tokens.ACCENT}")
    header.append("   sites  ·  ", style=tokens.DIM)
    header.append(f"{total:,}", style=f"bold {tokens.FG}")
    header.append(" probe targets across ", style=tokens.DIM)
    header.append(str(len(cats)), style=f"bold {tokens.FG}")
    header.append(" categories", style=tokens.DIM)

    t = Table.grid(padding=(0, 2))
    t.add_column(width=22)
    t.add_column(width=6, justify="right")
    t.add_column(width=32)
    t.add_column(ratio=1)
    t.add_row(
        Text("CATEGORY", style=f"bold {tokens.ACCENT}"),
        Text("COUNT", style=f"bold {tokens.ACCENT}"),
        Text("SHARE", style=f"bold {tokens.ACCENT}"),
        Text("", style=tokens.DIM),
    )
    t.add_row(
        Text("─" * 20, style=tokens.DIM),
        Text("──", style=tokens.DIM),
        Text("─" * 30, style=tokens.DIM),
        Text("", style=tokens.DIM),
    )
    mx = max(cats.values()) if cats else 1
    for cat, n in cats.most_common(25):
        pct = n / total * 100 if total else 0
        bar = "█" * max(1, int(n / mx * 28))
        t.add_row(
            Text(cat, style=tokens.FG),
            Text(f"{n}", style=f"bold {tokens.FG}"),
            Text(bar, style=tokens.ACCENT),
            Text(f"{pct:>4.1f}%", style=tokens.DIM),
        )
    console.print()
    console.print(header)
    console.print()
    console.print(t)
    console.print()
    footer = Text("   extend via: ", style=tokens.DIM)
    footer.append("scripts/sync_sherlock.py", style=tokens.ACCENT)
    footer.append("  ·  ", style=tokens.DIM)
    footer.append("scripts/sync_whatsmyname.py", style=tokens.ACCENT)
    console.print(footer)
    console.print()
    await _press_enter()


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

async def run_interactive(show_figlet: bool = False) -> int:
    """Top-level interactive shell. Returns process exit code.

    Cold-start: compact one-line brandmark by default (gh / starship style).
    The full BLUETM.UZ figlet is gated behind --banner — top-tier 2026 CLIs
    (gh, charm, lazygit, btop, starship) all skip the figlet by default; we
    follow suit.
    """
    from app import __version__ as _ver
    if show_figlet:
        from app.ui.banner import ASCII_ART
        console.print(Text(ASCII_ART, style=tokens.ACCENT))

    try:
        from app.modules.username import load_sites
        n_sites = len(load_sites())
    except Exception:
        n_sites = 0
    r = runner()
    n_modules = len(r.all_modules())

    title_line = Text("   ")
    title_line.append("mytools-osint ", style=tokens.FG)
    title_line.append(f"v{_ver} ", style=tokens.DIM)
    title_line.append("— by ", style=tokens.FG)
    title_line.append("Bluetm.uz", style=f"bold {tokens.ACCENT}")
    console.print(title_line)

    status_line = Text("   ")
    status_line.append("●", style=tokens.OK)
    status_line.append(" online ", style=tokens.DIM)
    status_line.append("·", style=tokens.DIM)
    status_line.append(f" {n_sites:,} ", style=tokens.FG)
    status_line.append("sites", style=tokens.DIM)
    status_line.append(" · ", style=tokens.DIM)
    status_line.append(f"{n_modules} ", style=tokens.FG)
    status_line.append("modules", style=tokens.DIM)
    status_line.append(" · ", style=tokens.DIM)
    status_line.append("free APIs", style=tokens.FG)
    status_line.append(" · ", style=tokens.DIM)
    status_line.append("authorised use only", style=tokens.DIM)
    console.print(status_line)
    console.print()

    s = settings()
    db = Database(s.db_path)
    await db.connect()
    try:
        while True:
            # v4.2: single-fire main menu (prompt_toolkit Application). The key
            # fires INSTANTLY — no Enter required, matching lazygit / k9s / btop.
            from app.ui.main_menu import pick_action
            choice = await pick_action()
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
                # cmd_wizard() is sync + internally calls asyncio.run() for
                # the Telegram-status check. Off-load to a thread so its
                # asyncio.run gets its own loop.
                import asyncio as _asyncio
                from app.ui.config_cli import cmd_wizard
                try:
                    await _asyncio.to_thread(cmd_wizard)
                except Exception as e:
                    console.print(f"[{tokens.BAD}]settings wizard error:[/] {e}")
            elif choice == "palette":
                from app.ui.command_palette import build_palette, open_palette

                async def _db_factory():
                    return db
                try:
                    await open_palette(build_palette(_db_factory))
                except Exception as e:
                    console.print(f"[{tokens.BAD}]palette error:[/] {e}")
            elif choice == "help":
                await show_help("main")
                await _press_enter()
            elif choice == "theme":
                await _action_theme_picker()
    except (KeyboardInterrupt, EOFError):
        console.print(f"\n[{tokens.DIM}]bye — {BRAND}[/]\n")
        return 130
    finally:
        await db.close()
