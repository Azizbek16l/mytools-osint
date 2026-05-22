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
    name: str
    state: str = "idle"     # idle | running | done
    hits: int = 0           # any Hit kind
    positives: int = 0      # only FOUND
    last_ts: float = 0.0


def _update_module_progress(progress: dict[str, ModProgress], hit: Hit,
                            now: float) -> None:
    p = progress.setdefault(hit.module, ModProgress(name=hit.module))
    p.hits += 1
    if hit.status == HitStatus.FOUND:
        p.positives += 1
    p.last_ts = now
    p.state = "running"


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


# ---- streaming dashboard (split-pane layout per design handoff) ------------

def _render_modules_rail(progress: dict[str, ModProgress], done: bool) -> Panel:
    """Left rail — per-module status + counters."""
    t = Table.grid(padding=(0, 1))
    t.add_column(width=2, no_wrap=True)
    t.add_column(width=14)
    t.add_column(justify="right", width=5)
    if not progress:
        t.add_row("", Text("waiting for modules…", style=tokens.DIM), "")
    for name in sorted(progress):
        p = progress[name]
        if done and p.state == "running":
            p.state = "done"
        if p.state == "idle":
            sym, colour = "○", tokens.DIM
        elif p.state == "running":
            sym, colour = _spin_char(), tokens.ACCENT
        elif p.state == "done":
            sym, colour = tokens.ICON_OK, tokens.OK
        else:
            sym, colour = tokens.ICON_SKIP, tokens.DIM
        cnt = Text(f"{p.positives}", style=f"bold {tokens.OK}" if p.positives else tokens.DIM)
        t.add_row(Text(sym, style=f"bold {colour}"),
                  Text(name, style=tokens.FG), cnt)
    active = sum(1 for p in progress.values() if p.state == "running")
    done_cnt = sum(1 for p in progress.values() if p.state == "done")
    return Panel(
        t,
        title=Text("modules", style=f"bold {tokens.FG}"),
        title_align="left",
        subtitle=Text(f"{active} active · {done_cnt} done", style=tokens.DIM),
        subtitle_align="left",
        border_style=tokens.DIM,
        padding=(0, 1),
    )


def _render_hits_feed(hits: list[Hit]) -> Panel:
    """Right pane — live positives feed with timestamp prefix."""
    t = Table.grid(padding=(0, 1), expand=True)
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

    visible = [h for h in hits if _is_actionable(h)]
    for h in visible[-22:]:
        ts = h.found_at.strftime("%H:%M:%S.%f")[:-3] if h.found_at else ""
        t.add_row(
            Text(ts, style=tokens.DIM),
            _status_marker(h.status),
            Text(h.module, style=tokens.DIM),
            Text(h.source[:22], style=tokens.FG),
            Text(h.detail[:120] if h.detail else (h.url or ""), style=tokens.FG),
        )
    if not visible:
        t.add_row("", "", "", "", Text("no positives yet …", style=tokens.DIM))
    return Panel(
        t,
        title=Text("live hits", style=f"bold {tokens.FG}"),
        subtitle=Text("positives + rate-limited shown", style=tokens.DIM),
        title_align="left",
        subtitle_align="left",
        border_style=tokens.DIM,
        padding=(0, 1),
    )


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
    root["header"].update(_render_header(query, done, elapsed_ms))
    root["body"].split_row(
        Layout(name="rail", size=28),
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
    """
    r = runner()
    hits: list[Hit] = []
    progress: dict[str, ModProgress] = {}
    for m in r.modules_for(query.kind):
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
                p.state = "done"
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
    console.print(_render_streaming_layout(query, hits, progress, elapsed_ms, True))

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

    return Group(
        Text(""),
        header,
        rule,
        Text(""),
        Text("   findings by category", style=tokens.DIM),
        Text(""),
        cat_table,
        Text(""),
        Text("   ─ what next ─", style=tokens.DIM),
        Text(""),
    )


# ---- menu actions -----------------------------------------------------------

async def action_lookup(db: Database) -> bool:
    """Single-prompt input — infer kind from value. Disambiguate only when needed.

    Hint line is printed ABOVE the prompt so the input box is clean.
    """
    console.print()
    hint = Text("   ")
    hint.append("what are you looking for?", style=f"bold {tokens.FG}")
    console.print(hint)
    examples = Text("   ")
    examples.append("examples:  ", style=tokens.DIM)
    examples.append("torvalds", style=tokens.ACCENT)
    examples.append("   ", style=tokens.DIM)
    examples.append("me@example.com", style=tokens.ACCENT)
    examples.append("   ", style=tokens.DIM)
    examples.append("+998948241222", style=tokens.ACCENT)
    examples.append("   ", style=tokens.DIM)
    examples.append("@durov", style=tokens.ACCENT)
    examples.append("   ", style=tokens.DIM)
    examples.append("marsits.uz", style=tokens.ACCENT)
    console.print(examples)
    console.print()
    value = await questionary.text(
        "",
        style=QSTYLE,
        validate=lambda s: True if s.strip() else "cannot be empty",
        qmark="❯",
        instruction="",
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
    # Render the design summary card (categorised findings + sparkline)
    console.print(_render_summary_card(query, hits, elapsed_ms))
    # For domain queries, also render the 3-column condensed report
    if query.kind == QueryKind.DOMAIN and positives:
        console.print(_render_domain_report(query, hits))

    while True:
        choice = await questionary.select(
            "what next?",
            choices=[
                Choice(f"  open positive in browser  ·  pick from {len(positives)} URLs",
                       value="open", shortcut_key="o",
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
        if choice == "open":
            await drill_open(positives)
        elif choice == "export":
            await action_export(query, hits)
        elif choice == "rerun":
            hits, elapsed_ms = await run_query(db, query)
            positives = [h for h in hits if h.status == HitStatus.FOUND]
            console.print(_render_summary_card(query, hits, elapsed_ms))
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
    """k9s-style modules table — interactive: arrow-select to toggle enable/disable."""
    r = runner()
    await _render_modules_table(r)
    # Interactive toggle loop
    while True:
        mods = r.all_modules()
        choices = []
        for m in mods:
            mark = "●" if m.enabled else "○"
            label = f"  {mark}  {m.name:<18}  {'on' if m.enabled else 'off'}"
            choices.append(Choice(label, value=m.name))
        choices.append(Choice("  ← back to main menu", value=None))
        pick = await questionary.select(
            "toggle a module:",
            choices=choices,
            style=QSTYLE,
            qmark="",
            instruction="(↵ flip enabled/disabled  ·  ← back)",
        ).ask_async()
        if pick is None:
            break
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

    t = Table.grid(padding=(0, 2))
    for w in (14, 38, 11, 8, 8, 14):
        t.add_column(width=w, overflow="ellipsis", no_wrap=True)
    headers = ("NAME", "KINDS", "HEALTH", "STATE", "GLYPH", "7d")
    t.add_row(*[Text(h, style=f"bold {tokens.ACCENT}") for h in headers])
    t.add_row(*[Text("─" * max(2, w - 2), style=tokens.DIM) for w in (14, 38, 11, 8, 8, 14)])

    for i, m in enumerate(mods):
        kinds = ", ".join(k.value for k in sorted(m.kinds, key=lambda k: k.value))
        if m.enabled:
            health_text, dot = "healthy", "●"
            colour = tokens.OK
        else:
            health_text, dot = "disabled", "○"
            colour = tokens.DIM
        state = "ready" if m.enabled else "off"
        glyph = tokens.MODULE_GLYPHS.get(m.name, "") or "—"
        # Synthetic placeholder for 7d activity — could be wired to ModuleStats later
        spark = _sparkline([2, 3, 4, 3, 5, 4, 6] if m.enabled else [0] * 7)
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

async def run_interactive() -> int:
    """Top-level interactive shell. Returns process exit code.

    Cold-start: BLUETM.UZ figlet (once) + single status subtitle.
    Each iteration: subtle section header → questionary list (no chrome).
    """
    # Banner figlet ONLY (skip the .render() subtitles to avoid duplicates)
    from app import __version__ as _ver
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
            # Subtle section header (no closing divider — questionary clears its own area)
            header = Text("   ")
            header.append("── ", style=tokens.DIM)
            header.append("main menu", style=f"bold {tokens.FG}")
            header.append(" " + ("─" * 70), style=tokens.DIM)
            console.print(header)
            console.print()
            choice = await questionary.select(
                "",
                choices=[
                    Choice("  [L]  new lookup           single prompt with auto-detect",
                           value="lookup",   shortcut_key="l"),
                    Choice("  [H]  recent history       last 50 queries · resume any",
                           value="history",  shortcut_key="h"),
                    Choice("  [M]  modules              k9s-style table · health · 7d",
                           value="modules",  shortcut_key="m"),
                    Choice("  [S]  sites                Sherlock + WhatsMyName breakdown",
                           value="stats",    shortcut_key="s"),
                    Choice("  [T]  settings             API keys · Telegram · paths",
                           value="settings", shortcut_key="t"),
                    Choice("  [Q]  exit",
                           value="exit",     shortcut_key="q"),
                ],
                style=QSTYLE,
                use_shortcuts=True,
                qmark="",
                instruction="(↑↓ or single key  ·  ↵ select)",
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
                # Open the FULL settings wizard (set/unset/Telegram/edit) — not
                # just a read-only overview. Runs in this loop so it doesn't
                # quit the shell when done.
                from app.ui.config_cli import cmd_wizard
                try:
                    cmd_wizard()
                except Exception as e:
                    console.print(f"[{tokens.BAD}]settings wizard error:[/] {e}")
    except (KeyboardInterrupt, EOFError):
        console.print(f"\n[{tokens.DIM}]bye — {BRAND}[/]\n")
        return 130
    finally:
        await db.close()
