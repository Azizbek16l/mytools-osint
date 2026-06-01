"""Pure rendering layer for the interactive chat shell.

Extracted verbatim from :mod:`app.ui.interactive` so that file can focus on
orchestration (prompt loop, slash dispatch, menus). Everything here is a pure
function of its arguments — it builds Rich renderables (``Text`` / ``Table`` /
``Group`` / ``Layout``) from the Hit stream and never touches ``console``,
``_CHAT_STATE``, ``questionary`` or any other shell state.

Dependency direction is strictly one-way: ``interactive`` imports this module
(and re-exports these names for back-compat — tests + diag scripts reference
``interactive._render_summary_card`` etc.). This module imports only leaves
(``app.ui.tokens``, ``app.core.types``, Rich), so there is no import cycle.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from rich.console import Group, RenderableType
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from app.core.types import Hit, HitStatus, Query
from app.ui import tokens


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

        ● Scanning   temur             [USERNAME] · 6 modules · 18s elapsed

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

    parts: list[RenderableType] = [
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
