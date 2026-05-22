"""mytools-osint CLI — `osint` command, no Qt dependency.

Examples:
  osint torvalds                         auto-detect kind from value
  osint me@example.com                   email lookup (breach + Holehe + derived)
  osint +998948241222                    phone (libphonenumber + Telegram MTProto)
  osint @durov                           Telegram username via MTProto
  osint marsits.uz                       domain (crt.sh + DNS + HackerTarget + urlscan)
  osint 8.8.8.8                          IP (rDNS + IPinfo)

  osint --kind username torvalds         force kind
  osint torvalds --json --out r.json     machine-readable output
  osint --list-modules                   show registered modules
  osint --list-stats                     show site dataset breakdown
  osint --version
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import io
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from app.core.config import load_settings
from app.core.http import close_client
from app.core.runner import runner
from app.core.types import Hit, HitStatus, Query, QueryKind
from app.ui import tokens
from app.ui.banner import BRAND
from app.ui.banner import render as render_banner

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_PHONE_RE = re.compile(r"^\+?[0-9 ()\-]{6,}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_\-]{2,}$")
_DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$"
)


def infer_kind(value: str) -> QueryKind:
    v = value.strip()
    if _EMAIL_RE.match(v):
        return QueryKind.EMAIL
    digits = re.sub(r"\D", "", v)
    if _PHONE_RE.match(v) and 6 <= len(digits) <= 16:
        return QueryKind.PHONE
    if v.startswith("@"):
        return QueryKind.USERNAME
    if "." in v and _DOMAIN_RE.match(v):
        return QueryKind.DOMAIN
    return QueryKind.USERNAME


# ---- ANSI colour ------------------------------------------------------------

class Style:
    """ANSI 256-colour palette aligned with app/ui/tokens.py.

    Single accent (azure) for brand moments; ok/warn/bad for status.
    Cyan/blue/magenta intentionally absent — reserve for nothing else.
    """

    def __init__(self, enabled: bool) -> None:
        self.on = enabled

    def _w(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.on else text

    def bold(self, t: str) -> str: return self._w("1", t)
    def dim(self, t: str) -> str: return self._w(tokens.ANSI_DIM, t)
    def accent(self, t: str) -> str: return self._w(tokens.ANSI_ACCENT, t)
    def ok(self, t: str) -> str: return self._w(tokens.ANSI_OK, t)
    def warn(self, t: str) -> str: return self._w(tokens.ANSI_WARN, t)
    def bad(self, t: str) -> str: return self._w(tokens.ANSI_BAD, t)
    def fg(self, t: str) -> str: return self._w(tokens.ANSI_FG, t)

    # Legacy aliases — some sites in the codebase still reference these.
    def green(self, t: str) -> str: return self.ok(t)
    def yellow(self, t: str) -> str: return self.warn(t)
    def red(self, t: str) -> str: return self.bad(t)
    def cyan(self, t: str) -> str: return self.accent(t)
    def blue(self, t: str) -> str: return self.accent(t)
    def magenta(self, t: str) -> str: return self.accent(t)


def _color_for(status: HitStatus, st: Style) -> str:
    """Two-char status badge — Nerd Font glyph or ASCII fallback."""
    return {
        HitStatus.FOUND:       st.ok(f"{tokens.ICON_OK} "),
        HitStatus.NOT_FOUND:   st.dim(f"{tokens.ICON_SKIP} "),
        HitStatus.UNCERTAIN:   st.warn(f"{tokens.ICON_QUESTION} "),
        HitStatus.ERROR:       st.bad(f"{tokens.ICON_BAD} "),
        HitStatus.RATELIMITED: st.warn(f"{tokens.ICON_WARN} "),
        HitStatus.SKIPPED:     st.dim(f"{tokens.ICON_SKIP} "),
    }.get(status, "? ")


# ---- boxes ------------------------------------------------------------------

def _box(title: str, rows: list[str], st: Style, sink, *, color="dim") -> None:
    """Generic rounded panel — title row + body rows. All rows pad to box width.

    `color` selects the border colour helper on Style (default: dim chrome).
    """
    def strip_ansi(s: str) -> int:
        return len(re.sub(r"\033\[[0-9;]*m", "", s))

    visible_widths = [strip_ansi(r) for r in rows]
    title_w = strip_ansi(title)
    width = max([title_w, *visible_widths]) + 4
    border_h = "─" * width
    colorize = getattr(st, color, st.dim)
    print(file=sink)
    print(colorize(f"  ╭{border_h}╮"), file=sink)
    pad = " " * (width - title_w)
    print(colorize("  │") + st.bold(f"  {title}") + pad[:-2] + colorize("│"), file=sink)
    print(colorize(f"  ├{border_h}┤"), file=sink)
    for row in rows:
        rpad = " " * (width - strip_ansi(row))
        print(colorize("  │") + row + rpad + colorize("│"), file=sink)
    print(colorize(f"  ╰{border_h}╯"), file=sink)


def _query_header(q: Query, st: Style, sink) -> None:
    """Underline-only header — no full box, less chrome. Matches the designer brief."""
    title = f"{q.kind.value.upper()} · {q.value}"
    print(st.bold(f"  {title}"), file=sink)
    print(st.accent("  " + "▔" * len(title)), file=sink)
    print(file=sink)


def _result_box(result, elapsed_ms: int, st: Style, sink) -> None:
    positives = result.found
    total = result.total
    errs = len(result.errors)
    rates = sum(1 for h in result.hits if h.status == HitStatus.RATELIMITED)
    skipped = sum(1 for h in result.hits if h.status == HitStatus.SKIPPED)
    rows = [
        f"  found       {st.ok(str(positives))} of {total}",
        f"  errors      {st.bad(str(errs))}",
        f"  rate-limit  {st.warn(str(rates))}",
        f"  skipped     {st.dim(str(skipped))}",
        f"  elapsed     {elapsed_ms} ms",
    ]
    _box(f"result — by {BRAND}", rows, st, sink, color="dim")


# ---- info panels ------------------------------------------------------------

def _print_no_arg_panel(st: Style, sink) -> None:
    rows = [
        f"  {st.green('osint <value>')}                          auto-detect kind",
        f"  {st.green('osint --kind email')} me@example.com      explicit kind",
        f"  {st.green('osint torvalds --json --out')} r.json     machine-readable",
        f"  {st.green('osint --list-modules')}                   what's loaded",
        f"  {st.green('osint --list-stats')}                     site dataset breakdown",
        f"  {st.green('osint --version')}                        version + banner",
        "",
        f"  {st.dim('kinds:')}  username · email · phone · telegram · whatsapp · ip · domain",
    ]
    _box(f"osint — by {BRAND}", rows, st, sink, color="cyan")
    print(file=sink)
    print(st.dim("  Try: ") + st.green("osint torvalds") + st.dim("  or  ")
          + st.green("osint --help"), file=sink)


def _print_modules(st: Style, sink) -> None:
    r = runner()
    rows = []
    for m in r.all_modules():
        kinds = ", ".join(k.value for k in sorted(m.kinds, key=lambda k: k.value))
        mark = st.green("●") if m.enabled else st.dim("○")
        rows.append(f"  {mark} {st.bold(m.name):<22}  {st.dim('kinds:')} {kinds}")
    _box(f"MODULES — by {BRAND}", rows, st, sink, color="magenta")


def _print_stats(st: Style, sink) -> None:
    from app.modules.username import load_sites
    sites = load_sites()
    cats = Counter((s.get("category") or "uncategorised") for s in sites)
    total = sum(cats.values())
    top = cats.most_common(20)
    rows = [f"  {st.bold(f'{total:,}')} total username probe targets", ""]
    for cat, n in top:
        bar = "█" * max(1, int(n / max(cats.values()) * 24))
        rows.append(f"  {cat:<24} {st.cyan(bar):<28} {n:>4}")
    rows.append("")
    rows.append(f"  {st.dim('extend via:')} python scripts/sync_sherlock.py | scripts/sync_whatsmyname.py")
    _box(f"SITES — by {BRAND}", rows, st, sink, color="magenta")


# ---- main loop --------------------------------------------------------------

async def _stream_run(q: Query, args: argparse.Namespace, st: Style, sink) -> int:
    r = runner()
    hits: list[Hit] = []

    def visible(h: Hit) -> bool:
        if args.all:
            return True
        return h.status in (HitStatus.FOUND, HitStatus.RATELIMITED) or (
            h.status == HitStatus.NOT_FOUND and (h.category or "").startswith("breach")
        )

    async def on_hit(h: Hit) -> None:
        hits.append(h)
        if args.format == "plain" and visible(h):
            url = h.url or ""
            line = f"  [{_color_for(h.status, st)}] {h.module:14} {h.source:30} {h.detail[:90]}"
            print(line, file=sink, flush=True)
            if url:
                print(f"        {st.blue(url)}", file=sink, flush=True)

    if args.format == "plain":
        _query_header(q, st, sink)

    started = datetime.now()
    result = await r.run(q, on_hit=on_hit)
    elapsed_ms = int((datetime.now() - started).total_seconds() * 1000)

    if args.format == "plain":
        _result_box(result, elapsed_ms, st, sink)
    elif args.format == "json":
        payload = {
            "query": {"kind": q.kind.value, "value": q.value,
                      "started_at": q.started_at.isoformat()},
            "hits": [h.model_dump(mode="json") for h in hits],
            "duration_ms": elapsed_ms,
        }
        json.dump(payload, sink, indent=2, default=str, ensure_ascii=False)
        print(file=sink)
    elif args.format == "csv":
        writer = csv.writer(sink)
        writer.writerow(["module", "source", "category", "status", "title",
                         "detail", "url", "severity", "latency_ms"])
        for h in hits:
            if not args.all and not visible(h):
                continue
            writer.writerow([h.module, h.source, h.category, h.status.value,
                             h.title, h.detail, h.url, h.severity.value, h.latency_ms])

    return 0 if result.found > 0 else 1


def _no_color_requested(args: argparse.Namespace) -> bool:
    if args.no_color:
        return True
    if not sys.stdout.isatty():
        return True
    if os.getenv("NO_COLOR"):
        return True
    return False


class _Formatter(argparse.RawDescriptionHelpFormatter):
    """Slightly wider help with raw description."""

    def __init__(self, *a, **kw) -> None:
        kw.setdefault("max_help_position", 32)
        kw.setdefault("width", 100)
        super().__init__(*a, **kw)


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="osint",
        description=f"mytools-osint — personal OSINT lookups by {BRAND} (free APIs, no paid keys)",
        formatter_class=_Formatter,
        epilog=__doc__.split("Examples:", 1)[1] if __doc__ and "Examples:" in __doc__ else None,
    )
    ap.add_argument("value", nargs="?", help="username, email, +phone, @tg, domain or IP")
    ap.add_argument("--kind", choices=[k.value for k in QueryKind], default=None,
                    help="force the query kind (auto-detect otherwise)")
    ap.add_argument("--all", action="store_true",
                    help="show every probe (default: only positives + rate-limited + breach)")
    ap.add_argument("--format", choices=["plain", "json", "csv"], default="plain",
                    help="output format")
    ap.add_argument("--out", default=None, help="write output to FILE instead of stdout")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    ap.add_argument("--no-banner", action="store_true", help="suppress the startup banner")
    ap.add_argument("--list-modules", action="store_true",
                    help="list all registered OSINT modules and exit")
    ap.add_argument("--list-stats", action="store_true",
                    help="show site dataset breakdown by category and exit")
    ap.add_argument("--version", action="store_true",
                    help="print banner + version and exit")
    ap.add_argument("--interactive", "-i", action="store_true",
                    help="launch the interactive menu shell (default when no value + TTY)")
    return ap


def _handle_config_subcommand(argv: list[str]) -> int:
    """`osint config ...` — dispatched before the main parser so its own arg shape works."""
    from app.ui import config_cli as cc
    sub = argv[0] if argv else ""
    if sub in ("", "wizard", "menu"):
        return cc.cmd_wizard()
    if sub == "show":
        return cc.cmd_show()
    if sub == "edit":
        return cc.cmd_edit()
    if sub == "telegram":
        # `osint config telegram` opens the wizard; `... telegram status` is read-only
        if len(argv) >= 2 and argv[1] == "status":
            return cc.cmd_telegram_status()
        return cc.cmd_telegram_wizard()
    if sub == "set":
        if len(argv) < 3:
            print("usage: osint config set KEY VALUE", file=sys.stderr)
            return 2
        return cc.cmd_set(argv[1], " ".join(argv[2:]))
    if sub == "unset":
        if len(argv) < 2:
            print("usage: osint config unset KEY", file=sys.stderr)
            return 2
        return cc.cmd_unset(argv[1])
    print(f"unknown config subcommand: {sub!r}\n"
          "valid: wizard | show | telegram [status] | set KEY VAL | unset KEY | edit",
          file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    from app import __version__ as _ver
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] == "config":
        return _handle_config_subcommand(raw[1:])

    ap = _build_parser()
    args = ap.parse_args(argv)
    st = Style(enabled=not _no_color_requested(args))

    if args.version:
        print(render_banner(st))
        print(f"  {st.bold('mytools-osint')} v{_ver}")
        return 0

    if args.list_modules:
        if not args.no_banner:
            print(render_banner(st))
        _print_modules(st, sys.stdout)
        return 0

    if args.list_stats:
        if not args.no_banner:
            print(render_banner(st))
        _print_stats(st, sys.stdout)
        return 0

    if args.interactive or (not args.value and sys.stdin.isatty()):
        from app.ui.interactive import run_interactive
        load_settings()
        return asyncio.run(run_interactive())

    if not args.value:
        print(render_banner(st))
        _print_no_arg_panel(st, sys.stdout)
        return 0

    load_settings()
    kind = QueryKind(args.kind) if args.kind else infer_kind(args.value)
    q = Query(kind=kind, value=args.value)

    sink_ctx: io.TextIOBase
    if args.out:
        sink_ctx = open(args.out, "w", encoding="utf-8", newline="")
    else:
        sink_ctx = sys.stdout

    show_banner = (
        args.format == "plain" and not args.no_banner and not args.out
    )
    if show_banner:
        print(render_banner(st), file=sink_ctx, flush=True)

    try:
        try:
            return asyncio.run(_stream_run(q, args, st, sink_ctx))
        finally:
            try:
                asyncio.run(close_client())
            except Exception:
                pass
    finally:
        if args.out:
            sink_ctx.close()


if __name__ == "__main__":
    raise SystemExit(main())
