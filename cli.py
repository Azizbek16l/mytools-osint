"""mytools-osint CLI — `osint` command, no Qt dependency.

Examples:
  osint torvalds                         auto-detect kind from value
  osint satya@microsoft.com              email lookup (breach + Holehe + derived)
  osint +1 415 555 0143                  phone (libphonenumber + Telegram MTProto)
  osint @durov                           Telegram username via MTProto
  osint github.com                       domain (crt.sh + DNS + HackerTarget + urlscan)
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
import ipaddress
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
# md5 = 32, sha1 = 40, sha256 = 64, sha512 = 128. Must be all hex.
_HASH_RE = re.compile(r"^[a-fA-F0-9]+$")


def infer_kind(value: str) -> QueryKind:
    v = value.strip()
    # IPv4 / IPv6 — must be checked BEFORE the domain regex, otherwise an IPv6
    # address falls through to USERNAME (1000-site probe blast) and IPv4 only
    # reaches the IP module by accident via _DOMAIN_RE.
    try:
        ipaddress.ip_address(v.split("/", 1)[0])
        return QueryKind.IP
    except ValueError:
        pass
    if _EMAIL_RE.match(v):
        return QueryKind.EMAIL
    # Hash detection — before phone (a 32-digit hex could look like digits).
    if _HASH_RE.match(v) and len(v) in (32, 40, 64, 128):
        return QueryKind.HASH
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
    """Two-char status badge. ERROR is reserved for true tool bugs; service-side
    outages render dim, never red."""
    return {
        HitStatus.FOUND:       st.ok(f"{tokens.ICON_OK} "),
        HitStatus.NOT_FOUND:   st.dim(f"{tokens.ICON_SKIP} "),
        HitStatus.UNCERTAIN:   st.warn(f"{tokens.ICON_QUESTION} "),
        HitStatus.ERROR:       st.bad(f"{tokens.ICON_BAD} "),         # OUR bug
        HitStatus.RATELIMITED: st.warn(f"{tokens.ICON_WARN} "),
        HitStatus.UNAVAILABLE: st.dim("~ "),                          # upstream down
        HitStatus.NO_DATA:     st.dim(f"{tokens.ICON_SKIP} "),        # empty result
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
    unavail = [h for h in result.hits if h.status == HitStatus.UNAVAILABLE]
    rows = [
        f"  found       {st.ok(str(positives))} of {total}",
        f"  errors      {st.bad(str(errs))}",
        f"  rate-limit  {st.warn(str(rates))}",
        f"  skipped     {st.dim(str(skipped))}",
        f"  elapsed     {elapsed_ms} ms",
    ]
    if unavail:
        names = sorted({h.title or h.source for h in unavail})
        rows.append(f"  upstream    {st.dim(str(len(unavail)))} down ({', '.join(names[:3])}"
                    + (", …" if len(names) > 3 else "") + ")")
    _box(f"result — by {BRAND}", rows, st, sink, color="dim")


# ---- info panels ------------------------------------------------------------

def _print_no_arg_panel(st: Style, sink) -> None:
    rows = [
        f"  {st.green('osint <value>')}                          auto-detect kind",
        f"  {st.green('osint --kind email')} satya@microsoft.com explicit kind",
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
    """k9s-style modules table — NAME · KINDS · HEALTH · STATE · GLYPH · 7d."""
    r = runner()
    mods = r.all_modules()
    n_active = sum(1 for m in mods if m.enabled)
    try:
        from app.modules.username import load_sites
        n_sites = len(load_sites())
    except Exception:
        n_sites = 0

    print(file=sink)
    hdr = (f"   {st.accent(st.bold('bluetm·uz'))}"
           f"{st.dim('   modules  ·  ')}{st.ok(st.bold(str(n_active)))}"
           f"{st.dim(' active  ·  ')}{st.bold(f'{n_sites:,}')}"
           f"{st.dim(' probe targets')}")
    print(hdr, file=sink)
    print(file=sink)

    # column header
    cols = [
        (st.accent(st.bold(f"{'NAME':<14}")), "NAME"),
        (st.accent(st.bold(f"{'KINDS':<38}")), "KINDS"),
        (st.accent(st.bold(f"{'HEALTH':<10}")), "HEALTH"),
        (st.accent(st.bold(f"{'STATE':<6}")), "STATE"),
        (st.accent(st.bold(f"{'GLYPH':<5}")), "GLYPH"),
        (st.accent(st.bold(f"{'7d':<7}")), "7d"),
    ]
    print("   " + "  ".join(c[0] for c in cols), file=sink)
    print("   " + "  ".join(st.dim("─" * max(2, len(c[1]) + 6)) for c in cols), file=sink)

    bars = "▁▂▃▄▅▆▇█"
    fake_spark = [2, 3, 4, 3, 5, 4, 6]
    for m in mods:
        kinds = ", ".join(k.value for k in sorted(m.kinds, key=lambda k: k.value))[:38]
        if m.enabled:
            health = st.ok("● healthy ")
            state = st.fg("ready ")
        else:
            health = st.dim("○ disabled")
            state = st.dim("off   ")
        glyph = tokens.MODULE_GLYPHS.get(m.name, "—")
        mx = max(fake_spark) or 1
        spark = "".join(bars[min(7, int(v / mx * 7))] for v in fake_spark) if m.enabled else "·······"
        spark_styled = st.accent(spark) if m.enabled else st.dim(spark)
        print(f"   {st.bold(m.name):<14}  "
              f"{st.dim(f'{kinds:<38}')}  "
              f"{health:<10}  "
              f"{state:<6}  "
              f"{glyph:<5}  "
              f"{spark_styled:<7}", file=sink)
    print(file=sink)


def _print_stats(st: Style, sink) -> None:
    """Sites bar chart — CATEGORY · COUNT · SHARE columns."""
    from app.modules.username import load_sites
    sites = load_sites()
    cats = Counter((s.get("category") or "uncategorised") for s in sites)
    total = sum(cats.values())
    mx = max(cats.values()) if cats else 1

    print(file=sink)
    hdr = (f"   {st.accent(st.bold('bluetm·uz'))}"
           f"{st.dim('   sites  ·  ')}{st.bold(f'{total:,}')}"
           f"{st.dim(' probe targets across ')}{st.bold(str(len(cats)))}"
           f"{st.dim(' categories')}")
    print(hdr, file=sink)
    print(file=sink)

    cat_lbl = f"{'CATEGORY':<22}"
    cnt_lbl = f"{'COUNT':>6}"
    shr_lbl = f"{'SHARE':<30}"
    print(f"   {st.accent(st.bold(cat_lbl))}"
          f"{st.accent(st.bold(cnt_lbl))}  "
          f"{st.accent(st.bold(shr_lbl))}", file=sink)
    print(f"   {st.dim('─' * 20)}    {st.dim('──')}  {st.dim('─' * 28)}", file=sink)

    for cat, n in cats.most_common(25):
        pct = n / total * 100 if total else 0
        bar = "█" * max(1, int(n / mx * 28))
        print(f"   {cat:<22}{st.bold(str(n)):>6}  "
              f"{st.accent(bar):<30}  {st.dim(f'{pct:>4.1f}%')}", file=sink)
    print(file=sink)
    print(f"   {st.dim('extend via:')} "
          f"{st.accent('scripts/sync_sherlock.py')} "
          f"{st.dim('·')} "
          f"{st.accent('scripts/sync_whatsmyname.py')}", file=sink)
    print(file=sink)


# ---- main loop --------------------------------------------------------------

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _hit_meets_severity(h: Hit, threshold: str | None) -> bool:
    if not threshold:
        return True
    return _SEV_RANK.get(h.severity.value, 0) >= _SEV_RANK.get(threshold, 0)


def _hit_to_jsonl(h: Hit, q: Query) -> str:
    payload = {
        "ts": h.found_at.isoformat() if h.found_at else None,
        "kind": q.kind.value,
        "target": q.value,
        "module": h.module,
        "source": h.source,
        "category": h.category,
        "status": h.status.value,
        "severity": h.severity.value,
        "title": h.title,
        "detail": h.detail,
        "url": h.url,
        "latency_ms": h.latency_ms,
        "extra": h.extra,
    }
    return json.dumps(payload, default=str, ensure_ascii=False)


async def _stream_run(q: Query, args: argparse.Namespace, st: Style, sink) -> int:
    r = runner()
    hits: list[Hit] = []
    min_sev = getattr(args, "min_severity", None)

    def visible(h: Hit) -> bool:
        if not _hit_meets_severity(h, min_sev):
            return False
        if args.debug:
            return True                                       # show everything
        if args.all:
            return h.status not in (HitStatus.NO_DATA,)       # all but truly-empty
        if (h.category or "") == "summary":
            return False                                      # quiet by default
        if h.status in (HitStatus.UNAVAILABLE, HitStatus.NO_DATA, HitStatus.SKIPPED):
            return False                                      # silent non-actionables
        return h.status in (HitStatus.FOUND, HitStatus.RATELIMITED) or (
            h.status == HitStatus.NOT_FOUND and (h.category or "").startswith("breach")
        )

    async def on_hit(h: Hit) -> None:
        hits.append(h)
        if args.format == "plain" and visible(h):
            url = h.url or ""
            sev_badge = ""
            if h.severity.value in ("high", "critical"):
                sev_badge = st.bad(f"[{h.severity.value.upper()}] ")
            elif h.severity.value == "medium":
                sev_badge = st.warn("[MED] ")
            line = (f"  [{_color_for(h.status, st)}] {h.module:14} "
                    f"{h.source:30} {sev_badge}{h.detail[:90]}")
            print(line, file=sink, flush=True)
            if url:
                print(f"        {st.blue(url)}", file=sink, flush=True)
        elif args.format == "jsonl":
            if visible(h):
                print(_hit_to_jsonl(h, q), file=sink, flush=True)

    if args.format == "plain":
        _query_header(q, st, sink)

    started = datetime.now()
    result = await r.run(q, on_hit=on_hit)
    elapsed_ms = int((datetime.now() - started).total_seconds() * 1000)

    if args.format == "plain":
        _result_box(result, elapsed_ms, st, sink)
    elif args.format == "json":
        from app.core.json_schema import serialize_query_result
        json.dump(serialize_query_result(result), sink, indent=2,
                  default=str, ensure_ascii=False)
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

    # If --html, write a report regardless of stream format.
    if getattr(args, "html", None):
        try:
            from app.ui.html_report import render_report
            html = render_report(q, result, elapsed_ms)
            await asyncio.to_thread(Path(args.html).write_text, html,
                                    encoding="utf-8")
            print(st.dim(f"  html report → {args.html}"), file=sys.stderr)
        except Exception as e:
            print(st.bad(f"  html report failed: {e}"), file=sys.stderr)

    if getattr(args, "md", None):
        try:
            from app.ui.md_report import render_markdown
            md = render_markdown(q, result, elapsed_ms)
            await asyncio.to_thread(Path(args.md).write_text, md, encoding="utf-8")
            print(st.dim(f"  markdown report → {args.md}"), file=sys.stderr)
        except Exception as e:
            print(st.bad(f"  markdown report failed: {e}"), file=sys.stderr)

    return 0 if result.found > 0 else 1


def _run_bulk(args: argparse.Namespace, st: Style) -> int:
    """Sequential bulk mode — one target per line in args.bulk file.

    Output is jsonl by default (machine-readable, easy to grep into).
    Switches to plain if --bulk-format=plain.

    Profile/enable/disable apply to every target. A failing target never
    aborts the loop; it gets one '{...,"error":...}' jsonl line.
    """
    targets: list[str] = []
    src = Path(args.bulk)
    if not src.exists():
        print(st.bad(f"  bulk file not found: {args.bulk}"), file=sys.stderr)
        return 2
    for raw in src.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    if not targets:
        print(st.bad("  bulk file is empty"), file=sys.stderr)
        return 2

    load_settings()
    r = runner()
    if args.profile:
        from app.core.profiles import apply_profile
        try:
            apply_profile(r, args.profile)
        except ValueError as e:
            print(st.bad(f"  {e}"), file=sys.stderr); return 2
    for m in args.enable:
        r.set_enabled(m, True)
    for m in args.disable:
        r.set_enabled(m, False)

    sink = sys.stdout
    if args.out:
        sink = open(args.out, "w", encoding="utf-8", newline="")

    async def _one(target: str) -> int:
        kind = QueryKind(args.kind) if args.kind else infer_kind(target)
        q = Query(kind=kind, value=target)
        # Force jsonl per-hit output for bulk plain too — keeps it grep-able.
        local_args = argparse.Namespace(**vars(args))
        local_args.format = "plain" if args.bulk_format == "plain" else "jsonl"
        local_args.html = None
        local_args.tui = False
        if args.bulk_format == "plain":
            print(st.dim(f"\n  ─── {kind.value}: {target} ───"), file=sink, flush=True)
        try:
            return await _stream_run(q, local_args, st, sink)
        except Exception as e:
            print(json.dumps({"target": target, "error": f"{type(e).__name__}: {e}"}),
                  file=sink, flush=True)
            return 1

    try:
        try:
            n_found = 0
            for t in targets:
                rc = asyncio.run(_one(t))
                if rc == 0:
                    n_found += 1
            print(st.dim(f"\n  bulk done: {n_found}/{len(targets)} with positives"),
                  file=sys.stderr)
            return 0 if n_found else 1
        finally:
            try:
                asyncio.run(close_client())
            except Exception:
                pass
    finally:
        if args.out:
            sink.close()


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
    ap.add_argument("--format", choices=["plain", "json", "jsonl", "csv"], default="plain",
                    help="output format (jsonl = one Hit per line, ideal for piping)")
    ap.add_argument("--out", default=None, help="write output to FILE instead of stdout")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    ap.add_argument("--no-banner", action="store_true", help="suppress the startup banner")
    ap.add_argument("--list-modules", action="store_true",
                    help="list all registered OSINT modules and exit")
    ap.add_argument("--list-stats", action="store_true",
                    help="show site dataset breakdown by category and exit")
    ap.add_argument("--list-profiles", action="store_true",
                    help="list available --profile presets and exit")
    ap.add_argument("--version", action="store_true",
                    help="print banner + version and exit")
    ap.add_argument("--interactive", "-i", action="store_true",
                    help="launch the interactive menu shell (default when no value + TTY)")
    ap.add_argument("--debug", action="store_true",
                    help="show per-source diagnostics, summaries, and upstream outages")
    ap.add_argument("--per-source", action="store_true",
                    help="emit one Hit per (subdomain, source) instead of deduplicated rows")
    ap.add_argument("--banner", action="store_true",
                    help="show the full BLUETM.UZ figlet banner (default: compact one-liner)")
    # --- red-team additions ---------------------------------------------
    ap.add_argument("--profile",
                    help="module preset: quick | deep | person | domain-recon | "
                         "red-team | blue-team | ioc (default: all enabled)")
    ap.add_argument("--enable", action="append", default=[], metavar="MOD",
                    help="force-enable a specific module (repeatable)")
    ap.add_argument("--disable", action="append", default=[], metavar="MOD",
                    help="force-disable a specific module (repeatable)")
    ap.add_argument("--min-severity", default=None,
                    choices=["info", "low", "medium", "high", "critical"],
                    help="only surface hits at or above this severity")
    ap.add_argument("--bulk", default=None, metavar="FILE",
                    help="read targets from FILE (one per line, '#' = comment); "
                         "run them sequentially")
    ap.add_argument("--bulk-format", choices=["plain", "jsonl"], default="jsonl",
                    help="output format when --bulk is set (default: jsonl)")
    ap.add_argument("--opsec", action="store_true",
                    help="route HTTP via SOCKS5 (TOR_SOCKS env or 127.0.0.1:9050), "
                         "add jitter, force-randomize UA")
    ap.add_argument("--tui", action="store_true",
                    help="launch the live Textual dashboard for this query")
    ap.add_argument("--html", default=None, metavar="FILE",
                    help="write a self-contained HTML report to FILE")
    ap.add_argument("--md", default=None, metavar="FILE",
                    help="write a Markdown report (great for GitHub issues / Notion)")
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


def _handle_mcp_subcommand(argv: list[str]) -> int:
    """`osint mcp` — start the Model Context Protocol server over stdio.

    Used by Claude Code, Warp Agents, Cursor and other MCP-aware clients.
    Stdout is reserved for the MCP transport — diagnostics go to stderr.
    """
    if argv and argv[0] in {"-h", "--help"}:
        print(
            "usage: osint mcp\n\n"
            "Start the mytools-osint MCP server over stdio. Wire it into\n"
            "your AI agent's config (see agent/mcp.json for an example).",
            file=sys.stderr,
        )
        return 0
    load_settings()
    from app.mcp.server import main as _mcp_main
    return _mcp_main()


def _handle_watch_subcommand(argv: list[str]) -> int:
    """`osint watch ...` — Sprint 3 watchlist + Telegram notifier dispatcher."""
    usage = (
        "usage:\n"
        "  osint watch add <kind> <value> [--label NAME] [--every HOURS]\n"
        "  osint watch list [--due]\n"
        "  osint watch remove <id|label>\n"
        "  osint watch enable <id>\n"
        "  osint watch disable <id>\n"
        "  osint watch run [--all]\n"
    )
    sub = argv[0] if argv else ""
    if sub in ("", "-h", "--help"):
        print(usage, file=sys.stderr)
        return 0 if sub else 2

    from app.core.config import settings
    from app.core.db import Database
    from app.features import notify, watchlist

    async def _run() -> int:
        load_settings()
        db = Database(settings().db_path)
        await db.connect()
        try:
            if sub == "add":
                rest = argv[1:]
                label: str | None = None
                every = 24
                pos: list[str] = []
                i = 0
                while i < len(rest):
                    tok = rest[i]
                    if tok == "--label" and i + 1 < len(rest):
                        label = rest[i + 1]; i += 2; continue
                    if tok == "--every" and i + 1 < len(rest):
                        try:
                            every = int(rest[i + 1])
                        except ValueError:
                            print("--every needs an integer (hours)", file=sys.stderr); return 2
                        i += 2; continue
                    pos.append(tok); i += 1
                if len(pos) < 2:
                    print("usage: osint watch add <kind> <value> [--label NAME] [--every HOURS]",
                          file=sys.stderr)
                    return 2
                try:
                    entry = await watchlist.add(db, pos[0], pos[1], label=label, interval_h=every)
                except ValueError as e:
                    print(f"error: {e}", file=sys.stderr); return 2
                print(f"  + watching #{entry.id} [{entry.kind}] {entry.value}"
                      f"  (every {entry.interval_h}h"
                      f"{', label=' + entry.label if entry.label else ''})")
                return 0
            if sub == "list":
                only_due = "--due" in argv[1:]
                rows = await watchlist.list_all(db, only_due=only_due)
                if not rows:
                    print("  (no watchlist entries)"
                          + ("" if not only_due else " — none are due"))
                    return 0
                print(f"  {len(rows)} watch entr{'y' if len(rows) == 1 else 'ies'}:")
                for e in rows:
                    flag = "  " if e.enabled else "× "
                    label = f" [{e.label}]" if e.label else ""
                    last = e.last_run_at.isoformat(timespec="minutes") if e.last_run_at else "never"
                    print(f"  {flag}#{e.id:<3} [{e.kind:8}] {e.value:<32}{label}"
                          f"  every {e.interval_h}h  last={last}")
                return 0
            if sub == "remove":
                if len(argv) < 2:
                    print("usage: osint watch remove <id|label>", file=sys.stderr); return 2
                tgt: int | str = argv[1]
                if isinstance(tgt, str) and tgt.isdigit():
                    tgt = int(tgt)
                ok = await watchlist.remove(db, tgt)
                print("  - removed" if ok else "  not found")
                return 0 if ok else 1
            if sub in ("enable", "disable"):
                if len(argv) < 2 or not argv[1].isdigit():
                    print(f"usage: osint watch {sub} <id>", file=sys.stderr); return 2
                action = watchlist.enable if sub == "enable" else watchlist.disable
                await action(db, int(argv[1]))
                print(f"  {sub}d #{argv[1]}")
                return 0
            if sub == "run":
                force_all = "--all" in argv[1:]
                from app.core.db import Database as _Db  # noqa: F401
                from app.core.runner import runner as _runner

                async def on_new(entry, hits):
                    msg = notify.format_watchlist_message(entry.value, hits)
                    ok = await notify.send_to_self(msg)
                    badge = "→ telegram" if ok else "→ log (telegram unreachable)"
                    print(f"  • {entry.value}  {len(hits)} new  {badge}")

                results = await watchlist.run_due(
                    db, _runner(), on_new_finding=on_new, force_all=force_all
                )
                if not results:
                    print("  (no new findings)")
                return 0
            print(usage, file=sys.stderr); return 2
        finally:
            await db.close()
            try:
                await close_client()
            except Exception:
                pass

    return asyncio.run(_run())


def _handle_diff_subcommand(argv: list[str]) -> int:
    """`osint diff <kind> <value> [--from ID] [--to ID]` — compare two historical scans."""
    usage = "usage: osint diff <kind> <value> [--from ID] [--to ID]"
    if not argv or argv[0] in ("-h", "--help") or len(argv) < 2:
        print(usage, file=sys.stderr)
        return 0 if argv and argv[0] in ("-h", "--help") else 2

    kind, value = argv[0], argv[1]
    from_id: int | None = None
    to_id: int | None = None
    i = 2
    while i < len(argv):
        if argv[i] == "--from" and i + 1 < len(argv):
            from_id = int(argv[i + 1]); i += 2; continue
        if argv[i] == "--to" and i + 1 < len(argv):
            to_id = int(argv[i + 1]); i += 2; continue
        print(f"unknown arg: {argv[i]}\n{usage}", file=sys.stderr); return 2

    from rich.console import Console as _RC

    from app.core.config import settings
    from app.core.db import Database
    from app.core.types import QueryResult
    from app.features import diff as diff_mod

    async def _run() -> int:
        load_settings()
        db = Database(settings().db_path)
        await db.connect()
        try:
            try:
                QueryKind(kind)
            except ValueError:
                print(f"unknown kind {kind!r}; expected one of "
                      f"{', '.join(k.value for k in QueryKind)}", file=sys.stderr); return 2
            if from_id is None or to_id is None:
                ids = await db.find_queries_for_value(kind, value, limit=10)
                if len(ids) < 2:
                    print(f"  need ≥2 prior scans of [{kind}] {value} — found {len(ids)}",
                          file=sys.stderr); return 1
                resolved_from = from_id if from_id is not None else ids[1]
                resolved_to = to_id if to_id is not None else ids[0]
            else:
                resolved_from, resolved_to = from_id, to_id

            old_q = await db.get_query(resolved_from)
            new_q = await db.get_query(resolved_to)
            if old_q is None or new_q is None:
                print(f"  query id not found (from={resolved_from} to={resolved_to})",
                      file=sys.stderr); return 1
            old_hits = await db.hits_for(resolved_from)
            new_hits = await db.hits_for(resolved_to)
            old_res = QueryResult(query=old_q, hits=old_hits, total=len(old_hits),
                                  found=sum(1 for h in old_hits if h.status == HitStatus.FOUND))
            new_res = QueryResult(query=new_q, hits=new_hits, total=len(new_hits),
                                  found=sum(1 for h in new_hits if h.status == HitStatus.FOUND))
            diff_mod.render_diff(new_q, old_res, new_res, _RC())
            return 0
        finally:
            await db.close()

    return asyncio.run(_run())


def main(argv: list[str] | None = None) -> int:
    if sys.platform == "win32":
        for _stream in (sys.stdout, sys.stderr):
            try:
                _stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, OSError):
                pass
    from app import __version__ as _ver
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] == "config":
        return _handle_config_subcommand(raw[1:])
    if raw and raw[0] == "mcp":
        return _handle_mcp_subcommand(raw[1:])
    if raw and raw[0] == "watch":
        return _handle_watch_subcommand(raw[1:])
    if raw and raw[0] == "diff":
        return _handle_diff_subcommand(raw[1:])
    if raw and raw[0] in ("self-update", "selfupdate", "update"):
        from app.features.self_update import cmd_self_update
        return cmd_self_update(check_only=("--check" in raw[1:]))
    if raw and raw[0] in ("opsec-check", "opseccheck"):
        # Honor --opsec for the check itself (otherwise it's just a baseline)
        if "--opsec" in raw[1:]:
            os.environ.setdefault("OSINT_OPSEC", "1")
        from app.features.opsec_check import cmd_opsec_check
        return cmd_opsec_check()
    if raw and raw[0] in ("cert-watch", "certwatch"):
        from app.features.cert_watch import cmd_cert_watch
        return cmd_cert_watch(raw[1:])
    if raw and raw[0] == "cache":
        from app.core.cache import cmd_cache
        return cmd_cache(raw[1:])
    if raw and raw[0] == "completion":
        shell = raw[1] if len(raw) > 1 else "bash"
        # Try filesystem path first (dev), then importlib resources (installed wheel).
        cand_paths = []
        here = Path(__file__).resolve().parent
        if shell == "bash":
            cand_paths.append(here / "scripts" / "completions" / "osint.bash")
        elif shell == "zsh":
            cand_paths.append(here / "scripts" / "completions" / "_osint")
        elif shell == "fish":
            print("# fish completion coming soon — for now, copy zsh script.",
                  file=sys.stderr)
            return 1
        else:
            print(f"unknown shell {shell!r}; valid: bash, zsh, fish", file=sys.stderr)
            return 2
        for p in cand_paths:
            if p.exists():
                print(p.read_text(encoding="utf-8"))
                return 0
        print(f"completion script not found for {shell!r}", file=sys.stderr)
        return 1
    if raw and raw[0] == "serve":
        from app.ui.web import serve as _serve
        port = 8765
        for i, a in enumerate(raw[1:]):
            if a == "--port" and i + 1 < len(raw[1:]):
                port = int(raw[1:][i + 1])
        return _serve(port=port)

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

    if args.list_profiles:
        from app.core.profiles import list_profiles
        if not args.no_banner:
            print(render_banner(st))
        print()
        print(f"   {st.accent(st.bold('profiles'))}  "
              f"{st.dim('— enable a curated module subset via --profile NAME')}")
        print()
        for name, n, mods in list_profiles():
            print(f"   {st.bold(f'{name:<14}')} {st.dim(f'({n:>2} modules)')}  "
                  f"{', '.join(mods[:6])}"
                  + (st.dim(f' … (+{len(mods)-6})') if len(mods) > 6 else ""))
        print()
        return 0

    # OPSEC mode: bootstrap the SOCKS-routed HTTP client BEFORE any module
    # creates the default singleton. We do this by setting env vars that
    # app.core.http honours on first call.
    if args.opsec:
        os.environ.setdefault("OSINT_OPSEC", "1")
        socks = os.getenv("TOR_SOCKS", "socks5://127.0.0.1:9050")
        os.environ["HTTPX_PROXY"] = socks
        if not args.no_banner:
            print(render_banner(st))
        print(st.warn(f"  ⚑ OPSEC MODE — SOCKS5 {socks}, "
                      f"jitter ON, UA randomization forced"), file=sys.stderr)

    # Bulk mode short-circuits the single-query path.
    if args.bulk:
        return _run_bulk(args, st)

    if args.interactive or (not args.value and sys.stdin.isatty()):
        from app.ui.interactive import run_interactive
        load_settings()
        return asyncio.run(run_interactive(show_figlet=bool(args.banner)))

    if not args.value:
        print(render_banner(st))
        _print_no_arg_panel(st, sys.stdout)
        return 0

    load_settings()
    kind = QueryKind(args.kind) if args.kind else infer_kind(args.value)
    q = Query(kind=kind, value=args.value)

    # Apply profile + per-module enable/disable (profile first so flags win).
    r = runner()
    if args.profile:
        from app.core.profiles import apply_profile
        try:
            enabled, disabled = apply_profile(r, args.profile)
            print(st.dim(f"  profile={args.profile} → "
                         f"{len(enabled)} enabled, {len(disabled)} disabled"),
                  file=sys.stderr)
        except ValueError as e:
            print(st.bad(f"  {e}"), file=sys.stderr)
            return 2
    for m in args.enable:
        r.set_enabled(m, True)
    for m in args.disable:
        r.set_enabled(m, False)

    # TUI mode: hand off to the textual app and skip the streaming printer.
    if args.tui:
        try:
            from app.ui.tui_dashboard import run_tui
            return run_tui(q, html_out=getattr(args, "html", None))
        except ImportError as e:
            print(st.bad(f"  TUI requires 'textual' — pip install textual\n  ({e})"),
                  file=sys.stderr)
            return 2

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
