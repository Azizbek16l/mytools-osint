"""Live Textual dashboard for a single OSINT query.

Three panes, fixed height:

  ┌─────────────────────────────────────────────────────────┐
  │  TARGET · KIND · ELAPSED                                │  ← header
  ├──────────────────┬──────────────────────────────────────┤
  │  modules         │   findings (live stream, sev-color)  │
  │  ● enabled       │   ● [CRITICAL] threat_intel/URLhaus  │
  │  ○ disabled      │   ● [HIGH]     takeover/Vercel       │
  │  + run-count     │   ...                                │
  ├──────────────────┴──────────────────────────────────────┤
  │  q quit · h html-report · s save jsonl · / filter       │  ← footer
  └─────────────────────────────────────────────────────────┘

Wired to the same Runner the CLI uses, so module visibility, profiles, and
OPSEC flags carry over.
"""
from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from app.core.config import load_settings
from app.core.runner import runner
from app.core.types import Hit, HitStatus, Query, QueryResult, Severity

if TYPE_CHECKING:
    pass

_SEV_STYLE = {
    "info":     "dim",
    "low":      "cyan",
    "medium":   "yellow",
    "high":     "red bold",
    "critical": "white on red",
}
_STATUS_DOT = {
    "found": "[green]●[/]", "not_found": "[dim]○[/]",
    "uncertain": "[yellow]?[/]", "error": "[red]✕[/]",
    "ratelimited": "[yellow]▲[/]", "unavailable": "[dim]~[/]",
    "no_data": "[dim]·[/]", "skipped": "[dim]·[/]",
}


def run_tui(query: Query, html_out: str | None = None) -> int:
    """Launch the textual dashboard for a single query. Blocks until quit.

    Returns 0 on quit-after-success, 1 if no positives.
    """
    try:
        from textual.app import App, ComposeResult
        from textual.binding import Binding
        from textual.containers import Horizontal, Vertical
        from textual.reactive import reactive
        from textual.screen import ModalScreen
        from textual.widgets import DataTable, Footer, Header, Input, Label, Static
    except ImportError as e:
        raise ImportError(
            "textual is required for --tui mode. Install: pip install textual>=0.50"
        ) from e

    load_settings()

    class _SearchScreen(ModalScreen):
        """Modal input for inline TUI search — pops up on `/` keypress."""
        CSS = """
        _SearchScreen { align: center middle; background: rgba(0,0,0,0.6); }
        #search-box { width: 60%; max-width: 80; height: 5;
                      background: #142231; border: solid #83c5ff;
                      padding: 1 2; }
        #search-input { background: #0e1822; color: #e6edf3; }
        #search-hint { color: #9ba9b8; text-style: italic; }
        """
        BINDINGS = [Binding("escape", "dismiss_now", "cancel")]

        def __init__(self, dashboard: "Dashboard") -> None:
            super().__init__()
            self._dashboard = dashboard

        def compose(self) -> ComposeResult:
            with Vertical(id="search-box"):
                yield Label("[b]filter findings[/]  [#9ba9b8](type to filter · Enter applies · Esc cancels)[/]")
                yield Input(value=self._dashboard.search_query,
                            placeholder="substring (matches module, source, title, detail, url)…",
                            id="search-input")

        def on_input_submitted(self, event: Input.Submitted) -> None:
            self._dashboard.search_query = event.value.strip()
            self._dashboard._refresh_stats()
            self._dashboard._rebuild_hit_table()
            self.app.pop_screen()

        def action_dismiss_now(self) -> None:
            self.app.pop_screen()


    class Dashboard(App):
        CSS = """
        Screen { background: #0a1219; }
        Header { background: #0e1822; color: #83c5ff; }
        Footer { background: #0e1822; color: #9ba9b8; }
        .title { color: #83c5ff; text-style: bold; padding: 0 1; }
        #modules { width: 28; background: #0e1822; border: solid #1f2c3a; }
        #findings { background: #0e1822; border: solid #1f2c3a; }
        #stats { height: 3; background: #142231; border: solid #1f2c3a;
                 color: #e6edf3; padding: 0 1; }
        DataTable { background: #0e1822; }
        DataTable > .datatable--header { background: #142231; color: #83c5ff; }
        """
        BINDINGS = [
            Binding("q", "quit", "quit"),
            Binding("h", "save_html", "html-report"),
            Binding("s", "save_jsonl", "save jsonl"),
            Binding("p", "toggle_pause", "pause stream"),
            Binding("f", "filter_found", "found-only"),
            Binding("slash", "search", "search"),       # v4.0: / inline filter
            Binding("escape", "clear_search", "clear"),
        ]

        paused = reactive(False)
        only_found = reactive(False)
        search_query = reactive("")

        def __init__(self, q: Query) -> None:
            super().__init__()
            self.query = q
            self.hits: list[Hit] = []
            self.started_at = datetime.now(UTC)
            self.runner_task: asyncio.Task | None = None
            self.module_counts: dict[str, int] = {}
            self.module_positives: dict[str, int] = {}
            self.result: QueryResult | None = None

        def compose(self) -> ComposeResult:
            yield Header(show_clock=False)
            yield Static(self._stats_text(), id="stats")
            with Horizontal():
                with Vertical(id="modules"):
                    yield Static("[b]modules[/b]", classes="title")
                    yield DataTable(id="mod_table",
                                    show_cursor=False, header_height=1, zebra_stripes=False)
                with Vertical(id="findings"):
                    yield Static("[b]findings[/b]", classes="title")
                    yield DataTable(id="hit_table",
                                    show_cursor=True, header_height=1, zebra_stripes=False)
            yield Footer()

        def on_mount(self) -> None:
            self.title = f"mytools-osint  ·  {self.query.kind.value}: {self.query.value}"
            mt: DataTable = self.query_one("#mod_table", DataTable)
            mt.add_columns("name", "found", "total")
            ht: DataTable = self.query_one("#hit_table", DataTable)
            ht.add_columns("sev", "module", "source", "detail")
            r = runner()
            for m in r.all_modules():
                marker = "[green]●[/]" if m.enabled else "[dim]○[/]"
                mt.add_row(f"{marker} {m.name}", "0", "0", key=m.name)
            # Kick off the actual scan.
            self.runner_task = asyncio.create_task(self._run_scan())
            self.set_interval(0.5, self._refresh_stats)

        async def _run_scan(self) -> None:
            r = runner()

            async def on_hit(h: Hit) -> None:
                if self.paused:
                    return
                self.hits.append(h)
                self.module_counts[h.module] = self.module_counts.get(h.module, 0) + 1
                if h.status == HitStatus.FOUND:
                    self.module_positives[h.module] = self.module_positives.get(h.module, 0) + 1
                # Update module table row
                try:
                    mt: DataTable = self.query_one("#mod_table", DataTable)
                    mt.update_cell(h.module, "found",
                                   str(self.module_positives.get(h.module, 0)))
                    mt.update_cell(h.module, "total",
                                   str(self.module_counts.get(h.module, 0)))
                except Exception:
                    pass
                # Append hit row
                if self.only_found and h.status != HitStatus.FOUND:
                    return
                try:
                    ht: DataTable = self.query_one("#hit_table", DataTable)
                    sev = h.severity.value
                    sev_style = _SEV_STYLE.get(sev, "dim")
                    ht.add_row(
                        f"[{sev_style}]{sev}[/]",
                        h.module,
                        h.source[:24],
                        (h.detail or "")[:100],
                    )
                    # auto-scroll
                    ht.action_scroll_end()
                except Exception:
                    pass

            try:
                self.result = await r.run(self.query, on_hit=on_hit)
            except Exception as e:
                self.notify(f"runner error: {e}", severity="error")
            else:
                self._refresh_stats()
                self.notify(f"scan complete — {self.result.found}/{self.result.total} positives",
                            severity="information")

        def _stats_text(self) -> str:
            elapsed = (datetime.now(UTC) - self.started_at).total_seconds()
            n = len(self.hits)
            pos = sum(1 for h in self.hits if h.status == HitStatus.FOUND)
            crit = sum(1 for h in self.hits if h.severity == Severity.CRITICAL)
            high = sum(1 for h in self.hits if h.severity == Severity.HIGH)
            pause = "[yellow] PAUSED[/]" if self.paused else ""
            filt = " · [cyan]found-only[/]" if self.only_found else ""
            search = (f" · [yellow]/{self.search_query}/[/]"
                      if self.search_query else "")
            return (f"[b]{self.query.kind.value.upper()}[/b]  "
                    f"[#83c5ff]{self.query.value}[/]   "
                    f"hits=[b]{n}[/]  found=[green]{pos}[/]  "
                    f"crit=[red]{crit}[/]  high=[red]{high}[/]  "
                    f"elapsed={elapsed:.1f}s{pause}{filt}{search}")

        def _refresh_stats(self) -> None:
            try:
                w: Static = self.query_one("#stats", Static)
                w.update(self._stats_text())
            except Exception:
                pass

        def action_toggle_pause(self) -> None:
            self.paused = not self.paused
            self._refresh_stats()

        def action_filter_found(self) -> None:
            self.only_found = not self.only_found
            self._refresh_stats()
            self._rebuild_hit_table()

        def action_search(self) -> None:
            """v4.0: prompt for inline filter — fuzzy substring across all fields."""
            from textual.widgets import Input
            # textual's screens push/pop modally; for now we use a simple
            # asyncio prompt via the footer-level keybinding hint.
            # Better: pop a modal Input. Stub for now: cycle through 3 demos
            # to prove the wiring works. Real impl below.
            self.push_screen(_SearchScreen(self))

        def action_clear_search(self) -> None:
            self.search_query = ""
            self._refresh_stats()
            self._rebuild_hit_table()

        def _hit_matches_search(self, h: Hit) -> bool:
            if not self.search_query:
                return True
            q = self.search_query.lower()
            for field in (h.module, h.source, h.title, h.detail, h.url,
                          h.category, h.severity.value):
                if field and q in field.lower():
                    return True
            return False

        def _rebuild_hit_table(self) -> None:
            try:
                ht: DataTable = self.query_one("#hit_table", DataTable)
                ht.clear()
                for h in self.hits:
                    if self.only_found and h.status != HitStatus.FOUND:
                        continue
                    if not self._hit_matches_search(h):
                        continue
                    sev = h.severity.value
                    sev_style = _SEV_STYLE.get(sev, "dim")
                    ht.add_row(f"[{sev_style}]{sev}[/]", h.module,
                               h.source[:24], (h.detail or "")[:100])
            except Exception:
                pass

        def action_save_jsonl(self) -> None:
            path = Path(f"osint-{self.query.kind.value}-"
                        f"{self.query.value}-{int(datetime.now().timestamp())}.jsonl")
            with path.open("w", encoding="utf-8") as f:
                for h in self.hits:
                    f.write(json.dumps({
                        "module": h.module, "source": h.source,
                        "status": h.status.value, "severity": h.severity.value,
                        "title": h.title, "detail": h.detail, "url": h.url,
                        "extra": h.extra, "category": h.category,
                    }, default=str) + "\n")
            self.notify(f"saved → {path}", severity="information")

        def action_save_html(self) -> None:
            from app.ui.html_report import render_report
            elapsed = int((datetime.now(UTC) - self.started_at).total_seconds() * 1000)
            res = self.result or QueryResult(query=self.query, hits=self.hits)
            html = render_report(self.query, res, elapsed)
            out = html_out or f"osint-{self.query.kind.value}-{self.query.value}.html"
            Path(out).write_text(html, encoding="utf-8")
            self.notify(f"html → {out}", severity="information")

    app = Dashboard(query)
    app.run()
    return 0 if any(h.status == HitStatus.FOUND for h in app.hits) else 1
