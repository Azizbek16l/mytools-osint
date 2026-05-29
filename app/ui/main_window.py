"""Main window — search bar, result table, sidebar, status bar."""
from __future__ import annotations

import asyncio
import csv
import json
import webbrowser
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolBar,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from app.core.config import load_settings, settings
from app.core.db import Database
from app.core.infer import infer_kind
from app.core.runner import runner
from app.core.types import Hit, HitStatus, Query, QueryKind, QueryResult

# infer_kind now lives in app.core.infer (Qt-free, imported at top) so it stays
# unit-testable without the optional PySide6 dependency.

# ----- main window -------------------------------------------------------------

class MainWindow(QMainWindow):
    streamed = Signal(object)  # Hit

    def __init__(self, db: Database) -> None:
        super().__init__()
        self.db = db
        self._current_task: asyncio.Task | None = None
        self._current_query: Query | None = None
        self._current_hits: list[Hit] = []

        from app import __version__ as _ver
        from app.ui.banner import BRAND
        self.setWindowTitle(f"{BRAND} — mytools-osint v{_ver}")
        self.resize(1400, 860)

        self._build_toolbar()
        self._build_central()
        self._build_status()
        self.streamed.connect(self._on_hit)

    # ---- chrome ----

    def _build_toolbar(self) -> None:
        tb = QToolBar("main")
        tb.setMovable(False)
        tb.setIconSize(tb.iconSize() * 0.9)
        self.addToolBar(tb)

        self.kind_box = QComboBox()
        self.kind_box.addItem("Auto-detect", "auto")
        self.kind_box.addItem("Username", QueryKind.USERNAME.value)
        self.kind_box.addItem("Email", QueryKind.EMAIL.value)
        self.kind_box.addItem("Phone", QueryKind.PHONE.value)
        self.kind_box.addItem("Telegram", QueryKind.TELEGRAM.value)
        self.kind_box.addItem("WhatsApp", QueryKind.WHATSAPP.value)
        self.kind_box.addItem("IP/Domain", QueryKind.IP.value)
        # Wave C — new kinds. Wallet/Image are auto-detected; Company is manual.
        self.kind_box.addItem("Wallet (BTC/ETH)", QueryKind.WALLET.value)
        self.kind_box.addItem("Image (URL/path)", QueryKind.IMAGE.value)
        self.kind_box.addItem("Company name", QueryKind.COMPANY.value)
        tb.addWidget(self.kind_box)

        self.query_edit = QLineEdit()
        self.query_edit.setPlaceholderText("Enter username, email, +phone, @telegram, IP or domain — press Enter")
        self.query_edit.returnPressed.connect(self._start_query)
        tb.addWidget(self.query_edit)

        self.run_btn = QPushButton("Search")
        self.run_btn.setProperty("accent", True)
        self.run_btn.clicked.connect(self._start_query)
        tb.addWidget(self.run_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self._stop_query)
        self.stop_btn.setEnabled(False)
        tb.addWidget(self.stop_btn)

        tb.addSeparator()

        export_btn = QToolButton(self)
        export_btn.setText("Export")
        export_btn.setPopupMode(QToolButton.InstantPopup)
        menu = QMenu(export_btn)
        a_csv = QAction("Export CSV…", self); a_csv.triggered.connect(lambda: self._export("csv"))
        a_json = QAction("Export JSON…", self); a_json.triggered.connect(lambda: self._export("json"))
        a_md = QAction("Export Markdown…", self); a_md.triggered.connect(lambda: self._export("md"))
        menu.addAction(a_csv); menu.addAction(a_json); menu.addAction(a_md)
        export_btn.setMenu(menu)
        tb.addWidget(export_btn)

    def _build_central(self) -> None:
        tabs = QTabWidget()
        tabs.addTab(self._build_results_tab(), "Results")
        tabs.addTab(self._build_history_tab(), "History")
        tabs.addTab(self._build_settings_tab(), "Settings")
        tabs.addTab(self._build_modules_tab(), "Modules")
        self.setCentralWidget(tabs)
        self.tabs = tabs

    def _build_results_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)

        # filter row
        filter_row = QHBoxLayout()
        self.only_found_chk = QCheckBox("Only positives")
        self.only_found_chk.setChecked(True)
        self.only_found_chk.toggled.connect(self._apply_filter)
        filter_row.addWidget(self.only_found_chk)

        self.cat_filter = QComboBox()
        self.cat_filter.addItem("All categories", "")
        self.cat_filter.currentIndexChanged.connect(self._apply_filter)
        filter_row.addWidget(self.cat_filter)

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by source / url / detail…")
        self.filter_edit.textChanged.connect(self._apply_filter)
        filter_row.addWidget(self.filter_edit, 1)

        self.summary_lbl = QLabel("")
        self.summary_lbl.setProperty("role", "subtitle")
        filter_row.addWidget(self.summary_lbl)
        lay.addLayout(filter_row)

        self.tbl = QTableWidget(0, 7)
        self.tbl.setHorizontalHeaderLabels(
            ["", "Module", "Source", "Category", "Status", "Detail", "URL"]
        )
        self.tbl.horizontalHeader().setStretchLastSection(True)
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.tbl.setColumnWidth(0, 28)
        self.tbl.setColumnWidth(1, 90)
        self.tbl.setColumnWidth(2, 200)
        self.tbl.setColumnWidth(3, 110)
        self.tbl.setColumnWidth(4, 110)
        self.tbl.setColumnWidth(5, 360)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setSelectionBehavior(QTableWidget.SelectRows)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl.itemDoubleClicked.connect(self._open_row_url)
        lay.addWidget(self.tbl)
        return w

    def _build_history_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        self.history_tbl = QTableWidget(0, 6)
        self.history_tbl.setHorizontalHeaderLabels(["When", "Kind", "Value", "Found", "Total", "ms"])
        self.history_tbl.horizontalHeader().setStretchLastSection(True)
        self.history_tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.history_tbl.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_tbl.itemDoubleClicked.connect(self._open_history_row)
        lay.addWidget(self.history_tbl)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(lambda: asyncio.ensure_future(self._reload_history()))
        lay.addWidget(refresh, 0, Qt.AlignLeft)
        return w

    def _build_settings_tab(self) -> QWidget:
        w = QWidget()
        s = settings()
        form = QFormLayout(w)

        def info(text: str) -> QLabel:
            lbl = QLabel(text)
            lbl.setProperty("role", "subtitle")
            return lbl

        form.addRow(QLabel("API keys (edit .env, then click Reload)"))
        form.addRow("HIBP:", info("set" if s.has_hibp else "not set"))
        form.addRow("Numverify:", info("set" if s.has_numverify else "not set"))
        form.addRow("IPinfo:", info("set" if s.has_ipinfo else "not set"))
        form.addRow("LeakCheck:", info("set" if s.has_leakcheck else "not set"))
        form.addRow("Telegram MTProto:", info("configured" if s.has_telegram else "not set"))

        reload_btn = QPushButton("Reload .env")
        reload_btn.clicked.connect(self._reload_settings)
        form.addRow(reload_btn)

        open_dir = QPushButton(f"Open data dir: {s.data_dir}")
        open_dir.clicked.connect(lambda: webbrowser.open(str(s.data_dir)))
        form.addRow(open_dir)
        return w

    def _build_modules_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lst = QListWidget()
        for m in runner().all_modules():
            item = QListWidgetItem(f"{m.name}  ({', '.join(k.value for k in m.kinds)})")
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if m.enabled else Qt.Unchecked)
            item.setData(Qt.UserRole, m.name)
            lst.addItem(item)
        lst.itemChanged.connect(
            lambda it: runner().set_enabled(it.data(Qt.UserRole), it.checkState() == Qt.Checked)
        )
        lay.addWidget(lst)
        return w

    def _build_status(self) -> None:
        sb = QStatusBar()
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)
        self.progress.setFixedWidth(180)
        self.elapsed_lbl = QLabel("")
        self.elapsed_lbl.setProperty("role", "subtitle")
        sb.addPermanentWidget(self.elapsed_lbl)
        sb.addPermanentWidget(self.progress)
        sb.showMessage("Ready.")
        self.setStatusBar(sb)
        self._tick = QTimer(self)
        self._tick.setInterval(250)
        self._tick.timeout.connect(self._tick_elapsed)
        self._t0: float = 0.0

    # ---- query lifecycle ----

    def _start_query(self) -> None:
        value = self.query_edit.text().strip()
        if not value:
            return
        chosen = self.kind_box.currentData()
        kind: QueryKind | None
        if chosen == "auto":
            kind = infer_kind(value)
        else:
            kind = QueryKind(chosen)
        if kind is None:
            QMessageBox.warning(self, "Invalid input", "Could not infer query kind from input.")
            return
        if self._current_task and not self._current_task.done():
            QMessageBox.information(self, "Busy", "A query is already running.")
            return

        self._reset_table()
        self._current_query = Query(kind=kind, value=value)
        self._current_hits = []
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress.setVisible(True)
        self.statusBar().showMessage(f"Querying {kind.value}: {value} …")
        self._t0 = asyncio.get_event_loop().time()
        self._tick.start()

        async def on_hit(h: Hit) -> None:
            self.streamed.emit(h)

        async def runit() -> None:
            try:
                result = await runner().run(self._current_query, on_hit=on_hit)
                self._current_hits = list(result.hits)
                qid = await self.db.save_result(result)
                self._finish(result, qid)
            except asyncio.CancelledError:
                self._finish_cancelled()
                raise

        self._current_task = asyncio.ensure_future(runit())

    def _stop_query(self) -> None:
        if self._current_task and not self._current_task.done():
            self._current_task.cancel()

    def _finish(self, result: QueryResult, qid: int) -> None:
        self._tick.stop()
        self.progress.setVisible(False)
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.statusBar().showMessage(
            f"Done. {result.found}/{result.total} positive — {result.duration_ms} ms — saved as #{qid}"
        )

    def _finish_cancelled(self) -> None:
        self._tick.stop()
        self.progress.setVisible(False)
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.statusBar().showMessage("Stopped.")

    def _tick_elapsed(self) -> None:
        elapsed = asyncio.get_event_loop().time() - self._t0
        self.elapsed_lbl.setText(f"{elapsed:0.1f}s")

    # ---- table ops ----

    def _reset_table(self) -> None:
        self.tbl.setRowCount(0)
        self._cats: set[str] = set()
        self.cat_filter.blockSignals(True)
        self.cat_filter.clear()
        self.cat_filter.addItem("All categories", "")
        self.cat_filter.blockSignals(False)
        self.summary_lbl.setText("")

    def _on_hit(self, h: Hit) -> None:
        # accumulate in case the streaming path doesn't fill self._current_hits live
        self._current_hits.append(h)
        if h.category and h.category not in self._cats:
            self._cats.add(h.category)
            self.cat_filter.addItem(h.category, h.category)
        self._add_row(h)
        self._apply_filter()
        self._update_summary()

    def _add_row(self, h: Hit) -> None:
        row = self.tbl.rowCount()
        self.tbl.insertRow(row)
        marker = {
            HitStatus.FOUND: "✓",
            HitStatus.NOT_FOUND: "·",
            HitStatus.UNCERTAIN: "?",
            HitStatus.ERROR: "!",
            HitStatus.RATELIMITED: "↯",
            HitStatus.SKIPPED: "—",
        }.get(h.status, "?")
        item0 = QTableWidgetItem(marker)
        item0.setTextAlignment(Qt.AlignCenter)
        if h.status == HitStatus.FOUND:
            item0.setForeground(Qt.green)
        elif h.status in (HitStatus.ERROR, HitStatus.RATELIMITED):
            item0.setForeground(Qt.red)
        self.tbl.setItem(row, 0, item0)
        self.tbl.setItem(row, 1, QTableWidgetItem(h.module))
        self.tbl.setItem(row, 2, QTableWidgetItem(h.source))
        self.tbl.setItem(row, 3, QTableWidgetItem(h.category))
        self.tbl.setItem(row, 4, QTableWidgetItem(h.status.value))
        self.tbl.setItem(row, 5, QTableWidgetItem(h.detail))
        self.tbl.setItem(row, 6, QTableWidgetItem(h.url))

    def _apply_filter(self, *_: object) -> None:
        only_pos = self.only_found_chk.isChecked()
        cat = self.cat_filter.currentData()
        needle = self.filter_edit.text().lower()
        for row in range(self.tbl.rowCount()):
            status = self.tbl.item(row, 4).text()
            category = self.tbl.item(row, 3).text()
            blob = " ".join(self.tbl.item(row, c).text() for c in range(self.tbl.columnCount())).lower()
            hide = False
            if only_pos and status != HitStatus.FOUND.value:
                hide = True
            if cat and category != cat:
                hide = True
            if needle and needle not in blob:
                hide = True
            self.tbl.setRowHidden(row, hide)

    def _update_summary(self) -> None:
        total = len(self._current_hits)
        found = sum(1 for h in self._current_hits if h.status == HitStatus.FOUND)
        err = sum(1 for h in self._current_hits if h.status == HitStatus.ERROR)
        self.summary_lbl.setText(f"{found} positive · {total} total · {err} errors")

    def _open_row_url(self, item: QTableWidgetItem) -> None:
        row = item.row()
        url = self.tbl.item(row, 6).text()
        if url:
            webbrowser.open(url)

    # ---- history ----

    async def _reload_history(self) -> None:
        rows = await self.db.list_history(200)
        self.history_tbl.setRowCount(0)
        for r in rows:
            n = self.history_tbl.rowCount()
            self.history_tbl.insertRow(n)
            when = (r.get("started_at") or "").replace("T", " ").split(".")[0]
            cells = [when, r.get("kind", ""), r.get("value", ""),
                     str(r.get("found", 0)), str(r.get("total", 0)),
                     str(r.get("duration_ms", 0))]
            for i, v in enumerate(cells):
                it = QTableWidgetItem(v)
                self.history_tbl.setItem(n, i, it)
            self.history_tbl.item(n, 0).setData(Qt.UserRole, r.get("id"))

    def _open_history_row(self, item: QTableWidgetItem) -> None:
        row = item.row()
        qid = self.history_tbl.item(row, 0).data(Qt.UserRole)
        asyncio.ensure_future(self._load_history_qid(int(qid)))

    async def _load_history_qid(self, qid: int) -> None:
        q = await self.db.get_query(qid)
        hits = await self.db.hits_for(qid)
        if not q:
            return
        self._current_query = q
        self._current_hits = hits
        self._reset_table()
        for h in hits:
            if h.category and h.category not in self._cats:
                self._cats.add(h.category)
                self.cat_filter.addItem(h.category, h.category)
            self._add_row(h)
        self._apply_filter()
        self._update_summary()
        self.tabs.setCurrentIndex(0)
        self.statusBar().showMessage(f"Loaded history #{qid} — {q.kind.value}: {q.value}")

    # ---- settings ----

    def _reload_settings(self) -> None:
        load_settings()
        # rebuild settings tab in place
        self.tabs.removeTab(2)
        self.tabs.insertTab(2, self._build_settings_tab(), "Settings")
        self.statusBar().showMessage(".env reloaded.")

    # ---- export ----

    def _export(self, fmt: str) -> None:
        if not self._current_hits:
            QMessageBox.information(self, "Nothing to export", "Run a query first.")
            return
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        default = str(settings().exports_dir / f"mytools-{ts}.{fmt}")
        path, _ = QFileDialog.getSaveFileName(self, "Save export", default,
                                              f"{fmt.upper()} (*.{fmt})")
        if not path:
            return
        p = Path(path)
        try:
            if fmt == "csv":
                self._write_csv(p)
            elif fmt == "json":
                self._write_json(p)
            else:
                self._write_md(p)
            self.statusBar().showMessage(f"Exported to {p}")
        except Exception as e:
            QMessageBox.critical(self, "Export failed", str(e))

    def _write_csv(self, p: Path) -> None:
        with p.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["module", "source", "category", "status", "title", "detail", "url", "severity", "latency_ms"])
            for h in self._current_hits:
                w.writerow([h.module, h.source, h.category, h.status.value, h.title, h.detail, h.url, h.severity.value, h.latency_ms])

    def _write_json(self, p: Path) -> None:
        payload = {
            "query": self._current_query.model_dump() if self._current_query else None,
            "hits": [h.model_dump() for h in self._current_hits],
            "exported_at": datetime.now().isoformat(),
        }
        p.write_text(json.dumps(payload, indent=2, default=str, ensure_ascii=False), encoding="utf-8")

    def _write_md(self, p: Path) -> None:
        q = self._current_query
        lines = [f"# OSINT report — {q.kind.value if q else ''}: `{q.value if q else ''}`", ""]
        lines.append(f"_Generated {datetime.now().isoformat(timespec='seconds')}_\n")
        positives = [h for h in self._current_hits if h.status == HitStatus.FOUND]
        lines.append(f"**{len(positives)} positives / {len(self._current_hits)} probes**\n")
        lines.append("## Positives")
        for h in positives:
            lines.append(f"- **{h.source}** — {h.detail}  \n  {h.url}")
        lines.append("\n## Errors / rate-limited")
        for h in self._current_hits:
            if h.status in (HitStatus.ERROR, HitStatus.RATELIMITED):
                lines.append(f"- {h.source} — {h.status.value} — {h.detail}")
        p.write_text("\n".join(lines), encoding="utf-8")
