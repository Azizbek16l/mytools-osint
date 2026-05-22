"""Headless smoke test — boots the UI under offscreen Qt, runs one history reload, exits 0."""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import qasync
from PySide6.QtWidgets import QApplication

from app.core.config import load_settings
from app.core.db import Database
from app.core.http import close_client
from app.core.runner import runner
from app.ui import theme
from app.ui.main_window import MainWindow


def main() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    theme.apply(app)
    s = load_settings()
    r = runner()
    assert len(r.all_modules()) >= 6, "expected ≥6 modules registered"

    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)
    db = Database(s.db_path)

    rc = {"code": 1}

    async def boot() -> None:
        try:
            await db.connect()
            w = MainWindow(db)
            w.show()
            await asyncio.sleep(0.15)
            assert w.kind_box.count() == 7
            assert w.tbl.columnCount() == 7
            await w._reload_history()
            print(f"SMOKE OK — modules={len(r.all_modules())} tabs={w.tabs.count()}", flush=True)
            rc["code"] = 0
        except Exception as e:
            print(f"SMOKE FAIL: {type(e).__name__}: {e}", flush=True)
            rc["code"] = 2
        finally:
            await close_client()
            await db.close()
            app.quit()

    with loop:
        asyncio.ensure_future(boot())
        loop.run_forever()
    return rc["code"]


if __name__ == "__main__":
    raise SystemExit(main())
