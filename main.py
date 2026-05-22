"""mytools-osint — entry point.

Boots Qt + asyncio in a single event loop via qasync, connects to the local
SQLite DB, registers OSINT modules, and shows the main window.
"""
from __future__ import annotations

import asyncio
import signal
import sys

import qasync
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication

from app.core.config import load_settings
from app.core.db import Database
from app.core.http import close_client
from app.core.runner import runner
from app.ui import theme
from app.ui.main_window import MainWindow


def main() -> int:
    QGuiApplication.setApplicationName("mytools-osint")
    QGuiApplication.setOrganizationName("MarsIT")

    app = QApplication(sys.argv)
    theme.apply(app)

    s = load_settings()
    runner()  # eagerly register modules

    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    db = Database(s.db_path)

    async def _bootstrap() -> MainWindow:
        await db.connect()
        win = MainWindow(db)
        win.show()
        await win._reload_history()
        return win

    asyncio.ensure_future(_bootstrap())

    async def _shutdown() -> None:
        try:
            await close_client()
        finally:
            await db.close()

    app.aboutToQuit.connect(lambda: asyncio.ensure_future(_shutdown()))

    # graceful Ctrl-C
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: app.quit())
    except (ValueError, OSError):
        pass

    with loop:
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
