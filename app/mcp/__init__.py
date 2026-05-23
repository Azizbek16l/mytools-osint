"""MCP (Model Context Protocol) server — exposes mytools-osint to AI agents.

Entry points:
  - ``create_server()``  — build a configured ``mcp.server.Server`` (sync helper).
  - ``run_stdio()``      — async coroutine that runs the server over stdio.

The actual handler implementations live in :mod:`app.mcp.server`.
"""

from __future__ import annotations

from .server import create_server, run_stdio

__all__ = ["create_server", "run_stdio"]
