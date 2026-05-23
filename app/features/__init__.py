"""Higher-level features built on top of app.core — watchlist, diff, notifications.

These are deliberately separated from app.core (which only deals in primitives:
DB, HTTP, the Runner registry) so they can be tested in isolation and so the
core layer stays free of policy.
"""
from __future__ import annotations
