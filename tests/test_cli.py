"""CLI argparse + kind inference — no network involved."""
from __future__ import annotations

import pytest

from app.core.types import QueryKind
from cli import infer_kind


@pytest.mark.parametrize(
    "value, expected",
    [
        ("torvalds", QueryKind.USERNAME),
        ("@durov", QueryKind.USERNAME),
        ("a@b.co", QueryKind.EMAIL),
        ("+998 94 824 12 22", QueryKind.PHONE),
        ("example.com", QueryKind.DOMAIN),
        ("sub.example.co.uk", QueryKind.DOMAIN),
        # Regression — IPv4 and IPv6 must route to QueryKind.IP, not USERNAME
        # (caught by the Bluetm Agent on 2026-05-23).
        ("8.8.8.8", QueryKind.IP),
        ("1.1.1.1", QueryKind.IP),
        ("2001:db8::1", QueryKind.IP),
        ("::1", QueryKind.IP),
        ("fe80::1", QueryKind.IP),
    ],
)
def test_infer_kind(value, expected):
    assert infer_kind(value) == expected
