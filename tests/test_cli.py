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
    ],
)
def test_infer_kind(value, expected):
    assert infer_kind(value) == expected
