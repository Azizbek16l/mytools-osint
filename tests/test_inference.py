"""Query-kind inference logic. Pure CPU, no Qt, no network."""
from __future__ import annotations

import pytest

from app.core.infer import infer_kind
from app.core.types import QueryKind
from app.modules.base import clean_email, clean_phone, clean_username


@pytest.mark.parametrize(
    "value, expected",
    [
        ("john@example.com", QueryKind.EMAIL),
        ("john.doe+tag@sub.example.co.uk", QueryKind.EMAIL),
        ("+998901234567", QueryKind.PHONE),
        ("998901234567", QueryKind.PHONE),
        ("+1 (415) 555-0102", QueryKind.PHONE),
        ("@durov", QueryKind.USERNAME),
        ("torvalds", QueryKind.USERNAME),
        ("github.com", QueryKind.DOMAIN),
        ("", None),
    ],
)
def test_infer_kind(value, expected):
    assert infer_kind(value) == expected


def test_clean_username():
    assert clean_username("  @durov ") == "durov"
    assert clean_username("torvalds") == "torvalds"


def test_clean_email():
    assert clean_email(" John@Example.COM ") == "john@example.com"


def test_clean_phone():
    assert clean_phone("+998 90 123 45 67") == "+998901234567"
    assert clean_phone("(415) 555-0102") == "4155550102"
    assert clean_phone("+1-415-555-0102") == "+14155550102"
