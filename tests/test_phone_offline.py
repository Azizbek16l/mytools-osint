"""Offline (libphonenumber) phone parsing assertions."""
from __future__ import annotations

import pytest

from app.modules.phone import _libphonenumber


def test_parse_uz_mobile():
    h = _libphonenumber("+998901234567")
    extra = h.extra
    assert extra["valid"] is True
    assert "Uzbekistan" in extra["region"] or extra["region"]
    assert extra["e164"] == "+998901234567"
    assert extra["type"] in {"MOBILE", "FIXED_OR_MOBILE"}


def test_parse_us():
    h = _libphonenumber("+14155550100")
    extra = h.extra
    assert extra["e164"] == "+14155550100"
    assert extra["region"]


@pytest.mark.parametrize("garbage", ["", "abc", "123"])
def test_parse_bad(garbage):
    h = _libphonenumber(garbage)
    assert h.status.value in {"not_found", "uncertain"}
