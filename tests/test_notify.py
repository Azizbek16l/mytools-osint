"""Notification dispatcher. Telegram is mocked — no network calls."""
from __future__ import annotations

import json
from typing import Any

import pytest

from app.core.types import Hit, HitStatus, Severity
from app.features import notify

# ---- fakes -----------------------------------------------------------------


class _FakeMe:
    def __init__(self, user_id: int = 42) -> None:
        self.id = user_id


class _FakeClient:
    def __init__(self, *, me: Any = None, raise_on_send: Exception | None = None):
        self._me = me if me is not None else _FakeMe()
        self._raise_on_send = raise_on_send
        self.sent: list[tuple[Any, str, dict[str, Any]]] = []

    async def get_me(self) -> Any:
        return self._me

    async def send_message(self, entity: Any, message: str, **kwargs: Any) -> Any:
        if self._raise_on_send is not None:
            raise self._raise_on_send
        self.sent.append((entity, message, kwargs))
        return object()


# ---- happy path ------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_to_self_success_with_mock_client(monkeypatch, tmp_path):
    # redirect fallback log path so we can confirm it's NOT written on success
    monkeypatch.setattr(
        notify, "_fallback_log_path", lambda: tmp_path / "notifications.log"
    )
    client = _FakeClient()

    async def factory():
        return client

    ok = await notify.send_to_self("hello *world*", client_factory=factory)
    assert ok is True
    assert len(client.sent) == 1
    entity, message, kwargs = client.sent[0]
    assert message == "hello *world*"
    assert kwargs.get("parse_mode") == "md"
    # on success we must NOT have written the fallback log
    assert not (tmp_path / "notifications.log").exists()


@pytest.mark.asyncio
async def test_send_to_self_missing_client_writes_fallback(monkeypatch, tmp_path):
    log_path = tmp_path / "notifications.log"
    monkeypatch.setattr(notify, "_fallback_log_path", lambda: log_path)

    async def factory():
        return None

    ok = await notify.send_to_self("important alert", client_factory=factory)
    assert ok is False
    assert log_path.exists()
    line = log_path.read_text(encoding="utf-8").strip()
    rec = json.loads(line)
    assert rec["reason"] == "telegram_unavailable"
    assert rec["message"] == "important alert"


@pytest.mark.asyncio
async def test_send_to_self_send_failure_falls_back(monkeypatch, tmp_path):
    log_path = tmp_path / "notifications.log"
    monkeypatch.setattr(notify, "_fallback_log_path", lambda: log_path)

    client = _FakeClient(raise_on_send=RuntimeError("network down"))

    async def factory():
        return client

    ok = await notify.send_to_self("msg", client_factory=factory)
    assert ok is False
    rec = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert rec["reason"].startswith("send_failed:")
    assert "RuntimeError" in rec["reason"]


@pytest.mark.asyncio
async def test_send_to_self_factory_raises_falls_back(monkeypatch, tmp_path):
    log_path = tmp_path / "notifications.log"
    monkeypatch.setattr(notify, "_fallback_log_path", lambda: log_path)

    async def factory():
        raise RuntimeError("session not initialised")

    ok = await notify.send_to_self("msg", client_factory=factory)
    assert ok is False
    rec = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert rec["reason"] == "telegram_unavailable"


# ---- message formatting ----------------------------------------------------


def test_format_watchlist_message_basic():
    hits = [
        Hit(module="m", source="GitLab", status=HitStatus.FOUND,
            url="https://gitlab.com/torvalds", title="torvalds",
            severity=Severity.HIGH),
        Hit(module="m", source="Mastodon", status=HitStatus.FOUND,
            url="https://mas.example/@torvalds", title="@torvalds",
            severity=Severity.MEDIUM),
    ]
    msg = notify.format_watchlist_message("torvalds", hits)
    assert "new findings" in msg
    assert "torvalds" in msg
    assert "GitLab" in msg
    assert "Mastodon" in msg
    assert "https://gitlab.com/torvalds" in msg


def test_format_watchlist_message_empty_hits():
    msg = notify.format_watchlist_message("torvalds", [])
    assert "no new informative hits" in msg


def test_format_watchlist_message_caps_at_20():
    many = [
        Hit(module="m", source=f"Site{i}", status=HitStatus.FOUND,
            url=f"https://example.com/{i}", title=f"acct{i}")
        for i in range(25)
    ]
    msg = notify.format_watchlist_message("user", many)
    # one of the first 20 must be present
    assert "Site0" in msg
    # cap notice must be present and reference the remainder
    assert "and 5 more" in msg
    # 24th entry (Site23) is beyond the cap
    assert "Site23" not in msg


def test_format_watchlist_message_escapes_markdown_in_value():
    msg = notify.format_watchlist_message("user_with_*stars*", [])
    # backslash-escaped underscores and stars in the bold-wrapped value
    assert "\\*" in msg
    assert "\\_" in msg
