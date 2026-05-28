"""MCP `call_tool` dispatch tests for app/mcp/server.py.

Two things matter here:
  1. A real lookup tool returns *structured* output — the serialised QueryResult
     with a `summary` block (by_status / by_severity / counts) and the hits.
  2. Malformed / unknown / empty-arg calls are handled gracefully (a JSON error
     payload, never an exception that breaks the MCP transport).

We isolate from the network by swapping the server's `runner()` for a tiny
in-process Runner with one fake module — this exercises the full
`_handle_call_tool → _run_query → _serialise_result` path without the 1000-site
fan-out, and stays hermetic and sub-second.
"""
from __future__ import annotations

import json
from collections.abc import AsyncIterator

import pytest

pytest.importorskip("mcp")

from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity
from app.mcp import server as mcp_server


def _fake_runner() -> Runner:
    r = Runner()

    async def fake_ip(_q: Query) -> AsyncIterator[Hit]:
        yield Hit(module="ip", source="rDNS", status=HitStatus.FOUND,
                  detail="dns.google", severity=Severity.MEDIUM)
        yield Hit(module="ip", source="IPinfo", status=HitStatus.SKIPPED,
                  detail="set IPINFO_API_TOKEN")

    r.register("ip", [QueryKind.IP], fake_ip)
    return r


def _payload(blocks) -> dict:
    assert blocks, "call_tool returned no content blocks"
    return json.loads(blocks[0].text)


class TestCallToolDispatch:
    async def test_lookup_returns_structured_result(self, monkeypatch) -> None:
        monkeypatch.setattr(mcp_server, "runner", _fake_runner)
        blocks = await mcp_server._handle_call_tool(
            "lookup_ip", {"ip": "8.8.8.8", "all_results": True}, with_telegram=False,
        )
        payload = _payload(blocks)
        # structured summary block present and correct
        summary = payload["summary"]
        assert summary["total"] == 2
        assert summary["found"] == 1
        assert summary["by_status"]["found"] == 1
        assert summary["by_status"]["skipped"] == 1
        # the query echoed back, hits serialised
        assert payload["query"]["value"] == "8.8.8.8"
        sources = {h["source"] for h in payload["hits"]}
        assert sources == {"rDNS", "IPinfo"}

    async def test_all_results_false_strips_skipped(self, monkeypatch) -> None:
        monkeypatch.setattr(mcp_server, "runner", _fake_runner)
        blocks = await mcp_server._handle_call_tool(
            "lookup_ip", {"ip": "8.8.8.8"}, with_telegram=False,  # all_results default False
        )
        payload = _payload(blocks)
        statuses = {h["status"] for h in payload["hits"]}
        assert "skipped" not in statuses  # SKIPPED filtered out of the view
        assert "found" in statuses
        # summary still counts everything (computed from the full result)
        assert payload["summary"]["total"] == 2

    async def test_missing_required_arg_is_graceful(self, monkeypatch) -> None:
        monkeypatch.setattr(mcp_server, "runner", _fake_runner)
        blocks = await mcp_server._handle_call_tool(
            "lookup_ip", {"wrong_key": "8.8.8.8"}, with_telegram=False,
        )
        payload = _payload(blocks)
        assert "error" in payload
        assert "ip" in payload["error"]  # names the missing primary arg

    async def test_empty_value_is_graceful(self, monkeypatch) -> None:
        monkeypatch.setattr(mcp_server, "runner", _fake_runner)
        blocks = await mcp_server._handle_call_tool(
            "lookup_ip", {"ip": "   "}, with_telegram=False,
        )
        payload = _payload(blocks)
        assert "error" in payload

    async def test_unknown_tool_is_graceful(self) -> None:
        blocks = await mcp_server._handle_call_tool(
            "lookup_nonsense", {"x": "y"}, with_telegram=False,
        )
        payload = _payload(blocks)
        assert "error" in payload
        assert "unknown tool" in payload["error"]

    async def test_none_arguments_handled(self) -> None:
        # arguments=None must not raise — treated as empty dict → missing-arg error
        blocks = await mcp_server._handle_call_tool(
            "lookup_ip", None, with_telegram=False,
        )
        payload = _payload(blocks)
        assert "error" in payload

    async def test_runner_exception_surfaces_as_error_payload(self, monkeypatch) -> None:
        async def _boom_runner_run(*_a, **_k):
            raise RuntimeError("module blew up")

        class _BoomRunner:
            def run(self, *_a, **_k):
                return _boom_runner_run()

        monkeypatch.setattr(mcp_server, "runner", lambda: _BoomRunner())
        blocks = await mcp_server._handle_call_tool(
            "lookup_ip", {"ip": "8.8.8.8"}, with_telegram=False,
        )
        payload = _payload(blocks)
        assert "error" in payload
        assert "RuntimeError" in payload["error"]
