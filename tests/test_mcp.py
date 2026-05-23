"""Smoke tests for the mytools-osint MCP server.

Drives the server over the SDK's in-memory transport — no real stdio,
no subprocesses. Asserts that the basic MCP surface (tools, resources,
prompts) is wired correctly and that the inventory tools return real data.
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip("mcp")

from mcp.shared.memory import create_connected_server_and_client_session

from app.mcp.server import (
    RES_HISTORY,
    RES_SITES,
    SERVER_NAME,
    create_server,
)


@pytest.mark.asyncio
async def test_server_constructs():
    """create_server() must return a Server with the right name without raising."""
    server = create_server()
    assert server.name == SERVER_NAME


@pytest.mark.asyncio
async def test_list_tools_includes_core_kinds():
    """Every QueryKind we promised in the spec must have a corresponding MCP tool."""
    server = create_server()
    async with create_connected_server_and_client_session(server) as client:
        await client.initialize()
        result = await client.list_tools()
    names = {t.name for t in result.tools}
    expected = {
        "lookup_username",
        "lookup_email",
        "lookup_phone",
        "lookup_whatsapp",
        "lookup_domain",
        "lookup_ip",
        "list_modules",
        "list_sites_stats",
    }
    missing = expected - names
    assert not missing, f"missing tools: {missing}"
    # Inventory tools must declare an empty-object input schema (no args).
    by_name = {t.name: t for t in result.tools}
    assert by_name["list_modules"].inputSchema.get("properties") == {}


@pytest.mark.asyncio
async def test_list_resources_exposes_history_and_sites():
    server = create_server()
    async with create_connected_server_and_client_session(server) as client:
        await client.initialize()
        result = await client.list_resources()
    uris = {str(r.uri) for r in result.resources}
    # AnyUrl may add a trailing slash to the bare authority; accept either form.
    def _contains(target: str) -> bool:
        return target in uris or target + "/" in uris or target.rstrip("/") in uris
    assert _contains(RES_HISTORY), f"history resource missing; got {uris}"
    assert _contains(RES_SITES), f"sites resource missing; got {uris}"


@pytest.mark.asyncio
async def test_list_prompts_returns_templates():
    server = create_server()
    async with create_connected_server_and_client_session(server) as client:
        await client.initialize()
        result = await client.list_prompts()
    names = {p.name for p in result.prompts}
    assert "digital_footprint_audit" in names
    assert "domain_security_check" in names


@pytest.mark.asyncio
async def test_call_list_modules_returns_at_least_13():
    """The runner registers 13 modules out of the box — `list_modules` must echo them all."""
    server = create_server()
    async with create_connected_server_and_client_session(server) as client:
        await client.initialize()
        result = await client.call_tool("list_modules", {})
    assert result.content, "list_modules returned no content"
    # First (and only) block is TextContent with a JSON array payload.
    block = result.content[0]
    payload = json.loads(block.text)
    assert isinstance(payload, list)
    assert len(payload) >= 13, f"expected >=13 modules, got {len(payload)}"
    # Sanity-check a couple of well-known modules.
    names = {m["name"] for m in payload}
    assert "username" in names
    assert "domain" in names


@pytest.mark.asyncio
async def test_call_list_sites_stats_returns_totals():
    server = create_server()
    async with create_connected_server_and_client_session(server) as client:
        await client.initialize()
        result = await client.call_tool("list_sites_stats", {})
    payload = json.loads(result.content[0].text)
    assert "total" in payload
    assert "by_category" in payload
    assert isinstance(payload["by_category"], dict)


@pytest.mark.asyncio
async def test_get_prompt_renders_template():
    """Prompt should interpolate the target arg into the rendered text."""
    server = create_server()
    async with create_connected_server_and_client_session(server) as client:
        await client.initialize()
        result = await client.get_prompt("digital_footprint_audit", {"target": "torvalds"})
    assert result.messages
    msg = result.messages[0]
    assert msg.role == "user"
    assert "torvalds" in msg.content.text
