"""MCP server for mytools-osint.

Exposes the OSINT runner over the Model Context Protocol so AI agents
(Claude Code, Warp, Cursor, etc.) can invoke lookups, browse history, and
read the curated probe-site dataset.

Surface:
  * Tools — one per :class:`~app.core.types.QueryKind` plus inventory helpers.
  * Resources — read-only views of recent history and the sites catalogue.
  * Prompts — pre-canned investigation templates.

This module is **purely additive**: it does not edit the runner, the module
registry, or any of the existing OSINT modules. It assembles a :class:`Query`,
delegates to ``runner().run(query)``, and serialises the resulting
:class:`QueryResult` as JSON for the client.

Transport defaults to stdio (``run_stdio``); ``create_server`` returns the
plain ``Server`` so tests can drive it over an in-memory transport.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections import Counter
from pathlib import Path
from typing import Any, cast

import mcp.types as mcp_types
from mcp.server import Server
from mcp.server.stdio import stdio_server
from pydantic import AnyUrl

from app import __version__ as APP_VERSION
from app.core.config import load_settings, settings
from app.core.db import Database
from app.core.runner import runner
from app.core.types import Query, QueryKind, QueryResult

logger = logging.getLogger(__name__)

SERVER_NAME = "mytools-osint"

# Resource URIs are kept as constants so tests can assert against them.
RES_HISTORY = "osint://history"
RES_SITES = "osint://sites"
_HISTORY_ITEM_PREFIX = "osint://history/"

# Sites JSON ships in the repo data dir. Loaded lazily — keeps server startup
# fast and avoids a hard dependency on the file existing for unrelated tools.
_SITES_PATH = Path(__file__).resolve().parents[2] / "data" / "sites.json"


# ---- helpers ----------------------------------------------------------------


def _serialise_result(result: QueryResult, *, include_all: bool = True) -> dict[str, Any]:
    """Convert a QueryResult into a JSON-friendly dict with a summary block.

    ``include_all=False`` strips NO_DATA / SKIPPED / UNAVAILABLE rows — the
    "interesting hits only" view most agents want by default.
    """
    payload = result.model_dump(mode="json")
    hits = result.hits
    if not include_all:
        keep = {"found", "ratelimited", "uncertain", "error"}
        hits = [h for h in hits if h.status.value in keep]
        payload["hits"] = [h.model_dump(mode="json") for h in hits]

    summary = {
        "total": len(result.hits),
        "found": result.found,
        "errors": len(result.errors),
        "duration_ms": result.duration_ms,
        "by_status": dict(Counter(h.status.value for h in result.hits)),
        "by_severity": dict(Counter(h.severity.value for h in result.hits)),
    }
    payload["summary"] = summary
    return payload


async def _run_query(kind: QueryKind, value: str, *, include_all: bool = True) -> dict[str, Any]:
    """Build a Query, dispatch through the shared runner, return JSON-friendly dict."""
    if not value or not value.strip():
        raise ValueError(f"empty value for {kind.value} lookup")
    q = Query(kind=kind, value=value.strip())
    result = await runner().run(q)
    return _serialise_result(result, include_all=include_all)


def _text(payload: Any) -> list[mcp_types.TextContent]:
    """Wrap a JSON-serialisable payload as a single TextContent block."""
    body = json.dumps(payload, indent=2, default=str, ensure_ascii=False)
    return [mcp_types.TextContent(type="text", text=body)]


def _load_sites_payload() -> dict[str, Any]:
    """Return the contents of ``data/sites.json`` or an empty stub if missing."""
    try:
        return cast("dict[str, Any]", json.loads(_SITES_PATH.read_text(encoding="utf-8")))
    except FileNotFoundError:
        return {"schema": 1, "sites": []}
    except Exception as e:
        logger.warning("failed to read sites.json: %s", e)
        return {"schema": 1, "sites": [], "_error": str(e)}


# ---- tool registry ----------------------------------------------------------

# Each entry is (tool-name, QueryKind, description, extra-schema-properties).
# We render this into the MCP `tools/list` payload and dispatch on it inside
# `call_tool`. Telegram is appended conditionally at startup time.
_TOOL_KINDS: list[tuple[str, QueryKind, str, dict[str, dict[str, Any]]]] = [
    (
        "lookup_username",
        QueryKind.USERNAME,
        "Probe ~1000 sites for a given username (Sherlock + WhatsMyName).",
        {"username": {"type": "string", "description": "The handle to enumerate, without leading @."}},
    ),
    (
        "lookup_email",
        QueryKind.EMAIL,
        "Email recon — Holehe registration check, breach search, MX/SPF.",
        {"email": {"type": "string", "format": "email", "description": "Target email address."}},
    ),
    (
        "lookup_phone",
        QueryKind.PHONE,
        "Phone number parsing (libphonenumber) + carrier/region metadata.",
        {"phone": {"type": "string", "description": "E.164 phone number, e.g. +14155550143."}},
    ),
    (
        "lookup_whatsapp",
        QueryKind.WHATSAPP,
        "WhatsApp wa.me deep-link probe for a phone number.",
        {"phone": {"type": "string", "description": "E.164 phone number."}},
    ),
    (
        "lookup_domain",
        QueryKind.DOMAIN,
        "Domain recon — crt.sh subdomains, DNS, HackerTarget, urlscan, headers, SSL/TLS, tech fingerprint.",
        {"domain": {"type": "string", "description": "Domain like example.com (no scheme)."}},
    ),
    (
        "lookup_ip",
        QueryKind.IP,
        "IP recon — reverse DNS, IPinfo (if configured), ASN/BGP.",
        {"ip": {"type": "string", "description": "IPv4 or IPv6 address."}},
    ),
]

_TELEGRAM_TOOL = (
    "lookup_telegram",
    QueryKind.TELEGRAM,
    "Telegram username probe — MTProto resolveUsername (if a session is configured) or t.me HTML fallback.",
    {"handle": {"type": "string", "description": "Telegram @handle (with or without @)."}},
)


def _tool_definitions(*, with_telegram: bool) -> list[mcp_types.Tool]:
    """Build the static list of tools exposed by the server."""
    tools: list[mcp_types.Tool] = []

    for name, _kind, desc, extra_props in _TOOL_KINDS:
        # primary key for the query value lives in extra_props (e.g. "email")
        primary = next(iter(extra_props))
        schema = {
            "type": "object",
            "properties": {
                **extra_props,
                "all_results": {
                    "type": "boolean",
                    "description": "Include NO_DATA/SKIPPED/UNAVAILABLE hits (default false).",
                    "default": False,
                },
            },
            "required": [primary],
            "additionalProperties": False,
        }
        tools.append(mcp_types.Tool(name=name, description=desc, inputSchema=schema))

    if with_telegram:
        name, _kind, desc, extra_props = _TELEGRAM_TOOL
        schema = {
            "type": "object",
            "properties": {
                **extra_props,
                "all_results": {
                    "type": "boolean",
                    "description": "Include NO_DATA/SKIPPED/UNAVAILABLE hits (default false).",
                    "default": False,
                },
            },
            "required": ["handle"],
            "additionalProperties": False,
        }
        tools.append(mcp_types.Tool(name=name, description=desc, inputSchema=schema))

    tools.append(
        mcp_types.Tool(
            name="list_modules",
            description="List every registered OSINT module with the kinds it handles.",
            inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
        )
    )
    tools.append(
        mcp_types.Tool(
            name="list_sites_stats",
            description="Return totals and per-category counts for the username probe-site catalogue.",
            inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
        )
    )

    return tools


# ---- tool dispatch ---------------------------------------------------------


def _resolve_tool(name: str, *, with_telegram: bool) -> tuple[QueryKind, str] | None:
    """Map an MCP tool name to (kind, primary-arg-key). Returns None for inventory tools."""
    for tool_name, kind, _desc, extra_props in _TOOL_KINDS:
        if tool_name == name:
            return kind, next(iter(extra_props))
    if with_telegram and name == _TELEGRAM_TOOL[0]:
        return _TELEGRAM_TOOL[1], next(iter(_TELEGRAM_TOOL[3]))
    return None


async def _handle_call_tool(
    name: str, arguments: dict[str, Any] | None, *, with_telegram: bool
) -> list[mcp_types.TextContent]:
    arguments = arguments or {}

    if name == "list_modules":
        from app.ui import tokens

        mods = runner().all_modules()
        modules_payload = [
            {
                "name": m.name,
                "kinds": sorted(k.value for k in m.kinds),
                "enabled": m.enabled,
                "glyph": tokens.MODULE_GLYPHS.get(m.name, "-"),
            }
            for m in mods
        ]
        return _text(modules_payload)

    if name == "list_sites_stats":
        try:
            from app.modules.username import load_sites
            sites = load_sites()
        except Exception as e:
            return _text({"error": f"failed to load sites: {e}", "total": 0, "by_category": {}})
        cats: Counter[str] = Counter((s.get("category") or "uncategorised") for s in sites)
        return _text({"total": sum(cats.values()), "by_category": dict(cats.most_common())})

    resolved = _resolve_tool(name, with_telegram=with_telegram)
    if resolved is None:
        return _text({"error": f"unknown tool: {name}"})

    kind, primary = resolved
    value = arguments.get(primary)
    if not isinstance(value, str) or not value.strip():
        return _text({"error": f"missing required string argument: {primary!r}"})
    include_all = bool(arguments.get("all_results", False))

    try:
        payload = await _run_query(kind, value, include_all=include_all)
    except Exception as e:
        logger.exception("tool %s failed", name)
        return _text({"error": f"{type(e).__name__}: {e}"})
    return _text(payload)


# ---- resources -------------------------------------------------------------


async def _list_resources() -> list[mcp_types.Resource]:
    return [
        mcp_types.Resource(
            uri=AnyUrl(RES_HISTORY),
            name="OSINT query history",
            description="Recent queries saved to the local SQLite history (newest first).",
            mimeType="application/json",
        ),
        mcp_types.Resource(
            uri=AnyUrl(RES_SITES),
            name="Username probe-site catalogue",
            description="The sites.json dataset used by the username module.",
            mimeType="application/json",
        ),
    ]


async def _read_resource(uri: AnyUrl) -> str:
    """Return the JSON body for a resource URI.

    Returning a string makes the MCP framework wrap it as text content.
    """
    s = str(uri)
    if s == RES_HISTORY or s == RES_HISTORY + "/":
        return json.dumps(await _history_payload(), indent=2, default=str, ensure_ascii=False)
    if s.startswith(_HISTORY_ITEM_PREFIX):
        rest = s[len(_HISTORY_ITEM_PREFIX):].rstrip("/")
        try:
            qid = int(rest)
        except ValueError:
            return json.dumps({"error": f"invalid query id: {rest!r}"})
        return json.dumps(await _history_item_payload(qid), indent=2, default=str, ensure_ascii=False)
    if s == RES_SITES:
        return json.dumps(_load_sites_payload(), indent=2, ensure_ascii=False)
    return json.dumps({"error": f"unknown resource: {s}"})


async def _history_payload() -> dict[str, Any]:
    s = settings()
    db = Database(s.db_path)
    try:
        await db.connect()
        rows = await db.list_history(limit=50)
    except Exception as e:
        logger.warning("history read failed: %s", e)
        return {"items": [], "error": str(e)}
    finally:
        with contextlib.suppress(Exception):
            await db.close()
    return {"items": rows, "count": len(rows)}


async def _history_item_payload(query_id: int) -> dict[str, Any]:
    s = settings()
    db = Database(s.db_path)
    try:
        await db.connect()
        q = await db.get_query(query_id)
        if q is None:
            return {"error": f"query {query_id} not found"}
        hits = await db.hits_for(query_id)
    except Exception as e:
        return {"error": str(e)}
    finally:
        with contextlib.suppress(Exception):
            await db.close()
    return {
        "query": q.model_dump(mode="json"),
        "hits": [h.model_dump(mode="json") for h in hits],
        "count": len(hits),
    }


# ---- prompts ---------------------------------------------------------------


_PROMPTS: dict[str, dict[str, Any]] = {
    "digital_footprint_audit": {
        "description": (
            "Comprehensive digital footprint audit for a person — covers usernames, "
            "email exposure, phone presence, and social account enumeration."
        ),
        "arguments": [
            mcp_types.PromptArgument(
                name="target",
                description="Subject identifier — username, email, phone, or full name.",
                required=True,
            ),
        ],
        "template": (
            "Perform a thorough digital footprint audit for the following subject:\n\n"
            "  TARGET: {target}\n\n"
            "Steps:\n"
            "1. If the target looks like a username, call `lookup_username` and summarise the FOUND hits.\n"
            "2. If the target is an email, call `lookup_email` and report breach exposure.\n"
            "3. If the target is a phone number, call `lookup_phone` and `lookup_whatsapp`.\n"
            "4. Cross-reference the discovered accounts — flag any reuse of the same handle across "
            "platforms (a strong signal of identity correlation).\n"
            "5. Output a final report grouped by category (social, dev, forum, breach) with severity ratings."
        ),
    },
    "domain_security_check": {
        "description": (
            "Security posture review for a domain — TLS hygiene, exposed subdomains, "
            "tech stack fingerprint, and HTTP header hardening."
        ),
        "arguments": [
            mcp_types.PromptArgument(
                name="domain",
                description="Domain to inspect, e.g. example.com (no scheme).",
                required=True,
            ),
        ],
        "template": (
            "Perform a security posture review of the domain:\n\n"
            "  DOMAIN: {domain}\n\n"
            "Steps:\n"
            "1. Call `lookup_domain` to enumerate subdomains (crt.sh, HackerTarget) and tech fingerprint.\n"
            "2. Report on TLS: certificate chain, age, weak ciphers, missing SANs.\n"
            "3. Report on HTTP hardening: HSTS, CSP, X-Frame-Options, Referrer-Policy, "
            "Permissions-Policy, X-Content-Type-Options.\n"
            "4. Flag any subdomain that doesn't appear in the certificate SAN list — possible takeover.\n"
            "5. Output the findings with severity (info / low / medium / high / critical) and concrete "
            "remediation actions."
        ),
    },
}


async def _list_prompts() -> list[mcp_types.Prompt]:
    return [
        mcp_types.Prompt(
            name=name,
            description=meta["description"],
            arguments=meta["arguments"],
        )
        for name, meta in _PROMPTS.items()
    ]


async def _get_prompt(name: str, arguments: dict[str, str] | None) -> mcp_types.GetPromptResult:
    arguments = arguments or {}
    meta = _PROMPTS.get(name)
    if meta is None:
        text = f"Unknown prompt: {name!r}"
    else:
        # Missing arguments render as <missing:name> so the agent sees a clear gap
        # rather than a Python KeyError.
        class _SafeDict(dict[str, str]):
            def __missing__(self, key: str) -> str:
                return f"<missing:{key}>"

        text = meta["template"].format_map(_SafeDict(arguments))
    return mcp_types.GetPromptResult(
        description=(meta or {}).get("description"),
        messages=[
            mcp_types.PromptMessage(
                role="user",
                content=mcp_types.TextContent(type="text", text=text),
            )
        ],
    )


# ---- public assembly -------------------------------------------------------


def create_server() -> Server:
    """Build a configured MCP ``Server`` ready to be run over any transport.

    Telegram tools are registered only if ``settings().has_telegram`` is true
    at the moment this function runs — re-create the server after editing the
    user config to pick up a newly-added session.
    """
    # Ensure .env / config.env are loaded so settings().has_telegram reflects
    # the persisted user config, not the bare process environment.
    load_settings()
    with_telegram = settings().has_telegram

    server: Server = Server(SERVER_NAME, version=APP_VERSION)

    # mcp SDK's @server.* registration decorators carry no return annotation
    # (the inner decorator(func) is unannotated upstream), so under strict mypy
    # they read as untyped. Scope the suppression to those exact codes.
    @server.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]  # mcp SDK decorator is unannotated
    async def _on_list_tools() -> list[mcp_types.Tool]:
        return _tool_definitions(with_telegram=with_telegram)

    @server.call_tool()  # type: ignore[untyped-decorator]  # mcp SDK decorator is unannotated
    async def _on_call_tool(name: str, arguments: dict[str, Any] | None) -> list[mcp_types.TextContent]:
        return await _handle_call_tool(name, arguments, with_telegram=with_telegram)

    @server.list_resources()  # type: ignore[no-untyped-call, untyped-decorator]  # mcp SDK decorator is unannotated
    async def _on_list_resources() -> list[mcp_types.Resource]:
        return await _list_resources()

    @server.read_resource()  # type: ignore[no-untyped-call, untyped-decorator]  # mcp SDK decorator is unannotated
    async def _on_read_resource(uri: AnyUrl) -> str:
        return await _read_resource(uri)

    @server.list_prompts()  # type: ignore[no-untyped-call, untyped-decorator]  # mcp SDK decorator is unannotated
    async def _on_list_prompts() -> list[mcp_types.Prompt]:
        return await _list_prompts()

    @server.get_prompt()  # type: ignore[no-untyped-call, untyped-decorator]  # mcp SDK decorator is unannotated
    async def _on_get_prompt(
        name: str, arguments: dict[str, str] | None
    ) -> mcp_types.GetPromptResult:
        return await _get_prompt(name, arguments)

    return server


async def run_stdio() -> None:
    """Run the MCP server over stdio (the transport used by Claude Code / Warp / Cursor)."""
    server = create_server()
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> int:
    """Sync entry point for ``osint mcp``."""
    try:
        asyncio.run(run_stdio())
    except KeyboardInterrupt:
        return 130
    return 0
