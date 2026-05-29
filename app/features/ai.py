"""AI-assisted analysis — `osint ai explain` / `osint ai query`.

Two sub-commands:
  osint ai explain <kind> <value> [--pattern NAME]
      Pulls the most recent saved scan from the DB and asks the active
      LLM provider for a structured executive summary.

  osint ai query "find phishing infra targeting acme.com"
      Translates natural language → (profile, kind, target) and runs it.

  osint ai patterns [list]
      List externalised report patterns.

This module is intentionally local-first. Providers are resolved by
:func:`select_provider`; if nothing is available we degrade gracefully
to a friendly message rather than crashing — `osint` is supposed to run
on user laptops with no cloud dependency.

Provider order (when ``OSINT_AI_PROVIDER`` is unset):
  Ollama (local, free, OPSEC-safe)  →  Claude (cloud, paid)  →  None
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
import sys
from collections.abc import Awaitable, Callable
from typing import Any, Protocol, runtime_checkable

from app.core.config import load_settings, settings
from app.core.db import Database
from app.core.http import _opsec_on, get_client

# Public constants — kept stable for callers / tests.
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-haiku-4-5"
OLLAMA_URL = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "qwen2.5:3b"

# Type for the streaming token callback. Synchronous on purpose so callers can
# `print(t, end="")` without faffing about with an event loop.
OnToken = Callable[[str], None]


class LLMUnavailable(RuntimeError):
    """Raised when the selected provider has no way to serve a request."""


@runtime_checkable
class LLMProvider(Protocol):
    """Minimal contract every provider implements.

    Implementations are free to do anything they like inside ``stream`` — yield
    one token, one chunk per network frame, or even the whole reply at once.
    The return value is always the full assembled text.
    """

    name: str

    def available(self) -> bool: ...

    async def stream(
        self,
        messages: list[dict[str, str]],
        *,
        max_tokens: int = 800,
        on_token: OnToken | None = None,
    ) -> str: ...


# --------------------------------------------------------------------------- #
# Concrete providers
# --------------------------------------------------------------------------- #

class OllamaProvider:
    """Local LLM via Ollama's HTTP API.

    Honours ``OSINT_AI_MODEL`` (else ``qwen2.5:3b`` — ~2 GB Q4, runs on
    a base Apple Silicon laptop). ``available()`` does a 250 ms TCP ping so a
    cold/no-network laptop returns false in well under a second.
    """

    name = "ollama"

    def __init__(self, base_url: str | None = None, model: str | None = None) -> None:
        self.base_url = (base_url or os.getenv("OLLAMA_URL") or OLLAMA_URL).rstrip("/")
        self.model = model or os.getenv("OSINT_AI_MODEL") or DEFAULT_OLLAMA_MODEL

    def available(self) -> bool:
        # We avoid an HTTP probe here because httpx pulls in the shared client
        # (and a real network round-trip). A raw TCP ping on port 11434 is the
        # cheapest signal: Ollama listens there if the daemon is up.
        host, _, port = self.base_url.replace("https://", "").replace("http://", "").partition(":")
        port = port.split("/", 1)[0] or "11434"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.25)
                s.connect((host or "localhost", int(port)))
            return True
        except OSError:
            return False

    async def stream(
        self,
        messages: list[dict[str, str]],
        *,
        max_tokens: int = 800,
        on_token: OnToken | None = None,
    ) -> str:
        client = await get_client()
        body = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            "options": {"num_predict": max_tokens},
        }
        buf: list[str] = []
        url = f"{self.base_url}/api/chat"
        try:
            async with client.stream("POST", url, json=body, timeout=120.0) as resp:
                if resp.status_code != 200:
                    raise LLMUnavailable(
                        f"Ollama HTTP {resp.status_code} at {url}",
                    )
                async for line in resp.aiter_lines():
                    if not line:
                        continue
                    try:
                        evt = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    msg = evt.get("message") or {}
                    chunk = msg.get("content", "")
                    if chunk:
                        buf.append(chunk)
                        if on_token:
                            with contextlib.suppress(Exception):
                                on_token(chunk)
                    if evt.get("done"):
                        break
        except (OSError, RuntimeError) as e:
            raise LLMUnavailable(f"Ollama stream failed: {e}") from e
        return "".join(buf)


class ClaudeProvider:
    """Anthropic Claude — wraps the existing /v1/messages call.

    Disabled under OPSEC: every prompt would leave the host. We want the user
    to consciously toggle OPSEC off before sending recon findings to a 3rd-party.
    """

    name = "claude"

    def __init__(self, model: str | None = None) -> None:
        self.model = model or os.getenv("OSINT_AI_MODEL") or DEFAULT_MODEL

    def _api_key(self) -> str:
        return os.getenv("ANTHROPIC_API_KEY", "").strip()

    def available(self) -> bool:
        if _opsec_on():
            return False
        return bool(self._api_key())

    async def stream(
        self,
        messages: list[dict[str, str]],
        *,
        max_tokens: int = 800,
        on_token: OnToken | None = None,
    ) -> str:
        if _opsec_on():
            raise LLMUnavailable("Claude disabled under OPSEC (queries would leave host)")
        key = self._api_key()
        if not key:
            raise LLMUnavailable("ANTHROPIC_API_KEY unset")
        system = ""
        user_msgs: list[dict[str, str]] = []
        for m in messages:
            if m.get("role") == "system":
                system = (system + "\n" + m.get("content", "")).strip()
            else:
                user_msgs.append({"role": m["role"], "content": m["content"]})
        body: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": user_msgs or [{"role": "user", "content": ""}],
        }
        if system:
            body["system"] = system
        client = await get_client()
        try:
            r = await client.post(
                ANTHROPIC_URL,
                json=body,
                headers={
                    "x-api-key": key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                timeout=60.0,
            )
        except OSError as e:
            raise LLMUnavailable(f"Anthropic network error: {e}") from e
        if r.status_code != 200:
            raise LLMUnavailable(f"Anthropic HTTP {r.status_code}: {r.text[:200]}")
        data = r.json()
        parts = data.get("content") or []
        text = "".join(p.get("text", "") for p in parts if isinstance(p, dict))
        if on_token and text:
            with contextlib.suppress(Exception):
                on_token(text)
        return text


class NoneProvider:
    """No-op provider — keeps the CLI from crashing on hosts with no LLM.

    Always ``available()`` so :func:`select_provider` always returns *something*;
    callers can decide whether to call ``stream`` or just print a hint.
    """

    name = "none"

    def available(self) -> bool:
        return True

    async def stream(
        self,
        messages: list[dict[str, str]],
        *,
        max_tokens: int = 800,
        on_token: OnToken | None = None,
    ) -> str:
        raise LLMUnavailable(
            "AI unavailable — set OSINT_AI_PROVIDER or run Ollama "
            "(`ollama pull qwen2.5:3b`)",
        )


# --------------------------------------------------------------------------- #
# Selection + caching
# --------------------------------------------------------------------------- #

_PROVIDER_CACHE: LLMProvider | None = None
_PROVIDER_CACHE_KEY: tuple[str, str, bool] | None = None


def _cache_key() -> tuple[str, str, bool]:
    """Key the cached provider on the variables that change its identity."""
    return (
        os.getenv("OSINT_AI_PROVIDER", "").strip().lower(),
        os.getenv("ANTHROPIC_API_KEY", "").strip(),
        _opsec_on(),
    )


def select_provider() -> LLMProvider:
    """Return the active provider, caching the choice for the process lifetime.

    Order (when ``OSINT_AI_PROVIDER`` is unset): Ollama → Claude → None.
    ``OSINT_AI_PROVIDER=ollama|claude|none`` forces a specific provider — when
    the forced one isn't available we still return it so the caller can show
    a meaningful error rather than silently falling back.
    """
    global _PROVIDER_CACHE, _PROVIDER_CACHE_KEY
    key = _cache_key()
    if _PROVIDER_CACHE is not None and key == _PROVIDER_CACHE_KEY:
        return _PROVIDER_CACHE

    forced = key[0]
    chosen: LLMProvider
    if forced == "ollama":
        chosen = OllamaProvider()
    elif forced == "claude":
        chosen = ClaudeProvider()
    elif forced == "none":
        chosen = NoneProvider()
    else:
        candidates: list[LLMProvider] = [OllamaProvider(), ClaudeProvider()]
        chosen = next((p for p in candidates if p.available()), NoneProvider())

    _PROVIDER_CACHE = chosen
    _PROVIDER_CACHE_KEY = key
    return chosen


def reset_provider_cache() -> None:
    """Drop the cached provider — exposed for tests that mutate env vars."""
    global _PROVIDER_CACHE, _PROVIDER_CACHE_KEY
    _PROVIDER_CACHE = None
    _PROVIDER_CACHE_KEY = None


# --------------------------------------------------------------------------- #
# Public AI helpers (used by the explain CLI and the chat shell)
# --------------------------------------------------------------------------- #

SUMMARISE_SYSTEM = """You are a senior threat-intel analyst. The user pastes
the raw findings from a single OSINT scan. Produce a short executive summary:
  1. ONE-LINE verdict (critical/high/medium/low risk + why)
  2. Top 5 findings, ranked by impact, each ONE concise line
  3. Three concrete next-step actions for the analyst
Output as Markdown. Be direct, not vague. NO disclaimers. NO restating obvious facts."""


QUERY_SYSTEM = """You translate a natural-language threat-intel question into
a single mytools-osint CLI invocation. Output ONLY a JSON object:
  {"kind": "domain|ip|email|username|phone|telegram|hash",
   "target": "<the entity>",
   "profile": "quick|deep|person|domain-recon|red-team|blue-team|ioc|creds|leak-hunt",
   "pivot": 0|1|2}

If you cannot extract a clear target, return {"error": "..."}."""


_UNAVAILABLE_MSG = (
    "AI unavailable — set OSINT_AI_PROVIDER or run Ollama "
    "(`ollama pull qwen2.5:3b` then `ollama serve`). Use `osint doctor` for a "
    "full diagnostic."
)


async def explain(
    payload: str,
    *,
    system: str = SUMMARISE_SYSTEM,
    max_tokens: int = 1200,
    on_token: OnToken | None = None,
    pattern: str | None = None,
) -> str:
    """Summarise findings via the active provider.

    Returns a friendly hint string (NOT raising) when no provider is configured
    — `osint` must keep working on laptops without an LLM installed.
    """
    provider = select_provider()
    if isinstance(provider, NoneProvider):
        return _UNAVAILABLE_MSG
    # Pattern is a thin Markdown template; render it around the payload.
    if pattern:
        try:
            from app.features.patterns import load_pattern
            pat = load_pattern(pattern)
            system = pat.system_block() or system
            user_content = pat.render({"PAYLOAD": payload})
        except FileNotFoundError as e:
            return f"AI explain failed: {e}"
    else:
        user_content = payload
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user_content},
    ]
    try:
        return await provider.stream(messages, max_tokens=max_tokens, on_token=on_token)
    except LLMUnavailable as e:
        return f"AI unavailable ({provider.name}): {e}"


async def nl_to_args(text: str) -> dict[str, Any]:
    """Ask the LLM to translate natural-language → osint CLI args.

    Returns ``{"error": "..."}`` on any failure (no exceptions thrown) so the
    caller can show one consistent error path.
    """
    provider = select_provider()
    if isinstance(provider, NoneProvider):
        return {"error": _UNAVAILABLE_MSG}
    messages = [
        {"role": "system", "content": QUERY_SYSTEM},
        {"role": "user", "content": text},
    ]
    try:
        raw = await provider.stream(messages, max_tokens=200)
    except LLMUnavailable as e:
        return {"error": f"{provider.name}: {e}"}
    try:
        start = raw.index("{")
        end = raw.rindex("}") + 1
        return json.loads(raw[start:end])
    except (ValueError, json.JSONDecodeError):
        return {"error": f"could not parse AI response: {raw[:200]}"}


# --------------------------------------------------------------------------- #
# CLI plumbing
# --------------------------------------------------------------------------- #

async def _explain(kind: str, value: str, *, pattern: str | None = None) -> int:
    load_settings()
    db = Database(settings().db_path)
    await db.connect()
    try:
        assert db._conn is not None
        async with db._conn.execute(
            "SELECT id FROM queries WHERE kind = ? AND value = ? "
            "ORDER BY id DESC LIMIT 1",
            (kind, value),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            print(f"  no saved scan found for {kind}={value} — run it first.",
                  file=sys.stderr)
            return 1
        qid = row["id"]
        async with db._conn.execute(
            "SELECT module, source, status, severity, title, detail, url "
            "FROM hits WHERE query_id = ? ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            " WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",
            (qid,),
        ) as cur:
            hrows = await cur.fetchall()
        positives = [dict(r) for r in hrows if r["status"] == "found"]
        if not positives:
            print("  scan has no positive findings to explain.")
            return 0
        payload = json.dumps([
            {"module": h["module"], "src": h["source"],
             "sev": h["severity"], "title": h["title"],
             "detail": (h["detail"] or "")[:200],
             "url": h["url"][:160] if h["url"] else ""}
            for h in positives[:80]
        ], indent=2, default=str)
        provider = select_provider()
        print(f"  ↻ explaining {len(positives)} findings via {provider.name}…",
              file=sys.stderr)
        text = await explain(
            f"Target: {kind}={value}\nFindings (top {len(positives[:80])} "
            f"of {len(positives)} positives):\n```json\n{payload}\n```\n",
            pattern=pattern or "exec-summary",
        )
        print("\n" + text + "\n")
        return 0
    finally:
        await db.close()


async def _nl_query(text: str) -> int:
    parsed = await nl_to_args(text)
    if "error" in parsed:
        print(f"  ai query failed: {parsed['error']}", file=sys.stderr)
        return 1
    target = parsed.get("target", "")
    if not target:
        print("  AI returned no target", file=sys.stderr)
        return 1
    new_argv = [target]
    if parsed.get("kind"):
        new_argv += ["--kind", parsed["kind"]]
    if parsed.get("profile"):
        new_argv += ["--profile", parsed["profile"]]
    if parsed.get("pivot"):
        new_argv += ["--pivot", str(parsed["pivot"])]
    print(f"  ↻ AI translated → osint {' '.join(new_argv)}", file=sys.stderr)
    from cli import main as _main
    return _main(new_argv)


def _patterns_cmd(argv: list[str]) -> int:
    """`osint ai patterns list` — enumerate built-in + user patterns."""
    from app.features.patterns import list_patterns, pattern_dirs
    if argv and argv[0] not in ("list", "ls"):
        print("usage: osint ai patterns [list]", file=sys.stderr)
        return 2
    names = list_patterns()
    if not names:
        print("  no patterns found.")
        return 0
    builtin_dir, user_dir = pattern_dirs()
    print(f"  built-in: {builtin_dir}")
    print(f"  user:     {user_dir} (overrides built-in)")
    print()
    for n in names:
        print(f"  • {n}")
    return 0


def cmd_ai(argv: list[str]) -> int:
    """Dispatch for `osint ai ...`."""
    if not argv or argv[0] in ("-h", "--help"):
        provider = select_provider()
        print(
            "usage: osint ai <explain|query|patterns> ...\n\n"
            "  ai explain <kind> <value> [--pattern NAME]\n"
            "      summarise the most recent saved scan via the active LLM\n"
            "  ai query \"natural-language\"\n"
            "      translate to osint args + run\n"
            "  ai patterns [list]\n"
            "      list externalised report patterns (Fabric-style)\n\n"
            f"  active provider: {provider.name}\n"
            "  set OSINT_AI_PROVIDER to ollama|claude|none to override.\n"
            "  Claude is disabled under --opsec (queries would leave host).",
            file=sys.stderr,
        )
        return 0 if argv else 2
    sub = argv[0]
    if sub == "explain" and len(argv) >= 3:
        pattern: str | None = None
        rest = argv[3:]
        if "--pattern" in rest:
            idx = rest.index("--pattern")
            if idx + 1 < len(rest):
                pattern = rest[idx + 1]
        return asyncio.run(_explain(argv[1], argv[2], pattern=pattern))
    if sub == "query" and len(argv) >= 2:
        return asyncio.run(_nl_query(" ".join(argv[1:])))
    if sub == "patterns":
        return _patterns_cmd(argv[1:])
    print("usage: osint ai <explain|query|patterns> ...", file=sys.stderr)
    return 2


# Backwards-compat re-exports (some tests / imports may still reference these).
async def _claude(prompt: str, system: str = "", *, model: str | None = None,
                  max_tokens: int = 800) -> str:
    """Legacy thin wrapper — kept so older callers don't crash. Uses the
    active provider, which is Claude when ANTHROPIC_API_KEY is set + OPSEC off."""
    _ = model  # legacy signature parity; provider chooses its own default
    provider = select_provider()
    msgs = ([{"role": "system", "content": system}] if system else []) + [
        {"role": "user", "content": prompt},
    ]
    return await provider.stream(msgs, max_tokens=max_tokens)


def _api_key() -> str:
    return os.getenv("ANTHROPIC_API_KEY", "").strip()


# Keep `Awaitable` import alive for type-checkers in this file.
_ = Awaitable
