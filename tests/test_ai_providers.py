"""LLM provider abstraction — hermetic.

Every test patches the environment (env vars, OPSEC, socket) so nothing escapes
to a real network. The Ollama probe uses an httpx ``MockTransport`` — we never
hit a live daemon.
"""
from __future__ import annotations

import socket

import httpx
import pytest

from app.features import ai as ai_mod
from app.features.ai import (
    ClaudeProvider,
    LLMUnavailable,
    NoneProvider,
    OllamaProvider,
    reset_provider_cache,
    select_provider,
)


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    """Every test starts from a clean env + a flushed provider cache."""
    for key in ("OSINT_AI_PROVIDER", "OSINT_AI_MODEL", "OSINT_OPSEC",
                "ANTHROPIC_API_KEY", "OLLAMA_URL"):
        monkeypatch.delenv(key, raising=False)
    reset_provider_cache()
    yield
    reset_provider_cache()


# --------------------------------------------------------------------------- #
# Selection precedence
# --------------------------------------------------------------------------- #

def test_select_provider_force_none(monkeypatch):
    monkeypatch.setenv("OSINT_AI_PROVIDER", "none")
    assert isinstance(select_provider(), NoneProvider)


def test_select_provider_force_claude_even_without_key(monkeypatch):
    monkeypatch.setenv("OSINT_AI_PROVIDER", "claude")
    p = select_provider()
    assert isinstance(p, ClaudeProvider)
    # Forced but unavailable — caller sees it via .available()
    assert p.available() is False


def test_select_provider_prefers_ollama_when_available(monkeypatch):
    monkeypatch.setattr(OllamaProvider, "available", lambda self: True)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-anything")
    p = select_provider()
    assert isinstance(p, OllamaProvider)


def test_select_provider_falls_back_to_claude_when_ollama_off(monkeypatch):
    monkeypatch.setattr(OllamaProvider, "available", lambda self: False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-anything")
    p = select_provider()
    assert isinstance(p, ClaudeProvider)


def test_select_provider_falls_back_to_none(monkeypatch):
    monkeypatch.setattr(OllamaProvider, "available", lambda self: False)
    # no ANTHROPIC_API_KEY → Claude unavailable
    p = select_provider()
    assert isinstance(p, NoneProvider)


def test_select_provider_cached(monkeypatch):
    """Same key → same instance (no re-probing on every call)."""
    monkeypatch.setattr(OllamaProvider, "available", lambda self: True)
    a = select_provider()
    b = select_provider()
    assert a is b


# --------------------------------------------------------------------------- #
# OPSEC blocks Claude
# --------------------------------------------------------------------------- #

def test_claude_unavailable_under_opsec(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-anything")
    monkeypatch.setenv("OSINT_OPSEC", "1")
    monkeypatch.setattr(OllamaProvider, "available", lambda self: False)
    p = select_provider()
    # OPSEC must NOT silently send prompts to Anthropic.
    assert not isinstance(p, ClaudeProvider)
    assert isinstance(p, NoneProvider)


def test_claude_stream_refuses_under_opsec(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-anything")
    monkeypatch.setenv("OSINT_OPSEC", "1")
    provider = ClaudeProvider()
    with pytest.raises(LLMUnavailable, match="OPSEC"):
        import asyncio
        asyncio.run(provider.stream([{"role": "user", "content": "hi"}]))


def test_opsec_allows_ollama(monkeypatch):
    monkeypatch.setenv("OSINT_OPSEC", "1")
    monkeypatch.setattr(OllamaProvider, "available", lambda self: True)
    assert isinstance(select_provider(), OllamaProvider)


# --------------------------------------------------------------------------- #
# NoneProvider semantics
# --------------------------------------------------------------------------- #

def test_none_provider_always_available():
    assert NoneProvider().available() is True


def test_none_provider_stream_raises():
    import asyncio
    with pytest.raises(LLMUnavailable):
        asyncio.run(NoneProvider().stream([{"role": "user", "content": "x"}]))


@pytest.mark.asyncio
async def test_explain_graceful_under_none(monkeypatch):
    """explain() must NEVER raise when no provider is available."""
    monkeypatch.setenv("OSINT_AI_PROVIDER", "none")
    msg = await ai_mod.explain("anything", pattern=None)
    assert "AI unavailable" in msg


@pytest.mark.asyncio
async def test_nl_to_args_graceful_under_none(monkeypatch):
    monkeypatch.setenv("OSINT_AI_PROVIDER", "none")
    out = await ai_mod.nl_to_args("find phishing for acme.com")
    assert "error" in out


# --------------------------------------------------------------------------- #
# Ollama probe (TCP) — use a fake socket so no daemon is required
# --------------------------------------------------------------------------- #

class _FakeSocket:
    def __init__(self, *, reachable: bool):
        self._reachable = reachable

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def settimeout(self, _t):
        pass

    def connect(self, _addr):
        if not self._reachable:
            raise OSError("connection refused")


def test_ollama_available_on_open_port(monkeypatch):
    monkeypatch.setattr(socket, "socket",
                        lambda *_a, **_k: _FakeSocket(reachable=True))
    assert OllamaProvider().available() is True


def test_ollama_unavailable_on_refused_port(monkeypatch):
    monkeypatch.setattr(socket, "socket",
                        lambda *_a, **_k: _FakeSocket(reachable=False))
    assert OllamaProvider().available() is False


# --------------------------------------------------------------------------- #
# Ollama HTTP stream (MockTransport — no real daemon)
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_ollama_stream_parses_ndjson(monkeypatch):
    """The Ollama API streams NDJSON; assemble the assistant text in order."""
    body = (
        b'{"message":{"content":"Hello"},"done":false}\n'
        b'{"message":{"content":" world"},"done":false}\n'
        b'{"message":{"content":"!"},"done":true}\n'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/chat"
        return httpx.Response(200, content=body)

    fake = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async def _fake_get_client():
        return fake

    monkeypatch.setattr("app.core.http.get_client", _fake_get_client)
    monkeypatch.setattr(ai_mod, "get_client", _fake_get_client)

    received: list[str] = []
    out = await OllamaProvider().stream(
        [{"role": "user", "content": "hi"}],
        on_token=received.append,
    )
    assert out == "Hello world!"
    # Streaming callback called per chunk
    assert received == ["Hello", " world", "!"]


@pytest.mark.asyncio
async def test_ollama_stream_http_5xx_raises_unavailable(monkeypatch):
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="ouch")

    fake = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async def _fake_get_client():
        return fake

    monkeypatch.setattr("app.core.http.get_client", _fake_get_client)
    monkeypatch.setattr(ai_mod, "get_client", _fake_get_client)

    with pytest.raises(LLMUnavailable, match="503"):
        await OllamaProvider().stream([{"role": "user", "content": "x"}])


# --------------------------------------------------------------------------- #
# Model selection
# --------------------------------------------------------------------------- #

def test_ollama_model_from_env(monkeypatch):
    monkeypatch.setenv("OSINT_AI_MODEL", "qwen2.5:7b")
    assert OllamaProvider().model == "qwen2.5:7b"


def test_ollama_model_default():
    assert OllamaProvider().model.startswith("qwen2.5")


# --------------------------------------------------------------------------- #
# Provider cache invalidation when env changes
# --------------------------------------------------------------------------- #

def test_provider_cache_invalidates_when_opsec_flips(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-x")
    monkeypatch.setattr(OllamaProvider, "available", lambda self: False)
    a = select_provider()
    assert isinstance(a, ClaudeProvider)
    monkeypatch.setenv("OSINT_OPSEC", "1")
    b = select_provider()
    # New key in cache → new provider chosen (Claude is now blocked).
    assert isinstance(b, NoneProvider)
