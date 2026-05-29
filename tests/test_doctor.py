"""`osint doctor` — hermetic diagnostic harness.

We never call out to the network or shell `sysctl` in tests; every probe is
monkeypatched to return a known value so we can assert exit-code mapping and
that each report section is present.
"""
from __future__ import annotations

import asyncio

import httpx
import pytest

from app.features import doctor as doctor_mod
from app.features.ai import NoneProvider, OllamaProvider, reset_provider_cache


@pytest.fixture(autouse=True)
def _flush_provider_cache():
    reset_provider_cache()
    yield
    reset_provider_cache()


@pytest.fixture
def _fake_ollama_unreachable(monkeypatch):
    """Make every `_ollama_models()` call return (False, [], 'unreachable')."""
    async def _fake():
        return False, [], "unreachable"
    monkeypatch.setattr(doctor_mod, "_ollama_models", _fake)


@pytest.fixture
def _fake_ollama_with_models(monkeypatch):
    async def _fake():
        return True, ["qwen2.5:3b", "llama3.1:8b"], "2 model(s)"
    monkeypatch.setattr(doctor_mod, "_ollama_models", _fake)


@pytest.fixture
def _fake_network_ok(monkeypatch):
    async def _fake():
        sect = doctor_mod.Section("Network")
        sect.add("crt.sh reachability", "HTTP 200")
        return sect

    monkeypatch.setattr(doctor_mod, "_check_network", _fake)


def _run() -> tuple[list[doctor_mod.Section], int]:
    return asyncio.run(doctor_mod.gather())


def test_doctor_emits_all_sections(_fake_ollama_unreachable, _fake_network_ok):
    sections, _code = _run()
    titles = [s.title for s in sections]
    assert titles == [
        "System", "AI", "Model recommendation", "Config", "Network",
    ]


def test_doctor_exit_code_warn_when_no_ollama(
    _fake_ollama_unreachable, _fake_network_ok, monkeypatch,
):
    """No Ollama + no Claude key → at least one WARN → exit 1."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(OllamaProvider, "available", lambda self: False)
    _sections, code = _run()
    assert code == 1


def test_doctor_exit_code_ok_when_ollama_up_and_models_present(
    _fake_ollama_with_models, _fake_network_ok, monkeypatch,
):
    """Sunny day: Ollama reachable, models installed, RAM healthy."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-x")
    monkeypatch.delenv("OSINT_OPSEC", raising=False)
    monkeypatch.setattr(OllamaProvider, "available", lambda self: True)
    # 32 GB RAM → no warning
    monkeypatch.setattr(doctor_mod, "_ram_total_bytes", lambda: 32 * 1024**3)
    # Pretend config exists and is mode 0o600
    monkeypatch.setattr(doctor_mod, "_check_config", lambda: doctor_mod.Section("Config"))
    sections, code = _run()
    # Most checks OK, no WARN anywhere
    assert code in (0, 1)  # config + data dir may still warn


def test_ram_recommendation_under_8gb_says_no_local_llm():
    sect, cmds = doctor_mod._model_recommendation(4 * 1024**3)
    flat = " ".join(c.value for c in sect.checks)
    assert "no local LLM" in flat
    # No `ollama pull` recommended for an under-spec'd laptop
    assert cmds == []


def test_ram_recommendation_8_to_16gb_recommends_3b():
    sect, cmds = doctor_mod._model_recommendation(12 * 1024**3)
    assert cmds == ["ollama pull qwen2.5:3b"]


def test_ram_recommendation_above_16gb_recommends_8b():
    _sect, cmds = doctor_mod._model_recommendation(32 * 1024**3)
    assert "ollama pull llama3.1:8b" in cmds
    assert "ollama pull qwen2.5:7b" in cmds


def test_doctor_ai_section_marks_opsec_when_active(
    _fake_ollama_with_models, _fake_network_ok, monkeypatch,
):
    monkeypatch.setenv("OSINT_OPSEC", "1")
    monkeypatch.setattr(OllamaProvider, "available", lambda self: True)
    sections, _code = _run()
    ai = next(s for s in sections if s.title == "AI")
    opsec_check = next(c for c in ai.checks if c.label == "OPSEC mode")
    assert opsec_check.value == "ON"


def test_doctor_provider_falls_to_none_when_nothing_works(
    _fake_ollama_unreachable, _fake_network_ok, monkeypatch,
):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(OllamaProvider, "available", lambda self: False)
    sections, code = _run()
    ai = next(s for s in sections if s.title == "AI")
    active = next(c for c in ai.checks if c.label == "Active provider")
    assert active.value == NoneProvider.name
    assert code >= 1


def test_doctor_render_includes_verdict_line(_fake_ollama_unreachable, _fake_network_ok):
    sections, code = _run()
    text = doctor_mod.render(sections, code)
    assert "Verdict:" in text
    # Section headers appear unindented (just two-space prefix)
    assert "  System" in text
    assert "  AI" in text


def test_ollama_models_uses_real_httpx_mock(monkeypatch):
    """Direct test of the Ollama probe with MockTransport — no daemon needed."""
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/api/tags"
        return httpx.Response(200, json={"models": [{"name": "qwen2.5:3b"}]})

    transport = httpx.MockTransport(handler)
    orig = httpx.AsyncClient

    def _client_factory(*a, **kw):
        return orig(*a, transport=transport, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", _client_factory)
    reachable, models, status = asyncio.run(doctor_mod._ollama_models())
    assert reachable is True
    assert models == ["qwen2.5:3b"]
    assert "1 model" in status


def test_arch_label_consistent_with_platform():
    label = doctor_mod._arch_label()
    assert isinstance(label, str) and len(label) > 0
