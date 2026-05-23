"""Adjacency module — surfaces follow-up queries from GitHub + Keybase.

We mock the HTTP layer so we can exercise the harvesters deterministically
and verify the per-query cap (≤ MAX_ADJACENT_HITS) is enforced.
"""
from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from app.core import http as http_mod
from app.core.types import HitStatus, Query, QueryKind, Severity
from app.modules import adjacency


@pytest.fixture
def mock_client(monkeypatch: pytest.MonkeyPatch) -> Callable[[Callable[[httpx.Request], httpx.Response]], None]:
    """Install a MockTransport-backed client. Patches both the shared
    `app.core.http.get_client` and the imported-by-name copy inside the
    `adjacency` module so all of its outbound calls hit the mock."""
    def install(handler: Callable[[httpx.Request], httpx.Response]) -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5)

        async def _get_client() -> httpx.AsyncClient:
            return client

        monkeypatch.setattr(http_mod, "get_client", _get_client, raising=False)
        monkeypatch.setattr(adjacency, "get_client", _get_client, raising=False)

    yield install


_GH_PROFILE_HTML = """
<html><head><title>tester · GitHub</title></head><body>
<main>
  <ul class="vcard-details">
    <li itemprop="email"><a href="mailto:tester@example.com">tester@example.com</a></li>
    <li itemprop="url"><a href="https://tester.dev/" rel="nofollow me">https://tester.dev/</a></li>
  </ul>
  <a href="https://twitter.com/tester_handle">Twitter</a>
</main>
</body></html>
"""

_KEYBASE_PROOFS = {
    "them": {
        "proofs_summary": {
            "all": [
                {"proof_type": "twitter", "nametag": "tester_kb",
                 "service_url": "https://twitter.com/tester_kb"},
                {"proof_type": "reddit", "nametag": "tester_reddit",
                 "service_url": "https://reddit.com/u/tester_reddit"},
                {"proof_type": "github", "nametag": "tester_gh",
                 "service_url": "https://github.com/tester_gh"},
                {"proof_type": "generic_web_site", "nametag": "https://tester.dev",
                 "service_url": "https://tester.dev"},
            ],
        },
    },
}


@pytest.mark.asyncio
async def test_emits_email_blog_twitter_from_github_html(mock_client):
    def handler(req: httpx.Request) -> httpx.Response:
        url = str(req.url)
        if "github.com" in url:
            return httpx.Response(200, text=_GH_PROFILE_HTML)
        if "keybase.io" in url:
            return httpx.Response(404)
        return httpx.Response(404)

    mock_client(handler)
    q = Query(kind=QueryKind.USERNAME, value="tester")
    hits = [h async for h in adjacency.run(q)]
    # All hits are LOW severity, source starts with the adjacent-suggestion prefix.
    assert hits, "expected at least one adjacency hit"
    assert all(h.severity == Severity.LOW for h in hits), \
        [h.severity for h in hits]
    assert all(h.source.startswith("adjacent suggestion · ") for h in hits)
    # The 3 candidates we planted must surface.
    kinds_values = {(h.extra["suggested_kind"], h.extra["suggested_value"]) for h in hits}
    assert ("email", "tester@example.com") in kinds_values
    assert ("domain", "tester.dev") in kinds_values
    assert ("username", "tester_handle") in kinds_values


@pytest.mark.asyncio
async def test_cap_at_three_hits(mock_client):
    """Even with overlapping signals from GitHub + Keybase, total ≤ 3."""
    def handler(req: httpx.Request) -> httpx.Response:
        url = str(req.url)
        if "github.com" in url:
            return httpx.Response(200, text=_GH_PROFILE_HTML)  # already 3 candidates
        if "keybase.io" in url:
            return httpx.Response(200, json=_KEYBASE_PROOFS)
        return httpx.Response(404)

    mock_client(handler)
    q = Query(kind=QueryKind.USERNAME, value="tester")
    hits = [h async for h in adjacency.run(q) if h.category == "adjacency"]
    # Drop any outage hits — only real suggestions are capped.
    suggestions = [h for h in hits if "suggested_kind" in h.extra]
    assert len(suggestions) <= adjacency.MAX_ADJACENT_HITS


@pytest.mark.asyncio
async def test_keybase_only_when_github_empty(mock_client):
    """GitHub returns 404 → Keybase picks up the slack."""
    def handler(req: httpx.Request) -> httpx.Response:
        url = str(req.url)
        if "github.com" in url:
            return httpx.Response(404)
        if "keybase.io" in url:
            return httpx.Response(200, json=_KEYBASE_PROOFS)
        return httpx.Response(404)

    mock_client(handler)
    q = Query(kind=QueryKind.USERNAME, value="tester")
    hits = [h async for h in adjacency.run(q)]
    suggestions = [h for h in hits if "suggested_kind" in (h.extra or {})]
    assert suggestions, "expected at least one keybase-derived suggestion"
    sources = {h.source for h in suggestions}
    assert any("keybase" in s for s in sources)


@pytest.mark.asyncio
async def test_github_outage_yields_info_hit(mock_client):
    def handler(req: httpx.Request) -> httpx.Response:
        url = str(req.url)
        if "github.com" in url:
            return httpx.Response(503)
        if "keybase.io" in url:
            return httpx.Response(404)
        return httpx.Response(404)

    mock_client(handler)
    q = Query(kind=QueryKind.USERNAME, value="tester")
    hits = [h async for h in adjacency.run(q)]
    # We expect an UNAVAILABLE-style outage hit for github.
    outage = [h for h in hits if "github fetch" in h.source]
    assert outage and outage[0].status == HitStatus.UNAVAILABLE


@pytest.mark.asyncio
async def test_non_username_kind_is_noop(mock_client):
    """The module only registers for USERNAME — calling it with EMAIL is a no-op."""
    called = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(200, text="")

    mock_client(handler)
    q = Query(kind=QueryKind.EMAIL, value="a@b.co")
    hits = [h async for h in adjacency.run(q)]
    assert hits == []
    assert called["n"] == 0


def test_module_registers_only_username():
    from app.core.runner import Runner
    r = Runner()
    adjacency.register(r)
    entries = r.all_modules()
    assert len(entries) == 1
    assert entries[0].name == "adjacency"
    assert entries[0].kinds == frozenset({QueryKind.USERNAME})
