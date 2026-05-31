"""Lock in BUG#1 fix: graphql_probe must recognize 401/403 + JSON-error responses
as 'GraphQL endpoint exists' (not just 200)."""
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.types import Query, QueryKind
from app.modules.waf_cms_graphql import _gql_run


def _fake_response(status_code: int, body=None, content_type="application/json"):
    r = MagicMock()
    r.status_code = status_code
    r.headers = {"content-type": content_type}
    if isinstance(body, dict):
        r.json = MagicMock(return_value=body)
        r.text = json.dumps(body)
    else:
        r.json = MagicMock(side_effect=ValueError("not json"))
        r.text = body or ""
    return r


async def _collect(target):
    out = []
    async for h in _gql_run(Query(value=target, kind=QueryKind.DOMAIN)):
        out.append(h)
    return out


def test_graphql_401_detected_as_auth_walled():
    """github.com-like endpoint returns 401 → must surface as HIGH severity."""
    with patch("app.modules.waf_cms_graphql.get_client", new=AsyncMock()) as m:
        client = AsyncMock()
        client.post = AsyncMock(return_value=_fake_response(401, "Unauthorized", "text/plain"))
        m.return_value = client
        hits = asyncio.run(_collect("example.com"))
    assert len(hits) >= 1, "401 must produce a hit"
    h = hits[0]
    assert h.severity.value == "high"
    assert "auth" in h.detail.lower() or "401" in h.detail


def test_graphql_403_detected_as_auth_walled():
    with patch("app.modules.waf_cms_graphql.get_client", new=AsyncMock()) as m:
        client = AsyncMock()
        client.post = AsyncMock(return_value=_fake_response(403, "Forbidden", "text/plain"))
        m.return_value = client
        hits = asyncio.run(_collect("example.com"))
    assert len(hits) >= 1
    assert hits[0].severity.value == "high"


def test_graphql_422_with_errors_json_detected():
    """Endpoint returns 422 + GraphQL-shape errors JSON → exists, query rejected."""
    with patch("app.modules.waf_cms_graphql.get_client", new=AsyncMock()) as m:
        client = AsyncMock()
        client.post = AsyncMock(return_value=_fake_response(422, {"errors": [{"message": "bad query"}]}))
        m.return_value = client
        hits = asyncio.run(_collect("example.com"))
    assert len(hits) >= 1


def test_graphql_404_html_not_detected():
    """Random 404 with HTML → must NOT produce a false-positive hit."""
    with patch("app.modules.waf_cms_graphql.get_client", new=AsyncMock()) as m:
        client = AsyncMock()
        client.post = AsyncMock(return_value=_fake_response(404, "<html>not found</html>", "text/html"))
        m.return_value = client
        hits = asyncio.run(_collect("example.com"))
    assert len(hits) == 0, f"404 HTML must not yield hits, got {hits}"


def test_graphql_200_with_real_schema_detected_as_introspection():
    types = [{"name": f"T{i}"} for i in range(20)]
    body = {"data": {"__schema": {"types": types}}}
    with patch("app.modules.waf_cms_graphql.get_client", new=AsyncMock()) as m:
        client = AsyncMock()
        client.post = AsyncMock(return_value=_fake_response(200, body))
        m.return_value = client
        hits = asyncio.run(_collect("example.com"))
    assert len(hits) >= 1
    assert any("introspection" in h.title.lower() and h.severity.value == "high" for h in hits)
