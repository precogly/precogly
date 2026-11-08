"""The tools as a client sees them, over the real protocol.

`mcp.client.Client` drives an `MCPServer` over in-memory streams, so these exercise
`tools/list` and `tools/call` as Claude Code would. `request` is a fake that answers
from a dictionary and records what it was asked.

In-memory streams carry no bearer token, so nothing runs the SDK's auth middleware.
The tests set the context variable that middleware would have set, before the client
starts, so the server's tasks inherit it.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import anyio
import pytest
from mcp.client import Client
from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.types import TextContent

from precogly_mcp import tools
from precogly_mcp.server import build_server

pytestmark = pytest.mark.anyio

# Shapes copied from the API: dj-rest-auth's user details, and the organization list,
# paginated and camelCased.
RESPONSES: dict[str, Any] = {
    "/api/auth/user/": {
        "pk": 7,
        "username": "ana@kestrel.test",
        "email": "ana@kestrel.test",
        "firstName": "Ana",
        "lastName": "Reyes",
    },
    "/api/organizations/": {
        "count": 1,
        "next": None,
        "previous": None,
        "results": [
            {
                "id": 3,
                "name": "Kestrel",
                "plan": "team",
                "businessUnitLabel": "Business unit",
                "myRole": "security_team",
            }
        ],
    },
}


async def fake_schema() -> dict[str, Any]:
    return {"paths": {"/api/auth/user/": {"get": {"summary": "Current user"}}}}


def server(request: FakeRequest) -> MCPServer:
    return build_server(request=request, schema=fake_schema)


class FakeRequest:
    def __init__(self) -> None:
        self.calls: list[tuple[AccessToken, str, str]] = []

    async def __call__(self, access_token: AccessToken, method: str, path: str) -> Any:
        self.calls.append((access_token, method, path))
        return RESPONSES[path]


@pytest.fixture
def access_token() -> Iterator[AccessToken]:
    token = AccessToken(
        token="t", client_id="claude-code", scopes=["read"], subject="7"
    )
    reset = auth_context_var.set(AuthenticatedUser(token))
    yield token
    auth_context_var.reset(reset)


async def call_whoami(request: FakeRequest) -> Any:
    async with Client(server(request)) as client:
        return await client.call_tool("whoami", {})


async def test_whoami_returns_the_user_their_organizations_and_scopes(
    access_token: AccessToken,
) -> None:
    request = FakeRequest()

    result = await call_whoami(request)

    assert not result.is_error, result.content
    assert json.loads(result.content[0].text) == {
        "user": RESPONSES["/api/auth/user/"],
        "organizations": RESPONSES["/api/organizations/"]["results"],
        "scopes": ["read"],
    }
    assert request.calls == [
        (access_token, "GET", "/api/auth/user/"),
        (access_token, "GET", "/api/organizations/"),
    ]


async def test_whoami_refuses_to_run_without_a_token() -> None:
    result = await call_whoami(FakeRequest())

    assert result.is_error


async def test_whoami_is_advertised_read_only_with_no_arguments() -> None:
    async with Client(server(FakeRequest())) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
    tool = tools["whoami"]

    assert tool.title == "Who am I"
    # `ctx` is stripped by its `Context` annotation. A wrong annotation would
    # advertise it as an argument no caller can supply.
    assert tool.input_schema.get("properties", {}) == {}
    assert tool.annotations is not None
    assert tool.annotations.read_only_hint is True
    assert tool.annotations.open_world_hint is False


async def test_search_runs_code_over_the_spec_in_the_sandbox() -> None:
    code = '[(path, method) for path, ops in spec["paths"].items() for method in ops]'

    async with Client(server(FakeRequest())) as client:
        result = await client.call_tool("search", {"code": code})

    assert not result.is_error, result.content
    (content,) = result.content
    assert isinstance(content, TextContent)
    assert json.loads(content.text) == [["/api/auth/user/", "get"]]


async def test_search_stops_code_that_runs_too_long(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tools, "SEARCH_TIME_LIMIT_SECS", 0.2)

    with anyio.fail_after(10):
        error = await search_error("while True:\n    pass")

    assert "TimeoutError" in error


async def search_error(code: str) -> str:
    """The message the model gets for `code` that fails."""
    async with Client(server(FakeRequest())) as client:
        result = await client.call_tool("search", {"code": code})
    assert result.is_error
    (content,) = result.content
    assert isinstance(content, TextContent)
    return content.text


async def test_an_exception_in_the_code_reaches_the_model_with_its_traceback() -> None:
    error = await search_error('spec["nope"]')

    assert "KeyError" in error
    assert "nope" in error


async def test_a_syntax_error_reaches_the_model() -> None:
    assert "SyntaxError" in await search_error("for path in spec[")


async def test_a_result_that_is_not_json_is_explained() -> None:
    assert "must be JSON" in await search_error("{1, 2}")
