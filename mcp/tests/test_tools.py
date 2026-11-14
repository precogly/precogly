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
from collections.abc import Iterator, Mapping
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
        self.calls: list[tuple[AccessToken, str, str, Any, Any]] = []

    async def __call__(
        self,
        access_token: AccessToken,
        method: str,
        path: str,
        params: Mapping[str, Any] | None = None,
        body: Any = None,
    ) -> Any:
        self.calls.append((access_token, method, path, params, body))
        if path == "/api/missing/":
            # The shape of the backend's `APIError` message.
            raise LookupError(f"{method} {path} returned 404: Not found.")
        if path == "/api/slow/":
            await anyio.sleep(5)
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
        (access_token, "GET", "/api/auth/user/", None, None),
        (access_token, "GET", "/api/organizations/", None, None),
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


async def test_the_tool_list_is_advertised_as_fixed() -> None:
    # Advertising `listChanged` invites Claude Code to open `subscriptions/listen`,
    # which Django's WSGI server fails with a 500 on every retry.
    async with Client(server(FakeRequest())) as client:
        capabilities = client.server_capabilities

    assert capabilities.tools is not None
    assert not capabilities.tools.list_changed


async def test_code_results_come_back_as_text_only() -> None:
    # Claude Code shows the model `structuredContent` when there is one; with the
    # SDK's `{"result": <str>}` wrapper, that was our JSON as a string inside JSON.
    async with Client(server(FakeRequest())) as client:
        tools_by_name = {tool.name: tool for tool in (await client.list_tools()).tools}
        result = await client.call_tool("search", {"code": "1"})

    assert tools_by_name["search"].output_schema is None
    assert tools_by_name["execute"].output_schema is None
    assert result.structured_content is None
    assert text(result) == "1"


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


async def test_an_oversized_result_is_cut_to_the_cap_and_stays_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tools, "RESULT_MAX_CHARS", 300)
    code = '[{"path": f"/api/{i}/", "summary": "x" * 50} for i in range(100)]'

    async with Client(server(FakeRequest())) as client:
        result = await client.call_tool("search", {"code": code})

    assert not result.is_error, result.content
    (content,) = result.content
    assert isinstance(content, TextContent)
    assert len(content.text) <= 300
    *kept, marker = json.loads(content.text)
    assert kept[0] == {"path": "/api/0/", "summary": "x" * 50}
    assert marker == f"--- TRUNCATED --- {100 - len(kept)} more items"


async def call_execute(code: str, request: FakeRequest | None = None) -> Any:
    async with Client(server(request or FakeRequest())) as client:
        return await client.call_tool("execute", {"code": code})


def text(result: Any) -> str:
    (content,) = result.content
    assert isinstance(content, TextContent)
    return content.text


async def test_execute_calls_the_api_as_the_caller(access_token: AccessToken) -> None:
    request = FakeRequest()
    code = 'await request("GET", "/api/organizations/", params={"page": 1})'

    result = await call_execute(code, request)

    assert not result.is_error, result.content
    assert json.loads(text(result)) == RESPONSES["/api/organizations/"]
    assert request.calls == [
        (access_token, "GET", "/api/organizations/", {"page": 1}, None)
    ]


async def test_an_api_error_reaches_the_model(access_token: AccessToken) -> None:
    result = await call_execute('await request("GET", "/api/missing/")')

    assert result.is_error
    assert "GET /api/missing/ returned 404: Not found." in text(result)


async def test_execute_stops_after_too_many_requests(
    access_token: AccessToken, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tools, "EXECUTE_MAX_REQUESTS", 3)
    code = 'for i in range(5):\n    await request("GET", "/api/auth/user/")'

    result = await call_execute(code)

    assert result.is_error
    assert "suspension limit 3 exceeded" in text(result)


async def test_execute_stops_a_run_that_waits_too_long(
    access_token: AccessToken, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The sandbox clock stops while it waits on `request`, so only the wall-clock
    # limit can end this.
    monkeypatch.setattr(tools, "EXECUTE_WALL_CLOCK_SECS", 0.2)

    with anyio.fail_after(10):
        result = await call_execute('await request("GET", "/api/slow/")')

    assert result.is_error
    assert "may have taken effect" in text(result)


async def test_execute_refuses_to_run_without_a_token() -> None:
    assert (await call_execute("1")).is_error


async def test_execute_is_advertised_as_able_to_change_data() -> None:
    async with Client(server(FakeRequest())) as client:
        tools_by_name = {tool.name: tool for tool in (await client.list_tools()).tools}
    annotations = tools_by_name["execute"].annotations

    assert annotations is not None
    assert annotations.read_only_hint is False
    assert annotations.destructive_hint is not False


async def test_a_request_that_was_never_awaited_is_explained(
    access_token: AccessToken,
) -> None:
    # Without the guard this returns the string "<coroutine external_future(0)>"
    # as if it were data.
    result = await call_execute('request("GET", "/api/auth/user/")')

    assert result.is_error
    assert "never awaited" in text(result)


async def test_the_sandbox_still_lets_a_builtin_beat_a_comprehension_variable() -> None:
    # Pins a pydantic-monty 1.5.0 bug that `execute`'s description warns about:
    # CPython gives ["7"]. When this starts failing, monty has fixed it; drop the
    # warning from EXECUTE_DESCRIPTION along with this test.
    async with Client(server(FakeRequest())) as client:
        result = await client.call_tool("search", {"code": '[f"{id}" for id in [7]]'})

    assert json.loads(text(result)) == ["<built-in function id>"]


def test_each_description_works_from_its_first_line_alone() -> None:
    # opencode's Code Mode shows only the first line, cut to 120 characters; a model
    # given nothing more guessed `client`, `token` and `schema` for a dozen calls.
    for name, description, names in [
        ("search", tools.SEARCH_DESCRIPTION, "spec"),
        ("execute", tools.EXECUTE_DESCRIPTION, "await request("),
    ]:
        first = description.split("\n", 1)[0]
        assert len(first) <= 120, (name, len(first))
        assert names in first, name


async def test_printed_output_comes_back_with_the_result() -> None:
    async with Client(server(FakeRequest())) as client:
        result = await client.call_tool(
            "search", {"code": 'print("paths:", len(spec["paths"]))\n42'}
        )

    assert json.loads(text(result)) == {"result": 42, "printed": "paths: 1\n"}


async def test_an_unknown_name_says_what_is_provided() -> None:
    error = await search_error('schema["paths"]')

    assert "NameError" in error
    assert "The only name provided here is `spec`" in error


async def test_a_missing_module_says_what_is_provided() -> None:
    error = await search_error("import requests")

    assert "ModuleNotFoundError" in error
    assert "The only name provided here is `spec`" in error
