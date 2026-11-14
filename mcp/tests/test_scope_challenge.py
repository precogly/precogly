"""`ScopeChallenge` turns scopes a tool recorded with `challenge` into a 403.

Driven as raw ASGI: the app below stands in for the MCP app, answering 200 the way the
SDK does when a tool call fails.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from starlette.requests import Request
from starlette.types import Message, Receive, Scope, Send

from precogly_mcp.scope_challenge import ScopeChallenge, challenge

pytestmark = pytest.mark.anyio

RESOURCE = "https://precogly.example/mcp"
TOOL_ERROR = b'{"jsonrpc":"2.0","id":1,"result":{"isError":true}}'


def app_that_challenges(*calls: set[str]) -> Any:
    """An app that calls `challenge` once per entry in `calls`, then answers 200."""

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        for scopes in calls:
            challenge(Request(scope), scopes)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": TOOL_ERROR})

    return app


async def run(app: Any) -> list[Message]:
    sent: list[Message] = []

    async def receive() -> Message:
        return {"type": "http.request", "body": b""}

    async def send(message: Message) -> None:
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": "/mcp", "headers": []}
    await ScopeChallenge(app, RESOURCE)(scope, receive, send)
    return sent


async def test_a_response_with_nothing_recorded_passes_through_unchanged() -> None:
    sent = await run(app_that_challenges())

    assert [m.get("status") for m in sent] == [200, None]
    assert sent[1]["body"] == TOOL_ERROR


async def test_recorded_scopes_replace_the_response_with_a_challenge() -> None:
    # Two refusals in one call: the challenge asks for the union.
    sent = await run(app_that_challenges({"read", "write"}, {"admin"}))

    start, body = sent
    assert start["status"] == 403
    headers = dict(start["headers"])
    assert headers[b"www-authenticate"].decode() == (
        'Bearer error="insufficient_scope", scope="admin read write", '
        'resource_metadata="https://precogly.example/.well-known/'
        'oauth-protected-resource/mcp", '
        'error_description="This needs the admin read write scopes; '
        'reconnect to grant them."'
    )
    assert json.loads(body["body"])["error"] == "insufficient_scope"
    assert int(headers[b"content-length"]) == len(body["body"])


async def test_lifespan_messages_reach_the_app_untouched() -> None:
    # The app's lifespan starts the sandbox pool; holding its messages would hang
    # startup.
    seen: list[str] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append(scope["type"])
        await send({"type": "lifespan.startup.complete"})

    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    async def receive() -> Message:
        return {"type": "lifespan.startup"}

    await ScopeChallenge(app, RESOURCE)({"type": "lifespan"}, receive, send)

    assert seen == ["lifespan"]
    assert sent == [{"type": "lifespan.startup.complete"}]
