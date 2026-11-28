"""Answer a tool call refused for a missing OAuth scope with a 403 scope challenge.

`execute` runs the agent's code, and that code's `request` is where a write without the
`write` scope is refused. Left alone, the refusal reaches the client as a tool error
inside a 200, so the client never learns that re-authorizing would fix it. The MCP
specification (2025-11-25, Scope Challenge Handling) asks for HTTP 403 with
`WWW-Authenticate: Bearer error="insufficient_scope", scope=...` instead; the client
then re-authorizes with those scopes and retries.

# How the refusal reaches the HTTP response

A tool returns a result, not an HTTP response, so the status has to be set from
outside the MCP app. `ScopeChallenge` wraps the whole app and holds back its response;
the tool leaves the scopes it needed in `request.state`, and the middleware reads them
once the app finishes:

```text
  HTTP POST /mcp
    |
    v
  ScopeChallenge ................ scope["state"] = {}       (one dict per request)
    |
    v
  MCP app (SDK) ................. auth, JSON-RPC, tools/call
    |
    v
  execute -> request(...) ....... raises InsufficientScope
    |                             challenge(): request.state.needed_scopes = {...}
    v
  ScopeChallenge ................ reads scope["state"]["needed_scopes"]
                                    not set: sends the held response unchanged
                                             (every request but a refused write)
                                    set:     sends 403 + WWW-Authenticate and drops
                                             the held response
```

`request.state` is Starlette's documented place for per-request data that middleware
and the code handling the request share. It is a view over the plain dict at
`scope["state"]`, and every layer of a Starlette app is handed the same `scope` object,
so a value the tool sets there is the one the middleware reads. The SDK attaches that
Starlette request to each tool call as `ctx.request_context.request`.

Retrying is safe because nothing the refusal guards ran: without `write`, every write
in the code is refused before it reaches the API, so the retry repeats only reads.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from mcp.server.auth.routes import build_resource_metadata_url
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class InsufficientScope(Exception):
    """An operation needs `scopes`, which the caller's token was not granted."""

    def __init__(self, message: str, scopes: Iterable[str]) -> None:
        super().__init__(message)
        self.scopes = frozenset(scopes)


def challenge(request: Request | None, scopes: Iterable[str]) -> None:
    """Records on `request` that it needs `scopes` to succeed.

    `request` is `None` when the server runs without HTTP, as in-memory tests do;
    the refusal then stays an ordinary tool error.
    """
    if request is None:
        return
    needed: set[str] = getattr(request.state, "needed_scopes", set())
    request.state.needed_scopes = needed | set(scopes)


class ScopeChallenge:
    """ASGI middleware that turns scopes recorded by `challenge` into a 403 challenge.

    It holds back every response until the app finishes, which costs nothing here: the
    endpoint answers in JSON, never as a stream, so each reply is complete only at the
    end anyway.
    """

    def __init__(self, app: ASGIApp, resource_url: str) -> None:
        self.app = app
        self.resource_metadata_url = str(
            build_resource_metadata_url(AnyHttpUrl(resource_url))
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        scope.setdefault("state", {})
        held: list[Message] = []

        async def hold(message: Message) -> None:
            held.append(message)

        await self.app(scope, receive, hold)

        # Read back from `scope`, not from a reference taken before the call, in case a
        # layer below replaced the dict.
        needed = scope["state"].get("needed_scopes")
        if not needed:
            for message in held:
                await send(message)
            return

        scopes = " ".join(sorted(needed))
        description = f"This needs the {scopes} scopes; reconnect to grant them."
        header = (
            f'Bearer error="insufficient_scope", scope="{scopes}", '
            f'resource_metadata="{self.resource_metadata_url}", '
            f'error_description="{description}"'
        )
        body = json.dumps(
            {"error": "insufficient_scope", "error_description": description}
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 403,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"www-authenticate", header.encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
