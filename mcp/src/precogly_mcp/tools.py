"""The tools the server exposes, and what they are given to work with."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.mcpserver.context import Context
from mcp.server.mcpserver.exceptions import ToolError
from pydantic_monty import (
    AsyncMonty,
    MontyRuntimeError,
    MontySyntaxError,
    ResourceLimits,
)

from precogly_mcp.truncate import dumps, fit

# Arbitrary, with wide margins: a search over the whole spec measured ~41 ms. Lower
# risks cutting off a legitimate scan of every operation; higher lets a runaway loop
# hold a sandbox worker, and the `/mcp` request waiting on it, for longer.
SEARCH_TIME_LIMIT_SECS = 2.0

# Cloudflare's cap, ~6,000 tokens at 4 characters each, not measured here: room for
# about eight median operations or one of the largest. Lower makes the model narrow
# its code sooner; higher spends more of its context on each result.
RESULT_MAX_CHARS = 24_000

# The sandbox clock stops while `execute` waits on `request`, so this bounds the
# model's own computation, as for `search`; the two limits below bound the waiting.
EXECUTE_TIME_LIMIT_SECS = 2.0

# Arbitrary: enough to page through any listing here, few enough that a runaway loop
# cannot hammer the API. Measured: one awaited `request` costs one suspension, so 100
# allows 100 sequential calls (99 when gathered).
EXECUTE_MAX_REQUESTS = 100

# Arbitrary: 100 requests at ~50 ms each spend ~5 s waiting, none of it on the sandbox
# clock. Past this the run is cancelled.
EXECUTE_WALL_CLOCK_SECS = 30.0


class Request(Protocol):
    """Call Precogly's REST API as the token's user; returns the parsed body or raises.

    `params` becomes the query string and `body` is sent as JSON. Supplied by the
    mounting application, since this package never imports Django.
    """

    async def __call__(
        self,
        access_token: AccessToken,
        method: str,
        path: str,
        params: Mapping[str, Any] | None = None,
        body: Any = None,
    ) -> Any: ...


# Return Precogly's OpenAPI schema. Supplied by the mounting application for the same
# reason as `Request`.
type Schema = Callable[[], Awaitable[dict[str, Any]]]


@dataclass(frozen=True)
class ToolContext:
    """What every tool call is given: built once per process and shared by all calls."""

    request: Request
    # A pool of sandbox worker processes that run model-written code.
    sandbox: AsyncMonty
    # The schema reduced by `process_spec`: what `search` code reads as `spec`.
    spec: dict[str, Any]


# Run against the real schema by `backend/apps/core/tests/test_mcp_search_examples.py`,
# so an example the API no longer supports fails a test instead of misleading a model.
SEARCH_EXAMPLES = (
    """\
[(method.upper(), path, op["tags"])
 for path, ops in spec["paths"].items()
 for method, op in ops.items()
 if "zones" in path]""",
    """\
[(p["name"], p["in"], p.get("schema", {}).get("type"))
 for p in spec["paths"]["/api/zones/"]["get"].get("parameters", [])]""",
    """\
body = spec["paths"]["/api/zones/"]["post"]["requestBody"]
schema = body["content"]["application/json"]["schema"]
{name: field.get("type")
 for name, field in schema["properties"].items()
 if not field.get("readOnly")}""",
)

SEARCH_DESCRIPTION = f"""\
Search Precogly's REST API by running Python over its OpenAPI schema.

Write Python; the value of the last expression is the result. It runs in a sandbox \
with no network or filesystem access, for at most {SEARCH_TIME_LIMIT_SECS:g} seconds.

`spec` is the schema as a dict. `spec["paths"][path][method]` is one operation, with \
`description`, `tags`, `parameters`, `requestBody` and `responses`. Methods are \
lowercase, every `$ref` is already inlined, and request bodies are JSON only.

Field names in the schema are snake_case, but response bodies arrive in camelCase: \
`zone_type` is returned as `zoneType`. Request bodies accept snake_case. Query \
parameters are used exactly as named.

Results over about {RESULT_MAX_CHARS:,} characters are cut, and each cut is \
marked `--- TRUNCATED ---`. Return the parts you need, not whole operations.

Examples:

""" + "\n\n".join(SEARCH_EXAMPLES)


async def search(ctx: Context[ToolContext, Any], code: str) -> str:
    """Run `code` over the reduced schema; the model reads `SEARCH_DESCRIPTION`."""
    tool = ctx.request_context.lifespan_context
    return await _run(
        tool.sandbox,
        code,
        ResourceLimits(max_feed_duration_secs=SEARCH_TIME_LIMIT_SECS),
        inputs={"spec": tool.spec},
    )


async def execute(ctx: Context[ToolContext, Any], code: str) -> str:
    """Run `code` with an async `request` bound to the caller's token."""
    tool = ctx.request_context.lifespan_context
    access_token = get_access_token()
    if access_token is None:
        raise RuntimeError("The server was run without auth")

    # A closure, so the sandboxed code calls the API without ever holding the token.
    async def request(
        method: str,
        path: str,
        params: Mapping[str, Any] | None = None,
        body: Any = None,
    ) -> Any:
        return await tool.request(access_token, method, path, params, body)

    try:
        async with asyncio.timeout(EXECUTE_WALL_CLOCK_SECS):
            return await _run(
                tool.sandbox,
                code,
                ResourceLimits(
                    max_feed_duration_secs=EXECUTE_TIME_LIMIT_SECS,
                    max_suspensions=EXECUTE_MAX_REQUESTS,
                ),
                external_lookup={"request": request},
            )
    except TimeoutError as err:
        # Cancelling does not undo what already ran: a write may have landed.
        raise ToolError(
            f"The code ran longer than {EXECUTE_WALL_CLOCK_SECS:g} seconds and was "
            f"stopped. Requests it had already made may have taken effect."
        ) from err


async def _run(
    sandbox: AsyncMonty,
    code: str,
    limits: ResourceLimits,
    *,
    inputs: dict[str, Any] | None = None,
    external_lookup: dict[str, Any] | None = None,
) -> str:
    """Run `code` once in a fresh sandbox session and return its result as JSON."""
    # One run per checkout, so a run stopped by a limit never reuses its session,
    # whose heap the library no longer vouches for.
    #
    # The model's own mistakes are raised as `ToolError`, whose message the SDK passes
    # to the client; a traceback into its code is what lets it fix the code. Anything
    # else, such as `MontyCrashedError` for a dead worker, is left to the SDK, which
    # reports it without detail.
    try:
        async with sandbox.checkout(limits=limits) as session:
            result = await session.feed_run(
                code, inputs=inputs, external_lookup=external_lookup
            )
    except (MontySyntaxError, MontyRuntimeError) as err:
        raise ToolError(err.display("traceback")) from err

    # Serialized here, not left to the SDK: it turns a returned list into one content
    # block per item, so `[("/api/zones/", "get")]` would reach the model as two
    # unrelated strings. Round-tripped before `fit` so it measures plain JSON, with
    # tuples as lists and non-string keys as strings, exactly as they are returned.
    try:
        data = json.loads(dumps(result))
    except (TypeError, ValueError) as err:
        raise ToolError(
            f"The result must be JSON: lists, dicts, strings, finite numbers, "
            f"booleans or None. {err}"
        ) from err
    return dumps(fit(data, RESULT_MAX_CHARS))


async def whoami(ctx: Context[ToolContext, Any]) -> dict[str, Any]:
    """Who this connection acts as: the user, their organizations, and what it may do.

    Call this first. Every other call runs as this user and sees only these
    organizations, and most data is scoped by organization, so its `id` is what
    narrows a query to one of them. `myRole` is the user's role in each.

    `scopes` says what the connection may do. With `read` alone, any call that changes
    data is refused; the user must reconnect and grant `write` for it to succeed.
    """
    request = ctx.request_context.lifespan_context.request
    access_token = get_access_token()
    if access_token is None:
        raise RuntimeError("The server was run without auth")
    user_profile = await request(access_token, "GET", "/api/auth/user/")
    organizations = await request(access_token, "GET", "/api/organizations/")
    return {
        "user": user_profile,
        "organizations": organizations["results"],
        "scopes": access_token.scopes,
    }
