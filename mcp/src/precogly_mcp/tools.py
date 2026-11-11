"""The tools the server exposes, and what they are given to work with."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any, Protocol

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.mcpserver.context import Context
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field
from pydantic_monty import (
    AsyncMonty,
    CollectString,
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

# Arbitrary: a sixth of the result cap, so debugging prints cannot crowd out the
# result. Printed output is returned only when there is some, as
# `{"result": ..., "printed": ...}`.
PRINTED_MAX_CHARS = 4_000

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

# The first line of each description must work alone, in at most 120 characters:
# opencode's Code Mode catalog shows a tool as its signature plus the description's
# first line, cut to 120 characters, and nothing else (opencode 2.0.25,
# `line: \`  - ${signature} // ${desc}\``). The rest is for clients that show it all.
SEARCH_DESCRIPTION = f"""\
Python over the API's OpenAPI schema: read `spec["paths"][path][method]`; the last \
expression is returned.

Write Python; the value of the last expression is the result, and anything printed \
comes back too. It runs in a sandbox with no network or filesystem access, for at \
most {SEARCH_TIME_LIMIT_SECS:g} seconds.

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


async def search(
    ctx: Context[ToolContext, Any],
    code: Annotated[
        str,
        Field(
            description="Python. `spec` is the OpenAPI schema as a dict: "
            '`spec["paths"][path][method]`. The last expression is returned.'
        ),
    ],
) -> str:
    """Run `code` over the reduced schema; the model reads `SEARCH_DESCRIPTION`."""
    tool = ctx.request_context.lifespan_context
    return await _run(
        tool.sandbox,
        code,
        ResourceLimits(max_feed_duration_secs=SEARCH_TIME_LIMIT_SECS),
        inputs={"spec": tool.spec},
        provided="`spec`, the OpenAPI schema as a dict",
    )


# Run against the real API with seeded data by
# `backend/apps/core/tests/test_mcp_execute_examples.py`, for the same reason as
# `SEARCH_EXAMPLES`.
EXECUTE_EXAMPLES = (
    """\
body = await request("GET", "/api/threat-models/", params={"search": "payments"})
[(model["id"], model["name"]) for model in body["results"]]""",
    """\
# Lists come a page at a time: follow `next` until it is null.
rows, page = [], 1
while True:
    body = await request("GET", "/api/threat-models/", params={"page": page})
    rows += body["results"]
    if not body["next"]:
        break
    page += 1
len(rows)""",
    """\
import asyncio

listing = await request("GET", "/api/threat-models/")
model_ids = [model["id"] for model in listing["results"][:5]]
details = await asyncio.gather(
    *[request("GET", f"/api/threat-models/{model_id}/") for model_id in model_ids]
)
[(model["name"], model["criticality"]) for model in details]""",
    """\
listing = await request("GET", "/api/threat-models/", params={"search": "payments"})
model = listing["results"][0]
await request(
    "PATCH", f"/api/threat-models/{model['id']}/", body={"criticality": "high"}
)""",
)

EXECUTE_DESCRIPTION = f"""\
Python calling the API as you: `await request(method, path, params, body)`; the last \
expression is returned.

Use `search` first to find the endpoint, its parameters and its body. Then write \
Python; the value of the last expression is the result, and anything printed comes \
back too. Do not name a comprehension \
variable after a builtin such as `id` or `type`: in this sandbox the builtin wins, \
so `[f"/x/{{id}}/" for id in ids]` puts the `id` function in the path.

`await request(method, path, params=None, body=None)` calls the API: `params` is the \
query string, `body` is sent as JSON, and it returns the parsed response. A failed \
call raises with the method, path, status and the API's reason, such as which field \
was invalid. `request` must be awaited; use `asyncio.gather` to run calls at once.

Calls run as the user, so they see only the user's organizations and are refused \
where the user is. Calls that change data need the connection's `write` scope; \
`whoami` shows the scopes.

Response bodies use camelCase field names (`zoneType`). Lists are paginated: \
`{{count, next, previous, results}}`, 20 rows per page unless `page_size` says \
otherwise.

Each run may make {EXECUTE_MAX_REQUESTS} requests, compute for \
{EXECUTE_TIME_LIMIT_SECS:g} seconds and take {EXECUTE_WALL_CLOCK_SECS:g} seconds in \
all. Results over about {RESULT_MAX_CHARS:,} characters are cut, and each cut is \
marked `--- TRUNCATED ---`: return what the question needs, not whole responses.

Examples:

""" + "\n\n".join(EXECUTE_EXAMPLES)


async def execute(
    ctx: Context[ToolContext, Any],
    code: Annotated[
        str,
        Field(
            description="Python. Call the API with "
            "`await request(method, path, params=None, body=None)`. "
            "The last expression is returned."
        ),
    ],
) -> str:
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
                provided="`request`, called as "
                "`await request(method, path, params=None, body=None)`",
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
    provided: str,
) -> str:
    """Run `code` once in a fresh sandbox session and return its result as JSON.

    `provided` names what the sandbox gives the code, for the `NameError` hint.
    """
    # One run per checkout, so a run stopped by a limit never reuses its session,
    # whose heap the library no longer vouches for.
    #
    # The model's own mistakes are raised as `ToolError`, whose message the SDK passes
    # to the client; a traceback into its code is what lets it fix the code. Anything
    # else, such as `MontyCrashedError` for a dead worker, is left to the SDK, which
    # reports it without detail.
    #
    # Printed output is collected rather than left to the default, which writes it to
    # the server's stdout: the model never saw it, and the server's logs did. Past
    # `max_bytes` the collector fails the whole run rather than truncating, so the
    # bound is generous (1 MB, arbitrary) and `fit` does the trimming afterwards.
    printed = CollectString(max_bytes=1_000_000)
    try:
        async with sandbox.checkout(limits=limits) as session:
            result = await session.feed_run(
                code,
                inputs=inputs,
                external_lookup=external_lookup,
                print_callback=printed,
            )
    except (MontySyntaxError, MontyRuntimeError) as err:
        message = err.display("traceback")
        # A model that has not seen the description guesses names (`client`,
        # `token`, `schema`) or imports (`requests`, `urllib`); without this it
        # guesses again.
        if "NameError" in message or "ModuleNotFoundError" in message:
            message += (
                f"\n\nThe only name provided here is {provided}. There is no client, "
                f"token or HTTP library."
            )
        raise ToolError(message) from err

    # Serialized here, not left to the SDK: it turns a returned list into one content
    # block per item, so `[("/api/zones/", "get")]` would reach the model as two
    # unrelated strings. Round-tripped before `fit` so it measures plain JSON, with
    # tuples as lists and non-string keys as strings, exactly as they are returned.
    try:
        text = dumps(result)
    except (TypeError, ValueError) as err:
        raise ToolError(
            f"The result must be JSON: lists, dicts, strings, finite numbers, "
            f"booleans or None. {err}"
        ) from err

    # `request` is async. A call returned without `await` raises nothing: it arrives
    # here as the string `<coroutine external_future(N)>`, which would read as data.
    if "<coroutine external_future(" in text:
        raise ToolError(
            "The result holds a `request(...)` call that was never awaited. "
            "`request` is async: write `await request(...)`."
        )
    data = json.loads(text)
    output = printed.output
    if output:
        data = {"result": data, "printed": fit(output, PRINTED_MAX_CHARS)}
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
