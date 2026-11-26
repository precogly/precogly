"""The Precogly MCP server, mounted inside Precogly at `/mcp`.

The mounting application supplies the `TokenVerifier` that checks tokens, the
`Request` the tools call the API through, and the `Schema` `search` reads, so this
package never imports Django.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from importlib.metadata import version

from mcp.server import MCPServer
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.types import ToolAnnotations
from pydantic_monty import AsyncMonty
from starlette.types import ASGIApp

from precogly_mcp.scope_challenge import ScopeChallenge
from precogly_mcp.spec import process_spec
from precogly_mcp.tools import (
    EXECUTE_DESCRIPTION,
    SEARCH_DESCRIPTION,
    Request,
    Schema,
    ToolContext,
    check_sandbox,
    execute,
    search,
    whoami,
)


def build_server(
    *,
    request: Request,
    schema: Schema,
    auth: AuthSettings | None = None,
    token_verifier: TokenVerifier | None = None,
) -> MCPServer:
    """Assemble the server.

    Tools reach their `ToolContext` through the lifespan, the only place a server-wide
    value can live.
    """

    # Yielding inside `async with` keeps the sandbox pool open for the server's life
    # and stops its worker processes at shutdown.
    #
    # The one-off costs are paid here, at startup, rather than by the first `search`:
    # generating the schema (~0.4 s) and the pool's first worker (~0.4 s), measured
    # on a laptop. A schema that fails to generate stops the server starting, rather
    # than surfacing as a broken tool.
    @asynccontextmanager
    async def lifespan(_: MCPServer) -> AsyncGenerator[ToolContext]:
        spec = process_spec(await schema())
        async with AsyncMonty() as sandbox:
            # Also the warm-up: the first run in a pool is slow (~0.4 s), and a sandbox
            # binary that does not run here fails startup instead of the first tool.
            await check_sandbox(sandbox)
            yield ToolContext(request=request, sandbox=sandbox, spec=spec)

    # `subscriptions=False`: the tool list never changes, so there is nothing to
    # notify. Served, `subscriptions/listen` is a long-lived SSE response, which under
    # WSGI holds a worker thread per client, and its `Connection` header is one WSGI
    # forbids an application to set (Django's dev server fails it with a 500).
    server = MCPServer(
        "precogly",
        version=version("precogly-mcp"),
        auth=auth,
        token_verifier=token_verifier,
        lifespan=lifespan,
        subscriptions=False,
    )
    # title = the display name
    #
    # The annotations are hints a client uses to decide whether to ask a human before
    # a call. Nothing enforces them; the `write` scope check in `request` does.
    # - read_only_hint: the tool changes nothing.
    # - idempotent_hint: repeating a call with the same arguments has no further
    #   effect. The spec reads it only when read_only_hint is false, so it says
    #   nothing here; it starts to matter on tools that write.
    # - open_world_hint=False: the tool touches only this deployment's own records,
    #   not external systems the way a web search does.
    server.add_tool(
        whoami,
        title="Who am I",
        annotations=ToolAnnotations(
            read_only_hint=True,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    # `structured_output=False` on `search` and `execute`: they return JSON already
    # serialized, so the SDK would add `structuredContent` `{"result": "<that JSON>"}`.
    # Claude Code shows the model the structured part when there is one, so every
    # result arrived as a JSON string inside JSON.
    #
    # Reads the schema only, in a sandbox with no network: read-only and closed.
    server.add_tool(
        search,
        title="Search the API",
        description=SEARCH_DESCRIPTION,
        structured_output=False,
        annotations=ToolAnnotations(
            read_only_hint=True,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    # Can change data, so a client should ask before running it. `destructive_hint`
    # is left at its default, true: code can delete. The `write` scope check in
    # `request` is what actually stops a read-only connection writing.
    server.add_tool(
        execute,
        title="Run code against the API",
        description=EXECUTE_DESCRIPTION,
        structured_output=False,
        annotations=ToolAnnotations(
            read_only_hint=False,
            idempotent_hint=False,
            open_world_hint=False,
        ),
    )
    return server


def asgi_app(
    *,
    request: Request,
    schema: Schema,
    token_verifier: TokenVerifier,
    issuer_url: str,
    resource_url: str,
    required_scopes: list[str] | None = None,
) -> ASGIApp:
    """Build the MCP endpoint for Precogly to mount.

    `resource_url` is the token audience (RFC 8707). It also fixes where the
    protected-resource document is served: RFC 9728 puts it at
    `/.well-known/oauth-protected-resource` plus this URL's path. Both routes sit at
    the origin root, so the app must be dispatched to from there, not mounted under a
    prefix.

    `json_response` lets this run under WSGI: each reply is one JSON object instead of
    an SSE stream. Nothing can stream, so a tool cannot report progress.

    `stateless_http`: the targeted transport revision has no protocol-level sessions.

    `ScopeChallenge` wraps the app. A write rejected for lacking the `write` scope gets
    a 403 scope challenge; see `precogly_mcp.scope_challenge`.
    """
    server = build_server(
        request=request,
        schema=schema,
        # Strings, not `AnyHttpUrl`. Pydantic's default normalization appends a
        # trailing slash to a path-less issuer, and RFC 8414 compares issuers as
        # exact strings, so the client would reject its own issuer. `AuthSettings`
        # sets `url_preserve_empty_path` to avoid that.
        #
        # `validate_token_resource`:
        # 1. What it does: True makes the SDK's bearer middleware refuse a token whose
        #    `AccessToken.resource` is not `resource_url`. That is the RFC 8707
        #    audience check the MCP specification requires: a token issued for another
        #    server must not work here.
        # 2. Why False: the token verifier already makes that check and reports
        #    `resource_url` for every token it accepts, so with True the SDK would
        #    compare that URL with itself and never refuse anything.
        # 3. Why that is still secure: the verifier refuses any token whose stored
        #    resources do not include `resource_url` exactly. Its tests cover the two
        #    cases a looser check lets through:
        #    - a token with no resource, which django-oauth-toolkit's
        #      `AccessToken.allows_audience()` accepts
        #    - a token issued for the origin, which a prefix match accepts
        # 4. Why set it at all: left unset, mcp 2.3 warns at startup and behaves as
        #    False; 3.0 switches the unset default to True.
        auth=AuthSettings(
            issuer_url=issuer_url,  # type: ignore[arg-type]
            resource_server_url=resource_url,  # type: ignore[arg-type]
            required_scopes=required_scopes or ["read"],
            validate_token_resource=False,
        ),
        token_verifier=token_verifier,
    )
    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
    )
    return ScopeChallenge(app, resource_url)
