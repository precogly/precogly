"""The Precogly MCP server, mounted inside Precogly at `/mcp`.

The mounting application supplies the `TokenVerifier` that checks tokens and the
`Request` the tools call the API through, so this package never imports Django.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from importlib.metadata import version

from mcp.server import MCPServer
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.types import ToolAnnotations
from starlette.applications import Starlette

from precogly_mcp.tools import Request, whoami


def build_server(
    *,
    request: Request,
    auth: AuthSettings | None = None,
    token_verifier: TokenVerifier | None = None,
) -> MCPServer:
    """Assemble the server.

    Tools reach `request` through the lifespan, the only place a server-wide value can
    live.
    """

    @asynccontextmanager
    async def lifespan(_: MCPServer) -> AsyncGenerator[Request]:
        yield request

    server = MCPServer(
        "precogly",
        version=version("precogly-mcp"),
        auth=auth,
        token_verifier=token_verifier,
        lifespan=lifespan,
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
    return server


def asgi_app(
    *,
    request: Request,
    token_verifier: TokenVerifier,
    issuer_url: str,
    resource_url: str,
    required_scopes: list[str] | None = None,
) -> Starlette:
    """Build the MCP endpoint for Precogly to mount.

    `resource_url` is the token audience (RFC 8707). It also fixes where the
    protected-resource document is served: RFC 9728 puts it at
    `/.well-known/oauth-protected-resource` plus this URL's path. Both routes sit at
    the origin root, so the app must be dispatched to from there, not mounted under a
    prefix.

    `json_response` lets this run under WSGI: each reply is one JSON object instead of
    an SSE stream. Nothing can stream, so a tool cannot report progress.

    `stateless_http`: the targeted transport revision has no protocol-level sessions.
    """
    server = build_server(
        request=request,
        # Strings, not `AnyHttpUrl`. Pydantic's default normalization appends a
        # trailing slash to a path-less issuer, and RFC 8414 compares issuers as
        # exact strings, so the client would reject its own issuer. `AuthSettings`
        # sets `url_preserve_empty_path` to avoid that.
        auth=AuthSettings(
            issuer_url=issuer_url,  # type: ignore[arg-type]
            resource_server_url=resource_url,  # type: ignore[arg-type]
            required_scopes=required_scopes or ["read"],
        ),
        token_verifier=token_verifier,
    )
    return server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
    )
