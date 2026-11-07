"""The tools the server exposes, and the one capability they use."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.mcpserver.context import Context

# Call Precogly's REST API as the token's user: `(access_token, method, path)` returns
# the parsed body or raises. Supplied by the mounting application, since this package
# never imports Django.
type Request = Callable[[AccessToken, str, str], Awaitable[Any]]


async def whoami(ctx: Context[Request, Any]) -> dict[str, Any]:
    """Who this connection acts as: the user, their organizations, and what it may do.

    Call this first. Every other call runs as this user and sees only these
    organizations, and most data is scoped by organization, so its `id` is what
    narrows a query to one of them. `myRole` is the user's role in each.

    `scopes` says what the connection may do. With `read` alone, any call that changes
    data is refused; the user must reconnect and grant `write` for it to succeed.
    """
    request = ctx.request_context.lifespan_context
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
