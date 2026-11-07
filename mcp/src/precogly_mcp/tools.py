"""The tools the server exposes, and the one capability they use."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server.auth.provider import AccessToken

# Call Precogly's REST API as the token's user: `(access_token, method, path)` returns
# the parsed body or raises. Supplied by the mounting application, since this package
# never imports Django.
type Request = Callable[[AccessToken, str, str], Awaitable[Any]]
