"""Call Precogly's REST API in-process, as the user a `/mcp` token resolved to.

A function call rather than an HTTP request, so no credential is presented.
"""

from __future__ import annotations

import functools
import json
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from asgiref.sync import sync_to_async
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import AbstractBaseUser
from django.core.handlers.base import BaseHandler
from django.test import RequestFactory
from mcp.server.auth.provider import AccessToken
from rest_framework.permissions import SAFE_METHODS

from apps.core.mcp.errors import APIError


@functools.cache
def _handler() -> BaseHandler:
    """The middleware chain, loaded on first use rather than at import.

    Middleware reads settings when it is constructed, so loading at import would tie
    it to whatever state the apps were in when this module was first imported.
    """
    handler = BaseHandler()
    handler.load_middleware()
    return handler


def dispatch(
    user: AbstractBaseUser,
    method: str,
    path: str,
    params: Mapping[str, Any] | None = None,
    body: Any = None,
) -> tuple[int, Any]:
    """Run one API request in-process as `user`, through the full middleware chain.

    `params` becomes the query string and `body`, if given, is sent as JSON.

    Returns the status and the parsed JSON body; `None` for an empty body, and the
    text for anything else, such as Django's HTML 404 for an unrouted path.
    """
    # Addressed to the endpoint's public origin. `RequestFactory` defaults to
    # `testserver` over http, which production refuses twice: the host is not in
    # `ALLOWED_HOSTS` (400), and `SECURE_SSL_REDIRECT` answers http with a 301.
    # Tests hide both, because the test runner adds `testserver` to `ALLOWED_HOSTS`.
    origin = urlsplit(settings.MCP_RESOURCE_URL)
    request = RequestFactory().generic(
        method,
        path,
        data=json.dumps(body) if body is not None else "",
        content_type="application/json",
        query_params=params,
        secure=origin.scheme == "https",
        HTTP_HOST=origin.netloc,
    )
    # DRF ignores `request.user` and runs its own authentication classes. This makes
    # it use `ForcedAuthentication` alone, so no credential is presented at all.
    request._force_auth_user = user

    response = _handler().get_response(request)

    if not response.content:
        return response.status_code, None
    if response.get("Content-Type", "").startswith("application/json"):
        return response.status_code, json.loads(response.content)
    return response.status_code, response.content.decode("utf-8", errors="replace")


async def request(
    access_token: AccessToken,
    method: str,
    path: str,
    params: Mapping[str, Any] | None = None,
    body: Any = None,
) -> Any:
    """The API call the agent's code makes: `method` on `path`, as the token's user."""
    method = method.upper()

    # `RequestFactory` drops a query string in the path when `params` is also given,
    # so half the query would vanish without a word.
    if params and "?" in path:
        raise APIError(
            f"Pass query parameters either in the path or as `params`, not both: "
            f"{path!r} and {dict(params)!r}."
        )

    if method not in SAFE_METHODS and "write" not in access_token.scopes:
        granted = " ".join(access_token.scopes) or "no scopes"
        raise APIError(
            f"{method} changes data and needs the `write` scope; this connection was "
            f"granted {granted}. Ask the user to reconnect with write access, or use "
            "a read-only method."
        )

    # Unreachable through `/mcp`: the verifier refuses a token that names no user.
    if access_token.subject is None:
        raise RuntimeError("MCP request reached dispatch without a resolved user")

    # `aget`, not a filter that may come back empty: the verifier accepted a token
    # naming this user moments ago, so a missing row is a broken invariant.
    user = await get_user_model().objects.aget(pk=int(access_token.subject))

    # `dispatch` is sync and runs views that query the ORM, which raises
    # `SynchronousOnlyOperation` inside the event loop. `thread_sensitive` keeps it on
    # the thread that owns the connection, as the verifier does.
    status, result = await sync_to_async(dispatch, thread_sensitive=True)(
        user, method, path, params, body
    )
    if status >= 400:
        raise APIError(f"{method} {path} returned {status}: {_describe(result)}")
    return result


def _describe(body: object) -> str:
    """Flatten a DRF error body into one line.

    Exceptions come as `{"detail": ...}`, validation errors keyed by field. Field names
    are kept: they tell the agent which parameter was wrong.
    """
    if isinstance(body, dict):
        detail = body.get("detail")
        if isinstance(detail, str):
            return detail
        fields = [
            f"{key}: {'; '.join(str(m) for m in value)}"
            if isinstance(value, list)
            else f"{key}: {value}"
            for key, value in body.items()
        ]
        if fields:
            return ", ".join(fields)
    return str(body)
