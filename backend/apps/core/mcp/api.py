"""Call Precogly's REST API in-process, as the user a `/mcp` token resolved to.

A function call rather than an HTTP request, so no credential is presented.
"""

from __future__ import annotations

import functools
import json
from typing import Any
from urllib.parse import urlsplit

from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser
from django.core.handlers.base import BaseHandler
from django.test import RequestFactory


@functools.cache
def _handler() -> BaseHandler:
    """The middleware chain, loaded on first use rather than at import.

    Middleware reads settings when it is constructed, so loading at import would tie
    it to whatever state the apps were in when this module was first imported.
    """
    handler = BaseHandler()
    handler.load_middleware()
    return handler


def dispatch(user: AbstractBaseUser, method: str, path: str) -> tuple[int, Any]:
    """Run one API request in-process as `user`, through the full middleware chain.

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
