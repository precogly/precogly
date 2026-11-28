"""Serve the MCP endpoint (ASGI) from inside Precogly's WSGI application.

The bridge works because the endpoint never streams: every reply is one JSON object.

```text
  gunicorn (WSGI)
      |
      +-- /mcp .............................. MCP endpoint  --+
      +-- /.well-known/oauth-protected-resource/mcp ..........+--> Starlette, via a2wsgi
      |
      +-- everything else ................................... Django
```
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Callable, Iterable
from typing import Any

from a2wsgi import ASGIMiddleware
from django.conf import settings
from precogly_mcp.server import asgi_app

from apps.core.mcp.api import request
from apps.core.mcp.schema import schema
from apps.core.mcp.token_verifier import DjangoAccessTokenVerifier

logger = logging.getLogger(__name__)

WSGIApplication = Callable[[dict[str, Any], Callable[..., Any]], Iterable[bytes]]

# Two literals, not a prefix: RFC 9728 puts the metadata document at the origin root,
# where it shares no prefix with `/mcp`. Miss it and the 401 challenge points at a 404,
# so discovery fails at the first hop.
_METADATA_PATH = "/.well-known/oauth-protected-resource/mcp"


# The running lifespan task, one per worker. This reference keeps it alive. asyncio
# holds tasks only weakly, and the task's other references form a cycle (task ->
# coroutine frame -> `receive` closure -> queue -> waiter callback -> task), which
# the cyclic collector reclaims. That closes the session manager's task group, and
# every later request fails with "Task group is not initialized" from whenever a
# collection happens to run.
_lifespan_task: asyncio.Task[Any] | None = None


def _start_lifespan(app: Any, loop: asyncio.AbstractEventLoop) -> str | None:
    """Run the ASGI lifespan once and leave it running.

    The lifespan is the setup an ASGI app runs once per process, before it serves a
    request, and the teardown it runs at shutdown. The server drives it with messages:
    it sends `lifespan.startup`, and the app answers `lifespan.startup.complete` or,
    if its setup raised, `lifespan.startup.failed`. Here the setup starts the session
    manager's task group, generates the API schema, and starts the Monty sandbox pool
    the tools run code in (`lifespan` in `precogly_mcp/server.py`).

    An ASGI server would send `lifespan.startup` itself. a2wsgi only dispatches
    requests, so this function plays that part. Without it every request fails with
    "Task group is not initialized". The task is never awaited: after startup it
    blocks on the next lifespan message, which keeps the task group open.

    Returns `None` once started, or the traceback Starlette sends with
    `lifespan.startup.failed` when the app's lifespan raised.
    """
    global _lifespan_task

    async def run() -> tuple[asyncio.Task[Any], str | None]:
        incoming: asyncio.Queue[dict[str, str]] = asyncio.Queue()
        started = asyncio.Event()
        failure: str | None = None
        await incoming.put({"type": "lifespan.startup"})

        async def receive() -> dict[str, str]:
            return await incoming.get()

        async def send(message: dict[str, str]) -> None:
            nonlocal failure
            if message["type"] == "lifespan.startup.failed":
                failure = message.get("message", "")
            if message["type"].startswith("lifespan.startup."):
                started.set()

        task = asyncio.ensure_future(
            app({"type": "lifespan", "asgi": {"version": "3.0"}}, receive, send)
        )
        await started.wait()
        if failure is not None:
            # Starlette re-raises after sending the failure. Collecting it here keeps
            # asyncio from logging the same traceback a second time.
            await asyncio.gather(task, return_exceptions=True)
        return task, failure

    _lifespan_task, failure = asyncio.run_coroutine_threadsafe(run(), loop).result(
        timeout=10
    )
    return failure


def mount(django_application: WSGIApplication) -> WSGIApplication:
    """Wrap Django so MCP requests reach the MCP app and nothing else changes."""
    resource_url = settings.MCP_RESOURCE_URL
    issuer_url = settings.MCP_ISSUER_URL

    app = asgi_app(
        request=request,
        schema=schema,
        token_verifier=DjangoAccessTokenVerifier(resource_url),
        issuer_url=issuer_url,
        resource_url=resource_url,
    )

    # One event loop per worker, in a daemon thread, shared by the lifespan and every
    # request. `mount` runs at import, so gunicorn must not use `--preload`: the
    # thread would start before the fork and not exist in the workers.
    loop = asyncio.new_event_loop()
    threading.Thread(target=loop.run_forever, daemon=True, name="mcp-asgi").start()
    # A failed lifespan startup (the schema did not generate, or the sandbox did not
    # start or failed `check_sandbox`) takes down only the MCP paths: the rest of Precogly keeps serving,
    # and the log says why. Raising here would stop the worker booting at all.
    failure = _start_lifespan(app, loop)
    if failure is not None:
        logger.error(
            "The MCP endpoint failed to start, so %s and %s answer 503 until a "
            "restart. Set MCP_ENABLED=0 to turn the endpoint off.\n%s",
            "/mcp",
            _METADATA_PATH,
            failure,
        )
    bridge = ASGIMiddleware(app, loop=loop)

    def dispatch(
        environ: dict[str, Any], start_response: Callable[..., Any]
    ) -> Iterable[bytes]:
        path = environ.get("PATH_INFO", "")
        if path == "/mcp" or path == _METADATA_PATH:
            if failure is not None:
                # MCP clients put this body in their connection error, we deliberately keep
                # the error message vague inline with how most behavior based errors in a web
                # app are treated.
                body = (
                    b"Precogly's MCP endpoint failed to start on this server. Ask your "
                    b"administrator to check the server log for 'The MCP endpoint "
                    b"failed to start'."
                )
                start_response(
                    "503 Service Unavailable",
                    [
                        ("Content-Type", "text/plain"),
                        ("Content-Length", str(len(body))),
                    ],
                )
                return [body]
            # Older clients open a GET for a standalone SSE stream and send DELETE to
            # end a session. This revision has neither and answers 405, as the
            # specification prescribes. Passed through, they return 500: an SSE
            # response carries `Connection: keep-alive`, a hop-by-hop header PEP 3333
            # forbids.
            if path == "/mcp" and environ.get("REQUEST_METHOD") in ("GET", "DELETE"):
                start_response(
                    "405 Method Not Allowed",
                    [("Content-Type", "text/plain"), ("Content-Length", "0")],
                )
                return [b""]
            return bridge(environ, start_response)
        return django_application(environ, start_response)

    return dispatch
