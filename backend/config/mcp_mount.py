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
import threading
from collections.abc import Callable, Iterable
from typing import Any

from a2wsgi import ASGIMiddleware
from django.conf import settings
from precogly_mcp.server import asgi_app

from apps.core.mcp.api import request
from apps.core.mcp.schema import schema
from apps.core.mcp.token_verifier import DjangoAccessTokenVerifier

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


def _start_lifespan(app: Any, loop: asyncio.AbstractEventLoop) -> None:
    """Run the ASGI lifespan once and leave it running.

    Starlette's lifespan starts the session manager's task group, and a2wsgi only
    dispatches requests, so without this every request fails with "Task group is not
    initialized". The task is never awaited: after startup it blocks on the next
    lifespan message, which keeps the task group open.
    """
    global _lifespan_task

    async def run() -> asyncio.Task[Any]:
        incoming: asyncio.Queue[dict[str, str]] = asyncio.Queue()
        started = asyncio.Event()
        await incoming.put({"type": "lifespan.startup"})

        async def receive() -> dict[str, str]:
            return await incoming.get()

        async def send(message: dict[str, str]) -> None:
            if message["type"].startswith("lifespan.startup."):
                started.set()

        task = asyncio.ensure_future(
            app({"type": "lifespan", "asgi": {"version": "3.0"}}, receive, send)
        )
        await started.wait()
        return task

    _lifespan_task = asyncio.run_coroutine_threadsafe(run(), loop).result(timeout=10)


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
    _start_lifespan(app, loop)
    bridge = ASGIMiddleware(app, loop=loop)

    def dispatch(
        environ: dict[str, Any], start_response: Callable[..., Any]
    ) -> Iterable[bytes]:
        path = environ.get("PATH_INFO", "")
        if path == "/mcp" or path == _METADATA_PATH:
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
