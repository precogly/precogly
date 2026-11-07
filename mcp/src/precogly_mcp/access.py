"""How a tool reads Precogly.

A tool never fetches for itself. It calls one of these methods on an object the
mounting application supplied: this package defines the shape, and Precogly decides
what satisfies it.

```text
  bearer token, granted in a browser; audience = /mcp
        |
        v  spent once, at /mcp
  the verifier, which yields a user
        |
        v  no credential; same process
  a reader on the ORM  (Precogly's `apps.core.mcp.ORMReader`)
        |
        v
  the tool
```

The token never reaches `/api/`. It is audience-bound to `/mcp` under RFC 8707, so
django-oauth-toolkit's `validate_bearer_token` refuses it anywhere else, and what
crosses into the data is the resolved user rather than the credential.

What the lifespan holds is a `ReaderFor`, not a reader. The lifespan runs once per
process and the user is resolved once per request, so a reader already scoped to a
user has the wrong lifetime to live there.

# Trade-offs

- **Rows, not models.** Every method returns decoded JSON as the API's serializers
  shape it, and the tool validates. The projection stays in one place, at the cost of
  the protocol being untyped about its own contents.

- **A `Listing` carries the total, and nothing carries a limit.** How many rows a
  reader can return is its own business — a reader over the paginated API gets one
  page at a time (precogly/precogly#208) — but how many *exist* is the caller's, so
  it comes back either way. [0005](../../docs/0005-code-execution-over-tools.md) is
  the reason: a projection is a capability decision wearing the costume of a size
  decision, and a bare truncated list is that mistake exactly. The model cannot
  distinguish "these are all of them" from "these are the first twenty" unless
  something says so.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from mcp.server.auth.provider import AccessToken


@dataclass(frozen=True)
class Listing:
    """Rows, and how many there were to have.

    `total` counts what the caller could read, not what came back. They differ when
    the reader could not return everything, and only `total` makes that visible.
    """

    rows: list[dict[str, Any]]
    total: int


class PrecoglyReader(Protocol):
    """Everything the tools read, and nothing else.

    One method per route rather than a general `get(path)`. A path would push routing
    into every implementation and leave the argument a tool passes — an organization
    id — as a stringly-typed query dictionary that neither side checks.
    """

    async def threat_models(self, organization_id: int | None = None) -> Listing:
        """Threat models the caller can read, most recently updated first.

        A reader returns as many as it can and reports how many there are.
        `organization_id` narrows to one organization; omitted, the caller's own
        scoping decides what comes back.
        """
        ...

    async def threat_library(self) -> list[dict[str, Any]]:
        """The whole shared threat catalog."""
        ...

    async def countermeasure_library(self) -> list[dict[str, Any]]:
        """The whole shared countermeasure catalog."""
        ...

    async def component_library(self) -> list[dict[str, Any]]:
        """The whole shared component catalog."""
        ...


# What the mounting application supplies and the lifespan carries. The argument is
# what the verifier resolved. It is `None` only when the server was built without
# auth, which `asgi_app` never does; an implementation should refuse rather than
# guess a user.
type ReaderFor = Callable[[AccessToken | None], PrecoglyReader]
