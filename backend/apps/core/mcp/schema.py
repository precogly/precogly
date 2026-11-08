"""The OpenAPI schema the MCP `search` tool reads, generated once per process.

Generated from the running code rather than read from a committed copy, so it cannot
go stale; a committed copy exists for review, not for serving.
"""

from __future__ import annotations

import functools
from typing import Any

from asgiref.sync import sync_to_async
from drf_spectacular.generators import SchemaGenerator


@functools.cache
def _generate_schema() -> dict[str, Any]:
    return SchemaGenerator().get_schema(request=None, public=True)


async def schema() -> dict[str, Any]:
    """The schema, shared by every caller in the process: do not modify it."""
    return await sync_to_async(_generate_schema, thread_sensitive=True)()
