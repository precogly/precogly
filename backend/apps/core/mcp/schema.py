"""The OpenAPI schema the MCP `search` tool reads, generated once per process.

Generated from the running code rather than read from a committed copy, so it cannot
go stale; a committed copy exists for review, not for serving.
"""

from __future__ import annotations

import functools
from typing import Any

from asgiref.sync import sync_to_async
from drf_spectacular.drainage import GENERATOR_STATS
from drf_spectacular.generators import SchemaGenerator


@functools.cache
def _generate_schema() -> dict[str, Any]:
    # Silenced: this runs as each worker starts, and would repeat every schema warning
    # into the production logs on every boot. `manage.py spectacular` reports them.
    with GENERATOR_STATS.silence():
        return SchemaGenerator().get_schema(request=None, public=True)


async def schema() -> dict[str, Any]:
    """The schema, shared by every caller in the process: do not modify it."""
    return await sync_to_async(_generate_schema, thread_sensitive=True)()
