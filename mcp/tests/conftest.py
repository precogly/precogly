"""Shared fixtures.

Tests run against the real MCP protocol and a fake reader. The protocol half uses
`mcp.client.Client`, which accepts an `MCPServer` directly and drives it over in-memory
streams — so a test exercises `tools/list` and `tools/call` as a client would, without a
subprocess. The data half is `tests.support.FakeReader`, so no test needs a database or
a running Precogly.
"""

from __future__ import annotations

import pytest
from mcp.server import MCPServer

from precogly_mcp.server import build_server
from tests.support import FakeReader


@pytest.fixture
def anyio_backend() -> str:
    """Run `@pytest.mark.anyio` tests on asyncio only.

    The MCP SDK is built on anyio, which would otherwise also parameterise every async
    test over trio. Nothing here is backend-specific and trio is not a dependency.
    """
    return "asyncio"


@pytest.fixture
def reader() -> FakeReader:
    """An empty reader for the test to fill and inspect."""
    return FakeReader()


@pytest.fixture
def server(reader: FakeReader) -> MCPServer:
    """A server whose every call reads `reader`.

    No auth settings and no verifier: that is the shape `Client` can speak over
    in-memory streams. The access token is then `None`, which `FakeReader` ignores.
    """
    return build_server(reader_for=lambda _token: reader)
