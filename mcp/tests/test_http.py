"""The endpoint over HTTP, as `asgi_app` builds it for Precogly to mount.

`test_tools.py` drives the server over in-memory streams, which skip everything HTTP
adds: the bearer middleware, the Host check, the protected-resource document and the
403 scope challenge. These send real requests through Starlette's test client, which
also runs the lifespan.

The host is `precogly.example`, not `localhost`: the SDK's defaults accept only
loopback hosts, which is the failure a localhost test would hide.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

import pytest
from mcp.server.auth.provider import AccessToken
from starlette.testclient import TestClient

from precogly_mcp.scope_challenge import InsufficientScope
from precogly_mcp.server import asgi_app

ORIGIN = "https://precogly.example"
RESOURCE = f"{ORIGIN}/mcp"
METADATA = "/.well-known/oauth-protected-resource/mcp"
READ_TOKEN = "read-token"

HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}


class ReadOnlyVerifier:
    """Accepts one token, granted `read` only."""

    async def verify_token(self, token: str) -> AccessToken | None:
        if token != READ_TOKEN:
            return None
        return AccessToken(
            token=token, client_id="c", scopes=["read"], subject="7", resource=RESOURCE
        )


async def fake_request(
    access_token: AccessToken,
    method: str,
    path: str,
    params: Mapping[str, Any] | None = None,
    body: Any = None,
) -> Any:
    # The backend's `request` refuses a write without `write` the same way.
    if method != "GET":
        raise InsufficientScope(f"{method} needs the `write` scope.", scopes={"write"})
    return {"path": path}


async def fake_schema() -> dict[str, Any]:
    return {"paths": {}}


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = asgi_app(
        request=fake_request,
        schema=fake_schema,
        token_verifier=ReadOnlyVerifier(),
        issuer_url=ORIGIN,
        resource_url=RESOURCE,
    )
    with TestClient(app, base_url=ORIGIN) as test_client:
        yield test_client


def execute(client: TestClient, code: str, **headers: str) -> Any:
    return client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "execute", "arguments": {"code": code}},
        },
        headers={**HEADERS, "Authorization": f"Bearer {READ_TOKEN}", **headers},
    )


def test_a_call_to_the_public_host_is_served(client: TestClient) -> None:
    response = execute(client, 'await request("GET", "/api/zones/")')

    assert response.status_code == 200, response.text
    assert "/api/zones/" in response.text


def test_a_call_addressed_to_another_host_is_refused(client: TestClient) -> None:
    response = execute(client, "1", host="attacker.example")

    assert response.status_code == 421


def test_a_call_without_a_token_is_told_where_to_authorize(client: TestClient) -> None:
    response = client.post("/mcp", json={}, headers=HEADERS)

    assert response.status_code == 401
    assert (
        f'resource_metadata="{ORIGIN}{METADATA}"'
        in response.headers["WWW-Authenticate"]
    )


def test_the_metadata_document_names_this_resource(client: TestClient) -> None:
    response = client.get(METADATA)

    assert response.status_code == 200
    assert response.json()["resource"] == RESOURCE


def test_a_refused_write_becomes_a_challenge_for_every_scope(
    client: TestClient,
) -> None:
    # The code catches the refusal, so only `execute` recording it outside the
    # sandbox can turn it into a 403. The challenge asks for the granted scope too,
    # so re-authorizing for `write` does not drop `read`.
    response = execute(
        client,
        'try:\n    await request("POST", "/api/zones/")\nexcept Exception:\n    pass',
    )

    assert response.status_code == 403
    challenge = response.headers["WWW-Authenticate"]
    assert 'error="insufficient_scope"' in challenge
    assert 'scope="read write"' in challenge
