"""The server as a client sees it, over the real protocol.

`mcp.client.Client` accepts an `MCPServer` and drives it over in-memory streams, so
these exercise `tools/list` and `tools/call` exactly as opencode or Claude Code would —
including the schema generation and result shaping that a direct function call skips.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx2
import pytest
from mcp.client import Client

from precogly_mcp.server import build_server
from tests.support import (
    COMPONENT_LIBRARY_ROWS,
    COUNTERMEASURE_LIBRARY_ROWS,
    THREAT_LIBRARY_ROWS,
    THREAT_MODEL_ROW,
    Handler,
    json_response,
    page,
)

pytestmark = pytest.mark.anyio

# Built once for the module. These tests drive the unauthorized shape — no auth
# settings, no verifier — which is what `Client` can speak over in-memory streams;
# the token then comes from the environment, which `token` in conftest sets.
server = build_server()


async def test_every_tool_is_advertised_read_only() -> None:
    """Nothing here writes yet, and a client should not have to assume otherwise.

    The count is asserted because it is a budget: docs/0005-code-execution-over-tools.md
    puts the revisit trigger at nine, where measured tool-selection accuracy starts to
    degrade. Update the number when a tool lands, and read that document at nine.
    """
    async with Client(server) as client:
        tools = (await client.list_tools()).tools

    assert [t.name for t in tools] == [
        "list_threat_models",
        "search_threat_library",
        "search_countermeasure_library",
        "search_component_library",
    ]
    for tool in tools:
        assert tool.annotations is not None, tool.name
        assert tool.annotations.read_only_hint is True, tool.name
        assert tool.annotations.idempotent_hint is True, tool.name
        assert tool.title, tool.name


async def test_the_reader_is_not_advertised_as_an_argument() -> None:
    """A tool's parameters are its schema, and one of them is not a parameter.

    Tools take a `Context` to reach the reader the lifespan carries. The SDK strips it
    by annotation rather than by name, so a wrong annotation does not fail — it
    advertises an argument no caller can supply, on every tool at once.
    """
    async with Client(server) as client:
        tools = (await client.list_tools()).tools

    for tool in tools:
        assert "ctx" not in tool.input_schema.get("properties", {}), tool.name

    by_name = {tool.name: tool for tool in tools}
    assert list(by_name["list_threat_models"].input_schema["properties"]) == [
        "organization_id"
    ]


async def described(name: str) -> str:
    """The description a client sees for one tool."""
    async with Client(server) as client:
        tools = (await client.list_tools()).tools
    return next(t.description or "" for t in tools if t.name == name)


async def test_description_qualifies_frameworks_as_incidence() -> None:
    # `frameworks` is derived incidence: one countermeasure mapping to one requirement
    # puts a model under a framework. Unqualified, the field reads as coverage, and an
    # agent asked "are we SOC 2 compliant" answers yes off a single grazing control.
    assert "incidence, not coverage" in await described("list_threat_models")


async def test_truncation_is_reported_rather_than_left_to_be_inferred(
    patched_server_http: Callable[[Handler], None], token: str
) -> None:
    """A short read has to say how much was left, not hint at it in prose.

    The description used to promise "at most twenty" and ask the model to treat a full
    page as "at least twenty" — an inference, and one that reads identically whether
    twenty is the whole set or the first of two hundred. `total` is the fact instead.
    """
    patched_server_http(json_response(200, page(THREAT_MODEL_ROW, total=37)))

    async with Client(server) as client:
        result = await client.call_tool("list_threat_models", {})

    payload = json.loads(result.content[0].text)  # type: ignore[union-attr]
    assert len(payload["models"]) == 1
    assert payload["total"] == 37


async def test_organization_id_is_an_optional_integer() -> None:
    """Ids are `bigint`; a string parameter would be rejected by the filter."""
    async with Client(server) as client:
        tools = (await client.list_tools()).tools

    listing = next(t for t in tools if t.name == "list_threat_models")
    prop = listing.input_schema["properties"]["organization_id"]
    assert {"type": "integer"} in prop["anyOf"]
    assert {"type": "null"} in prop["anyOf"]
    assert prop["default"] is None


async def test_returns_projected_rows(
    patched_server_http: Callable[[Handler], None], token: str
) -> None:
    patched_server_http(json_response(200, page(THREAT_MODEL_ROW)))

    async with Client(server) as client:
        result = await client.call_tool("list_threat_models", {})

    payload = json.loads(result.content[0].text)  # type: ignore[union-attr]
    assert payload["models"][0]["name"] == "Sample Threat Model"
    assert payload["models"][0]["frameworks"] == ["CRA", "OWASP"]


async def test_organization_id_is_sent_as_organization(
    patched_server_http: Callable[[Handler], None],
    recorded_requests: list[httpx2.Request],
    token: str,
) -> None:
    """The wire name differs from the argument name, and getting it wrong is silent.

    django-filter ignores an unrecognised parameter rather than rejecting it, so passing
    `organization_id=` would return an unfiltered page with no error at all.
    """
    patched_server_http(json_response(200, page(THREAT_MODEL_ROW)))

    async with Client(server) as client:
        await client.call_tool("list_threat_models", {"organization_id": 7})

    params = recorded_requests[0].url.params
    assert params["organization"] == "7"
    assert "organization_id" not in params


async def test_omitting_the_argument_sends_no_filter(
    patched_server_http: Callable[[Handler], None],
    recorded_requests: list[httpx2.Request],
    token: str,
) -> None:
    patched_server_http(json_response(200, page()))

    async with Client(server) as client:
        await client.call_tool("list_threat_models", {})

    assert "organization" not in recorded_requests[0].url.params


async def search(client: Client, name: str, args: dict[str, object]) -> dict[str, Any]:
    """Call a search tool and decode the whole answer, counts included."""
    result = await client.call_tool(name, args)
    assert not result.is_error, result.content[0].text  # type: ignore[union-attr]
    answer: dict[str, Any] = json.loads(result.content[0].text)  # type: ignore[union-attr]
    return answer


async def call(
    client: Client, name: str, args: dict[str, object]
) -> list[dict[str, Any]]:
    """The rows a search matched, for assertions that are not about the counts."""
    rows: list[dict[str, Any]] = (await search(client, name, args))["matches"]
    return rows


async def test_search_sends_no_query_parameters(
    patched_server_http: Callable[[Handler], None],
    recorded_requests: list[httpx2.Request],
    token: str,
) -> None:
    """The whole catalog is fetched and filtered here. That is the design, not a gap.

    `?search=` is `icontains` over name and description only, and the hand-rolled
    parameters on these viewsets 500 on bad input and are absent from the published
    schema (precogly/precogly #266, #261). Filtering here reaches the taxonomy
    mappings, which no server-side search can match at all.
    """
    patched_server_http(json_response(200, THREAT_LIBRARY_ROWS))

    async with Client(server) as client:
        await call(client, "search_threat_library", {"query": "injection"})

    assert not recorded_requests[0].url.params, "the query must not reach the viewset"


async def test_identifier_search_does_not_match_a_longer_identifier(
    patched_server_http: Callable[[Handler], None], token: str
) -> None:
    """Regression, and the reason the query is filtered here rather than forwarded.

    `?search=CWE-20` is `icontains`, so on the seeded catalog it returns 17 threats
    where 9 are mapped to CWE-20. The extras are not near-misses a caller can spot:
    CWE-200 is Exposure of Sensitive Information, an unrelated weakness.
    """
    patched_server_http(json_response(200, THREAT_LIBRARY_ROWS))

    async with Client(server) as client:
        rows = await call(client, "search_threat_library", {"query": "CWE-20"})

    assert [row["name"] for row in rows] == ["API Gateway Input Injection"]


async def test_threat_search_matches_prose_as_a_substring(
    patched_server_http: Callable[[Handler], None], token: str
) -> None:
    """Only identifiers match in full; titles and descriptions are substrings."""
    patched_server_http(json_response(200, THREAT_LIBRARY_ROWS))

    async with Client(server) as client:
        by_description = await call(
            client, "search_threat_library", {"query": "bucket policy"}
        )
        by_entry_title = await call(
            client, "search_threat_library", {"query": "improper input"}
        )

    assert [row["id"] for row in by_description] == [1]
    assert [row["id"] for row in by_entry_title] == [9]


async def test_threat_projection_drops_three_taxonomy_fields(
    patched_server_http: Callable[[Handler], None], token: str
) -> None:
    """`reference_url` is derivable from `external_id`, and empty for every stride
    entry. `taxonomy_name` is determined by `taxonomy_slug`. The entry `id` is a
    primary key no tool accepts."""
    patched_server_http(json_response(200, THREAT_LIBRARY_ROWS))

    async with Client(server) as client:
        rows = await call(client, "search_threat_library", {"query": "CWE-20"})

    assert set(rows[0]) == {
        "id",
        "name",
        "description",
        "sourcePackName",
        "taxonomyEntries",
    }
    assert set(rows[0]["taxonomyEntries"][0]) == {
        "taxonomySlug",
        "externalId",
        "title",
    }


async def test_omitting_the_query_returns_the_whole_catalog(
    patched_server_http: Callable[[Handler], None], token: str
) -> None:
    patched_server_http(json_response(200, THREAT_LIBRARY_ROWS))

    async with Client(server) as client:
        rows = await call(client, "search_threat_library", {})

    assert len(rows) == len(THREAT_LIBRARY_ROWS)


async def test_a_search_counts_its_own_matches(
    patched_server_http: Callable[[Handler], None], token: str
) -> None:
    """The counts exist because the arithmetic is what a model gets wrong.

    Asked which countermeasures are preventive, Claude Sonnet 4.5 was handed all 37
    rows and answered 36 while grouping them by cost. Both numbers are derivable from
    the response — that is the difference from `ThreatModelListing.total`, which
    reports something the rows cannot show — so what these buy is that nobody has to
    derive them.
    """
    patched_server_http(json_response(200, THREAT_LIBRARY_ROWS))

    async with Client(server) as client:
        narrowed = await search(client, "search_threat_library", {"query": "CWE-20"})
        everything = await search(client, "search_threat_library", {})

    assert narrowed["matched"] == len(narrowed["matches"]) == 1
    assert narrowed["catalogSize"] == len(THREAT_LIBRARY_ROWS)

    assert (
        everything["matched"] == everything["catalogSize"] == len(THREAT_LIBRARY_ROWS)
    )


async def test_nothing_matching_is_not_an_empty_catalog(
    patched_server_http: Callable[[Handler], None], token: str
) -> None:
    """`matched` of 0 beside a non-zero `catalogSize` says which of the two happened.

    A bare empty list cannot: an agent reading it has to guess whether the catalog was
    searched and held nothing relevant, or was empty to begin with.
    """
    patched_server_http(json_response(200, COUNTERMEASURE_LIBRARY_ROWS))

    async with Client(server) as client:
        answer = await search(
            client, "search_countermeasure_library", {"query": "no such control"}
        )

    assert answer["matches"] == []
    assert answer["matched"] == 0
    assert answer["catalogSize"] == len(COUNTERMEASURE_LIBRARY_ROWS) > 0


async def test_countermeasure_search_narrows_by_control_function_and_cost(
    patched_server_http: Callable[[Handler], None], token: str
) -> None:
    patched_server_http(json_response(200, COUNTERMEASURE_LIBRARY_ROWS))

    async with Client(server) as client:
        detective = await call(
            client, "search_countermeasure_library", {"control_function": "detective"}
        )
        cheap = await call(client, "search_countermeasure_library", {"cost": "low"})
        both = await call(
            client,
            "search_countermeasure_library",
            {"control_function": "detective", "cost": "low"},
        )

    assert [row["id"] for row in detective] == [18]
    assert [row["id"] for row in cheap] == [14]
    assert both == []


async def test_countermeasure_query_matches_the_description(
    patched_server_http: Callable[[Handler], None], token: str
) -> None:
    """The listing carries `description`, so a mechanism the name does not mention
    is still found through it, and the tool description says so."""
    patched_server_http(json_response(200, COUNTERMEASURE_LIBRARY_ROWS))

    async with Client(server) as client:
        by_mechanism = await call(
            client, "search_countermeasure_library", {"query": "rate limiting"}
        )

    assert [row["id"] for row in by_mechanism] == [18]
    assert by_mechanism[0]["description"].startswith("Send access logs")

    description = await described("search_countermeasure_library")
    assert "name and the description" in description


async def test_component_search_matches_type_and_slug_not_only_name(
    patched_server_http: Callable[[Handler], None], token: str
) -> None:
    patched_server_http(json_response(200, COMPONENT_LIBRARY_ROWS))

    async with Client(server) as client:
        by_type = await call(client, "search_component_library", {"query": "database"})
        by_slug = await call(client, "search_component_library", {"query": "aws/l"})
        by_category = await call(
            client, "search_component_library", {"category": "datastore"}
        )

    assert [row["id"] for row in by_type] == [4]
    assert [row["id"] for row in by_slug] == [1]
    assert [row["id"] for row in by_category] == [4]


async def test_component_projection_drops_timestamps_and_the_bare_slug(
    patched_server_http: Callable[[Handler], None], token: str
) -> None:
    """These are pack templates. When one was imported does not bear on choosing it,
    and the bare slug is unique only within a pack where `qualifiedSlug` is not."""
    patched_server_http(json_response(200, COMPONENT_LIBRARY_ROWS))

    async with Client(server) as client:
        rows = await call(client, "search_component_library", {})

    assert set(rows[0]) == {
        "id",
        "qualifiedSlug",
        "name",
        "category",
        "kind",
        "effectiveKind",
        "componentType",
        "provider",
        "sourcePackName",
    }


def test_empty_precogly_url_falls_back_to_the_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An MCP client can hand over an empty string for a variable it was told to pass.

    opencode interpolates `{env:PRECOGLY_URL}` into the server's environment. Set but
    empty, that produced "Could not reach Precogly at :" — the connect-failure message
    naming no address, which reads as a down server rather than as configuration.
    """
    import importlib

    from precogly_mcp import server as server_module

    monkeypatch.setenv("PRECOGLY_URL", "")
    assert importlib.reload(server_module)._BASE_URL == "http://localhost:8000"

    monkeypatch.setenv("PRECOGLY_URL", "https://precogly.example")
    assert importlib.reload(server_module)._BASE_URL == "https://precogly.example"

    # Leave the module as the rest of the suite expects to find it.
    monkeypatch.delenv("PRECOGLY_URL")
    importlib.reload(server_module)


async def test_api_errors_reach_the_caller_as_tool_errors(
    patched_server_http: Callable[[Handler], None], token: str
) -> None:
    """The client's message is written for an agent, so it must survive the boundary."""
    patched_server_http(
        json_response(401, {"detail": "Given token not valid for any token type"})
    )

    async with Client(server) as client:
        result = await client.call_tool("list_threat_models", {})

    assert result.is_error
    assert "60 minutes" in result.content[0].text  # type: ignore[union-attr]
