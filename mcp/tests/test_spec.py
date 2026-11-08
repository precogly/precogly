"""`process_spec` inlines references and keeps only what a search reads."""

from __future__ import annotations

import copy
from typing import Any

from precogly_mcp.spec import process_spec, resolve_refs

ORGANIZATION = {"type": "object", "properties": {"name": {"type": "string"}}}

SPEC: dict[str, Any] = {
    "paths": {
        "/api/threat-models/": {
            "parameters": [{"name": "path-level", "in": "query"}],
            "get": {
                "operationId": "threat_models_list",
                "summary": "List threat models",
                "tags": ["threat-models"],
                "security": [{"oauth2": []}],
                "responses": {
                    "200": {"$ref": "#/components/responses/ThreatModelList"},
                },
            },
            "post": {
                "requestBody": {"$ref": "#/components/schemas/ThreatModel"},
                "responses": {"201": {"$ref": "#/components/schemas/ThreatModel"}},
            },
        },
    },
    "components": {
        "responses": {
            "ThreatModelList": {
                "type": "array",
                "items": {"$ref": "#/components/schemas/ThreatModel"},
            }
        },
        "schemas": {
            "ThreatModel": {
                "type": "object",
                "properties": {
                    "organization": {"$ref": "#/components/schemas/Organization"},
                    "owningOrganization": {"$ref": "#/components/schemas/Organization"},
                    "parent": {"$ref": "#/components/schemas/ThreatModel"},
                },
            },
            "Organization": ORGANIZATION,
        },
    },
}


def test_references_are_inlined() -> None:
    post = process_spec(SPEC)["paths"]["/api/threat-models/"]["post"]

    assert post["requestBody"]["properties"]["organization"] == ORGANIZATION


def test_a_component_used_twice_is_inlined_both_times() -> None:
    # Regression guard against tracking every reference seen rather than ancestors:
    # the second `Organization` would come back as `$circular`.
    model = resolve_refs({"$ref": "#/components/schemas/ThreatModel"}, SPEC)

    assert model["properties"]["organization"] == ORGANIZATION
    assert model["properties"]["owningOrganization"] == ORGANIZATION


def test_only_a_genuine_cycle_is_marked() -> None:
    model = resolve_refs({"$ref": "#/components/schemas/ThreatModel"}, SPEC)

    assert model["properties"]["parent"] == {
        "$circular": "#/components/schemas/ThreatModel"
    }


def test_operations_keep_only_what_a_search_reads() -> None:
    item = process_spec(SPEC)["paths"]["/api/threat-models/"]

    assert set(item) == {"get", "post"}
    assert set(item["get"]) == {"summary", "tags", "responses"}


def test_the_input_is_not_modified() -> None:
    # The backend's schema is cached and shared by every caller in the process.
    before = copy.deepcopy(SPEC)

    process_spec(SPEC)

    assert before == SPEC
