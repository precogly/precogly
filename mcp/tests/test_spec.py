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
                # The shape drf-spectacular emits: one body per parser DRF accepts.
                "requestBody": {
                    "content": {
                        media_type: {
                            "schema": {"$ref": "#/components/schemas/ThreatModel"}
                        }
                        for media_type in [
                            "application/json",
                            "application/x-www-form-urlencoded",
                            "multipart/form-data",
                        ]
                    },
                    "required": True,
                },
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
    body = post["requestBody"]["content"]["application/json"]["schema"]

    assert body["properties"]["organization"] == ORGANIZATION


def test_request_bodies_keep_only_json() -> None:
    # `request()` sends JSON only; the form and multipart copies were 38% of the
    # reduced spec.
    body = process_spec(SPEC)["paths"]["/api/threat-models/"]["post"]["requestBody"]

    assert list(body["content"]) == ["application/json"]
    assert body["required"] is True


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


def test_json_pointer_escapes_are_decoded() -> None:
    spec = {"components": {"schemas": {"a/b": {"type": "string"}, "~1": {"x": 1}}}}

    assert resolve_refs({"$ref": "#/components/schemas/a~1b"}, spec) == {
        "type": "string"
    }
    # `~01` is the escaped name `~1`, not `/`.
    assert resolve_refs({"$ref": "#/components/schemas/~01"}, spec) == {"x": 1}


def test_operations_keep_only_what_a_search_reads() -> None:
    item = process_spec(SPEC)["paths"]["/api/threat-models/"]

    assert set(item) == {"get", "post"}
    assert set(item["get"]) == {"summary", "tags", "responses"}


def test_the_input_is_not_modified() -> None:
    # The backend's schema is cached and shared by every caller in the process.
    before = copy.deepcopy(SPEC)

    process_spec(SPEC)

    assert before == SPEC
