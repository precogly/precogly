"""Shared test data and types.

Separate from `conftest.py` because conftest is auto-loaded by pytest for its fixtures
and importing from it fights that. Anything a test needs to import by name lives here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from precogly_mcp.access import Listing


@dataclass
class FakeReader:
    """A `PrecoglyReader` returning what a test put in it, recording what it was asked.

    These tests cover what the tools do with rows: projecting, matching, counting.
    Whether a real reader returns the right rows for a user is Precogly's to test,
    against a database, in `backend/apps/core/tests/test_mcp_reader.py`.
    """

    threat_model_rows: list[dict[str, Any]] = field(default_factory=list)
    # `None` means "as many as there are rows". Set it higher to fake a reader that
    # could not return everything.
    threat_model_total: int | None = None
    threats: list[dict[str, Any]] = field(default_factory=list)
    countermeasures: list[dict[str, Any]] = field(default_factory=list)
    components: list[dict[str, Any]] = field(default_factory=list)

    organization_ids: list[int | None] = field(default_factory=list)

    async def threat_models(self, organization_id: int | None = None) -> Listing:
        self.organization_ids.append(organization_id)
        total = self.threat_model_total
        rows = list(self.threat_model_rows)
        return Listing(rows=rows, total=len(rows) if total is None else total)

    async def threat_library(self) -> list[dict[str, Any]]:
        return list(self.threats)

    async def countermeasure_library(self) -> list[dict[str, Any]]:
        return list(self.countermeasures)

    async def component_library(self) -> list[dict[str, Any]]:
        return list(self.components)


# One row exactly as the API sends it: camelCase, string timestamps with a Z suffix,
# a null businessUnitName, and `frameworks` as the objects the projection reduces to
# names. Copied from a live response rather than invented, so it stays a fixture of
# the real shape.
THREAT_MODEL_ROW: dict[str, object] = {
    "id": 1,
    "name": "Sample Threat Model",
    "description": "A sample threat model to explore Precogly's features.",
    "criticality": "high",
    "owner": "admin@precogly.dev",
    "owningTeam": 1,
    "owningTeamName": "My Team",
    "businessUnitName": None,
    "frameworks": [
        {"id": 4, "name": "CRA", "version": "2024"},
        {"id": 1, "name": "OWASP", "version": "2021"},
    ],
    "riskScoringMethod": "qualitative-matrix",
    "methodologies": ["STRIDE"],
    "lifecyclePhase": "",
    "approvedAt": None,
    "primarySystemName": None,
    "serialNumber": "6d9e7f2c-2b2a-4c7c-9b0e-4a3b2c1d0e9f",
    "version": 1,
    "blueprintCount": 1,
    "createdAt": "2026-07-29T12:58:38.046907Z",
    "updatedAt": "2026-07-29T12:58:38.046917Z",
}


# Two threat-library rows, copied live. They are the CWE-20 case from
# docs/0005-code-execution-over-tools.md: the first is mapped to CWE-20 and the second
# to CWE-200, so a substring matcher returns both and the tool must return one.
THREAT_LIBRARY_ROWS: list[dict[str, object]] = [
    {
        "id": 9,
        "name": "API Gateway Input Injection",
        "description": (
            "Malicious payloads passed through API Gateway to backend services,\n"
            "exploiting insufficient input validation.\n"
        ),
        "sourcePack": 13,
        "sourcePackName": "AWS",
        "sourcePackSlug": "aws",
        "taxonomyEntries": [
            {
                "id": 97,
                "taxonomySlug": "cwe",
                "taxonomyName": "CWE Software Weaknesses",
                "externalId": "CWE-20",
                "title": "Improper Input Validation",
                "referenceUrl": "https://cwe.mitre.org/data/definitions/20.html",
            },
            {
                "id": 2,
                "taxonomySlug": "stride",
                "taxonomyName": "STRIDE Threat Model",
                "externalId": "tampering",
                "title": "Tampering",
                # Empty for all six stride entries, which is why the projection can
                # drop the field rather than needing it for the ones that have none.
                "referenceUrl": "",
            },
        ],
    },
    {
        "id": 1,
        "name": "S3 Bucket Public Exposure",
        "description": "Misconfigured bucket policy exposes objects publicly.\n",
        "sourcePack": 13,
        "sourcePackName": "AWS",
        "sourcePackSlug": "aws",
        "taxonomyEntries": [
            {
                "id": 105,
                "taxonomySlug": "cwe",
                "taxonomyName": "CWE Software Weaknesses",
                "externalId": "CWE-200",
                "title": "Exposure of Sensitive Information",
                "referenceUrl": "https://cwe.mitre.org/data/definitions/200.html",
            },
        ],
    },
]


# Note what is absent: `CountermeasureLibraryListSerializer` omits `description`, so
# there is nothing here for a query to match beyond the name.
COUNTERMEASURE_LIBRARY_ROWS: list[dict[str, object]] = [
    {
        "id": 14,
        "name": "API Gateway API Keys",
        "description": "Require an API key on every request so unauthenticated "
        "callers are rejected at the gateway.",
        "controlFunctions": ["preventive"],
        "controlNature": "technical",
        "cost": "low",
        "defaultStatus": "gap",
        "sourcePack": 13,
        "sourcePackName": "AWS",
        "sourcePackSlug": "aws",
    },
    {
        "id": 18,
        "name": "API Gateway CloudWatch Logging",
        "description": "Send access logs to CloudWatch so rate limiting breaches "
        "and abuse can be reviewed.",
        "controlFunctions": ["detective"],
        "controlNature": "technical",
        "cost": "medium",
        "defaultStatus": "gap",
        "sourcePack": 13,
        "sourcePackName": "AWS",
        "sourcePackSlug": "aws",
    },
]


# This route has no list serializer, so `createdAt` and `updatedAt` come back and the
# projection drops them. Kept in the fixture so the drop is what is being tested.
COMPONENT_LIBRARY_ROWS: list[dict[str, object]] = [
    {
        "id": 4,
        "slug": "dynamodb",
        "qualifiedSlug": "aws/dynamodb",
        "name": "Amazon DynamoDB",
        "category": "datastore",
        "componentType": "NoSQL Database",
        "provider": "aws",
        "sourcePack": 13,
        "sourcePackName": "AWS",
        "sourcePackSlug": "aws",
        "createdAt": "2026-08-01T13:21:14.669326Z",
        "updatedAt": "2026-08-01T13:21:14.669329Z",
    },
    {
        "id": 1,
        "slug": "lambda",
        "qualifiedSlug": "aws/lambda",
        "name": "AWS Lambda",
        "category": "process",
        "componentType": "Serverless Function",
        "provider": "aws",
        "sourcePack": 13,
        "sourcePackName": "AWS",
        "sourcePackSlug": "aws",
        "createdAt": "2026-08-01T13:21:14.660891Z",
        "updatedAt": "2026-08-01T13:21:14.660895Z",
    },
]
