"""Shared test data and types.

Separate from `conftest.py` because conftest is auto-loaded by pytest for its fixtures
and importing from it fights that. Anything a test needs to import by name lives here.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx2

# A MockTransport handler: given the outbound request, return the response to fake.
Handler = Callable[[httpx2.Request], httpx2.Response]


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


def page(*rows: dict[str, object], total: int | None = None) -> dict[str, object]:
    """Wrap rows in the `PageNumberPagination` envelope the API returns.

    `total` sets `count` independently of how many rows are on the page, which is
    what a truncated read looks like: DRF counts the whole filtered queryset, and
    that difference is the only signal that there is more than what came back.
    """
    return {
        "count": len(rows) if total is None else total,
        "next": None,
        "previous": None,
        "results": list(rows),
    }


def json_response(status: int, body: object) -> Handler:
    """A handler that answers every request with one JSON response."""
    return lambda _request: httpx2.Response(status, json=body)
