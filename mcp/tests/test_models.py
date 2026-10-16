"""What the projection guarantees about a threat model row.

Each test here pins a decision argued in docs/0002-tool-implementation-order.md or in
`models.py` itself. They exist so that reversing one of those decisions fails a test
rather than passing silently.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from precogly_mcp.models import ThreatModelSummary
from tests.support import THREAT_MODEL_ROW


def test_parses_the_camelcase_the_api_sends() -> None:
    """The API camelCases both directions; attributes stay snake_case."""
    row = ThreatModelSummary.model_validate(THREAT_MODEL_ROW)

    assert row.owning_team_name == "My Team"
    assert row.risk_scoring_method == "qualitative-matrix"
    assert isinstance(row.created_at, datetime)


def test_serialises_back_to_camelcase() -> None:
    dumped = ThreatModelSummary.model_validate(THREAT_MODEL_ROW).model_dump(
        by_alias=True
    )

    assert "owningTeamName" in dumped
    assert "owning_team_name" not in dumped


def test_narrows_frameworks_to_names() -> None:
    """Framework objects are carried, reduced to their names.

    This field was dropped once, on the grounds that `get_frameworks` costs three
    queries per row. The server pays that cost either way — it is a
    `SerializerMethodField` in the list serializer's `fields`, so it runs regardless of
    the result. Dropping it bought tokens and nothing else, at the price of making
    "which models map to SOC 2" unanswerable from the one tool that could have.
    """
    dumped = ThreatModelSummary.model_validate(THREAT_MODEL_ROW).model_dump(
        by_alias=True
    )

    assert dumped["frameworks"] == ["CRA", "OWASP"]


def test_frameworks_default_to_empty() -> None:
    """A model whose countermeasures map to nothing has no frameworks at all.

    The fixture is a seeded model connected to every pack, so it never exhibits this.
    """
    without = {k: v for k, v in THREAT_MODEL_ROW.items() if k != "frameworks"}

    assert ThreatModelSummary.model_validate(without).frameworks == []


def test_unknown_criticality_is_rejected_loudly() -> None:
    """A vocabulary added upstream must fail here, not reach an agent unchecked.

    The alternative considered was a plain `str` with the known values in the field
    description, which would pass an unrecognised value through silently.
    """
    mutated = dict(THREAT_MODEL_ROW, criticality="informational")

    with pytest.raises(ValidationError, match="low"):
        ThreatModelSummary.model_validate(mutated)


def test_unknown_risk_scoring_method_is_rejected_loudly() -> None:
    mutated = dict(THREAT_MODEL_ROW, riskScoringMethod="monte_carlo")

    with pytest.raises(ValidationError, match="qualitative-matrix"):
        ThreatModelSummary.model_validate(mutated)


def test_description_is_required_because_the_column_is_not_null() -> None:
    """An empty description arrives as `""`, never as null, so it is not optional."""
    without = {k: v for k, v in THREAT_MODEL_ROW.items() if k != "description"}

    with pytest.raises(ValidationError, match="description"):
        ThreatModelSummary.model_validate(without)

    assert ThreatModelSummary.model_validate({**THREAT_MODEL_ROW, "description": ""})


def test_nullable_columns_accept_null() -> None:
    """`created_by_id` and `owning_team_id` are nullable, so these four may be absent.

    The live sample only had `businessUnitName` null, which is why this is asserted from
    the schema rather than from what one response happened to contain.
    """
    sparse = dict(
        THREAT_MODEL_ROW,
        owner=None,
        owningTeam=None,
        owningTeamName=None,
        businessUnitName=None,
    )

    row = ThreatModelSummary.model_validate(sparse)

    assert (row.owner, row.owning_team, row.owning_team_name) == (None, None, None)


def test_unknown_extra_keys_are_ignored() -> None:
    """Extras cannot be forbidden: the projection drops `frameworks` by design."""
    assert ThreatModelSummary.model_validate(
        dict(THREAT_MODEL_ROW, someFieldAddedUpstream=1)
    )
