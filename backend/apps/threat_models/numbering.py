"""Threat and countermeasure numbers: `T7`, `C3`.

A number is handed out once, under a row lock on the model's state row, and
never reused or renumbered: deleting `T4` leaves a gap. Component, flow, zone,
boundary and whole-system threats share one sequence per model. The database
holds the integer; serializers add the prefix.
"""

from django.db import transaction

from .models import ThreatModelState

THREATS = "threats"
COUNTERMEASURES = "countermeasures"

_COUNTER_FIELD = {
    THREATS: "next_threat_number",
    COUNTERMEASURES: "next_countermeasure_number",
}


def allocate_numbers(threat_model_id, kind: str, count: int = 1) -> list[int]:
    """Return ``count`` consecutive numbers for ``kind`` and advance the counter.

    Runs in its own atomic block (joining the caller's transaction when there
    is one) and locks the state row, so two concurrent allocations never
    overlap. The state row exists from the model's creation; this never
    inserts one.
    """
    if count < 1:
        return []
    field = _COUNTER_FIELD[kind]
    with transaction.atomic():
        state = ThreatModelState.objects.select_for_update().get(
            threat_model_id=threat_model_id
        )
        first = getattr(state, field)
        setattr(state, field, first + count)
        state.save(update_fields=[field, "updated_at"])
    return list(range(first, first + count))


def raise_counter_to(threat_model_id, kind: str, minimum_next: int) -> None:
    """Make sure the next number is at least ``minimum_next`` (import, M12)."""
    field = _COUNTER_FIELD[kind]
    with transaction.atomic():
        state = ThreatModelState.objects.select_for_update().get(
            threat_model_id=threat_model_id
        )
        if getattr(state, field) < minimum_next:
            setattr(state, field, minimum_next)
            state.save(update_fields=[field, "updated_at"])
