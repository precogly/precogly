"""``risks.risks[]`` (step 8 slice, plan sections 4.7 and 9.3).

One entry per ``Risk``: ``statement`` (the risk's, else its description, else
its name, marked ``precogly:statement-generated``), ``status``, ``domains``,
``relatedThreats`` as scenario refs, the three ratings, ``responses[]`` with
their own refs, strategy, status, effectiveness, cost, priority, owner,
target date and ``controls``, and the owner party. ``exposure`` is derived
and not exported.
"""

from ..properties import PropertyOwner, make_property
from ..ratings import rating_to_spec
from ..refs import RefRegistry
from ..spec_values import custom_type

RISK_STATUSES = (
    "identified",
    "assessed",
    "mitigated",
    "accepted",
    "transferred",
    "retired",
)
RESPONSE_STATUS_TO_SPEC = {
    "planned": "planned",
    "in_progress": "in-progress",
    "implemented": "implemented",
    "verified": "verified",
}


def _cyclonedx_metadata(row) -> dict:
    return (getattr(row, "format_metadata", None) or {}).get("cyclonedx") or {}


def _response(response, refs: RefRegistry, parties) -> dict:
    entry = {
        "bom-ref": refs.ref("response", response),
        "strategy": response.strategy,
    }
    if response.description:
        entry["description"] = response.description
    entry["status"] = RESPONSE_STATUS_TO_SPEC.get(response.status) or custom_type(
        response.status
    )
    if response.effectiveness is not None:
        entry["effectiveness"] = {"percentage": response.effectiveness}
    if response.cost:
        entry["cost"] = response.cost
    if response.priority:
        entry["priority"] = response.priority
    if response.owner_id:
        entry["owner"] = parties.user_ref(response.owner, "owner")
    if response.target_date:
        entry["targetDate"] = response.target_date.isoformat()
    controls = [
        refs.ref("control", link.countermeasure)
        for link in response.countermeasure_links.all()
    ]
    if controls:
        entry["controls"] = controls
    return entry


def _risk(risk, refs: RefRegistry, parties) -> dict:
    statement = risk.statement or risk.description or risk.name
    entry = {
        "bom-ref": refs.ref("risk", risk),
        "name": risk.name,
        "statement": statement,
    }
    if risk.description:
        entry["description"] = risk.description
    entry["status"] = (
        risk.status if risk.status in RISK_STATUSES else custom_type(risk.status)
    )
    kept_status = _cyclonedx_metadata(risk).get("custom_status")
    if isinstance(kept_status, dict) and risk.status == "identified":
        entry["status"] = kept_status
    if risk.domains:
        entry["domains"] = [{"type": domain} for domain in risk.domains]
    # Explicit order: the link table has no default ordering, and an unordered
    # scan can return rows in any order once the table has seen deletes.
    related = [
        refs.ref("scenario", link.threat) for link in risk.risk_threats.order_by("id")
    ]
    for extra in _cyclonedx_metadata(risk).get("extra_related_threats") or []:
        if isinstance(extra, str) and refs.will_resolve(extra) and extra not in related:
            related.append(extra)
    if related:
        entry["relatedThreats"] = related
    objectives = [
        refs.ref("objective", link.business_objective)
        for link in risk.business_objective_links.all()
    ]
    if objectives:
        entry["relatedBusinessObjectives"] = objectives
    entry["inherentRisk"] = rating_to_spec(risk.inherent)
    if risk.residual_id:
        entry["residualRisk"] = rating_to_spec(risk.residual)
    if risk.target_id:
        entry["targetRisk"] = rating_to_spec(risk.target)
    responses = [_response(r, refs, parties) for r in risk.responses.all()]
    for kept in _cyclonedx_metadata(risk).get("extra_responses") or []:
        if isinstance(kept, dict) and kept.get("bom-ref") and kept.get("strategy"):
            responses.append(kept)
    if responses:
        entry["responses"] = responses
    if risk.owner_id:
        entry["owner"] = parties.user_ref(risk.owner, "owner")
    properties = []
    if not risk.statement:
        properties.append(
            make_property("precogly:statement-generated", PropertyOwner.RISK, True)
        )
    if risk.assigned_to_id:
        properties.append(
            make_property(
                "precogly:assigned-to",
                PropertyOwner.RISK,
                parties.user_ref(risk.assigned_to, "assignee"),
            )
        )
    if properties:
        entry["properties"] = properties
    return entry


def risks_queryset(threat_model):
    return (
        threat_model.risks.select_related(
            "inherent", "residual", "target", "owner", "assigned_to"
        )
        .prefetch_related(
            "risk_threats__threat",
            "responses__owner",
            "responses__countermeasure_links__countermeasure",
            "business_objective_links__business_objective",
        )
        .order_by("id")
    )


def reserve_risk_refs(threat_model, refs: RefRegistry) -> None:
    from apps.threats.models import RiskResponse

    refs.reserve_stored(threat_model.risks.all())
    refs.reserve_stored(RiskResponse.objects.filter(risk__threat_model=threat_model))


def export_risks(threat_model, refs: RefRegistry, parties) -> list[dict]:
    return [_risk(risk, refs, parties) for risk in risks_queryset(threat_model)]
