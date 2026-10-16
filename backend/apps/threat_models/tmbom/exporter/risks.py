"""``risks.risks[]`` (step 8 slice, plan sections 4.7 and 9.3).

One entry per ``Risk``: ``statement`` (the risk's, else its description, else
its name, marked ``precogly:statement-generated``), ``status``, ``domains``,
``relatedThreats`` as scenario refs, the three ratings, ``responses[]`` with
their own refs, strategy, status, effectiveness, cost, priority, owner,
target date and ``controls``, and the owner party. ``exposure`` is derived
and not exported. Values kept at import (``kept_values``) are written back
while the row still holds what it was imported as: a response's original
status, the effectiveness ``rating``, an owner that is no member, a
domain's priority and description, and custom domains.
"""

from ..kept_values import effectiveness_entry, kept_owner_entry
from ..properties import PropertyOwner, make_property
from ..ratings import rating_to_spec
from ..refs import RefRegistry
from ..spec_values import (
    RESPONSE_STATUS_TO_SPEC,
    SPEC_STATUS_TO_RESPONSE,
    custom_type,
    type_name,
)

RISK_STATUSES = (
    "identified",
    "assessed",
    "mitigated",
    "accepted",
    "transferred",
    "retired",
)


def _cyclonedx_metadata(row) -> dict:
    return (getattr(row, "format_metadata", None) or {}).get("cyclonedx") or {}


def _response_status(response):
    # A spec status stored as one of ours ("proposed" as planned, a custom
    # status as planned) is written back while the row still holds it.
    original = _cyclonedx_metadata(response).get("original_status")
    if original is not None:
        mapped = (
            SPEC_STATUS_TO_RESPONSE.get(type_name(original), "planned")
            if isinstance(original, str)
            else "planned"
        )
        if mapped == response.status:
            return original
    return RESPONSE_STATUS_TO_SPEC.get(response.status) or custom_type(response.status)


def _owner(row, refs: RefRegistry, parties):
    if row.owner_id:
        return parties.user_ref(row.owner, "owner")
    return kept_owner_entry(row, refs)


def _response(response, refs: RefRegistry, parties) -> dict:
    entry = {
        "bom-ref": refs.ref("response", response),
        "strategy": response.strategy,
    }
    if response.description:
        entry["description"] = response.description
    entry["status"] = _response_status(response)
    effectiveness = effectiveness_entry(response.effectiveness, response)
    if effectiveness is not None:
        entry["effectiveness"] = effectiveness
    if response.cost:
        entry["cost"] = response.cost
    if response.priority:
        entry["priority"] = response.priority
    owner = _owner(response, refs, parties)
    if owner is not None:
        entry["owner"] = owner
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
    details = _cyclonedx_metadata(risk).get("domain_details") or {}
    domains = [
        {"type": domain, **(details.get(domain) or {})} for domain in risk.domains or []
    ]
    domains += [
        domain
        for domain in _cyclonedx_metadata(risk).get("extra_domains") or []
        if isinstance(domain, dict)
    ]
    if domains:
        entry["domains"] = domains
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
    owner = _owner(risk, refs, parties)
    if owner is not None:
        entry["owner"] = owner
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
