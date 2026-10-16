"""Assumptions, business objectives and methodologies (steps 9 to 11).

- ``blueprints[].assumptions[]`` from the ``Assumption`` rows of each
  blueprint: topic, validity, impact, owner as a party (a user is declared
  once; a name-only owner is an inline person party with the ``owner``
  role), ``relatedAssets``, validation method and date.
- ``definitions.businessObjectives[]`` from the model's objectives;
  ``relatedBusinessObjectives`` on risks; the union on each abstract threat
  with ``precogly:business-objectives`` on the scenario.
- ``threats.methodologies[]``: spec values as strings, custom names as
  ``{name}`` objects.
"""

from apps.threat_models.models import ThreatModelReview

from ..refs import RefRegistry
from ..spec_values import custom_type
from .blueprint import component_ref

METHODOLOGIES = (
    "STRIDE",
    "LINDDUN",
    "PASTA",
    "MAESTRO",
    "OWASP",
    "TRIKE",
    "VAST",
    "ATFAA",
    "attack-tree",
)
ASSUMPTION_TOPICS = (
    "availability",
    "business",
    "compliance",
    "operational",
    "performance",
    "security",
    "technical",
)


def owner_party(owner, owner_name: str, parties):
    """A party ref for a user owner, else an inline party for a name."""
    if owner is not None:
        return parties.user_ref(owner, "owner")
    if owner_name:
        return {"roles": [{"role": "owner"}], "person": {"name": owner_name}}
    return None


def export_assumptions(blueprint, refs: RefRegistry, parties) -> list[dict]:
    entries = []
    for assumption in blueprint.assumptions.select_related("owner").prefetch_related(
        "component_links__component__component_library"
    ):
        entry = {
            "bom-ref": refs.ref("assumption", assumption),
            "description": assumption.description,
            "validity": assumption.validity,
        }
        if assumption.topic in ASSUMPTION_TOPICS:
            entry["topic"] = assumption.topic
        kept = ((assumption.format_metadata or {}).get("cyclonedx") or {}).get(
            "custom_type"
        )
        if isinstance(kept, dict) and kept.get("name") and not assumption.topic:
            entry["topic"] = kept
        if assumption.impact:
            entry["impact"] = assumption.impact
        party = owner_party(assumption.owner, assumption.owner_name, parties)
        if party is not None:
            entry["owner"] = party
        related = [
            component_ref(link.component, refs)
            for link in assumption.component_links.all()
        ]
        if related:
            entry["relatedAssets"] = related
        if assumption.validation_method:
            entry["validationMethod"] = assumption.validation_method
        if assumption.validation_date:
            entry["validationDate"] = assumption.validation_date.isoformat()
        entries.append(entry)
    return entries


def export_business_objectives(threat_model, refs: RefRegistry, parties) -> list[dict]:
    entries = []
    for objective in threat_model.business_objectives.select_related("owner"):
        entry = {"bom-ref": refs.ref("objective", objective), "name": objective.name}
        if objective.description:
            entry["description"] = objective.description
        if objective.criticality:
            entry["criticality"] = objective.criticality
        party = owner_party(objective.owner, objective.owner_name, parties)
        if party is not None:
            entry["owner"] = party
        entries.append(entry)
    return entries


def export_methodologies(threat_model) -> list:
    return [
        name if name in METHODOLOGIES else custom_type(name)
        for name in threat_model.methodologies or []
    ]


def reserve_context_refs(threat_model, refs: RefRegistry) -> None:
    from apps.threat_models.models import Assumption

    refs.reserve_stored(Assumption.objects.filter(blueprint__threat_model=threat_model))
    refs.reserve_stored(threat_model.business_objectives.all())


def document_lifecycles(threat_model) -> list[dict]:
    if not threat_model.lifecycle_phase:
        return []
    return [{"phase": threat_model.lifecycle_phase}]


def blueprint_metadata(threat_model, parties) -> dict | None:
    """The spec ``blueprint.metadata`` block: reviewer, approver, dates, lifecycle
    and validity period. The same block goes on every blueprint (F16)."""
    # A fresh read: the instance may carry the review row cached at creation.
    review = ThreatModelReview.objects.filter(threat_model=threat_model).first()
    metadata = {}
    if review is not None:
        if review.reviewer_id:
            metadata["reviewer"] = parties.user_ref(review.reviewer, "reviewer")
        if review.reviewed_at:
            metadata["reviewDate"] = review.reviewed_at.isoformat()
        if review.approver_id and review.approved_at:
            metadata["approver"] = parties.user_ref(review.approver, "signatory")
            metadata["approvalDate"] = review.approved_at.isoformat()
    lifecycles = document_lifecycles(threat_model)
    if lifecycles:
        metadata["lifecycles"] = lifecycles
    validity = {}
    if threat_model.valid_from:
        validity["start"] = threat_model.valid_from.isoformat()
    if threat_model.valid_until:
        validity["end"] = threat_model.valid_until.isoformat()
    if threat_model.review_frequency:
        validity["reviewFrequency"] = threat_model.review_frequency
    if validity:
        metadata["validityPeriod"] = validity
    return metadata or None
