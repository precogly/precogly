"""Assumptions, business objectives and methodologies on import (steps 9 to 11)."""

from datetime import datetime

from django.contrib.auth import get_user_model

from apps.threat_models.models import (
    METHODOLOGIES,
    Assumption,
    AssumptionComponent,
    BusinessObjective,
)

from ..passthrough import keep_unknown
from ..refs import remember_ref
from ..spec_values import type_name

User = get_user_model()

ASSUMPTION_TOPICS = (
    "availability",
    "business",
    "compliance",
    "operational",
    "performance",
    "security",
    "technical",
)
VALIDITIES = ("invalid", "unknown", "unverified", "verified")
CRITICALITIES = ("minimal", "low", "moderate", "high", "critical")


def _owner(raw, context, threat_model):
    """``(user, name)`` from a party ref or inline party."""
    party = raw
    if isinstance(raw, str):
        party = context.parties.get(raw) if hasattr(context, "parties") else None
        if party is None:
            component = (context.document.get("metadata") or {}).get("component") or {}
            for candidate in (
                component.get("parties") if isinstance(component, dict) else None
            ) or []:
                if isinstance(candidate, dict) and candidate.get("bom-ref") == raw:
                    party = candidate
                    break
    if not isinstance(party, dict):
        return None, ""
    person = party.get("person") if isinstance(party.get("person"), dict) else {}
    for item in person.get("email") or []:
        if isinstance(item, dict) and item.get("address"):
            user = User.objects.filter(
                email__iexact=str(item["address"]),
                organization_memberships__organization_id=threat_model.organization_id,
            ).first()
            if user is not None:
                return user, ""
    organization = (
        party.get("organization") if isinstance(party.get("organization"), dict) else {}
    )
    return None, str(person.get("name") or organization.get("name") or "")[:255]


def _datetime(raw, context, label: str):
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        context.warn(f"{label}: date '{raw}' ignored.")
        return None


def import_assumptions(data: dict, blueprint, context) -> None:
    threat_model = blueprint.threat_model
    for index, assumption_data in enumerate(data.get("assumptions") or []):
        if not isinstance(assumption_data, dict) or not assumption_data.get(
            "description"
        ):
            context.warn(
                f"Assumption {index} of '{blueprint.name}' has no description; skipped."
            )
            continue
        label = str(assumption_data["description"])[:60]
        raw_topic = assumption_data.get("topic")
        topic = type_name(raw_topic)
        kept = None
        if topic and topic not in ASSUMPTION_TOPICS:
            kept = raw_topic if isinstance(raw_topic, dict) else {"name": topic}
            context.warn(
                f"Assumption '{label}': topic '{topic}' is not a spec value; kept for export."
            )
            topic = ""
        validity = assumption_data.get("validity")
        owner, owner_name = _owner(assumption_data.get("owner"), context, threat_model)
        assumption = Assumption.objects.create(
            blueprint=blueprint,
            description=str(assumption_data["description"]),
            topic=topic,
            validity=validity if validity in VALIDITIES else "unknown",
            impact=str(assumption_data.get("impact") or ""),
            owner=owner,
            owner_name=owner_name,
            validation_method=str(assumption_data.get("validationMethod") or ""),
            validation_date=_datetime(
                assumption_data.get("validationDate"), context, f"Assumption '{label}'"
            ),
            display_order=index,
        )
        remember_ref(assumption, assumption_data.get("bom-ref", ""))
        keep_unknown(assumption, assumption_data, "assumption")
        if kept is not None:
            assumption.format_metadata.setdefault("cyclonedx", {})["custom_type"] = kept
        assumption.save(update_fields=["format_metadata"])
        for position, ref in enumerate(assumption_data.get("relatedAssets") or []):
            component = context.resolve(ref, "asset", "datastore")
            if component is None or component.blueprint_id != blueprint.id:
                context.warn(
                    f"Assumption '{label}': related asset '{ref}' is not a component of "
                    "this blueprint; skipped."
                )
                continue
            AssumptionComponent.objects.get_or_create(
                assumption=assumption,
                component=component,
                defaults={"display_order": position},
            )
        context.register(assumption_data.get("bom-ref"), "assumption", assumption)
        context.count("assumptions")


def import_business_objectives(document: dict, threat_model, context) -> None:
    definitions = document.get("definitions") or {}
    for index, data in enumerate(definitions.get("businessObjectives") or []):
        if not isinstance(data, dict) or not data.get("name"):
            context.warn(f"Business objective {index} has no name; skipped.")
            continue
        criticality = type_name(data.get("criticality"))
        owner, owner_name = _owner(data.get("owner"), context, threat_model)
        objective = BusinessObjective.objects.create(
            threat_model=threat_model,
            name=str(data["name"])[:255],
            description=str(data.get("description") or ""),
            criticality=criticality if criticality in CRITICALITIES else "",
            owner=owner,
            owner_name=owner_name,
            display_order=index,
        )
        remember_ref(objective, data.get("bom-ref", ""))
        keep_unknown(objective, data, "objective")
        objective.save(update_fields=["format_metadata"])
        context.register(data.get("bom-ref"), "objective", objective)
        context.count("business_objectives")


def import_methodologies(document: dict, threat_model, context) -> None:
    section = document.get("threats")
    raw = section.get("methodologies") if isinstance(section, dict) else None
    if not isinstance(raw, list):
        return
    names = []
    for item in raw:
        name = type_name(item)
        if name and name not in names:
            names.append(name[:100])
        if name and name not in METHODOLOGIES and isinstance(item, str):
            context.warn(
                f"Methodology '{name}' is not a spec value; kept as a custom name."
            )
    if names:
        threat_model.methodologies = names
        threat_model.save(update_fields=["methodologies"])


LIFECYCLE_PHASES = (
    "design",
    "pre-build",
    "build",
    "post-build",
    "operations",
    "discovery",
    "decommission",
)


def _phase(lifecycles) -> str:
    for item in lifecycles or []:
        if isinstance(item, dict) and item.get("phase") in LIFECYCLE_PHASES:
            return item["phase"]
    return ""


def _party_summary(ref: str, context) -> dict:
    component = (context.document.get("metadata") or {}).get("component") or {}
    parties = component.get("parties") if isinstance(component, dict) else None
    for party in parties or []:
        if isinstance(party, dict) and party.get("bom-ref") == ref:
            person = (
                party.get("person") if isinstance(party.get("person"), dict) else {}
            )
            emails = [
                item.get("address")
                for item in person.get("email") or []
                if isinstance(item, dict) and item.get("address")
            ]
            return {
                "ref": ref,
                "name": person.get("name"),
                "email": emails[0] if emails else None,
            }
    return {"ref": ref}


def import_blueprint_metadata(document: dict, threat_model, context) -> None:
    """Lifecycle, validity period and the source document's review block.

    Import does not count as approval (D18): reviewer, approver and dates are
    kept in ``format_metadata["cyclonedx"]["review"]`` and shown as approved
    in the source document; the model starts with no approval of its own.
    The first blueprint with a block wins; others that differ are warned (F16).
    """
    blocks = [
        (b.get("name"), b.get("metadata"))
        for b in document.get("blueprints") or []
        if isinstance(b, dict)
        and isinstance(b.get("metadata"), dict)
        and b.get("metadata")
    ]
    update_fields = []
    block = {}
    if blocks:
        first_name, block = blocks[0]
        for name, other in blocks[1:]:
            if other != block:
                context.warn(
                    f"Blueprint '{name}': its metadata block differs from "
                    f"'{first_name}'; the first one is kept."
                )
    phase = _phase(block.get("lifecycles")) or _phase(
        (document.get("metadata") or {}).get("lifecycles")
    )
    if phase:
        threat_model.lifecycle_phase = phase
        update_fields.append("lifecycle_phase")
    validity = (
        block.get("validityPeriod")
        if isinstance(block.get("validityPeriod"), dict)
        else {}
    )
    for key, field in (("start", "valid_from"), ("end", "valid_until")):
        value = _datetime(validity.get(key), context, "Validity period")
        if value is not None:
            setattr(threat_model, field, value)
            update_fields.append(field)
    frequency = validity.get("reviewFrequency")
    if isinstance(frequency, str) and frequency:
        threat_model.review_frequency = frequency[:40]
        update_fields.append("review_frequency")
    review = {}
    for key in ("reviewer", "reviewDate", "approver", "approvalDate"):
        if block.get(key) is not None:
            review[key] = block[key]
    for key in ("reviewer", "approver"):
        if isinstance(review.get(key), str):
            review[key] = _party_summary(review[key], context)
    if review:
        metadata = dict(threat_model.format_metadata or {})
        cyclonedx = dict(metadata.get("cyclonedx") or {})
        cyclonedx["review"] = review
        metadata["cyclonedx"] = cyclonedx
        threat_model.format_metadata = metadata
        update_fields.append("format_metadata")
        context.warn(
            "The document carries a review or approval; it is shown as approved in "
            "the source document and the imported model starts unapproved."
        )
    if update_fields:
        threat_model.save(update_fields=list(dict.fromkeys(update_fields)))
