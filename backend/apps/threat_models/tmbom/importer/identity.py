"""Model relationships and criticality on import (step 13).

A system asset carrying a ``threat-model`` external reference stands for
another model. Its BOM-Link's serial number is resolved among the models
the importing user can see (their organization), by the model's own
serial number first, then by a kept original (H13, I4); a match becomes a
``ThreatModelRelationship`` with the type from ``precogly:relationship``
(default related_to), and the asset is not kept as a component. No match
keeps the asset as a plain component with a warning. Two matches (the same
file imported twice) link neither and warn with both names (M13).
"""

import re

from apps.systems.models import Orgsystem, OrgsystemComponent
from apps.threat_models.models import ThreatModel, ThreatModelRelationship
from apps.threat_models.relationships import RelationshipError, add_relationship

from ..properties import PropertyOwner, read_properties

BOM_LINK = re.compile(r"^urn:cdx:([0-9a-f-]{36})/([1-9][0-9]*)")
RELATION_TYPES = {choice for choice, _ in ThreatModelRelationship.RelationType.choices}
SPEC_TO_CRITICALITY = {
    "minimal": "low",
    "low": "low",
    "moderate": "medium",
    "high": "high",
    "critical": "critical",
}


def _models_with_serial(serial: str, organization):
    own = list(
        ThreatModel.objects.filter(organization=organization, serial_number=serial)
    )
    if own:
        return own
    return list(
        ThreatModel.objects.filter(
            organization=organization,
            format_metadata__cyclonedx__imported_serial_number__in=[
                f"urn:uuid:{serial}",
                serial,
            ],
        )
    )


def import_relationships(document: dict, threat_model, context) -> None:
    for blueprint_data in document.get("blueprints") or []:
        if not isinstance(blueprint_data, dict):
            continue
        for asset_data in blueprint_data.get("assets") or []:
            if not isinstance(asset_data, dict):
                continue
            link = None
            for reference in asset_data.get("externalReferences") or []:
                if (
                    isinstance(reference, dict)
                    and reference.get("type") == "threat-model"
                ):
                    link = str(reference.get("url") or "")
                    break
            if link is None:
                continue
            label = str(asset_data.get("name") or asset_data.get("bom-ref"))
            match = BOM_LINK.match(link)
            if match is None:
                context.warn(
                    f"Asset '{label}': the threat-model reference '{link}' is not a "
                    "BOM-Link; the asset stays a component."
                )
                continue
            found = _models_with_serial(match.group(1), threat_model.organization)
            if not found:
                context.warn(
                    f"Asset '{label}': no model here has serial number {match.group(1)}; "
                    "the asset stays a component."
                )
                continue
            if len(found) > 1:
                names = ", ".join(sorted(m.name for m in found))
                context.warn(
                    f"Asset '{label}': {len(found)} models carry serial number "
                    f"{match.group(1)} ({names}); none was linked."
                )
                continue
            target = found[0]
            if target.pk == threat_model.pk:
                continue
            properties = read_properties(
                asset_data.get("properties"), PropertyOwner.ASSET
            )
            relation_type = properties.get("precogly:relationship")
            if relation_type not in RELATION_TYPES:
                relation_type = ThreatModelRelationship.RelationType.RELATED_TO
            try:
                add_relationship(threat_model, target, relation_type)
            except RelationshipError as error:
                context.warn(
                    f"Asset '{label}': relationship not linked ({error}); "
                    "the asset stays a component."
                )
                continue
            context.count("relationships")
            component = context.resolve(asset_data.get("bom-ref"), "asset")
            if isinstance(component, OrgsystemComponent):
                component.delete()
                context.count("components", -1)


def import_primary_system(document: dict, threat_model, context) -> None:
    """``metadata.component`` as the primary system (step 13).

    An inventory system of the organization with the same name is linked. One
    is created only when the document says the component is an inventory
    system (it carries ``precogly:lifecycle-state``); a model exported without
    a primary system names itself as the component, and importing it must not
    put a system in the inventory.
    """
    component = (document.get("metadata") or {}).get("component") or {}
    if not isinstance(component, dict) or not component.get("name"):
        return
    name = str(component["name"])[:255]
    properties = read_properties(component.get("properties"), PropertyOwner.SYSTEM)
    lifecycle_state = properties.get("precogly:lifecycle-state")
    system = Orgsystem.objects.filter(
        organization=threat_model.organization, name__iexact=name
    ).first()
    if system is None:
        if lifecycle_state not in Orgsystem.LifecycleState.values:
            if lifecycle_state:
                context.warn(
                    f"Lifecycle state '{lifecycle_state}' is not one of ours; "
                    "no inventory system was created."
                )
            return
        system = Orgsystem.objects.create(
            organization=threat_model.organization,
            name=name,
            description=str(component.get("description") or ""),
            lifecycle_state=lifecycle_state,
        )
        context.count("systems")
    threat_model.primary_system = system
    threat_model.save(update_fields=["primary_system"])


def import_criticality(document: dict, threat_model) -> None:
    component = (document.get("metadata") or {}).get("component") or {}
    if not isinstance(component, dict):
        return
    properties = read_properties(component.get("properties"), PropertyOwner.SYSTEM)
    value = SPEC_TO_CRITICALITY.get(str(properties.get("precogly:criticality") or ""))
    if value and value != threat_model.criticality:
        threat_model.criticality = value
        threat_model.save(update_fields=["criticality"])
