"""Document identity, the primary system, connected systems and relationships
(step 13 slice, plan sections 4.9, 9.3 row 13 and 9.4).

- ``serialNumber`` is the model's stored UUID as a URN; ``version`` comes
  from the state row and is raised only when the export digest changed
  (F34, D7): the digest is taken over the document with the serial number,
  version, timestamps and the version part of every BOM-Link removed.
- ``metadata.component`` is the primary system when one is set, else a
  component named after the model (M20). Its criticality travels as
  ``precogly:criticality``; a system's lifecycle state as
  ``precogly:lifecycle-state`` (F2).
- Each model relationship is a ``system`` asset on the first blueprint with a
  ``threat-model`` external reference holding the BOM-Link to the other
  model, ``precogly:relationship``, and a blueprint ``relationships`` entry
  for depends-on and subsystem-of (G6, D15).
"""

import copy
import hashlib
import json
import re

from django.db import transaction

from apps.threat_models.models import ThreatModelState

from ..properties import PropertyOwner, make_property
from ..refs import RefRegistry

CRITICALITY_TO_SPEC = {
    "low": "low",
    "medium": "moderate",
    "high": "high",
    "critical": "critical",
}
SPEC_TO_CRITICALITY = {
    "minimal": "low",
    "low": "low",
    "moderate": "medium",
    "high": "high",
    "critical": "critical",
}
BOM_LINK_VERSION = re.compile(r"^(urn:cdx:[0-9a-f-]{36})/[1-9][0-9]*(#.*)?$")


def serial_urn(threat_model) -> str:
    return f"urn:uuid:{threat_model.serial_number}"


def bom_link(threat_model) -> str:
    state = ThreatModelState.objects.filter(threat_model=threat_model).first()
    version = state.version if state is not None else 1
    return f"urn:cdx:{threat_model.serial_number}/{version}"


def system_component(threat_model, refs: RefRegistry) -> dict:
    """``metadata.component``: the primary system, else one named after the model."""
    primary = threat_model.primary_system
    if primary is not None:
        component = {
            "type": "application",
            "bom-ref": refs.fixed(f"system-{primary.pk}"),
            "name": primary.name,
        }
        if primary.description:
            component["description"] = primary.description
        properties = [
            make_property(
                "precogly:criticality",
                PropertyOwner.SYSTEM,
                CRITICALITY_TO_SPEC.get(threat_model.criticality, "moderate"),
            )
        ]
        if primary.lifecycle_state:
            properties.append(
                make_property(
                    "precogly:lifecycle-state",
                    PropertyOwner.SYSTEM,
                    primary.lifecycle_state,
                )
            )
        component["properties"] = properties
        return component
    component = {
        "type": "application",
        "bom-ref": refs.fixed(f"system-model-{threat_model.pk}"),
        "name": threat_model.name,
    }
    if threat_model.description:
        component["description"] = threat_model.description
    component["properties"] = [
        make_property(
            "precogly:criticality",
            PropertyOwner.SYSTEM,
            CRITICALITY_TO_SPEC.get(threat_model.criticality, "moderate"),
        )
    ]
    return component


def relationship_assets(threat_model, refs: RefRegistry, system_ref: str):
    """``(assets, relationships)`` for the model's outgoing relationships."""
    assets = []
    depends_on = []
    contains_me = []
    for relationship in threat_model.outgoing_relationships.select_related(
        "target_threat_model"
    ).order_by("id"):
        target = relationship.target_threat_model
        ref = refs.fixed(f"asset-model-{target.pk}")
        asset = {
            "bom-ref": ref,
            "name": target.name,
            "type": "system",
            "externalReferences": [{"type": "threat-model", "url": bom_link(target)}],
            "properties": [
                make_property(
                    "precogly:relationship",
                    PropertyOwner.ASSET,
                    relationship.relation_type,
                )
            ],
        }
        if target.description:
            asset["description"] = target.description
        assets.append(asset)
        if relationship.relation_type == "depends_on":
            depends_on.append(ref)
        elif relationship.relation_type == "subsystem_of":
            contains_me.append(ref)
    relationships = []
    if depends_on:
        relationships.append({"ref": system_ref, "dependsOn": depends_on})
    for other in contains_me:
        relationships.append({"ref": other, "contains": [system_ref]})
    return assets, relationships


def _strip_for_digest(document: dict) -> dict:
    stripped = copy.deepcopy(document)
    stripped.pop("serialNumber", None)
    stripped.pop("version", None)
    metadata = stripped.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("timestamp", None)

    def walk(node):
        if isinstance(node, dict):
            for key, value in list(node.items()):
                if key in ("timestamp", "reviewDate", "approvalDate") and isinstance(
                    value, str
                ):
                    node[key] = ""
                elif isinstance(value, str):
                    match = BOM_LINK_VERSION.match(value)
                    if match:
                        node[key] = match.group(1) + (match.group(2) or "")
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(stripped)
    return stripped


def export_digest(document: dict) -> str:
    payload = json.dumps(
        _strip_for_digest(document), sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def version_for(threat_model, document: dict) -> int:
    """The version to write: raised when the export digest changed (M2, N2).

    Written under a row lock on the state row; a first export keeps version 1.
    """
    digest = export_digest(document)
    with transaction.atomic():
        state = ThreatModelState.objects.select_for_update().get(
            threat_model=threat_model
        )
        if state.export_digest and state.export_digest != digest:
            state.version += 1
        if state.export_digest != digest:
            state.export_digest = digest
            state.save(update_fields=["version", "export_digest", "updated_at"])
        return state.version
