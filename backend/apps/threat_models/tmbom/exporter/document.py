"""The document skeleton: metadata, the system component, blueprints, definitions.

Reads live rows only; nothing is replayed from an import snapshot (section
9.2). Every slice that later steps add plugs in here.
"""

from django.conf import settings
from django.utils.timezone import now

from apps.threat_models.models import ThreatModelState

from ..properties import PropertyOwner, make_property
from ..refs import RefRegistry
from .blueprint import export_blueprint, reserve_blueprint_refs
from .context import (
    blueprint_metadata,
    document_lifecycles,
    export_assumptions,
    export_business_objectives,
    export_methodologies,
    reserve_context_refs,
)
from .controls import PartyIndex, export_controls, reserve_control_refs
from .identity import relationship_assets, serial_urn, system_component, version_for
from .passthrough import apply_passthrough, kept_content_refs
from .risks import export_risks, reserve_risk_refs
from .threats import export_threats, reserve_threat_refs
from .trust_boundaries import export_trust_boundaries
from .use_cases import export_use_cases

PRECOGLY_VERSION = getattr(settings, "PRECOGLY_VERSION", "0.5.0")


def _metadata(threat_model, refs: RefRegistry) -> dict:
    metadata = {
        "timestamp": now().isoformat(),
        "tools": {
            "components": [
                {"type": "application", "name": "Precogly", "version": PRECOGLY_VERSION}
            ]
        },
    }
    creator = threat_model.created_by
    if creator is not None:
        author = {}
        full_name = creator.get_full_name()
        if full_name:
            author["name"] = full_name
        if creator.email:
            author["email"] = creator.email
        if author:
            metadata["authors"] = [author]

    metadata["component"] = system_component(threat_model, refs)
    return metadata


def export_threat_model(threat_model, warnings: list | None = None) -> dict:
    """Build the TM-BOM document for ``threat_model``.

    ``warnings`` collects what the export had to repair (stale refs in kept
    content, K2); the document itself is always complete.
    """
    warnings = warnings if warnings is not None else []
    refs = RefRegistry()
    blueprints = list(threat_model.blueprints.all())
    reserve_blueprint_refs(blueprints, refs)
    reserve_threat_refs(threat_model, refs)
    reserve_control_refs(threat_model, refs)
    reserve_risk_refs(threat_model, refs)
    reserve_context_refs(threat_model, refs)
    refs.reserve_kept(kept_content_refs(threat_model))

    metadata = _metadata(threat_model, refs)
    party_index = PartyIndex(refs)
    document = {
        "specFormat": "CycloneDX",
        "specVersion": "2.0",
        "serialNumber": serial_urn(threat_model),
        "metadata": metadata,
        "blueprints": [export_blueprint(blueprint, refs) for blueprint in blueprints],
    }
    model_assets, relationships = relationship_assets(
        threat_model, refs, metadata["component"]["bom-ref"]
    )
    if model_assets and document["blueprints"]:
        first = document["blueprints"][0]
        first["assets"] = [*first.get("assets", []), *model_assets]
        if relationships:
            first["relationships"] = relationships
    review_block = blueprint_metadata(threat_model, party_index)
    for blueprint, entry in zip(blueprints, document["blueprints"], strict=True):
        assumptions = export_assumptions(blueprint, refs, party_index)
        if assumptions:
            entry["assumptions"] = assumptions
        if review_block:
            entry["metadata"] = dict(review_block)
    lifecycles = document_lifecycles(threat_model)
    if lifecycles:
        metadata["lifecycles"] = lifecycles

    threats, actors = export_threats(
        threat_model, refs, system_ref=metadata["component"]["bom-ref"]
    )
    if threats:
        document["threats"] = threats
    if actors and document["blueprints"]:
        document["blueprints"][0]["actors"] = actors

    controls, _, standards = export_controls(threat_model, refs, parties=party_index)
    if controls:
        document["controls"] = controls
    risks = export_risks(threat_model, refs, party_index)
    if risks:
        document["risks"] = {"risks": risks}
    if party_index.entries:
        metadata["component"]["parties"] = party_index.entries

    trust_boundaries = export_trust_boundaries(threat_model, refs)
    if trust_boundaries:
        document.setdefault("threats", {})["trustBoundaries"] = trust_boundaries

    methodologies = export_methodologies(threat_model)
    if methodologies:
        document.setdefault("threats", {})["methodologies"] = methodologies

    definitions = {}
    objectives = export_business_objectives(threat_model, refs, party_index)
    if objectives:
        definitions["businessObjectives"] = objectives
    if standards:
        definitions["standards"] = standards
    use_cases = export_use_cases(threat_model, refs)
    if use_cases:
        definitions["useCases"] = use_cases
    if definitions:
        document["definitions"] = definitions

    document["properties"] = _document_properties(threat_model)
    apply_passthrough(document, threat_model, refs, warnings)
    # The version is decided last, from the whole document (F34, D7).
    document["version"] = version_for(threat_model, document)
    return document


def _document_properties(threat_model) -> list[dict]:
    """The number counters travel with the file (M12)."""
    # Read the row, not the instance's cached relation: the counter moves
    # under row locks while the model instance stays in memory.
    state = ThreatModelState.objects.filter(threat_model_id=threat_model.pk).first()
    next_threat_number = state.next_threat_number if state is not None else 1
    next_countermeasure_number = (
        state.next_countermeasure_number if state is not None else 1
    )
    return [
        make_property(
            "precogly:next-threat-number", PropertyOwner.DOCUMENT, next_threat_number
        ),
        make_property(
            "precogly:next-countermeasure-number",
            PropertyOwner.DOCUMENT,
            next_countermeasure_number,
        ),
        make_property(
            "precogly:risk-scoring-method",
            PropertyOwner.DOCUMENT,
            threat_model.risk_scoring_method,
        ),
    ]
