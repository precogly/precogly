"""Import entry point (plan section 9.2).

Rules:

- Import warns, it does not reject. The document is validated against the
  pinned schema and each error becomes a warning; anything skipped is a
  warning, never a silent drop. Only a document that is not a TM-BOM at all
  is refused.
- Import writes through the services where there are services.
- A ref that arrives is kept on its row (``format_metadata.cyclonedx.bom_ref``)
  so export re-emits it.
- The importing user's team owns the new model (#337).
"""

import logging
from dataclasses import dataclass, field

from django.db import transaction

from apps.organizations.models import TeamMembership
from apps.packs.models import LibraryPack
from apps.threat_models.models import ThreatModel, ThreatModelLibraryPack

from ..passthrough import keep_document_level
from ..properties import PropertyOwner, read_properties
from ..validation import check_ref_integrity, validate_document
from .blueprint import generate_missing_canvases, import_blueprint
from .context import (
    import_blueprint_metadata,
    import_business_objectives,
    import_methodologies,
)
from .controls import import_controls
from .identity import import_criticality, import_primary_system, import_relationships
from .risks import import_risks
from .threats import import_threats
from .use_cases import import_use_cases

logger = logging.getLogger(__name__)

SECTIONS_NOT_YET_IMPORTED = ()


class TmBomImportError(Exception):
    """User-facing import error. Raised only when the file is not a TM-BOM."""


@dataclass
class ImportContext:
    """Everything the importer threads through its steps."""

    document: dict
    organization: object
    user: object
    warnings: list[str] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    refs: dict = field(default_factory=dict)  # bom-ref -> (kind, row)
    actors: dict = field(default_factory=dict)  # actor bom-ref -> {blueprint, data}
    scenarios_by_threat_ref: dict = field(default_factory=dict)  # threat ref -> rows
    mitigations_by_threat_ref: dict = field(default_factory=dict)  # threat ref -> refs

    def warn(self, message: str) -> None:
        logger.warning("TM-BOM import: %s", message)
        self.warnings.append(message)

    def count(self, key: str, amount: int = 1) -> None:
        self.summary[key] = self.summary.get(key, 0) + amount

    def register(self, bom_ref, kind: str, row) -> None:
        if isinstance(bom_ref, str) and bom_ref:
            self.refs[bom_ref] = (kind, row)

    def resolve(self, bom_ref, *kinds):
        """The row a ref points at, when it is one of ``kinds`` (any kind if empty)."""
        entry = self.refs.get(bom_ref) if isinstance(bom_ref, str) else None
        if entry is None:
            return None
        kind, row = entry
        if kinds and kind not in kinds:
            return None
        return row


def _apply_scoring_method(document: dict, threat_model, context) -> None:
    """The document's ``precogly:risk-scoring-method``, when it is one of ours."""
    properties = read_properties(document.get("properties"), PropertyOwner.DOCUMENT)
    method = properties.get("precogly:risk-scoring-method")
    if not method:
        return
    if method not in {
        value for value, _ in ThreatModel._meta.get_field("risk_scoring_method").choices
    }:
        context.warn(
            f"Risk scoring method '{method}' is not one of ours; the default is used."
        )
        return
    threat_model.risk_scoring_method = method


def _refuse_unless_tmbom(document) -> None:
    if not isinstance(document, dict):
        raise TmBomImportError(
            "The uploaded file does not contain a JSON object. "
            "CycloneDX TM-BOM files must be a JSON object at the top level."
        )
    spec_format = document.get("specFormat")
    if spec_format != "CycloneDX":
        if spec_format:
            raise TmBomImportError(
                f"This file has specFormat '{spec_format}' but expected 'CycloneDX'. "
                "Make sure you are uploading a CycloneDX TM-BOM file."
            )
        raise TmBomImportError(
            "This file has no specFormat field. CycloneDX TM-BOM files must "
            "declare specFormat: CycloneDX."
        )
    spec_version = str(document.get("specVersion", ""))
    if not spec_version.startswith("2."):
        raise TmBomImportError(
            f"This file declares specVersion '{spec_version}'; only CycloneDX 2.x "
            "TM-BOM files can be imported."
        )


def _owning_team_for(user, organization):
    """The user's team in the organization, when they have exactly one."""
    memberships = TeamMembership.objects.filter(
        user=user, team__organization=organization
    ).select_related("team")
    if memberships.count() == 1:
        return memberships.first().team
    return None


def _model_name(document: dict) -> tuple[str, str]:
    component = (document.get("metadata") or {}).get("component") or {}
    blueprints = document.get("blueprints") or []
    first = blueprints[0] if blueprints and isinstance(blueprints[0], dict) else {}
    name = component.get("name") or first.get("name") or "Imported threat model"
    description = component.get("description") or first.get("description") or ""
    return str(name)[:255], str(description)


def import_document(document, organization, user):
    """Create a threat model from ``document``. Returns ``(threat_model, summary)``."""
    _refuse_unless_tmbom(document)
    context = ImportContext(document=document, organization=organization, user=user)

    for error in validate_document(document):
        context.warn(f"Schema: {error}")
    for finding in check_ref_integrity(document):
        context.warn(f"References: {finding}")

    name, description = _model_name(document)

    with transaction.atomic():
        threat_model = ThreatModel.objects.create(
            organization=organization,
            created_by=user,
            owning_team=_owning_team_for(user, organization),
            name=name,
            description=description,
            format_metadata={
                "cyclonedx": {
                    "spec_version": str(document.get("specVersion", "2.0")),
                    "imported_serial_number": document.get("serialNumber"),
                    "imported_version": document.get("version"),
                }
            },
        )
        context.count("threat_model")

        # Every installed pack is connected, as the create API does, so the
        # imported components can generate threats.
        ThreatModelLibraryPack.objects.bulk_create(
            [
                ThreatModelLibraryPack(threat_model=threat_model, library_pack=pack)
                for pack in LibraryPack.objects.all()
            ],
            ignore_conflicts=True,
        )

        blueprints = document.get("blueprints") or []
        if not blueprints:
            context.warn("The document has no blueprints; the model has no structure.")
        for index, blueprint_data in enumerate(blueprints):
            if not isinstance(blueprint_data, dict):
                context.warn(f"Blueprint {index} is not an object and was skipped.")
                continue
            import_blueprint(blueprint_data, threat_model, context, is_first=index == 0)

        import_use_cases(document, threat_model, context)
        import_business_objectives(document, threat_model, context)
        import_methodologies(document, threat_model, context)
        import_blueprint_metadata(document, threat_model, context)
        import_relationships(document, threat_model, context)
        import_criticality(document, threat_model)
        import_primary_system(document, threat_model, context)
        generate_missing_canvases(threat_model, context)
        system_component = (document.get("metadata") or {}).get("component") or {}
        system_ref = (
            system_component.get("bom-ref")
            if isinstance(system_component, dict)
            else None
        )
        import_threats(document, threat_model, context, system_ref=system_ref)
        import_controls(document, threat_model, context, system_ref=system_ref)
        import_risks(document, threat_model, context)
        keep_document_level(threat_model, document)
        _apply_scoring_method(document, threat_model, context)
        threat_model.save(update_fields=["format_metadata", "risk_scoring_method"])

        for section in SECTIONS_NOT_YET_IMPORTED:
            if document.get(section):
                context.warn(
                    f"The '{section}' section is not imported by this version; "
                    "it was left out."
                )

    summary = dict(context.summary)
    if context.warnings:
        summary["warnings"] = list(context.warnings)
    return threat_model, summary
