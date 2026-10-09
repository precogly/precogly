"""Re-emit kept content after the document is built (section 9.7)."""

import copy

from apps.systems.models import Boundary, DataAsset, Flow, OrgsystemComponent, Zone
from apps.threat_models.models import Assumption, Blueprint, BusinessObjective, UseCase
from apps.threats.models import (
    InstanceCountermeasure,
    InstanceThreat,
    Risk,
    RiskResponse,
)

from ..passthrough import restore, restore_document_level, stale_refs
from ..refs import RefRegistry, stored_ref


def _entries_by_ref(node, found: dict) -> None:
    if isinstance(node, dict):
        ref = node.get("bom-ref")
        if isinstance(ref, str):
            found.setdefault(ref, node)
        for value in node.values():
            _entries_by_ref(value, found)
    elif isinstance(node, list):
        for item in node:
            _entries_by_ref(item, found)


def _rows_with_kept_content(threat_model):
    kept = []
    for model, filters in (
        (Blueprint, {"threat_model": threat_model}),
        (Zone, {"blueprint__threat_model": threat_model}),
        (Boundary, {"blueprint__threat_model": threat_model}),
        (OrgsystemComponent, {"blueprint__threat_model": threat_model}),
        (DataAsset, {"blueprint__threat_model": threat_model}),
        (Flow, {"blueprint__threat_model": threat_model}),
        (Assumption, {"blueprint__threat_model": threat_model}),
        (BusinessObjective, {"threat_model": threat_model}),
        (UseCase, {"threat_model": threat_model}),
        (InstanceThreat, {"threat_model": threat_model}),
        (InstanceCountermeasure, {"threat_model": threat_model}),
        (Risk, {"threat_model": threat_model}),
        (RiskResponse, {"risk__threat_model": threat_model}),
    ):
        rows = model.objects.filter(**filters).filter(
            format_metadata__has_key="cyclonedx"
        )
        for row in rows:
            cyclonedx = (row.format_metadata or {}).get("cyclonedx") or {}
            if any(
                key in cyclonedx
                for key in ("passthrough", "foreign_properties", "threat_passthrough")
            ):
                kept.append(row)
    return kept


def apply_passthrough(
    document: dict, threat_model, refs: RefRegistry, warnings: list
) -> None:
    """Merge every row's kept content and the document-level sections back in."""
    stale = stale_refs(threat_model, document)
    entries: dict = {}
    _entries_by_ref(document, entries)
    for row in _rows_with_kept_content(threat_model):
        ref = stored_ref(row)
        entry = entries.get(ref) if ref else None
        if entry is None:
            continue
        label = f"{type(row).__name__} '{ref}'"
        restore(entry, row, stale=stale, warnings=warnings, label=label)
        threat_kept = ((row.format_metadata or {}).get("cyclonedx") or {}).get(
            "threat_passthrough"
        )
        if isinstance(threat_kept, dict) and isinstance(entry.get("threats"), list):
            abstract = entries.get(entry["threats"][0]) if entry["threats"] else None
            if abstract is not None:
                for key, value in threat_kept.items():
                    if key not in abstract:
                        abstract[key] = copy.deepcopy(value)
    _restore_blueprint_extras(document, threat_model, refs, warnings)
    restore_document_level(document, threat_model, stale=stale, warnings=warnings)


def _restore_blueprint_extras(
    document: dict, threat_model, refs: RefRegistry, warnings: list
) -> None:
    """Kept visualizations, actors nobody became and the scope's unknown keys."""
    by_ref = {}
    for blueprint in threat_model.blueprints.all():
        ref = stored_ref(blueprint)
        if ref:
            by_ref[ref] = blueprint
    for entry in document.get("blueprints") or []:
        blueprint = by_ref.get(entry.get("bom-ref"))
        if blueprint is None:
            continue
        cyclonedx = (blueprint.format_metadata or {}).get("cyclonedx") or {}
        for visualization in cyclonedx.get("visualizations") or []:
            if isinstance(visualization, dict) and not refs.is_issued(
                visualization.get("bom-ref", "")
            ):
                entry.setdefault("visualizations", []).append(
                    copy.deepcopy(visualization)
                )
        issued_actors = {a.get("bom-ref") for a in entry.get("actors") or []}
        for actor in cyclonedx.get("actors") or []:
            ref = actor.get("bom-ref") if isinstance(actor, dict) else None
            if ref and ref not in issued_actors and not refs.is_issued(ref):
                entry.setdefault("actors", []).append(copy.deepcopy(actor))
        scope_kept = cyclonedx.get("scope_passthrough")
        if isinstance(scope_kept, dict):
            scope = entry.setdefault("scope", {"name": f"{blueprint.name} scope"})
            for key, value in scope_kept.items():
                scope.setdefault(key, copy.deepcopy(value))
