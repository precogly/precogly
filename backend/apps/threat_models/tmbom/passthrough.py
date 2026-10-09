"""Passthrough: what we do not model is kept whole and re-emitted (section 9.7).

Three places hold it, all under ``format_metadata["cyclonedx"]["passthrough"]``:

- the threat model: unknown top-level sections and the unknown keys of the
  ``threats``, ``risks`` and ``definitions`` sections (attack trees, attack
  paths, abuse cases, attack patterns, threat profiles, assessments, risk
  appetites, patents, ...);
- a blueprint: its unknown keys (behaviors, interfaces, requirements, use
  case entries, external references, ...);
- any known object: its unknown fields and its foreign (non ``precogly:``)
  properties, under ``format_metadata["cyclonedx"]["passthrough"]`` and
  ``["foreign_properties"]`` of that row.

On export the kept content is merged back under the object it came from;
a key we now write wins over a kept one. Refs inside kept content can go
stale when the rows they point at are deleted (K2): the set of refs the
document carried is stored at import, and on export a kept ref that was in
that set but resolves to nothing any more is removed from its list, or its
optional field dropped, with a warning naming the object.
"""

import copy

from .properties import PROPERTY_PREFIX
from .spec_values import REF_KEYS
from .validation import required_ref_keys

DOCUMENT_KNOWN = {
    "$schema",
    "specFormat",
    "specVersion",
    "serialNumber",
    "version",
    "metadata",
    "blueprints",
    "threats",
    "controls",
    "risks",
    "definitions",
    "properties",
}
THREATS_SECTION_KNOWN = {"threats", "scenarios", "trustBoundaries", "methodologies"}
RISKS_SECTION_KNOWN = {"risks"}
DEFINITIONS_KNOWN = {"standards", "useCases", "businessObjectives", "requirements"}
METADATA_KNOWN = {"timestamp", "tools", "authors", "component", "lifecycles"}

OBJECT_KNOWN = {
    "blueprint": {
        "bom-ref",
        "name",
        "description",
        "metadata",
        "modelTypes",
        "scope",
        "assets",
        "dataStores",
        "dataSets",
        "zones",
        "boundaries",
        "flows",
        "relationships",
        "actors",
        "assumptions",
        "visualizations",
        "properties",
    },
    "asset": {
        "bom-ref",
        "name",
        "description",
        "type",
        "zone",
        "properties",
        "externalReferences",
    },
    "data-store": {
        "bom-ref",
        "name",
        "description",
        "type",
        "vendor",
        "zone",
        "dataSets",
        "properties",
    },
    "data-set": {
        "bom-ref",
        "name",
        "description",
        "dataProfiles",
        "placements",
        "properties",
    },
    "zone": {"bom-ref", "name", "description", "type", "parent", "properties"},
    "boundary": {
        "bom-ref",
        "name",
        "type",
        "zones",
        "crossingRequirements",
        "sessionManagement",
        "properties",
    },
    "flow": {
        "bom-ref",
        "name",
        "description",
        "type",
        "source",
        "destination",
        "encrypted",
        "protocols",
        "authentication",
        "authorization",
        "dataProfiles",
        "properties",
    },
    "assumption": {
        "bom-ref",
        "description",
        "topic",
        "relatedAssets",
        "validity",
        "impact",
        "owner",
        "validationMethod",
        "validationDate",
    },
    "visualization": {"bom-ref", "name", "type", "attachment", "properties"},
    "scope": {"name", "description", "excludedComponents", "properties"},
    "threat": {
        "bom-ref",
        "name",
        "description",
        "source",
        "origin",
        "categories",
        "mitigations",
        "relatedBusinessObjectives",
        "properties",
    },
    "scenario": {
        "bom-ref",
        "name",
        "description",
        "threats",
        "actor",
        "intent",
        "accessLevel",
        "affectedAssets",
        "likelihood",
        "impact",
        "riskScore",
        "properties",
    },
    "control": {
        "bom-ref",
        "name",
        "description",
        "category",
        "status",
        "appliesTo",
        "implementedBy",
        "satisfies",
        "effectiveness",
        "owner",
        "externalReferences",
        "properties",
    },
    "risk": {
        "bom-ref",
        "name",
        "statement",
        "description",
        "domains",
        "relatedThreats",
        "relatedBusinessObjectives",
        "inherentRisk",
        "residualRisk",
        "targetRisk",
        "responses",
        "status",
        "owner",
        "properties",
    },
    "response": {
        "bom-ref",
        "strategy",
        "description",
        "controls",
        "status",
        "effectiveness",
        "cost",
        "priority",
        "owner",
        "targetDate",
    },
    "objective": {
        "bom-ref",
        "name",
        "description",
        "criticality",
        "owner",
        "properties",
    },
    "usecase": {
        "bom-ref",
        "name",
        "description",
        "preconditions",
        "postconditions",
        "successCriteria",
        "mainFlow",
        "alternativeFlows",
        "exceptions",
        "notes",
    },
}


def _cyclonedx(row) -> dict:
    metadata = dict(getattr(row, "format_metadata", None) or {})
    cyclonedx = dict(metadata.get("cyclonedx") or {})
    metadata["cyclonedx"] = cyclonedx
    row.format_metadata = metadata
    return cyclonedx


def keep_unknown(row, data: dict, kind: str) -> bool:
    """Store ``data``'s unknown keys and foreign properties on ``row``.

    Returns True when something was kept; the caller saves the row.
    """
    known = OBJECT_KNOWN[kind]
    unknown = {key: value for key, value in data.items() if key not in known}
    foreign = [
        item
        for item in data.get("properties") or []
        if isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and not item["name"].startswith(PROPERTY_PREFIX)
    ]
    if not unknown and not foreign:
        return False
    cyclonedx = _cyclonedx(row)
    if unknown:
        cyclonedx["passthrough"] = copy.deepcopy(unknown)
    if foreign:
        cyclonedx["foreign_properties"] = copy.deepcopy(foreign)
    return True


def keep_document_level(threat_model, document: dict) -> None:
    """Unknown top-level sections and the unknown keys of the known sections."""
    kept = {}
    top = {key: value for key, value in document.items() if key not in DOCUMENT_KNOWN}
    if top:
        kept["document"] = top
    for section, known in (
        ("threats", THREATS_SECTION_KNOWN),
        ("risks", RISKS_SECTION_KNOWN),
        ("definitions", DEFINITIONS_KNOWN),
        ("metadata", METADATA_KNOWN),
    ):
        value = document.get(section)
        if isinstance(value, dict):
            unknown = {key: item for key, item in value.items() if key not in known}
            if unknown:
                kept[section] = unknown
    foreign = [
        item
        for item in document.get("properties") or []
        if isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and not item["name"].startswith(PROPERTY_PREFIX)
    ]
    cyclonedx = _cyclonedx(threat_model)
    if kept:
        cyclonedx["passthrough"] = copy.deepcopy(kept)
    if foreign:
        cyclonedx["foreign_properties"] = copy.deepcopy(foreign)
    cyclonedx["known_refs"] = sorted(collect_refs(document))


def collect_refs(node, found=None) -> set:
    """Every ``bom-ref`` value in the document."""
    if found is None:
        found = set()
    if isinstance(node, dict):
        value = node.get("bom-ref")
        if isinstance(value, str):
            found.add(value)
        for item in node.values():
            collect_refs(item, found)
    elif isinstance(node, list):
        for item in node:
            collect_refs(item, found)
    return found


# Returned by ``_repair`` for an entry that lost a required ref: the caller
# leaves the entry out.
_LEFT_OUT = object()


def _describe(entry: dict, key: str) -> str:
    """How a warning names an entry: its key, then its name or bom-ref."""
    name = entry.get("name") or entry.get("bom-ref")
    return f"{key} '{name}'" if name else f"an entry in {key}"


def _repair(value, stale: set, label: str, warnings: list, key: str = ""):
    """Remove stale refs from kept content (K2, R19).

    Only values under ref keys (``spec_values.REF_KEYS``) count as refs, so a
    name or description that happens to equal a stale ref stays. A stale
    entry in a ref list goes; a stale optional ref field goes. An entry that
    loses a ref the schema requires somewhere (``required_ref_keys``) is left
    out whole, since it would not validate without it. Warnings name the
    entry, not only the section.
    """
    if isinstance(value, list):
        result = []
        for item in value:
            if isinstance(item, str):
                if key in REF_KEYS and item in stale:
                    warnings.append(
                        f"{label}: removed '{item}' from {key}; it no longer resolves."
                    )
                    continue
                result.append(item)
                continue
            repaired = _repair(item, stale, label, warnings, key)
            if repaired is not _LEFT_OUT:
                result.append(repaired)
        return result
    if isinstance(value, dict):
        where = f"{label}, {_describe(value, key)}" if key else label
        result = {}
        lost_required = []
        for inner_key, item in value.items():
            if inner_key in REF_KEYS and isinstance(item, str) and item in stale:
                warnings.append(
                    f"{where}: dropped {inner_key} '{item}'; it no longer resolves."
                )
                if inner_key in required_ref_keys():
                    lost_required.append(inner_key)
                continue
            repaired = _repair(item, stale, where, warnings, inner_key)
            if repaired is _LEFT_OUT:
                continue
            if _emptied(item, repaired):
                if inner_key in required_ref_keys():
                    lost_required.append(inner_key)
                continue
            result[inner_key] = repaired
        if lost_required:
            warnings.append(
                f"{where}: left out of the file; its {', '.join(lost_required)} "
                "no longer resolves."
            )
            return _LEFT_OUT
        return result
    return value


def _emptied(original, repaired) -> bool:
    """True when a repair removed every entry of a list: the key goes with it."""
    return isinstance(original, list) and bool(original) and repaired == []


def _kept(original, repaired) -> bool:
    """True when a repaired top-level value still belongs in the export."""
    return repaired is not _LEFT_OUT and not _emptied(original, repaired)


def restore(entry: dict, row, *, stale: set, warnings: list, label: str) -> None:
    """Merge a row's kept keys and foreign properties into its exported entry."""
    cyclonedx = (getattr(row, "format_metadata", None) or {}).get("cyclonedx") or {}
    kept = cyclonedx.get("passthrough")
    if isinstance(kept, dict):
        for key, value in kept.items():
            if key in entry:
                continue
            repaired = _repair(copy.deepcopy(value), stale, label, warnings, key)
            if _kept(value, repaired):
                entry[key] = repaired
    foreign = cyclonedx.get("foreign_properties")
    if isinstance(foreign, list) and foreign:
        properties = list(entry.get("properties") or [])
        existing = {
            (p.get("name"), p.get("value")) for p in properties if isinstance(p, dict)
        }
        for item in foreign:
            if (
                isinstance(item, dict)
                and (item.get("name"), item.get("value")) not in existing
            ):
                properties.append(copy.deepcopy(item))
        entry["properties"] = properties


def restore_document_level(
    document: dict, threat_model, *, stale: set, warnings: list
) -> None:
    cyclonedx = (threat_model.format_metadata or {}).get("cyclonedx") or {}
    kept = cyclonedx.get("passthrough")
    if isinstance(kept, dict):
        for key, value in kept.get("document", {}).items():
            if key in document:
                continue
            repaired = _repair(copy.deepcopy(value), stale, "document", warnings, key)
            if _kept(value, repaired):
                document[key] = repaired
        for section in ("threats", "risks", "definitions", "metadata"):
            extra = kept.get(section)
            if not isinstance(extra, dict):
                continue
            target = document.setdefault(section, {})
            for key, value in extra.items():
                if key in target:
                    continue
                repaired = _repair(
                    copy.deepcopy(value), stale, f"{section} section", warnings, key
                )
                if _kept(value, repaired):
                    target[key] = repaired
    foreign = cyclonedx.get("foreign_properties")
    if isinstance(foreign, list) and foreign:
        properties = list(document.get("properties") or [])
        properties.extend(
            copy.deepcopy(item) for item in foreign if isinstance(item, dict)
        )
        document["properties"] = properties


def stale_refs(threat_model, document: dict) -> set:
    """Refs the imported document had that the current document no longer has."""
    cyclonedx = (threat_model.format_metadata or {}).get("cyclonedx") or {}
    known = set(cyclonedx.get("known_refs") or [])
    if not known:
        return set()
    return known - collect_refs(document)
