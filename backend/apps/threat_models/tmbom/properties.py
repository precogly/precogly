"""The ``precogly:`` property registry (plan section 9.6).

Every property Precogly writes into a TM-BOM document is declared here with the
object it sits on and the type of its value. Export and import both read this
list, a generator mirrors it into the guest editor, and the importing and
exporting guide prints it. Anything not in the registry is passthrough.

Registered by the adapter slice that first emits it, so the list grows step by
step (section 9.3).
"""

import json
from dataclasses import dataclass
from enum import StrEnum

PROPERTY_PREFIX = "precogly:"


class PropertyOwner(StrEnum):
    """The TM-BOM object a property is attached to."""

    DOCUMENT = "document"
    THREAT = "threat"
    SCENARIO = "scenario"
    CONTROL = "control"
    RISK = "risk"
    ZONE = "zone"
    FLOW = "flow"
    ASSET = "asset"
    DATA_STORE = "data-store"
    SCOPE = "scope"
    VISUALIZATION = "visualization"
    SYSTEM = "system"
    PERSONA_PARTY = "persona-party"
    ACTOR = "actor"
    REQUIREMENT = "requirement"
    EXTERNAL_REFERENCE_THREAT_MODEL = "external-reference:threat-model"
    EXTERNAL_REFERENCE_PENTEST_REPORT = "external-reference:pentest-report"
    DATA_SET = "data-set"


class PropertyValueType(StrEnum):
    """How the property's string value is encoded."""

    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    DATE = "date"
    JSON = "json"


@dataclass(frozen=True)
class PrecoglyProperty:
    """One registered property."""

    name: str
    owner: PropertyOwner
    value_type: PropertyValueType
    description: str

    def __post_init__(self) -> None:
        if not self.name.startswith(PROPERTY_PREFIX):
            raise ValueError(f"property name must start with {PROPERTY_PREFIX!r}")


# Declared in the order the adapter slices add them. Keep names in one place.
REGISTRY: tuple[PrecoglyProperty, ...] = (
    # Step 1: blueprint structure
    PrecoglyProperty(
        "precogly:out-of-scope",
        PropertyOwner.SCOPE,
        PropertyValueType.JSON,
        "An out-of-scope item whose name matches no component: {name, reason}.",
    ),
    PrecoglyProperty(
        "precogly:diagram-type",
        PropertyOwner.VISUALIZATION,
        PropertyValueType.STRING,
        "The DFD level (context, level1, level2) of a Precogly canvas visualization.",
    ),
    PrecoglyProperty(
        "precogly:primary",
        PropertyOwner.VISUALIZATION,
        PropertyValueType.BOOLEAN,
        "True on the blueprint's primary DFD, the one that syncs to rows.",
    ),
    PrecoglyProperty(
        "precogly:category",
        PropertyOwner.ASSET,
        PropertyValueType.STRING,
        "Precogly's DFD role of a component: process, datastore, external_human_actor "
        "or external_system_actor.",
    ),
    PrecoglyProperty(
        "precogly:actor-type",
        PropertyOwner.ASSET,
        PropertyValueType.STRING,
        "The actor or system type chosen on an external actor component.",
    ),
    PrecoglyProperty(
        "precogly:data-sensitivity",
        PropertyOwner.ASSET,
        PropertyValueType.STRING,
        "The data sensitivity level chosen on a process or data store.",
    ),
    PrecoglyProperty(
        "precogly:data-store-type",
        PropertyOwner.DATA_STORE,
        PropertyValueType.STRING,
        "Precogly's own data store type value when it is not a spec value.",
    ),
    # Step 3: scenarios, abstract threats, actors
    PrecoglyProperty(
        "precogly:next-threat-number",
        PropertyOwner.DOCUMENT,
        PropertyValueType.INTEGER,
        "The model's next threat number, so a reopened file never reuses one (M12).",
    ),
    PrecoglyProperty(
        "precogly:number",
        PropertyOwner.SCENARIO,
        PropertyValueType.INTEGER,
        "The scenario's threat number (T7 is 7).",
    ),
    PrecoglyProperty(
        "precogly:threat-status",
        PropertyOwner.SCENARIO,
        PropertyValueType.STRING,
        "Derived status: exposed, addressable or mitigated.",
    ),
    PrecoglyProperty(
        "precogly:triage-status",
        PropertyOwner.SCENARIO,
        PropertyValueType.STRING,
        "Triage decision: open, accept, mitigate, delegate or eliminate.",
    ),
    PrecoglyProperty(
        "precogly:decision-rationale",
        PropertyOwner.SCENARIO,
        PropertyValueType.STRING,
        "Rationale recorded with the triage decision.",
    ),
    PrecoglyProperty(
        "precogly:auto-generated",
        PropertyOwner.SCENARIO,
        PropertyValueType.BOOLEAN,
        "True while the scenario is an untouched product of library generation.",
    ),
    PrecoglyProperty(
        "precogly:impact-description",
        PropertyOwner.SCENARIO,
        PropertyValueType.STRING,
        "What the attacker achieves, when the scenario has no impact level to "
        "carry it as impact.description.",
    ),
    PrecoglyProperty(
        "precogly:instance-categories",
        PropertyOwner.SCENARIO,
        PropertyValueType.JSON,
        "Taxonomy entries added on the scenario itself: "
        "[{taxonomy_slug, external_id, title}].",
    ),
    PrecoglyProperty(
        "precogly:threat-sources",
        PropertyOwner.SCENARIO,
        PropertyValueType.JSON,
        "Slugs of the NIST SP 800-30 threat sources the scenario cites.",
    ),
    PrecoglyProperty(
        "precogly:split-from",
        PropertyOwner.SCENARIO,
        PropertyValueType.STRING,
        "The ref of the imported scenario this one was split from (H10).",
    ),
    PrecoglyProperty(
        "precogly:taxonomy",
        PropertyOwner.THREAT,
        PropertyValueType.JSON,
        "A taxonomy entry outside the four spec taxonomies: "
        "{taxonomy_slug, external_id, title}.",
    ),
    PrecoglyProperty(
        "precogly:actor-text",
        PropertyOwner.ACTOR,
        PropertyValueType.STRING,
        "The free-text actor of a scenario, declared once as an actor entry.",
    ),
    PrecoglyProperty(
        "precogly:persona-name",
        PropertyOwner.PERSONA_PARTY,
        PropertyValueType.STRING,
        "The persona's display name (the spec party has none).",
    ),
    PrecoglyProperty(
        "precogly:persona-symbolic-name",
        PropertyOwner.PERSONA_PARTY,
        PropertyValueType.STRING,
        "The persona's symbolic name; the match key on import.",
    ),
    PrecoglyProperty(
        "precogly:persona-is-person",
        PropertyOwner.PERSONA_PARTY,
        PropertyValueType.BOOLEAN,
        "Whether the persona is a person rather than a system or group.",
    ),
    PrecoglyProperty(
        "precogly:persona-malicious-intent",
        PropertyOwner.PERSONA_PARTY,
        PropertyValueType.BOOLEAN,
        "Whether the persona acts with malicious intent.",
    ),
    PrecoglyProperty(
        "precogly:persona-skill-level",
        PropertyOwner.PERSONA_PARTY,
        PropertyValueType.STRING,
        "The persona's skill level.",
    ),
    PrecoglyProperty(
        "precogly:persona-motivation",
        PropertyOwner.PERSONA_PARTY,
        PropertyValueType.STRING,
        "The persona's motivation, as text.",
    ),
    PrecoglyProperty(
        "precogly:persona-resources",
        PropertyOwner.PERSONA_PARTY,
        PropertyValueType.STRING,
        "The persona's resources, as text.",
    ),
    PrecoglyProperty(
        "precogly:persona-objectives",
        PropertyOwner.PERSONA_PARTY,
        PropertyValueType.STRING,
        "The persona's objectives, as text.",
    ),
    # Step 4: controls, scope, provider, compliance
    PrecoglyProperty(
        "precogly:next-countermeasure-number",
        PropertyOwner.DOCUMENT,
        PropertyValueType.INTEGER,
        "The model's next countermeasure number (M12).",
    ),
    PrecoglyProperty(
        "precogly:number",
        PropertyOwner.CONTROL,
        PropertyValueType.INTEGER,
        "The control's number (C3 is 3).",
    ),
    PrecoglyProperty(
        "precogly:control-functions",
        PropertyOwner.CONTROL,
        PropertyValueType.JSON,
        "Every control function; the spec's single category holds the first spec value.",
    ),
    PrecoglyProperty(
        "precogly:control-nature",
        PropertyOwner.CONTROL,
        PropertyValueType.STRING,
        "technical, administrative or physical.",
    ),
    PrecoglyProperty(
        "precogly:priority",
        PropertyOwner.CONTROL,
        PropertyValueType.STRING,
        "The control's priority.",
    ),
    PrecoglyProperty(
        "precogly:due-date",
        PropertyOwner.CONTROL,
        PropertyValueType.DATE,
        "Target completion date (a POA&M scheduled completion date).",
    ),
    PrecoglyProperty(
        "precogly:required-for-release",
        PropertyOwner.CONTROL,
        PropertyValueType.BOOLEAN,
        "True when the control blocks a release.",
    ),
    PrecoglyProperty(
        "precogly:auto-generated",
        PropertyOwner.CONTROL,
        PropertyValueType.BOOLEAN,
        "True while the control is an untouched product of library generation.",
    ),
    PrecoglyProperty(
        "precogly:source",
        PropertyOwner.CONTROL,
        PropertyValueType.STRING,
        "Where the control came from, as text (from PR #559).",
    ),
    PrecoglyProperty(
        "precogly:verified-by",
        PropertyOwner.CONTROL,
        PropertyValueType.STRING,
        "Email of the user who verified the control.",
    ),
    PrecoglyProperty(
        "precogly:library",
        PropertyOwner.CONTROL,
        PropertyValueType.STRING,
        "Qualified slug of the library countermeasure the control was made from.",
    ),
    PrecoglyProperty(
        "precogly:mitigates",
        PropertyOwner.CONTROL,
        PropertyValueType.JSON,
        "Refs of the scenarios the control is explicitly linked to (G2).",
    ),
    PrecoglyProperty(
        "precogly:sufficiency",
        PropertyOwner.CONTROL,
        PropertyValueType.JSON,
        "[{requirement, sufficiency}] for each requirement in satisfies.",
    ),
    # Step 6: zones and boundaries
    PrecoglyProperty(
        "precogly:trust-level",
        PropertyOwner.ZONE,
        PropertyValueType.INTEGER,
        "The zone's trust level, 0 to 100; absent when not set.",
    ),
    # Step 7: flows
    PrecoglyProperty(
        "precogly:port",
        PropertyOwner.FLOW,
        PropertyValueType.INTEGER,
        "The flow's port.",
    ),
    PrecoglyProperty(
        "precogly:has-sensitive-data",
        PropertyOwner.FLOW,
        PropertyValueType.BOOLEAN,
        "True when the flow carries sensitive data.",
    ),
    PrecoglyProperty(
        "precogly:data-classification",
        PropertyOwner.FLOW,
        PropertyValueType.JSON,
        "The flow's data classification tags.",
    ),
    # Step 10: business objectives
    PrecoglyProperty(
        "precogly:business-objectives",
        PropertyOwner.SCENARIO,
        PropertyValueType.JSON,
        "Refs of the business objectives this scenario puts at risk; the abstract "
        "threat carries the union.",
    ),
    # Step 13: identity, systems, relationships
    PrecoglyProperty(
        "precogly:criticality",
        PropertyOwner.SYSTEM,
        PropertyValueType.STRING,
        "The model's criticality as a spec criticality value (low, moderate, high, critical).",
    ),
    PrecoglyProperty(
        "precogly:lifecycle-state",
        PropertyOwner.SYSTEM,
        PropertyValueType.STRING,
        "The inventory system's lifecycle state (F2).",
    ),
    PrecoglyProperty(
        "precogly:lifecycle-state",
        PropertyOwner.ASSET,
        PropertyValueType.STRING,
        "The lifecycle state of the inventory system a system asset stands for (F2).",
    ),
    PrecoglyProperty(
        "precogly:relationship",
        PropertyOwner.ASSET,
        PropertyValueType.STRING,
        "On a system asset that stands for another threat model: depends_on, "
        "subsystem_of, related_to or superseded_by (G6).",
    ),
    # Step 8: risks
    PrecoglyProperty(
        "precogly:statement-generated",
        PropertyOwner.RISK,
        PropertyValueType.BOOLEAN,
        "True when the statement was synthesized from the description or name "
        "because the risk had none (the spec requires one).",
    ),
    # Step 14: the fields the coverage check found without a home (H17)
    PrecoglyProperty(
        "precogly:risk-scoring-method",
        PropertyOwner.DOCUMENT,
        PropertyValueType.STRING,
        "The model's scoring method: qualitative-matrix, owasp-risk-rating, fair "
        "or mozilla-rra. Each rating also names its own methodology.",
    ),
    PrecoglyProperty(
        "precogly:library",
        PropertyOwner.ASSET,
        PropertyValueType.STRING,
        "Qualified slug of the component library row the component was made from. "
        "Also read on data stores.",
    ),
    PrecoglyProperty(
        "precogly:component-type",
        PropertyOwner.ASSET,
        PropertyValueType.STRING,
        "The component type copied from the library (M16). Also read on data stores.",
    ),
    PrecoglyProperty(
        "precogly:provider",
        PropertyOwner.ASSET,
        PropertyValueType.STRING,
        "The provider copied from the library (M16); a data store writes it as "
        "vendor instead.",
    ),
    PrecoglyProperty(
        "precogly:parent",
        PropertyOwner.ASSET,
        PropertyValueType.STRING,
        "Ref of the component this one sits inside (a system asset or a process). "
        "Also read on data stores.",
    ),
    PrecoglyProperty(
        "precogly:confidentiality",
        PropertyOwner.DATA_SET,
        PropertyValueType.STRING,
        "The data set's confidentiality need: low, medium or high.",
    ),
    PrecoglyProperty(
        "precogly:integrity",
        PropertyOwner.DATA_SET,
        PropertyValueType.STRING,
        "The data set's integrity need: low, medium or high.",
    ),
    PrecoglyProperty(
        "precogly:availability",
        PropertyOwner.DATA_SET,
        PropertyValueType.STRING,
        "The data set's availability need: low, medium or high.",
    ),
    PrecoglyProperty(
        "precogly:data-sensitivity-tags",
        PropertyOwner.DATA_SET,
        PropertyValueType.JSON,
        "The data set's sensitivity tags (pii, phi, pci and so on).",
    ),
    PrecoglyProperty(
        "precogly:placements",
        PropertyOwner.DATA_SET,
        PropertyValueType.JSON,
        "Per placement, what the spec placement cannot hold: "
        "[{dataStore, dataState, volume}].",
    ),
    PrecoglyProperty(
        "precogly:flow-data",
        PropertyOwner.FLOW,
        PropertyValueType.JSON,
        "Per data set the flow carries, how it is protected: "
        "[{dataSet, protectionMethod, encryptionType, format, sensitivityOverride}].",
    ),
    PrecoglyProperty(
        "precogly:assigned-to",
        PropertyOwner.RISK,
        PropertyValueType.STRING,
        "Party ref of the person the risk is assigned to; the owner is the spec field.",
    ),
)

_BY_NAME = {(entry.name, entry.owner): entry for entry in REGISTRY}


def registered_names(owner: PropertyOwner | None = None) -> set[str]:
    """Names in the registry, optionally for one owner."""
    return {entry.name for entry in REGISTRY if owner is None or entry.owner == owner}


def is_registered(name: str, owner: PropertyOwner) -> bool:
    return (name, owner) in _BY_NAME


def encode_value(value, value_type: PropertyValueType) -> str:
    """The string form a property carries in the document."""
    if value_type == PropertyValueType.JSON:
        return json.dumps(value, separators=(",", ":"), sort_keys=True)
    if value_type == PropertyValueType.BOOLEAN:
        return "true" if value else "false"
    return str(value)


def decode_value(raw: str, value_type: PropertyValueType):
    """The Python value of a property string, by its registered type."""
    if value_type == PropertyValueType.JSON:
        return json.loads(raw)
    if value_type == PropertyValueType.BOOLEAN:
        return str(raw).strip().lower() in {"true", "1", "yes"}
    if value_type == PropertyValueType.INTEGER:
        return int(raw)
    return raw


def make_property(name: str, owner: PropertyOwner, value) -> dict:
    """A `{name, value}` property for a registered name, value encoded by type."""
    entry = _BY_NAME.get((name, owner))
    if entry is None:
        raise KeyError(f"{name!r} is not registered for {owner}")
    return {"name": name, "value": encode_value(value, entry.value_type)}


def read_properties(properties, owner: PropertyOwner) -> dict:
    """Registered properties of an object, decoded, keyed by name.

    Unknown names are left out; a name registered with another owner is
    treated as unknown. A value that does not decode is skipped. Duplicate
    names keep every value in a list under the name when the registered type
    is JSON, else the last one wins.
    """
    decoded: dict = {}
    for item in properties or []:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        entry = _BY_NAME.get((name, owner))
        if entry is None:
            continue
        try:
            value = decode_value(item.get("value", ""), entry.value_type)
        except (ValueError, TypeError):
            continue
        if entry.value_type == PropertyValueType.JSON:
            decoded.setdefault(name, []).append(value)
        else:
            decoded[name] = value
    return decoded
