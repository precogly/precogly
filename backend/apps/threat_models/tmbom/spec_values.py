"""Every enum the adapter writes, and the maps between our values and the spec's.

One source for both directions (G9). A backend test compares each list with
the pinned schema, so a re-pin shows exactly what changed. The guest editor's
copy is generated from this module.
"""

from apps.systems.crossing import (
    ASSET_TYPES,
    BOUNDARY_TYPES,
    FLOW_TYPES,
    ZONE_TYPES,
)

__all__ = ["ASSET_TYPES", "BOUNDARY_TYPES", "FLOW_TYPES", "ZONE_TYPES"]

DATA_STORE_TYPES = (
    "block",
    "blockchain",
    "cache",
    "column-family",
    "data-lake",
    "data-warehouse",
    "document",
    "event-log",
    "file",
    "graph",
    "hierarchical",
    "in-memory",
    "key-value",
    "ledger",
    "message-queue",
    "multi-model",
    "object",
    "registry",
    "relational",
    "search",
    "spatial",
    "time-series",
    "vector",
)

MODEL_TYPES = (
    "architecture",
    "behavioral",
    "conceptual",
    "data-flow",
    "deployment",
    "logical",
    "network",
    "operational",
    "physical",
    "process",
)

VISUALIZATION_TYPES = (
    "activity",
    "architecture",
    "attack-tree",
    "block",
    "class",
    "code",
    "communication",
    "component",
    "container",
    "context",
    "data-flow",
    "deployment",
    "entity",
    "flowchart",
    "matrix",
    "mind-map",
    "network",
    "process",
    "sequence",
    "state",
    "timing",
    "use-case",
)

DATA_CLASSIFICATIONS = (
    "confidential",
    "internal",
    "public",
    "restricted",
    "classified",
)

METADATA_COMPONENT_TYPES = (
    "application",
    "framework",
    "library",
    "container",
    "platform",
    "operating-system",
    "device",
    "device-driver",
    "firmware",
    "file",
    "machine-learning-model",
    "data",
    "cryptographic-asset",
    "material",
    "service",
)

THREAT_TAXONOMIES = ("STRIDE", "LINDDUN", "MAESTRO", "MITRE-ATTACK")

THREAT_CATEGORIES = {
    "STRIDE": (
        "spoofing",
        "tampering",
        "repudiation",
        "information-disclosure",
        "denial-of-service",
        "elevation-of-privilege",
    ),
    "LINDDUN": (
        "linkability",
        "identifiability",
        "non-repudiation",
        "detectability",
        "disclosure-of-information",
        "unawareness",
        "non-compliance",
    ),
    "MAESTRO": (
        "foundation-models",
        "data-operations",
        "agent-frameworks",
        "deployment-and-infrastructure",
        "evaluation-and-observability",
        "security-and-compliance",
        "agent-ecosystem",
    ),
    "MITRE-ATTACK": (
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    ),
}

THREAT_ORIGINS = ("adversarial", "accidental", "structural", "environmental")

SCENARIO_INTENTS = ("accidental", "opportunistic", "targeted", "persistent")

SCENARIO_ACCESS_LEVELS = ("none", "external", "internal", "privileged", "physical")

PERSONA_ARCHETYPES = (
    "end-user",
    "power-user",
    "administrator",
    "developer",
    "operator",
    "internal",
    "external",
    "anonymous",
    "guest",
    "customer",
    "partner",
    "supplier",
    "vendor",
    "contractor",
    "third-party",
    "auditor",
    "researcher",
    "regulator",
    "law-enforcement",
    "attacker",
    "insider-threat",
    "hacktivist",
    "nation-state",
    "organized-crime",
    "competitor",
    "public",
)

# Archetypes that mark a party as a threat actor on import (M10).
ATTACKER_ARCHETYPES = (
    "attacker",
    "insider-threat",
    "hacktivist",
    "nation-state",
    "organized-crime",
    "competitor",
)

# Our taxonomy slugs -> the spec's taxonomy names. Anything else is carried
# as `precogly:taxonomy`.
TAXONOMY_SLUG_TO_SPEC = {
    "stride": "STRIDE",
    "linddun": "LINDDUN",
    "maestro": "MAESTRO",
    "mitre-attack": "MITRE-ATTACK",
    "mitre_attack": "MITRE-ATTACK",
    "mitre-att&ck": "MITRE-ATTACK",
    "attack": "MITRE-ATTACK",
}

CONTROL_CATEGORIES = (
    "preventive",
    "detective",
    "corrective",
    "compensating",
    "deterrent",
    "recovery",
)

IMPLEMENTATION_STATUSES = (
    "recommended",
    "proposed",
    "approved",
    "rejected",
    "planned",
    "in-progress",
    "implemented",
    "verified",
    "decommissioned",
)

# Our countermeasure status -> spec status. The three without a spec value
# (gap, waived, platform) export as custom status objects.
COUNTERMEASURE_STATUS_TO_SPEC = {
    "planned": "planned",
    "in_progress": "in-progress",
    "implemented": "implemented",
    "verified": "verified",
    "decommissioned": "decommissioned",
}
SPEC_STATUS_TO_COUNTERMEASURE = {
    **{spec: ours for ours, spec in COUNTERMEASURE_STATUS_TO_SPEC.items()},
    # Decision-process statuses other tools write; the original is kept.
    "recommended": "planned",
    "proposed": "planned",
    "approved": "planned",
    "rejected": "waived",
}
CUSTOM_COUNTERMEASURE_STATUSES = ("gap", "waived", "platform")

EXTERNAL_REFERENCE_TYPES = (
    "issue-tracker",
    "evidence",
    "pentest-report",
)

TRUST_LEVELS = ("untrusted", "semi-trusted", "trusted", "highly-trusted")


def trust_level_name(level: int) -> str:
    """The spec's trust level for a 0 to 100 value, by fixed ranges (section 9.4)."""
    if level <= 25:
        return "untrusted"
    if level <= 50:
        return "semi-trusted"
    if level <= 75:
        return "trusted"
    return "highly-trusted"


# The media type that marks a visualization attachment as a Precogly canvas
# (G5, D14). Import recognises our canvases by it.
PRECOGLY_DFD_MEDIA_TYPE = "application/vnd.precogly.dfd+json"

# Spec asset type -> Precogly component category, for documents from other
# tools. Our own documents carry `precogly:category`, which wins.
ASSET_TYPE_TO_CATEGORY = {
    "actor": "external_human_actor",
    "agent": "external_system_actor",
    "system": "external_system_actor",
    "subsystem": "external_system_actor",
    "data-store": "datastore",
    "cache": "datastore",
    "queue": "datastore",
    "stream": "datastore",
}
DEFAULT_CATEGORY = "process"

# Precogly data store type (free text today) -> spec data store type.
DATA_STORE_TYPE_TO_SPEC = {
    "relational": "relational",
    "sql": "relational",
    "document": "document",
    "nosql": "document",
    "key_value": "key-value",
    "key-value": "key-value",
    "graph": "graph",
    "file": "file",
    "object": "object",
    "blob": "object",
    "cache": "cache",
    "queue": "message-queue",
    "message_queue": "message-queue",
    "search": "search",
    "time_series": "time-series",
    "vector": "vector",
    "data_lake": "data-lake",
    "data_warehouse": "data-warehouse",
}
SPEC_TO_DATA_STORE_TYPE = {
    spec: ours for ours, spec in reversed(list(DATA_STORE_TYPE_TO_SPEC.items()))
}

# DFD diagram type -> spec visualization type.
DIAGRAM_TYPE_TO_VISUALIZATION_TYPE = {
    "context": "context",
    "level1": "data-flow",
    "level2": "data-flow",
}


def custom_type(name: str, description: str = "") -> dict:
    """The spec's custom-type object, for a value outside an enum."""
    value = {"name": name}
    if description:
        value["description"] = description
    return value


def type_name(value) -> str:
    """The name of a spec type value: the string itself or the custom object's name."""
    if isinstance(value, dict):
        return str(value.get("name", ""))
    return str(value or "")


# Keys whose values are refs to elements of the same document (H18, R18):
# every property the pinned schema types as a ref or a list of refs, except
# the few that also hold plain strings (a URL, a name) elsewhere, where
# "source" and "owner" stay because ours are always refs.
# `tests/test_tmbom_validation.py` derives the set from the schema and fails
# when this list differs, so a re-pin shows what to add. The guest editor gets
# it through `frontend/scripts/generate-cyclonedx-spec.mjs`.
REF_KEYS = (
    "abuseCases",
    "abuser",
    "access",
    "actor",
    "actors",
    "addresses",
    "affectedAssets",
    "affects",
    "affiliation",
    "aggregates",
    "algorithmRef",
    "algorithms",
    "appliesTo",
    "approver",
    "assemblies",
    "asserter",
    "assessor",
    "assessors",
    "assets",
    "associates",
    "attackPattern",
    "attackPatterns",
    "attackTrees",
    "attributedTo",
    "authors",
    "behaviors",
    "boundary",
    "boundaryCrossed",
    "businessObjectives",
    "children",
    "claims",
    "collection",
    "componentRef",
    "composes",
    "configurationRef",
    "contains",
    "controls",
    "controlsAtBoundary",
    "counterClaims",
    "counterEvidence",
    "dataProfiles",
    "dataSets",
    "dataStore",
    "delegatedBy",
    "dependsOn",
    "destination",
    "disposal",
    "doActivity",
    "effect",
    "elements",
    "evidence",
    "excludedComponents",
    "exploits",
    "flows",
    "generalizes",
    "governance",
    "graph",
    "implementedBy",
    "includedComponents",
    "issuer",
    "members",
    "mitigatingControls",
    "mitigationStrategies",
    "mitigations",
    "onEntry",
    "onExit",
    "owner",
    "owners",
    "ownership",
    "parent",
    "parties",
    "party",
    "partyRef",
    "patentRefs",
    "performedBy",
    "process",
    "processing",
    "profile",
    "provides",
    "realizes",
    "ref",
    "relatedAssets",
    "relatedBusinessObjectives",
    "relatedClaims",
    "relatedRequirements",
    "relatedRisks",
    "relatedStandards",
    "relatedThreats",
    "relatedVulnerabilities",
    "relatedWeaknesses",
    "requirement",
    "requirementRefs",
    "requirements",
    "reviewer",
    "riskAppetites",
    "risks",
    "root",
    "ruleset",
    "satisfies",
    "serves",
    "sharing",
    "source",
    "sourceAttributes",
    "subject",
    "subjects",
    "target",
    "targetAttributes",
    "targets",
    "threatProfile",
    "threats",
    "threatsAtBoundary",
    "tools",
    "useCaseRefs",
    "weakness",
    "zone",
    "zones",
)
