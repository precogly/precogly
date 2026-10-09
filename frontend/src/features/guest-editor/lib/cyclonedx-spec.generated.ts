/**
 * GENERATED FILE. Do not edit by hand: run `node scripts/generate-cyclonedx-spec.mjs`
 * from `frontend/`.
 *
 * Mirrors the backend's one source for CycloneDX TM-BOM spec values and
 * `precogly:` property names (plan section 9.6):
 *   backend/apps/threat_models/tmbom/properties.py
 *   backend/apps/threat_models/tmbom/spec_values.py
 *   backend/apps/systems/crossing.py
 *
 * `__tests__/cyclonedx-spec.test.ts` regenerates this file in memory and
 * fails when the committed copy differs.
 */

export interface PrecoglyPropertyEntry {
  name: string
  owner: string
  valueType: string
  description: string
}

export const PROPERTY_PREFIX = "precogly:"

export const PROPERTY_OWNER = {
  "DOCUMENT": "document",
  "THREAT": "threat",
  "SCENARIO": "scenario",
  "CONTROL": "control",
  "RISK": "risk",
  "ZONE": "zone",
  "FLOW": "flow",
  "ASSET": "asset",
  "DATA_STORE": "data-store",
  "SCOPE": "scope",
  "VISUALIZATION": "visualization",
  "SYSTEM": "system",
  "PERSONA_PARTY": "persona-party",
  "ACTOR": "actor",
  "REQUIREMENT": "requirement",
  "EXTERNAL_REFERENCE_THREAT_MODEL": "external-reference:threat-model",
  "EXTERNAL_REFERENCE_PENTEST_REPORT": "external-reference:pentest-report",
  "DATA_SET": "data-set",
} as const

export const PROPERTY_VALUE_TYPE = {
  "STRING": "string",
  "INTEGER": "integer",
  "BOOLEAN": "boolean",
  "DATE": "date",
  "JSON": "json",
} as const

/** The `precogly:` property registry, in the order the backend declares it. */
export const PRECOGLY_PROPERTIES: readonly PrecoglyPropertyEntry[] = [
  {
    "name": "precogly:out-of-scope",
    "owner": "scope",
    "valueType": "json",
    "description": "An out-of-scope item whose name matches no component: {name, reason}.",
  },
  {
    "name": "precogly:diagram-type",
    "owner": "visualization",
    "valueType": "string",
    "description": "The DFD level (context, level1, level2) of a Precogly canvas visualization.",
  },
  {
    "name": "precogly:primary",
    "owner": "visualization",
    "valueType": "boolean",
    "description": "True on the blueprint's primary DFD, the one that syncs to rows.",
  },
  {
    "name": "precogly:category",
    "owner": "asset",
    "valueType": "string",
    "description": "Precogly's DFD role of a component: process, datastore, external_human_actor or external_system_actor.",
  },
  {
    "name": "precogly:actor-type",
    "owner": "asset",
    "valueType": "string",
    "description": "The actor or system type chosen on an external actor component.",
  },
  {
    "name": "precogly:data-sensitivity",
    "owner": "asset",
    "valueType": "string",
    "description": "The data sensitivity level chosen on a process or data store.",
  },
  {
    "name": "precogly:data-store-type",
    "owner": "data-store",
    "valueType": "string",
    "description": "Precogly's own data store type value when it is not a spec value.",
  },
  {
    "name": "precogly:next-threat-number",
    "owner": "document",
    "valueType": "integer",
    "description": "The model's next threat number, so a reopened file never reuses one (M12).",
  },
  {
    "name": "precogly:number",
    "owner": "scenario",
    "valueType": "integer",
    "description": "The scenario's threat number (T7 is 7).",
  },
  {
    "name": "precogly:threat-status",
    "owner": "scenario",
    "valueType": "string",
    "description": "Derived status: exposed, addressable or mitigated.",
  },
  {
    "name": "precogly:triage-status",
    "owner": "scenario",
    "valueType": "string",
    "description": "Triage decision: open, accept, mitigate, delegate or eliminate.",
  },
  {
    "name": "precogly:decision-rationale",
    "owner": "scenario",
    "valueType": "string",
    "description": "Rationale recorded with the triage decision.",
  },
  {
    "name": "precogly:auto-generated",
    "owner": "scenario",
    "valueType": "boolean",
    "description": "True while the scenario is an untouched product of library generation.",
  },
  {
    "name": "precogly:impact-description",
    "owner": "scenario",
    "valueType": "string",
    "description": "What the attacker achieves, when the scenario has no impact level to carry it as impact.description.",
  },
  {
    "name": "precogly:instance-categories",
    "owner": "scenario",
    "valueType": "json",
    "description": "Taxonomy entries added on the scenario itself: [{taxonomy_slug, external_id, title}].",
  },
  {
    "name": "precogly:threat-sources",
    "owner": "scenario",
    "valueType": "json",
    "description": "Slugs of the NIST SP 800-30 threat sources the scenario cites.",
  },
  {
    "name": "precogly:split-from",
    "owner": "scenario",
    "valueType": "string",
    "description": "The ref of the imported scenario this one was split from (H10).",
  },
  {
    "name": "precogly:taxonomy",
    "owner": "threat",
    "valueType": "json",
    "description": "A taxonomy entry outside the four spec taxonomies: {taxonomy_slug, external_id, title}.",
  },
  {
    "name": "precogly:actor-text",
    "owner": "actor",
    "valueType": "string",
    "description": "The free-text actor of a scenario, declared once as an actor entry.",
  },
  {
    "name": "precogly:persona-name",
    "owner": "persona-party",
    "valueType": "string",
    "description": "The persona's display name (the spec party has none).",
  },
  {
    "name": "precogly:persona-symbolic-name",
    "owner": "persona-party",
    "valueType": "string",
    "description": "The persona's symbolic name; the match key on import.",
  },
  {
    "name": "precogly:persona-is-person",
    "owner": "persona-party",
    "valueType": "boolean",
    "description": "Whether the persona is a person rather than a system or group.",
  },
  {
    "name": "precogly:persona-malicious-intent",
    "owner": "persona-party",
    "valueType": "boolean",
    "description": "Whether the persona acts with malicious intent.",
  },
  {
    "name": "precogly:persona-skill-level",
    "owner": "persona-party",
    "valueType": "string",
    "description": "The persona's skill level.",
  },
  {
    "name": "precogly:persona-motivation",
    "owner": "persona-party",
    "valueType": "string",
    "description": "The persona's motivation, as text.",
  },
  {
    "name": "precogly:persona-resources",
    "owner": "persona-party",
    "valueType": "string",
    "description": "The persona's resources, as text.",
  },
  {
    "name": "precogly:persona-objectives",
    "owner": "persona-party",
    "valueType": "string",
    "description": "The persona's objectives, as text.",
  },
  {
    "name": "precogly:next-countermeasure-number",
    "owner": "document",
    "valueType": "integer",
    "description": "The model's next countermeasure number (M12).",
  },
  {
    "name": "precogly:number",
    "owner": "control",
    "valueType": "integer",
    "description": "The control's number (C3 is 3).",
  },
  {
    "name": "precogly:control-functions",
    "owner": "control",
    "valueType": "json",
    "description": "Every control function; the spec's single category holds the first spec value.",
  },
  {
    "name": "precogly:control-nature",
    "owner": "control",
    "valueType": "string",
    "description": "technical, administrative or physical.",
  },
  {
    "name": "precogly:priority",
    "owner": "control",
    "valueType": "string",
    "description": "The control's priority.",
  },
  {
    "name": "precogly:due-date",
    "owner": "control",
    "valueType": "date",
    "description": "Target completion date (a POA&M scheduled completion date).",
  },
  {
    "name": "precogly:required-for-release",
    "owner": "control",
    "valueType": "boolean",
    "description": "True when the control blocks a release.",
  },
  {
    "name": "precogly:auto-generated",
    "owner": "control",
    "valueType": "boolean",
    "description": "True while the control is an untouched product of library generation.",
  },
  {
    "name": "precogly:source",
    "owner": "control",
    "valueType": "string",
    "description": "Where the control came from, as text (from PR #559).",
  },
  {
    "name": "precogly:verified-by",
    "owner": "control",
    "valueType": "string",
    "description": "Email of the user who verified the control.",
  },
  {
    "name": "precogly:library",
    "owner": "control",
    "valueType": "string",
    "description": "Qualified slug of the library countermeasure the control was made from.",
  },
  {
    "name": "precogly:mitigates",
    "owner": "control",
    "valueType": "json",
    "description": "Refs of the scenarios the control is explicitly linked to (G2).",
  },
  {
    "name": "precogly:sufficiency",
    "owner": "control",
    "valueType": "json",
    "description": "[{requirement, sufficiency}] for each requirement in satisfies.",
  },
  {
    "name": "precogly:trust-level",
    "owner": "zone",
    "valueType": "integer",
    "description": "The zone's trust level, 0 to 100; absent when not set.",
  },
  {
    "name": "precogly:port",
    "owner": "flow",
    "valueType": "integer",
    "description": "The flow's port.",
  },
  {
    "name": "precogly:has-sensitive-data",
    "owner": "flow",
    "valueType": "boolean",
    "description": "True when the flow carries sensitive data.",
  },
  {
    "name": "precogly:data-classification",
    "owner": "flow",
    "valueType": "json",
    "description": "The flow's data classification tags.",
  },
  {
    "name": "precogly:business-objectives",
    "owner": "scenario",
    "valueType": "json",
    "description": "Refs of the business objectives this scenario puts at risk; the abstract threat carries the union.",
  },
  {
    "name": "precogly:criticality",
    "owner": "system",
    "valueType": "string",
    "description": "The model's criticality as a spec criticality value (low, moderate, high, critical).",
  },
  {
    "name": "precogly:lifecycle-state",
    "owner": "system",
    "valueType": "string",
    "description": "The inventory system's lifecycle state (F2).",
  },
  {
    "name": "precogly:lifecycle-state",
    "owner": "asset",
    "valueType": "string",
    "description": "The lifecycle state of the inventory system a system asset stands for (F2).",
  },
  {
    "name": "precogly:relationship",
    "owner": "asset",
    "valueType": "string",
    "description": "On a system asset that stands for another threat model: depends_on, subsystem_of, related_to or superseded_by (G6).",
  },
  {
    "name": "precogly:statement-generated",
    "owner": "risk",
    "valueType": "boolean",
    "description": "True when the statement was synthesized from the description or name because the risk had none (the spec requires one).",
  },
  {
    "name": "precogly:risk-scoring-method",
    "owner": "document",
    "valueType": "string",
    "description": "The model's scoring method: qualitative-matrix, owasp-risk-rating, fair or mozilla-rra. Each rating also names its own methodology.",
  },
  {
    "name": "precogly:library",
    "owner": "asset",
    "valueType": "string",
    "description": "Qualified slug of the component library row the component was made from. Also read on data stores.",
  },
  {
    "name": "precogly:component-type",
    "owner": "asset",
    "valueType": "string",
    "description": "The component type copied from the library (M16). Also read on data stores.",
  },
  {
    "name": "precogly:provider",
    "owner": "asset",
    "valueType": "string",
    "description": "The provider copied from the library (M16); a data store writes it as vendor instead.",
  },
  {
    "name": "precogly:parent",
    "owner": "asset",
    "valueType": "string",
    "description": "Ref of the component this one sits inside (a system asset or a process). Also read on data stores.",
  },
  {
    "name": "precogly:confidentiality",
    "owner": "data-set",
    "valueType": "string",
    "description": "The data set's confidentiality need: low, medium or high.",
  },
  {
    "name": "precogly:integrity",
    "owner": "data-set",
    "valueType": "string",
    "description": "The data set's integrity need: low, medium or high.",
  },
  {
    "name": "precogly:availability",
    "owner": "data-set",
    "valueType": "string",
    "description": "The data set's availability need: low, medium or high.",
  },
  {
    "name": "precogly:data-sensitivity-tags",
    "owner": "data-set",
    "valueType": "json",
    "description": "The data set's sensitivity tags (pii, phi, pci and so on).",
  },
  {
    "name": "precogly:placements",
    "owner": "data-set",
    "valueType": "json",
    "description": "Per placement, what the spec placement cannot hold: [{dataStore, dataState, volume}].",
  },
  {
    "name": "precogly:flow-data",
    "owner": "flow",
    "valueType": "json",
    "description": "Per data set the flow carries, how it is protected: [{dataSet, protectionMethod, encryptionType, format, sensitivityOverride}].",
  },
  {
    "name": "precogly:assigned-to",
    "owner": "risk",
    "valueType": "string",
    "description": "Party ref of the person the risk is assigned to; the owner is the spec field.",
  },
]

export const ZONE_TYPES = [
  "availability",
  "compliance",
  "data",
  "deployment",
  "functional",
  "geographic",
  "logical",
  "network",
  "organizational",
  "physical",
  "process",
  "tenant",
  "trust",
] as const

export const BOUNDARY_TYPES = [
  "data",
  "functional",
  "network",
  "organizational",
  "physical",
  "process",
  "trust",
] as const

export const FLOW_TYPES = [
  "control",
  "data",
  "energy",
  "event",
  "financial",
  "message",
  "physical",
  "process",
  "signal",
] as const

export const DATA_LIKE_FLOW_TYPES = [
  "data",
  "message",
  "event",
] as const

export const ANY_FLOW_TYPE = "any"

export const ASSET_TYPES = [
  "actor",
  "agent",
  "api",
  "broker",
  "cache",
  "component",
  "container",
  "data",
  "data-store",
  "device",
  "endpoint",
  "function",
  "gateway",
  "infrastructure",
  "interface",
  "model",
  "module",
  "network",
  "process",
  "queue",
  "resource",
  "service",
  "stream",
  "subsystem",
  "system",
  "tool",
] as const

export const CATEGORY_TO_KIND: Record<string, string> = {
  "process": "process",
  "datastore": "data-store",
  "external_human_actor": "actor",
  "external_system_actor": "actor",
}

export const UNSPECIFIED = "unspecified"

export const AUTHENTICATION_TYPES = [
  "api-key",
  "basic",
  "bearer",
  "biometric",
  "certificate",
  "digest",
  "eap",
  "fido2",
  "form",
  "hmac",
  "jwt",
  "kerberos",
  "ldap",
  "magic-link",
  "mtls",
  "none",
  "ntlm",
  "oauth1",
  "oauth2",
  "oidc",
  "pin",
  "psk",
  "push",
  "radius",
  "saml",
  "scram",
  "session-cookie",
  "ssh",
  "totp",
] as const

export const AUTHORIZATION_TYPES = [
  "abac",
  "acl",
  "capability",
  "dac",
  "mac",
  "none",
  "pbac",
  "radac",
  "rbac",
  "rebac",
] as const

export const NONE = "none"

export const SESSION_MANAGEMENT_KEYS: Record<string, string> = {
  "accessTokenExpires": "bool",
  "accessTokenTtl": "int",
  "refreshToken": "bool",
  "refreshTokenExpires": "bool",
  "refreshTokenTtl": "int",
  "idleTimeout": "int",
  "absoluteTimeout": "int",
  "userLogout": "bool",
  "systemLogout": "bool",
}

export const SESSION_EDITOR_KEYS = [
  "accessTokenExpires",
  "accessTokenTtl",
  "refreshToken",
  "refreshTokenExpires",
  "refreshTokenTtl",
  "userLogout",
  "systemLogout",
] as const

export const CANVAS_SESSION_KEYS: Record<string, string> = {
  "access_token_expires": "accessTokenExpires",
  "access_token_ttl": "accessTokenTtl",
  "has_refresh_token": "refreshToken",
  "refresh_token_expires": "refreshTokenExpires",
  "refresh_token_ttl": "refreshTokenTtl",
  "can_user_logout": "userLogout",
  "can_system_logout": "systemLogout",
}

export const DATA_STORE_TYPES = [
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
] as const

export const MODEL_TYPES = [
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
] as const

export const VISUALIZATION_TYPES = [
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
] as const

export const DATA_CLASSIFICATIONS = [
  "confidential",
  "internal",
  "public",
  "restricted",
  "classified",
] as const

export const METADATA_COMPONENT_TYPES = [
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
] as const

export const THREAT_TAXONOMIES = [
  "STRIDE",
  "LINDDUN",
  "MAESTRO",
  "MITRE-ATTACK",
] as const

export const THREAT_CATEGORIES: Record<string, readonly string[]> = {
  "STRIDE": [
    "spoofing",
    "tampering",
    "repudiation",
    "information-disclosure",
    "denial-of-service",
    "elevation-of-privilege",
  ],
  "LINDDUN": [
    "linkability",
    "identifiability",
    "non-repudiation",
    "detectability",
    "disclosure-of-information",
    "unawareness",
    "non-compliance",
  ],
  "MAESTRO": [
    "foundation-models",
    "data-operations",
    "agent-frameworks",
    "deployment-and-infrastructure",
    "evaluation-and-observability",
    "security-and-compliance",
    "agent-ecosystem",
  ],
  "MITRE-ATTACK": [
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
  ],
}

export const THREAT_ORIGINS = [
  "adversarial",
  "accidental",
  "structural",
  "environmental",
] as const

export const SCENARIO_INTENTS = [
  "accidental",
  "opportunistic",
  "targeted",
  "persistent",
] as const

export const SCENARIO_ACCESS_LEVELS = [
  "none",
  "external",
  "internal",
  "privileged",
  "physical",
] as const

export const PERSONA_ARCHETYPES = [
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
] as const

export const ATTACKER_ARCHETYPES = [
  "attacker",
  "insider-threat",
  "hacktivist",
  "nation-state",
  "organized-crime",
  "competitor",
] as const

export const TAXONOMY_SLUG_TO_SPEC: Record<string, string> = {
  "stride": "STRIDE",
  "linddun": "LINDDUN",
  "maestro": "MAESTRO",
  "mitre-attack": "MITRE-ATTACK",
  "mitre_attack": "MITRE-ATTACK",
  "mitre-att&ck": "MITRE-ATTACK",
  "attack": "MITRE-ATTACK",
}

export const CONTROL_CATEGORIES = [
  "preventive",
  "detective",
  "corrective",
  "compensating",
  "deterrent",
  "recovery",
] as const

export const IMPLEMENTATION_STATUSES = [
  "recommended",
  "proposed",
  "approved",
  "rejected",
  "planned",
  "in-progress",
  "implemented",
  "verified",
  "decommissioned",
] as const

export const COUNTERMEASURE_STATUS_TO_SPEC: Record<string, string> = {
  "planned": "planned",
  "in_progress": "in-progress",
  "implemented": "implemented",
  "verified": "verified",
  "decommissioned": "decommissioned",
}

export const CUSTOM_COUNTERMEASURE_STATUSES = [
  "gap",
  "waived",
  "platform",
] as const

export const EXTERNAL_REFERENCE_TYPES = [
  "issue-tracker",
  "evidence",
  "pentest-report",
] as const

export const TRUST_LEVELS = [
  "untrusted",
  "semi-trusted",
  "trusted",
  "highly-trusted",
] as const

export const PRECOGLY_DFD_MEDIA_TYPE = "application/vnd.precogly.dfd+json"

export const ASSET_TYPE_TO_CATEGORY: Record<string, string> = {
  "actor": "external_human_actor",
  "agent": "external_system_actor",
  "system": "external_system_actor",
  "subsystem": "external_system_actor",
  "data-store": "datastore",
  "cache": "datastore",
  "queue": "datastore",
  "stream": "datastore",
}

export const DEFAULT_CATEGORY = "process"

export const DATA_STORE_TYPE_TO_SPEC: Record<string, string> = {
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

export const DIAGRAM_TYPE_TO_VISUALIZATION_TYPE: Record<string, string> = {
  "context": "context",
  "level1": "data-flow",
  "level2": "data-flow",
}
