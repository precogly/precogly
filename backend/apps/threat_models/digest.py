"""The content digest of a threat model (plan section 4.8, L5, M2).

Answers "has the model changed since it was approved?" from a defined
snapshot of the rows the model owns, not from the export output, so a pack
upgrade, a renamed user or a new exporter release does not change it.

Rules:

- Ids stand in for anything outside the model (library rows, users, inventory
  systems, requirements, other models), so renaming those changes nothing.
- Library and standards text, diagram layout, timestamps and the review
  fields are left out. Comments and ordering are left out too: whatever is
  in the snapshot counts; whatever is left out does not.
- ``format_metadata`` counts in full (N3, S1): nothing writes it after import.
- A rating is snapshotted inline under the threat or risk that holds it, by
  content. Rating rows are replaced, not edited, every time a rating is set or
  a residual is recalculated, so their ids would mark an unchanged model as
  changed (R9).
- No scheme number (S3). If a release changes the snapshot, models approved
  before it read as changed once, and the release notes say why.

``SNAPSHOT_FIELDS`` lists, per model-owned table, the fields that count and
the fields deliberately left out. A test requires every concrete field of
every listed model to be in one of the two lists, so a new field fails the
test until someone decides where it goes.
"""

import hashlib
import json

from django.db.models import ForeignKey, ManyToManyField, OneToOneField

# model label -> (fields that count, fields left out)
SNAPSHOT_FIELDS = {
    "threat_models.ThreatModel": (
        [
            "name",
            "description",
            "criticality",
            "risk_scoring_method",
            "format_metadata",
            "methodologies",
            "lifecycle_phase",
            "valid_from",
            "valid_until",
            "review_frequency",
            "owning_team",
            "organization",
            "primary_system",
        ],
        # The serial number is the document's identity, not its content.
        [
            "id",
            "created_at",
            "updated_at",
            "created_by",
            "workspace_data",
            "serial_number",
        ],
    ),
    "threat_models.Blueprint": (
        ["name", "description", "model_types", "scope_description", "format_metadata"],
        ["id", "created_at", "updated_at", "threat_model", "display_order"],
    ),
    "threat_models.OutOfScopeItem": (
        ["name", "reason"],
        ["id", "created_at", "updated_at", "blueprint"],
    ),
    "threat_models.Assumption": (
        [
            "blueprint",
            "description",
            "topic",
            "validity",
            "impact",
            "owner",
            "owner_name",
            "validation_method",
            "validation_date",
            "format_metadata",
        ],
        ["id", "created_at", "updated_at", "display_order"],
    ),
    "threat_models.AssumptionComponent": (
        ["assumption", "component"],
        ["id", "created_at", "updated_at", "display_order"],
    ),
    "threat_models.BusinessObjective": (
        [
            "name",
            "description",
            "criticality",
            "owner",
            "owner_name",
            "format_metadata",
        ],
        ["id", "created_at", "updated_at", "threat_model", "display_order"],
    ),
    "threat_models.UseCase": (
        ["name", "description", "flow_data", "format_metadata"],
        ["id", "created_at", "updated_at", "threat_model"],
    ),
    "threat_models.ThreatModelRelationship": (
        ["target_threat_model", "relation_type"],
        ["id", "created_at", "updated_at", "source_threat_model"],
    ),
    "threat_models.ThreatModelFramework": (
        ["framework"],
        ["id", "threat_model"],
    ),
    "threat_models.ThreatModelLibraryPack": (
        ["library_pack"],
        ["id", "threat_model"],
    ),
    "systems.OrgsystemComponent": (
        [
            "blueprint",
            "name",
            "description",
            "category",
            "kind",
            "actor_type",
            "data_store_type",
            "data_sensitivity_level",
            "component_library",
            "zone",
            "parent_component",
            "orgsystem",
            "component_type",
            "provider",
            "format_metadata",
        ],
        ["id", "created_at", "updated_at", "source_integration"],
    ),
    "systems.Zone": (
        [
            "blueprint",
            "name",
            "zone_type",
            "trust_level",
            "description",
            "parent",
            "format_metadata",
        ],
        ["id", "created_at", "updated_at"],
    ),
    "systems.Boundary": (
        [
            "blueprint",
            "zone_a",
            "zone_b",
            "label",
            "description",
            "boundary_type",
            "authentication",
            "authorization",
            "data_validation",
            "data_transformation",
            "logging",
            "monitoring",
            "rate_limit",
            "protocols",
            "session_management",
            "format_metadata",
        ],
        ["id", "created_at", "updated_at", "edge_id"],
    ),
    "systems.Flow": (
        [
            "blueprint",
            "source_component",
            "dest_component",
            "label",
            "description",
            "flow_type",
            "protocol",
            "port",
            "encrypted",
            "authentication",
            "authorization",
            "crosses_boundary",
            "has_sensitive_data",
            "data_classification",
            "format_metadata",
        ],
        ["id", "created_at", "updated_at", "edge_id"],
    ),
    "systems.FlowAsset": (
        [
            "flow",
            "data_asset",
            "protection_method",
            "encryption_type",
            "sensitivity_override",
            "format",
        ],
        ["id", "created_at", "updated_at"],
    ),
    "systems.DataAsset": (
        [
            "blueprint",
            "name",
            "description",
            "classification",
            "confidentiality",
            "integrity",
            "availability",
            "compliance_tags",
            "data_sensitivity",
            "format_metadata",
        ],
        ["id", "created_at", "updated_at"],
    ),
    "systems.ComponentDataAsset": (
        ["component", "data_asset", "data_state", "volume", "encrypted"],
        ["id", "created_at", "updated_at"],
    ),
    "diagrams.DFD": (
        ["blueprint", "name", "diagram_type", "is_primary"],
        # Layout (canvas_data) is left out on purpose: moving a node is not a change.
        [
            "id",
            "created_at",
            "updated_at",
            "canvas_data",
            "updated_by",
            "template_library",
        ],
    ),
    "threats.InstanceThreat": (
        [
            "number",
            "whole_system",
            "threat_library",
            "rating",
            "status",
            "triage_status",
            "decision_rationale",
            "threat_name",
            "threat_description",
            "taxonomy_snapshot",
            "impact_description",
            "actor_persona",
            "threat_actor_text",
            "intent",
            "access_level",
            "format_metadata",
        ],
        [
            "id",
            "created_at",
            "updated_at",
            "threat_model",
            "auto_generated",
            "display_order",
        ],
    ),
    "threats.InstanceThreatTarget": (
        ["threat", "component", "flow", "zone", "boundary"],
        ["id", "display_order"],
    ),
    "threats.Rating": (
        [
            "methodology",
            "level",
            "score",
            "likelihood_level",
            "likelihood_score",
            "likelihood_factors",
            "likelihood_extra",
            "impact_level",
            "impact_score",
            "impact_factors",
            "impact_extra",
            "rationale",
        ],
        ["id", "created_at", "updated_at", "organization"],
    ),
    "threats.InstanceCountermeasure": (
        [
            "number",
            "countermeasure_library",
            "status",
            "verified_by",
            "evidence_url",
            "required_for_release",
            "assigned_owner",
            "countermeasure_name",
            "countermeasure_description",
            "control_functions",
            "control_nature",
            "effectiveness",
            "priority",
            "due_date",
            "external_ticket_url",
            "implemented_by_party",
            "source",
            "format_metadata",
        ],
        ["id", "created_at", "updated_at", "threat_model", "auto_generated"],
    ),
    "threats.InstanceCountermeasureTarget": (
        ["countermeasure", "component", "flow", "zone", "boundary"],
        ["id", "display_order"],
    ),
    "threats.InstanceCountermeasureProvider": (
        ["countermeasure", "component"],
        ["id", "created_at", "updated_at", "display_order"],
    ),
    "threats.CountermeasureThreatLink": (
        ["countermeasure", "threat"],
        ["id", "created_at", "updated_at", "display_order"],
    ),
    "threats.InstanceCountermeasureStandard": (
        [
            "countermeasure",
            "requirement",
            "sufficiency",
            "section_code",
            "framework_name",
            "requirement_description",
        ],
        ["id", "created_at", "updated_at"],
    ),
    "threats.InstanceThreatTaxonomyEntry": (
        ["taxonomy_entry", "threat"],
        ["id", "created_at", "updated_at"],
    ),
    "threats.ThreatSourceLink": (
        ["source", "threat"],
        ["id", "created_at", "updated_at"],
    ),
    "threats.InstanceThreatBusinessObjective": (
        ["threat", "business_objective"],
        ["id", "created_at", "updated_at", "display_order"],
    ),
    "threats.ThreatPersona": (
        [
            "symbolic_name",
            "name",
            "description",
            "is_person",
            "malicious_intent",
            "skill_level",
            "motivation",
            "resources",
            "objectives",
            "format_metadata",
        ],
        ["id", "created_at", "updated_at", "threat_model"],
    ),
    "threats.Risk": (
        [
            "name",
            "description",
            "status",
            "statement",
            "inherent",
            "residual",
            "target",
            "domains",
            "owner",
            "assigned_to",
            "format_metadata",
        ],
        ["id", "created_at", "updated_at", "threat_model"],
    ),
    "threats.RiskThreat": (
        ["risk", "threat"],
        ["id", "created_at", "updated_at"],
    ),
    "threats.RiskBusinessObjective": (
        ["risk", "business_objective"],
        ["id", "created_at", "updated_at", "display_order"],
    ),
    "threats.RiskResponse": (
        [
            "risk",
            "strategy",
            "description",
            "status",
            "effectiveness",
            "cost",
            "priority",
            "owner",
            "target_date",
            "format_metadata",
        ],
        ["id", "created_at", "updated_at"],
    ),
    "threats.RiskResponseCountermeasure": (
        ["response", "countermeasure"],
        ["id", "created_at", "updated_at", "display_order"],
    ),
    # A model's own internal standard and its requirements (pack standards
    # have no threat_model and are outside the model).
    "compliance.StandardFramework": (
        ["slug", "name", "version", "issuer", "description"],
        ["id", "created_at", "updated_at", "source_pack", "threat_model"],
    ),
    "compliance.StandardRequirement": (
        [
            "framework",
            "section_code",
            "name",
            "description",
            "parent",
            "requirement_type",
            "status",
            "priority",
            "acceptance_criteria",
            "format_metadata",
        ],
        ["id", "created_at", "updated_at"],
    ),
    # Which verification tests a control is checked by; when it was last
    # tested is a result, not part of the model.
    "threats.InstanceCountermeasureTest": (
        ["countermeasure", "verification_test"],
        ["id", "created_at", "updated_at", "tested_at"],
    ),
}

# Model-owned tables whose rows are left out of the snapshot entirely, with
# the reason. Together with ``SNAPSHOT_FIELDS`` this decides every table that
# hangs off a model (R30); a test walks the foreign keys and fails on a table
# in neither.
LEFT_OUT_TABLES = {
    "threat_models.ThreatModelReview": "the review fields themselves",
    "threat_models.ThreatModelState": "export bookkeeping (version, export digest)",
    "threat_models.ThreatModelReferenceImage": "attachments, like diagram layout",
    "threats.CountermeasureComment": "comments are not content",
    "threats.PentestFinding": "results of a test against the system, not the model",
    "organizations.MagicLink": "sharing, not content",
    "organizations.SharedWithMe": "sharing, not content",
}


def _model(label):
    from django.apps import apps

    app_label, model_name = label.split(".")
    return apps.get_model(app_label, model_name)


def _rows(label, **filters):
    return _model(label).objects.filter(**filters)


# How each table's rows are found from the model.
ROW_SOURCES = {
    "threat_models.ThreatModel": lambda tm: [tm],
    "threat_models.Blueprint": lambda tm: tm.blueprints.all(),
    "threat_models.OutOfScopeItem": lambda tm: tm.out_of_scope_items,
    "threat_models.Assumption": lambda tm: _rows(
        "threat_models.Assumption", blueprint__threat_model=tm
    ),
    "threat_models.AssumptionComponent": lambda tm: _rows(
        "threat_models.AssumptionComponent", assumption__blueprint__threat_model=tm
    ),
    "threat_models.BusinessObjective": lambda tm: tm.business_objectives.all(),
    "threat_models.UseCase": lambda tm: tm.use_cases.all(),
    "threat_models.ThreatModelRelationship": lambda tm: tm.outgoing_relationships.all(),
    "threat_models.ThreatModelFramework": lambda tm: _rows(
        "threat_models.ThreatModelFramework", threat_model=tm
    ),
    "threat_models.ThreatModelLibraryPack": lambda tm: _rows(
        "threat_models.ThreatModelLibraryPack", threat_model=tm
    ),
    "systems.OrgsystemComponent": lambda tm: tm.components,
    "systems.Zone": lambda tm: tm.zones,
    "systems.Boundary": lambda tm: tm.boundaries,
    "systems.Flow": lambda tm: tm.flows,
    "systems.FlowAsset": lambda tm: _rows(
        "systems.FlowAsset", flow__blueprint__threat_model=tm
    ),
    "systems.DataAsset": lambda tm: tm.data_assets,
    "systems.ComponentDataAsset": lambda tm: _rows(
        "systems.ComponentDataAsset", component__blueprint__threat_model=tm
    ),
    "diagrams.DFD": lambda tm: tm.dfds,
    "threats.InstanceThreat": lambda tm: tm.threats.all(),
    "threats.InstanceThreatTarget": lambda tm: _rows(
        "threats.InstanceThreatTarget", threat__threat_model=tm
    ),
    "threats.InstanceCountermeasure": lambda tm: tm.countermeasures.all(),
    "threats.InstanceCountermeasureTarget": lambda tm: _rows(
        "threats.InstanceCountermeasureTarget", countermeasure__threat_model=tm
    ),
    "threats.InstanceCountermeasureProvider": lambda tm: _rows(
        "threats.InstanceCountermeasureProvider", countermeasure__threat_model=tm
    ),
    "threats.CountermeasureThreatLink": lambda tm: _rows(
        "threats.CountermeasureThreatLink", threat__threat_model=tm
    ),
    "threats.InstanceCountermeasureStandard": lambda tm: _rows(
        "threats.InstanceCountermeasureStandard", countermeasure__threat_model=tm
    ),
    "threats.InstanceThreatTaxonomyEntry": lambda tm: _rows(
        "threats.InstanceThreatTaxonomyEntry", threat__threat_model=tm
    ),
    "threats.ThreatSourceLink": lambda tm: _rows(
        "threats.ThreatSourceLink", threat__threat_model=tm
    ),
    "threats.InstanceThreatBusinessObjective": lambda tm: _rows(
        "threats.InstanceThreatBusinessObjective", threat__threat_model=tm
    ),
    "threats.ThreatPersona": lambda tm: tm.threat_personas.all(),
    "threats.Risk": lambda tm: tm.risks.all(),
    "threats.RiskThreat": lambda tm: _rows("threats.RiskThreat", risk__threat_model=tm),
    "threats.RiskBusinessObjective": lambda tm: _rows(
        "threats.RiskBusinessObjective", risk__threat_model=tm
    ),
    "threats.RiskResponse": lambda tm: _rows(
        "threats.RiskResponse", risk__threat_model=tm
    ),
    "threats.RiskResponseCountermeasure": lambda tm: _rows(
        "threats.RiskResponseCountermeasure", response__risk__threat_model=tm
    ),
    "compliance.StandardFramework": lambda tm: _rows(
        "compliance.StandardFramework", threat_model=tm
    ),
    "compliance.StandardRequirement": lambda tm: _rows(
        "compliance.StandardRequirement", framework__threat_model=tm
    ),
    "threats.InstanceCountermeasureTest": lambda tm: _rows(
        "threats.InstanceCountermeasureTest", countermeasure__threat_model=tm
    ),
}


# Tables whose rows are snapshotted inside the row that points at them, by
# content, rather than as a table of their own keyed by id.
INLINE_TABLES = {"threats.Rating"}


def _inline(row):
    label = row._meta.label
    return {name: _value(row, name) for name in SNAPSHOT_FIELDS[label][0]}


def _value(row, field_name):
    field = row._meta.get_field(field_name)
    if isinstance(field, (ForeignKey, OneToOneField)):
        if field.related_model._meta.label in INLINE_TABLES:
            related = getattr(row, field_name)
            return _inline(related) if related is not None else None
        return getattr(row, field.attname)
    if isinstance(field, ManyToManyField):
        return sorted(getattr(row, field_name).values_list("pk", flat=True))
    value = getattr(row, field_name)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def model_snapshot(threat_model) -> dict:
    """The defined snapshot: ``{table: [{field: value}, ...]}`` in a stable order."""
    snapshot = {}
    for label, (fields, _left_out) in SNAPSHOT_FIELDS.items():
        if label in INLINE_TABLES:
            continue
        rows = ROW_SOURCES[label](threat_model)
        if hasattr(rows, "order_by"):
            rows = rows.order_by("pk")
        snapshot[label] = [
            {name: _value(row, name) for name in fields} | {"pk": row.pk}
            for row in rows
        ]
    return snapshot


def model_digest(threat_model) -> str:
    """SHA-256 of the snapshot's canonical JSON."""
    payload = json.dumps(
        model_snapshot(threat_model), sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
