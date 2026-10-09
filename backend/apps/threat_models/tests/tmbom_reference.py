"""The reference model behind ``fixtures/tmbom/reference-model.cdx.json`` (9.10).

``build_reference_model`` makes one model that touches every slice of the
adapter. ``canonical`` rewrites a document so two exports of the same content
compare equal: refs become ordinal tokens in document order, and the
timestamp, serial number, version and dates are blanked.
"""

import base64
import copy
import json
import re
import uuid

from apps.compliance.models import (
    CountermeasureLibraryStandard,
    StandardFramework,
    StandardRequirement,
)
from apps.diagrams.models import DFD
from apps.diagrams.services import update_crosses_boundary
from apps.systems.models import (
    Boundary,
    ComponentDataAsset,
    DataAsset,
    Flow,
    FlowAsset,
    Orgsystem,
    OrgsystemComponent,
    Zone,
)
from apps.threat_models.models import (
    Assumption,
    AssumptionComponent,
    BusinessObjective,
    OutOfScopeItem,
    ThreatModel,
    ThreatModelRelationship,
    UseCase,
)
from apps.threat_models.review import approve
from apps.threats.models import (
    CountermeasureLibrary,
    ExternalTaxonomy,
    InstanceCountermeasureStandard,
    InstanceThreatTaxonomyEntry,
    TaxonomyEntry,
    ThreatLibrary,
    ThreatLibraryTaxonomyEntry,
    ThreatPersona,
    ThreatSource,
    ThreatSourceLink,
)
from apps.threats.scoring.owasp_risk_rating import OwaspRiskRatingEngine
from apps.threats.services import (
    create_instance_countermeasure,
    create_instance_threat,
    create_risk,
    create_risk_response,
    link_countermeasure,
    recalculate_threat_status,
    set_risk_business_objectives,
    set_threat_business_objectives,
)

LEDGER_SERIAL = uuid.UUID("5f1d4f6a-2c1e-4d6b-9c0a-7b1e2a3c4d5e")

OWASP_INPUTS = {
    "threat_agent": {"skill_level": 5, "motive": 6, "opportunity": 5, "size": 6},
    "vulnerability": {
        "ease_of_discovery": 5,
        "ease_of_exploit": 6,
        "awareness": 5,
        "intrusion_detection": 5,
    },
    "technical_impact": {
        "loss_of_confidentiality": 6,
        "loss_of_integrity": 6,
        "loss_of_availability": 6,
        "loss_of_accountability": 7,
    },
    "business_impact": {
        "financial_damage": 6,
        "reputation_damage": 6,
        "non_compliance": 6,
        "privacy_violation": 6,
    },
}


def build_reference_model(organization, user):
    """Every slice at once: structure, scenarios, controls, risks, context, identity."""
    stride, _ = ExternalTaxonomy.objects.get_or_create(
        slug="stride", defaults={"name": "STRIDE"}
    )
    tampering, _ = TaxonomyEntry.objects.get_or_create(
        taxonomy=stride, external_id="tampering", defaults={"title": "Tampering"}
    )
    capec, _ = ExternalTaxonomy.objects.get_or_create(
        slug="capec", defaults={"name": "CAPEC"}
    )
    capec_66, _ = TaxonomyEntry.objects.get_or_create(
        taxonomy=capec, external_id="66", defaults={"title": "SQL Injection"}
    )
    library_threat, _ = ThreatLibrary.objects.get_or_create(
        qualified_slug="reference/sql-injection",
        defaults={
            "name": "SQL injection",
            "description": "Injected SQL",
            "slug": "sql-injection",
        },
    )
    ThreatLibraryTaxonomyEntry.objects.get_or_create(
        threat_library=library_threat, taxonomy_entry=tampering
    )
    framework, _ = StandardFramework.objects.get_or_create(
        slug="reference-standard",
        defaults={"name": "Reference standard", "version": "1", "issuer": "Precogly"},
    )
    requirement, _ = StandardRequirement.objects.get_or_create(
        framework=framework,
        section_code="AC-2",
        defaults={"description": "Account management"},
    )
    library_control, _ = CountermeasureLibrary.objects.get_or_create(
        qualified_slug="reference/param-queries",
        defaults={
            "name": "Parameterised queries",
            "description": "Bind parameters",
            "slug": "param-queries",
            "control_functions": ["preventive"],
            "control_nature": "technical",
        },
    )
    CountermeasureLibraryStandard.objects.get_or_create(
        countermeasure_library=library_control,
        requirement=requirement,
        defaults={"sufficiency": "full"},
    )
    adversarial, _ = ThreatSource.objects.get_or_create(
        slug="adversarial", defaults={"name": "Adversarial"}
    )

    payments = Orgsystem.objects.create(
        organization=organization,
        name="Payments platform",
        lifecycle_state="production",
    )
    other_model = ThreatModel.objects.create(
        name="Ledger",
        organization=organization,
        created_by=user,
        # Fixed, so the fixture's BOM-Link to it resolves in every test run.
        serial_number=LEDGER_SERIAL,
    )
    threat_model = ThreatModel.objects.create(
        name="Reference model",
        description="The model behind the reference fixture",
        organization=organization,
        created_by=user,
        primary_system=payments,
        methodologies=["STRIDE", "Our own"],
        lifecycle_phase="build",
        review_frequency="P6M",
        risk_scoring_method="owasp-risk-rating",
    )
    ThreatModelRelationship.objects.create(
        source_threat_model=threat_model,
        target_threat_model=other_model,
        relation_type="depends_on",
    )
    blueprint = threat_model.default_blueprint
    blueprint.scope_description = "The card path"
    blueprint.save()

    internet = Zone.objects.create(blueprint=blueprint, name="Internet", trust_level=10)
    dmz = Zone.objects.create(
        blueprint=blueprint, name="DMZ", zone_type="network", trust_level=40
    )
    core = Zone.objects.create(
        blueprint=blueprint, name="Core", parent=dmz, trust_level=80
    )
    edge = Boundary.objects.create(
        blueprint=blueprint,
        zone_a=internet,
        zone_b=dmz,
        label="Edge",
        boundary_type="trust",
        authentication=["oauth2", "Badge"],
        authorization=["rbac"],
        data_validation=True,
        rate_limit="100 rps",
        protocols=["https"],
        session_management={"accessTokenTtl": 900, "idleTimeout": 600},
    )
    Boundary.objects.create(
        blueprint=blueprint,
        zone_a=dmz,
        zone_b=core,
        label="Inner",
        boundary_type="network",
    )
    customer = OrgsystemComponent.objects.create(
        blueprint=blueprint,
        name="Customer",
        category="external_human_actor",
        actor_type="customer",
    )
    api = OrgsystemComponent.objects.create(
        blueprint=blueprint,
        name="API",
        category="process",
        zone=dmz,
        description="Public API",
        data_sensitivity_level="high",
        kind="service",
    )
    worker = OrgsystemComponent.objects.create(
        blueprint=blueprint, name="Worker", category="process", zone=core
    )
    database = OrgsystemComponent.objects.create(
        blueprint=blueprint,
        name="Database",
        category="datastore",
        data_store_type="relational",
        zone=core,
    )
    sensor = OrgsystemComponent.objects.create(
        blueprint=blueprint, name="Sensor", category="process", kind="device"
    )
    login = Flow.objects.create(
        blueprint=blueprint,
        source_component=customer,
        dest_component=api,
        label="Login",
        protocol="HTTPS",
        encrypted=True,
        authentication=["oauth2"],
        port=443,
    )
    query = Flow.objects.create(
        blueprint=blueprint,
        source_component=api,
        dest_component=database,
        label="Query",
        has_sensitive_data=True,
        data_classification=["pii"],
    )
    Flow.objects.create(
        blueprint=blueprint,
        source_component=sensor,
        dest_component=worker,
        label="Reading",
        flow_type="signal",
    )
    records = DataAsset.objects.create(
        blueprint=blueprint,
        name="Card records",
        classification="confidential",
        compliance_tags=["PCI DSS"],
        description="Card data",
        confidentiality="high",
        availability="low",
        data_sensitivity=["pci", "pii"],
    )
    ComponentDataAsset.objects.create(
        component=database,
        data_asset=records,
        data_state="at_rest",
        encrypted=True,
        volume="2 million rows",
    )
    FlowAsset.objects.create(
        flow=login,
        data_asset=records,
        protection_method="encrypted",
        encryption_type="AES-256",
        format="json",
    )
    OutOfScopeItem.objects.create(
        blueprint=blueprint, name="Mainframe", reason="Separate model"
    )
    DFD.objects.create(
        blueprint=blueprint,
        name="Primary",
        diagram_type="level1",
        is_primary=True,
        canvas_data={
            "nodes": [
                {
                    "id": "z1",
                    "type": "trustZone",
                    "position": {"x": 0, "y": 0},
                    "data": {
                        "label": "DMZ",
                        "trust_zone_id": dmz.id,
                        "zone_type": "network",
                    },
                },
                {
                    "id": "n1",
                    "type": "process",
                    "position": {"x": 10, "y": 10},
                    "parent_id": "z1",
                    "data": {"label": "API", "component_id": api.id},
                },
            ],
            "edges": [],
        },
    )
    UseCase.objects.create(
        threat_model=threat_model,
        name="Pay",
        flow_data={
            "preconditions": ["Logged in"],
            "main_flow": [{"number": 1, "description": "Enter card"}],
        },
    )
    assumption = Assumption.objects.create(
        blueprint=blueprint,
        description="TLS everywhere",
        topic="security",
        validity="verified",
        owner=user,
        validation_method="Config review",
    )
    AssumptionComponent.objects.create(assumption=assumption, component=api)
    objective = BusinessObjective.objects.create(
        threat_model=threat_model,
        name="Keep card data private",
        criticality="high",
        owner_name="CISO",
    )
    persona = ThreatPersona.objects.create(
        threat_model=threat_model,
        symbolic_name="malicious-insider",
        name="Malicious insider",
        skill_level="high",
    )

    multi = create_instance_threat(
        threat_model,
        targets=[api, query],
        threat_library=library_threat,
        level="high",
        auto_generated=True,
        actor_persona=persona,
        intent="targeted",
        access_level="internal",
        triage_status="accept",
        decision_rationale="Accepted for now",
    )
    ThreatSourceLink.objects.create(source=adversarial, threat=multi)
    InstanceThreatTaxonomyEntry.objects.create(taxonomy_entry=capec_66, threat=multi)
    set_threat_business_objectives(multi, [objective])
    rated = create_instance_threat(
        threat_model,
        whole_system=True,
        threat_name="Backup theft",
        threat_description="Backups leave the building",
        rating=OwaspRiskRatingEngine().rate(OWASP_INPUTS),
        threat_actor_text="Organized crime",
        impact_description="Data leaves",
    )
    crossing = create_instance_threat(
        threat_model, targets=[edge], threat_name="Boundary crossing", level="low"
    )

    control = create_instance_countermeasure(
        threat_model,
        countermeasure_library=library_control,
        status="planned",
        targets=[api, query],
        implemented_by=[worker],
        implemented_by_party="Cloudflare",
        source="Pentest 2026-09",
        priority="high",
        required_for_release=True,
        effectiveness=0.6,
        assigned_owner=user,
        external_ticket_url="https://tickets.example/1",
        evidence_url="https://evidence.example/1.pdf",
    )
    link_countermeasure(control, multi)
    InstanceCountermeasureStandard.objects.create(
        countermeasure=control,
        requirement=None,
        section_code="SI-4",
        framework_name="Elsewhere standard",
        requirement_description="Monitor the system.",
        sufficiency="partial",
    )
    whole_control = create_instance_countermeasure(
        threat_model,
        countermeasure_name="Security training",
        status="platform",
        targets=[edge],
    )
    link_countermeasure(whole_control, crossing)

    risk = create_risk(
        threat_model,
        name="Customer data exposure",
        description="PII leaves the system",
        rating_inputs=OWASP_INPUTS,
        threat_ids=[multi.id, rated.id],
        status="assessed",
        domains=["security", "privacy"],
        owner=user,
        statement="An attacker reads card records through the API.",
    )
    set_risk_business_objectives(risk, [objective])
    for threat in (multi, rated, crossing):
        recalculate_threat_status(threat)
    update_crosses_boundary(blueprint)
    create_risk_response(
        risk,
        strategy="reduce",
        description="Add a WAF",
        status="in_progress",
        cost="medium",
        priority="high",
        owner=user,
        countermeasures=[control],
    )
    approve(threat_model, user)
    return threat_model


_DATE_KEYS = {"timestamp", "reviewDate", "approvalDate", "validationDate", "targetDate"}
# Import does not count as approval (D18): the review block and the roles it
# gives to parties are the one place an imported copy differs on purpose.
_REVIEW_KEYS = {"reviewer", "reviewDate", "approver", "approvalDate"}
_REVIEW_ROLES = {"reviewer", "signatory"}
# Row ids inside a canvas differ between installations; the refs beside them
# are what import matches on.
_CANVAS_ID_KEYS = {
    "component_id",
    "trust_zone_id",
    "dataflow_id",
    "trust_boundary_id",
    "orgsystem_id",
}


def canonical(document: dict) -> dict:
    """The document with refs replaced by ordinal tokens and volatile values blanked."""
    doc = copy.deepcopy(document)
    doc.pop("serialNumber", None)
    doc.pop("version", None)
    refs: dict[str, str] = {}

    def token(value: str) -> str:
        if value not in refs:
            refs[value] = f"ref:{len(refs) + 1}"
        return refs[value]

    def collect(node):
        if isinstance(node, dict):
            if isinstance(node.get("bom-ref"), str):
                token(node["bom-ref"])
            for value in node.values():
                collect(value)
        elif isinstance(node, list):
            for item in node:
                collect(item)

    collect(doc)

    def strip_canvas_ids(node):
        if isinstance(node, dict):
            return {
                k: strip_canvas_ids(v)
                for k, v in node.items()
                if k not in _CANVAS_ID_KEYS
            }
        if isinstance(node, list):
            return [strip_canvas_ids(item) for item in node]
        return node

    def rewrite(node, key=None):
        if isinstance(node, dict):
            if key == "metadata" and _REVIEW_KEYS & set(node):
                node = {k: v for k, v in node.items() if k not in _REVIEW_KEYS}
            if "roles" in node and isinstance(node["roles"], list):
                node = {
                    **node,
                    "roles": [
                        r for r in node["roles"] if r.get("role") not in _REVIEW_ROLES
                    ],
                }
            if (
                key == "attachment"
                and node.get("encoding") == "base64"
                and isinstance(node.get("content"), str)
            ):
                try:
                    decoded = json.loads(base64.b64decode(node["content"]))
                except (ValueError, TypeError):
                    decoded = None
                if decoded is not None:
                    node = {**node, "content": strip_canvas_ids(decoded)}
            return {k: rewrite(v, k) for k, v in node.items()}
        if isinstance(node, list):
            items = [rewrite(item, key) for item in node]
            if key == "parties":
                items = [p for p in items if not isinstance(p, dict) or p.get("roles")]
            return items
        if isinstance(node, str):
            if key in _DATE_KEYS:
                return "<date>"
            if node in refs:
                return refs[node]
            match = re.match(r"^(urn:cdx:)[0-9a-f-]{36}/\d+(#.*)?$", node)
            if match:
                return "urn:cdx:<serial>" + (match.group(2) or "")
            if node.startswith("urn:uuid:"):
                return "urn:uuid:<serial>"
            if key == "value" and node[:1] in "[{":
                # JSON-valued properties may hold refs
                try:
                    decoded = json.loads(node)
                except ValueError:
                    return node
                return json.dumps(
                    rewrite(decoded), separators=(",", ":"), sort_keys=True
                )
            return node
        return node

    return rewrite(doc)
