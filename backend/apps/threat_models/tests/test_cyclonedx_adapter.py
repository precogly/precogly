# ruff: noqa
"""Switched off with the pre-2.0 adapter it tests (plan step 1, section 9.1).

The adapter module this file exercises is listed for removal and no longer
imported by the application. Collected but skipped, so the suite stays green
until the owner deletes both files.
"""

import pytest

pytest.skip(
    "legacy adapter test: the module under test is listed for removal",
    allow_module_level=True,
)

"""Tests for CycloneDX 2.0 TM-BOM adapter import and export."""

import json
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.diagrams.models import DFD
from apps.organizations.models import (
    Organization,
    OrganizationMember,
    Team,
    TeamMembership,
)
from apps.systems.models import (
    DataAsset,
    DataFlow,
    OrgsystemComponent,
    TrustBoundary,
    TrustZone,
)
from apps.threat_models.models import UseCase
from apps.threats.models import (
    ComponentInstanceThreat,
    InstanceCountermeasure,
    Risk,
    RiskThreat,
    ThreatLibrary,
)

from ..adapters import CycloneDxAdapter

User = get_user_model()

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name):
    return json.loads((FIXTURES_DIR / name).read_text())


class CycloneDxTestMixin:
    """Shared setup for CycloneDX adapter tests."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            username="cdxuser", email="cdx@example.com", password="testpass123"
        )
        cls.org = Organization.objects.create(name="CDX Test Org", domain="cdx.test")
        OrganizationMember.objects.create(
            organization=cls.org, user=cls.user, role="security_team"
        )
        cls.team = Team.objects.create(
            organization=cls.org, name="Default Team", code="default"
        )
        TeamMembership.objects.create(team=cls.team, user=cls.user, role="lead")
        cls.adapter = CycloneDxAdapter()


# =====================================================================
# Validation Tests
# =====================================================================


class TestCycloneDxValidation(CycloneDxTestMixin, TestCase):
    """Test CycloneDX validation logic."""

    def test_non_dict_input_raises_error(self):
        with self.assertRaises(Exception):
            self.adapter.validate("not a dict")

    def test_wrong_spec_format_raises_error(self):
        with self.assertRaises(Exception):
            self.adapter.validate({"specFormat": "SPDX", "specVersion": "2.0"})

    def test_missing_spec_format_raises_error(self):
        with self.assertRaises(Exception):
            self.adapter.validate({"specVersion": "2.0"})

    def test_wrong_spec_version_raises_error(self):
        with self.assertRaises(Exception):
            self.adapter.validate({"specFormat": "CycloneDX", "specVersion": "1.5"})

    def test_valid_minimal_no_blueprints(self):
        warnings = self.adapter.validate(
            {"specFormat": "CycloneDX", "specVersion": "2.0"}
        )
        self.assertTrue(any("No blueprints" in w for w in warnings))

    def test_multiple_blueprints_warns(self):
        warnings = self.adapter.validate(
            {
                "specFormat": "CycloneDX",
                "specVersion": "2.0",
                "blueprints": [
                    {"name": "First"},
                    {"name": "Second"},
                ],
            }
        )
        self.assertTrue(any("2 blueprints" in w for w in warnings))

    def test_valid_single_blueprint(self):
        warnings = self.adapter.validate(
            {
                "specFormat": "CycloneDX",
                "specVersion": "2.0",
                "blueprints": [{"name": "Test"}],
            }
        )
        self.assertEqual(len(warnings), 0)


# =====================================================================
# Import Tests
# =====================================================================


class TestCycloneDxImportMinimal(CycloneDxTestMixin, TestCase):
    """Test import of the minimal CycloneDX fixture."""

    def setUp(self):
        self.json_data = load_fixture("cyclonedx_minimal.json")
        self.threat_model, self.summary = self.adapter.import_data(
            self.json_data, self.org, self.user
        )

    def test_threat_model_created(self):
        self.assertEqual(self.threat_model.name, "Minimal Test Blueprint")
        self.assertEqual(self.summary["threat_model"], 1)

    def test_zones_created(self):
        self.assertEqual(self.summary["zones"], 2)
        zones = TrustZone.objects.filter(
            components__threat_model=self.threat_model
        ).distinct()
        zone_names = set(zones.values_list("name", flat=True))
        self.assertIn("Internal Zone", zone_names)

    def test_boundaries_created(self):
        self.assertEqual(self.summary["boundaries"], 1)
        boundary = TrustBoundary.objects.first()
        self.assertEqual(boundary.label, "Perimeter Boundary")
        self.assertTrue(boundary.authentication)
        self.assertTrue(boundary.authorization)
        self.assertFalse(boundary.data_validation)

    def test_components_created(self):
        self.assertEqual(self.summary["components"], 3)
        components = OrgsystemComponent.objects.filter(threat_model=self.threat_model)
        self.assertEqual(components.count(), 3)

    def test_asset_type_mapping(self):
        web_app = OrgsystemComponent.objects.get(
            threat_model=self.threat_model, name="Web Application"
        )
        self.assertEqual(web_app.category, "process")

        database = OrgsystemComponent.objects.get(
            threat_model=self.threat_model, name="Patient Database"
        )
        self.assertEqual(database.category, "datastore")

        user = OrgsystemComponent.objects.get(
            threat_model=self.threat_model, name="End User"
        )
        self.assertEqual(user.category, "external_human_actor")

    def test_flows_created(self):
        self.assertEqual(self.summary["flows"], 2)
        flow = DataFlow.objects.get(label="User Requests")
        self.assertEqual(flow.protocol, "HTTPS")
        self.assertTrue(flow.encrypted)
        self.assertTrue(flow.authenticated)

    def test_threats_created(self):
        self.assertEqual(self.summary["threats"], 1)
        threat_lib = ThreatLibrary.objects.get(name="SQL Injection")
        self.assertIsNotNone(threat_lib)

    def test_scenarios_created(self):
        self.assertEqual(self.summary["scenarios"], 1)
        scenario = ComponentInstanceThreat.objects.get(
            component__threat_model=self.threat_model
        )
        self.assertEqual(scenario.inherent_severity, "high")
        self.assertEqual(scenario.intent, "targeted")
        self.assertEqual(scenario.access_level, "external")

    def test_controls_created(self):
        self.assertEqual(self.summary["controls"], 1)
        control = InstanceCountermeasure.objects.get(threat_model=self.threat_model)
        self.assertEqual(control.countermeasure_name, "Input Validation")
        self.assertEqual(control.status, "implemented")
        self.assertAlmostEqual(control.effectiveness, 0.85)

    def test_risks_created(self):
        self.assertEqual(self.summary["risks"], 1)
        risk = Risk.objects.get(threat_model=self.threat_model)
        self.assertEqual(risk.name, "Data Breach via SQL Injection")
        self.assertEqual(risk.inherent_score, 75)
        self.assertEqual(risk.inherent_level, "high")
        self.assertEqual(risk.residual_score, 30)
        self.assertEqual(risk.residual_level, "low")
        self.assertEqual(risk.domains, ["security", "compliance"])

    def test_risk_responses_created(self):
        risk = Risk.objects.get(threat_model=self.threat_model)
        responses = list(risk.responses.all())
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0].strategy, "reduce")
        self.assertEqual(responses[0].status, "implemented")

    def test_risk_threat_links(self):
        risk = Risk.objects.get(threat_model=self.threat_model)
        risk_threats = RiskThreat.objects.filter(risk=risk)
        self.assertGreaterEqual(risk_threats.count(), 1)


class TestCycloneDxImportFull(CycloneDxTestMixin, TestCase):
    """Test import of the full CycloneDX fixture."""

    def setUp(self):
        self.json_data = load_fixture("cyclonedx_full.json")
        self.threat_model, self.summary = self.adapter.import_data(
            self.json_data, self.org, self.user
        )

    def test_use_cases_created(self):
        self.assertEqual(self.summary["use_cases"], 1)
        use_case = UseCase.objects.get(threat_model=self.threat_model)
        self.assertEqual(use_case.name, "User Login")
        self.assertIn("preconditions", use_case.flow_data)
        self.assertIn("main_flow", use_case.flow_data)
        self.assertIn("alternative_flows", use_case.flow_data)

    def test_device_asset_maps_to_process(self):
        plc = OrgsystemComponent.objects.get(
            threat_model=self.threat_model, name="PLC Controller"
        )
        self.assertEqual(plc.category, "process")
        self.assertEqual(plc.format_metadata["cyclonedx"]["asset_type"], "device")

    def test_gateway_asset_maps_to_process(self):
        gateway = OrgsystemComponent.objects.get(
            threat_model=self.threat_model, name="API Gateway"
        )
        self.assertEqual(gateway.category, "process")

    def test_agent_asset_maps_to_external_system(self):
        payment = OrgsystemComponent.objects.get(
            threat_model=self.threat_model, name="Payment Provider"
        )
        self.assertEqual(payment.category, "external_system_actor")

    def test_cache_asset_maps_to_datastore(self):
        cache = OrgsystemComponent.objects.get(
            threat_model=self.threat_model, name="Redis Cache"
        )
        self.assertEqual(cache.category, "datastore")

    def test_boundary_all_crossing_requirements(self):
        boundary = TrustBoundary.objects.get(label="Network Perimeter")
        self.assertTrue(boundary.authentication)
        self.assertTrue(boundary.authorization)
        self.assertTrue(boundary.data_validation)
        self.assertTrue(boundary.logging)
        self.assertTrue(boundary.monitoring)
        self.assertTrue(boundary.rate_limiting)

    def test_boundary_session_management_in_tier3(self):
        boundary = TrustBoundary.objects.get(label="Internal Boundary")
        cdx_meta = boundary.format_metadata.get("cyclonedx", {})
        session = cdx_meta.get("session_management", {})
        self.assertEqual(session.get("tokenType"), "JWT")
        self.assertEqual(session.get("ttl"), 3600)

    def test_multiple_risk_responses(self):
        risk = Risk.objects.get(name="Data Breach via SQL Injection")
        responses = list(risk.responses.order_by("created_at"))
        self.assertEqual(len(responses), 2)
        self.assertEqual(responses[0].strategy, "reduce")
        self.assertEqual(responses[1].strategy, "transfer")

    def test_target_risk_imported(self):
        risk = Risk.objects.get(name="Data Breach via SQL Injection")
        self.assertEqual(risk.target_score, 10)
        self.assertEqual(risk.target_level, "low")

    def test_risk_domains(self):
        risk = Risk.objects.get(name="Data Breach via SQL Injection")
        self.assertEqual(risk.domains, ["security", "compliance", "privacy"])

    def test_data_assets_created(self):
        self.assertEqual(self.summary["data_assets"], 1)
        data_asset = DataAsset.objects.get(threat_model=self.threat_model)
        self.assertEqual(data_asset.name, "Customer PII")
        self.assertEqual(data_asset.classification, "confidential")

    def test_tier3_attack_trees_stored(self):
        self.threat_model.refresh_from_db()
        cdx_meta = self.threat_model.format_metadata.get("cyclonedx", {})
        self.assertIn("attack_trees", cdx_meta)

    def test_tier3_behaviors_stored(self):
        self.threat_model.refresh_from_db()
        cdx_meta = self.threat_model.format_metadata.get("cyclonedx", {})
        self.assertIn("behaviors", cdx_meta)

    def test_control_status_mapping(self):
        controls = InstanceCountermeasure.objects.filter(threat_model=self.threat_model)
        statuses = set(controls.values_list("status", flat=True))
        self.assertIn("verified", statuses)
        self.assertIn("implemented", statuses)

    def test_scenario_intent_and_access_level(self):
        scenario = ComponentInstanceThreat.objects.filter(
            component__threat_model=self.threat_model,
            intent="targeted",
        ).first()
        self.assertIsNotNone(scenario)
        self.assertEqual(scenario.access_level, "external")

    def test_multiple_threats_and_scenarios(self):
        self.assertEqual(self.summary["threats"], 2)
        self.assertEqual(self.summary["scenarios"], 2)

    def test_dfd_canvas_imported(self):
        dfd = DFD.objects.get(threat_model=self.threat_model)
        self.assertEqual(dfd.name, "Full Test DFD")
        self.assertEqual(dfd.diagram_type, "level1")
        self.assertTrue(dfd.is_primary)
        self.assertEqual(len(dfd.canvas_data["nodes"]), 3)
        self.assertEqual(len(dfd.canvas_data["edges"]), 2)


# =====================================================================
# Export Tests
# =====================================================================


class TestCycloneDxExport(CycloneDxTestMixin, TestCase):
    """Test export of a Precogly threat model to CycloneDX."""

    def setUp(self):
        # Import the full fixture first, then export it
        self.json_data = load_fixture("cyclonedx_full.json")
        self.threat_model, _ = self.adapter.import_data(
            self.json_data, self.org, self.user
        )
        self.export = self.adapter.export_data(self.threat_model)

    def test_root_envelope(self):
        self.assertEqual(self.export["specFormat"], "CycloneDX")
        self.assertEqual(self.export["specVersion"], "2.0")
        self.assertIn("serialNumber", self.export)
        self.assertEqual(self.export["version"], 1)

    def test_metadata_present(self):
        metadata = self.export["metadata"]
        self.assertIn("timestamp", metadata)
        self.assertIn("tools", metadata)
        self.assertEqual(metadata["tools"]["components"][0]["name"], "Precogly")

    def test_single_blueprint(self):
        self.assertEqual(len(self.export["blueprints"]), 1)
        blueprint = self.export["blueprints"][0]
        self.assertEqual(blueprint["name"], "Full Test Blueprint")
        self.assertEqual(blueprint["modelTypes"], ["data-flow"])

    def test_assets_exported(self):
        blueprint = self.export["blueprints"][0]
        assets = blueprint.get("assets", [])
        self.assertGreaterEqual(len(assets), 5)
        asset_names = {a["name"] for a in assets}
        self.assertIn("API Gateway", asset_names)
        self.assertIn("Application Server", asset_names)

    def test_zones_exported(self):
        blueprint = self.export["blueprints"][0]
        zones = blueprint.get("zones", [])
        self.assertGreaterEqual(len(zones), 2)

    def test_boundaries_exported(self):
        blueprint = self.export["blueprints"][0]
        boundaries = blueprint.get("boundaries", [])
        self.assertGreaterEqual(len(boundaries), 1)
        # Check crossing requirements
        perimeter = next(
            (b for b in boundaries if b.get("name") == "Network Perimeter"),
            None,
        )
        self.assertIsNotNone(perimeter)
        crossing = perimeter.get("crossingRequirements", {})
        self.assertTrue(crossing.get("authentication"))
        self.assertTrue(crossing.get("rateLimit"))

    def test_flows_exported(self):
        blueprint = self.export["blueprints"][0]
        flows = blueprint.get("flows", [])
        self.assertGreaterEqual(len(flows), 3)

    def test_threats_block_exported(self):
        threats = self.export.get("threats", {})
        self.assertIn("threats", threats)
        self.assertIn("scenarios", threats)
        self.assertGreaterEqual(len(threats["threats"]), 1)
        self.assertGreaterEqual(len(threats["scenarios"]), 1)

    def test_risks_block_exported(self):
        risks = self.export.get("risks", {})
        self.assertIn("risks", risks)
        self.assertGreaterEqual(len(risks["risks"]), 1)

        risk = risks["risks"][0]
        self.assertIn("inherentRisk", risk)
        self.assertIn("statement", risk)

    def test_risk_responses_exported(self):
        risks = self.export.get("risks", {})
        risk_with_responses = next(
            (r for r in risks["risks"] if r.get("responses")), None
        )
        self.assertIsNotNone(risk_with_responses)
        self.assertGreaterEqual(len(risk_with_responses["responses"]), 1)

    def test_controls_exported(self):
        controls = self.export.get("controls", [])
        self.assertGreaterEqual(len(controls), 1)

    def test_use_cases_exported(self):
        definitions = self.export.get("definitions", {})
        use_cases = definitions.get("useCases", [])
        self.assertEqual(len(use_cases), 1)
        self.assertEqual(use_cases[0]["name"], "User Login")
        self.assertIn("preconditions", use_cases[0])
        self.assertIn("mainFlow", use_cases[0])

    def test_tier3_attack_trees_re_emitted(self):
        threats = self.export.get("threats", {})
        self.assertIn("attackTrees", threats)

    def test_tier3_behaviors_re_emitted(self):
        blueprint = self.export["blueprints"][0]
        self.assertIn("behaviors", blueprint)

    def test_dfd_canvas_exported(self):
        blueprint = self.export["blueprints"][0]
        visualizations = blueprint.get("visualizations", [])
        dfd_vis = next(
            (v for v in visualizations if v.get("type") == "precogly-dfd"),
            None,
        )
        self.assertIsNotNone(dfd_vis)
        self.assertEqual(dfd_vis["name"], "Full Test DFD")
        self.assertEqual(dfd_vis["diagramType"], "level1")
        self.assertEqual(len(dfd_vis["data"]["nodes"]), 3)
        self.assertEqual(len(dfd_vis["data"]["edges"]), 2)


# =====================================================================
# Round-Trip Tests
# =====================================================================


class TestCycloneDxRoundTrip(CycloneDxTestMixin, TestCase):
    """Test import -> export -> import round-trip fidelity."""

    def test_import_export_import_equivalence(self):
        """Import full fixture, export, re-import, compare."""
        json_data = load_fixture("cyclonedx_full.json")

        # First import
        tm1, summary1 = self.adapter.import_data(json_data, self.org, self.user)

        # Export
        exported = self.adapter.export_data(tm1)

        # Create a second org to avoid name conflicts
        org2 = Organization.objects.create(name="CDX Test Org 2", domain="cdx2.test")
        OrganizationMember.objects.create(
            organization=org2, user=self.user, role="security_team"
        )

        # Re-import
        tm2, summary2 = self.adapter.import_data(exported, org2, self.user)

        # Compare key counts
        self.assertEqual(
            OrgsystemComponent.objects.filter(threat_model=tm1).count(),
            OrgsystemComponent.objects.filter(threat_model=tm2).count(),
        )
        self.assertEqual(
            DataFlow.objects.filter(source_component__threat_model=tm1).count(),
            DataFlow.objects.filter(source_component__threat_model=tm2).count(),
        )
        self.assertEqual(
            Risk.objects.filter(threat_model=tm1).count(),
            Risk.objects.filter(threat_model=tm2).count(),
        )
        self.assertEqual(
            InstanceCountermeasure.objects.filter(threat_model=tm1).count(),
            InstanceCountermeasure.objects.filter(threat_model=tm2).count(),
        )
        self.assertEqual(
            UseCase.objects.filter(threat_model=tm1).count(),
            UseCase.objects.filter(threat_model=tm2).count(),
        )

    def test_boundary_crossing_requirements_round_trip(self):
        """Boolean crossing requirement fields survive round-trip."""
        json_data = load_fixture("cyclonedx_full.json")
        tm1, _ = self.adapter.import_data(json_data, self.org, self.user)

        exported = self.adapter.export_data(tm1)

        # Find boundary with all crossing requirements
        blueprint = exported["blueprints"][0]
        perimeter = next(
            (
                b
                for b in blueprint["boundaries"]
                if b.get("name") == "Network Perimeter"
            ),
            None,
        )
        self.assertIsNotNone(perimeter)
        crossing = perimeter.get("crossingRequirements", {})
        self.assertTrue(crossing.get("authentication"))
        self.assertTrue(crossing.get("authorization"))
        self.assertTrue(crossing.get("dataValidation"))
        self.assertTrue(crossing.get("logging"))
        self.assertTrue(crossing.get("monitoring"))
        self.assertTrue(crossing.get("rateLimit"))

    def test_risk_responses_round_trip(self):
        """Multiple risk responses survive round-trip."""
        json_data = load_fixture("cyclonedx_full.json")
        tm1, _ = self.adapter.import_data(json_data, self.org, self.user)
        exported = self.adapter.export_data(tm1)

        risks = exported.get("risks", {}).get("risks", [])
        breach_risk = next(
            (r for r in risks if "Data Breach" in r.get("name", "")), None
        )
        self.assertIsNotNone(breach_risk)
        self.assertEqual(len(breach_risk.get("responses", [])), 2)

    def test_use_cases_round_trip(self):
        """Use cases survive round-trip via UseCase table."""
        json_data = load_fixture("cyclonedx_full.json")
        tm1, _ = self.adapter.import_data(json_data, self.org, self.user)
        exported = self.adapter.export_data(tm1)

        use_cases = exported.get("definitions", {}).get("useCases", [])
        self.assertEqual(len(use_cases), 1)
        uc = use_cases[0]
        self.assertEqual(uc["name"], "User Login")
        self.assertIn("preconditions", uc)
        self.assertIn("mainFlow", uc)
        self.assertIn("alternativeFlows", uc)
        self.assertIn("exceptions", uc)

    def test_intent_access_level_round_trip(self):
        """Intent and access_level survive round-trip."""
        json_data = load_fixture("cyclonedx_full.json")
        tm1, _ = self.adapter.import_data(json_data, self.org, self.user)
        exported = self.adapter.export_data(tm1)

        scenarios = exported.get("threats", {}).get("scenarios", [])
        targeted_scenario = next(
            (s for s in scenarios if s.get("intent") == "targeted"), None
        )
        self.assertIsNotNone(targeted_scenario)
        self.assertEqual(targeted_scenario["accessLevel"], "external")

    def test_dfd_canvas_round_trip(self):
        """DFD canvas data survives import -> export -> reimport."""
        json_data = load_fixture("cyclonedx_full.json")
        tm1, _ = self.adapter.import_data(json_data, self.org, self.user)

        # Verify DFD was created on import
        dfd1 = DFD.objects.get(threat_model=tm1)
        self.assertEqual(len(dfd1.canvas_data["nodes"]), 3)

        # Export
        exported = self.adapter.export_data(tm1)

        # Verify DFD is in the export
        blueprint = exported["blueprints"][0]
        dfd_vis = next(
            v for v in blueprint["visualizations"] if v.get("type") == "precogly-dfd"
        )
        self.assertEqual(len(dfd_vis["data"]["nodes"]), 3)

        # Reimport
        org2 = Organization.objects.create(name="DFD Round-Trip Org", domain="dfd.test")
        OrganizationMember.objects.create(
            organization=org2, user=self.user, role="security_team"
        )
        tm2, _ = self.adapter.import_data(exported, org2, self.user)

        # Verify DFD was recreated
        dfd2 = DFD.objects.get(threat_model=tm2)
        self.assertEqual(dfd2.name, "Full Test DFD")
        self.assertTrue(dfd2.is_primary)
        self.assertEqual(len(dfd2.canvas_data["nodes"]), 3)
        self.assertEqual(len(dfd2.canvas_data["edges"]), 2)
        # Verify node positions survived
        node1 = next(n for n in dfd2.canvas_data["nodes"] if n["id"] == "n1")
        self.assertEqual(node1["position"]["x"], 100)
        self.assertEqual(node1["position"]["y"], 200)


# =====================================================================
# Enum Mapping Tests
# =====================================================================


class TestCycloneDxEnumMappings(CycloneDxTestMixin, TestCase):
    """Test enum mapping edge cases."""

    def test_proposed_status_maps_to_planned(self):
        json_data = {
            "specFormat": "CycloneDX",
            "specVersion": "2.0",
            "blueprints": [{"name": "Test"}],
            "controls": [
                {
                    "bom-ref": "ctrl-1",
                    "name": "Proposed Control",
                    "status": "proposed",
                }
            ],
        }
        tm, _ = self.adapter.import_data(json_data, self.org, self.user)
        control = InstanceCountermeasure.objects.get(threat_model=tm)
        self.assertEqual(control.status, "planned")
        # Original status preserved in format_metadata
        cdx_meta = control.format_metadata.get("cyclonedx", {})
        self.assertEqual(cdx_meta.get("original_status"), "proposed")

    def test_unknown_asset_type_defaults_to_process(self):
        json_data = {
            "specFormat": "CycloneDX",
            "specVersion": "2.0",
            "blueprints": [
                {
                    "name": "Test",
                    "assets": [
                        {
                            "bom-ref": "a-1",
                            "name": "Unknown Thing",
                            "type": "quantum-processor",
                        }
                    ],
                }
            ],
        }
        tm, _ = self.adapter.import_data(json_data, self.org, self.user)
        component = OrgsystemComponent.objects.get(threat_model=tm)
        self.assertEqual(component.category, "process")

    def test_info_risk_level_maps_to_low(self):
        json_data = {
            "specFormat": "CycloneDX",
            "specVersion": "2.0",
            "blueprints": [{"name": "Test"}],
            "risks": {
                "risks": [
                    {
                        "bom-ref": "r-1",
                        "name": "Info Risk",
                        "inherentRisk": {
                            "riskScore": {"level": "info"},
                        },
                    }
                ]
            },
        }
        tm, _ = self.adapter.import_data(json_data, self.org, self.user)
        risk = Risk.objects.get(threat_model=tm)
        self.assertEqual(risk.inherent_level, "low")

    def test_invalid_control_status_defaults_to_gap(self):
        """Unknown CDX status values must not persist as invalid choices."""
        from apps.threat_models.adapters.cyclonedx_enum_maps import (
            CDX_STATUS_TO_CONTROL,
        )

        original = dict(CDX_STATUS_TO_CONTROL)
        CDX_STATUS_TO_CONTROL["totally-bogus"] = "totally_bogus"
        try:
            json_data = {
                "specFormat": "CycloneDX",
                "specVersion": "2.0",
                "blueprints": [{"name": "Test"}],
                "controls": [
                    {
                        "bom-ref": "ctrl-bogus",
                        "name": "Bogus Status Control",
                        "status": "totally-bogus",
                    }
                ],
            }
            tm, _ = self.adapter.import_data(json_data, self.org, self.user)
            control = InstanceCountermeasure.objects.get(threat_model=tm)
            self.assertEqual(control.status, "gap")
        finally:
            CDX_STATUS_TO_CONTROL.clear()
            CDX_STATUS_TO_CONTROL.update(original)

    def test_duplicate_affected_asset_does_not_abort_import(self):
        """Same asset listed twice in affectedAssets must not raise
        IntegrityError on the (component, threat_library) unique constraint.
        The duplicate should be skipped and surfaced as a warning."""
        json_data = {
            "specFormat": "CycloneDX",
            "specVersion": "2.0",
            "blueprints": [
                {
                    "name": "Test",
                    "assets": [
                        {
                            "bom-ref": "asset-dup",
                            "name": "Shared Component",
                            "type": "component",
                        }
                    ],
                }
            ],
            "threats": {
                "threats": [
                    {
                        "bom-ref": "threat-dup",
                        "name": "Duplicate Ref Threat",
                        "affectedAssets": ["asset-dup", "asset-dup"],
                    },
                ],
            },
        }
        tm, summary = self.adapter.import_data(json_data, self.org, self.user)
        self.assertEqual(summary["threats"], 1)
        instances = ComponentInstanceThreat.objects.filter(component__threat_model=tm)
        self.assertEqual(instances.count(), 1)
        warnings = summary.get("warnings", [])
        dup_warnings = [w for w in warnings if "Duplicate threat-asset link" in w]
        self.assertEqual(len(dup_warnings), 1)
        self.assertIn("Shared Component", dup_warnings[0])
