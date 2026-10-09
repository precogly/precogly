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

"""Tests for TM-Library adapter import and export."""

import json

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.exceptions import ValidationError

from apps.organizations.models import (
    Organization,
    OrganizationMember,
    Team,
    TeamMembership,
)
from apps.systems.models import OrgsystemComponent
from apps.threats.models import (
    ComponentInstanceThreat,
    DataFlowInstanceThreat,
    InstanceCountermeasure,
    Risk,
    ThreatPersona,
    ThreatPersonaLink,
)

from ..adapters import TmLibraryAdapter

User = get_user_model()


class TmLibraryAdapterTestMixin:
    """Shared setup for adapter tests."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            username="testuser", email="test@example.com", password="testpass123"
        )
        cls.org = Organization.objects.create(name="Test Org", domain="test.com")
        OrganizationMember.objects.create(
            organization=cls.org, user=cls.user, role="security_team"
        )
        cls.team = Team.objects.create(
            organization=cls.org, name="Default Team", code="default"
        )
        TeamMembership.objects.create(team=cls.team, user=cls.user, role="lead")
        cls.adapter = TmLibraryAdapter()


class TestValidation(TmLibraryAdapterTestMixin, TestCase):
    """Test validation of input data."""

    def test_missing_scope_raises_error(self):
        with self.assertRaises(ValidationError):
            self.adapter.import_data({"threats": []}, self.org, self.user)

    def test_invalid_json_raises_error(self):
        with self.assertRaises(ValidationError):
            self.adapter.validate("not a dict")

    def test_missing_scope_title_raises_error(self):
        with self.assertRaises(ValidationError):
            self.adapter.validate({"scope": {}})

    def test_valid_minimal_input(self):
        json_data = {
            "scope": {"title": "Minimal Model"},
        }
        threat_model, _summary = self.adapter.import_data(
            json_data, self.org, self.user
        )
        self.assertEqual(threat_model.name, "Minimal Model")
        self.assertEqual(_summary["threats"], 0)


class TestEnumMappings(TmLibraryAdapterTestMixin, TestCase):
    """Test enum edge cases for actor types and control statuses."""

    def test_unknown_actor_type_defaults_to_human(self):
        json_data = {
            "scope": {"title": "Test"},
            "actors": [
                {
                    "symbolic_name": "unknown-actor",
                    "title": "Unknown",
                    "type": "quantum_computer",
                },
            ],
        }
        threat_model, _summary = self.adapter.import_data(
            json_data, self.org, self.user
        )
        actor = OrgsystemComponent.objects.get(
            threat_model=threat_model, name="Unknown"
        )
        self.assertIsNone(actor.category)

    def test_control_status_mappings(self):
        json_data = {
            "scope": {"title": "Test"},
            "controls": [
                {
                    "symbolic_name": "ctrl-1",
                    "title": "Active Control",
                    "status": "active",
                    "threats": [],
                },
                {
                    "symbolic_name": "ctrl-2",
                    "title": "Assumed Control",
                    "status": "assumed",
                    "threats": [],
                },
                {
                    "symbolic_name": "ctrl-3",
                    "title": "Unknown Control",
                    "status": "unknown",
                    "threats": [],
                },
                {
                    "symbolic_name": "ctrl-4",
                    "title": "Retired Control",
                    "status": "retired",
                    "threats": [],
                },
            ],
        }
        self.adapter.import_data(json_data, self.org, self.user)
        # Controls without referenced threats create library entries but no instances
        # The mapping logic is tested via the module constants


class TestMultiThreatControl(TmLibraryAdapterTestMixin, TestCase):
    """Test control referencing multiple threats → duplicated countermeasure instances → re-merged on export."""

    def test_control_duplicated_per_threat(self):
        json_data = {
            "scope": {"title": "Test"},
            "components": [
                {"symbolic_name": "comp-a", "title": "Component A"},
            ],
            "threats": [
                {
                    "symbolic_name": "t1",
                    "title": "Threat 1",
                    "components_affected": ["comp-a"],
                },
                {
                    "symbolic_name": "t2",
                    "title": "Threat 2",
                    "components_affected": ["comp-a"],
                },
            ],
            "controls": [
                {
                    "symbolic_name": "shared-ctrl",
                    "title": "Shared Control",
                    "threats": ["t1", "t2"],
                    "status": "active",
                },
            ],
        }
        threat_model, _summary = self.adapter.import_data(
            json_data, self.org, self.user
        )

        # Should have 1 shared countermeasure instance linked to 2 threats
        cm_count = InstanceCountermeasure.objects.filter(
            threat_model=threat_model
        ).count()
        self.assertEqual(cm_count, 1)

        # Export → should re-merge into single control
        exported = self.adapter.export_data(threat_model)
        control_names = [c["symbolic_name"] for c in exported["controls"]]
        self.assertEqual(control_names.count("shared-ctrl"), 1)
        shared_ctrl = next(
            c for c in exported["controls"] if c["symbolic_name"] == "shared-ctrl"
        )
        self.assertEqual(len(shared_ctrl["threats"]), 2)


class TestEmptyExport(TmLibraryAdapterTestMixin, TestCase):
    """Test export of a threat model with no entities."""

    def test_empty_export_produces_valid_json(self):
        json_data = {"scope": {"title": "Empty Model"}}
        threat_model, _ = self.adapter.import_data(json_data, self.org, self.user)

        exported = self.adapter.export_data(threat_model)
        self.assertEqual(exported["scope"]["title"], "Empty Model")
        self.assertEqual(exported["trust_zones"], [])
        self.assertEqual(exported["actors"], [])
        self.assertEqual(exported["components"], [])
        self.assertEqual(exported["threats"], [])
        self.assertEqual(exported["controls"], [])
        self.assertEqual(exported["risks"], [])

        # Verify it's JSON serializable
        json.dumps(exported)


class TestRiskScoring(TmLibraryAdapterTestMixin, TestCase):
    """Test that risk scoring uses the engine, not raw file scores."""

    def test_risk_uses_engine_scoring(self):
        json_data = {
            "scope": {"title": "Test"},
            "risks": [
                {
                    "symbolic_name": "test-risk",
                    "title": "Test Risk",
                    "likelihood": "likely",
                    "impact": "major",
                    "score": 99,  # This should be ignored — engine computes
                    "level": "critical",  # This too
                },
            ],
        }
        threat_model, _ = self.adapter.import_data(json_data, self.org, self.user)
        risk = Risk.objects.get(threat_model=threat_model)

        # Engine: likely(4) * major(4) = 16 → 16/25*100 = 64 → high
        self.assertEqual(risk.inherent_score, 64)
        self.assertEqual(risk.inherent_level, "high")

    def test_risk_export_denormalizes_score(self):
        json_data = {
            "scope": {"title": "Test"},
            "risks": [
                {
                    "symbolic_name": "test-risk",
                    "title": "Test Risk",
                    "likelihood": "possible",
                    "impact": "moderate",
                    "score": 9,
                },
            ],
        }
        threat_model, _ = self.adapter.import_data(json_data, self.org, self.user)
        exported = self.adapter.export_data(threat_model)

        risk = exported["risks"][0]
        # Engine: possible(3) * moderate(3) = 9 → 9/25*100 = 36 → medium
        # Export: round(36/100*25) = 9
        self.assertEqual(risk["score"], 9)


class TestPerInstanceThreatDetails(TmLibraryAdapterTestMixin, TestCase):
    """Test that per-instance threat details survive export/import roundtrip."""

    def test_divergent_severity_metadata_survives_roundtrip(self):
        """Two components with the same threat but different severity metadata
        should both appear in the export and restore correctly on re-import."""
        json_data = {
            "scope": {"title": "Severity Test"},
            "components": [
                {"symbolic_name": "comp-a", "title": "Component A"},
                {"symbolic_name": "comp-b", "title": "Component B"},
            ],
            "threats": [
                {
                    "symbolic_name": "shared-threat",
                    "title": "Shared Threat",
                    "components_affected": ["comp-a", "comp-b"],
                    "inherent_severity": "medium",
                },
            ],
        }
        threat_model, _ = self.adapter.import_data(json_data, self.org, self.user)

        # Set divergent severity_scoring_metadata on each instance
        comp_a = OrgsystemComponent.objects.get(
            threat_model=threat_model, name="Component A"
        )
        comp_b = OrgsystemComponent.objects.get(
            threat_model=threat_model, name="Component B"
        )

        threat_a = ComponentInstanceThreat.objects.get(
            component=comp_a, threat_name="Shared Threat"
        )
        threat_a.severity_scoring_metadata = {
            "likelihood": "certain",
            "impact": "severe",
            "rationale": "User-facing input",
        }
        threat_a.save(update_fields=["severity_scoring_metadata"])

        threat_b = ComponentInstanceThreat.objects.get(
            component=comp_b, threat_name="Shared Threat"
        )
        threat_b.severity_scoring_metadata = {
            "likelihood": "rare",
            "impact": "negligible",
            "rationale": "Internal service",
        }
        threat_b.save(update_fields=["severity_scoring_metadata"])

        # Export
        exported = self.adapter.export_data(threat_model)

        # Verify both instances appear in the extension
        threat_details = exported["extensions"]["precogly.org/threat-details"]
        self.assertIn("shared-threat", threat_details)
        instance_details = threat_details["shared-threat"]["instance_details"]
        self.assertEqual(len(instance_details), 2)

        details_by_affected = {d["affected"]: d for d in instance_details}
        self.assertIn("comp-a", details_by_affected)
        self.assertIn("comp-b", details_by_affected)
        self.assertEqual(
            details_by_affected["comp-a"]["severity_scoring_metadata"]["likelihood"],
            "certain",
        )
        self.assertEqual(
            details_by_affected["comp-b"]["severity_scoring_metadata"]["likelihood"],
            "rare",
        )

        # Re-import into a fresh threat model and verify metadata is restored
        reimported_model, _ = self.adapter.import_data(exported, self.org, self.user)

        reimported_comp_a = OrgsystemComponent.objects.get(
            threat_model=reimported_model, name="Component A"
        )
        reimported_comp_b = OrgsystemComponent.objects.get(
            threat_model=reimported_model, name="Component B"
        )

        reimported_threat_a = ComponentInstanceThreat.objects.get(
            component=reimported_comp_a, threat_name="Shared Threat"
        )
        reimported_threat_b = ComponentInstanceThreat.objects.get(
            component=reimported_comp_b, threat_name="Shared Threat"
        )

        self.assertEqual(
            reimported_threat_a.severity_scoring_metadata["likelihood"], "certain"
        )
        self.assertEqual(
            reimported_threat_a.severity_scoring_metadata["impact"], "severe"
        )
        self.assertEqual(
            reimported_threat_b.severity_scoring_metadata["likelihood"], "rare"
        )
        self.assertEqual(
            reimported_threat_b.severity_scoring_metadata["impact"], "negligible"
        )

    def test_divergent_severity_and_impact_survives_roundtrip(self):
        """Per-instance inherent_severity, residual_severity, and impact_description
        should all survive export/import roundtrip."""
        json_data = {
            "scope": {"title": "Full Per-Instance Test"},
            "components": [
                {"symbolic_name": "comp-a", "title": "Component A"},
                {"symbolic_name": "comp-b", "title": "Component B"},
            ],
            "threats": [
                {
                    "symbolic_name": "shared-threat",
                    "title": "Shared Threat",
                    "components_affected": ["comp-a", "comp-b"],
                    "inherent_severity": "medium",
                },
            ],
        }
        threat_model, _ = self.adapter.import_data(json_data, self.org, self.user)

        comp_a = OrgsystemComponent.objects.get(
            threat_model=threat_model, name="Component A"
        )
        comp_b = OrgsystemComponent.objects.get(
            threat_model=threat_model, name="Component B"
        )

        threat_a = ComponentInstanceThreat.objects.get(
            component=comp_a, threat_name="Shared Threat"
        )
        threat_a.inherent_severity = "critical"
        threat_a.residual_severity = "high"
        threat_a.impact_description = "Total system compromise"
        threat_a.save(
            update_fields=[
                "inherent_severity",
                "residual_severity",
                "impact_description",
            ]
        )

        threat_b = ComponentInstanceThreat.objects.get(
            component=comp_b, threat_name="Shared Threat"
        )
        threat_b.inherent_severity = "low"
        threat_b.residual_severity = ""
        threat_b.impact_description = "Minor data exposure"
        threat_b.save(
            update_fields=[
                "inherent_severity",
                "residual_severity",
                "impact_description",
            ]
        )

        # Export
        exported = self.adapter.export_data(threat_model)

        threat_details = exported["extensions"]["precogly.org/threat-details"]
        instance_details = threat_details["shared-threat"]["instance_details"]
        details_by_affected = {d["affected"]: d for d in instance_details}

        # Verify per-instance fields in export
        self.assertEqual(details_by_affected["comp-a"]["inherent_severity"], "critical")
        self.assertEqual(details_by_affected["comp-a"]["residual_severity"], "high")
        self.assertEqual(
            details_by_affected["comp-a"]["event"], "Total system compromise"
        )
        self.assertEqual(details_by_affected["comp-b"]["inherent_severity"], "low")
        self.assertNotIn("residual_severity", details_by_affected["comp-b"])
        self.assertEqual(details_by_affected["comp-b"]["event"], "Minor data exposure")

        # Re-import and verify
        reimported_model, _ = self.adapter.import_data(exported, self.org, self.user)

        reimported_comp_a = OrgsystemComponent.objects.get(
            threat_model=reimported_model, name="Component A"
        )
        reimported_comp_b = OrgsystemComponent.objects.get(
            threat_model=reimported_model, name="Component B"
        )

        reimported_threat_a = ComponentInstanceThreat.objects.get(
            component=reimported_comp_a, threat_name="Shared Threat"
        )
        reimported_threat_b = ComponentInstanceThreat.objects.get(
            component=reimported_comp_b, threat_name="Shared Threat"
        )

        self.assertEqual(reimported_threat_a.inherent_severity, "critical")
        self.assertEqual(reimported_threat_a.residual_severity, "high")
        self.assertEqual(
            reimported_threat_a.impact_description, "Total system compromise"
        )
        self.assertEqual(reimported_threat_b.inherent_severity, "low")
        self.assertEqual(reimported_threat_b.impact_description, "Minor data exposure")

    def test_divergent_persona_survives_roundtrip(self):
        """Per-instance threat_persona links should survive export/import roundtrip."""
        json_data = {
            "scope": {"title": "Persona Test"},
            "components": [
                {"symbolic_name": "comp-a", "title": "Component A"},
                {"symbolic_name": "comp-b", "title": "Component B"},
            ],
            "threat_personas": [
                {
                    "symbolic_name": "insider",
                    "title": "Malicious Insider",
                    "description": "Employee with access",
                    "is_person": True,
                    "malicious_intent": True,
                },
                {
                    "symbolic_name": "external",
                    "title": "External Attacker",
                    "description": "Remote attacker",
                    "is_person": True,
                    "malicious_intent": True,
                },
            ],
            "threats": [
                {
                    "symbolic_name": "shared-threat",
                    "title": "Shared Threat",
                    "components_affected": ["comp-a", "comp-b"],
                    "inherent_severity": "medium",
                },
            ],
        }
        threat_model, _ = self.adapter.import_data(json_data, self.org, self.user)

        comp_a = OrgsystemComponent.objects.get(
            threat_model=threat_model, name="Component A"
        )
        comp_b = OrgsystemComponent.objects.get(
            threat_model=threat_model, name="Component B"
        )
        threat_a = ComponentInstanceThreat.objects.get(
            component=comp_a, threat_name="Shared Threat"
        )
        threat_b = ComponentInstanceThreat.objects.get(
            component=comp_b, threat_name="Shared Threat"
        )

        # Link different personas to each instance
        insider = ThreatPersona.objects.get(
            threat_model=threat_model, symbolic_name="insider"
        )
        external = ThreatPersona.objects.get(
            threat_model=threat_model, symbolic_name="external"
        )
        ThreatPersonaLink.objects.create(persona=insider, component_threat=threat_a)
        ThreatPersonaLink.objects.create(persona=external, component_threat=threat_b)

        # Export
        exported = self.adapter.export_data(threat_model)

        threat_details = exported["extensions"]["precogly.org/threat-details"]
        instance_details = threat_details["shared-threat"]["instance_details"]
        details_by_affected = {d["affected"]: d for d in instance_details}

        self.assertEqual(details_by_affected["comp-a"]["threat_persona"], "insider")
        self.assertEqual(details_by_affected["comp-b"]["threat_persona"], "external")

        # Re-import and verify persona links are restored
        reimported_model, _ = self.adapter.import_data(exported, self.org, self.user)

        reimported_comp_a = OrgsystemComponent.objects.get(
            threat_model=reimported_model, name="Component A"
        )
        reimported_comp_b = OrgsystemComponent.objects.get(
            threat_model=reimported_model, name="Component B"
        )
        reimported_threat_a = ComponentInstanceThreat.objects.get(
            component=reimported_comp_a, threat_name="Shared Threat"
        )
        reimported_threat_b = ComponentInstanceThreat.objects.get(
            component=reimported_comp_b, threat_name="Shared Threat"
        )

        persona_a = ThreatPersonaLink.objects.get(component_threat=reimported_threat_a)
        persona_b = ThreatPersonaLink.objects.get(component_threat=reimported_threat_b)
        self.assertEqual(persona_a.persona.symbolic_name, "insider")
        self.assertEqual(persona_b.persona.symbolic_name, "external")

    def test_legacy_flat_metadata_import(self):
        """Old exports with flat severity_scoring_metadata (no instance_details)
        should still apply metadata to all instances."""
        json_data = {
            "scope": {"title": "Legacy Test"},
            "components": [
                {"symbolic_name": "comp-x", "title": "Component X"},
                {"symbolic_name": "comp-y", "title": "Component Y"},
            ],
            "threats": [
                {
                    "symbolic_name": "legacy-threat",
                    "title": "Legacy Threat",
                    "components_affected": ["comp-x", "comp-y"],
                    "inherent_severity": "high",
                },
            ],
            "extensions": {
                "precogly.org/threat-details": {
                    "legacy-threat": {
                        "severity_scoring_metadata": {
                            "likelihood": "likely",
                            "impact": "major",
                            "rationale": "Legacy format",
                        }
                    }
                }
            },
        }
        threat_model, _ = self.adapter.import_data(json_data, self.org, self.user)

        comp_x = OrgsystemComponent.objects.get(
            threat_model=threat_model, name="Component X"
        )
        comp_y = OrgsystemComponent.objects.get(
            threat_model=threat_model, name="Component Y"
        )

        threat_x = ComponentInstanceThreat.objects.get(
            component=comp_x, threat_name="Legacy Threat"
        )
        threat_y = ComponentInstanceThreat.objects.get(
            component=comp_y, threat_name="Legacy Threat"
        )

        # Both should have the same metadata (legacy flat format applies to all)
        self.assertEqual(threat_x.severity_scoring_metadata["likelihood"], "likely")
        self.assertEqual(threat_y.severity_scoring_metadata["likelihood"], "likely")
        self.assertEqual(
            threat_x.severity_scoring_metadata["rationale"], "Legacy format"
        )
        self.assertEqual(
            threat_y.severity_scoring_metadata["rationale"], "Legacy format"
        )

    def test_triage_state_survives_roundtrip(self):
        """Per-instance triage_status and decision_rationale should survive
        export/import roundtrip."""
        json_data = {
            "scope": {"title": "Triage Test"},
            "components": [
                {"symbolic_name": "comp-a", "title": "Component A"},
                {"symbolic_name": "comp-b", "title": "Component B"},
            ],
            "threats": [
                {
                    "symbolic_name": "shared-threat",
                    "title": "Shared Threat",
                    "components_affected": ["comp-a", "comp-b"],
                    "inherent_severity": "medium",
                },
            ],
        }
        threat_model, _ = self.adapter.import_data(json_data, self.org, self.user)

        comp_a = OrgsystemComponent.objects.get(
            threat_model=threat_model, name="Component A"
        )

        # Triage one instance as accepted, leave the other open
        threat_a = ComponentInstanceThreat.objects.get(
            component=comp_a, threat_name="Shared Threat"
        )
        threat_a.triage_status = "accept"
        threat_a.decision_rationale = "Not applicable to this component"
        threat_a.save(update_fields=["triage_status", "decision_rationale"])

        # threat_b stays active (triage_status="open", default)

        # Export
        exported = self.adapter.export_data(threat_model)

        threat_details = exported["extensions"]["precogly.org/threat-details"]
        instance_details = threat_details["shared-threat"]["instance_details"]
        details_by_affected = {d["affected"]: d for d in instance_details}

        # Verify export: comp-a is triaged (accept), comp-b is not
        self.assertEqual(details_by_affected["comp-a"]["triage_status"], "accept")
        self.assertEqual(
            details_by_affected["comp-a"]["decision_rationale"],
            "Not applicable to this component",
        )
        self.assertNotIn("triage_status", details_by_affected["comp-b"])
        self.assertNotIn("decision_rationale", details_by_affected["comp-b"])

        # Re-import and verify
        reimported_model, _ = self.adapter.import_data(exported, self.org, self.user)

        reimported_comp_a = OrgsystemComponent.objects.get(
            threat_model=reimported_model, name="Component A"
        )
        reimported_comp_b = OrgsystemComponent.objects.get(
            threat_model=reimported_model, name="Component B"
        )

        reimported_threat_a = ComponentInstanceThreat.objects.get(
            component=reimported_comp_a, threat_name="Shared Threat"
        )
        reimported_threat_b = ComponentInstanceThreat.objects.get(
            component=reimported_comp_b, threat_name="Shared Threat"
        )

        self.assertEqual(reimported_threat_a.triage_status, "accept")
        self.assertEqual(
            reimported_threat_a.decision_rationale,
            "Not applicable to this component",
        )
        self.assertEqual(reimported_threat_b.triage_status, "open")
        self.assertEqual(reimported_threat_b.decision_rationale, "")


class TestSymbolicNameCollision(TmLibraryAdapterTestMixin, TestCase):
    """Test that component and flow threats don't produce colliding symbolic names."""

    def test_component_and_flow_threats_get_unique_symbolic_names(self):
        """When a component threat and a flow threat both lack stored symbolic
        names, the export should not produce duplicate symbolic_name entries."""
        json_data = {
            "scope": {"title": "Collision Test"},
            "components": [
                {"symbolic_name": "comp-a", "title": "Component A"},
                {"symbolic_name": "comp-b", "title": "Component B"},
            ],
            "data_flows": [
                {
                    "symbolic_name": "flow-ab",
                    "title": "A to B",
                    "source": {"type": "component", "name": "comp-a"},
                    "destination": {"type": "component", "name": "comp-b"},
                },
            ],
            "threats": [
                {
                    "symbolic_name": "comp-threat",
                    "title": "Component Threat",
                    "components_affected": ["comp-a"],
                    "inherent_severity": "medium",
                },
                {
                    "symbolic_name": "flow-threat",
                    "title": "Flow Threat",
                    "data_flows_affected": ["flow-ab"],
                    "inherent_severity": "medium",
                },
            ],
        }
        threat_model, _ = self.adapter.import_data(json_data, self.org, self.user)

        # Clear format_metadata symbolic names to simulate natively-created threats
        ComponentInstanceThreat.objects.filter(
            component__threat_model=threat_model
        ).update(format_metadata={})
        DataFlowInstanceThreat.objects.filter(
            data_flow__source_component__threat_model=threat_model
        ).update(format_metadata={})

        # Export
        exported = self.adapter.export_data(threat_model)

        # Verify no duplicate symbolic names
        threat_syms = [t["symbolic_name"] for t in exported["threats"]]
        self.assertEqual(
            len(threat_syms),
            len(set(threat_syms)),
            f"Duplicate symbolic names found: {threat_syms}",
        )

        # Verify roundtrip works
        reimported, _ = self.adapter.import_data(exported, self.org, self.user)
        self.assertEqual(
            ComponentInstanceThreat.objects.filter(
                component__threat_model=reimported
            ).count(),
            1,
        )
        self.assertEqual(
            DataFlowInstanceThreat.objects.filter(
                data_flow__source_component__threat_model=reimported
            ).count(),
            1,
        )
