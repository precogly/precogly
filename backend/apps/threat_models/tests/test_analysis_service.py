"""The one threat analysis payload builder and its shared-audience allow-list."""

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.organizations.models import Organization
from apps.systems.models import Flow, OrgsystemComponent
from apps.threat_models.analysis_service import (
    SHARED,
    SHARED_COUNTERMEASURE_KEYS,
    SHARED_TARGET_KEYS,
    SHARED_THREAT_KEYS,
    build_threat_analysis,
)
from apps.threat_models.models import ThreatModel
from apps.threats.models import (
    CountermeasureThreatLink,
    InstanceCountermeasure,
    ThreatLibrary,
)
from apps.threats.services import create_instance_threat

User = get_user_model()

SIGNED_IN_ONLY_THREAT_KEYS = {
    "auto_generated",
    "library_mismatch",
    "decision_rationale",
    "display_order",
    "impact_description",
    "threat_actor_text",
    "actor_persona_id",
    "actor_persona_name",
    "intent",
    "access_level",
}
SIGNED_IN_ONLY_COUNTERMEASURE_KEYS = {
    "due_date",
    "external_ticket_url",
    "display_order",
    "implemented_by",
    "implemented_by_party",
    "source",
    "auto_generated",
    "also_mitigates",
}


class AnalysisPayloadTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.threat_model = ThreatModel.objects.create(
            name="TM", organization=cls.organization
        )
        cls.library_threat = ThreatLibrary.objects.create(
            slug="sqli", name="SQL injection", description="Injected SQL"
        )
        cls.api = OrgsystemComponent.objects.create(
            blueprint=cls.threat_model.default_blueprint, name="API"
        )
        cls.database = OrgsystemComponent.objects.create(
            blueprint=cls.threat_model.default_blueprint,
            name="Database",
            category="datastore",
        )
        cls.flow = Flow.objects.create(
            blueprint=cls.api.blueprint,
            source_component=cls.api,
            dest_component=cls.database,
            label="Query",
        )
        cls.component_threat = create_instance_threat(
            cls.api.blueprint.threat_model,
            targets=[cls.api],
            threat_library=cls.library_threat,
            level="high",
            decision_rationale="internal note",
            impact_description="data loss",
            threat_actor_text="insider",
        )
        cls.flow_threat = create_instance_threat(
            cls.flow.blueprint.threat_model,
            targets=[cls.flow],
            threat_library=cls.library_threat,
            level="medium",
        )
        cls.countermeasure = InstanceCountermeasure.objects.create(
            threat_model=cls.threat_model,
            countermeasure_name="Parameterised queries",
            status="planned",
            external_ticket_url="https://tickets.example/1",
        )
        CountermeasureThreatLink.objects.create(
            countermeasure=cls.countermeasure, threat=cls.component_threat
        )
        CountermeasureThreatLink.objects.create(
            countermeasure=cls.countermeasure, threat=cls.flow_threat
        )


class SignedInPayloadTests(AnalysisPayloadTestCase):
    def test_lists_threats_with_their_targets_placed_on_the_canvas(self):
        payload = build_threat_analysis(self.threat_model)

        self.assertEqual(payload["threat_model_id"], str(self.threat_model.id))
        self.assertEqual(payload["total_count"], 2)
        by_target_type = {
            threat["targets"][0]["type"]: threat for threat in payload["threats"]
        }
        self.assertEqual(set(by_target_type), {"component", "flow"})

        component_threat = by_target_type["component"]
        self.assertEqual(component_threat["display_number"], "T1")
        self.assertFalse(component_threat["whole_system"])
        self.assertEqual(component_threat["threat_name"], "SQL injection")
        self.assertEqual(component_threat["decision_rationale"], "internal note")
        component_target = component_threat["targets"][0]
        self.assertEqual(component_target["id"], self.api.id)
        self.assertEqual(component_target["name"], "API")
        self.assertEqual(component_target["node_id"], f"analysis-{self.api.id}")
        self.assertIsNone(component_target["edge_id"])

        flow_threat = by_target_type["flow"]
        self.assertEqual(flow_threat["display_number"], "T2")
        flow_target = flow_threat["targets"][0]
        self.assertEqual(flow_target["id"], self.flow.id)
        self.assertEqual(flow_target["name"], "Query")
        self.assertEqual(flow_target["edge_id"], f"analysis-flow-{self.flow.id}")
        self.assertIsNone(flow_target["node_id"])

        self.assertIn(f"analysis-{self.api.id}", payload["node_component_map"])
        self.assertIn(f"analysis-flow-{self.flow.id}", payload["edge_flow_map"])

    def test_countermeasure_carries_its_other_threats(self):
        payload = build_threat_analysis(self.threat_model)
        component_threat = next(
            t for t in payload["threats"] if t["targets"][0]["type"] == "component"
        )
        countermeasure = component_threat["countermeasures"][0]
        self.assertEqual(countermeasure["countermeasure_name"], "Parameterised queries")
        self.assertEqual(
            countermeasure["external_ticket_url"], "https://tickets.example/1"
        )
        self.assertFalse(countermeasure["auto_generated"])
        self.assertEqual(len(countermeasure["also_mitigates"]), 1)
        other = countermeasure["also_mitigates"][0]
        self.assertEqual(other["display_number"], "T2")
        self.assertEqual(other["targets"][0]["type"], "flow")
        self.assertEqual(other["targets"][0]["name"], "Query")


class SharedPayloadTests(AnalysisPayloadTestCase):
    def test_shared_threat_keys_are_exactly_the_allow_list(self):
        payload = build_threat_analysis(self.threat_model, audience=SHARED)
        self.assertEqual(len(payload["threats"]), 2)
        for threat in payload["threats"]:
            self.assertEqual(set(threat), SHARED_THREAT_KEYS)
            self.assertFalse(set(threat) & SIGNED_IN_ONLY_THREAT_KEYS)
            for target in threat["targets"]:
                self.assertEqual(set(target), SHARED_TARGET_KEYS)

    def test_shared_countermeasure_keys_are_exactly_the_allow_list(self):
        payload = build_threat_analysis(self.threat_model, audience=SHARED)
        for threat in payload["threats"]:
            for countermeasure in threat["countermeasures"]:
                self.assertEqual(set(countermeasure), SHARED_COUNTERMEASURE_KEYS)
                self.assertFalse(
                    set(countermeasure) & SIGNED_IN_ONLY_COUNTERMEASURE_KEYS
                )

    def test_unknown_audience_is_refused(self):
        with self.assertRaises(ValueError):
            build_threat_analysis(self.threat_model, audience="public")
