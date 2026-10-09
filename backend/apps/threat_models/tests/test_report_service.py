"""Baseline for the report payload before the model rewrite (plan step 0).

Each section is pinned at the level a report reader depends on: which keys
exist, how threats are grouped, what the summary counts. The later steps
rewrite these builders and update this file with them.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.organizations.models import Organization, Team
from apps.systems.models import Boundary, Flow, OrgsystemComponent, Zone
from apps.threat_models.models import Assumption, OutOfScopeItem, ThreatModel
from apps.threat_models.report_service import build_report_data
from apps.threats.models import (
    CountermeasureThreatLink,
    ExternalTaxonomy,
    InstanceCountermeasure,
    TaxonomyEntry,
    ThreatLibrary,
    ThreatLibraryTaxonomyEntry,
)
from apps.threats.services import create_instance_threat, create_risk

User = get_user_model()


class ReportServiceTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="owner", email="owner@org.test", password="x"
        )
        cls.team = Team.objects.create(organization=cls.organization, name="Core")
        cls.threat_model = ThreatModel.objects.create(
            name="Payments",
            description="Card capture",
            organization=cls.organization,
            owning_team=cls.team,
            created_by=cls.user,
        )
        Assumption.objects.create(
            blueprint=cls.threat_model.default_blueprint,
            description="TLS everywhere",
            validity="verified",
        )
        OutOfScopeItem.objects.create(
            blueprint=cls.threat_model.default_blueprint,
            name="Mainframe",
            reason="Separate model",
        )

        blueprint = cls.threat_model.default_blueprint
        cls.internal = Zone.objects.create(
            blueprint=blueprint, name="Internal", trust_level=70
        )
        cls.dmz = Zone.objects.create(blueprint=blueprint, name="DMZ", trust_level=30)
        Boundary.objects.create(
            blueprint=blueprint,
            zone_a=cls.dmz,
            zone_b=cls.internal,
            label="Edge",
        )

        cls.api = OrgsystemComponent.objects.create(
            blueprint=cls.threat_model.default_blueprint, name="API", zone=cls.dmz
        )
        cls.database = OrgsystemComponent.objects.create(
            blueprint=cls.threat_model.default_blueprint,
            name="Database",
            category="datastore",
            zone=cls.internal,
        )
        cls.customer = OrgsystemComponent.objects.create(
            blueprint=cls.threat_model.default_blueprint,
            name="Customer",
            category="external_human_actor",
        )
        cls.flow = Flow.objects.create(
            blueprint=cls.api.blueprint,
            source_component=cls.api,
            dest_component=cls.database,
            label="Query",
            protocol="TLS",
            encrypted=True,
        )

        stride = ExternalTaxonomy.objects.create(slug="stride", name="STRIDE")
        tampering = TaxonomyEntry.objects.create(
            taxonomy=stride, external_id="tampering", title="Tampering"
        )
        cls.library_threat = ThreatLibrary.objects.create(
            slug="sqli", name="SQL injection", description="Injected SQL"
        )
        ThreatLibraryTaxonomyEntry.objects.create(
            threat_library=cls.library_threat, taxonomy_entry=tampering
        )

        cls.component_threat = create_instance_threat(
            cls.api.blueprint.threat_model,
            targets=[cls.api],
            threat_library=cls.library_threat,
            level="high",
        )
        cls.flow_threat = create_instance_threat(
            cls.flow.blueprint.threat_model,
            targets=[cls.flow],
            threat_library=cls.library_threat,
            level="medium",
        )
        cls.accepted_threat = create_instance_threat(
            cls.database.blueprint.threat_model,
            targets=[cls.database],
            threat_name="Backup theft",
            level="low",
            triage_status="accept",
            decision_rationale="Backups are encrypted",
        )

        cls.gap = InstanceCountermeasure.objects.create(
            threat_model=cls.threat_model,
            countermeasure_name="Parameterised queries",
            status="gap",
            priority="high",
        )
        CountermeasureThreatLink.objects.create(
            countermeasure=cls.gap, threat=cls.component_threat
        )
        cls.waived = InstanceCountermeasure.objects.create(
            threat_model=cls.threat_model, countermeasure_name="WAF", status="waived"
        )
        CountermeasureThreatLink.objects.create(
            countermeasure=cls.waived, threat=cls.flow_threat
        )

        cls.risk = create_risk(
            cls.threat_model,
            name="Customer data exposure",
            rating_inputs={"likelihood": "likely", "impact": "major"},
            threat_ids=[cls.component_threat.id],
            owner=cls.user,
        )

    def setUp(self):
        self.report = build_report_data(self.threat_model)

    def test_top_level_sections(self):
        self.assertEqual(
            set(self.report),
            {
                "metadata",
                "scope",
                "architecture",
                "data_assets",
                "components",
                "flows",
                "threat_analysis",
                "countermeasure_summary",
                "risks",
                "compliance",
                "summary_metrics",
                "progress_checklist",
                "completion_status",
            },
        )

    def test_metadata_and_scope(self):
        metadata = self.report["metadata"]
        self.assertEqual(metadata["name"], "Payments")
        self.assertEqual(metadata["owning_team"], "Core")
        self.assertEqual(metadata["created_by"], "owner@org.test")

        scope = self.report["scope"]
        self.assertEqual(scope["assumptions"][0]["description"], "TLS everywhere")
        self.assertEqual(scope["out_of_scope_items"][0]["name"], "Mainframe")

    def test_architecture_lists_zones_and_boundaries_in_scope(self):
        architecture = self.report["architecture"]
        self.assertEqual(
            {zone["name"] for zone in architecture["zones"]}, {"Internal", "DMZ"}
        )
        self.assertEqual(architecture["boundaries"][0]["label"], "Edge")
        self.assertEqual(
            {
                architecture["boundaries"][0]["zone_a"],
                architecture["boundaries"][0]["zone_b"],
            },
            {"DMZ", "Internal"},
        )

    def test_components_are_grouped_by_category(self):
        components = self.report["components"]
        self.assertEqual([c["name"] for c in components["processes"]], ["API"])
        self.assertEqual([c["name"] for c in components["data_stores"]], ["Database"])
        self.assertEqual([c["name"] for c in components["human_actors"]], ["Customer"])
        self.assertEqual(components["processes"][0]["zone"], "DMZ")
        self.assertEqual(
            components["processes"][0]["kind"], "component"
        )  # no category set
        self.assertEqual(components["data_stores"][0]["kind"], "data-store")

    def test_flows(self):
        flows = self.report["flows"]
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["label"], "Query")
        self.assertEqual(flows[0]["source"], "API")
        self.assertEqual(flows[0]["destination"], "Database")
        self.assertTrue(flows[0]["encrypted"])

    def test_threat_analysis_lists_every_scenario_once_with_its_targets(self):
        analysis = self.report["threat_analysis"]
        self.assertEqual(analysis["stride_summary"], {"tampering": 2})
        by_target = {threat["targets"][0]: threat for threat in analysis["threats"]}
        self.assertEqual(set(by_target), {"API", "Query"})
        component_threat = by_target["API"]
        self.assertEqual(component_threat["threat_name"], "SQL injection")
        self.assertEqual(component_threat["stride_category"], "tampering")
        self.assertEqual(component_threat["countermeasures"][0]["status"], "gap")
        self.assertTrue(component_threat["display_number"].startswith("T"))
        self.assertFalse(component_threat["whole_system"])
        self.assertEqual(len(analysis["triaged_threats"]), 1)
        self.assertEqual(analysis["triaged_threats"][0]["threat_name"], "Backup theft")
        self.assertEqual(analysis["triaged_threats"][0]["triage_status"], "accept")

    def test_countermeasure_summary(self):
        summary = self.report["countermeasure_summary"]
        self.assertEqual(summary["status_breakdown"], {"gap": 1, "waived": 1})
        self.assertEqual(
            summary["gaps"][0]["countermeasure_name"], "Parameterised queries"
        )
        self.assertEqual(summary["gaps"][0]["targets"], ["API"])
        self.assertEqual(summary["waived"][0]["targets"], ["Query"])
        self.assertNotIn("inherited", summary)
        self.assertEqual(summary["unattached"], [])
        self.assertEqual(summary["gaps"][0]["control_number"], "C1")

    def test_risks_with_contributing_threats(self):
        risks = self.report["risks"]
        self.assertEqual(len(risks), 1)
        self.assertEqual(risks[0]["name"], "Customer data exposure")
        self.assertEqual(risks[0]["owner_email"], "owner@org.test")
        self.assertEqual(
            risks[0]["contributing_threats"][0]["threat_name"], "SQL injection"
        )

    def test_summary_metrics(self):
        metrics = self.report["summary_metrics"]
        self.assertEqual(metrics["total_active_threats"], 2)
        self.assertEqual(metrics["total_triaged_threats"], 1)
        self.assertEqual(metrics["threats_by_status"], {"exposed": 2})
        self.assertEqual(metrics["total_countermeasures"], 2)
        self.assertEqual(metrics["total_gaps"], 1)
        self.assertEqual(metrics["total_waived"], 1)
        self.assertEqual(metrics["total_risks"], 1)
        self.assertEqual(metrics["risks_by_level"], {"high": 1})

    def test_completion_status_counts_scope_from_rows(self):
        completion = self.report["completion_status"]
        by_id = {item["id"]: item for item in completion["system_definition"]}
        self.assertEqual(by_id["components_identified"]["count"], 3)
        self.assertEqual(by_id["trust_boundaries_identified"]["count"], 2)
        coverage = {item["id"]: item for item in completion["coverage"]}
        # Both the component threat and the flow threat count: scope is read
        # from the rows' blueprint keys, not from the primary canvas (F30).
        self.assertEqual(coverage["countermeasures_assigned"]["numerator"], 2)
        self.assertEqual(coverage["countermeasures_assigned"]["denominator"], 2)
