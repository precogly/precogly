"""Every seeded model exports as a valid TM-BOM (plan 9.10 item 1, F35).

The seed command runs once against the test database. Each sample model,
the OT one included, then exports with zero schema and ref errors, and the
OT export carries what the OT template was converted for: a network zone
nested under another, a signal flow, a control flow, a device asset and a
boundary. A second seed run changes nothing, which is the idempotency the
seed promises.
"""

from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from apps.core.management.commands.seed import (
    DEMO_ORG_NAME,
    SAMPLE_THREAT_MODELS,
    SECOND_ORG_THREAT_MODELS,
)
from apps.diagrams.models import DFD
from apps.systems.models import Boundary, Flow, Zone
from apps.threat_models.models import ThreatModel
from apps.threat_models.tmbom import TmBomAdapter
from apps.threat_models.tmbom.testing import assert_valid_tmbom

OT_SAMPLE_NAME = "Sample LNG Process Control"


def run_seed() -> None:
    call_command("seed", stdout=StringIO(), stderr=StringIO())


class SeededModelsExportTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        run_seed()

    def test_seed_builds_every_sample_model(self):
        expected_names = {sample["name"] for sample in SAMPLE_THREAT_MODELS} | {
            sample["name"] for sample in SECOND_ORG_THREAT_MODELS
        }
        self.assertEqual(
            set(ThreatModel.objects.values_list("name", flat=True)), expected_names
        )
        self.assertIn(OT_SAMPLE_NAME, expected_names)

    def test_every_seeded_model_exports_with_zero_errors(self):
        for threat_model in ThreatModel.objects.order_by("id"):
            document = TmBomAdapter().export_data(threat_model)
            assert_valid_tmbom(document, context=threat_model.name)

    def test_ot_sample_export_has_network_zone_signal_flow_device_and_boundary(self):
        threat_model = ThreatModel.objects.get(
            name=OT_SAMPLE_NAME, organization__name=DEMO_ORG_NAME
        )
        document = TmBomAdapter().export_data(threat_model)
        blueprint = document["blueprints"][0]

        zone_types = {zone["type"] for zone in blueprint["zones"]}
        self.assertIn("network", zone_types)
        nested_zones = [zone for zone in blueprint["zones"] if zone.get("parent")]
        self.assertTrue(nested_zones, "the Purdue zones should nest under a parent")
        trust_levels = [
            prop["value"]
            for zone in blueprint["zones"]
            for prop in zone.get("properties", [])
            if prop["name"] == "precogly:trust-level"
        ]
        self.assertTrue(trust_levels, "the OT zones should export trust levels")

        flow_types = {flow["type"] for flow in blueprint["flows"]}
        self.assertIn("signal", flow_types)
        self.assertIn("control", flow_types)

        asset_types = {asset["type"] for asset in blueprint["assets"]}
        self.assertIn("device", asset_types)

        self.assertTrue(blueprint["boundaries"])
        boundary = blueprint["boundaries"][0]
        self.assertEqual(boundary["type"], "network")
        self.assertEqual(
            boundary["crossingRequirements"]["authentication"], ["certificate"]
        )

    def test_ot_sample_rows_match_the_template(self):
        threat_model = ThreatModel.objects.get(
            name=OT_SAMPLE_NAME, organization__name=DEMO_ORG_NAME
        )
        blueprint = threat_model.default_blueprint
        self.assertEqual(
            Zone.objects.filter(blueprint=blueprint, zone_type="network").count(), 5
        )
        self.assertEqual(
            Zone.objects.filter(blueprint=blueprint, parent__isnull=False).count(), 2
        )
        self.assertEqual(
            Flow.objects.filter(blueprint=blueprint, flow_type="signal").count(), 3
        )
        self.assertEqual(
            Flow.objects.filter(blueprint=blueprint, flow_type="control").count(), 1
        )
        boundary = Boundary.objects.get(blueprint=blueprint)
        self.assertEqual(boundary.boundary_type, "network")
        self.assertTrue(boundary.requires_authentication)
        # The historian sits in the DMZ and the SCADA server in the operations
        # network, so the archival flow crosses the conduit.
        crossing = Flow.objects.filter(blueprint=blueprint, crosses_boundary=True)
        self.assertTrue(crossing.exists())

    def test_second_seed_run_changes_nothing(self):
        before = (
            ThreatModel.objects.count(),
            DFD.objects.count(),
            Zone.objects.count(),
            Flow.objects.count(),
            Boundary.objects.count(),
        )
        run_seed()
        after = (
            ThreatModel.objects.count(),
            DFD.objects.count(),
            Zone.objects.count(),
            Flow.objects.count(),
            Boundary.objects.count(),
        )
        self.assertEqual(after, before)
