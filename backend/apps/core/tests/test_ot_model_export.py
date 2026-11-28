"""An OT model exports network zones, signal and control flows, devices and a boundary.

These tests ran on the seeded "Sample LNG Process Control" model until the seed
switched to the small demo packs, which have no OT content. They now build the
same model from a test-only pack (tests/fixtures/packs/ot-fixture: the LNG
template and the 12 components it uses), the way the seed builds a sample
model: import the pack, create the threat model, create its primary diagram from
the template, and sync it. The assertions are unchanged.
"""

from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.diagrams.canvas import normalize_canvas
from apps.diagrams.models import DFD, DFDTemplatesLibrary
from apps.diagrams.services import sync_dfd_nodes_to_components
from apps.organizations.models import Organization
from apps.packs.models import LibraryPack
from apps.packs.services import ImportResult, import_pack_from_path
from apps.systems.models import Boundary, Flow, Zone
from apps.threat_models.models import ThreatModel, ThreatModelLibraryPack
from apps.threat_models.tmbom import TmBomAdapter
from apps.threat_models.tmbom.testing import assert_valid_tmbom

User = get_user_model()

OT_FIXTURE_PACK = Path(__file__).resolve().parent / "fixtures" / "packs" / "ot-fixture"


class OtModelExportTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        result = import_pack_from_path(OT_FIXTURE_PACK)
        assert isinstance(result, ImportResult) and result.success, result

        organization = Organization.objects.create(name="Org", domain="org.test")
        user = User.objects.create_user(username="u", email="u@org.test", password="x")
        cls.threat_model = ThreatModel.objects.create(
            name="LNG Process Control", organization=organization, created_by=user
        )
        ThreatModelLibraryPack.objects.create(
            threat_model=cls.threat_model,
            library_pack=LibraryPack.objects.get(slug="ot-fixture"),
        )
        template = DFDTemplatesLibrary.objects.get(
            qualified_slug="ot-fixture/lng-process-control"
        )
        blueprint = cls.threat_model.default_blueprint
        dfd = DFD.objects.create(
            name="Data Flow Diagram 1",
            diagram_type=template.diagram_type,
            blueprint=blueprint,
            template_library=template,
            canvas_data=normalize_canvas(template.canvas_data),
            is_primary=True,
            updated_by=user,
        )
        sync_dfd_nodes_to_components(dfd, blueprint)

    def test_the_ot_model_exports_with_zero_errors(self):
        document = TmBomAdapter().export_data(self.threat_model)
        assert_valid_tmbom(document, context=self.threat_model.name)

    def test_ot_sample_export_has_network_zone_signal_flow_device_and_boundary(self):
        threat_model = self.threat_model
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
        threat_model = self.threat_model
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
