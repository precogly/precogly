"""The step 7 adapter slice: flow types, flow auth lists, flow properties, asset kinds."""

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import Flow, OrgsystemComponent
from apps.threat_models.models import ThreatModel
from apps.threat_models.tmbom import TmBomAdapter
from apps.threat_models.tmbom.testing import assert_valid_tmbom

User = get_user_model()


class FlowSliceTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="u", email="u@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        cls.threat_model = ThreatModel.objects.create(
            name="Plant", organization=cls.organization, created_by=cls.user
        )
        blueprint = cls.threat_model.default_blueprint
        sensor = OrgsystemComponent.objects.create(
            blueprint=blueprint, name="Sensor", category="process", kind="device"
        )
        plc = OrgsystemComponent.objects.create(
            blueprint=blueprint, name="PLC", category="process"
        )
        Flow.objects.create(
            blueprint=blueprint,
            source_component=sensor,
            dest_component=plc,
            label="4-20mA",
            flow_type="signal",
            authentication=["psk", "Badge"],
            authorization=["acl"],
            port=502,
            has_sensitive_data=True,
            data_classification=["telemetry"],
        )

    def test_round_trip(self):
        adapter = TmBomAdapter()
        document = adapter.export_data(self.threat_model)
        assert_valid_tmbom(document, context="step 7 export")
        first = document["blueprints"][0]
        assets = {a["name"]: a for a in first["assets"]}
        self.assertEqual(assets["Sensor"]["type"], "device")
        self.assertEqual(assets["PLC"]["type"], "process")
        flow = first["flows"][0]
        self.assertEqual(flow["type"], "signal")
        self.assertEqual(flow["authentication"], ["psk", {"name": "Badge"}])
        self.assertEqual(flow["authorization"], ["acl"])
        properties = {p["name"]: p["value"] for p in flow["properties"]}
        self.assertEqual(properties["precogly:port"], "502")
        self.assertEqual(properties["precogly:has-sensitive-data"], "true")
        self.assertEqual(properties["precogly:data-classification"], '["telemetry"]')

        imported, summary = adapter.import_data(document, self.organization, self.user)
        self.assertNotIn("warnings", summary)
        blueprint = imported.default_blueprint
        self.assertEqual(blueprint.components.get(name="Sensor").kind, "device")
        self.assertEqual(blueprint.components.get(name="PLC").kind, "process")
        back = blueprint.flows.get()
        self.assertEqual(back.flow_type, "signal")
        self.assertEqual(back.authentication, ["psk", "Badge"])
        self.assertEqual(back.authorization, ["acl"])
        self.assertEqual(
            (back.port, back.has_sensitive_data, back.data_classification),
            (502, True, ["telemetry"]),
        )

    def test_custom_flow_type_and_asset_type_are_kept(self):
        document = {
            "specFormat": "CycloneDX",
            "specVersion": "2.0",
            "blueprints": [
                {
                    "name": "Other",
                    "modelTypes": ["data-flow"],
                    "assets": [
                        {"bom-ref": "a1", "name": "Thing", "type": {"name": "widget"}},
                        {"bom-ref": "a2", "name": "Svc", "type": "service"},
                    ],
                    "flows": [
                        {
                            "bom-ref": "f1",
                            "name": "Beam",
                            "type": {"name": "laser"},
                            "source": "a1",
                            "destination": "a2",
                            "authentication": ["none", "psk"],
                        }
                    ],
                }
            ],
        }
        imported, summary = TmBomAdapter().import_data(
            document, self.organization, self.user
        )
        blueprint = imported.default_blueprint
        thing = blueprint.components.get(name="Thing")
        self.assertEqual((thing.kind, thing.effective_kind), ("", "process"))
        self.assertEqual(
            thing.format_metadata["cyclonedx"]["custom_type"], {"name": "widget"}
        )
        self.assertEqual(blueprint.components.get(name="Svc").kind, "service")
        flow = blueprint.flows.get()
        self.assertEqual(flow.flow_type, "data")
        self.assertEqual(flow.authentication, [])
        warnings = "\n".join(summary["warnings"])
        self.assertIn("widget", warnings)
        self.assertIn("laser", warnings)
        self.assertIn("none", warnings)
        again = TmBomAdapter().export_data(imported)
        assert_valid_tmbom(again)
        self.assertEqual(again["blueprints"][0]["flows"][0]["type"], {"name": "laser"})
        self.assertEqual(
            next(a for a in again["blueprints"][0]["assets"] if a["name"] == "Thing")[
                "type"
            ],
            {"name": "widget"},
        )
