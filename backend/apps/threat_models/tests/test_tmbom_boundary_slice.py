"""The step 6 adapter slice: zone and boundary types, crossing requirements, trust boundaries."""

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import Boundary, OrgsystemComponent, Zone
from apps.threat_models.models import ThreatModel
from apps.threat_models.tmbom import TmBomAdapter
from apps.threat_models.tmbom.testing import assert_valid_tmbom
from apps.threats.services import create_instance_countermeasure, create_instance_threat

User = get_user_model()


def build_model(organization, user):
    threat_model = ThreatModel.objects.create(
        name="Payments", organization=organization, created_by=user
    )
    blueprint = threat_model.default_blueprint
    internet = Zone.objects.create(blueprint=blueprint, name="Internet", trust_level=10)
    dmz = Zone.objects.create(
        blueprint=blueprint, name="DMZ", zone_type="network", trust_level=40
    )
    core = Zone.objects.create(blueprint=blueprint, name="Core")
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
    Boundary.objects.create(
        blueprint=blueprint,
        zone_a=dmz,
        zone_b=core,
        label="Inner trust",
        boundary_type="trust",
    )
    OrgsystemComponent.objects.create(blueprint=blueprint, name="API", zone=dmz)
    threat = create_instance_threat(
        threat_model, targets=[edge], threat_name="Crossing"
    )
    control = create_instance_countermeasure(
        threat_model, countermeasure_name="WAF", targets=[edge]
    )
    return threat_model, edge, threat, control


class BoundarySliceTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="u", email="u@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )

    def test_export_carries_types_requirements_and_trust_boundaries(self):
        threat_model, *_ = build_model(self.organization, self.user)
        document = TmBomAdapter().export_data(threat_model)
        assert_valid_tmbom(document, context="step 6 export")
        first = document["blueprints"][0]
        zones = {z["name"]: z for z in first["zones"]}
        self.assertEqual(zones["DMZ"]["type"], "network")
        self.assertEqual(zones["DMZ"]["properties"][0]["value"], "40")
        self.assertNotIn("properties", zones["Core"])
        boundaries = {b["name"]: b for b in first["boundaries"]}
        requirements = boundaries["Edge"]["crossingRequirements"]
        self.assertEqual(requirements["authentication"], ["oauth2", {"name": "Badge"}])
        self.assertEqual(requirements["authorization"], ["rbac"])
        self.assertTrue(requirements["dataValidation"])
        self.assertNotIn("logging", requirements)
        self.assertEqual(requirements["rateLimit"], "100 rps")
        self.assertEqual(
            boundaries["Edge"]["sessionManagement"],
            {"accessTokenTtl": 900, "idleTimeout": 600},
        )
        self.assertEqual(boundaries["Inner"]["type"], "network")
        self.assertNotIn("crossingRequirements", boundaries["Inner"])

        trust_boundaries = {
            t["name"]: t for t in document["threats"]["trustBoundaries"]
        }
        self.assertEqual(set(trust_boundaries), {"Edge", "Inner trust"})
        self.assertEqual(trust_boundaries["Edge"]["trustLevel"], "untrusted")
        self.assertNotIn("trustLevel", trust_boundaries["Inner trust"])
        self.assertEqual(
            trust_boundaries["Edge"]["boundary"], boundaries["Edge"]["bom-ref"]
        )
        self.assertEqual(
            trust_boundaries["Edge"]["threatsAtBoundary"],
            [document["threats"]["scenarios"][0]["bom-ref"]],
        )
        self.assertEqual(
            trust_boundaries["Edge"]["controlsAtBoundary"],
            [document["controls"][0]["bom-ref"]],
        )

    def test_round_trip(self):
        threat_model, *_ = build_model(self.organization, self.user)
        adapter = TmBomAdapter()
        document = adapter.export_data(threat_model)
        imported, summary = adapter.import_data(document, self.organization, self.user)
        self.assertNotIn("warnings", summary)
        blueprint = imported.default_blueprint
        dmz = blueprint.zones.get(name="DMZ")
        self.assertEqual((dmz.zone_type, dmz.trust_level), ("network", 40))
        self.assertIsNone(blueprint.zones.get(name="Core").trust_level)
        edge = blueprint.boundaries.get(label="Edge")
        self.assertEqual(edge.authentication, ["oauth2", "Badge"])
        self.assertEqual(edge.authorization, ["rbac"])
        self.assertTrue(edge.data_validation)
        self.assertFalse(edge.logging)
        self.assertEqual(edge.rate_limit, "100 rps")
        self.assertEqual(edge.protocols, ["https"])
        self.assertEqual(
            edge.session_management, {"accessTokenTtl": 900, "idleTimeout": 600}
        )
        self.assertEqual(blueprint.boundaries.filter(zone_a__name="DMZ").count(), 2)
        self.assertEqual(imported.threats.get().targets.get().target, edge)
        self.assertEqual(imported.countermeasures.get().targets.get().target, edge)
        again = adapter.export_data(imported)
        assert_valid_tmbom(again)
        self.assertEqual(len(again["threats"]["trustBoundaries"]), 2)

    def test_other_tools_custom_types_and_boundary_links(self):
        document = {
            "specFormat": "CycloneDX",
            "specVersion": "2.0",
            "blueprints": [
                {
                    "name": "Other",
                    "modelTypes": ["data-flow"],
                    "zones": [
                        {
                            "bom-ref": "z1",
                            "name": "A",
                            "type": {"name": "blast-radius"},
                        },
                        {"bom-ref": "z2", "name": "B", "type": "trust"},
                        {"bom-ref": "z3", "name": "C", "type": "trust"},
                    ],
                    "boundaries": [
                        {
                            "bom-ref": "b1",
                            "name": "Tri",
                            "type": "trust",
                            "zones": ["z1", "z2", "z3"],
                            "crossingRequirements": {
                                "authentication": ["none", "basic"]
                            },
                        }
                    ],
                    "assets": [{"bom-ref": "a1", "name": "App", "type": "service"}],
                }
            ],
            "threats": {
                "threats": [{"bom-ref": "t1", "name": "Spoof"}],
                "scenarios": [
                    {
                        "bom-ref": "s1",
                        "name": "S",
                        "threats": ["t1"],
                        "affectedAssets": ["a1"],
                    }
                ],
                "trustBoundaries": [
                    {
                        "bom-ref": "tb1",
                        "boundary": "b1",
                        "threatsAtBoundary": ["s1"],
                        "controlsAtBoundary": ["c1"],
                    }
                ],
            },
            "controls": [{"bom-ref": "c1", "name": "Gate", "status": "planned"}],
        }
        imported, summary = TmBomAdapter().import_data(
            document, self.organization, self.user
        )
        blueprint = imported.default_blueprint
        zone_a = blueprint.zones.get(name="A")
        self.assertEqual(zone_a.zone_type, "trust")
        self.assertEqual(
            zone_a.format_metadata["cyclonedx"]["custom_type"], {"name": "blast-radius"}
        )
        boundary = blueprint.boundaries.get()
        self.assertEqual(boundary.authentication, [])
        self.assertEqual(boundary.format_metadata["cyclonedx"]["extra_zones"], ["z3"])
        self.assertEqual(
            [r.target_kind for r in imported.threats.get().targets.all()],
            ["component", "boundary"],
        )
        self.assertEqual(imported.countermeasures.get().targets.get().target, boundary)
        warnings = "\n".join(summary["warnings"])
        self.assertIn("blast-radius", warnings)
        self.assertIn("none", warnings)
        again = TmBomAdapter().export_data(imported)
        assert_valid_tmbom(again)
        zone = next(z for z in again["blueprints"][0]["zones"] if z["name"] == "A")
        self.assertEqual(zone["type"], {"name": "blast-radius"})
        self.assertEqual(again["blueprints"][0]["boundaries"][0]["zones"][2], "z3")
