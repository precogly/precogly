"""Adapter slices for steps 9 to 11: assumptions, business objectives, methodologies."""

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import OrgsystemComponent
from apps.threat_models.models import (
    Assumption,
    AssumptionComponent,
    BusinessObjective,
    ThreatModel,
)
from apps.threat_models.tmbom import TmBomAdapter
from apps.threat_models.tmbom.testing import assert_valid_tmbom
from apps.threats.services import (
    create_instance_threat,
    create_risk,
    set_risk_business_objectives,
    set_threat_business_objectives,
)

User = get_user_model()


class ContextSliceTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="u", email="u@org.test", password="x", first_name="Uma"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        cls.threat_model = ThreatModel.objects.create(
            name="Payments",
            organization=cls.organization,
            created_by=cls.user,
            methodologies=["STRIDE", "Our own"],
        )
        blueprint = cls.threat_model.default_blueprint
        api = OrgsystemComponent.objects.create(blueprint=blueprint, name="API")
        assumption = Assumption.objects.create(
            blueprint=blueprint,
            description="TLS everywhere",
            topic="security",
            validity="verified",
            impact="Eavesdropping is out of scope",
            owner=cls.user,
            validation_method="Config review",
        )
        AssumptionComponent.objects.create(assumption=assumption, component=api)
        Assumption.objects.create(
            blueprint=blueprint,
            description="Ops watches the logs",
            owner_name="Ops lead",
        )
        objective = BusinessObjective.objects.create(
            threat_model=cls.threat_model,
            name="Keep card data private",
            criticality="high",
            owner_name="CISO",
        )
        threat = create_instance_threat(
            cls.threat_model, targets=[api], threat_name="SQLi"
        )
        set_threat_business_objectives(threat, [objective])
        risk = create_risk(
            cls.threat_model, name="Leak", level="high", threat_ids=[threat.id]
        )
        set_risk_business_objectives(risk, [objective])

    def test_round_trip(self):
        adapter = TmBomAdapter()
        document = adapter.export_data(self.threat_model)
        assert_valid_tmbom(document, context="steps 9 to 11 export")
        first = document["blueprints"][0]
        assumptions = {a["description"]: a for a in first["assumptions"]}
        tls = assumptions["TLS everywhere"]
        self.assertEqual((tls["topic"], tls["validity"]), ("security", "verified"))
        self.assertEqual(tls["owner"], f"party-user-{self.user.pk}")
        self.assertEqual(tls["relatedAssets"], [first["assets"][0]["bom-ref"]])
        self.assertEqual(
            assumptions["Ops watches the logs"]["owner"]["person"]["name"], "Ops lead"
        )
        objective = document["definitions"]["businessObjectives"][0]
        self.assertEqual(
            (objective["name"], objective["criticality"]),
            ("Keep card data private", "high"),
        )
        self.assertEqual(
            document["threats"]["methodologies"], ["STRIDE", {"name": "Our own"}]
        )
        self.assertEqual(
            document["threats"]["threats"][0]["relatedBusinessObjectives"],
            [objective["bom-ref"]],
        )
        scenario_properties = {
            p["name"]: p["value"]
            for p in document["threats"]["scenarios"][0]["properties"]
        }
        self.assertIn(
            objective["bom-ref"], scenario_properties["precogly:business-objectives"]
        )
        self.assertEqual(
            document["risks"]["risks"][0]["relatedBusinessObjectives"],
            [objective["bom-ref"]],
        )

        imported, summary = adapter.import_data(document, self.organization, self.user)
        self.assertNotIn("warnings", summary)
        self.assertEqual(summary["assumptions"], 2)
        self.assertEqual(summary["business_objectives"], 1)
        self.assertEqual(imported.methodologies, ["STRIDE", "Our own"])
        blueprint = imported.default_blueprint
        back = blueprint.assumptions.get(description="TLS everywhere")
        self.assertEqual(
            (back.topic, back.validity, back.owner, back.validation_method),
            ("security", "verified", self.user, "Config review"),
        )
        self.assertEqual(back.component_links.get().component.name, "API")
        self.assertEqual(
            blueprint.assumptions.get(description="Ops watches the logs").owner_name,
            "Ops lead",
        )
        objective_row = imported.business_objectives.get()
        self.assertEqual(objective_row.owner_name, "CISO")
        self.assertEqual(
            imported.threats.get().business_objective_links.get().business_objective,
            objective_row,
        )
        self.assertEqual(
            imported.risks.get().business_objective_links.get().business_objective,
            objective_row,
        )
        again = adapter.export_data(imported)
        assert_valid_tmbom(again)

    def test_other_tools_fallbacks(self):
        document = {
            "specFormat": "CycloneDX",
            "specVersion": "2.0",
            "blueprints": [
                {
                    "name": "Other",
                    "modelTypes": ["data-flow"],
                    "assets": [{"bom-ref": "a1", "name": "App", "type": "service"}],
                    "assumptions": [
                        {
                            "description": "Legacy",
                            "topic": {"name": "folklore"},
                            "relatedAssets": ["a1", "nope"],
                        },
                        {"topic": "security"},
                    ],
                }
            ],
            "definitions": {
                "businessObjectives": [{"bom-ref": "o1", "name": "Uptime"}]
            },
            "threats": {
                "methodologies": ["PASTA", {"name": "House style"}],
                "threats": [
                    {
                        "bom-ref": "t1",
                        "name": "Flood",
                        "relatedBusinessObjectives": ["o1"],
                    }
                ],
                "scenarios": [
                    {
                        "bom-ref": "s1",
                        "name": "S",
                        "threats": ["t1"],
                        "affectedAssets": ["a1"],
                    }
                ],
            },
        }
        imported, summary = TmBomAdapter().import_data(
            document, self.organization, self.user
        )
        legacy = imported.default_blueprint.assumptions.get()
        self.assertEqual((legacy.topic, legacy.validity), ("", "unknown"))
        self.assertEqual(
            legacy.format_metadata["cyclonedx"]["custom_type"], {"name": "folklore"}
        )
        self.assertEqual(legacy.component_links.get().component.name, "App")
        self.assertEqual(imported.methodologies, ["PASTA", "House style"])
        self.assertEqual(
            imported.threats.get()
            .business_objective_links.get()
            .business_objective.name,
            "Uptime",
        )
        warnings = "\n".join(summary["warnings"])
        self.assertIn("folklore", warnings)
        self.assertIn("nope", warnings)
        self.assertIn("no description", warnings)
        again = TmBomAdapter().export_data(imported)
        assert_valid_tmbom(again)
        self.assertEqual(
            again["blueprints"][0]["assumptions"][0]["topic"], {"name": "folklore"}
        )
