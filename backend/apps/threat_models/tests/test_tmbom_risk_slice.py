"""The step 8 adapter slice: risks with status, statement, ratings and responses."""

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import OrgsystemComponent
from apps.threat_models.models import ThreatModel
from apps.threat_models.tmbom import TmBomAdapter
from apps.threat_models.tmbom.testing import assert_valid_tmbom
from apps.threats.services import (
    create_instance_countermeasure,
    create_instance_threat,
    create_risk,
    create_risk_response,
)

User = get_user_model()


class RiskSliceTests(TestCase):
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
            name="Payments", organization=cls.organization, created_by=cls.user
        )
        api = OrgsystemComponent.objects.create(
            blueprint=cls.threat_model.default_blueprint, name="API"
        )
        threat = create_instance_threat(
            cls.threat_model, targets=[api], threat_name="SQLi", level="high"
        )
        control = create_instance_countermeasure(
            cls.threat_model, countermeasure_name="WAF", status="planned"
        )
        cls.risk = create_risk(
            cls.threat_model,
            name="Customer data exposure",
            description="PII leaves the system",
            rating_inputs={"likelihood": "likely", "impact": "severe"},
            threat_ids=[threat.id],
            status="assessed",
            domains=["security", "privacy"],
            owner=cls.user,
        )
        create_risk_response(
            cls.risk,
            strategy="reduce",
            description="Add a WAF",
            status="in_progress",
            cost="medium",
            priority="high",
            owner=cls.user,
            countermeasures=[control],
        )
        create_risk(cls.threat_model, name="Unstated", level="low")

    def test_round_trip(self):
        adapter = TmBomAdapter()
        document = adapter.export_data(self.threat_model)
        assert_valid_tmbom(document, context="step 8 export")
        risks = {r["name"]: r for r in document["risks"]["risks"]}
        exposure = risks["Customer data exposure"]
        self.assertEqual(exposure["statement"], "PII leaves the system")
        self.assertEqual(exposure["status"], "assessed")
        self.assertEqual(
            exposure["domains"], [{"type": "security"}, {"type": "privacy"}]
        )
        self.assertEqual(
            exposure["relatedThreats"], [document["threats"]["scenarios"][0]["bom-ref"]]
        )
        self.assertEqual(exposure["inherentRisk"]["score"]["level"], "critical")
        self.assertEqual(exposure["residualRisk"]["score"]["level"], "critical")
        self.assertEqual(exposure["owner"], f"party-user-{self.user.pk}")
        response = exposure["responses"][0]
        self.assertEqual(response["strategy"], "reduce")
        self.assertEqual(response["status"], "in-progress")
        self.assertEqual(response["controls"], [document["controls"][0]["bom-ref"]])
        self.assertEqual(response["owner"], f"party-user-{self.user.pk}")
        self.assertEqual(
            {p["name"] for p in exposure.get("properties", [])},
            {"precogly:statement-generated"},
        )
        self.assertEqual(risks["Unstated"]["statement"], "Unstated")

        imported, summary = adapter.import_data(document, self.organization, self.user)
        self.assertNotIn("warnings", summary)
        self.assertEqual(summary["risks"], 2)
        self.assertEqual(summary["risk_responses"], 1)
        back = imported.risks.get(name="Customer data exposure")
        self.assertEqual(back.statement, "")  # generated statements are not stored
        self.assertEqual(back.status, "assessed")
        self.assertEqual(back.domains, ["security", "privacy"])
        self.assertEqual(back.inherent.level, "critical")
        self.assertEqual(back.owner, self.user)
        self.assertEqual(back.risk_threats.get().threat.threat_name, "SQLi")
        response = back.responses.get()
        self.assertEqual(
            (response.strategy, response.status, response.cost, response.priority),
            ("reduce", "in_progress", "medium", "high"),
        )
        self.assertEqual(
            response.countermeasure_links.get().countermeasure.countermeasure_name,
            "WAF",
        )
        again = adapter.export_data(imported)
        assert_valid_tmbom(again)
        self.assertEqual(
            {r["bom-ref"] for r in again["risks"]["risks"]},
            {r["bom-ref"] for r in document["risks"]["risks"]},
        )

    def test_other_tools_risks_keep_what_we_cannot_hold(self):
        document = {
            "specFormat": "CycloneDX",
            "specVersion": "2.0",
            "blueprints": [
                {
                    "name": "Other",
                    "modelTypes": ["data-flow"],
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
            },
            "risks": {
                "risks": [
                    {
                        "bom-ref": "r1",
                        "name": "Fraud",
                        "statement": "Someone spoofs a customer and moves money.",
                        "status": {"name": "under-review"},
                        "relatedThreats": ["s1", "t1"],
                        "inherentRisk": {
                            "score": {
                                "level": "high",
                                "methodology": "dread",
                                "score": 7,
                            }
                        },
                        "responses": [
                            {
                                "bom-ref": "rr1",
                                "strategy": "exploit",
                                "description": "Lean in",
                            },
                            {
                                "bom-ref": "rr2",
                                "strategy": "accept",
                                "status": "approved",
                            },
                        ],
                    },
                    {"bom-ref": "r2", "name": "Fraud", "statement": "Again."},
                ]
            },
        }
        imported, summary = TmBomAdapter().import_data(
            document, self.organization, self.user
        )
        fraud = imported.risks.get(format_metadata__cyclonedx__bom_ref="r1")
        self.assertEqual(fraud.status, "identified")
        self.assertEqual(
            fraud.format_metadata["cyclonedx"]["custom_status"],
            {"name": "under-review"},
        )
        self.assertEqual(
            fraud.format_metadata["cyclonedx"]["extra_related_threats"], ["t1"]
        )
        self.assertEqual(fraud.risk_threats.get().threat.threat_name, "S")
        self.assertEqual(fraud.inherent.methodology, "dread")
        self.assertEqual(fraud.responses.get().strategy, "accept")
        self.assertEqual(
            fraud.format_metadata["cyclonedx"]["extra_responses"][0]["strategy"],
            "exploit",
        )
        self.assertEqual(
            imported.risks.get(format_metadata__cyclonedx__bom_ref="r2").name,
            "Fraud (2)",
        )
        warnings = "\n".join(summary["warnings"])
        self.assertIn("under-review", warnings)
        self.assertIn("exploit", warnings)
        self.assertIn("no inherent rating", warnings)
        again = TmBomAdapter().export_data(imported)
        assert_valid_tmbom(again)
        exported = next(r for r in again["risks"]["risks"] if r["bom-ref"] == "r1")
        self.assertEqual(exported["status"], {"name": "under-review"})
        self.assertEqual(sorted(exported["relatedThreats"]), ["s1", "t1"])
        self.assertEqual(
            {r["strategy"] for r in exported["responses"]}, {"accept", "exploit"}
        )
