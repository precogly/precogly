"""Ratings (#31 comment, section 2.11, and plan section 4.2)."""

from django.contrib.auth import get_user_model
from django.db import connection
from django.db.models import RestrictedError
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from rest_framework.exceptions import ValidationError
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import OrgsystemComponent
from apps.threat_models.models import ThreatModel
from apps.threat_models.tmbom import TmBomAdapter
from apps.threat_models.tmbom.testing import assert_valid_tmbom
from apps.threats.models import Rating
from apps.threats.scoring.manual import ManualEngine
from apps.threats.scoring.owasp_risk_rating import OwaspRiskRatingEngine
from apps.threats.scoring.qualitative_matrix import QualitativeMatrixEngine
from apps.threats.scoring.registry import get_engine, get_scoring_methods_list
from apps.threats.services import (
    apply_rating,
    create_instance_countermeasure,
    create_instance_threat,
    create_risk,
    link_countermeasure,
    recalculate_residual,
)

User = get_user_model()

OWASP_EXAMPLE = {
    "threat_agent": {"skill_level": 5, "motive": 6, "opportunity": 5, "size": 6},
    "vulnerability": {
        "ease_of_discovery": 5,
        "ease_of_exploit": 6,
        "awareness": 5,
        "intrusion_detection": 5,
    },
    "technical_impact": {
        "loss_of_confidentiality": 6,
        "loss_of_integrity": 6,
        "loss_of_availability": 6,
        "loss_of_accountability": 7,
    },
    "business_impact": {
        "financial_damage": 6,
        "reputation_damage": 6,
        "non_compliance": 6,
        "privacy_violation": 6,
    },
}


class EngineTests(TestCase):
    def test_owasp_example(self):
        rating = OwaspRiskRatingEngine().rate(OWASP_EXAMPLE)
        self.assertEqual(rating.likelihood_score, 5.4)
        self.assertEqual(rating.impact_score, 6.1)
        self.assertEqual(rating.likelihood_level, "medium")
        self.assertEqual(rating.impact_level, "major")
        self.assertEqual(rating.level, "high")
        self.assertEqual(rating.score, 5.75)
        self.assertEqual(rating.likelihood_factors[0]["type"], "threat-capability")
        self.assertEqual(
            rating.impact_factors[3]["category"], {"name": "Accountability"}
        )

    def test_owasp_low_low_is_info(self):
        inputs = {
            group: dict.fromkeys(fields, 1)
            for group, fields in (
                (g, list(f))
                for g, f in OwaspRiskRatingEngine.input_schema.items()
                if g != "rationale"
                for f in [OwaspRiskRatingEngine.input_schema[g]["fields"]]
            )
        }
        self.assertEqual(OwaspRiskRatingEngine().rate(inputs).level, "info")

    def test_owasp_validation(self):
        with self.assertRaises(ValidationError):
            OwaspRiskRatingEngine().validate({"threat_agent": {"skill_level": 12}})

    def test_matrix_likely_major(self):
        rating = QualitativeMatrixEngine().rate(
            {"likelihood": "likely", "impact": "major"}
        )
        self.assertEqual(rating.likelihood_level, "high")
        self.assertEqual(rating.impact_level, "major")
        self.assertEqual(rating.score, 16)
        self.assertEqual(rating.level, "high")
        self.assertEqual(
            QualitativeMatrixEngine()
            .rate({"likelihood": "rare", "impact": "negligible"})
            .level,
            "info",
        )

    def test_matrix_rejects_unknown_values(self):
        with self.assertRaises(ValidationError):
            QualitativeMatrixEngine().validate(
                {"likelihood": "sometimes", "impact": "big"}
            )

    def test_manual_is_level_only(self):
        rating = ManualEngine().rate({"level": "critical"})
        self.assertEqual(
            (rating.level, rating.score, rating.likelihood_level),
            ("critical", None, ""),
        )

    def test_registry_lists_engines_and_planned_methods(self):
        methods = {m["key"]: m for m in get_scoring_methods_list()}
        self.assertTrue(methods["qualitative-matrix"]["available"])
        self.assertTrue(methods["owasp-risk-rating"]["available"])
        self.assertFalse(methods["fair"]["available"])
        self.assertNotIn("manual", methods)
        self.assertIsNone(get_engine("fair"))
        self.assertEqual(
            methods["owasp-risk-rating"]["input_schema"]["threat_agent"]["type"],
            "group",
        )


class RiskRatingTests(TestCase):
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
            name="TM", organization=cls.organization
        )
        cls.api = OrgsystemComponent.objects.create(
            blueprint=cls.threat_model.default_blueprint, name="API"
        )
        cls.threat = create_instance_threat(
            cls.threat_model, targets=[cls.api], threat_name="SQLi", level="high"
        )

    def api_client(self):
        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(self.user).access_token}"
        )
        return client

    def test_residual_reduces_likelihood_and_rebands(self):
        risk = create_risk(
            self.threat_model,
            name="Exposure",
            rating_inputs={"likelihood": "certain", "impact": "severe"},
            threat_ids=[self.threat.id],
        )
        self.assertEqual((risk.inherent.level, risk.inherent.score), ("critical", 25))
        self.assertEqual(risk.residual.level, "critical")  # nothing contributes yet
        verified = create_instance_countermeasure(
            self.threat_model, countermeasure_name="WAF", status="verified"
        )
        link_countermeasure(verified, self.threat)
        recalculate_residual(risk)
        risk.refresh_from_db()
        self.assertEqual(risk.residual.likelihood_score, 1)
        self.assertEqual(risk.residual.score, 5)
        self.assertEqual(risk.residual.level, "low")
        self.assertEqual(risk.residual.organization, self.organization)

    def test_deleting_a_risk_deletes_its_ratings_and_restrict_holds(self):
        risk = create_risk(self.threat_model, name="R", level="low")
        inherent_id = risk.inherent_id
        residual_id = risk.residual_id
        with self.assertRaises(RestrictedError):
            Rating.objects.get(pk=inherent_id).delete()
        risk.delete()
        self.assertFalse(
            Rating.objects.filter(pk__in=[inherent_id, residual_id]).exists()
        )

    def test_deleting_a_threat_deletes_its_rating(self):
        rating_id = self.threat.rating_id
        with self.assertRaises(RestrictedError):
            Rating.objects.get(pk=rating_id).delete()
        self.threat.delete()
        self.assertFalse(Rating.objects.filter(pk=rating_id).exists())

    def test_deleting_an_organization_with_rated_rows_goes_through(self):
        organization = Organization.objects.create(name="Gone", domain="gone.test")
        threat_model = ThreatModel.objects.create(name="X", organization=organization)
        create_instance_threat(
            threat_model, whole_system=True, threat_name="T", level="low"
        )
        create_risk(threat_model, name="R", level="low")
        organization_id = organization.id
        organization.delete()
        self.assertFalse(
            Rating.objects.filter(organization_id=organization_id).exists()
        )

    def test_every_rating_belongs_to_the_owners_organization(self):
        risk = create_risk(self.threat_model, name="R", level="medium")
        rating = ManualEngine().rate({"level": "high"})
        rating.organization = Organization.objects.create(name="Other", domain="o.test")
        apply_rating(risk, "inherent", rating)
        risk.refresh_from_db()
        self.assertEqual(risk.inherent.organization, self.organization)
        for row in Rating.objects.all():
            self.assertEqual(row.organization_id, self.organization.id)

    def test_methodology_guard(self):
        client = self.api_client()
        url = f"/api/threat-models/{self.threat_model.id}/"
        allowed = client.patch(
            url, {"risk_scoring_method": "owasp-risk-rating"}, format="json"
        )
        self.assertEqual(allowed.status_code, 200, allowed.content)
        create_risk(self.threat_model, name="R", level="low")
        refused = client.patch(
            url, {"risk_scoring_method": "qualitative-matrix"}, format="json"
        )
        self.assertEqual(refused.status_code, 400)
        self.assertIn("risk_scoring_method", refused.data)

    def test_risk_api_rates_from_inputs_and_lists_constant_queries(self):
        client = self.api_client()
        base = f"/api/threat-models/{self.threat_model.id}/risks/"
        created = client.post(
            base,
            {
                "name": "Data exposure",
                "rating_inputs": {
                    "likelihood": "likely",
                    "impact": "major",
                    "impact_categories": ["confidentiality", "privacy"],
                    "impact_quantification": {
                        "financial_loss": 25000,
                        "currency": "USD",
                    },
                },
                "threat_ids": [self.threat.id],
            },
            format="json",
        )
        self.assertEqual(created.status_code, 201, created.content)
        self.assertEqual(created.data["inherent"]["level"], "high")
        self.assertEqual(created.data["inherent"]["score"], 16)
        self.assertEqual(
            created.data["inherent"]["impact"]["extra"]["categories"],
            ["confidentiality", "privacy"],
        )
        self.assertEqual(created.data["residual"]["level"], "high")
        self.assertEqual(created.data["threats"][0]["rating"]["level"], "high")

        bad = client.post(
            base,
            {
                "name": "Bad",
                "rating_inputs": {"impact_categories": ["weather"], "level": "low"},
            },
            format="json",
        )
        self.assertEqual(bad.status_code, 400)
        missing = client.post(base, {"name": "Unrated"}, format="json")
        self.assertEqual(missing.status_code, 400)

        level_only = client.post(
            base,
            {"name": "Picked", "rating_inputs": {"level": "critical"}},
            format="json",
        )
        self.assertEqual(level_only.data["inherent"]["methodology"], "manual")
        self.assertIsNone(level_only.data["inherent"]["likelihood"])

        rerated = client.patch(
            f"{base}{created.data['id']}/",
            {"rating_inputs": {"likelihood": "rare", "impact": "negligible"}},
            format="json",
        )
        self.assertEqual(rerated.data["inherent"]["level"], "info")

        # Every risk carries a link, so both pages prefetch the same relations
        # and the count compares the shape of the query plan, not the data.
        for index in range(8):
            create_risk(
                self.threat_model,
                name=f"R{index}",
                level="medium",
                threat_ids=[self.threat.id],
            )
        with CaptureQueriesContext(connection) as small:
            client.get(base, {"page_size": 3})
        with self.assertNumQueries(len(small.captured_queries)):
            client.get(base, {"page_size": 50})
        ordered = client.get(base, {"ordering": "-inherent_rank"})
        self.assertEqual(ordered.data["results"][0]["inherent"]["level"], "critical")
        filtered = client.get(base, {"inherent__level": "info"})
        self.assertEqual(
            [r["name"] for r in filtered.data["results"]], ["Data exposure"]
        )

    def test_threat_api_rates_from_inputs(self):
        client = self.api_client()
        response = client.patch(
            f"/api/threats/{self.threat.id}/",
            {"rating_inputs": {"likelihood": "likely", "impact": "major"}},
            format="json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.data["rating"]["methodology"], "qualitative-matrix")
        self.assertEqual(response.data["rating"]["score"], 16)
        self.threat.refresh_from_db()
        self.assertEqual(Rating.objects.filter(pk=self.threat.rating_id).count(), 1)
        by_level = client.get("/api/threats/", {"rating__level": "high"})
        self.assertEqual([t["id"] for t in by_level.data["results"]], [self.threat.id])

    def test_exported_ratings_validate(self):
        create_instance_threat(
            self.threat_model,
            whole_system=True,
            threat_name="Rated",
            rating=OwaspRiskRatingEngine().rate(OWASP_EXAMPLE),
            impact_description="Data leaves",
        )
        document = TmBomAdapter().export_data(self.threat_model)
        assert_valid_tmbom(document, context="rated export")
        scenarios = {s["name"]: s for s in document["threats"]["scenarios"]}
        manual = scenarios["SQLi"]
        self.assertEqual(
            manual["riskScore"], {"level": "high", "methodology": {"name": "manual"}}
        )
        self.assertNotIn("likelihood", manual)
        self.assertNotIn("impact", manual)
        owasp = scenarios["Rated"]
        self.assertEqual(owasp["riskScore"]["methodology"], "owasp-risk-rating")
        self.assertEqual(owasp["likelihood"]["level"], "medium")
        self.assertEqual(owasp["impact"]["description"], "Data leaves")
        self.assertEqual(len(owasp["likelihood"]["factors"]), 8)

        imported, summary = TmBomAdapter().import_data(
            document, self.organization, self.user
        )
        self.assertNotIn("warnings", summary)
        rated = imported.threats.get(threat_name="Rated")
        self.assertEqual(rated.rating.methodology, "owasp-risk-rating")
        self.assertEqual(rated.rating.likelihood_score, 5.4)
        self.assertEqual(rated.rating.level, "high")
        self.assertEqual(rated.impact_description, "Data leaves")
        self.assertEqual(imported.threats.get(threat_name="SQLi").rating.level, "high")
