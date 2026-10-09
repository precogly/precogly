"""Risk lifecycle: status, statement, responses, exposure (step 8, section 4.7)."""

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import OrgsystemComponent
from apps.threat_models.models import ThreatModel
from apps.threats.models import InstanceCountermeasure, RiskResponse
from apps.threats.services import (
    create_instance_countermeasure,
    create_instance_threat,
    create_risk,
    create_risk_response,
    link_countermeasure,
    set_response_countermeasures,
)

User = get_user_model()


class LifecycleFixture(TestCase):
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
        cls.risk = create_risk(
            cls.threat_model,
            name="Exposure",
            level="high",
            threat_ids=[cls.threat.id],
            statement="An attacker injects SQL and reads customer records.",
        )

    def api_client(self):
        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(self.user).access_token}"
        )
        return client


class ResponseServiceTests(LifecycleFixture):
    def test_responses_rely_on_controls_of_the_same_model(self):
        control = create_instance_countermeasure(
            self.threat_model, countermeasure_name="WAF"
        )
        response = create_risk_response(
            self.risk, strategy="reduce", countermeasures=[control], priority="high"
        )
        self.assertEqual(
            [link.countermeasure for link in response.countermeasure_links.all()],
            [control],
        )
        other = ThreatModel.objects.create(name="Other", organization=self.organization)
        foreign = create_instance_countermeasure(other, countermeasure_name="Foreign")
        from apps.threats.services import TargetError

        with self.assertRaises(TargetError):
            set_response_countermeasures(response, [foreign])

    def test_orphan_rule_spares_a_control_a_response_relies_on(self):
        generated = create_instance_countermeasure(
            self.threat_model, countermeasure_name="Gen", auto_generated=True
        )
        link_countermeasure(generated, self.threat)
        response = create_risk_response(
            self.risk, strategy="reduce", countermeasures=[generated]
        )
        self.threat.delete()
        self.assertTrue(InstanceCountermeasure.objects.filter(pk=generated.pk).exists())
        set_response_countermeasures(response, [])
        self.assertFalse(
            InstanceCountermeasure.objects.filter(pk=generated.pk).exists()
        )


class RiskLifecycleApiTests(LifecycleFixture):
    def test_status_statement_and_exposure(self):
        client = self.api_client()
        base = f"/api/threat-models/{self.threat_model.id}/risks/"
        detail = client.get(f"{base}{self.risk.id}/")
        self.assertEqual(detail.data["status"], "identified")
        self.assertEqual(detail.data["exposure"], "exposed")
        self.assertIn("injects SQL", detail.data["statement"])
        self.assertEqual(detail.data["responses"], [])
        moved = client.patch(
            f"{base}{self.risk.id}/", {"status": "assessed"}, format="json"
        )
        self.assertEqual(moved.data["status"], "assessed")
        refused = client.patch(
            f"{base}{self.risk.id}/", {"status": "lost"}, format="json"
        )
        self.assertEqual(refused.status_code, 400)
        verified = create_instance_countermeasure(
            self.threat_model, countermeasure_name="WAF", status="verified"
        )
        link_countermeasure(verified, self.threat)
        from apps.threats.services import recalculate_threat_status

        recalculate_threat_status(self.threat)
        self.assertEqual(
            client.get(f"{base}{self.risk.id}/").data["exposure"], "mitigated"
        )
        by_status = client.get(base, {"status": "assessed"})
        self.assertEqual([r["id"] for r in by_status.data["results"]], [self.risk.id])

    def test_exposure_costs_no_query_per_risk(self):
        client = self.api_client()
        base = f"/api/threat-models/{self.threat_model.id}/risks/"
        for index in range(3):
            create_risk(
                self.threat_model,
                name=f"R{index}",
                level="low",
                threat_ids=[self.threat.id],
            )
        with CaptureQueriesContext(connection) as few:
            client.get(base, {"page_size": 2})
        with self.assertNumQueries(len(few.captured_queries)):
            client.get(base, {"page_size": 50})

    def test_response_crud(self):
        client = self.api_client()
        base = (
            f"/api/threat-models/{self.threat_model.id}/risks/{self.risk.id}/responses/"
        )
        control = create_instance_countermeasure(
            self.threat_model, countermeasure_name="WAF"
        )
        created = client.post(
            base,
            {
                "strategy": "reduce",
                "description": "Front the API with a WAF",
                "status": "planned",
                "cost": "medium",
                "priority": "high",
                "owner": self.user.id,
                "target_date": "2026-12-01T00:00:00Z",
                "countermeasure_ids": [control.id],
            },
            format="json",
        )
        self.assertEqual(created.status_code, 201, created.content)
        self.assertEqual(created.data["countermeasures"][0]["display_number"], "C1")
        self.assertEqual(created.data["owner_email"], "u@org.test")
        bad = client.post(base, {"strategy": "exploit"}, format="json")
        self.assertEqual(bad.status_code, 400)
        other = ThreatModel.objects.create(name="Other", organization=self.organization)
        foreign = create_instance_countermeasure(other, countermeasure_name="Foreign")
        refused = client.post(
            base,
            {"strategy": "accept", "countermeasure_ids": [foreign.id]},
            format="json",
        )
        self.assertEqual(refused.status_code, 400)
        edited = client.patch(
            f"{base}{created.data['id']}/",
            {"status": "implemented", "countermeasure_ids": []},
            format="json",
        )
        self.assertEqual(edited.status_code, 200, edited.content)
        self.assertEqual(edited.data["countermeasures"], [])
        listed = client.get(base)
        self.assertEqual(len(listed.data["results"]), 1)
        self.assertEqual(
            client.get(
                f"/api/threat-models/{self.threat_model.id}/risks/{self.risk.id}/"
            ).data["responses"][0]["status"],
            "implemented",
        )
        deleted = client.delete(f"{base}{created.data['id']}/")
        self.assertEqual(deleted.status_code, 204)
        self.assertEqual(RiskResponse.objects.count(), 0)
        other_user = User.objects.create_user(
            username="o", email="o@other.test", password="x"
        )
        outsider = APIClient()
        outsider.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(other_user).access_token}"
        )
        self.assertEqual(outsider.get(base).status_code, 404)
