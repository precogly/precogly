"""Baseline for risk CRUD, threat linking and bulk update (plan step 0)."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import Flow, OrgsystemComponent
from apps.threat_models.models import ThreatModel
from apps.threats.models import (
    CountermeasureThreatLink,
    InstanceCountermeasure,
    Risk,
    RiskThreat,
)
from apps.threats.services import create_instance_threat

User = get_user_model()


class RiskApiTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="sec", email="sec@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        cls.other_user = User.objects.create_user(
            username="owner2", email="owner2@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.other_user, role="member"
        )
        cls.threat_model = ThreatModel.objects.create(
            name="TM", organization=cls.organization
        )
        cls.api = OrgsystemComponent.objects.create(
            blueprint=cls.threat_model.default_blueprint, name="API"
        )
        cls.database = OrgsystemComponent.objects.create(
            blueprint=cls.threat_model.default_blueprint,
            name="DB",
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
            threat_name="SQLi",
            level="high",
        )
        cls.flow_threat = create_instance_threat(
            cls.flow.blueprint.threat_model,
            targets=[cls.flow],
            threat_name="Sniffing",
            level="medium",
        )
        verified = InstanceCountermeasure.objects.create(
            threat_model=cls.threat_model, status="verified"
        )
        CountermeasureThreatLink.objects.create(
            countermeasure=verified, threat=cls.component_threat
        )

    def setUp(self):
        self.client = APIClient()
        token = str(RefreshToken.for_user(self.user).access_token)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        self.base_url = f"/api/threat-models/{self.threat_model.id}/risks/"

    def _create(self, **overrides):
        payload = {
            "name": "Customer data exposure",
            "description": "PII leaves the system",
            "rating_inputs": {"likelihood": "likely", "impact": "severe"},
            **overrides,
        }
        response = self.client.post(self.base_url, payload, format="json")
        self.assertEqual(response.status_code, 201, response.content)
        return response.data

    def test_create_rates_the_risk_from_the_inputs(self):
        data = self._create()
        self.assertEqual(data["inherent"]["score"], 20)
        self.assertEqual(data["inherent"]["level"], "critical")
        self.assertEqual(data["inherent"]["methodology"], "qualitative-matrix")
        self.assertEqual(data["scoring_method"], self.threat_model.risk_scoring_method)
        self.assertEqual(data["threats"], [])

    def test_create_with_threats_links_them_and_computes_the_residual(self):
        data = self._create(
            threat_ids=[self.component_threat.id, self.flow_threat.id],
        )
        self.assertEqual(len(data["threats"]), 2)
        self.assertEqual(
            {t["targets"][0]["type"] for t in data["threats"]}, {"component", "flow"}
        )
        self.assertEqual({t["display_number"] for t in data["threats"]}, {"T1", "T2"})
        self.assertIsNotNone(data["residual"])
        self.assertLessEqual(data["residual"]["score"], data["inherent"]["score"])

    def test_invalid_scoring_inputs_are_rejected(self):
        response = self.client.post(
            self.base_url,
            {
                "name": "Bad",
                "rating_inputs": {"likelihood": "sometimes", "impact": "big"},
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400)

    def test_list_detail_update_and_delete(self):
        created = self._create()
        risk_id = created["id"]

        listed = self.client.get(self.base_url)
        self.assertEqual(listed.status_code, 200)
        self.assertEqual([r["id"] for r in listed.data["results"]], [risk_id])

        detail = self.client.get(f"{self.base_url}{risk_id}/")
        self.assertEqual(detail.data["name"], "Customer data exposure")

        updated = self.client.patch(
            f"{self.base_url}{risk_id}/", {"status": "assessed"}, format="json"
        )
        self.assertEqual(updated.status_code, 200, updated.content)
        self.assertEqual(updated.data["status"], "assessed")

        rescored = self.client.patch(
            f"{self.base_url}{risk_id}/",
            {"rating_inputs": {"likelihood": "rare", "impact": "negligible"}},
            format="json",
        )
        self.assertLess(
            rescored.data["inherent"]["score"], created["inherent"]["score"]
        )

        deleted = self.client.delete(f"{self.base_url}{risk_id}/")
        self.assertEqual(deleted.status_code, 204)
        self.assertFalse(Risk.objects.filter(id=risk_id).exists())

    def test_add_and_remove_threats(self):
        risk_id = self._create()["id"]

        added = self.client.post(
            f"{self.base_url}{risk_id}/add-threats/",
            {"threat_ids": [self.component_threat.id, self.flow_threat.id]},
            format="json",
        )
        self.assertEqual(added.status_code, 200, added.content)
        self.assertEqual(RiskThreat.objects.filter(risk_id=risk_id).count(), 2)

        removed = self.client.post(
            f"{self.base_url}{risk_id}/remove-threats/",
            {"threat_ids": [self.flow_threat.id]},
            format="json",
        )
        self.assertEqual(removed.status_code, 200)
        self.assertEqual(RiskThreat.objects.filter(risk_id=risk_id).count(), 1)

    def test_add_threats_rejects_a_threat_from_another_model(self):
        other_model = ThreatModel.objects.create(
            name="Other", organization=self.organization
        )
        other_component = OrgsystemComponent.objects.create(
            blueprint=other_model.default_blueprint, name="X"
        )
        foreign_threat = create_instance_threat(
            other_component.blueprint.threat_model,
            targets=[other_component],
            level="low",
        )
        risk_id = self._create()["id"]
        response = self.client.post(
            f"{self.base_url}{risk_id}/add-threats/",
            {"threat_ids": [foreign_threat.id]},
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["rejected_ids"], [foreign_threat.id])

    def test_bulk_update_sets_response_and_owner(self):
        first = self._create(name="First")["id"]
        second = self._create(name="Second")["id"]

        response = self.client.post(
            f"{self.base_url}bulk-update/",
            {
                "risk_ids": [first, second],
                "status": "accepted",
                "owner": self.other_user.id,
            },
            format="json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.data["updated"], 2)
        self.assertEqual(
            set(
                Risk.objects.filter(id__in=[first, second]).values_list(
                    "status", flat=True
                )
            ),
            {"accepted"},
        )
        self.assertEqual(
            set(
                Risk.objects.filter(id__in=[first, second]).values_list(
                    "owner_id", flat=True
                )
            ),
            {self.other_user.id},
        )

        refused = self.client.post(
            f"{self.base_url}bulk-update/",
            {"risk_ids": [first], "status": "gone"},
            format="json",
        )
        self.assertEqual(refused.status_code, 400)

    def test_recalculate_action(self):
        risk_id = self._create(threat_ids=[self.component_threat.id])["id"]
        response = self.client.post(f"{self.base_url}{risk_id}/recalculate/")
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(response.data["residual"])
