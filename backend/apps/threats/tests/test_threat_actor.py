"""One actor per threat: a persona of the model or free text, never both
(plan J10, K3), and ``threat_count`` on personas."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import OrgsystemComponent
from apps.threat_models.models import ThreatModel
from apps.threats.models import ThreatPersona
from apps.threats.services import create_instance_threat

User = get_user_model()


class ThreatActorTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="sec", email="sec@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        cls.threat_model = ThreatModel.objects.create(
            name="TM", organization=cls.organization
        )
        cls.other_model = ThreatModel.objects.create(
            name="Other", organization=cls.organization
        )
        cls.insider = ThreatPersona.objects.create(
            threat_model=cls.threat_model, symbolic_name="insider", name="Insider"
        )
        cls.foreign_persona = ThreatPersona.objects.create(
            threat_model=cls.other_model, symbolic_name="outsider", name="Outsider"
        )
        cls.component = OrgsystemComponent.objects.create(
            blueprint=cls.threat_model.default_blueprint, name="API"
        )

    def setUp(self):
        self.client = APIClient()
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(self.user).access_token}"
        )
        self.threat = create_instance_threat(
            self.threat_model,
            targets=[self.component],
            threat_name="Tampering",
            level="high",
        )
        self.url = f"/api/threats/{self.threat.id}/"
        self.persona_url = f"/api/threat-models/{self.threat_model.id}/threat-personas/"

    def _patch(self, body):
        return self.client.patch(self.url, body, format="json")

    def test_persona_with_empty_text_is_stored(self):
        self.threat.threat_actor_text = "state actor"
        self.threat.save()
        response = self._patch(
            {"actor_persona": self.insider.id, "threat_actor_text": ""}
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["actor_persona"], self.insider.id)
        self.assertEqual(response.data["actor_persona_name"], "Insider")
        self.assertEqual(response.data["threat_actor_text"], "")
        self.threat.refresh_from_db()
        self.assertEqual(self.threat.actor_persona_id, self.insider.id)
        self.assertEqual(self.threat.threat_actor_text, "")

    def test_persona_without_clearing_existing_text_is_refused(self):
        self.threat.threat_actor_text = "state actor"
        self.threat.save()
        response = self._patch({"actor_persona": self.insider.id})
        self.assertEqual(response.status_code, 400)
        self.assertIn("threat_actor_text", response.data)
        self.threat.refresh_from_db()
        self.assertIsNone(self.threat.actor_persona_id)
        self.assertEqual(self.threat.threat_actor_text, "state actor")

    def test_persona_and_text_in_one_request_are_refused(self):
        response = self._patch(
            {"actor_persona": self.insider.id, "threat_actor_text": "hacktivist"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("threat_actor_text", response.data)

    def test_text_without_clearing_existing_persona_is_refused(self):
        self.threat.actor_persona = self.insider
        self.threat.save()
        response = self._patch({"threat_actor_text": "hacktivist"})
        self.assertEqual(response.status_code, 400)
        response = self._patch(
            {"threat_actor_text": "hacktivist", "actor_persona": None}
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.threat.refresh_from_db()
        self.assertIsNone(self.threat.actor_persona_id)
        self.assertEqual(self.threat.threat_actor_text, "hacktivist")

    def test_another_models_persona_is_refused(self):
        response = self._patch({"actor_persona": self.foreign_persona.id})
        self.assertEqual(response.status_code, 400)
        self.assertIn("actor_persona", response.data)

    def test_create_with_persona(self):
        response = self.client.post(
            "/api/threats/",
            {
                "threat_model": self.threat_model.id,
                "threat_name": "Spoofing",
                "targets": [{"type": "component", "id": self.component.id}],
                "actor_persona": self.insider.id,
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["actor_persona"], self.insider.id)

    def test_persona_delete_clears_the_key_on_its_threats(self):
        self.threat.actor_persona = self.insider
        self.threat.save()
        response = self.client.delete(f"{self.persona_url}{self.insider.id}/")
        self.assertEqual(response.status_code, 204)
        self.threat.refresh_from_db()
        self.assertIsNone(self.threat.actor_persona_id)
        self.assertEqual(self.threat.threat_actor_text, "")

    def test_persona_list_carries_threat_count(self):
        self.threat.actor_persona = self.insider
        self.threat.save()
        create_instance_threat(
            self.threat_model,
            targets=[self.component],
            threat_name="Repudiation",
            level="low",
        )
        response = self.client.get(self.persona_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [(row["name"], row["threat_count"]) for row in response.data],
            [("Insider", 1)],
        )
        detail = self.client.get(f"{self.persona_url}{self.insider.id}/")
        self.assertEqual(detail.data["threat_count"], 1)

    def test_persona_create_uses_the_url_model(self):
        response = self.client.post(
            self.persona_url,
            {"symbolic_name": "vendor", "name": "Vendor", "is_person": False},
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["threat_model"], self.threat_model.id)
        self.assertEqual(response.data["threat_count"], 0)
