"""Use cases: list, retrieve and delete only (plan J14, K2)."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import Organization, OrganizationMember
from apps.threat_models.models import ThreatModel, UseCase

User = get_user_model()


class UseCaseApiTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.other_organization = Organization.objects.create(
            name="Other", domain="other.test"
        )
        cls.user = User.objects.create_user(
            username="sec", email="sec@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        cls.outsider = User.objects.create_user(
            username="out", email="out@other.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.other_organization, user=cls.outsider, role="security_team"
        )
        cls.threat_model = ThreatModel.objects.create(
            name="TM", organization=cls.organization
        )
        cls.login = UseCase.objects.create(
            threat_model=cls.threat_model,
            name="Login",
            description="A user signs in",
            flow_data={"main_flow": ["Open the page", "Enter credentials"]},
        )
        cls.checkout = UseCase.objects.create(
            threat_model=cls.threat_model, name="Checkout"
        )
        other_model = ThreatModel.objects.create(
            name="Other model", organization=cls.organization
        )
        UseCase.objects.create(threat_model=other_model, name="Elsewhere")

    def _client(self, user):
        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(user).access_token}"
        )
        return client

    def setUp(self):
        self.client = self._client(self.user)
        self.base_url = f"/api/threat-models/{self.threat_model.id}/use-cases/"

    def test_list_returns_only_this_models_use_cases(self):
        response = self.client.get(self.base_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual([row["name"] for row in response.data], ["Checkout", "Login"])
        self.assertEqual(
            set(response.data[0]),
            {"id", "name", "description", "flow_data", "created_at", "updated_at"},
        )

    def test_retrieve_carries_the_flow_data(self):
        response = self.client.get(f"{self.base_url}{self.login.id}/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["description"], "A user signs in")
        self.assertEqual(
            response.data["flow_data"]["main_flow"],
            ["Open the page", "Enter credentials"],
        )

    def test_delete_removes_the_row(self):
        response = self.client.delete(f"{self.base_url}{self.checkout.id}/")
        self.assertEqual(response.status_code, 204)
        self.assertFalse(UseCase.objects.filter(id=self.checkout.id).exists())
        self.assertTrue(UseCase.objects.filter(id=self.login.id).exists())

    def test_create_and_update_are_refused(self):
        response = self.client.post(self.base_url, {"name": "New"}, format="json")
        self.assertEqual(response.status_code, 405)
        response = self.client.patch(
            f"{self.base_url}{self.login.id}/", {"name": "Renamed"}, format="json"
        )
        self.assertEqual(response.status_code, 405)
        response = self.client.put(
            f"{self.base_url}{self.login.id}/", {"name": "Renamed"}, format="json"
        )
        self.assertEqual(response.status_code, 405)
        self.login.refresh_from_db()
        self.assertEqual(self.login.name, "Login")

    def test_outsider_gets_404(self):
        outsider = self._client(self.outsider)
        self.assertEqual(outsider.get(self.base_url).status_code, 404)
        self.assertEqual(
            outsider.get(f"{self.base_url}{self.login.id}/").status_code, 404
        )
        self.assertEqual(
            outsider.delete(f"{self.base_url}{self.login.id}/").status_code, 404
        )
        self.assertTrue(UseCase.objects.filter(id=self.login.id).exists())
