"""Tests for DFD cross-tenant access control (SEC-02 fix)."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import Organization, OrganizationMember
from apps.threat_models.models import ThreatModel

User = get_user_model()


class DFDCrossTenantTests(TestCase):
    """Verify that DFDs cannot be created for another org's threat models."""

    @classmethod
    def setUpTestData(cls):
        cls.org_a = Organization.objects.create(name="Org A", domain="a.com")
        cls.org_b = Organization.objects.create(name="Org B", domain="b.com")

        cls.user_a = User.objects.create_user(
            username="user_a", email="a@a.com", password="testpass123"
        )
        OrganizationMember.objects.create(
            organization=cls.org_a, user=cls.user_a, role="security_team"
        )

        cls.user_b = User.objects.create_user(
            username="user_b", email="b@b.com", password="testpass123"
        )
        OrganizationMember.objects.create(
            organization=cls.org_b, user=cls.user_b, role="security_team"
        )

        cls.tm_a = ThreatModel.objects.create(
            name="TM A", organization=cls.org_a
        )
        cls.tm_b = ThreatModel.objects.create(
            name="TM B", organization=cls.org_b
        )

    def setUp(self):
        self.client_a = APIClient()
        self.client_a.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(self.user_a).access_token}"
        )
        self.client_b = APIClient()
        self.client_b.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(self.user_b).access_token}"
        )

    def test_cannot_create_dfd_for_other_orgs_tm(self):
        """SEC-02 core bug: user in org B must not attach a DFD to org A's TM."""
        resp = self.client_b.post(
            "/api/diagrams/",
            {"name": "Evil DFD", "threat_model_id": str(self.tm_a.id)},
        )
        self.assertEqual(resp.status_code, 404)
        self.assertIn("not found", resp.data.get("error", "").lower())

    def test_can_create_dfd_for_own_orgs_tm(self):
        """User can create a DFD for their own org's threat model."""
        resp = self.client_a.post(
            "/api/diagrams/",
            {"name": "Legit DFD", "threat_model_id": str(self.tm_a.id)},
        )
        self.assertEqual(resp.status_code, 201)

    def test_cannot_create_dfd_without_threat_model(self):
        """DFD creation requires a threat_model_id."""
        resp = self.client_a.post(
            "/api/diagrams/",
            {"name": "Orphan DFD"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_nonexistent_threat_model_returns_404(self):
        """A bogus threat_model_id returns 404."""
        resp = self.client_a.post(
            "/api/diagrams/",
            {"name": "Ghost DFD", "threat_model_id": 999999},
        )
        self.assertEqual(resp.status_code, 404)
