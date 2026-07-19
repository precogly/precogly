"""Tests for cross-tenant isolation of null-orgsystem components (SEC-03, SEC-04)."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import OrgsystemComponent, TrustZone
from apps.threat_models.models import ThreatModel

User = get_user_model()


class NullOrgsystemIsolationTests(TestCase):
    """SEC-03: null-orgsystem components must not leak across tenants."""

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

        cls.tm_a = ThreatModel.objects.create(name="TM A", organization=cls.org_a)
        cls.tm_b = ThreatModel.objects.create(name="TM B", organization=cls.org_b)

        cls.comp_a = OrgsystemComponent.objects.create(
            name="Secret Component A",
            orgsystem=None,
            threat_model=cls.tm_a,
        )
        cls.comp_b = OrgsystemComponent.objects.create(
            name="Secret Component B",
            orgsystem=None,
            threat_model=cls.tm_b,
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

    def test_user_a_sees_only_own_null_orgsystem_components(self):
        resp = self.client_a.get("/api/components/")
        self.assertEqual(resp.status_code, 200)
        results = resp.data.get("results", resp.data)
        ids = [r["id"] for r in results]
        self.assertIn(self.comp_a.id, ids)
        self.assertNotIn(self.comp_b.id, ids)

    def test_user_b_sees_only_own_null_orgsystem_components(self):
        resp = self.client_b.get("/api/components/")
        self.assertEqual(resp.status_code, 200)
        results = resp.data.get("results", resp.data)
        ids = [r["id"] for r in results]
        self.assertIn(self.comp_b.id, ids)
        self.assertNotIn(self.comp_a.id, ids)

    def test_user_b_cannot_retrieve_org_a_component(self):
        resp = self.client_b.get(f"/api/components/{self.comp_a.id}/")
        self.assertEqual(resp.status_code, 404)

    def test_user_a_can_retrieve_own_component(self):
        resp = self.client_a.get(f"/api/components/{self.comp_a.id}/")
        self.assertEqual(resp.status_code, 200)


class TrustZoneIDORTests(TestCase):
    """SEC-04: trust zone query by threat_model must be org-scoped."""

    @classmethod
    def setUpTestData(cls):
        cls.org_a = Organization.objects.create(name="Org A", domain="a.com")
        cls.org_b = Organization.objects.create(name="Org B", domain="b.com")

        cls.user_a = User.objects.create_user(
            username="tz_a", email="tz_a@a.com", password="testpass123"
        )
        OrganizationMember.objects.create(
            organization=cls.org_a, user=cls.user_a, role="security_team"
        )

        cls.user_b = User.objects.create_user(
            username="tz_b", email="tz_b@b.com", password="testpass123"
        )
        OrganizationMember.objects.create(
            organization=cls.org_b, user=cls.user_b, role="security_team"
        )

        cls.tm_a = ThreatModel.objects.create(name="TM A", organization=cls.org_a)

        cls.zone = TrustZone.objects.create(name="Secret Zone A")
        cls.comp = OrgsystemComponent.objects.create(
            name="Zoned Component",
            orgsystem=None,
            threat_model=cls.tm_a,
            trust_zone=cls.zone,
        )

    def setUp(self):
        self.client_b = APIClient()
        self.client_b.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(self.user_b).access_token}"
        )
        self.client_a = APIClient()
        self.client_a.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(self.user_a).access_token}"
        )

    def test_user_b_cannot_enumerate_org_a_zones_via_tm_param(self):
        """SEC-04: ?threat_model=<victim_tm_id> must not leak zones."""
        resp = self.client_b.get(f"/api/trust-zones/?threat_model={self.tm_a.id}")
        self.assertEqual(resp.status_code, 200)
        results = resp.data.get("results", resp.data)
        zone_ids = [r["id"] for r in results]
        self.assertNotIn(self.zone.id, zone_ids)

    def test_user_a_can_see_own_zones_via_tm_param(self):
        resp = self.client_a.get(f"/api/trust-zones/?threat_model={self.tm_a.id}")
        self.assertEqual(resp.status_code, 200)
        results = resp.data.get("results", resp.data)
        zone_ids = [r["id"] for r in results]
        self.assertIn(self.zone.id, zone_ids)
