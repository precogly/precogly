"""Tests for magic link cross-tenant access control (SEC-01 fix)."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import Organization, OrganizationMember
from apps.threat_models.models import ThreatModel

User = get_user_model()


class MagicLinkCrossTenantTests(TestCase):
    """Verify that magic links cannot be created for another org's threat models."""

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

        cls.member_a = User.objects.create_user(
            username="member_a", email="m@a.com", password="testpass123"
        )
        OrganizationMember.objects.create(
            organization=cls.org_a, user=cls.member_a, role="member"
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
        self.member_client = APIClient()
        self.member_client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(self.member_a).access_token}"
        )

    def test_cannot_create_magic_link_for_other_orgs_tm(self):
        """SEC-01 core bug: user in org B must not mint a share link for org A's TM."""
        resp = self.client_b.post(
            "/api/magic-links/",
            {"threat_model": str(self.tm_a.id)},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("do not have access", str(resp.data))

    def test_can_create_magic_link_for_own_orgs_tm(self):
        """Security team member can create magic link for own org's TM."""
        resp = self.client_a.post(
            "/api/magic-links/",
            {"threat_model": str(self.tm_a.id)},
        )
        self.assertIn(resp.status_code, [200, 201])

    def test_plain_member_blocked_by_org_ownership(self):
        """Non-security-team member passes has_permission (personal workspace)
        but is blocked by the org-ownership check in perform_create."""
        resp = self.member_client.post(
            "/api/magic-links/",
            {"threat_model": str(self.tm_b.id)},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("do not have access", str(resp.data))

    def test_list_only_shows_own_org_links(self):
        """get_queryset already filters by org — verify no cross-org leakage."""
        self.client_a.post(
            "/api/magic-links/",
            {"threat_model": str(self.tm_a.id)},
        )
        resp_b = self.client_b.get("/api/magic-links/")
        self.assertEqual(resp_b.status_code, 200)
        results = resp_b.data.get("results", resp_b.data)
        for link in results:
            self.assertNotEqual(
                str(link["threat_model"]), str(self.tm_a.id),
                "Org B should not see org A's magic links",
            )
