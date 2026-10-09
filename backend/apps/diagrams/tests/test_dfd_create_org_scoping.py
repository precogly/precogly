"""Regression test: DFDViewSet.create() must scope threat model to the caller's orgs.

Without org scoping, any authenticated user can attach a DFD to any threat model
by supplying its id, regardless of organization membership.
"""

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase

from apps.diagrams.models import DFD
from apps.organizations.models import Organization, OrganizationMember
from apps.threat_models.models import ThreatModel

User = get_user_model()


class DFDCreateOrgScopingTests(APITestCase):
    """Verify that DFD creation rejects cross-org threat model ids."""

    @classmethod
    def setUpTestData(cls):
        cls.org_a = Organization.objects.create(name="Org A")
        cls.org_b = Organization.objects.create(name="Org B")

        cls.user_a = User.objects.create_user(
            username="user_a", email="a@orga.test", password="pw"
        )
        OrganizationMember.objects.create(organization=cls.org_a, user=cls.user_a)

        cls.tm_a = ThreatModel.objects.create(
            organization=cls.org_a, created_by=cls.user_a, name="TM in Org A"
        )
        cls.tm_b = ThreatModel.objects.create(
            organization=cls.org_b, created_by=cls.user_a, name="TM in Org B"
        )

    def setUp(self):
        self.client.force_authenticate(user=self.user_a)

    def _create_dfd(self, threat_model_id):
        return self.client.post(
            "/api/diagrams/",
            {"threat_model_id": str(threat_model_id), "name": "Test DFD"},
            format="json",
        )

    def test_create_dfd_for_own_org_succeeds(self):
        response = self._create_dfd(self.tm_a.id)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(DFD.objects.filter(blueprint__threat_model=self.tm_a).exists())

    def test_create_dfd_for_other_org_returns_404(self):
        response = self._create_dfd(self.tm_b.id)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(DFD.objects.filter(blueprint__threat_model=self.tm_b).exists())

    def test_create_dfd_nonexistent_threat_model_returns_404(self):
        response = self._create_dfd(999999999)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_first_dfd_becomes_primary_only_for_own_org(self):
        self.assertFalse(self.tm_a.dfds.exists())
        response = self._create_dfd(self.tm_a.id)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        dfd = DFD.objects.get(blueprint__threat_model=self.tm_a)
        self.assertTrue(dfd.is_primary)

    def test_cross_org_cannot_inject_primary_dfd(self):
        self.assertFalse(self.tm_b.dfds.exists())
        response = self._create_dfd(self.tm_b.id)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(self.tm_b.dfds.exists())
