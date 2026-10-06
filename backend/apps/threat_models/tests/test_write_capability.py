"""Tests for the threat-model write capability exposed to the frontend."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import (
    Organization,
    OrganizationMember,
    Team,
    TeamMembership,
)
from apps.threat_models.models import ThreatModel

User = get_user_model()


class ThreatModelWriteCapabilityTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(
            name="Capability Org", domain="capability.test"
        )
        cls.team = Team.objects.create(
            organization=cls.organization,
            name="Capability Team",
        )
        cls.threat_model = ThreatModel.objects.create(
            organization=cls.organization,
            owning_team=cls.team,
            name="Capability Model",
        )

    def _client_for(self, username, org_role, team_role=None):
        user = User.objects.create_user(
            username=username,
            email=f"{username}@capability.test",
            password="testpass123",
        )
        OrganizationMember.objects.create(
            organization=self.organization,
            user=user,
            role=org_role,
        )
        if team_role:
            TeamMembership.objects.create(
                team=self.team,
                user=user,
                role=team_role,
            )
        client = APIClient()
        token = str(RefreshToken.for_user(user).access_token)
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        return client

    def test_viewer_receives_read_only_capability(self):
        response = self._client_for("viewer", "member", "viewer").get(
            f"/api/threat-models/{self.threat_model.pk}/"
        )

        self.assertEqual(response.status_code, 200)
        self.assertIs(response.json()["canWrite"], False)

    def test_member_receives_write_capability(self):
        response = self._client_for("member", "member", "member").get(
            f"/api/threat-models/{self.threat_model.pk}/"
        )

        self.assertEqual(response.status_code, 200)
        self.assertIs(response.json()["canWrite"], True)

    def test_security_team_receives_write_capability(self):
        response = self._client_for("security", "security_team").get(
            f"/api/threat-models/{self.threat_model.pk}/"
        )

        self.assertEqual(response.status_code, 200)
        self.assertIs(response.json()["canWrite"], True)
