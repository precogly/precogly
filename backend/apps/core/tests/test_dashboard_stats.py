"""Baseline for the dashboard endpoint before the model rewrite (plan step 0)."""

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
from apps.systems.models import OrgsystemComponent
from apps.threat_models.models import ThreatModel
from apps.threats.models import (
    CountermeasureThreatLink,
    InstanceCountermeasure,
)
from apps.threats.services import create_instance_threat, create_risk

User = get_user_model()

DASHBOARD_URL = "/api/dashboard/stats/"


def _client_for(user):
    client = APIClient()
    token = str(RefreshToken.for_user(user).access_token)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return client


class DashboardStatsTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.core_team = Team.objects.create(organization=cls.organization, name="Core")
        cls.other_team = Team.objects.create(
            organization=cls.organization, name="Other"
        )

        cls.security = User.objects.create_user(
            username="sec", email="sec@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.security, role="security_team"
        )
        cls.member = User.objects.create_user(
            username="member", email="member@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.member, role="member"
        )
        TeamMembership.objects.create(
            team=cls.core_team, user=cls.member, role="member"
        )
        # User creation auto-enrols every new account in a personal workspace
        # with the security team role, and the dashboard treats that role in any
        # organization as org-wide read access. Strip the auto-enrolment so the
        # member is exactly what the name says.
        OrganizationMember.objects.filter(user=cls.member).exclude(
            organization=cls.organization
        ).delete()
        TeamMembership.objects.filter(user=cls.member).exclude(
            team=cls.core_team
        ).delete()

        cls.core_model = ThreatModel.objects.create(
            name="Core TM", organization=cls.organization, owning_team=cls.core_team
        )
        cls.other_model = ThreatModel.objects.create(
            name="Other TM", organization=cls.organization, owning_team=cls.other_team
        )
        cls.unowned_model = ThreatModel.objects.create(
            name="Unowned TM", organization=cls.organization
        )

        component = OrgsystemComponent.objects.create(
            blueprint=cls.core_model.default_blueprint, name="API"
        )
        mitigated_threat = create_instance_threat(
            component.blueprint.threat_model,
            targets=[component],
            level="high",
            status="mitigated",
        )
        countermeasure = InstanceCountermeasure.objects.create(
            threat_model=cls.core_model, status="verified"
        )
        CountermeasureThreatLink.objects.create(
            countermeasure=countermeasure, threat=mitigated_threat
        )

        cls.mitigated_risk = create_risk(
            cls.core_model,
            name="Mitigated",
            level="high",
            threat_ids=[mitigated_threat.id],
        )
        create_risk(cls.core_model, name="Exposed, no threats", level="critical")
        create_risk(cls.other_model, name="Other team's risk", level="low")

    def test_security_team_sees_the_whole_organization(self):
        response = _client_for(self.security).get(DASHBOARD_URL)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["total"], 3)
        risks = response.data["risks"]
        self.assertEqual(risks["total"], 3)
        self.assertEqual(risks["critical"], 1)
        self.assertEqual(risks["high"], 1)
        self.assertEqual(risks["low"], 1)
        self.assertEqual(risks["exposed"], 2)
        self.assertEqual(risks["mitigated"], 1)

    def test_member_sees_own_team_and_unowned_models_only(self):
        response = _client_for(self.member).get(DASHBOARD_URL)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["total"], 2)
        risks = response.data["risks"]
        self.assertEqual(risks["total"], 2)
        self.assertEqual(risks["low"], 0)
        self.assertEqual(risks["exposed"], 1)
        self.assertEqual(risks["mitigated"], 1)

    def test_requires_authentication(self):
        self.assertEqual(APIClient().get(DASHBOARD_URL).status_code, 401)
