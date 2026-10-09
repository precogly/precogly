"""Model-level ``POST /api/threat-models/{id}/generate-threats/`` (plan L7)."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import ComponentLibrary, Flow, OrgsystemComponent
from apps.threat_models.models import Blueprint, ThreatModel
from apps.threats.models import ComponentLibraryThreat, InstanceThreat, ThreatLibrary
from apps.threats.services import ensure_generated_threats

User = get_user_model()


class GenerateThreatsActionTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="sec", email="sec@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        other_organization = Organization.objects.create(name="Other", domain="o.test")
        cls.outsider = User.objects.create_user(
            username="out", email="out@o.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=other_organization, user=cls.outsider, role="security_team"
        )
        cls.threat_model = ThreatModel.objects.create(
            name="TM", organization=cls.organization
        )
        cls.gateway_library = ComponentLibrary.objects.create(
            name="API Gateway", category=ComponentLibrary.Category.PROCESS
        )
        cls.injection = ThreatLibrary.objects.create(name="Injection", description="d")
        cls.eavesdropping = ThreatLibrary.objects.create(
            name="Eavesdropping", description="d"
        )
        ComponentLibraryThreat.objects.create(
            component_library=cls.gateway_library,
            threat_library=cls.injection,
            applies_to=ComponentLibraryThreat.AppliesTo.COMPONENT,
        )
        ComponentLibraryThreat.objects.create(
            component_library=cls.gateway_library,
            threat_library=cls.eavesdropping,
            applies_to=ComponentLibraryThreat.AppliesTo.FLOW,
        )
        first_blueprint = cls.threat_model.default_blueprint
        second_blueprint = Blueprint.objects.create(
            threat_model=cls.threat_model, name="Second", display_order=2
        )
        cls.gateway = OrgsystemComponent.objects.create(
            blueprint=first_blueprint,
            name="Gateway",
            component_library=cls.gateway_library,
        )
        cls.database = OrgsystemComponent.objects.create(
            blueprint=first_blueprint, name="DB", category="datastore"
        )
        cls.flow = Flow.objects.create(
            blueprint=first_blueprint,
            source_component=cls.gateway,
            dest_component=cls.database,
            label="Query",
        )
        cls.second_gateway = OrgsystemComponent.objects.create(
            blueprint=second_blueprint,
            name="Second gateway",
            component_library=cls.gateway_library,
        )

    def _client(self, user):
        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(user).access_token}"
        )
        return client

    def setUp(self):
        self.client = self._client(self.user)
        self.url = f"/api/threat-models/{self.threat_model.id}/generate-threats/"

    def _generated(self):
        return set(
            InstanceThreat.objects.filter(
                threat_model=self.threat_model, threat_library__isnull=False
            ).values_list("threat_library__name", "targets__component__name")
        )

    def test_missing_library_threats_come_back_across_blueprints(self):
        # Generation on creation, then the user deletes the gateway's threat.
        for target in (self.gateway, self.flow, self.second_gateway):
            ensure_generated_threats(target)
        self.assertEqual(
            self._generated(),
            {
                ("Injection", "Gateway"),
                ("Eavesdropping", None),
                ("Injection", "Second gateway"),
            },
        )
        InstanceThreat.objects.filter(
            threat_library=self.injection, targets__component=self.gateway
        ).delete()
        self.assertNotIn(("Injection", "Gateway"), self._generated())

        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 200)
        # Three components and one flow visited; one threat recreated.
        self.assertEqual(response.data, {"created": 1, "targets": 4})
        self.assertIn(("Injection", "Gateway"), self._generated())

        # Nothing is missing any more: nothing is created.
        response = self.client.post(self.url)
        self.assertEqual(response.data, {"created": 0, "targets": 4})

    def test_a_fresh_model_gets_everything(self):
        response = self.client.post(self.url)
        self.assertEqual(response.data, {"created": 3, "targets": 4})

    def test_outsider_gets_404(self):
        response = self._client(self.outsider).post(self.url)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self._generated(), set())
