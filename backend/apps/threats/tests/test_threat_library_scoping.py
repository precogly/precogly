"""What the ``component_id`` filter on ``/threat-library/`` may offer.

A component library maps two different things through the same join table: the
threats a component carries itself, and the threats its *connections* carry. An
API gateway maps eavesdropping and replay so that flows touching it inherit
them — those threats belong on the data flow, never on the gateway.

The picker filtered by component library but not by ``applies_to``, so it
offered flow-scoped threats when adding to a component, and users added them
there. The AI ranker never had the bug because
``candidate_library_threats`` filtered correctly; these tests pin the two paths
to the same rule.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import ComponentLibrary, OrgsystemComponent
from apps.threat_models.models import ThreatModel
from apps.threats.models import ComponentLibraryThreat, ThreatLibrary

User = get_user_model()


class ThreatLibraryComponentScopingTests(TestCase):
    """The ``component_id`` filter must exclude flow-only threats."""

    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Scoping Org", domain="scope.test")
        cls.user = User.objects.create_user(
            username="scopeuser", email="scope@scope.test", password="testpass123"
        )
        OrganizationMember.objects.create(
            organization=cls.org, user=cls.user, role="security_team"
        )

        # An API gateway, mapped to one threat of each scope — the exact shape
        # that produced the bug in the aws-mini pack.
        gateway_library = ComponentLibrary.objects.create(
            name="API Gateway", category=ComponentLibrary.Category.PROCESS
        )
        threat_model = ThreatModel.objects.create(name="Payments", organization=cls.org)
        cls.component = OrgsystemComponent.objects.create(
            blueprint=threat_model.default_blueprint,
            component_library=gateway_library,
            name="Payments API Gateway",
        )

        cls.own_threat = ThreatLibrary.objects.create(name="Unauthorized API Access")
        cls.shared_threat = ThreatLibrary.objects.create(name="API Injection")
        cls.flow_threat = ThreatLibrary.objects.create(name="Data Eavesdropping")

        for threat, applies_to in (
            (cls.own_threat, ComponentLibraryThreat.AppliesTo.COMPONENT),
            (cls.shared_threat, ComponentLibraryThreat.AppliesTo.BOTH),
            (cls.flow_threat, ComponentLibraryThreat.AppliesTo.FLOW),
        ):
            ComponentLibraryThreat.objects.create(
                component_library=gateway_library,
                threat_library=threat,
                applies_to=applies_to,
            )

    def setUp(self):
        self.client = APIClient()
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(self.user).access_token}"
        )

    def _names_for_component(self):
        response = self.client.get(
            f"/api/threat-library/?component_id={self.component.pk}"
        )
        self.assertEqual(response.status_code, 200)
        return {item["name"] for item in response.data}

    def test_flow_only_threats_are_not_offered_for_a_component(self):
        self.assertNotIn("Data Eavesdropping", self._names_for_component())

    def test_component_and_both_scoped_threats_are_offered(self):
        names = self._names_for_component()
        self.assertIn("Unauthorized API Access", names)
        self.assertIn("API Injection", names)

    def test_unfiltered_listing_still_returns_flow_threats(self):
        """The scope rule belongs to the component filter, not the catalogue.

        Without ``component_id`` this endpoint is the whole library — a flow
        threat is a real entry and must still be listed, or browsing the
        catalogue would silently hide part of a pack.
        """
        response = self.client.get("/api/threat-library/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Data Eavesdropping", {item["name"] for item in response.data})
