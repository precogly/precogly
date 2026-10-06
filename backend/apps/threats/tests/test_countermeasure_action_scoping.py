"""Tenant and threat-model scoping for countermeasure relationship actions."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import DataFlow, OrgsystemComponent
from apps.threat_models.models import ThreatModel
from apps.threats.models import (
    ComponentInstanceThreat,
    CountermeasureLibrary,
    CountermeasureThreatLink,
    DataFlowInstanceThreat,
    InstanceCountermeasure,
)

User = get_user_model()


class CountermeasureActionScopingTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.home_org = Organization.objects.create(name="Home", domain="home.test")
        cls.other_org = Organization.objects.create(name="Other", domain="other.test")
        cls.user = User.objects.create_user(
            username="security",
            email="security@home.test",
            password="testpass123",
        )
        OrganizationMember.objects.create(
            organization=cls.home_org,
            user=cls.user,
            role="security_team",
        )

        cls.home_model = ThreatModel.objects.create(
            name="Home model", organization=cls.home_org
        )
        cls.sibling_model = ThreatModel.objects.create(
            name="Sibling model", organization=cls.home_org
        )
        cls.foreign_model = ThreatModel.objects.create(
            name="Foreign model", organization=cls.other_org
        )
        cls.home_threat = cls._threat(cls.home_model, "Home threat")
        cls.sibling_threat = cls._threat(cls.sibling_model, "Sibling threat")
        cls.foreign_threat = cls._threat(cls.foreign_model, "Foreign threat")
        cls.home_flow_threat = cls._flow_threat(cls.home_model, "Home flow")
        cls.foreign_flow_threat = cls._flow_threat(cls.foreign_model, "Foreign flow")
        cls.home_countermeasure = cls._countermeasure(cls.home_model, "Home control")
        cls.sibling_countermeasure = cls._countermeasure(
            cls.sibling_model, "Sibling control"
        )
        cls.foreign_countermeasure = cls._countermeasure(
            cls.foreign_model, "Foreign control"
        )
        cls.library_countermeasure = CountermeasureLibrary.objects.create(
            name="Library control",
            description="Test control",
        )

    @classmethod
    def _threat(cls, threat_model, name):
        component = OrgsystemComponent.objects.create(
            threat_model=threat_model,
            name=name,
        )
        return ComponentInstanceThreat.objects.create(
            component=component,
            threat_name=name,
            inherent_severity="high",
        )

    @classmethod
    def _countermeasure(cls, threat_model, name):
        return InstanceCountermeasure.objects.create(
            threat_model=threat_model,
            countermeasure_name=name,
            status="verified",
        )

    @classmethod
    def _flow_threat(cls, threat_model, name):
        source = OrgsystemComponent.objects.create(
            threat_model=threat_model,
            name=f"{name} source",
        )
        destination = OrgsystemComponent.objects.create(
            threat_model=threat_model,
            name=f"{name} destination",
        )
        flow = DataFlow.objects.create(
            source_component=source,
            dest_component=destination,
            label=name,
        )
        return DataFlowInstanceThreat.objects.create(
            data_flow=flow,
            threat_name=name,
            inherent_severity="high",
        )

    def setUp(self):
        self.client = APIClient()
        token = str(RefreshToken.for_user(self.user).access_token)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

    def test_apply_rejects_countermeasure_from_other_tenant(self):
        response = self.client.post(
            f"/api/component-threats/{self.home_threat.pk}/apply_countermeasure/",
            {"existingCountermeasureId": self.foreign_countermeasure.pk},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(
            CountermeasureThreatLink.objects.filter(
                countermeasure=self.foreign_countermeasure,
                component_threat=self.home_threat,
            ).exists()
        )

    def test_apply_rejects_countermeasure_from_sibling_model(self):
        response = self.client.post(
            f"/api/component-threats/{self.home_threat.pk}/apply_countermeasure/",
            {"existingCountermeasureId": self.sibling_countermeasure.pk},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_flow_apply_rejects_countermeasure_from_other_tenant(self):
        response = self.client.post(
            f"/api/flow-threats/{self.home_flow_threat.pk}/apply_countermeasure/",
            {"existingCountermeasureId": self.foreign_countermeasure.pk},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_apply_rejects_invalid_status_without_creating_countermeasure(self):
        original_count = InstanceCountermeasure.objects.count()

        response = self.client.post(
            f"/api/component-threats/{self.home_threat.pk}/apply_countermeasure/",
            {
                "countermeasureLibraryId": self.library_countermeasure.pk,
                "status": "not-a-status",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(InstanceCountermeasure.objects.count(), original_count)

    def test_link_rejects_threat_from_other_tenant(self):
        response = self.client.post(
            f"/api/countermeasures/{self.home_countermeasure.pk}/link/",
            {"threatId": self.foreign_threat.pk, "threatType": "component"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(
            CountermeasureThreatLink.objects.filter(
                countermeasure=self.home_countermeasure,
                component_threat=self.foreign_threat,
            ).exists()
        )

    def test_link_rejects_threat_from_sibling_model(self):
        response = self.client.post(
            f"/api/countermeasures/{self.home_countermeasure.pk}/link/",
            {"threatId": self.sibling_threat.pk, "threatType": "component"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_link_rejects_flow_threat_from_other_tenant(self):
        response = self.client.post(
            f"/api/countermeasures/{self.home_countermeasure.pk}/link/",
            {"threatId": self.foreign_flow_threat.pk, "threatType": "flow"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_link_accepts_threat_from_same_model(self):
        response = self.client.post(
            f"/api/countermeasures/{self.home_countermeasure.pk}/link/",
            {"threatId": self.home_threat.pk, "threatType": "component"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(
            CountermeasureThreatLink.objects.filter(
                countermeasure=self.home_countermeasure,
                component_threat=self.home_threat,
            ).exists()
        )

    def test_unlink_rejects_preexisting_cross_model_link(self):
        link = CountermeasureThreatLink.objects.create(
            countermeasure=self.home_countermeasure,
            component_threat=self.foreign_threat,
        )

        response = self.client.post(
            f"/api/countermeasures/{self.home_countermeasure.pk}/unlink/",
            {"threatId": self.foreign_threat.pk, "threatType": "component"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertTrue(CountermeasureThreatLink.objects.filter(pk=link.pk).exists())

    def test_reorder_rejects_cross_model_countermeasures(self):
        CountermeasureThreatLink.objects.create(
            countermeasure=self.home_countermeasure,
            component_threat=self.home_threat,
        )
        CountermeasureThreatLink.objects.create(
            countermeasure=self.sibling_countermeasure,
            component_threat=self.sibling_threat,
        )

        response = self.client.post(
            "/api/countermeasures/reorder/",
            {
                "threatId": self.home_threat.pk,
                "threatType": "component",
                "orderedIds": [
                    self.home_countermeasure.pk,
                    self.sibling_countermeasure.pk,
                ],
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
