"""API regression tests for data assets linked to data flows."""

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import DataAsset, Flow, FlowAsset, OrgsystemComponent
from apps.threat_models.models import ThreatModel

User = get_user_model()


class FlowAssetAPITests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Acme")
        cls.other_organization = Organization.objects.create(name="Globex")
        cls.member = User.objects.create_user(
            username="member", email="member@acme.test", password="pw"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.member
        )

        cls.threat_model = ThreatModel.objects.create(
            organization=cls.organization,
            created_by=cls.member,
            name="Acme threat model",
        )
        cls.other_threat_model = ThreatModel.objects.create(
            organization=cls.other_organization,
            created_by=cls.member,
            name="Globex threat model",
        )

    def setUp(self):
        self.client.force_authenticate(self.member)

    @staticmethod
    def _flow(threat_model, label):
        source = OrgsystemComponent.objects.create(
            name=f"{label} source", blueprint=threat_model.default_blueprint
        )
        destination = OrgsystemComponent.objects.create(
            name=f"{label} destination", blueprint=threat_model.default_blueprint
        )
        return Flow.objects.create(
            blueprint=source.blueprint,
            source_component=source,
            dest_component=destination,
            label=label,
        )

    def test_created_asset_link_is_returned_for_threat_model_components(self):
        flow = self._flow(self.threat_model, "Acme flow")
        asset = DataAsset.objects.create(
            blueprint=self.threat_model.default_blueprint,
            name="Customer records",
            classification="confidential",
        )

        create_response = self.client.post(
            "/api/flow-assets/",
            {"flow": flow.id, "dataAsset": asset.id, "protectionMethod": "none"},
            format="json",
        )
        self.assertEqual(
            create_response.status_code, status.HTTP_201_CREATED, create_response.data
        )

        list_response = self.client.get("/api/flow-assets/", {"flow": flow.id})
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        self.assertEqual(list_response.data["count"], 1)
        self.assertEqual(list_response.data["results"][0]["data_asset"], asset.id)

    def test_asset_links_from_other_organizations_are_not_returned(self):
        flow = self._flow(self.other_threat_model, "Globex flow")
        asset = DataAsset.objects.create(
            blueprint=self.other_threat_model.default_blueprint,
            name="Private records",
            classification="confidential",
        )
        FlowAsset.objects.create(flow=flow, data_asset=asset)

        response = self.client.get("/api/flow-assets/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 0)
