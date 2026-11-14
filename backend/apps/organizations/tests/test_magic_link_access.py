"""The magic link share payload: what an anonymous viewer gets."""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from apps.diagrams.models import DFD
from apps.organizations.models import MagicLink, Organization
from apps.systems.models import ComponentLibrary
from apps.threat_models.models import ThreatModel

User = get_user_model()


def node(node_id, technology=None):
    data = {"label": node_id}
    if technology is not None:
        data["technology"] = technology
    return {
        "id": node_id,
        "type": "process",
        "position": {"x": 0, "y": 0},
        "data": data,
    }


class MagicLinkAccessTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="u", email="u@org.test", password="x"
        )
        cls.cloudformation = ComponentLibrary.objects.create(
            slug="cloudformation",
            qualified_slug="aws/cloudformation",
            name="AWS CloudFormation",
            category="process",
            component_type="infrastructure",
            icon_svg="<svg><title>cf</title></svg>",
        )
        ComponentLibrary.objects.create(
            slug="s3",
            qualified_slug="aws/s3",
            name="Amazon S3",
            category="datastore",
            component_type="storage",
            icon_svg="<svg><title>s3</title></svg>",
        )

    def _share(self, threat_model):
        link = MagicLink.objects.create(
            threat_model=threat_model,
            token=f"token-{threat_model.pk}",
            created_by=self.user,
            expires_at=timezone.now() + timedelta(days=1),
        )
        response = APIClient().get(f"/api/share/{link.token}/")
        self.assertEqual(response.status_code, 200, response.data)
        return response.data

    def test_payload_carries_the_technologies_the_diagrams_reference(self):
        threat_model = ThreatModel.objects.create(
            name="AWS", organization=self.organization
        )
        DFD.objects.create(
            blueprint=threat_model.default_blueprint,
            name="Main",
            is_primary=True,
            canvas_data={
                "nodes": [
                    node("n1", "cloudformation"),
                    node("n2", "cloudformation"),  # referenced twice, sent once
                    node(
                        "n3", "amazon s3"
                    ),  # a legacy display name, matched ignoring case
                    node("n4", "custom-thing"),  # unknown to the library, left out
                    node("n5"),  # no technology
                ]
            },
        )

        payload = self._share(threat_model)

        technologies = {t["id"]: t for t in payload["technologies"]}
        self.assertEqual(set(technologies), {"cloudformation", "s3"})
        self.assertEqual(technologies["cloudformation"]["name"], "AWS CloudFormation")
        self.assertEqual(
            technologies["cloudformation"]["icon_svg"], "<svg><title>cf</title></svg>"
        )
        self.assertEqual(technologies["s3"]["name"], "Amazon S3")

    def test_payload_without_technologies_is_an_empty_list(self):
        threat_model = ThreatModel.objects.create(
            name="Plain", organization=self.organization
        )
        DFD.objects.create(
            blueprint=threat_model.default_blueprint,
            name="Main",
            is_primary=True,
            canvas_data={"nodes": [node("n1")]},
        )

        payload = self._share(threat_model)

        self.assertEqual(payload["technologies"], [])
        self.assertTrue(payload["read_only"])
