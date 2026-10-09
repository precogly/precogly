"""``format_metadata`` cannot be written through the API.

It holds what an import kept for round-tripping (bom-refs, custom type objects,
passthrough sections). A client that could change or drop it would break the
next export, so every serializer that exposes it marks it read-only (plan N3).
"""

import inspect

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework import serializers as drf_serializers
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import Organization, OrganizationMember
from apps.systems import serializers as systems_serializers
from apps.systems.models import OrgsystemComponent
from apps.threat_models import serializers as threat_model_serializers
from apps.threat_models.models import ThreatModel
from apps.threats import serializers as threats_serializers
from apps.threats.services import create_instance_threat

User = get_user_model()

SERIALIZER_MODULES = (
    systems_serializers,
    threats_serializers,
    threat_model_serializers,
)


class SerializerDeclarationTests(TestCase):
    def test_every_serializer_exposing_format_metadata_marks_it_read_only(self):
        offenders = []
        for module in SERIALIZER_MODULES:
            for name, serializer_class in inspect.getmembers(module, inspect.isclass):
                if not issubclass(serializer_class, drf_serializers.ModelSerializer):
                    continue
                if serializer_class.__module__ != module.__name__:
                    continue
                meta = getattr(serializer_class, "Meta", None)
                fields = getattr(meta, "fields", None) or ()
                if "format_metadata" not in fields:
                    continue
                read_only = getattr(meta, "read_only_fields", None) or ()
                if "format_metadata" not in read_only:
                    offenders.append(f"{module.__name__}.{name}")
        self.assertEqual(offenders, [])


class ApiWriteTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="writer", email="writer@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        cls.threat_model = ThreatModel.objects.create(
            name="TM",
            organization=cls.organization,
            format_metadata={"cyclonedx": {"serial": "kept"}},
        )
        cls.component = OrgsystemComponent.objects.create(
            blueprint=cls.threat_model.default_blueprint, name="API"
        )
        cls.threat = create_instance_threat(
            cls.component.blueprint.threat_model,
            targets=[cls.component],
            level="high",
            format_metadata={"cyclonedx": {"bom_ref": "scenario-7"}},
        )

    def setUp(self):
        self.client = APIClient()
        token = RefreshToken.for_user(self.user).access_token
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

    def test_patch_on_a_threat_leaves_format_metadata_alone(self):
        response = self.client.patch(
            f"/api/threats/{self.threat.id}/",
            {"format_metadata": {}, "decision_rationale": "changed"},
            format="json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.threat.refresh_from_db()
        self.assertEqual(self.threat.decision_rationale, "changed")
        self.assertEqual(
            self.threat.format_metadata, {"cyclonedx": {"bom_ref": "scenario-7"}}
        )

    def test_patch_on_a_threat_model_leaves_format_metadata_alone(self):
        response = self.client.patch(
            f"/api/threat-models/{self.threat_model.id}/",
            {"format_metadata": {"cyclonedx": {}}, "description": "changed"},
            format="json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.threat_model.refresh_from_db()
        self.assertEqual(self.threat_model.description, "changed")
        self.assertEqual(
            self.threat_model.format_metadata, {"cyclonedx": {"serial": "kept"}}
        )

    def test_format_metadata_is_still_readable(self):
        response = self.client.get(f"/api/threats/{self.threat.id}/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data["format_metadata"], {"cyclonedx": {"bom_ref": "scenario-7"}}
        )
