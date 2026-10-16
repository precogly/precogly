"""Tests for InstanceThreatTaxonomyEntry model and viewset, on the merged threat table."""

from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import OrgsystemComponent
from apps.threat_models.models import ThreatModel
from apps.threats.models import (
    ExternalTaxonomy,
    InstanceThreatTaxonomyEntry,
    TaxonomyEntry,
    ThreatLibrary,
    ThreatLibraryTaxonomyEntry,
)
from apps.threats.services import create_instance_threat

User = get_user_model()


class InstanceTaxonomyTestCase(TestCase):
    """Base class with shared fixtures."""

    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Test Org", domain="test.org")
        cls.user = User.objects.create_user(
            username="testuser", email="test@test.org", password="testpass123"
        )
        OrganizationMember.objects.create(
            organization=cls.org, user=cls.user, role="security_team"
        )

        cls.tm = ThreatModel.objects.create(name="Test TM", organization=cls.org)
        cls.component = OrgsystemComponent.objects.create(
            blueprint=cls.tm.default_blueprint, name="Test Component"
        )
        cls.threat = create_instance_threat(
            cls.tm, targets=[cls.component], level="high"
        )

        cls.taxonomy = ExternalTaxonomy.objects.create(slug="stride", name="STRIDE")
        cls.entry_tampering = TaxonomyEntry.objects.create(
            taxonomy=cls.taxonomy, external_id="tampering", title="Tampering"
        )
        cls.entry_spoofing = TaxonomyEntry.objects.create(
            taxonomy=cls.taxonomy, external_id="spoofing", title="Spoofing"
        )

        cls.capec_taxonomy = ExternalTaxonomy.objects.create(slug="capec", name="CAPEC")
        cls.entry_capec_66 = TaxonomyEntry.objects.create(
            taxonomy=cls.capec_taxonomy, external_id="66", title="SQL Injection"
        )


class ModelConstraintTests(InstanceTaxonomyTestCase):
    """UniqueConstraint on (taxonomy_entry, threat)."""

    def test_create_with_threat_succeeds(self):
        entry = InstanceThreatTaxonomyEntry.objects.create(
            taxonomy_entry=self.entry_tampering, threat=self.threat
        )
        self.assertEqual(entry.threat, self.threat)

    def test_duplicate_taxonomy_entry_on_a_threat_fails(self):
        InstanceThreatTaxonomyEntry.objects.create(
            taxonomy_entry=self.entry_tampering, threat=self.threat
        )
        with self.assertRaises(IntegrityError):
            InstanceThreatTaxonomyEntry.objects.create(
                taxonomy_entry=self.entry_tampering, threat=self.threat
            )

    def test_different_entries_same_threat_succeeds(self):
        InstanceThreatTaxonomyEntry.objects.create(
            taxonomy_entry=self.entry_tampering, threat=self.threat
        )
        entry2 = InstanceThreatTaxonomyEntry.objects.create(
            taxonomy_entry=self.entry_spoofing, threat=self.threat
        )
        self.assertIsNotNone(entry2.pk)


class APITests(InstanceTaxonomyTestCase):
    """Test the InstanceThreatTaxonomyEntryViewSet CRUD endpoints."""

    def setUp(self):
        self.client = APIClient()
        token = str(RefreshToken.for_user(self.user).access_token)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

    def test_create_entry(self):
        response = self.client.post(
            "/api/threat-taxonomy-entries/",
            {"taxonomyEntry": self.entry_tampering.pk, "threat": self.threat.pk},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        data = response.json()
        self.assertEqual(data["taxonomySlug"], "stride")
        self.assertEqual(data["externalId"], "tampering")
        self.assertEqual(data["title"], "Tampering")

    def test_create_entry_marks_a_generated_threat_as_edited(self):
        generated = create_instance_threat(
            self.tm,
            targets=[self.component],
            level="low",
            auto_generated=True,
        )
        response = self.client.post(
            "/api/threat-taxonomy-entries/",
            {"taxonomyEntry": self.entry_tampering.pk, "threat": generated.pk},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        generated.refresh_from_db()
        self.assertFalse(generated.auto_generated)

    def test_list_filtered_by_threat(self):
        InstanceThreatTaxonomyEntry.objects.create(
            taxonomy_entry=self.entry_tampering, threat=self.threat
        )
        InstanceThreatTaxonomyEntry.objects.create(
            taxonomy_entry=self.entry_spoofing, threat=self.threat
        )
        response = self.client.get(
            f"/api/threat-taxonomy-entries/?threat={self.threat.pk}"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        results = data.get("results", data)
        self.assertEqual(len(results), 2)

    def test_delete_entry(self):
        entry = InstanceThreatTaxonomyEntry.objects.create(
            taxonomy_entry=self.entry_tampering, threat=self.threat
        )
        response = self.client.delete(f"/api/threat-taxonomy-entries/{entry.pk}/")
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(
            InstanceThreatTaxonomyEntry.objects.filter(pk=entry.pk).exists()
        )

    def test_duplicate_returns_400(self):
        InstanceThreatTaxonomyEntry.objects.create(
            taxonomy_entry=self.entry_tampering, threat=self.threat
        )
        response = self.client.post(
            "/api/threat-taxonomy-entries/",
            {"taxonomyEntry": self.entry_tampering.pk, "threat": self.threat.pk},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_validation_requires_a_threat(self):
        response = self.client.post(
            "/api/threat-taxonomy-entries/",
            {"taxonomyEntry": self.entry_tampering.pk},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_org_scoping(self):
        other_org = Organization.objects.create(name="Other Org", domain="other.org")
        other_user = User.objects.create_user(
            username="otheruser", email="other@other.org", password="testpass123"
        )
        OrganizationMember.objects.create(
            organization=other_org, user=other_user, role="security_team"
        )

        entry = InstanceThreatTaxonomyEntry.objects.create(
            taxonomy_entry=self.entry_tampering, threat=self.threat
        )

        other_client = APIClient()
        other_token = str(RefreshToken.for_user(other_user).access_token)
        other_client.credentials(HTTP_AUTHORIZATION=f"Bearer {other_token}")

        response = other_client.get(f"/api/threat-taxonomy-entries/{entry.pk}/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class MergeLogicTests(InstanceTaxonomyTestCase):
    """Library and instance taxonomy entries merge in the threat payload."""

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.library = ThreatLibrary.objects.create(
            name="SQL Injection", description="SQL injection threat"
        )
        cls.threat_with_library = create_instance_threat(
            cls.tm,
            targets=[cls.component],
            threat_library=cls.library,
            level="high",
        )
        ThreatLibraryTaxonomyEntry.objects.create(
            threat_library=cls.library, taxonomy_entry=cls.entry_tampering
        )

    def setUp(self):
        self.client = APIClient()
        token = str(RefreshToken.for_user(self.user).access_token)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

    def _entries(self, threat):
        response = self.client.get(f"/api/threats/{threat.pk}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        return {
            (e["taxonomySlug"], e["externalId"]): e["source"]
            for e in response.json()["taxonomyEntries"]
        }

    def test_instance_entry_adds_to_library_entries(self):
        InstanceThreatTaxonomyEntry.objects.create(
            taxonomy_entry=self.entry_capec_66, threat=self.threat_with_library
        )
        self.assertEqual(
            self._entries(self.threat_with_library),
            {("stride", "tampering"): "library", ("capec", "66"): "instance"},
        )

    def test_instance_override_deduplicates_by_taxonomy_and_external_id(self):
        InstanceThreatTaxonomyEntry.objects.create(
            taxonomy_entry=self.entry_tampering, threat=self.threat_with_library
        )
        self.assertEqual(
            self._entries(self.threat_with_library),
            {("stride", "tampering"): "library"},
        )

    def test_custom_threat_only_has_instance_entries(self):
        custom_threat = create_instance_threat(
            self.tm, targets=[self.component], level="medium"
        )
        InstanceThreatTaxonomyEntry.objects.create(
            taxonomy_entry=self.entry_spoofing, threat=custom_threat
        )
        self.assertIsNone(custom_threat.threat_library)
        self.assertEqual(
            self._entries(custom_threat), {("stride", "spoofing"): "instance"}
        )
