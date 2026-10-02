"""Regression tests for threat-library search across taxonomy mappings."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import Organization, OrganizationMember
from apps.threats.models import (
    ExternalTaxonomy,
    TaxonomyEntry,
    ThreatLibrary,
    ThreatLibraryTaxonomyEntry,
)

User = get_user_model()


class ThreatLibraryTaxonomySearchTests(TestCase):
    """The search query reaches taxonomy IDs and titles without duplicate rows."""

    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(
            name="Taxonomy Search Org", domain="taxonomy-search.test"
        )
        cls.user = User.objects.create_user(
            username="taxonomysearchuser",
            email="search@taxonomy-search.test",
            password="testpass123",
        )
        OrganizationMember.objects.create(
            organization=cls.org,
            user=cls.user,
            role=OrganizationMember.Role.SECURITY_TEAM,
        )

        taxonomy = ExternalTaxonomy.objects.create(name="CWE", slug="cwe-search")
        improper_input_validation = TaxonomyEntry.objects.create(
            taxonomy=taxonomy,
            external_id="CWE-20",
            title="Improper Input Validation",
        )
        weak_validation_boundary = TaxonomyEntry.objects.create(
            taxonomy=taxonomy,
            external_id="CWE-999",
            title="Weak Validation Boundary",
        )
        exposure_of_sensitive_information = TaxonomyEntry.objects.create(
            taxonomy=taxonomy,
            external_id="CWE-200",
            title="Exposure of Sensitive Information",
        )

        cls.input_threat = ThreatLibrary.objects.create(
            name="Untrusted Boundary Handling",
            description="Untrusted data crosses a processing boundary.",
        )
        cls.exposure_threat = ThreatLibrary.objects.create(
            name="Sensitive Record Disclosure",
            description="Private records become visible to an unintended party.",
        )
        cls.unrelated_threat = ThreatLibrary.objects.create(
            name="Credential Replay",
            description="A falconmarker token is reused by an attacker.",
        )

        for entry in (improper_input_validation, weak_validation_boundary):
            ThreatLibraryTaxonomyEntry.objects.create(
                threat_library=cls.input_threat,
                taxonomy_entry=entry,
            )
        ThreatLibraryTaxonomyEntry.objects.create(
            threat_library=cls.exposure_threat,
            taxonomy_entry=exposure_of_sensitive_information,
        )

    def setUp(self):
        self.client = APIClient()
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(self.user).access_token}"
        )

    def _search(self, query):
        response = self.client.get("/api/threat-library/", {"search": query})
        self.assertEqual(response.status_code, 200)
        return response.data

    def test_search_matches_taxonomy_external_id(self):
        results = self._search("CWE-20")
        result_ids = {item["id"] for item in results}

        self.assertIn(self.input_threat.pk, result_ids)
        self.assertNotIn(self.unrelated_threat.pk, result_ids)

    def test_search_matches_taxonomy_title_and_excludes_unrelated_threats(self):
        results = self._search("Improper Input Validation")

        self.assertEqual(
            [item["id"] for item in results],
            [self.input_threat.pk],
        )

    def test_search_returns_threat_once_when_multiple_taxonomy_entries_match(self):
        results = self._search("Validation")
        result_ids = [item["id"] for item in results]

        self.assertEqual(result_ids.count(self.input_threat.pk), 1)

    def test_existing_name_and_description_search_still_work(self):
        for query in ("Credential Replay", "falconmarker"):
            with self.subTest(query=query):
                results = self._search(query)
                self.assertEqual(
                    [item["id"] for item in results],
                    [self.unrelated_threat.pk],
                )
