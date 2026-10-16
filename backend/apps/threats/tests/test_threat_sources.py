"""Threat sources edited through the API (major-changes/threat-sources-ui.md).

The four NIST SP 800-30 sources are shared reference rows seeded by migration
``threats/0005``. Editing them reverses plan decision L2 for sources only.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import OrgsystemComponent
from apps.threat_models.models import ThreatModel
from apps.threat_models.tmbom import TmBomAdapter
from apps.threat_models.tmbom.properties import PropertyOwner, read_properties
from apps.threat_models.tmbom.testing import assert_valid_tmbom
from apps.threats.models import ThreatLibrary, ThreatSource
from apps.threats.services import create_instance_threat

User = get_user_model()


class ThreatSourceEditTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="sec", email="sec@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        cls.threat_model = ThreatModel.objects.create(
            name="TM", organization=cls.organization
        )
        cls.api = OrgsystemComponent.objects.create(
            blueprint=cls.threat_model.default_blueprint, name="API"
        )
        cls.adversarial = ThreatSource.objects.get(slug="adversarial")
        cls.accidental = ThreatSource.objects.get(slug="accidental")

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        self.threat = create_instance_threat(
            self.threat_model, targets=[self.api], threat_name="SQLi"
        )

    def patch_sources(self, source_ids, threat=None):
        threat = threat or self.threat
        return self.client.patch(
            f"/api/threats/{threat.id}/",
            {"threat_source_ids": source_ids},
            format="json",
        )

    def source_slugs(self, threat=None):
        threat = threat or self.threat
        return sorted(threat.source_links.values_list("source__slug", flat=True))

    def test_set_replace_and_clear(self):
        response = self.patch_sources([self.adversarial.id, self.accidental.id])
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(self.source_slugs(), ["accidental", "adversarial"])
        self.assertEqual(
            sorted(source["slug"] for source in response.data["threat_sources"]),
            ["accidental", "adversarial"],
        )

        self.patch_sources([self.accidental.id, self.accidental.id])
        self.assertEqual(self.source_slugs(), ["accidental"])

        self.patch_sources([])
        self.assertEqual(self.source_slugs(), [])

    def test_unknown_id_is_refused_and_changes_nothing(self):
        self.patch_sources([self.adversarial.id])
        unknown_id = ThreatSource.objects.order_by("-id").first().id + 100
        response = self.patch_sources([self.accidental.id, unknown_id])
        self.assertEqual(response.status_code, 400, response.content)
        self.assertIn("threat_source_ids", response.data)
        self.assertEqual(self.source_slugs(), ["adversarial"])

    def test_leaving_the_field_out_keeps_the_sources(self):
        self.patch_sources([self.adversarial.id])
        response = self.client.patch(
            f"/api/threats/{self.threat.id}/",
            {"triage_status": "accept"},
            format="json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(self.source_slugs(), ["adversarial"])

    def test_create_with_sources(self):
        response = self.client.post(
            "/api/threats/",
            {
                "threat_model": self.threat_model.id,
                "threat_name": "Phishing",
                "whole_system": True,
                "threat_source_ids": [self.adversarial.id],
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(
            [source["slug"] for source in response.data["threat_sources"]],
            ["adversarial"],
        )

    def test_a_sources_edit_marks_a_generated_threat_edited(self):
        generated = create_instance_threat(
            self.threat_model,
            targets=[self.api],
            threat_name="Generated",
            auto_generated=True,
        )
        self.patch_sources([self.adversarial.id], threat=generated)
        generated.refresh_from_db()
        self.assertFalse(generated.auto_generated)

    def export_sources(self):
        document = TmBomAdapter().export_data(self.threat_model)
        assert_valid_tmbom(document, context="threat sources")
        abstract = {entry["name"]: entry for entry in document["threats"]["threats"]}
        # read_properties gives a repeatable property as a list of values;
        # each value here is one scenario's list of slugs.
        scenario_sources = [
            value
            for entry in document["threats"]["scenarios"]
            for value in read_properties(
                entry.get("properties"), PropertyOwner.SCENARIO
            ).get("precogly:threat-sources", [])
        ]
        return abstract, scenario_sources

    def test_export_writes_origin_only_when_every_scenario_agrees(self):
        library = ThreatLibrary.objects.create(name="Injection", description="d")
        first = create_instance_threat(
            self.threat_model, targets=[self.api], threat_library=library
        )
        second = create_instance_threat(
            self.threat_model, whole_system=True, threat_library=library
        )
        self.patch_sources([self.adversarial.id], threat=first)
        self.patch_sources([self.adversarial.id], threat=second)
        abstract, _sources = self.export_sources()
        self.assertEqual(abstract["Injection"]["origin"], "adversarial")

        self.patch_sources([self.accidental.id], threat=second)
        abstract, scenario_sources = self.export_sources()
        self.assertNotIn("origin", abstract["Injection"])
        self.assertIn(["adversarial"], scenario_sources)
        self.assertIn(["accidental"], scenario_sources)
