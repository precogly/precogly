"""Tests for GSA-TTS/TTSE-petrified-forest-sspp#82/#81: CDX poam:* property import.

The CycloneDX importer must map ``poam:*`` properties onto the existing
``InstanceCountermeasure`` -- annotating the control rather than creating a
new entity -- using the fields that already existed before this PR wherever
possible (per maintainer review on #559):

- ``poam:scheduled-completion`` -> the pre-existing ``due_date`` field
  (not a parallel ``scheduled_completion`` column).
- ``poam:id`` -> ``format_metadata.cyclonedx.poam.id`` (not a first-class
  ``poam_id`` column); this is sufficient for round-tripping and matches
  how other CDX-origin properties are already preserved.
"""

from datetime import date

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.organizations.models import (
    Organization,
    OrganizationMember,
    Team,
    TeamMembership,
)
from apps.threats.models import InstanceCountermeasure

from ..adapters import CycloneDxAdapter

User = get_user_model()


def _minimal_blueprint_with_control(control_data):
    return {
        "specFormat": "CycloneDX",
        "specVersion": "2.0",
        "blueprints": [{"name": "Poam Import Test"}],
        "controls": [control_data],
    }


class CdxPoamImportTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            username="cdxpoam", email="cdxpoam@test.org", password="pw"
        )
        cls.org = Organization.objects.create(
            name="CDX Poam Org", domain="cdxpoam.test"
        )
        OrganizationMember.objects.create(
            organization=cls.org, user=cls.user, role="security_team"
        )
        cls.team = Team.objects.create(
            organization=cls.org, name="Default Team", code="default"
        )
        TeamMembership.objects.create(team=cls.team, user=cls.user, role="lead")
        cls.adapter = CycloneDxAdapter()

    def test_poam_properties_populate_countermeasure(self):
        json_data = _minimal_blueprint_with_control(
            {
                "bom-ref": "control-poam-1",
                "name": "Encrypt data at rest",
                "status": "recommended",
                "properties": [
                    {"name": "poam:id", "value": "POAM-42"},
                    {"name": "poam:scheduled-completion", "value": "2026-12-31"},
                ],
            }
        )
        threat_model, _ = self.adapter.import_data(json_data, self.org, self.user)

        cm = InstanceCountermeasure.objects.get(threat_model=threat_model)
        self.assertEqual(cm.due_date, date(2026, 12, 31))
        self.assertEqual(cm.source, InstanceCountermeasure.Source.VAULT_IMPORT)
        self.assertEqual(cm.format_metadata["cyclonedx"]["poam"]["id"], "POAM-42")

    def test_invalid_scheduled_completion_date_is_warned_and_ignored(self):
        json_data = _minimal_blueprint_with_control(
            {
                "bom-ref": "control-poam-2",
                "name": "Bad date control",
                "status": "recommended",
                "properties": [
                    {"name": "poam:id", "value": "POAM-43"},
                    {"name": "poam:scheduled-completion", "value": "not-a-date"},
                ],
            }
        )
        threat_model, summary = self.adapter.import_data(json_data, self.org, self.user)

        cm = InstanceCountermeasure.objects.get(threat_model=threat_model)
        self.assertEqual(cm.format_metadata["cyclonedx"]["poam"]["id"], "POAM-43")
        self.assertIsNone(cm.due_date)
        self.assertTrue(
            any("scheduled-completion" in w for w in summary.get("warnings", []))
        )

    def test_control_without_poam_properties_defaults_to_manual_source(self):
        json_data = _minimal_blueprint_with_control(
            {
                "bom-ref": "control-plain-1",
                "name": "Plain control",
                "status": "recommended",
            }
        )
        threat_model, _ = self.adapter.import_data(json_data, self.org, self.user)

        cm = InstanceCountermeasure.objects.get(threat_model=threat_model)
        self.assertNotIn("poam", cm.format_metadata.get("cyclonedx", {}))
        self.assertIsNone(cm.due_date)
        self.assertEqual(cm.source, InstanceCountermeasure.Source.MANUAL)

    def test_vault_origination_sets_vault_import_source_without_poam(self):
        json_data = _minimal_blueprint_with_control(
            {
                "bom-ref": "control-inherited-1",
                "name": "Inherited control",
                "status": "recommended",
                "properties": [
                    {"name": "vault:origination", "value": "inherited"},
                    {"name": "vault:providing-system", "value": "Platform IAM"},
                ],
            }
        )
        threat_model, _ = self.adapter.import_data(json_data, self.org, self.user)

        cm = InstanceCountermeasure.objects.get(threat_model=threat_model)
        self.assertTrue(cm.is_inherited)
        self.assertEqual(cm.source, InstanceCountermeasure.Source.VAULT_IMPORT)
        self.assertNotIn("poam", cm.format_metadata.get("cyclonedx", {}))
