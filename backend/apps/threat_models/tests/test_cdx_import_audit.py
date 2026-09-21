"""Tests for GSA-TTS/TTSE-petrified-forest-sspp#31: CDX import completeness.

Covers the three remaining #31 asks that lacked coverage:
  1. Control ``satisfies[]`` -> ``InstanceCountermeasureStandard`` (with the
     FK-miss fallback that stores ``section_code``/``framework_name``).
  3. ``externalReferences`` typed ``evidence`` -> ``evidence_url``.
  5. ``crosses_trust_zone`` set when a flow's endpoints sit in different zones.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.compliance.models import StandardFramework, StandardRequirement
from apps.organizations.models import (
    Organization,
    OrganizationMember,
    Team,
    TeamMembership,
)
from apps.systems.models import DataFlow
from apps.threats.models import InstanceCountermeasure, InstanceCountermeasureStandard

from ..adapters import CycloneDxAdapter

User = get_user_model()


def _blueprint(controls=None, definitions=None, blueprint=None):
    doc = {
        "specFormat": "CycloneDX",
        "specVersion": "2.0",
        "blueprints": [blueprint or {"name": "Import Audit Test"}],
    }
    if definitions is not None:
        doc["definitions"] = definitions
    if controls is not None:
        doc["controls"] = controls
    return doc


class CdxImportAuditTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            username="cdxaudit", email="cdxaudit@test.org", password="pw"
        )
        cls.org = Organization.objects.create(
            name="CDX Audit Org", domain="cdxaudit.test"
        )
        OrganizationMember.objects.create(
            organization=cls.org, user=cls.user, role="security_team"
        )
        cls.team = Team.objects.create(
            organization=cls.org, name="Default Team", code="default"
        )
        TeamMembership.objects.create(team=cls.team, user=cls.user, role="lead")
        cls.adapter = CycloneDxAdapter()

        cls.framework = StandardFramework.objects.create(
            name="NIST 800-53 Rev 5", slug="nist-800-53-r5"
        )
        cls.req_ac2 = StandardRequirement.objects.create(
            framework=cls.framework,
            section_code="AC-2",
            description="Account management",
        )

    # --- item 1: satisfies[] -> InstanceCountermeasureStandard ------------

    def test_satisfies_resolved_requirement_creates_mapping(self):
        json_data = _blueprint(
            definitions={
                "requirements": [
                    {
                        "bom-ref": "req-ac2",
                        "identifier": "AC-2",
                        "title": "Account management",
                        "source": {"name": "NIST 800-53 Rev 5"},
                    }
                ]
            },
            controls=[
                {
                    "bom-ref": "control-ac2",
                    "name": "Account Management",
                    "status": "implemented",
                    "satisfies": ["req-ac2"],
                }
            ],
        )
        tm, _ = self.adapter.import_data(json_data, self.org, self.user)

        cm = InstanceCountermeasure.objects.get(threat_model=tm)
        mapping = InstanceCountermeasureStandard.objects.get(countermeasure=cm)
        self.assertEqual(mapping.requirement, self.req_ac2)
        self.assertEqual(mapping.section_code, "AC-2")
        self.assertEqual(mapping.framework_name, "NIST 800-53 Rev 5")

    def test_satisfies_unresolved_requirement_stores_snapshot(self):
        json_data = _blueprint(
            definitions={
                "requirements": [
                    {
                        "bom-ref": "req-si4",
                        "identifier": "SI-4",
                        "title": "System monitoring",
                        "description": "Monitor the system.",
                        "source": {"name": "NIST 800-53 Rev 5 UNINSTALLED"},
                    }
                ]
            },
            controls=[
                {
                    "bom-ref": "control-si4",
                    "name": "System Monitoring",
                    "status": "implemented",
                    "satisfies": ["req-si4"],
                }
            ],
        )
        tm, _ = self.adapter.import_data(json_data, self.org, self.user)

        cm = InstanceCountermeasure.objects.get(threat_model=tm)
        mapping = InstanceCountermeasureStandard.objects.get(countermeasure=cm)
        self.assertIsNone(mapping.requirement)
        self.assertEqual(mapping.section_code, "SI-4")
        self.assertEqual(mapping.framework_name, "NIST 800-53 Rev 5 UNINSTALLED")
        self.assertEqual(mapping.requirement_description, "Monitor the system.")

    def test_multiple_unresolved_satisfies_create_distinct_snapshots(self):
        json_data = _blueprint(
            definitions={
                "requirements": [
                    {
                        "bom-ref": "req-si4",
                        "identifier": "SI-4",
                        "description": "System monitoring.",
                        "source": {"name": "NIST 800-53 Rev 5 UNINSTALLED"},
                    },
                    {
                        "bom-ref": "req-cp9",
                        "identifier": "CP-9",
                        "description": "System backup.",
                        "source": {"name": "NIST 800-53 Rev 5 UNINSTALLED"},
                    },
                ]
            },
            controls=[
                {
                    "bom-ref": "control-two-reqs",
                    "name": "Monitoring and Backup",
                    "status": "implemented",
                    "satisfies": ["req-si4", "req-cp9"],
                }
            ],
        )
        tm, _ = self.adapter.import_data(json_data, self.org, self.user)

        cm = InstanceCountermeasure.objects.get(threat_model=tm)
        self.assertCountEqual(
            cm.instance_standard_mappings.values_list("section_code", flat=True),
            ["SI-4", "CP-9"],
        )

    def test_satisfies_dangling_reference_warns_and_skips(self):
        json_data = _blueprint(
            controls=[
                {
                    "bom-ref": "control-dangling",
                    "name": "Dangling Satisfies",
                    "status": "implemented",
                    "satisfies": ["req-does-not-exist"],
                }
            ],
        )
        tm, summary = self.adapter.import_data(json_data, self.org, self.user)

        cm = InstanceCountermeasure.objects.get(threat_model=tm)
        self.assertEqual(cm.instance_standard_mappings.count(), 0)
        self.assertTrue(
            any("req-does-not-exist" in w for w in summary.get("warnings", []))
        )

    # --- item 3: externalReferences evidence -> evidence_url --------------

    def test_evidence_external_reference_sets_evidence_url(self):
        json_data = _blueprint(
            controls=[
                {
                    "bom-ref": "control-evidence",
                    "name": "Documented Control",
                    "status": "implemented",
                    "externalReferences": [
                        {"type": "website", "url": "https://example.gov/home"},
                        {"type": "evidence", "url": "https://example.gov/ssp/ac2.pdf"},
                    ],
                }
            ],
        )
        tm, _ = self.adapter.import_data(json_data, self.org, self.user)

        cm = InstanceCountermeasure.objects.get(threat_model=tm)
        self.assertEqual(cm.evidence_url, "https://example.gov/ssp/ac2.pdf")

    def test_control_without_evidence_reference_has_blank_url(self):
        json_data = _blueprint(
            controls=[
                {
                    "bom-ref": "control-plain",
                    "name": "Plain Control",
                    "status": "implemented",
                    "externalReferences": [
                        {"type": "website", "url": "https://example.gov/home"}
                    ],
                }
            ],
        )
        tm, _ = self.adapter.import_data(json_data, self.org, self.user)

        cm = InstanceCountermeasure.objects.get(threat_model=tm)
        self.assertEqual(cm.evidence_url, "")

    # --- item 5: crosses_trust_zone on imported flows ---------------------

    def test_flow_crossing_zones_sets_flag(self):
        json_data = _blueprint(
            blueprint={
                "name": "Zone Flow Test",
                "zones": [
                    {"bom-ref": "zone-dmz", "name": "DMZ", "trustLevel": 30},
                    {"bom-ref": "zone-internal", "name": "Internal", "trustLevel": 80},
                ],
                "assets": [
                    {"bom-ref": "asset-gw", "name": "Gateway", "zone": "zone-dmz"},
                    {
                        "bom-ref": "asset-db",
                        "name": "Database",
                        "zone": "zone-internal",
                    },
                ],
                "flows": [
                    {
                        "bom-ref": "flow-gw-db",
                        "name": "gw-to-db",
                        "source": "asset-gw",
                        "destination": "asset-db",
                    }
                ],
            }
        )
        tm, _ = self.adapter.import_data(json_data, self.org, self.user)

        flow = DataFlow.objects.get(source_component__threat_model=tm)
        self.assertTrue(flow.crosses_trust_zone)

    def test_flow_within_same_zone_does_not_set_flag(self):
        json_data = _blueprint(
            blueprint={
                "name": "Same Zone Flow Test",
                "zones": [
                    {"bom-ref": "zone-internal", "name": "Internal", "trustLevel": 80}
                ],
                "assets": [
                    {"bom-ref": "asset-a", "name": "App A", "zone": "zone-internal"},
                    {"bom-ref": "asset-b", "name": "App B", "zone": "zone-internal"},
                ],
                "flows": [
                    {
                        "bom-ref": "flow-a-b",
                        "name": "a-to-b",
                        "source": "asset-a",
                        "destination": "asset-b",
                    }
                ],
            }
        )
        tm, _ = self.adapter.import_data(json_data, self.org, self.user)

        flow = DataFlow.objects.get(source_component__threat_model=tm)
        self.assertFalse(flow.crosses_trust_zone)

    # --- round-trip: satisfies survives export -> import ------------------

    def test_unresolved_satisfies_round_trips_through_export(self):
        json_data = _blueprint(
            definitions={
                "requirements": [
                    {
                        "bom-ref": "req-si4",
                        "identifier": "SI-4",
                        "title": "System monitoring",
                        "source": {"name": "NIST 800-53 Rev 5 UNINSTALLED"},
                    }
                ]
            },
            controls=[
                {
                    "bom-ref": "control-si4",
                    "name": "System Monitoring",
                    "status": "implemented",
                    "satisfies": ["req-si4"],
                }
            ],
        )
        tm1, _ = self.adapter.import_data(json_data, self.org, self.user)

        exported = self.adapter.export_data(tm1)
        control = exported["controls"][0]
        self.assertIn("satisfies", control)

        org2 = Organization.objects.create(name="RT Org", domain="rt.test")
        OrganizationMember.objects.create(
            organization=org2, user=self.user, role="security_team"
        )
        tm2, _ = self.adapter.import_data(exported, org2, self.user)

        cm2 = InstanceCountermeasure.objects.get(threat_model=tm2)
        mapping = InstanceCountermeasureStandard.objects.get(countermeasure=cm2)
        self.assertIsNone(mapping.requirement)
        self.assertEqual(mapping.section_code, "SI-4")
        self.assertEqual(mapping.framework_name, "NIST 800-53 Rev 5 UNINSTALLED")
