"""Cross-check with the guest editor (plan 11.9, 9.10 item 3).

A file the guest editor saved (``fixtures/tmbom/guest-editor-export.cdx.json``,
a copy of ``frontend/src/features/guest-editor/__tests__/fixtures/``) imports
into the backend with no warnings and the same threats, targets and numbers.
Regenerate the frontend fixture with ``GUEST_WRITE_FIXTURES=1 npx vitest run
src/features/guest-editor/__tests__/fixtures.test.ts`` when the adapter changes.
"""

import json
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import Boundary, Flow, OrgsystemComponent, Zone
from apps.threat_models.models import ThreatModelState
from apps.threat_models.tmbom import TmBomAdapter
from apps.threat_models.tmbom.importer.document import import_document
from apps.threat_models.tmbom.testing import assert_valid_tmbom
from apps.threats.models import InstanceCountermeasure, InstanceThreat

User = get_user_model()
FIXTURE = Path(__file__).parent / "fixtures" / "tmbom" / "guest-editor-export.cdx.json"


class GuestEditorFixtureTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="owner", email="owner@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        cls.document = json.loads(FIXTURE.read_text())

    def test_fixture_is_valid(self):
        assert_valid_tmbom(self.document, context="guest editor export")

    def test_imports_with_no_warnings(self):
        threat_model, summary = import_document(
            json.loads(json.dumps(self.document)), self.organization, self.user
        )
        self.assertEqual(summary.get("warnings", []), [])
        self.assertEqual(threat_model.name, "Web shop")
        blueprint = threat_model.default_blueprint
        self.assertEqual(Zone.objects.filter(blueprint=blueprint).count(), 2)
        self.assertEqual(Boundary.objects.filter(blueprint=blueprint).count(), 1)
        self.assertEqual(
            OrgsystemComponent.objects.filter(blueprint=blueprint).count(), 4
        )
        self.assertEqual(Flow.objects.filter(blueprint=blueprint).count(), 3)

        threats = list(
            InstanceThreat.objects.filter(threat_model=threat_model).order_by("number")
        )
        self.assertEqual(
            [
                (t.number, t.threat_name, t.rating.level, t.whole_system)
                for t in threats
            ],
            [
                (1, "SQL Injection", "high", False),
                (2, "Session hijacking", "medium", False),
                (3, "No backup tested", "info", True),
                (4, "Lateral movement in the core network", "low", False),
            ],
        )
        self.assertEqual(
            sorted(row.target_kind for row in threats[0].targets.all()),
            ["component", "flow"],
        )
        self.assertEqual(
            sorted(row.target_kind for row in threats[1].targets.all()),
            ["boundary", "flow"],
        )
        self.assertEqual(
            [row.target_kind for row in threats[3].targets.all()], ["zone"]
        )
        self.assertEqual(threats[2].triage_status, "accept")

        controls = list(
            InstanceCountermeasure.objects.filter(threat_model=threat_model).order_by(
                "number"
            )
        )
        self.assertEqual(
            [(c.number, c.countermeasure_name) for c in controls],
            [(1, "Input Validation"), (2, "Short-lived tokens")],
        )
        self.assertEqual(
            sorted(link.threat.number for link in controls[1].threat_links.all()),
            [1, 2],
        )
        self.assertEqual(
            [row.target_kind for row in controls[0].targets.all()], ["component"]
        )
        self.assertEqual(controls[1].targets.count(), 0)

        state = ThreatModelState.objects.get(threat_model=threat_model)
        self.assertEqual(state.next_threat_number, 5)
        self.assertEqual(state.next_countermeasure_number, 3)

        # The imported model exports to a valid document with the same numbers.
        exported = TmBomAdapter().export_data(threat_model)
        assert_valid_tmbom(exported, context="re-export of the guest file")
        numbers = [
            next(
                int(p["value"])
                for p in scenario["properties"]
                if p["name"] == "precogly:number"
            )
            for scenario in exported["threats"]["scenarios"]
        ]
        self.assertEqual(numbers, [1, 2, 3, 4])
