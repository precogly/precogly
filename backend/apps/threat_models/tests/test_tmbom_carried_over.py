"""Tests carried over from the retired adapter suite (plan 9.10 items 5 and 6).

Issue #224: an invalid control status is never persisted and a scenario that
lists the same asset twice does not abort the import. Issue #508 (out-of-scope
items survive import) is covered by ``test_tmbom_blueprint_slice``. The
numbering rules: a document with no numbers gets fresh ones in document
order, a duplicate number is renumbered with a warning, and the counter is
set past the highest number seen.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.organizations.models import Organization, OrganizationMember
from apps.threat_models.models import ThreatModelState
from apps.threat_models.tmbom import TmBomAdapter
from apps.threat_models.tmbom.testing import assert_valid_tmbom
from apps.threats.models import InstanceCountermeasure, InstanceThreat

User = get_user_model()


def minimal_document(**sections) -> dict:
    document = {
        "specFormat": "CycloneDX",
        "specVersion": "2.0",
        "metadata": {
            "component": {"type": "application", "bom-ref": "sys", "name": "X"}
        },
        "blueprints": [
            {
                "name": "Other tool",
                "modelTypes": ["data-flow"],
                "assets": [
                    {"bom-ref": "a1", "name": "Shared component", "type": "process"}
                ],
            }
        ],
    }
    document.update(sections)
    return document


def scenario(ref: str, name: str, number: int | None = None) -> dict:
    entry = {
        "bom-ref": ref,
        "name": name,
        "threats": ["t1"],
        "affectedAssets": ["a1"],
    }
    if number is not None:
        entry["properties"] = [{"name": "precogly:number", "value": str(number)}]
    return entry


class CarriedOverTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="member", email="member@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="member"
        )

    def import_document(self, document):
        assert_valid_tmbom(document, context="input")
        return TmBomAdapter().import_data(document, self.organization, self.user)

    def test_duplicate_affected_asset_does_not_abort_the_import(self):
        """#224: the same asset twice gives one scenario with one target."""
        document = minimal_document(
            threats={
                "threats": [{"bom-ref": "t1", "name": "Duplicate ref threat"}],
                "scenarios": [
                    {
                        **scenario("s1", "Duplicate ref"),
                        "affectedAssets": ["a1", "a1"],
                    }
                ],
            }
        )
        # The schema requires unique items, so the input is not run through the gate.
        imported, summary = TmBomAdapter().import_data(
            document, self.organization, self.user
        )
        threat = InstanceThreat.objects.get(threat_model=imported)
        self.assertEqual(threat.targets.count(), 1)
        self.assertEqual(summary["threats"], 1)

    def test_spec_status_proposed_is_stored_as_planned_and_written_back(self):
        """#224: a spec status we do not have maps to ours; the original is kept."""
        document = minimal_document(
            controls=[
                {"bom-ref": "c1", "name": "Proposed control", "status": "proposed"}
            ]
        )
        imported, _summary = self.import_document(document)
        control = InstanceCountermeasure.objects.get(threat_model=imported)
        self.assertEqual(control.status, "planned")
        self.assertEqual(
            control.format_metadata["cyclonedx"].get("original_status"), "proposed"
        )
        exported = TmBomAdapter().export_data(imported)
        assert_valid_tmbom(exported)
        self.assertEqual(exported["controls"][0]["status"], "proposed")

    def test_unknown_status_is_never_persisted(self):
        """#224: a status that is neither the spec's nor ours stores ``gap`` and warns."""
        document = minimal_document(
            controls=[
                {"bom-ref": "c1", "name": "Odd control", "status": {"name": "wishful"}}
            ]
        )
        imported, summary = self.import_document(document)
        control = InstanceCountermeasure.objects.get(threat_model=imported)
        self.assertEqual(control.status, "gap")
        self.assertIn(control.status, dict(InstanceCountermeasure.Status.choices))
        self.assertTrue(any("wishful" in w for w in summary["warnings"]), summary)

    def test_a_document_without_numbers_gets_fresh_ones_in_document_order(self):
        document = minimal_document(
            threats={
                "threats": [{"bom-ref": "t1", "name": "Threat"}],
                "scenarios": [
                    scenario("s1", "First"),
                    scenario("s2", "Second"),
                    scenario("s3", "Third"),
                ],
            }
        )
        imported, _summary = self.import_document(document)
        by_name = {
            t.threat_name: t.number
            for t in InstanceThreat.objects.filter(threat_model=imported)
        }
        self.assertEqual(by_name, {"First": 1, "Second": 2, "Third": 3})
        state = ThreatModelState.objects.get(threat_model=imported)
        self.assertEqual(state.next_threat_number, 4)

    def test_a_duplicate_number_is_renumbered_with_a_warning(self):
        document = minimal_document(
            threats={
                "threats": [{"bom-ref": "t1", "name": "Threat"}],
                "scenarios": [
                    scenario("s1", "Seven", 7),
                    scenario("s2", "Also seven", 7),
                ],
            }
        )
        imported, summary = self.import_document(document)
        by_name = {
            t.threat_name: t.number
            for t in InstanceThreat.objects.filter(threat_model=imported)
        }
        self.assertEqual(by_name["Seven"], 7)
        self.assertNotEqual(by_name["Also seven"], 7)
        self.assertTrue(
            any("Also seven" in w and "7" in w for w in summary["warnings"])
        )
        state = ThreatModelState.objects.get(threat_model=imported)
        self.assertGreater(state.next_threat_number, max(by_name.values()))

    def test_the_counter_is_set_past_the_highest_number_seen(self):
        document = minimal_document(
            threats={
                "threats": [{"bom-ref": "t1", "name": "Threat"}],
                "scenarios": [scenario("s1", "Forty two", 42)],
            },
            properties=[{"name": "precogly:next-threat-number", "value": "10"}],
        )
        imported, _summary = self.import_document(document)
        self.assertEqual(InstanceThreat.objects.get(threat_model=imported).number, 42)
        state = ThreatModelState.objects.get(threat_model=imported)
        self.assertEqual(state.next_threat_number, 43)
