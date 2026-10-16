"""Spec values a row holds only in part survive a round trip (tmbom/kept_values.py).

A document from another tool carries owners that are no member, decision
statuses on responses, effectiveness ratings, domain details, custom domains
and ``satisfies`` refs to engineering requirements. Each is written back on
export while the row still holds what it was imported as; an edit in
Precogly wins.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from apps.organizations.models import Organization, OrganizationMember
from apps.threat_models.tmbom import TmBomAdapter
from apps.threat_models.tmbom.testing import assert_valid_tmbom

User = get_user_model()

VENDOR = {
    "bom-ref": "party-vendor",
    "roles": [{"role": "owner"}],
    "organization": {"name": "Acme Payments Ltd"},
}
OUTSIDER = {
    "roles": [{"role": "owner"}],
    "person": {"name": "Olga Outsider", "email": [{"address": "olga@else.test"}]},
}
EFFECTIVENESS = {"percentage": 0.6, "rating": "good"}


def _document() -> dict:
    return {
        "specFormat": "CycloneDX",
        "specVersion": "2.0",
        "metadata": {
            "component": {
                "type": "application",
                "name": "Shop",
                "parties": [VENDOR],
            }
        },
        "blueprints": [
            {
                "name": "Shop",
                "modelTypes": ["data-flow"],
                "assets": [{"bom-ref": "a1", "name": "API", "type": "service"}],
            }
        ],
        "definitions": {
            "requirements": [
                {"bom-ref": "req-rate-limit", "name": "Rate limit checkout"}
            ]
        },
        "threats": {
            "threats": [{"bom-ref": "t1", "name": "Card testing"}],
            "scenarios": [
                {
                    "bom-ref": "s1",
                    "name": "S",
                    "threats": ["t1"],
                    "affectedAssets": ["a1"],
                }
            ],
        },
        "controls": [
            {
                "bom-ref": "c1",
                "name": "Checkout rate limit",
                "status": "planned",
                "satisfies": ["req-rate-limit"],
                "effectiveness": EFFECTIVENESS,
                "owner": "party-vendor",
            }
        ],
        "risks": {
            "risks": [
                {
                    "bom-ref": "r1",
                    "name": "Fraud losses",
                    "statement": "Stolen cards are tested at checkout.",
                    "owner": "party-vendor",
                    "domains": [
                        {"type": "financial", "priority": "high"},
                        {"type": {"name": "fraud"}, "description": "Card fraud"},
                    ],
                    "relatedThreats": ["s1"],
                    "inherentRisk": {"score": {"level": "high"}},
                    "responses": [
                        {
                            "bom-ref": "rr1",
                            "strategy": "reduce",
                            "status": "proposed",
                            "effectiveness": EFFECTIVENESS,
                            "owner": OUTSIDER,
                            "controls": ["c1"],
                        }
                    ],
                }
            ]
        },
    }


class KeptValuesTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="u", email="u@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )

    def _import(self):
        imported, summary = TmBomAdapter().import_data(
            _document(), self.organization, self.user
        )
        return imported, "\n".join(summary.get("warnings", []))

    def _export(self, threat_model):
        document = TmBomAdapter().export_data(threat_model)
        assert_valid_tmbom(document)
        risk = document["risks"]["risks"][0]
        control = next(c for c in document["controls"] if c["bom-ref"] == "c1")
        return risk, risk["responses"][0], control

    def test_round_trip_keeps_what_rows_hold_in_part(self):
        imported, warnings = self._import()
        self.assertIn("owner matches no member", warnings)
        self.assertIn("kept for export, not linked", warnings)
        self.assertIn("custom domain", warnings)

        risk = imported.risks.get()
        response = risk.responses.get()
        self.assertIsNone(risk.owner)
        self.assertEqual(response.status, "planned")
        self.assertEqual(response.effectiveness, 0.6)
        self.assertEqual(risk.domains, ["financial"])

        risk_entry, response_entry, control_entry = self._export(imported)
        vendor_inline = {k: v for k, v in VENDOR.items() if k != "bom-ref"}
        self.assertEqual(risk_entry["owner"], vendor_inline)
        self.assertEqual(
            risk_entry["domains"],
            [
                {"type": "financial", "priority": "high"},
                {"type": {"name": "fraud"}, "description": "Card fraud"},
            ],
        )
        self.assertEqual(response_entry["status"], "proposed")
        self.assertEqual(response_entry["effectiveness"], EFFECTIVENESS)
        self.assertEqual(response_entry["owner"], OUTSIDER)
        self.assertEqual(control_entry["satisfies"], ["req-rate-limit"])
        self.assertEqual(control_entry["effectiveness"], EFFECTIVENESS)
        self.assertEqual(control_entry["owner"], vendor_inline)

    def test_edits_in_precogly_win_over_kept_values(self):
        imported, _ = self._import()
        risk = imported.risks.get()
        response = risk.responses.get()
        control = imported.countermeasures.get()
        client = APIClient()
        client.force_authenticate(self.user)
        base = f"/api/threat-models/{imported.pk}/risks/{risk.pk}"

        # Set, then clear: the kept owner does not come back.
        for owner in (self.user.pk, None):
            self.assertEqual(
                client.patch(f"{base}/", {"owner": owner}, format="json").status_code,
                200,
            )
        self.assertEqual(
            client.patch(
                f"{base}/responses/{response.pk}/",
                {"status": "implemented", "effectiveness": 0.9, "owner": None},
                format="json",
            ).status_code,
            200,
        )
        self.assertEqual(
            client.patch(
                f"/api/countermeasures/{control.pk}/",
                {"effectiveness": 0.8, "assignedOwner": None},
                format="json",
            ).status_code,
            200,
        )
        risk.domains = []
        risk.save(update_fields=["domains"])

        risk_entry, response_entry, control_entry = self._export(imported)
        self.assertNotIn("owner", risk_entry)
        self.assertEqual(
            risk_entry["domains"],
            [{"type": {"name": "fraud"}, "description": "Card fraud"}],
        )
        self.assertEqual(response_entry["status"], "implemented")
        self.assertEqual(response_entry["effectiveness"], {"percentage": 0.9})
        self.assertNotIn("owner", response_entry)
        self.assertEqual(control_entry["effectiveness"], {"percentage": 0.8})
        self.assertNotIn("owner", control_entry)

    def test_bulk_owner_update_drops_the_kept_owner(self):
        imported, _ = self._import()
        risk = imported.risks.get()
        client = APIClient()
        client.force_authenticate(self.user)
        reply = client.post(
            f"/api/threat-models/{imported.pk}/risks/bulk-update/",
            {"riskIds": [risk.pk], "owner": None},
            format="json",
        )
        self.assertEqual(reply.status_code, 200)
        risk.refresh_from_db()
        self.assertNotIn("owner", risk.format_metadata["cyclonedx"])


def _standards_document() -> dict:
    return {
        "specFormat": "CycloneDX",
        "specVersion": "2.0",
        "blueprints": [
            {
                "name": "Shop",
                "modelTypes": ["data-flow"],
                "assets": [{"bom-ref": "a1", "name": "API", "type": "service"}],
            }
        ],
        "definitions": {
            "standards": [
                {
                    "bom-ref": "pci-dss",
                    "name": "PCI DSS",
                    "requirements": [
                        {
                            "bom-ref": "pci-3.4",
                            "identifier": "3.4",
                            "openCre": ["CRE:764-507"],
                        },
                        {"bom-ref": "pci-8.3", "identifier": "8.3"},
                        {"bom-ref": "pci-10.2", "identifier": "10.2"},
                    ],
                }
            ]
        },
        "controls": [
            {
                "bom-ref": "c1",
                "name": "Encrypt card data",
                "status": "planned",
                "satisfies": ["pci-3.4"],
            }
        ],
        "risks": {
            "risks": [
                {
                    "bom-ref": "r1",
                    "name": "Card data exposure",
                    "statement": "Card data leaks.",
                    "relatedStandards": ["pci-dss"],
                    "inherentRisk": {"score": {"level": "high"}},
                }
            ]
        },
    }


class KeptStandardsTests(TestCase):
    """``definitions.standards`` comes back as imported, plus mappings made here."""

    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="u", email="u@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )

    def test_standards_round_trip_with_a_mapping_added_here(self):
        from apps.threats.models import InstanceCountermeasureStandard

        imported, summary = TmBomAdapter().import_data(
            _standards_document(), self.organization, self.user
        )
        self.assertNotIn("warnings", summary)
        control = imported.countermeasures.get()
        InstanceCountermeasureStandard.objects.create(
            countermeasure=control,
            framework_name="PCI DSS",
            section_code="4.2",
            sufficiency="partial",
        )
        InstanceCountermeasureStandard.objects.create(
            countermeasure=control,
            framework_name="ISO 27001",
            section_code="A.8.24",
            sufficiency="partial",
        )

        document = TmBomAdapter().export_data(imported)
        assert_valid_tmbom(document)
        standards = document["definitions"]["standards"]
        pci = standards[0]
        self.assertEqual(pci["bom-ref"], "pci-dss")
        requirements = {r["identifier"]: r for r in pci["requirements"]}
        self.assertEqual(set(requirements), {"3.4", "8.3", "10.2", "4.2"})
        self.assertEqual(requirements["3.4"]["bom-ref"], "pci-3.4")
        self.assertEqual(requirements["3.4"]["openCre"], ["CRE:764-507"])
        self.assertEqual([s["name"] for s in standards], ["PCI DSS", "ISO 27001"])

        exported_control = document["controls"][0]
        self.assertEqual(
            exported_control["satisfies"],
            [
                "pci-3.4",
                requirements["4.2"]["bom-ref"],
                standards[1]["requirements"][0]["bom-ref"],
            ],
        )
        risk = document["risks"]["risks"][0]
        self.assertEqual(risk["relatedStandards"], ["pci-dss"])

        # A second round trip changes nothing.
        again, _ = TmBomAdapter().import_data(document, self.organization, self.user)
        self.assertEqual(
            TmBomAdapter().export_data(again)["definitions"]["standards"], standards
        )
