"""The step 4 adapter slice: controls, scope, providers, compliance, out and back.

The compliance cases (``satisfies`` resolved, unresolved with a snapshot,
object form, dangling; the ``evidence`` external reference) are ported from
PR #559 by JJediny (D20).
"""

from datetime import date

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.compliance.models import (
    CountermeasureLibraryStandard,
    StandardFramework,
    StandardRequirement,
)
from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import Flow, OrgsystemComponent, Zone
from apps.threat_models.models import ThreatModel, ThreatModelState
from apps.threat_models.tmbom import TmBomAdapter
from apps.threat_models.tmbom.testing import assert_valid_tmbom
from apps.threats.models import (
    CountermeasureLibrary,
    InstanceCountermeasure,
    InstanceCountermeasureStandard,
)
from apps.threats.services import (
    create_instance_countermeasure,
    create_instance_threat,
    link_countermeasure,
)

User = get_user_model()


def _document(controls=None, definitions=None, blueprint=None, threats=None):
    document = {
        "specFormat": "CycloneDX",
        "specVersion": "2.0",
        "metadata": {
            "component": {"type": "application", "bom-ref": "sys", "name": "X"}
        },
        "blueprints": [blueprint or {"name": "Import", "modelTypes": ["data-flow"]}],
    }
    if definitions is not None:
        document["definitions"] = definitions
    if controls is not None:
        document["controls"] = controls
    if threats is not None:
        document["threats"] = threats
    return document


class ControlSliceTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="sec", email="sec@org.test", password="x", first_name="Sam"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        cls.member = User.objects.create_user(
            username="dev", email="dev@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.member, role="member"
        )
        cls.framework = StandardFramework.objects.create(
            name="NIST 800-53 Rev 5", slug="nist-800-53-r5", version="5", issuer="NIST"
        )
        cls.ac2 = StandardRequirement.objects.create(
            framework=cls.framework,
            section_code="AC-2",
            description="Account management",
        )


def build_control_model(organization, user, ac2):
    """A model with one scoped, linked, compliant control and one whole-system one."""
    threat_model = ThreatModel.objects.create(
        name="Payments", organization=organization, created_by=user
    )
    blueprint = threat_model.default_blueprint
    Zone.objects.create(blueprint=blueprint, name="DMZ")
    api = OrgsystemComponent.objects.create(blueprint=blueprint, name="API")
    waf = OrgsystemComponent.objects.create(blueprint=blueprint, name="WAF")
    flow = Flow.objects.create(
        blueprint=blueprint, source_component=api, dest_component=waf, label="Q"
    )
    threat = create_instance_threat(
        threat_model, targets=[api], threat_name="SQLi", level="high"
    )
    library = CountermeasureLibrary.objects.create(
        name="Parameterised queries",
        description="Bind parameters",
        slug="param-queries",
        qualified_slug="demo/param-queries",
        control_functions=["preventive", "detective"],
        control_nature="technical",
    )
    CountermeasureLibraryStandard.objects.create(
        countermeasure_library=library, requirement=ac2, sufficiency="full"
    )
    scoped = create_instance_countermeasure(
        threat_model,
        countermeasure_library=library,
        status="gap",
        targets=[api, flow],
        implemented_by=[waf],
        implemented_by_party="Cloudflare",
        source="Pentest 2026-09",
        priority="high",
        due_date=date(2026, 12, 1),
        required_for_release=True,
        effectiveness=0.6,
        assigned_owner=user,
        external_ticket_url="https://tickets.example/1",
        evidence_url="https://evidence.example/1.pdf",
    )
    link_countermeasure(scoped, threat)
    InstanceCountermeasureStandard.objects.create(
        countermeasure=scoped,
        requirement=None,
        section_code="SI-4",
        framework_name="NIST 800-53 Rev 5 UNINSTALLED",
        requirement_description="Monitor the system.",
        sufficiency="partial",
    )
    create_instance_countermeasure(
        threat_model, countermeasure_name="Security training", status="platform"
    )
    return threat_model


class ExportTests(ControlSliceTestCase):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.threat_model = build_control_model(cls.organization, cls.user, cls.ac2)
        cls.document = TmBomAdapter().export_data(cls.threat_model)

    def test_export_validates(self):
        assert_valid_tmbom(self.document, context="step 4 export")

    def test_controls_carry_scope_provider_status_and_compliance(self):
        by_name = {c["name"]: c for c in self.document["controls"]}
        scoped = by_name["Parameterised queries"]
        first = self.document["blueprints"][0]
        api_ref = next(a["bom-ref"] for a in first["assets"] if a["name"] == "API")
        waf_ref = next(a["bom-ref"] for a in first["assets"] if a["name"] == "WAF")
        self.assertEqual(scoped["appliesTo"], [api_ref, first["flows"][0]["bom-ref"]])
        self.assertEqual(scoped["implementedBy"][0], waf_ref)
        self.assertTrue(scoped["implementedBy"][1].startswith("party-provider-"))
        self.assertEqual(scoped["status"], {"name": "gap"})
        self.assertEqual(scoped["category"], "preventive")
        self.assertEqual(scoped["effectiveness"], {"percentage": 0.6})
        self.assertEqual(scoped["owner"], f"party-user-{self.user.pk}")
        self.assertEqual(
            {r["type"]: r["url"] for r in scoped["externalReferences"]},
            {
                "issue-tracker": "https://tickets.example/1",
                "evidence": "https://evidence.example/1.pdf",
            },
        )
        properties = {p["name"]: p["value"] for p in scoped["properties"]}
        self.assertEqual(properties["precogly:number"], "1")
        self.assertEqual(properties["precogly:source"], "Pentest 2026-09")
        self.assertEqual(properties["precogly:due-date"], "2026-12-01")
        self.assertEqual(properties["precogly:required-for-release"], "true")
        self.assertEqual(properties["precogly:library"], "demo/param-queries")
        self.assertEqual(
            properties["precogly:control-functions"], '["preventive","detective"]'
        )
        scenario_ref = self.document["threats"]["scenarios"][0]["bom-ref"]
        self.assertEqual(properties["precogly:mitigates"], f'["{scenario_ref}"]')
        self.assertIn('"sufficiency":"full"', properties["precogly:sufficiency"])

        standards = {s["name"]: s for s in self.document["definitions"]["standards"]}
        self.assertEqual(
            standards["NIST 800-53 Rev 5"]["requirements"][0]["identifier"], "AC-2"
        )
        self.assertEqual(
            standards["NIST 800-53 Rev 5 UNINSTALLED"]["requirements"][0]["identifier"],
            "SI-4",
        )
        self.assertEqual(len(scoped["satisfies"]), 2)

        whole = by_name["Security training"]
        self.assertNotIn("appliesTo", whole)
        self.assertEqual(whole["status"], {"name": "platform"})

        parties = {
            p["bom-ref"]: p for p in self.document["metadata"]["component"]["parties"]
        }
        self.assertEqual(
            parties[scoped["owner"]]["person"]["email"], [{"address": "sec@org.test"}]
        )
        self.assertEqual(
            parties[scoped["implementedBy"][1]]["organization"]["name"], "Cloudflare"
        )

    def test_abstract_threat_lists_the_mitigating_controls(self):
        threat = self.document["threats"]["threats"][0]
        self.assertEqual(
            threat["mitigations"], [self.document["controls"][0]["bom-ref"]]
        )

    def test_document_carries_the_next_countermeasure_number(self):
        properties = {p["name"]: p["value"] for p in self.document["properties"]}
        self.assertEqual(properties["precogly:next-countermeasure-number"], "3")


class RoundTripTests(ControlSliceTestCase):
    def test_controls_survive_a_round_trip(self):
        source = build_control_model(self.organization, self.user, self.ac2)
        adapter = TmBomAdapter()
        document = adapter.export_data(source)
        imported, summary = adapter.import_data(document, self.organization, self.user)
        self.assertEqual(summary["controls"], 2)
        self.assertNotIn("warnings", summary)

        scoped = imported.countermeasures.get(
            countermeasure_name="Parameterised queries"
        )
        self.assertEqual(scoped.number, 1)
        self.assertEqual(scoped.status, "gap")
        self.assertEqual(
            scoped.countermeasure_library.qualified_slug, "demo/param-queries"
        )
        self.assertEqual(
            [r.target_kind for r in scoped.targets.all()], ["component", "flow"]
        )
        self.assertEqual(
            [link.component.name for link in scoped.provider_links.all()], ["WAF"]
        )
        self.assertEqual(scoped.implemented_by_party, "Cloudflare")
        self.assertEqual(scoped.source, "Pentest 2026-09")
        self.assertEqual(scoped.due_date, date(2026, 12, 1))
        self.assertTrue(scoped.required_for_release)
        self.assertEqual(scoped.effectiveness, 0.6)
        self.assertEqual(scoped.assigned_owner, self.user)
        self.assertEqual(scoped.external_ticket_url, "https://tickets.example/1")
        self.assertEqual(scoped.evidence_url, "https://evidence.example/1.pdf")
        self.assertEqual(scoped.control_functions, ["preventive", "detective"])
        self.assertEqual(scoped.threat_links.get().threat.threat_name, "SQLi")
        mappings = {m.section_code: m for m in scoped.instance_standard_mappings.all()}
        self.assertEqual(mappings["AC-2"].requirement, self.ac2)
        self.assertEqual(mappings["AC-2"].sufficiency, "full")
        self.assertIsNone(mappings["SI-4"].requirement)
        self.assertEqual(
            mappings["SI-4"].framework_name, "NIST 800-53 Rev 5 UNINSTALLED"
        )

        whole = imported.countermeasures.get(countermeasure_name="Security training")
        self.assertEqual(whole.status, "platform")
        self.assertEqual(whole.targets.count(), 0)
        self.assertEqual(
            ThreatModelState.objects.get(
                threat_model=imported
            ).next_countermeasure_number,
            3,
        )

        again = adapter.export_data(imported)
        assert_valid_tmbom(again)
        self.assertEqual(
            {c["bom-ref"] for c in again["controls"]},
            {c["bom-ref"] for c in document["controls"]},
        )

    def test_platform_status_from_a_file_needs_the_role(self):
        document = _document(
            controls=[
                {"bom-ref": "c1", "name": "Managed", "status": {"name": "platform"}}
            ]
        )
        imported, summary = TmBomAdapter().import_data(
            document, self.organization, self.member
        )
        self.assertEqual(imported.countermeasures.get().status, "gap")
        self.assertIn("Security Team", "\n".join(summary["warnings"]))


class ComplianceImportTests(ControlSliceTestCase):
    """Ported from PR #559 (JJediny): satisfies and evidence on import."""

    def _import(self, document):
        return TmBomAdapter().import_data(document, self.organization, self.user)

    def test_satisfies_resolved_requirement_creates_mapping(self):
        document = _document(
            definitions={
                "standards": [
                    {
                        "bom-ref": "std",
                        "name": "NIST 800-53 Rev 5",
                        "requirements": [
                            {
                                "bom-ref": "req-ac2",
                                "identifier": "AC-2",
                                "title": "Account management",
                            }
                        ],
                    }
                ]
            },
            controls=[
                {
                    "bom-ref": "control-ac2",
                    "name": "Account Management",
                    "status": "implemented",
                    "satisfies": ["req-ac2"],
                    "properties": [
                        {
                            "name": "precogly:sufficiency",
                            "value": '[{"requirement":"req-ac2","sufficiency":"full"}]',
                        }
                    ],
                }
            ],
        )
        threat_model, _ = self._import(document)
        mapping = InstanceCountermeasureStandard.objects.get(
            countermeasure__threat_model=threat_model
        )
        self.assertEqual(mapping.requirement, self.ac2)
        self.assertEqual(mapping.section_code, "AC-2")
        self.assertEqual(mapping.framework_name, "NIST 800-53 Rev 5")
        self.assertEqual(mapping.sufficiency, "full")

    def test_satisfies_unresolved_requirement_stores_snapshot(self):
        document = _document(
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
        threat_model, _ = self._import(document)
        mapping = InstanceCountermeasureStandard.objects.get(
            countermeasure__threat_model=threat_model
        )
        self.assertIsNone(mapping.requirement)
        self.assertEqual(mapping.section_code, "SI-4")
        self.assertEqual(mapping.framework_name, "NIST 800-53 Rev 5 UNINSTALLED")
        self.assertEqual(mapping.requirement_description, "Monitor the system.")

    def test_satisfies_object_snapshot_creates_mapping(self):
        document = _document(
            controls=[
                {
                    "bom-ref": "control-object-snapshot",
                    "name": "Object Snapshot",
                    "status": "implemented",
                    "satisfies": [
                        {
                            "reference": "AC-4",
                            "framework": "nist-800-53-r5",
                            "description": "Information flow enforcement",
                        }
                    ],
                }
            ],
        )
        threat_model, _ = self._import(document)
        mapping = InstanceCountermeasureStandard.objects.get(
            countermeasure__threat_model=threat_model
        )
        self.assertIsNone(mapping.requirement)
        self.assertEqual(mapping.section_code, "AC-4")
        self.assertEqual(mapping.framework_name, "nist-800-53-r5")
        self.assertEqual(
            mapping.requirement_description, "Information flow enforcement"
        )

    def test_satisfies_dangling_reference_warns_and_skips(self):
        document = _document(
            controls=[
                {
                    "bom-ref": "control-dangling",
                    "name": "Dangling",
                    "status": "implemented",
                    "satisfies": ["req-does-not-exist"],
                }
            ],
        )
        threat_model, summary = self._import(document)
        self.assertEqual(
            InstanceCountermeasureStandard.objects.filter(
                countermeasure__threat_model=threat_model
            ).count(),
            0,
        )
        self.assertTrue(any("req-does-not-exist" in w for w in summary["warnings"]))

    def test_evidence_external_reference_sets_evidence_url(self):
        document = _document(
            controls=[
                {
                    "bom-ref": "control-evidence",
                    "name": "Documented Control",
                    "status": "implemented",
                    "externalReferences": [
                        {"type": "website", "url": "https://example.gov/home"},
                        {"type": "evidence", "url": "https://example.gov/ssp/ac2.pdf"},
                        {
                            "type": "issue-tracker",
                            "url": "https://example.gov/issues/1",
                        },
                    ],
                }
            ],
        )
        threat_model, _ = self._import(document)
        control = InstanceCountermeasure.objects.get(threat_model=threat_model)
        self.assertEqual(control.evidence_url, "https://example.gov/ssp/ac2.pdf")
        self.assertEqual(control.external_ticket_url, "https://example.gov/issues/1")
        self.assertEqual(
            control.format_metadata["cyclonedx"]["external_references"],
            [{"type": "website", "url": "https://example.gov/home"}],
        )

    def test_other_tools_controls_fall_back_to_threat_mitigations(self):
        document = _document(
            blueprint={
                "name": "Other",
                "modelTypes": ["data-flow"],
                "assets": [{"bom-ref": "a1", "name": "Gateway", "type": "gateway"}],
                "dataSets": [{"bom-ref": "ds1", "name": "PII", "description": "PII"}],
            },
            threats={
                "threats": [
                    {"bom-ref": "t1", "name": "Spoofing", "mitigations": ["c1"]}
                ],
                "scenarios": [
                    {
                        "bom-ref": "s1",
                        "name": "A",
                        "threats": ["t1"],
                        "affectedAssets": ["a1"],
                    },
                    {
                        "bom-ref": "s2",
                        "name": "B",
                        "threats": ["t1"],
                        "affectedAssets": ["a1"],
                    },
                ],
            },
            controls=[
                {
                    "bom-ref": "c1",
                    "name": "MFA",
                    "status": "proposed",
                    "category": "preventive",
                    "appliesTo": ["a1", "ds1"],
                    "implementedBy": ["unknown-party"],
                }
            ],
        )
        threat_model, summary = self._import(document)
        control = threat_model.countermeasures.get()
        self.assertEqual(control.status, "planned")
        self.assertEqual(
            control.format_metadata["cyclonedx"]["original_status"], "proposed"
        )
        self.assertEqual(control.control_functions, ["preventive"])
        self.assertEqual(control.targets.get().target.name, "Gateway")
        self.assertEqual(
            control.format_metadata["cyclonedx"]["extra_applies_to"], ["ds1"]
        )
        self.assertEqual(
            sorted(control.threat_links.values_list("threat__threat_name", flat=True)),
            ["A", "B"],
        )
        warnings = "\n".join(summary["warnings"])
        self.assertIn("ds1", warnings)
        self.assertIn("unknown-party", warnings)
        for threat in threat_model.threats.all():
            self.assertEqual(threat.status, "addressable")
