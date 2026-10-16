"""Use case links and abuse cases, out and back (editable-use-cases.md)."""

import copy

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import Flow, OrgsystemComponent
from apps.threat_models.models import (
    AbuseCase,
    AbuseCaseThreat,
    BusinessObjective,
    ThreatModel,
    UseCase,
)
from apps.threat_models.serializers import AbuseCaseSerializer, unlinked_realizes
from apps.threat_models.tmbom import TmBomAdapter
from apps.threat_models.tmbom.passthrough import _merge_entries
from apps.threat_models.tmbom.testing import assert_valid_tmbom
from apps.threats.models import (
    InstanceCountermeasure,
    InstanceThreat,
    ThreatLibrary,
    ThreatPersona,
)
from apps.threats.services import create_instance_threat

from .test_tmbom_round_trip import as_lines

User = get_user_model()


def _scenario_property(scenario, name):
    for item in scenario.get("properties") or []:
        if item["name"] == name:
            return item["value"]
    return None


class AbuseCaseExchangeTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="sec", email="sec@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        cls.fraud = ThreatLibrary.objects.create(
            name="Payment fraud",
            slug="payment-fraud",
            qualified_slug="demo/payment-fraud",
        )

    def setUp(self):
        self.threat_model = ThreatModel.objects.create(
            name="Shop", organization=self.organization, created_by=self.user
        )
        blueprint = self.threat_model.default_blueprint
        self.web = OrgsystemComponent.objects.create(
            blueprint=blueprint, name="Web", category="process"
        )
        self.payment = OrgsystemComponent.objects.create(
            blueprint=blueprint, name="Payment API", category="process"
        )
        self.orders = OrgsystemComponent.objects.create(
            blueprint=blueprint, name="Orders DB", category="datastore"
        )
        self.flow = Flow.objects.create(
            blueprint=blueprint,
            source_component=self.web,
            dest_component=self.payment,
            label="Pay",
        )
        self.objective = BusinessObjective.objects.create(
            threat_model=self.threat_model, name="Revenue"
        )
        self.fraudster = ThreatPersona.objects.create(
            threat_model=self.threat_model, symbolic_name="fraudster", name="Fraudster"
        )
        self.on_payment = create_instance_threat(
            self.threat_model, targets=[self.payment], threat_library=self.fraud
        )
        self.on_web = create_instance_threat(
            self.threat_model, targets=[self.web], threat_library=self.fraud
        )
        self.use_case = UseCase.objects.create(
            threat_model=self.threat_model,
            name="Place order",
            flow_data={"main_flow": [{"number": 1, "description": "Pay"}]},
        )
        self.use_case.target_links.create(component=self.web)
        self.use_case.target_links.create(component=self.orders)
        self.use_case.target_links.create(flow=self.flow)
        self.use_case.business_objective_links.create(business_objective=self.objective)
        self.abuse_case = AbuseCase.objects.create(
            threat_model=self.threat_model,
            name="Card testing",
            abuser=self.fraudster,
            flow_data={
                "preconditions": ["Stolen cards"],
                "main_flow": [{"number": 1, "description": "Try small payments"}],
                "detection_opportunities": ["Many declines"],
            },
        )
        self.abuse_case.use_case_links.create(use_case=self.use_case)
        self.abuse_case.target_links.create(component=self.payment)
        AbuseCaseThreat.objects.create(
            abuse_case=self.abuse_case, threat=self.on_payment
        )

    def export(self, threat_model=None, warnings=None):
        return TmBomAdapter().export_data(threat_model or self.threat_model, warnings)

    def import_copy(self, document):
        imported, summary = TmBomAdapter().import_data(
            copy.deepcopy(document), self.organization, self.user
        )
        return imported, summary.get("warnings", [])

    # -- export ----------------------------------------------------------

    def test_export_writes_the_spec_fields_and_validates(self):
        document = self.export()
        assert_valid_tmbom(document, context="use case and abuse case export")
        blueprint = document["blueprints"][0]
        refs = {
            asset["name"]: asset["bom-ref"]
            for asset in blueprint["assets"] + blueprint["dataStores"]
        }
        use_case = document["definitions"]["useCases"][0]
        abuse_case = document["threats"]["abuseCases"][0]
        flow_ref = blueprint["flows"][0]["bom-ref"]

        self.assertEqual(
            blueprint["useCases"],
            [
                {
                    "ref": use_case["bom-ref"],
                    "assets": [refs["Web"], refs["Orders DB"]],
                    "flows": [flow_ref],
                }
            ],
        )
        web = next(a for a in blueprint["assets"] if a["name"] == "Web")
        self.assertEqual(web["useCases"], [use_case["bom-ref"]])
        # A dataStores entry has no useCases field.
        self.assertNotIn("useCases", blueprint["dataStores"][0])
        objective_ref = document["definitions"]["businessObjectives"][0]["bom-ref"]
        self.assertEqual(use_case["businessObjectives"], [objective_ref])
        self.assertEqual(
            _scenario_property(use_case, "precogly:abuse-cases"),
            f'["{abuse_case["bom-ref"]}"]',
        )

        abstract_ref = f"threat-{self.fraud.qualified_slug}"
        self.assertEqual(abuse_case["realizes"], [abstract_ref])
        self.assertEqual(abuse_case["targets"], [refs["Payment API"]])
        self.assertEqual(abuse_case["preconditions"], ["Stolen cards"])
        self.assertEqual(abuse_case["detectionOpportunities"], ["Many declines"])
        persona_actor = blueprint["actors"][0]["bom-ref"]
        self.assertEqual(abuse_case["abuser"], persona_actor)
        self.assertNotIn("properties", abuse_case)
        abstract = document["threats"]["threats"][0]
        self.assertEqual(abstract["abuseCases"], [abuse_case["bom-ref"]])

        scenarios = {s["bom-ref"]: s for s in document["threats"]["scenarios"]}
        exact = [
            ref
            for ref, scenario in scenarios.items()
            if _scenario_property(scenario, "precogly:abuse-cases")
        ]
        self.assertEqual(len(exact), 1)

    # -- round trip ------------------------------------------------------

    def test_round_trip_keeps_rows_and_document(self):
        first = self.export()
        imported, warnings = self.import_copy(first)
        self.assertEqual(warnings, [])
        use_case = imported.use_cases.get()
        self.assertEqual(
            sorted(
                link.component.name
                for link in use_case.target_links.all()
                if link.component_id
            ),
            ["Orders DB", "Web"],
        )
        self.assertEqual(use_case.target_links.filter(flow__isnull=False).count(), 1)
        self.assertEqual(
            [
                link.business_objective.name
                for link in use_case.business_objective_links.all()
            ],
            ["Revenue"],
        )
        abuse_case = imported.abuse_cases.get()
        self.assertEqual(abuse_case.abuser.name, "Fraudster")
        self.assertEqual(
            [link.use_case.name for link in abuse_case.use_case_links.all()],
            ["Place order"],
        )
        linked = [link.threat for link in abuse_case.threat_links.all()]
        self.assertEqual(len(linked), 1)
        self.assertEqual(
            [target.component.name for target in linked[0].targets.all()],
            ["Payment API"],
        )
        # The first import draws a diagram (the model had none); from then on
        # export, import and export again is stable.
        second = self.export(imported)
        again, warnings = self.import_copy(second)
        self.assertEqual(warnings, [])
        self.assertEqual(as_lines(self.export(again)), as_lines(second))

    def test_targets_choose_the_scenario_when_the_property_is_absent(self):
        document = self.export()
        for scenario in document["threats"]["scenarios"]:
            scenario["properties"] = [
                item
                for item in scenario["properties"]
                if item["name"] != "precogly:abuse-cases"
            ]
        imported, _ = self.import_copy(document)
        linked = [link.threat for link in imported.abuse_cases.get().threat_links.all()]
        self.assertEqual(
            [[t.component.name for t in threat.targets.all()] for threat in linked],
            [["Payment API"]],
        )

    def test_no_targets_and_two_scenarios_links_neither_and_keeps_realizes(self):
        self.abuse_case.target_links.all().delete()
        document = self.export()
        for scenario in document["threats"]["scenarios"]:
            scenario["properties"] = [
                item
                for item in scenario["properties"]
                if item["name"] != "precogly:abuse-cases"
            ]
        imported, warnings = self.import_copy(document)
        self.assertEqual(warnings, [])
        abuse_case = imported.abuse_cases.get()
        self.assertFalse(abuse_case.threat_links.exists())
        self.assertEqual(
            unlinked_realizes(abuse_case),
            [{"library_threat_id": self.fraud.pk, "name": "Payment fraud"}],
        )
        exported = self.export(imported)
        assert_valid_tmbom(exported, context="kept realizes")
        self.assertEqual(
            exported["threats"]["abuseCases"][0]["realizes"],
            [f"threat-{self.fraud.qualified_slug}"],
        )

        # Linking a threat of the same library threat: written once, note gone.
        threat = imported.threats.first()
        AbuseCaseThreat.objects.create(abuse_case=abuse_case, threat=threat)
        self.assertEqual(unlinked_realizes(abuse_case), [])
        exported = self.export(imported)
        self.assertEqual(
            exported["threats"]["abuseCases"][0]["realizes"],
            [f"threat-{self.fraud.qualified_slug}"],
        )

    def test_kept_realizes_with_no_threat_left_is_left_out_with_a_warning(self):
        self.abuse_case.target_links.all().delete()
        document = self.export()
        for scenario in document["threats"]["scenarios"]:
            scenario["properties"] = [
                item
                for item in scenario["properties"]
                if item["name"] != "precogly:abuse-cases"
            ]
        imported, _ = self.import_copy(document)
        InstanceThreat.objects.filter(threat_model=imported).delete()
        warnings = []
        exported = self.export(imported, warnings)
        assert_valid_tmbom(exported, context="realizes with no threat left")
        self.assertNotIn("realizes", exported["threats"]["abuseCases"][0])
        self.assertTrue(any("Payment fraud" in w for w in warnings), warnings)

    def test_an_abuser_that_points_nowhere_is_kept_then_left_out(self):
        document = self.export()
        document["threats"]["abuseCases"][0]["abuser"] = "actor-gone"
        imported, warnings = self.import_copy(document)
        self.assertTrue(any("actor-gone" in w for w in warnings), warnings)
        abuse_case = imported.abuse_cases.get()
        self.assertIsNone(abuse_case.abuser)
        export_warnings = []
        exported = self.export(imported, export_warnings)
        assert_valid_tmbom(exported, context="abuser pointing nowhere")
        self.assertNotIn("abuser", exported["threats"]["abuseCases"][0])
        self.assertTrue(any("actor-gone" in w for w in export_warnings))

    def test_kept_mitigations_survive(self):
        InstanceCountermeasure.objects.create(
            threat_model=self.threat_model, countermeasure_name="Rate limit checkout"
        )
        document = self.export()
        control_ref = next(
            c["bom-ref"]
            for c in document["controls"]
            if c["name"] == "Rate limit checkout"
        )
        document["threats"]["abuseCases"][0]["mitigations"] = [control_ref]
        imported, warnings = self.import_copy(document)
        self.assertEqual(warnings, [])
        serialized = AbuseCaseSerializer(imported.abuse_cases.get()).data
        self.assertEqual(
            [m["name"] for m in serialized["mitigations"]], ["Rate limit checkout"]
        )
        exported = self.export(imported)
        assert_valid_tmbom(exported, context="kept mitigations")
        new_control_ref = next(
            c["bom-ref"]
            for c in exported["controls"]
            if c["name"] == "Rate limit checkout"
        )
        self.assertEqual(
            exported["threats"]["abuseCases"][0]["mitigations"], [new_control_ref]
        )

    def test_engineering_requirements_and_their_links_are_kept(self):
        """``definitions.requirements`` is not modelled: kept whole and written
        back, so the use case, blueprint and blueprint use case entry links to
        it still resolve."""
        document = self.export()
        document["definitions"]["requirements"] = [
            {
                "bom-ref": "req-lockout",
                "name": "Lock the account after 5 failed logins",
                "priority": "high",
            }
        ]
        document["definitions"]["useCases"][0]["requirements"] = ["req-lockout"]
        document["blueprints"][0]["requirements"] = ["req-lockout"]
        document["blueprints"][0]["useCases"][0]["requirements"] = ["req-lockout"]
        assert_valid_tmbom(document, context="engineering requirements")
        imported, warnings = self.import_copy(document)
        self.assertEqual(warnings, [])
        export_warnings = []
        exported = self.export(imported, export_warnings)
        assert_valid_tmbom(exported, context="engineering requirements out")
        self.assertEqual(export_warnings, [])
        self.assertEqual(
            exported["definitions"]["requirements"],
            document["definitions"]["requirements"],
        )
        self.assertEqual(
            exported["definitions"]["useCases"][0]["requirements"], ["req-lockout"]
        )
        self.assertEqual(exported["blueprints"][0]["requirements"], ["req-lockout"])
        self.assertEqual(
            exported["blueprints"][0]["useCases"][0]["requirements"], ["req-lockout"]
        )

    def test_kept_blueprint_use_case_entries_merge_with_written_ones(self):
        """A kept entry for a use case the export also writes joins its link
        lists (requirements, unresolved assets); other kept entries follow."""
        written = [{"ref": "uc-1", "assets": ["a-1"]}]
        _merge_entries(
            "useCases",
            written,
            [
                {"ref": "uc-1", "assets": ["a-1", "a-9"], "requirements": ["req-1"]},
                {"ref": "uc-2", "flows": ["f-1"]},
            ],
        )
        self.assertEqual(
            written,
            [
                {"ref": "uc-1", "assets": ["a-1", "a-9"], "requirements": ["req-1"]},
                {"ref": "uc-2", "flows": ["f-1"]},
            ],
        )
        asset_use_cases = ["uc-1"]
        _merge_entries("useCases", asset_use_cases, ["uc-1", "uc-3"])
        self.assertEqual(asset_use_cases, ["uc-1", "uc-3"])

    def test_another_tools_abuse_case_imports(self):
        """Names only, realizing an abstract threat through ``threat.abuseCases``."""
        document = self.export()
        document["threats"].pop("abuseCases")
        for scenario in document["threats"]["scenarios"]:
            scenario["properties"] = [
                item
                for item in scenario["properties"]
                if item["name"] != "precogly:abuse-cases"
            ]
        document["definitions"]["useCases"][0].pop("properties", None)
        document["threats"]["threats"][0].pop("abuseCases", None)
        document["threats"]["abuseCases"] = [
            {"bom-ref": "abuse-x", "name": "Price tampering"}
        ]
        document["threats"]["threats"][0]["abuseCases"] = ["abuse-x"]
        assert_valid_tmbom(document, context="another tool")
        imported, warnings = self.import_copy(document)
        self.assertEqual(warnings, [])
        abuse_case = imported.abuse_cases.get()
        self.assertEqual(abuse_case.name, "Price tampering")
        self.assertEqual(
            [entry["name"] for entry in unlinked_realizes(abuse_case)],
            ["Payment fraud"],
        )
        assert_valid_tmbom(self.export(imported), context="another tool out")

    def test_kept_abuse_cases_from_an_earlier_import_still_export(self):
        """A model imported before abuse cases were rows keeps them as kept
        content; adding an abuse case must not drop them (export merge)."""
        self.threat_model.format_metadata = {
            "cyclonedx": {
                "passthrough": {
                    "threats": {
                        "abuseCases": [{"bom-ref": "abuse-old", "name": "Old one"}]
                    }
                }
            }
        }
        self.threat_model.save()
        document = self.export()
        assert_valid_tmbom(document, context="kept abuse case merged")
        self.assertEqual(
            [entry["name"] for entry in document["threats"]["abuseCases"]],
            ["Card testing", "Old one"],
        )
