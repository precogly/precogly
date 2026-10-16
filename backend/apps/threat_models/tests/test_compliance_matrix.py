"""The compliance matrix in the report (idea from PR #561 by JJediny, GSA-TTS).

One entry per framework the model's controls map to; rows are requirements,
with a state, the mapped controls and their threats. The access-isolation
and payload-shape tests follow #561's approach.
"""

from datetime import date, timedelta

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import SimpleTestCase, TestCase
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.compliance.models import StandardFramework, StandardRequirement
from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import OrgsystemComponent
from apps.threat_models.compliance_matrix import (
    build_compliance_matrix,
    group_key,
    natural_key,
    row_state,
)
from apps.threat_models.models import ThreatModel
from apps.threats.models import InstanceCountermeasureStandard
from apps.threats.services import (
    create_instance_countermeasure,
    create_instance_threat,
    link_countermeasure,
)

User = get_user_model()


class PureHelperTests(SimpleTestCase):
    def test_group_key_uses_the_part_before_the_first_dot_then_dash(self):
        self.assertEqual(group_key("V1.2.3"), "V1")
        self.assertEqual(group_key("SR 1.1 RE 1"), "SR 1")
        self.assertEqual(group_key("6.5.1"), "6")
        self.assertEqual(group_key("Annex I.1(a)"), "Annex I")
        self.assertEqual(group_key("SC-8"), "SC")
        self.assertEqual(group_key("A01:2021"), "A01:2021")

    def test_natural_key_orders_numbers_by_value(self):
        codes = ["V1.10.1", "V1.2.1", "10.2", "6.5.1", "V1.9"]
        self.assertEqual(
            sorted(codes, key=natural_key),
            ["6.5.1", "10.2", "V1.2.1", "V1.9", "V1.10.1"],
        )

    def test_row_state(self):
        full_gap = {"sufficiency": "full", "status": "gap"}
        full_verified = {"sufficiency": "full", "status": "verified"}
        partial_verified = {"sufficiency": "partial", "status": "verified"}
        self.assertEqual(row_state([]), "not_covered")
        self.assertEqual(row_state([partial_verified]), "partial_only")
        self.assertEqual(row_state([full_gap, partial_verified]), "covered")
        self.assertEqual(row_state([full_gap, full_verified]), "satisfied")


class MatrixFixture(TestCase):
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
            name="Payments", organization=cls.organization
        )
        api = OrgsystemComponent.objects.create(
            blueprint=cls.threat_model.default_blueprint, name="API"
        )
        cls.threat = create_instance_threat(
            cls.threat_model, targets=[api], threat_name="Stolen session", level="high"
        )

        cls.framework = StandardFramework.objects.create(
            name="Example Standard", slug="example-standard", version="1.0", issuer="Ex"
        )
        family = StandardRequirement.objects.create(
            framework=cls.framework,
            section_code="AC",
            name="Access control",
            description="Family",
        )

        def requirement(code, parent=None):
            return StandardRequirement.objects.create(
                framework=cls.framework,
                section_code=code,
                description=f"Text of {code}",
                parent=parent,
            )

        cls.ac1 = requirement("AC-1", family)
        cls.ac2 = requirement("AC-2", family)
        cls.ac10 = requirement("AC-10", family)
        cls.ac3 = requirement("AC-3", family)  # nothing maps to it

        cls.mfa = create_instance_countermeasure(
            cls.threat_model, countermeasure_name="MFA", status="verified"
        )
        cls.reviews = create_instance_countermeasure(
            cls.threat_model, countermeasure_name="Access reviews", status="planned"
        )
        cls.reviews.due_date = date.today() - timedelta(days=5)
        cls.reviews.save(update_fields=["due_date"])
        cls.logging = create_instance_countermeasure(
            cls.threat_model, countermeasure_name="Logging", status="gap"
        )
        link_countermeasure(cls.mfa, cls.threat)

        def maps(countermeasure, requirement=None, sufficiency="full", **snapshot):
            InstanceCountermeasureStandard.objects.create(
                countermeasure=countermeasure,
                requirement=requirement,
                sufficiency=sufficiency,
                section_code=snapshot.get(
                    "section_code", requirement.section_code if requirement else ""
                ),
                framework_name=snapshot.get(
                    "framework_name", cls.framework.name if requirement else ""
                ),
                requirement_description=snapshot.get("description", ""),
            )

        maps(cls.mfa, cls.ac1)  # satisfied: full and verified
        maps(cls.reviews, cls.ac2)  # covered: full, planned, overdue
        maps(cls.logging, cls.ac10, sufficiency="partial")  # partial only
        # A framework that is not installed: a snapshot mapping.
        maps(
            cls.logging,
            None,
            section_code="A.8.15",
            framework_name="ISO 27001 (not installed)",
            description="Logging",
        )

    def client_for(self, user):
        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(user).access_token}"
        )
        return client


class MatrixTests(MatrixFixture):
    def test_installed_framework_lists_every_pack_requirement_with_its_state(self):
        matrix = build_compliance_matrix(self.threat_model)
        installed = next(entry for entry in matrix if entry["installed"])
        self.assertEqual(installed["name"], "Example Standard")
        rows = {
            row["section_code"]: row
            for group in installed["groups"]
            for row in group["rows"]
        }
        self.assertEqual(rows["AC-1"]["state"], "satisfied")
        self.assertEqual(rows["AC-2"]["state"], "covered")
        self.assertTrue(rows["AC-2"]["overdue"])
        self.assertEqual(rows["AC-10"]["state"], "partial_only")
        self.assertEqual(rows["AC-3"]["state"], "not_covered")
        self.assertEqual(rows["AC-3"]["controls"], [])
        self.assertEqual(
            rows["AC-1"]["controls"][0]["threats"], [self.threat.display_number]
        )
        # The family (AC) is the group heading, not a row: four requirements count.
        self.assertEqual(installed["pack_requirement_count"], 4)
        counts = {item["state"]: item["count"] for item in installed["state_counts"]}
        self.assertEqual(counts["not_covered"], 1)

    def test_rows_group_by_parent_and_sort_naturally(self):
        matrix = build_compliance_matrix(self.threat_model)
        installed = next(entry for entry in matrix if entry["installed"])
        family = next(
            group for group in installed["groups"] if group["name"].startswith("AC")
        )
        self.assertEqual(
            [row["section_code"] for row in family["rows"]],
            ["AC-1", "AC-2", "AC-3", "AC-10"],
        )

    def test_a_framework_that_is_not_installed_shows_its_mapped_requirements(self):
        matrix = build_compliance_matrix(self.threat_model)
        snapshot = next(entry for entry in matrix if not entry["installed"])
        self.assertEqual(snapshot["name"], "ISO 27001 (not installed)")
        self.assertIsNone(snapshot["pack_requirement_count"])
        self.assertEqual(snapshot["mapped_requirement_count"], 1)
        row = snapshot["groups"][0]["rows"][0]
        self.assertEqual((row["section_code"], row["state"]), ("A.8.15", "covered"))

    def test_query_count_does_not_grow_with_requirements(self):
        with CaptureQueriesContext(connection) as before:
            build_compliance_matrix(self.threat_model)
        for index in range(30):
            StandardRequirement.objects.create(
                framework=self.framework, section_code=f"AU-{index}", description="More"
            )
        with CaptureQueriesContext(connection) as after:
            build_compliance_matrix(self.threat_model)
        self.assertEqual(len(before), len(after))

    def test_a_model_without_mappings_has_an_empty_matrix(self):
        other = ThreatModel.objects.create(name="Empty", organization=self.organization)
        self.assertEqual(build_compliance_matrix(other), [])

    def test_the_report_carries_the_matrix_with_a_stable_shape(self):
        response = self.client_for(self.user).get(
            f"/api/threat-models/{self.threat_model.pk}/report/"
        )
        self.assertEqual(response.status_code, 200)
        entry = response.json()["complianceMatrix"][0]
        self.assertEqual(
            set(entry),
            {
                "name",
                "version",
                "installed",
                "packRequirementCount",
                "mappedRequirementCount",
                "stateCounts",
                "groups",
            },
        )
        row = entry["groups"][0]["rows"][0]
        self.assertEqual(
            set(row),
            {
                "requirementId",
                "sectionCode",
                "name",
                "description",
                "state",
                "controls",
                "overdue",
            },
        )
        self.assertEqual(
            set(row["controls"][0]) if row["controls"] else set(),
            {
                "id",
                "displayNumber",
                "name",
                "status",
                "sufficiency",
                "daysOverdue",
                "threats",
            }
            if row["controls"]
            else set(),
        )

    def test_a_model_of_another_organization_is_not_reachable(self):
        """Ported from PR #561: no matrix leaks across organizations."""
        other_organization = Organization.objects.create(
            name="Other", domain="other.test"
        )
        outsider = User.objects.create_user(
            username="out", email="out@other.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=other_organization, user=outsider, role="security_team"
        )
        response = self.client_for(outsider).get(
            f"/api/threat-models/{self.threat_model.pk}/report/"
        )
        self.assertEqual(response.status_code, 404)
