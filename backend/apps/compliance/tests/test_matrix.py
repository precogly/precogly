"""Tests for the compliance-matrix endpoint."""

from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase

from apps.compliance.models import StandardFramework, StandardRequirement
from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import DataFlow, OrgsystemComponent
from apps.threat_models.models import ThreatModel
from apps.threats.models import (
    ComponentInstanceThreat,
    CountermeasureThreatLink,
    DataFlowInstanceThreat,
    InstanceCountermeasure,
    InstanceCountermeasureStandard,
)

User = get_user_model()


class ComplianceMatrixTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Kestrel", domain="kestrel.test")
        cls.other_org = Organization.objects.create(
            name="Contoso", domain="contoso.test"
        )
        cls.user = User.objects.create_user(
            username="matrix@kestrel.test",
            email="matrix@kestrel.test",
            password="pw",
        )
        OrganizationMember.objects.create(
            organization=cls.org, user=cls.user, role="security_team"
        )

        cls.tm = ThreatModel.objects.create(name="TM-A", organization=cls.org)
        cls.other_tm = ThreatModel.objects.create(
            name="TM-B", organization=cls.other_org
        )

        cls.framework = StandardFramework.objects.create(
            name="NIST 800-53 Rev 5", slug="nist-800-53-r5"
        )
        cls.req_ac3 = StandardRequirement.objects.create(
            framework=cls.framework,
            section_code="AC-3",
            description="Access enforcement",
        )
        cls.req_au6 = StandardRequirement.objects.create(
            framework=cls.framework,
            section_code="AU-6",
            description="Audit review",
        )
        cls.req_cm2 = StandardRequirement.objects.create(
            framework=cls.framework,
            section_code="CM-2",
            description="Baseline configuration",
        )

        cls.component = OrgsystemComponent.objects.create(
            threat_model=cls.tm, name="API"
        )
        cls.dest = OrgsystemComponent.objects.create(threat_model=cls.tm, name="DB")
        cls.flow = DataFlow.objects.create(
            source_component=cls.component, dest_component=cls.dest, label="query"
        )
        cls.threat = ComponentInstanceThreat.objects.create(
            component=cls.component,
            threat_name="Spoofing",
            inherent_severity="high",
        )
        cls.flow_threat = DataFlowInstanceThreat.objects.create(
            data_flow=cls.flow,
            threat_name="Sniffing",
            inherent_severity="medium",
            format_metadata={"cyclonedx": {"ctrl_id": "AC-3"}},
        )
        # Threat-side ctrl_id fallback: this threat is not linked to any CM, so
        # it can only reach AU-6 via its own format_metadata.
        cls.orphan_threat = ComponentInstanceThreat.objects.create(
            component=cls.component,
            threat_name="Undetected access",
            inherent_severity="medium",
            format_metadata={"cyclonedx": {"ctrl_id": "AU-6"}},
        )

        cls.cm_ac3 = InstanceCountermeasure.objects.create(
            threat_model=cls.tm,
            countermeasure_name="MFA everywhere",
            status="implemented",
            control_nature="preventive",
            is_inherited=False,
            format_metadata={
                "cyclonedx": {
                    "providing_system": "Platform IAM",
                    "responsibility_source": "crm",
                    "control_type": "preventive",
                    "is_inherited": True,
                    "poam": {"poam_id": "POAM-123", "due_date": "2026-12-31"},
                }
            },
        )
        InstanceCountermeasureStandard.objects.create(
            countermeasure=cls.cm_ac3,
            requirement=cls.req_ac3,
            section_code="AC-3",
            sufficiency="partial",
        )
        InstanceCountermeasureStandard.objects.create(
            countermeasure=cls.cm_ac3,
            requirement=cls.req_au6,
            section_code="AU-6",
            sufficiency="full",
        )
        CountermeasureThreatLink.objects.create(
            countermeasure=cls.cm_ac3, component_threat=cls.threat
        )

        cls.cm_au6 = InstanceCountermeasure.objects.create(
            threat_model=cls.tm,
            countermeasure_name="Centralised logging",
            status="planned",
            format_metadata={"cyclonedx": {"ctrl_id": "AU-6"}},
        )

    def test_matrix_lists_families_and_countermeasures(self):
        self.client.force_authenticate(self.user)
        url = reverse("compliance-matrix", kwargs={"tm_id": self.tm.id})
        response = self.client.get(url)
        assert response.status_code == 200
        data = response.json()
        assert data["framework"]["name"] == "NIST 800-53 Rev 5"

        families = {fam["family"]: fam for fam in data["families"]}
        assert set(families) == {"AC", "AU"}
        assert "CM" not in families

        ac3 = families["AC"]["requirements"][0]
        assert ac3["sectionCode"] == "AC-3"
        assert [cm["name"] for cm in ac3["countermeasures"]] == ["MFA everywhere"]
        assert ac3["countermeasures"][0]["mappings"] == [
            {"sufficiency": "partial", "sectionCode": "AC-3", "evidenceUrl": ""}
        ]

    def test_matrix_requires_authentication(self):
        url = reverse("compliance-matrix", kwargs={"tm_id": self.tm.id})
        response = self.client.get(url)
        assert response.status_code in (401, 403)

    def test_matrix_hides_threat_models_in_other_orgs(self):
        self.client.force_authenticate(self.user)
        url = reverse("compliance-matrix", kwargs={"tm_id": self.other_tm.id})
        response = self.client.get(url)
        assert response.status_code == 404

    def test_matrix_returns_warning_for_unknown_framework(self):
        self.client.force_authenticate(self.user)
        url = reverse("compliance-matrix", kwargs={"tm_id": self.tm.id})
        response = self.client.get(url, {"framework": "does-not-exist"})
        assert response.status_code == 200
        assert response.json()["framework"] is None
        assert "warning" in response.json()

    def test_threat_side_ctrl_id_surfaces_orphan_threats(self):
        self.client.force_authenticate(self.user)
        url = reverse("compliance-matrix", kwargs={"tm_id": self.tm.id})
        data = self.client.get(url).json()
        families = {fam["family"]: fam for fam in data["families"]}
        au6 = families["AU"]["requirements"][0]
        threat_names = sorted(t["name"] for t in au6["threats"])
        # AU-6 sees:
        #   - "Spoofing" via CountermeasureThreatLink (cm_ac3 maps to AU-6)
        #   - "Undetected access" via its own format_metadata.cyclonedx.ctrl_id
        assert "Undetected access" in threat_names
        # AC-3 sees the flow threat via its own format_metadata.
        ac3 = families["AC"]["requirements"][0]
        flow_names = [t["name"] for t in ac3["threats"] if t["kind"] == "flow"]
        assert "Sniffing" in flow_names

    def test_cm_payload_projects_inheritance_and_poam(self):
        self.client.force_authenticate(self.user)
        url = reverse("compliance-matrix", kwargs={"tm_id": self.tm.id})
        data = self.client.get(url).json()
        ac3 = data["families"][0]["requirements"][0]
        cm = ac3["countermeasures"][0]
        assert cm["inheritance"] == {
            "isInherited": True,
            "providingSystem": "Platform IAM",
            "responsibilitySource": "crm",
            "controlType": "preventive",
        }
        assert cm["poam"] == {"poamId": "POAM-123", "dueDate": "2026-12-31"}

    def test_include_empty_shows_seeded_but_unlinked_requirements(self):
        self.client.force_authenticate(self.user)
        url = reverse("compliance-matrix", kwargs={"tm_id": self.tm.id})

        default_families = {
            fam["family"] for fam in self.client.get(url).json()["families"]
        }
        assert "CM" not in default_families

        expanded = self.client.get(url, {"include_empty": "true"}).json()
        expanded_families = {fam["family"]: fam for fam in expanded["families"]}
        assert "CM" in expanded_families
        cm2 = expanded_families["CM"]["requirements"][0]
        assert cm2["sectionCode"] == "CM-2"
        assert cm2["countermeasures"] == []
        assert cm2["threats"] == []


class ComplianceMatrixHtmlTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Kestrel", domain="kestrel.test")
        cls.user = User.objects.create_user(
            username="html@kestrel.test",
            email="html@kestrel.test",
            password="pw",
        )
        OrganizationMember.objects.create(
            organization=cls.org, user=cls.user, role="security_team"
        )
        cls.tm = ThreatModel.objects.create(name="TM-A", organization=cls.org)
        cls.framework = StandardFramework.objects.create(
            name="NIST 800-53 Rev 5", slug="nist-800-53-r5"
        )
        StandardRequirement.objects.create(
            framework=cls.framework,
            section_code="AC-3",
            description="Access enforcement",
        )

    def test_html_view_renders_matrix(self):
        self.client.force_login(self.user)
        url = reverse("compliance-matrix-html", kwargs={"tm_id": self.tm.id})
        response = self.client.get(url, {"include_empty": "true"})
        assert response.status_code == 200
        body = response.content.decode()
        assert "AC-3" in body
        assert "Access enforcement" in body
