"""Assumptions, business objectives and methodologies (steps 9 to 11, section 4.8)."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import OrgsystemComponent
from apps.threat_models.models import (
    Assumption,
    Blueprint,
    BusinessObjective,
    ThreatModel,
)
from apps.threat_models.report_service import build_report_data
from apps.threat_models.serializers import ThreatModelSerializer
from apps.threats.services import create_instance_threat, create_risk

User = get_user_model()


class Fixture(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="u", email="u@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        cls.threat_model = ThreatModel.objects.create(
            name="TM", organization=cls.organization
        )
        cls.blueprint = cls.threat_model.default_blueprint
        cls.api = OrgsystemComponent.objects.create(blueprint=cls.blueprint, name="API")
        cls.other_blueprint = Blueprint.objects.create(
            threat_model=cls.threat_model, name="Net"
        )
        cls.firewall = OrgsystemComponent.objects.create(
            blueprint=cls.other_blueprint, name="Firewall"
        )

    def api_client(self):
        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(self.user).access_token}"
        )
        return client


class AssumptionTests(Fixture):
    def test_moving_to_another_blueprint_cannot_keep_old_links(self):
        """R42: a blueprint change alone is refused while links point back."""
        client = self.api_client()
        base = f"/api/threat-models/{self.threat_model.id}/assumptions/"
        created = client.post(
            base,
            {"description": "Only staff reach it", "component_ids": [self.api.id]},
            format="json",
        )
        self.assertEqual(created.status_code, 201, created.content)
        url = f"{base}{created.data['id']}/"

        moved_alone = client.patch(
            url, {"blueprint": self.other_blueprint.id}, format="json"
        )
        self.assertEqual(moved_alone.status_code, 400, moved_alone.content)
        self.assertIn("component_ids", moved_alone.data)

        moved_with_links = client.patch(
            url,
            {"blueprint": self.other_blueprint.id, "component_ids": [self.firewall.id]},
            format="json",
        )
        self.assertEqual(moved_with_links.status_code, 200, moved_with_links.content)
        self.assertEqual(moved_with_links.data["component_ids"], [self.firewall.id])

    def test_crud_defaults_and_related_components(self):
        client = self.api_client()
        base = f"/api/threat-models/{self.threat_model.id}/assumptions/"
        created = client.post(
            base,
            {
                "description": "TLS everywhere",
                "topic": "security",
                "component_ids": [self.api.id],
                "impact": "Eavesdropping is out",
            },
            format="json",
        )
        self.assertEqual(created.status_code, 201, created.content)
        self.assertEqual(created.data["blueprint"], self.blueprint.id)
        self.assertEqual(created.data["validity"], "unverified")
        self.assertEqual(
            created.data["components"], [{"id": self.api.id, "name": "API"}]
        )
        refused = client.post(
            base,
            {"description": "Cross", "component_ids": [self.firewall.id]},
            format="json",
        )
        self.assertEqual(refused.status_code, 400)
        self.assertIn("component_ids", refused.data)
        verified = client.patch(
            f"{base}{created.data['id']}/",
            {
                "validity": "verified",
                "validation_method": "Reviewed the config",
                "owner_name": "Ops lead",
                "component_ids": [],
            },
            format="json",
        )
        self.assertEqual(verified.status_code, 200, verified.content)
        self.assertEqual(verified.data["component_ids"], [])
        client.post(
            base,
            {"description": "Second", "blueprint": self.other_blueprint.id},
            format="json",
        )
        by_blueprint = client.get(base, {"blueprint": self.other_blueprint.id})
        self.assertEqual(len(by_blueprint.data["results"]), 1)
        completion = ThreatModelSerializer()._compute_completion_status(
            self.threat_model
        )
        self.assertEqual(completion["assumptions"], {"total": 2, "unverified": 1})
        scope = build_report_data(self.threat_model)["scope"]
        self.assertEqual(
            {a["validity"] for a in scope["assumptions"]}, {"verified", "unverified"}
        )
        self.assertEqual(scope["assumptions"][0]["owner"], "Ops lead")
        other = ThreatModel.objects.create(name="Other", organization=self.organization)
        self.assertEqual(
            client.get(f"/api/threat-models/{other.id}/assumptions/").data["results"],
            [],
        )
        self.assertEqual(Assumption.objects.count(), 2)


class BusinessObjectiveTests(Fixture):
    def test_objectives_link_to_threats_and_risks_of_the_same_model(self):
        client = self.api_client()
        base = f"/api/threat-models/{self.threat_model.id}/business-objectives/"
        created = client.post(
            base,
            {"name": "Keep card data private", "criticality": "high"},
            format="json",
        )
        self.assertEqual(created.status_code, 201, created.content)
        objective_id = created.data["id"]
        other = ThreatModel.objects.create(name="Other", organization=self.organization)
        foreign = BusinessObjective.objects.create(threat_model=other, name="Foreign")

        threat = create_instance_threat(
            self.threat_model, targets=[self.api], threat_name="SQLi"
        )
        linked = client.patch(
            f"/api/threats/{threat.id}/",
            {"business_objective_ids": [objective_id]},
            format="json",
        )
        self.assertEqual(linked.status_code, 200, linked.content)
        self.assertEqual(
            linked.data["business_objectives"],
            [{"id": objective_id, "name": "Keep card data private"}],
        )
        refused = client.patch(
            f"/api/threats/{threat.id}/",
            {"business_objective_ids": [foreign.id]},
            format="json",
        )
        self.assertEqual(refused.status_code, 400)

        risk = client.post(
            f"/api/threat-models/{self.threat_model.id}/risks/",
            {
                "name": "Leak",
                "rating_inputs": {"level": "high"},
                "business_objective_ids": [objective_id],
            },
            format="json",
        )
        self.assertEqual(risk.status_code, 201, risk.content)
        self.assertEqual(
            [o["name"] for o in risk.data["business_objectives"]],
            ["Keep card data private"],
        )
        listed = client.get(base)
        self.assertEqual(
            (listed.data[0]["threat_count"], listed.data[0]["risk_count"]), (1, 1)
        )
        report = build_report_data(self.threat_model)
        self.assertEqual(report["scope"]["business_objectives"][0]["threat_count"], 1)
        self.assertEqual(
            report["threat_analysis"]["threats"][0]["business_objectives"],
            ["Keep card data private"],
        )
        self.assertEqual(
            report["risks"][0]["business_objectives"], ["Keep card data private"]
        )
        create_risk(self.threat_model, name="Plain", level="low")


class MethodologyTests(Fixture):
    def test_methodologies_default_validate_and_report(self):
        self.assertEqual(self.threat_model.methodologies, ["STRIDE"])
        client = self.api_client()
        url = f"/api/threat-models/{self.threat_model.id}/"
        updated = client.patch(
            url,
            {"methodologies": ["STRIDE", "LINDDUN", "Our own", "STRIDE"]},
            format="json",
        )
        self.assertEqual(updated.status_code, 200, updated.content)
        self.assertEqual(
            updated.data["methodologies"], ["STRIDE", "LINDDUN", "Our own"]
        )
        refused = client.patch(url, {"methodologies": ["", "STRIDE"]}, format="json")
        self.assertEqual(refused.status_code, 400)
        listed = client.get("/api/threat-models/")
        row = next(r for r in listed.data["results"] if r["id"] == self.threat_model.id)
        self.assertEqual(row["methodologies"], ["STRIDE", "LINDDUN", "Our own"])
        created = client.post(
            "/api/threat-models/",
            {
                "name": "New",
                "organization": self.organization.id,
                "methodologies": ["PASTA"],
            },
            format="json",
        )
        self.assertEqual(created.status_code, 201, created.content)
        self.assertEqual(
            ThreatModel.objects.get(id=created.data["id"]).methodologies, ["PASTA"]
        )
        fresh = ThreatModel.objects.get(pk=self.threat_model.pk)
        self.assertEqual(
            build_report_data(fresh)["metadata"]["methodologies"],
            ["STRIDE", "LINDDUN", "Our own"],
        )
