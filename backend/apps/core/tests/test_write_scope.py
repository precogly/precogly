"""Ids from another organization or model are refused wherever one can be sent.

Plan section 15: "an id from another threat model or organization is refused
everywhere one can be sent, with a test for each place." Each test below sends
a foreign id to one endpoint; the matching review items are R1 to R8 in
``major-changes/issues-583-584-review-findings.md``.
"""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import (
    MagicLink,
    Organization,
    OrganizationMember,
    Team,
    TeamMembership,
)
from apps.systems.models import DataAsset, Flow, OrgsystemComponent, Zone
from apps.threat_models.analysis_service import SHARED_THREAT_MODEL_KEYS
from apps.threat_models.models import (
    Assumption,
    Blueprint,
    ThreatModel,
    ThreatModelRelationship,
)
from apps.threats.models import (
    ExternalTaxonomy,
    InstanceCountermeasure,
    InstanceThreat,
    PentestFinding,
    Risk,
    RiskResponse,
    TaxonomyEntry,
)
from apps.threats.services import (
    create_instance_countermeasure,
    create_instance_threat,
)

User = get_user_model()


class WriteScopeFixture(TestCase):
    """Two organizations, each with a Security Team user and a model."""

    @classmethod
    def setUpTestData(cls):
        cls.acme = Organization.objects.create(name="Acme", domain="acme.test")
        cls.globex = Organization.objects.create(name="Globex", domain="globex.test")
        cls.acme_security = User.objects.create_user(
            username="acme-sec", email="sec@acme.test", password="x"
        )
        cls.globex_security = User.objects.create_user(
            username="globex-sec", email="sec@globex.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.acme, user=cls.acme_security, role="security_team"
        )
        OrganizationMember.objects.create(
            organization=cls.globex, user=cls.globex_security, role="security_team"
        )

        cls.acme_model = ThreatModel.objects.create(
            name="Acme TM", organization=cls.acme
        )
        cls.globex_model = ThreatModel.objects.create(
            name="Globex TM", organization=cls.globex
        )
        cls.acme_blueprint = cls.acme_model.default_blueprint
        cls.globex_blueprint = cls.globex_model.default_blueprint

        cls.globex_threat = create_instance_threat(
            cls.globex_model, whole_system=True, threat_name="Globex threat"
        )
        cls.globex_control = create_instance_countermeasure(
            cls.globex_model, countermeasure_name="Globex control"
        )
        cls.globex_source = OrgsystemComponent.objects.create(
            blueprint=cls.globex_blueprint, name="Globex source"
        )
        cls.globex_destination = OrgsystemComponent.objects.create(
            blueprint=cls.globex_blueprint, name="Globex destination"
        )
        cls.globex_flow = Flow.objects.create(
            blueprint=cls.globex_blueprint,
            source_component=cls.globex_source,
            dest_component=cls.globex_destination,
            label="Globex flow",
        )
        cls.globex_asset = DataAsset.objects.create(
            blueprint=cls.globex_blueprint, name="Globex records"
        )

    def acme_member(self, username):
        """A plain Acme member, without the personal workspace a new user gets.

        That workspace makes the user Security Team somewhere, and Security
        Team anywhere reads every model in every organization (#209).
        """
        user = User.objects.create_user(
            username=username, email=f"{username}@acme.test", password="x"
        )
        user.organization_memberships.all().delete()
        OrganizationMember.objects.create(
            organization=self.acme, user=user, role="member"
        )
        return user

    def client_for(self, user):
        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(user).access_token}"
        )
        return client

    def setUp(self):
        self.client = self.client_for(self.acme_security)


class ThreatAndControlCreateTests(WriteScopeFixture):
    """R1: threats and controls in another organization's model."""

    def test_threat_in_a_foreign_model_is_refused(self):
        response = self.client.post(
            "/api/threats/",
            {
                "threat_model": self.globex_model.id,
                "threat_name": "Planted",
                "whole_system": True,
            },
            format="json",
        )
        self.assertEqual(response.status_code, 404, response.content)
        self.assertFalse(InstanceThreat.objects.filter(threat_name="Planted").exists())

    def test_threat_in_own_model_is_created(self):
        response = self.client.post(
            "/api/threats/",
            {
                "threat_model": self.acme_model.id,
                "threat_name": "Own",
                "whole_system": True,
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.content)

    def test_control_in_a_foreign_model_is_refused(self):
        response = self.client.post(
            "/api/countermeasures/",
            {"threat_model": self.globex_model.id, "countermeasure_name": "Planted"},
            format="json",
        )
        self.assertEqual(response.status_code, 404, response.content)
        self.assertFalse(
            InstanceCountermeasure.objects.filter(
                countermeasure_name="Planted"
            ).exists()
        )

    def test_threat_cannot_move_to_another_model(self):
        threat = create_instance_threat(
            self.acme_model, whole_system=True, threat_name="Mine"
        )
        other_model = ThreatModel.objects.create(name="Acme 2", organization=self.acme)
        response = self.client.patch(
            f"/api/threats/{threat.id}/",
            {"threat_model": other_model.id},
            format="json",
        )
        self.assertEqual(response.status_code, 400, response.content)
        threat.refresh_from_db()
        self.assertEqual(threat.threat_model_id, self.acme_model.id)

    def test_control_cannot_move_to_another_model(self):
        control = create_instance_countermeasure(
            self.acme_model, countermeasure_name="Mine"
        )
        response = self.client.patch(
            f"/api/countermeasures/{control.id}/",
            {"threat_model": self.globex_model.id},
            format="json",
        )
        self.assertEqual(response.status_code, 400, response.content)
        control.refresh_from_db()
        self.assertEqual(control.threat_model_id, self.acme_model.id)

    def test_pentest_finding_in_a_foreign_model_is_refused(self):
        response = self.client.post(
            "/api/pentest-findings/",
            {
                "threat_model": self.globex_model.id,
                "finding_description": "Planted",
                "severity": "high",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 404, response.content)
        self.assertFalse(PentestFinding.objects.exists())

    def test_pentest_finding_cannot_match_a_foreign_control(self):
        response = self.client.post(
            "/api/pentest-findings/",
            {
                "threat_model": self.acme_model.id,
                "finding_description": "Mine",
                "severity": "high",
                "matched_countermeasure": self.globex_control.id,
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400, response.content)


class ReorderTests(WriteScopeFixture):
    """Collection actions that write rows named in the body."""

    def test_control_reorder_under_a_foreign_threat_is_refused(self):
        from apps.threats.services import link_countermeasure

        link_countermeasure(self.globex_control, self.globex_threat)
        response = self.client.post(
            "/api/countermeasures/reorder/",
            {
                "threat_id": self.globex_threat.id,
                "ordered_ids": [self.globex_control.id],
            },
            format="json",
        )
        self.assertEqual(response.status_code, 404, response.content)


class LinkRowCreateTests(WriteScopeFixture):
    """R2: link rows against another organization's threat or control."""

    def test_taxonomy_entry_on_a_foreign_threat_is_refused(self):
        taxonomy = ExternalTaxonomy.objects.create(slug="cwe-test", name="CWE")
        entry = TaxonomyEntry.objects.create(
            taxonomy=taxonomy, external_id="CWE-89", title="SQL injection"
        )
        response = self.client.post(
            "/api/threat-taxonomy-entries/",
            {"threat": self.globex_threat.id, "taxonomy_entry": entry.id},
            format="json",
        )
        self.assertEqual(response.status_code, 404, response.content)

    def test_standard_on_a_foreign_control_is_refused(self):
        response = self.client.post(
            "/api/instance-countermeasure-standards/",
            {"countermeasure": self.globex_control.id, "sufficiency": "full"},
            format="json",
        )
        self.assertEqual(response.status_code, 404, response.content)

    def test_comment_on_a_foreign_control_is_refused(self):
        response = self.client.post(
            "/api/countermeasure-comments/",
            {"countermeasure": self.globex_control.id, "body": "Planted"},
            format="json",
        )
        self.assertEqual(response.status_code, 404, response.content)
        self.assertFalse(self.globex_control.comments.exists())


class RiskCreateTests(WriteScopeFixture):
    """Risks and responses nested under a foreign model."""

    def test_risk_in_a_foreign_model_is_refused(self):
        response = self.client.post(
            f"/api/threat-models/{self.globex_model.id}/risks/",
            {"name": "Planted", "rating_inputs": {"level": "high"}},
            format="json",
        )
        self.assertEqual(response.status_code, 404, response.content)
        self.assertFalse(Risk.objects.filter(name="Planted").exists())

    def test_risk_bulk_update_needs_write_access(self):
        member = self.acme_member("viewer")
        risk = Risk.objects.create(threat_model=self.acme_model, name="R")
        response = self.client_for(member).post(
            f"/api/threat-models/{self.acme_model.id}/risks/bulk-update/",
            {"risk_ids": [risk.id], "status": "accepted"},
            format="json",
        )
        self.assertEqual(response.status_code, 403, response.content)


class BlueprintRowTests(WriteScopeFixture):
    """R3: zones, components and asset links across blueprints and organizations."""

    def test_zone_cannot_move_to_a_foreign_blueprint(self):
        zone = Zone.objects.create(blueprint=self.acme_blueprint, name="DMZ")
        response = self.client.patch(
            f"/api/zones/{zone.id}/",
            {"blueprint": self.globex_blueprint.id},
            format="json",
        )
        self.assertEqual(response.status_code, 400, response.content)
        zone.refresh_from_db()
        self.assertEqual(zone.blueprint_id, self.acme_blueprint.id)

    def test_component_cannot_move_to_another_blueprint_of_its_model(self):
        second = Blueprint.objects.create(threat_model=self.acme_model, name="Second")
        component = OrgsystemComponent.objects.create(
            blueprint=self.acme_blueprint, name="API"
        )
        response = self.client.patch(
            f"/api/components/{component.id}/",
            {"blueprint": second.id},
            format="json",
        )
        self.assertEqual(response.status_code, 400, response.content)

    def test_component_in_a_foreign_blueprint_is_refused(self):
        response = self.client.post(
            "/api/components/",
            {"blueprint": self.globex_blueprint.id, "name": "Planted"},
            format="json",
        )
        self.assertEqual(response.status_code, 404, response.content)

    def test_flow_asset_on_a_foreign_flow_is_refused(self):
        response = self.client.post(
            "/api/flow-assets/",
            {
                "flow": self.globex_flow.id,
                "data_asset": self.globex_asset.id,
                "protection_method": "none",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 404, response.content)

    def test_component_asset_on_a_foreign_component_is_refused(self):
        response = self.client.post(
            "/api/component-data-assets/",
            {
                "component": self.globex_source.id,
                "data_asset": self.globex_asset.id,
                "data_state": "at_rest",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 404, response.content)

    def test_asset_link_across_blueprints_is_refused(self):
        component = OrgsystemComponent.objects.create(
            blueprint=self.acme_blueprint, name="API"
        )
        second = Blueprint.objects.create(threat_model=self.acme_model, name="Second")
        asset = DataAsset.objects.create(blueprint=second, name="Elsewhere")
        response = self.client.post(
            "/api/component-data-assets/",
            {
                "component": component.id,
                "data_asset": asset.id,
                "data_state": "at_rest",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400, response.content)

    def test_component_cannot_link_a_foreign_system(self):
        from apps.systems.models import Orgsystem

        foreign_system = Orgsystem.objects.create(
            organization=self.globex, name="Globex ERP"
        )
        response = self.client.post(
            "/api/components/",
            {
                "blueprint": self.acme_blueprint.id,
                "name": "ERP link",
                "orgsystem": foreign_system.id,
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400, response.content)


class UserFieldTests(WriteScopeFixture):
    """R4: owner and assignee fields take members of the model's organization only."""

    def assert_refused(self, response, field_name):
        self.assertEqual(response.status_code, 400, response.content)
        self.assertNotIn(b"sec@globex.test", response.content)
        self.assertIn(field_name, response.json())

    def test_assumption_owner(self):
        response = self.client.post(
            f"/api/threat-models/{self.acme_model.id}/assumptions/",
            {"description": "A", "owner": self.globex_security.id},
            format="json",
        )
        self.assert_refused(response, "owner")
        self.assertFalse(Assumption.objects.exists())

    def test_business_objective_owner(self):
        response = self.client.post(
            f"/api/threat-models/{self.acme_model.id}/business-objectives/",
            {"name": "Revenue", "owner": self.globex_security.id},
            format="json",
        )
        self.assert_refused(response, "owner")

    def test_risk_owner_and_assignee(self):
        for field_name in ("owner", "assigned_to"):
            with self.subTest(field_name=field_name):
                response = self.client.post(
                    f"/api/threat-models/{self.acme_model.id}/risks/",
                    {
                        "name": "R",
                        "rating_inputs": {"level": "high"},
                        field_name: self.globex_security.id,
                    },
                    format="json",
                )
                self.assert_refused(
                    response, "assignedTo" if field_name == "assigned_to" else "owner"
                )

    def test_risk_response_owner(self):
        risk = Risk.objects.create(threat_model=self.acme_model, name="R")
        response = self.client.post(
            f"/api/threat-models/{self.acme_model.id}/risks/{risk.id}/responses/",
            {"strategy": "reduce", "owner": self.globex_security.id},
            format="json",
        )
        self.assert_refused(response, "owner")
        self.assertFalse(RiskResponse.objects.exists())

    def test_control_owner_and_verifier(self):
        control = create_instance_countermeasure(
            self.acme_model, countermeasure_name="Mine"
        )
        for field_name, json_name in (
            ("assigned_owner", "assignedOwner"),
            ("verified_by", "verifiedBy"),
        ):
            with self.subTest(field_name=field_name):
                response = self.client.patch(
                    f"/api/countermeasures/{control.id}/",
                    {field_name: self.globex_security.id},
                    format="json",
                )
                self.assert_refused(response, json_name)

    def test_risk_bulk_owner(self):
        risk = Risk.objects.create(threat_model=self.acme_model, name="R")
        response = self.client.post(
            f"/api/threat-models/{self.acme_model.id}/risks/bulk-update/",
            {"risk_ids": [risk.id], "owner": self.globex_security.id},
            format="json",
        )
        self.assertEqual(response.status_code, 400, response.content)
        risk.refresh_from_db()
        self.assertIsNone(risk.owner_id)

    def test_member_of_the_organization_is_accepted(self):
        response = self.client.post(
            f"/api/threat-models/{self.acme_model.id}/business-objectives/",
            {"name": "Revenue", "owner": self.acme_security.id},
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.content)


class SharedViewTests(WriteScopeFixture):
    """R5: the shared view's model payload has exactly the allowed keys."""

    def test_shared_model_keys_are_exactly_the_allow_list(self):
        ThreatModelRelationship.objects.create(
            source_threat_model=ThreatModel.objects.create(
                name="Neighbour", organization=self.acme
            ),
            target_threat_model=self.acme_model,
            relation_type=ThreatModelRelationship.RelationType.RELATED_TO,
        )
        link = MagicLink.objects.create(
            threat_model=self.acme_model,
            created_by=self.acme_security,
            token="shared-view-test",
            expires_at=timezone.now() + timedelta(days=1),
        )
        response = APIClient().get(f"/api/share/{link.token}/")
        self.assertEqual(response.status_code, 200, response.content)
        returned = set(response.json()["threatModel"])
        expected = {
            "".join(
                part.capitalize() if index else part
                for index, part in enumerate(key.split("_"))
            )
            for key in SHARED_THREAT_MODEL_KEYS
        }
        self.assertEqual(returned, expected)
        self.assertNotIn(b"Neighbour", response.content)


class PlatformStatusTests(WriteScopeFixture):
    """R6: the platform gate runs on create through the API."""

    def setUp(self):
        super().setUp()
        team = Team.objects.create(organization=self.acme, name="Payments")
        self.acme_model.owning_team = team
        self.acme_model.save(update_fields=["owning_team"])
        self.member = self.acme_member("dev")
        TeamMembership.objects.create(team=team, user=self.member, role="member")

    def test_member_cannot_create_a_platform_control(self):
        response = self.client_for(self.member).post(
            "/api/countermeasures/",
            {
                "threat_model": self.acme_model.id,
                "countermeasure_name": "Platform WAF",
                "status": "platform",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 403, response.content)
        self.assertFalse(
            InstanceCountermeasure.objects.filter(
                countermeasure_name="Platform WAF"
            ).exists()
        )

    def test_member_can_create_an_ordinary_control(self):
        response = self.client_for(self.member).post(
            "/api/countermeasures/",
            {"threat_model": self.acme_model.id, "countermeasure_name": "WAF"},
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.content)

    def test_security_team_can_create_a_platform_control(self):
        response = self.client.post(
            "/api/countermeasures/",
            {
                "threat_model": self.acme_model.id,
                "countermeasure_name": "Platform WAF",
                "status": "platform",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.content)


class ModelScopeTests(WriteScopeFixture):
    """R8 and the model create path."""

    def test_nested_routes_follow_team_visibility(self):
        team = Team.objects.create(organization=self.acme, name="Payments")
        self.acme_model.owning_team = team
        self.acme_model.save(update_fields=["owning_team"])
        outsider = self.acme_member("outsider")
        client = self.client_for(outsider)
        for route in ("assumptions", "business-objectives", "use-cases"):
            with self.subTest(route=route):
                response = client.get(
                    f"/api/threat-models/{self.acme_model.id}/{route}/"
                )
                self.assertEqual(response.status_code, 404, response.content)

    def test_create_refuses_a_foreign_referenced_model(self):
        response = self.client.post(
            "/api/threat-models/",
            {"name": "New", "referenced_model_ids": [self.globex_model.id]},
            format="json",
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertFalse(ThreatModel.objects.filter(name="New").exists())

    def test_create_links_a_visible_model(self):
        response = self.client.post(
            "/api/threat-models/",
            {"name": "New", "referenced_model_ids": [self.acme_model.id]},
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.content)
        created = ThreatModel.objects.get(name="New")
        self.assertTrue(
            ThreatModelRelationship.objects.filter(
                source_threat_model=created, target_threat_model=self.acme_model
            ).exists()
        )

    def test_create_refuses_a_foreign_organization(self):
        response = self.client.post(
            "/api/threat-models/",
            {"name": "Planted", "organization": self.globex.id},
            format="json",
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertFalse(ThreatModel.objects.filter(name="Planted").exists())

    def test_model_cannot_move_to_another_organization(self):
        response = self.client.patch(
            f"/api/threat-models/{self.acme_model.id}/",
            {"organization": self.globex.id},
            format="json",
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.acme_model.refresh_from_db()
        self.assertEqual(self.acme_model.organization_id, self.acme.id)
