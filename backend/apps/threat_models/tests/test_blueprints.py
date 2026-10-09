"""Blueprints: one per model from the start, CRUD, last-blueprint protection,
cross-blueprint validation and one primary DFD per blueprint."""

from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.diagrams.models import DFD
from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import Flow, OrgsystemComponent, Zone
from apps.threat_models.models import Blueprint, OutOfScopeItem, ThreatModel

User = get_user_model()


def _client_for(user):
    client = APIClient()
    token = str(RefreshToken.for_user(user).access_token)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return client


class DefaultBlueprintTests(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Org", domain="org.test")

    def test_every_new_model_gets_a_blueprint_named_after_it(self):
        threat_model = ThreatModel.objects.create(
            name="Payments", organization=self.organization
        )
        self.assertEqual(threat_model.blueprints.count(), 1)
        blueprint = threat_model.default_blueprint
        self.assertEqual(blueprint.name, "Payments")
        self.assertEqual(blueprint.model_types, ["data-flow"])

    def test_renaming_the_model_renames_the_blueprint_that_carried_its_name(self):
        threat_model = ThreatModel.objects.create(
            name="Payments", organization=self.organization
        )
        Blueprint.objects.create(
            threat_model=threat_model, name="Network view", display_order=1
        )

        threat_model.name = "Payments v2"
        threat_model.save()

        self.assertEqual(
            set(threat_model.blueprints.values_list("name", flat=True)),
            {"Payments v2", "Network view"},
        )

    def test_a_blueprint_renamed_by_hand_does_not_follow_the_model(self):
        threat_model = ThreatModel.objects.create(
            name="Payments", organization=self.organization
        )
        blueprint = threat_model.default_blueprint
        blueprint.name = "Card path"
        blueprint.save()

        threat_model.name = "Payments v2"
        threat_model.save()

        blueprint.refresh_from_db()
        self.assertEqual(blueprint.name, "Card path")

    def test_one_primary_dfd_per_blueprint(self):
        threat_model = ThreatModel.objects.create(
            name="Payments", organization=self.organization
        )
        first = threat_model.default_blueprint
        second = Blueprint.objects.create(
            threat_model=threat_model, name="Second", display_order=1
        )
        DFD.objects.create(blueprint=first, name="A", is_primary=True)
        DFD.objects.create(blueprint=second, name="B", is_primary=True)
        with self.assertRaises(IntegrityError):
            DFD.objects.create(blueprint=first, name="C", is_primary=True)


class BlueprintApiTests(TestCase):
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
        other_organization = Organization.objects.create(
            name="Other", domain="other.test"
        )
        cls.other_model = ThreatModel.objects.create(
            name="Elsewhere", organization=other_organization
        )

    def setUp(self):
        self.client = _client_for(self.user)
        self.base_url = f"/api/threat-models/{self.threat_model.id}/blueprints/"

    def test_list_create_update(self):
        listed = self.client.get(self.base_url)
        self.assertEqual(listed.status_code, 200)
        self.assertEqual([b["name"] for b in listed.data], ["Payments"])

        created = self.client.post(
            self.base_url,
            {
                "name": "Network view",
                "model_types": ["network", "deployment"],
                "display_order": 1,
            },
            format="json",
        )
        self.assertEqual(created.status_code, 201, created.content)
        self.assertEqual(created.data["threat_model"], self.threat_model.id)
        self.assertEqual(created.data["model_types"], ["network", "deployment"])

        updated = self.client.patch(
            f"{self.base_url}{created.data['id']}/",
            {"scope_description": "Plant floor only"},
            format="json",
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.data["scope_description"], "Plant floor only")

    def test_unknown_model_type_is_refused(self):
        response = self.client.post(
            self.base_url, {"name": "Bad", "model_types": ["sketch"]}, format="json"
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("model_types", response.data)

    def test_the_last_blueprint_cannot_be_deleted(self):
        only = self.threat_model.default_blueprint
        response = self.client.delete(f"{self.base_url}{only.id}/")
        self.assertEqual(response.status_code, 400)
        self.assertTrue(Blueprint.objects.filter(id=only.id).exists())

        second = Blueprint.objects.create(
            threat_model=self.threat_model, name="Second", display_order=1
        )
        response = self.client.delete(f"{self.base_url}{second.id}/")
        self.assertEqual(response.status_code, 204)

    def test_delete_preview_counts_what_goes(self):
        second = Blueprint.objects.create(
            threat_model=self.threat_model, name="Second", display_order=1
        )
        api = OrgsystemComponent.objects.create(blueprint=second, name="API")
        database = OrgsystemComponent.objects.create(
            blueprint=second, name="DB", category="datastore"
        )
        Flow.objects.create(
            blueprint=second, source_component=api, dest_component=database
        )
        Zone.objects.create(blueprint=second, name="Zone")
        DFD.objects.create(blueprint=second, name="View", is_primary=True)
        OutOfScopeItem.objects.create(blueprint=second, name="Mainframe")

        response = self.client.get(f"{self.base_url}{second.id}/delete_preview/")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.data["is_last"])
        self.assertEqual(response.data["components"], 2)
        self.assertEqual(response.data["flows"], 1)
        self.assertEqual(response.data["zones"], 1)
        self.assertEqual(response.data["diagrams"], 1)
        self.assertEqual(response.data["out_of_scope_items"], 1)

    def test_another_tenants_model_is_not_reachable(self):
        response = self.client.get(
            f"/api/threat-models/{self.other_model.id}/blueprints/"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, [])
        created = self.client.post(
            f"/api/threat-models/{self.other_model.id}/blueprints/",
            {"name": "Leak"},
            format="json",
        )
        self.assertEqual(created.status_code, 404)

    def test_threat_model_detail_lists_blueprints(self):
        response = self.client.get(f"/api/threat-models/{self.threat_model.id}/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([b["name"] for b in response.data["blueprints"]], ["Payments"])


class CrossBlueprintValidationTests(TestCase):
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
        cls.first = cls.threat_model.default_blueprint
        cls.second = Blueprint.objects.create(
            threat_model=cls.threat_model, name="Second", display_order=1
        )
        cls.first_zone = Zone.objects.create(blueprint=cls.first, name="DMZ")
        cls.api = OrgsystemComponent.objects.create(blueprint=cls.first, name="API")
        cls.remote = OrgsystemComponent.objects.create(
            blueprint=cls.second, name="Remote"
        )

    def setUp(self):
        self.client = _client_for(self.user)

    def test_component_zone_must_share_the_blueprint(self):
        response = self.client.post(
            "/api/components/",
            {
                "blueprint": self.second.id,
                "name": "Mixed",
                "zone": self.first_zone.id,
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400)

    def test_flow_ends_must_share_the_blueprint(self):
        response = self.client.post(
            "/api/flows/",
            {
                "source_component": self.api.id,
                "dest_component": self.remote.id,
                "label": "x",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400)

    def test_flow_blueprint_defaults_to_the_source_components(self):
        database = OrgsystemComponent.objects.create(
            blueprint=self.first, name="DB", category="datastore"
        )
        response = self.client.post(
            "/api/flows/",
            {
                "source_component": self.api.id,
                "dest_component": database.id,
                "label": "q",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.data["blueprint"], self.first.id)

    def test_dfd_create_defaults_to_the_models_first_blueprint(self):
        response = self.client.post(
            "/api/diagrams/",
            {"threat_model_id": self.threat_model.id, "name": "Primary"},
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.data["blueprint"], self.first.id)
        self.assertEqual(response.data["threat_model"], self.threat_model.id)
        self.assertTrue(response.data["is_primary"])

        second = self.client.post(
            "/api/diagrams/",
            {"blueprint_id": self.second.id, "name": "Network"},
            format="json",
        )
        self.assertEqual(second.status_code, 201, second.content)
        self.assertEqual(second.data["blueprint"], self.second.id)
        self.assertTrue(second.data["is_primary"])

    def test_out_of_scope_item_defaults_to_the_first_blueprint_and_refuses_foreign_ones(
        self,
    ):
        base = f"/api/threat-models/{self.threat_model.id}/out-of-scope-items/"
        created = self.client.post(base, {"name": "Mainframe"}, format="json")
        self.assertEqual(created.status_code, 201, created.content)
        self.assertEqual(created.data["blueprint"], self.first.id)

        other_model = ThreatModel.objects.create(
            name="Other", organization=self.organization
        )
        foreign = self.client.post(
            base,
            {"name": "Leak", "blueprint": other_model.default_blueprint.id},
            format="json",
        )
        self.assertEqual(foreign.status_code, 400)
