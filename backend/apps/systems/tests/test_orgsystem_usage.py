"""Inventory systems: usage counts and the delete guard (plan J1, H5)."""

from django.contrib.auth import get_user_model
from django.db import connection
from django.db.models import RestrictedError
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import Orgsystem, OrgsystemComponent
from apps.threat_models.models import ThreatModel

User = get_user_model()


class OrgsystemUsageTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="sec", email="sec@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        cls.payments = Orgsystem.objects.create(
            organization=cls.organization, name="Payments"
        )
        cls.ledger = Orgsystem.objects.create(
            organization=cls.organization, name="Ledger"
        )
        cls.unused = Orgsystem.objects.create(
            organization=cls.organization, name="Unused"
        )
        cls.model_one = ThreatModel.objects.create(
            name="Checkout", organization=cls.organization, primary_system=cls.payments
        )
        cls.model_two = ThreatModel.objects.create(
            name="Refunds", organization=cls.organization, primary_system=cls.payments
        )
        cls.model_three = ThreatModel.objects.create(
            name="Reporting", organization=cls.organization
        )
        # Two system assets stand for Payments, one for Ledger.
        for blueprint, orgsystem, name in (
            (cls.model_one.default_blueprint, cls.payments, "Payments core"),
            (cls.model_three.default_blueprint, cls.payments, "Payments feed"),
            (cls.model_three.default_blueprint, cls.ledger, "Ledger feed"),
        ):
            OrgsystemComponent.objects.create(
                blueprint=blueprint, orgsystem=orgsystem, name=name, kind="system"
            )

    def setUp(self):
        self.client = APIClient()
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(self.user).access_token}"
        )

    def test_list_carries_both_counts(self):
        response = self.client.get("/api/systems/")
        self.assertEqual(response.status_code, 200)
        rows = {
            row["name"]: (row["primary_model_count"], row["linked_component_count"])
            for row in response.data["results"]
        }
        self.assertEqual(rows, {"Payments": (2, 2), "Ledger": (0, 1), "Unused": (0, 0)})

    def test_detail_carries_counts_and_primary_models(self):
        response = self.client.get(f"/api/systems/{self.payments.id}/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["primary_model_count"], 2)
        self.assertEqual(response.data["linked_component_count"], 2)
        self.assertEqual(
            response.data["primary_models"],
            [
                {"id": self.model_one.id, "name": "Checkout"},
                {"id": self.model_two.id, "name": "Refunds"},
            ],
        )

    def test_create_response_carries_zero_counts(self):
        response = self.client.post(
            "/api/systems/", {"name": "Brand new"}, format="json"
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["primary_model_count"], 0)
        self.assertEqual(response.data["linked_component_count"], 0)
        self.assertEqual(response.data["primary_models"], [])

    def test_list_query_count_does_not_grow_with_rows(self):
        with CaptureQueriesContext(connection) as first:
            self.client.get("/api/systems/")
        for index in range(6):
            system = Orgsystem.objects.create(
                organization=self.organization, name=f"Extra {index}"
            )
            ThreatModel.objects.create(
                name=f"Model {index}",
                organization=self.organization,
                primary_system=system,
            )
        with self.assertNumQueries(len(first.captured_queries)):
            response = self.client.get("/api/systems/")
        self.assertEqual(len(response.data["results"]), 9)

    def test_deleting_a_primary_system_is_a_409_naming_the_models(self):
        response = self.client.delete(f"/api/systems/{self.payments.id}/")
        self.assertEqual(response.status_code, 409)
        self.assertIn("Checkout", response.data["error"])
        self.assertIn("Refunds", response.data["error"])
        self.assertEqual(
            response.data["models"],
            [
                {"id": self.model_one.id, "name": "Checkout"},
                {"id": self.model_two.id, "name": "Refunds"},
            ],
        )
        self.assertTrue(Orgsystem.objects.filter(id=self.payments.id).exists())

    def test_deleting_a_system_with_linked_assets_only_unlinks_them(self):
        asset = OrgsystemComponent.objects.get(name="Ledger feed")
        response = self.client.delete(f"/api/systems/{self.ledger.id}/")
        self.assertEqual(response.status_code, 204)
        self.assertFalse(Orgsystem.objects.filter(id=self.ledger.id).exists())
        asset.refresh_from_db()
        self.assertIsNone(asset.orgsystem_id)
        self.assertEqual(asset.name, "Ledger feed")


class OrgsystemDeleteRestrictTests(TestCase):
    """R34, section 15 / plan K1: RESTRICT blocks a lone delete, not an org delete."""

    def setUp(self):
        self.organization = Organization.objects.create(name="Org", domain="org.test")
        self.system = Orgsystem.objects.create(
            organization=self.organization, name="Payments"
        )
        self.threat_model = ThreatModel.objects.create(
            name="Checkout", organization=self.organization, primary_system=self.system
        )

    def test_deleting_the_system_alone_is_restricted_at_the_orm_level(self):
        with self.assertRaises(RestrictedError):
            self.system.delete()
        self.assertTrue(Orgsystem.objects.filter(id=self.system.id).exists())
        self.assertTrue(ThreatModel.objects.filter(id=self.threat_model.id).exists())

    def test_deleting_the_whole_organization_takes_system_and_model(self):
        system_id, model_id = self.system.id, self.threat_model.id
        self.organization.delete()
        self.assertFalse(Orgsystem.objects.filter(id=system_id).exists())
        self.assertFalse(ThreatModel.objects.filter(id=model_id).exists())
