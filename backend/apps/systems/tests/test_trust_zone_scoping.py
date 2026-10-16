"""Regression tests for precogly/precogly#404, in blueprint-scoped form.

`?threat_model=` on the zone list used to replace the organization join instead
of narrowing it, so any authenticated user could name any threat model and read
that tenant's zones. Zones now belong to a blueprint, the organization is reached
through `blueprint.threat_model.organization`, and the filter applies on top of
that scope.

The tests asserting that own zones are still returned exist because a queryset
returning nothing would pass the leak assertions too.
"""

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import Boundary, Zone
from apps.threat_models.models import Blueprint, ThreatModel

User = get_user_model()


class ZoneScopingTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Acme")
        cls.other_organization = Organization.objects.create(name="Globex")
        cls.member = User.objects.create_user(
            username="member", email="member@acme.test", password="pw"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.member
        )

        cls.threat_model = ThreatModel.objects.create(
            organization=cls.organization,
            created_by=cls.member,
            name="Acme threat model",
        )
        cls.second_model = ThreatModel.objects.create(
            organization=cls.organization,
            created_by=cls.member,
            name="Acme second model",
        )
        cls.other_threat_model = ThreatModel.objects.create(
            organization=cls.other_organization,
            created_by=cls.member,
            name="Globex threat model",
        )

        cls.own_zone = Zone.objects.create(
            blueprint=cls.threat_model.default_blueprint, name="Acme DMZ"
        )
        cls.second_blueprint = Blueprint.objects.create(
            threat_model=cls.threat_model, name="Network view", display_order=1
        )
        cls.second_blueprint_zone = Zone.objects.create(
            blueprint=cls.second_blueprint, name="Acme plant"
        )
        Zone.objects.create(
            blueprint=cls.second_model.default_blueprint, name="Acme other model"
        )
        cls.other_zone = Zone.objects.create(
            blueprint=cls.other_threat_model.default_blueprint, name="Globex DMZ"
        )

    def setUp(self):
        self.client.force_authenticate(self.member)

    def _names(self, response):
        rows = response.data
        if isinstance(rows, dict):
            rows = rows["results"]
        return {row["name"] for row in rows}

    def test_naming_another_tenants_threat_model_returns_nothing(self):
        response = self.client.get(
            "/api/zones/", {"threat_model": self.other_threat_model.id}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self._names(response), set())

    def test_the_filter_still_returns_own_zones_across_blueprints(self):
        response = self.client.get(
            "/api/zones/", {"threat_model": self.threat_model.id}
        )

        self.assertEqual(self._names(response), {"Acme DMZ", "Acme plant"})

    def test_the_blueprint_filter_narrows_to_one_blueprint(self):
        response = self.client.get(
            "/api/zones/", {"blueprint": self.second_blueprint.id}
        )

        self.assertEqual(self._names(response), {"Acme plant"})

    def test_unfiltered_list_is_scoped_to_the_callers_organization(self):
        response = self.client.get("/api/zones/")

        self.assertEqual(
            self._names(response), {"Acme DMZ", "Acme plant", "Acme other model"}
        )

    def test_a_zone_cannot_be_created_in_another_tenants_blueprint(self):
        response = self.client.post(
            "/api/zones/",
            {"blueprint": self.other_threat_model.default_blueprint.id, "name": "Leak"},
            format="json",
        )

        # The blueprint is outside the caller's scope, so the row never exists.
        self.assertIn(
            response.status_code,
            (
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_403_FORBIDDEN,
                status.HTTP_404_NOT_FOUND,
            ),
        )
        self.assertFalse(Zone.objects.filter(name="Leak").exists())

    def test_a_parent_from_another_blueprint_is_refused(self):
        response = self.client.post(
            "/api/zones/",
            {
                "blueprint": self.threat_model.default_blueprint.id,
                "name": "Nested",
                "parent": self.second_blueprint_zone.id,
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("parent", response.data)


class BoundaryScopingTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Acme")
        cls.other_organization = Organization.objects.create(name="Globex")
        cls.member = User.objects.create_user(
            username="member", email="member@acme.test", password="pw"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.member
        )
        cls.threat_model = ThreatModel.objects.create(
            organization=cls.organization, created_by=cls.member, name="Acme model"
        )
        cls.other_threat_model = ThreatModel.objects.create(
            organization=cls.other_organization,
            created_by=cls.member,
            name="Globex model",
        )

        cls.own = cls._boundary(cls.threat_model.default_blueprint, "Acme edge")
        cls.other = cls._boundary(
            cls.other_threat_model.default_blueprint, "Globex edge"
        )

    def setUp(self):
        self.client.force_authenticate(self.member)

    @classmethod
    def _boundary(cls, blueprint, label):
        zone_a = Zone.objects.create(blueprint=blueprint, name=f"{label} a")
        zone_b = Zone.objects.create(blueprint=blueprint, name=f"{label} b")
        return Boundary.objects.create(
            blueprint=blueprint, zone_a=zone_a, zone_b=zone_b, label=label
        )

    def test_list_is_scoped_to_the_callers_organization(self):
        response = self.client.get("/api/boundaries/")

        rows = response.data
        if isinstance(rows, dict):
            rows = rows["results"]
        self.assertEqual({row["label"] for row in rows}, {"Acme edge"})

    def test_zones_from_two_blueprints_are_refused(self):
        other_blueprint = Blueprint.objects.create(
            threat_model=self.threat_model, name="Second", display_order=1
        )
        foreign_zone = Zone.objects.create(blueprint=other_blueprint, name="Elsewhere")
        response = self.client.post(
            "/api/boundaries/",
            {
                "blueprint": self.threat_model.default_blueprint.id,
                "zone_a": self.own.zone_a.id,
                "zone_b": foreign_zone.id,
                "label": "Cross",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(Boundary.objects.filter(label="Cross").exists())
