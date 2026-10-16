"""Zone and boundary types and crossing requirements (step 6, plan section 4.5)."""

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.diagrams.canvas import normalize_canvas
from apps.diagrams.models import DFD
from apps.diagrams.services import sync_dfd_nodes_to_components
from apps.organizations.models import Organization, OrganizationMember
from apps.systems.crossing import clean_type_list, requires
from apps.systems.models import Boundary, Zone
from apps.threat_models.models import ThreatModel

User = get_user_model()


class CrossingHelperTests(SimpleTestCase):
    def test_requires_reads_the_none_value(self):
        self.assertFalse(requires([]))
        self.assertFalse(requires(["none"]))
        self.assertTrue(requires(["oauth2"]))

    def test_none_cannot_sit_beside_other_values(self):
        with self.assertRaises(ValueError):
            clean_type_list(["none", "oauth2"], field="authentication")
        self.assertEqual(
            clean_type_list(
                ["oauth2", {"name": "Badge"}, "oauth2"], field="authentication"
            ),
            ["oauth2", "Badge"],
        )

    def test_canvas_defaults_fill_missing_types(self):
        canvas = normalize_canvas(
            {
                "nodes": [{"id": "z", "type": "trustZone", "data": {"label": "Z"}}],
                "edges": [
                    {
                        "id": "b",
                        "type": "trustBoundary",
                        "source": "z",
                        "target": "z",
                        "data": {},
                    }
                ],
            }
        )
        self.assertEqual(canvas["nodes"][0]["data"]["zone_type"], "trust")
        self.assertEqual(canvas["edges"][0]["data"]["boundary_type"], "trust")


def _canvas(boundary_data=None, zone_b_data=None):
    return {
        "nodes": [
            {
                "id": "z1",
                "type": "trustZone",
                "position": {"x": 0, "y": 0},
                "data": {"label": "DMZ"},
            },
            {
                "id": "z2",
                "type": "trustZone",
                "position": {"x": 0, "y": 0},
                "data": {"label": "Internal", **(zone_b_data or {})},
            },
        ],
        "edges": [
            {
                "id": "b1",
                "type": "trustBoundary",
                "source": "z1",
                "target": "z2",
                "data": {"label": "Edge", **(boundary_data or {})},
            }
        ],
    }


class SyncTests(TestCase):
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

    def _sync(self, canvas, dfd=None):
        if dfd is None:
            dfd = DFD.objects.create(
                blueprint=self.blueprint, name="D", is_primary=True, canvas_data=canvas
            )
        else:
            old = dfd.canvas_data
            dfd.canvas_data = canvas
            sync_dfd_nodes_to_components(dfd, self.blueprint, old_canvas_data=old)
            return dfd
        sync_dfd_nodes_to_components(dfd, self.blueprint)
        return dfd

    def test_defaults_when_the_canvas_names_no_types(self):
        self._sync(_canvas())
        zone = self.blueprint.zones.get(name="DMZ")
        self.assertEqual(zone.zone_type, "trust")
        self.assertIsNone(zone.trust_level)
        boundary = self.blueprint.boundaries.get()
        self.assertEqual(boundary.boundary_type, "trust")
        self.assertEqual(boundary.authentication, [])
        self.assertEqual(boundary.session_management, {})
        self.assertEqual(boundary.format_metadata, {})

    def test_crossing_requirements_round_trip_through_sync(self):
        dfd = self._sync(
            _canvas(
                boundary_data={
                    "boundary_type": "network",
                    "authentication_methods": ["oauth2", "mtls"],
                    "access_control_methods": ["rbac"],
                    "data_validation": True,
                    "rate_limit": "100 rps",
                    "access_token_expires": True,
                    "access_token_ttl": 900,
                    "can_user_logout": True,
                },
                zone_b_data={"zone_type": "network", "trust_level": 80},
            )
        )
        boundary = self.blueprint.boundaries.get()
        self.assertEqual(boundary.boundary_type, "network")
        self.assertEqual(boundary.authentication, ["oauth2", "mtls"])
        self.assertEqual(boundary.authorization, ["rbac"])
        self.assertTrue(boundary.requires_authentication)
        self.assertTrue(boundary.data_validation)
        self.assertEqual(boundary.rate_limit, "100 rps")
        self.assertEqual(
            boundary.session_management,
            {"accessTokenExpires": True, "accessTokenTtl": 900, "userLogout": True},
        )
        internal = self.blueprint.zones.get(name="Internal")
        self.assertEqual((internal.zone_type, internal.trust_level), ("network", 80))

        # A timeout set by import survives a save that clears the editor's keys.
        boundary.session_management["idleTimeout"] = 600
        boundary.save()
        canvas = dfd.canvas_data
        canvas["edges"][0]["data"] = {
            "label": "Edge",
            "trust_boundary_id": boundary.id,
            "authentication_methods": ["none"],
        }
        self._sync(canvas, dfd=dfd)
        boundary.refresh_from_db()
        self.assertEqual(boundary.authentication, ["none"])
        self.assertFalse(boundary.requires_authentication)
        self.assertEqual(boundary.session_management, {"idleTimeout": 600})
        self.assertEqual(boundary.rate_limit, "")

    def test_two_boundaries_on_one_zone_pair(self):
        canvas = _canvas(boundary_data={"boundary_type": "trust"})
        canvas["edges"].append(
            {
                "id": "b2",
                "type": "trustBoundary",
                "source": "z1",
                "target": "z2",
                "data": {"label": "Net", "boundary_type": "network"},
            }
        )
        self._sync(canvas)
        self.assertEqual(
            sorted(self.blueprint.boundaries.values_list("boundary_type", flat=True)),
            ["network", "trust"],
        )

    def test_api_validates_lists_and_types(self):
        dmz = Zone.objects.create(blueprint=self.blueprint, name="DMZ")
        internal = Zone.objects.create(blueprint=self.blueprint, name="Internal")
        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(self.user).access_token}"
        )
        refused = client.post(
            "/api/boundaries/",
            {
                "blueprint": self.blueprint.id,
                "zone_a": dmz.id,
                "zone_b": internal.id,
                "authentication": ["none", "oauth2"],
            },
            format="json",
        )
        self.assertEqual(refused.status_code, 400)
        self.assertIn("authentication", refused.data)
        bad_session = client.post(
            "/api/boundaries/",
            {
                "blueprint": self.blueprint.id,
                "zone_a": dmz.id,
                "zone_b": internal.id,
                "session_management": {"accessTokenTtl": -1},
            },
            format="json",
        )
        self.assertEqual(bad_session.status_code, 400)
        created = client.post(
            "/api/boundaries/",
            {
                "blueprint": self.blueprint.id,
                "zone_a": dmz.id,
                "zone_b": internal.id,
                "boundary_type": "data",
                "authentication": ["saml"],
                "session_management": {"idleTimeout": 300},
            },
            format="json",
        )
        self.assertEqual(created.status_code, 201, created.content)
        self.assertTrue(created.data["requires_authentication"])
        bad_zone = client.patch(
            f"/api/zones/{dmz.id}/", {"trust_level": 140}, format="json"
        )
        self.assertEqual(bad_zone.status_code, 400)
        typed = client.patch(
            f"/api/zones/{dmz.id}/", {"zone_type": "geographic"}, format="json"
        )
        self.assertEqual(typed.data["zone_type"], "geographic")
        self.assertEqual(Boundary.objects.filter(boundary_type="data").count(), 1)
