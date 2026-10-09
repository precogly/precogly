"""The canvas normaliser gives every reader one key shape."""

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase

from apps.diagrams.canvas import normalize_canvas, to_snake_case
from apps.diagrams.models import DFD
from apps.diagrams.services import sync_dfd_nodes_to_components
from apps.organizations.models import Organization
from apps.systems.models import OrgsystemComponent, Zone
from apps.threat_models.models import ThreatModel

User = get_user_model()


class ToSnakeCaseTests(SimpleTestCase):
    def test_camel_case_keys(self):
        self.assertEqual(to_snake_case("parentId"), "parent_id")
        self.assertEqual(to_snake_case("zoneType"), "zone_type")
        self.assertEqual(to_snake_case("dataClassification"), "data_classification")

    def test_snake_case_and_plain_keys_are_unchanged(self):
        self.assertEqual(to_snake_case("parent_id"), "parent_id")
        self.assertEqual(to_snake_case("label"), "label")
        self.assertEqual(to_snake_case("id"), "id")


class NormalizeCanvasTests(SimpleTestCase):
    def test_empty_canvas(self):
        self.assertEqual(normalize_canvas(None), {"nodes": [], "edges": []})
        self.assertEqual(normalize_canvas({}), {"nodes": [], "edges": []})

    def test_template_style_canvas_becomes_snake_case(self):
        canvas = {
            "nodes": [
                {
                    "id": "tz-1",
                    "type": "trustZone",
                    "parentId": "scope-1",
                    "position": {"x": 1, "y": 2},
                    "style": {"width": 10, "height": 20},
                    "data": {"label": "Zone", "zoneType": "zoneInternal"},
                },
                {
                    "id": "n-1",
                    "type": "humanActor",
                    "parentId": "tz-1",
                    "data": {"label": "User", "actorType": "customer"},
                },
            ],
            "edges": [
                {
                    "id": "e-1",
                    "type": "dataFlow",
                    "source": "n-1",
                    "target": "n-2",
                    "data": {"label": "Login", "dataClassification": ["pii"]},
                }
            ],
        }
        normalized = normalize_canvas(canvas)
        zone, actor = normalized["nodes"]
        self.assertEqual(zone["parent_id"], "scope-1")
        self.assertEqual(zone["data"]["zone_type"], "zoneInternal")
        self.assertEqual(zone["type"], "trustZone")
        self.assertEqual(zone["style"], {"width": 10, "height": 20})
        self.assertEqual(actor["data"]["actor_type"], "customer")
        self.assertEqual(normalized["edges"][0]["type"], "dataFlow")
        self.assertEqual(normalized["edges"][0]["data"]["data_classification"], ["pii"])

    def test_idempotent_on_snake_case_input(self):
        canvas = {
            "nodes": [
                {
                    "id": "n",
                    "type": "process",
                    "parent_id": "z",
                    "data": {"component_id": 4},
                }
            ],
            "edges": [],
        }
        self.assertEqual(normalize_canvas(canvas), canvas)
        self.assertEqual(normalize_canvas(normalize_canvas(canvas)), canvas)

    def test_input_is_not_mutated(self):
        canvas = {
            "nodes": [{"id": "n", "type": "process", "parentId": "z", "data": {}}]
        }
        normalize_canvas(canvas)
        self.assertIn("parentId", canvas["nodes"][0])


class SyncNormalizesTemplateCanvasTests(TestCase):
    """A seeded canvas in template casing keeps its zone membership."""

    def test_component_inside_camel_case_zone_gets_the_zone(self):
        organization = Organization.objects.create(name="Org", domain="org.test")
        user = User.objects.create_user(username="u", email="u@org.test", password="x")
        threat_model = ThreatModel.objects.create(name="TM", organization=organization)
        dfd = DFD.objects.create(
            name="DFD",
            blueprint=threat_model.default_blueprint,
            is_primary=True,
            updated_by=user,
            canvas_data={
                "nodes": [
                    {
                        "id": "tz-1",
                        "type": "trustZone",
                        "position": {"x": 0, "y": 0},
                        "data": {"label": "Internal", "trustLevel": 60},
                    },
                    {
                        "id": "p-1",
                        "type": "process",
                        "parentId": "tz-1",
                        "position": {"x": 0, "y": 0},
                        "data": {"label": "API"},
                    },
                ],
                "edges": [],
            },
        )

        sync_dfd_nodes_to_components(dfd, threat_model.default_blueprint)

        component = OrgsystemComponent.objects.get(
            blueprint__threat_model=threat_model, name="API"
        )
        zone = Zone.objects.get(
            blueprint=threat_model.default_blueprint, name="Internal"
        )
        self.assertEqual(component.zone_id, zone.id)
        self.assertEqual(zone.trust_level, 60)
        dfd.refresh_from_db()
        self.assertEqual(dfd.canvas_data["nodes"][1]["parent_id"], "tz-1")
        self.assertNotIn("parentId", dfd.canvas_data["nodes"][1])
