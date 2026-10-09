"""Flow types, component kinds, applicability and boundary crossing (step 7, section 4.6)."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.diagrams.models import DFD
from apps.diagrams.services import sync_dfd_nodes_to_components
from apps.organizations.models import Organization, OrganizationMember
from apps.systems.crossing import link_applies_to_flow_type
from apps.systems.models import (
    Boundary,
    ComponentLibrary,
    Flow,
    OrgsystemComponent,
    Zone,
)
from apps.threat_models.models import ThreatModel
from apps.threats.models import ComponentLibraryThreat, InstanceThreat, ThreatLibrary
from apps.threats.services import create_risk, ensure_generated_threats

User = get_user_model()


class ApplicabilityTests(TestCase):
    def test_flow_types_rule(self):
        self.assertTrue(link_applies_to_flow_type([], "data"))
        self.assertTrue(link_applies_to_flow_type([], "message"))
        self.assertFalse(link_applies_to_flow_type([], "signal"))
        self.assertTrue(link_applies_to_flow_type(["signal"], "signal"))
        self.assertFalse(link_applies_to_flow_type(["signal"], "data"))
        self.assertTrue(link_applies_to_flow_type(["any"], "energy"))


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
        cls.sensor = ComponentLibrary.objects.create(
            name="Sensor", category=ComponentLibrary.Category.PROCESS, kind="device"
        )
        cls.generic = ThreatLibrary.objects.create(
            name="Eavesdropping", description="d"
        )
        cls.signal_only = ThreatLibrary.objects.create(
            name="Signal spoofing", description="d"
        )
        ComponentLibraryThreat.objects.create(
            component_library=cls.sensor,
            threat_library=cls.generic,
            applies_to=ComponentLibraryThreat.AppliesTo.FLOW,
        )
        ComponentLibraryThreat.objects.create(
            component_library=cls.sensor,
            threat_library=cls.signal_only,
            applies_to=ComponentLibraryThreat.AppliesTo.FLOW,
            flow_types=["signal", "control"],
        )

    def _components(self):
        source = OrgsystemComponent.objects.create(
            blueprint=self.blueprint,
            name="Field sensor",
            component_library=self.sensor,
            category="process",
            kind="device",
        )
        dest = OrgsystemComponent.objects.create(
            blueprint=self.blueprint,
            name="PLC",
            component_library=self.sensor,
            category="process",
        )
        return source, dest


class GenerationTests(Fixture):
    def test_a_signal_flow_gets_only_threats_whose_flow_types_allow_it(self):
        source, dest = self._components()
        signal = Flow.objects.create(
            blueprint=self.blueprint,
            source_component=source,
            dest_component=dest,
            label="4-20mA",
            flow_type="signal",
        )
        self.assertEqual(ensure_generated_threats(signal), 1)
        self.assertEqual(
            list(
                InstanceThreat.objects.filter(targets__flow=signal).values_list(
                    "threat_library__name", flat=True
                )
            ),
            ["Signal spoofing"],
        )
        data = Flow.objects.create(
            blueprint=self.blueprint,
            source_component=source,
            dest_component=dest,
            label="Telemetry",
        )
        self.assertEqual(ensure_generated_threats(data), 1)
        self.assertEqual(
            list(
                InstanceThreat.objects.filter(targets__flow=data).values_list(
                    "threat_library__name", flat=True
                )
            ),
            ["Eavesdropping"],
        )

    def test_kind_defaults_from_category(self):
        source, dest = self._components()
        self.assertEqual(source.effective_kind, "device")
        self.assertEqual(dest.effective_kind, "process")
        store = OrgsystemComponent.objects.create(
            blueprint=self.blueprint, name="DB", category="datastore"
        )
        actor = OrgsystemComponent.objects.create(
            blueprint=self.blueprint, name="User", category="external_human_actor"
        )
        self.assertEqual(
            (store.effective_kind, actor.effective_kind), ("data-store", "actor")
        )
        library = ComponentLibrary.objects.create(name="Queue", category="datastore")
        self.assertEqual(library.effective_kind, "data-store")


class SyncTests(Fixture):
    def _canvas(self, edge_data=None, boundary=False, nested=False):
        nodes = [
            {
                "id": "z1",
                "type": "trustZone",
                "position": {"x": 0, "y": 0},
                "data": {"label": "Plant"},
            },
            {
                "id": "z2",
                "type": "trustZone",
                "position": {"x": 0, "y": 0},
                "data": {"label": "Cell"},
                **({"parent_id": "z1"} if nested else {}),
            },
            {
                "id": "n1",
                "type": "process",
                "position": {"x": 0, "y": 0},
                "parent_id": "z1",
                "data": {"label": "Sensor", "component_library_id": self.sensor.id},
            },
            {
                "id": "n2",
                "type": "process",
                "position": {"x": 0, "y": 0},
                "parent_id": "z2",
                "data": {
                    "label": "PLC",
                    "component_library_id": self.sensor.id,
                    "kind": "system",
                },
            },
        ]
        edges = [
            {
                "id": "e1",
                "type": "dataFlow",
                "source": "n1",
                "target": "n2",
                "data": {"label": "Reading", **(edge_data or {})},
            }
        ]
        if boundary:
            edges.append(
                {
                    "id": "b1",
                    "type": "trustBoundary",
                    "source": "z1",
                    "target": "z2",
                    "data": {"label": "Cell edge"},
                }
            )
        return {"nodes": nodes, "edges": edges}

    def test_flow_type_authentication_and_kind_from_the_canvas(self):
        dfd = DFD.objects.create(
            blueprint=self.blueprint,
            name="D",
            is_primary=True,
            canvas_data=self._canvas(
                {
                    "flow_type": "signal",
                    "protocol": "Modbus",
                    "encrypted": True,
                    "authenticated": True,
                }
            ),
        )
        sync_dfd_nodes_to_components(dfd, self.blueprint)
        flow = self.blueprint.flows.get()
        self.assertEqual(flow.flow_type, "signal")
        self.assertEqual(flow.protocol, "")  # not a data-like flow
        self.assertFalse(flow.encrypted)
        self.assertEqual(flow.authentication, ["unspecified"])
        self.assertTrue(flow.requires_authentication)
        self.assertEqual(
            {
                t.threat_library.name
                for t in InstanceThreat.objects.filter(targets__flow=flow)
            },
            {"Signal spoofing"},
        )
        sensor = self.blueprint.components.get(name="Sensor")
        self.assertEqual(sensor.kind, "device")  # copied from the library
        plc = self.blueprint.components.get(name="PLC")
        self.assertEqual(plc.kind, "system")  # named on the canvas

        # A flow type change regenerates: the signal threat goes, the data one arrives.
        old = dfd.canvas_data
        canvas = self._canvas(
            {"flow_type": "data", "protocol": "Modbus", "authentication": ["psk"]}
        )
        canvas["edges"][0]["data"]["dataflow_id"] = flow.id
        for node, name in ((canvas["nodes"][2], "Sensor"), (canvas["nodes"][3], "PLC")):
            node["data"]["component_id"] = self.blueprint.components.get(name=name).id
        for node, name in ((canvas["nodes"][0], "Plant"), (canvas["nodes"][1], "Cell")):
            node["data"]["trust_zone_id"] = self.blueprint.zones.get(name=name).id
        dfd.canvas_data = canvas
        sync_dfd_nodes_to_components(dfd, self.blueprint, old_canvas_data=old)
        flow.refresh_from_db()
        self.assertEqual(
            (flow.flow_type, flow.protocol, flow.authentication),
            ("data", "Modbus", ["psk"]),
        )
        self.assertEqual(
            {
                t.threat_library.name
                for t in InstanceThreat.objects.filter(targets__flow=flow)
            },
            {"Eavesdropping"},
        )

    def test_crosses_boundary_needs_a_boundary_row(self):
        dfd = DFD.objects.create(
            blueprint=self.blueprint,
            name="D",
            is_primary=True,
            canvas_data=self._canvas(nested=True),
        )
        sync_dfd_nodes_to_components(dfd, self.blueprint)
        self.assertFalse(self.blueprint.flows.get().crosses_boundary)
        dfd2 = DFD.objects.create(
            blueprint=self.threat_model.blueprints.create(name="B2"),
            name="D2",
            is_primary=True,
            canvas_data=self._canvas(boundary=True),
        )
        sync_dfd_nodes_to_components(dfd2, dfd2.blueprint)
        self.assertTrue(dfd2.blueprint.flows.get().crosses_boundary)
        self.assertEqual(Boundary.objects.filter(blueprint=dfd2.blueprint).count(), 1)
        Zone.objects.filter(blueprint=dfd2.blueprint).exists()


class ApiTests(Fixture):
    def test_flow_and_component_fields_and_risk_domains(self):
        source, dest = self._components()
        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(self.user).access_token}"
        )
        refused = client.post(
            "/api/flows/",
            {
                "source_component": source.id,
                "dest_component": dest.id,
                "authentication": ["none", "psk"],
            },
            format="json",
        )
        self.assertEqual(refused.status_code, 400)
        created = client.post(
            "/api/flows/",
            {
                "source_component": source.id,
                "dest_component": dest.id,
                "flow_type": "energy",
                "authorization": ["rbac"],
            },
            format="json",
        )
        self.assertEqual(created.status_code, 201, created.content)
        self.assertEqual(created.data["flow_type"], "energy")
        self.assertFalse(created.data["requires_authentication"])
        by_type = client.get("/api/flows/", {"flow_type": "energy"})
        self.assertEqual(len(by_type.data["results"]), 1)
        component = client.patch(
            f"/api/components/{dest.id}/", {"kind": "gateway"}, format="json"
        )
        self.assertEqual(component.status_code, 200, component.content)
        self.assertEqual(component.data["effective_kind"], "gateway")
        bad_kind = client.patch(
            f"/api/components/{dest.id}/", {"kind": "toaster"}, format="json"
        )
        self.assertEqual(bad_kind.status_code, 400)

        base = f"/api/threat-models/{self.threat_model.id}/risks/"
        bad = client.post(
            base,
            {"name": "R", "rating_inputs": {"level": "low"}, "domains": ["weather"]},
            format="json",
        )
        self.assertEqual(bad.status_code, 400)
        good = client.post(
            base,
            {
                "name": "R",
                "rating_inputs": {"level": "low"},
                "domains": ["safety", "security", "safety"],
            },
            format="json",
        )
        self.assertEqual(good.status_code, 201, good.content)
        self.assertEqual(good.data["domains"], ["safety", "security"])
        self.assertEqual(
            create_risk(self.threat_model, name="R2", level="low").domains, []
        )
