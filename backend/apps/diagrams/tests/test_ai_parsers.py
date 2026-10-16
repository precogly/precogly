"""Parsing of AI model output for DFD generation, image analysis and suggestions.

Plan section 8 asks for parser tests with recorded model output and no
provider call. The replies below are shaped like real model replies,
including the old key names a model may still produce.
"""

from django.test import SimpleTestCase, TestCase

from apps.diagrams.ai.analyze import normalize_analysis
from apps.diagrams.ai.generate import _fix_layout, _validate_and_resolve
from apps.organizations.models import Organization
from apps.threat_models.models import ThreatModel
from apps.threats.ai.suggest import _coerce_severity, _parse_selections

RECORDED_ANALYSIS = {
    "components": [
        {
            "name": "Web App",
            "type": "process",
            "description": "Customer site",
            "technology": "Django",
            "zone": "DMZ",
            "kind": "service",
            "dataSensitivity": "medium",
        },
        {
            "name": "PLC",
            "type": "process",
            "description": "Line controller",
            "technology": "",
            "trustZone": "Plant",
            "kind": "toaster",
            "dataSensitivity": "high",
        },
        {
            "name": "Orders DB",
            "type": "datastore",
            "description": "Order history",
            "technology": "PostgreSQL",
            "zone": "DMZ",
            "dataStoreType": "sql",
            "dataSensitivity": "high",
        },
        {
            "name": "Operator",
            "type": "humanActor",
            "description": "Plant operator",
            "technology": "",
            "zone": "External",
            "dataStoreType": "sql",
            "dataSensitivity": "low",
        },
    ],
    "flows": [
        {
            "from": "Web App",
            "to": "PLC",
            "description": "Set points",
            "type": "control",
            "protocol": "Modbus",
            "encrypted": False,
            "authentication": ["psk", "made-up"],
        },
        {
            "from": "PLC",
            "to": "Web App",
            "description": "Readings",
            "type": "telepathy",
            "protocol": "HTTPS",
            "encrypted": True,
            "authenticated": True,
        },
    ],
    "zones": [
        {"name": "DMZ", "type": "network", "trustLevel": 140},
        {"name": "Plant", "type": "zoneRestricted", "trustLevel": "high"},
    ],
    "boundaries": [
        {
            "name": "DMZ to plant",
            "type": "network",
            "zones": ["DMZ", "Plant", "Extra"],
            "authentication": ["mtls", "bogus"],
            "authorization": ["rbac"],
        },
        {
            "name": "Odd",
            "type": "moat",
            "zones": "DMZ",
            "authenticated": True,
            "authorization": ["none", "acl"],
        },
    ],
    "systemScope": {"name": "Plant portal", "description": ""},
    "questions": ["Is the PLC reachable from the internet?"],
}


class AnalysisParserTests(SimpleTestCase):
    def test_new_keys_are_kept_and_unknown_values_dropped(self):
        result = normalize_analysis(dict(RECORDED_ANALYSIS), "App", "")
        web, plc, orders, operator = result["components"]
        self.assertEqual((web["zone"], web["kind"]), ("DMZ", "service"))
        self.assertEqual(plc["zone"], "Plant")
        self.assertNotIn("trustZone", plc)
        self.assertNotIn("kind", plc)
        self.assertEqual(orders["dataStoreType"], "sql")
        self.assertNotIn("dataStoreType", operator)
        self.assertNotIn("zone", operator)
        dmz_to_plant, odd = result["boundaries"]
        self.assertEqual(dmz_to_plant["type"], "network")
        self.assertEqual(dmz_to_plant["zones"], ["DMZ", "Plant"])
        self.assertEqual(dmz_to_plant["authentication"], ["mtls"])
        self.assertEqual(dmz_to_plant["authorization"], ["rbac"])
        self.assertNotIn("type", odd)
        self.assertEqual(odd["zones"], [])
        self.assertEqual(odd["authentication"], ["unspecified"])
        self.assertNotIn("authenticated", odd)
        self.assertEqual(odd["authorization"], [])
        control, readings = result["flows"]
        self.assertEqual(control["type"], "control")
        self.assertEqual(control["authentication"], ["psk"])
        self.assertNotIn("type", readings)
        self.assertEqual(readings["authentication"], ["unspecified"])
        self.assertNotIn("authenticated", readings)
        dmz, plant = result["zones"]
        self.assertEqual((dmz["type"], dmz["trustLevel"]), ("network", 100))
        self.assertNotIn("type", plant)
        self.assertNotIn("trustLevel", plant)

    def test_old_key_names_are_read(self):
        result = normalize_analysis(
            {
                "components": [],
                "dataFlows": [
                    {"from": "A", "to": "B", "authenticated": False},
                ],
                "trustZones": [{"name": "Internet", "trustLevel": 0}],
                "systemScope": {"name": "S", "description": ""},
                "questions": [],
            },
            "App",
            "",
        )
        self.assertNotIn("dataFlows", result)
        self.assertNotIn("trustZones", result)
        self.assertEqual(result["flows"][0]["authentication"], [])
        self.assertEqual(result["zones"], [{"name": "Internet", "trustLevel": 0}])

    def test_missing_or_malformed_keys_get_defaults(self):
        result = normalize_analysis(
            {"components": "none", "systemScope": []}, "App", "About"
        )
        self.assertEqual(result["components"], [])
        self.assertEqual(result["flows"], [])
        self.assertEqual(result["zones"], [])
        self.assertEqual(result["boundaries"], [])
        self.assertEqual(result["questions"], [])
        self.assertEqual(result["systemScope"], {"name": "App", "description": "About"})


class GenerateParserTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        organization = Organization.objects.create(name="Org", domain="org.test")
        cls.threat_model = ThreatModel.objects.create(
            name="TM", organization=organization
        )

    def test_canvas_keys_from_new_and_old_model_output(self):
        nodes = [
            {
                "id": "zone-1",
                "type": "trustZone",
                "data": {"label": "Plant", "zoneType": "physical", "trustLevel": 75},
            },
            {
                "id": "zone-2",
                "type": "trustZone",
                "data": {"label": "Odd", "zoneType": "zoneDmz", "trustLevel": "x"},
            },
            {
                "id": "process-1",
                "type": "process",
                "parentId": "zone-1",
                "data": {"label": "PLC", "kind": "device"},
            },
            {
                "id": "process-2",
                "type": "process",
                "data": {"label": "Web", "kind": "blender", "dataStoreType": "sql"},
            },
            {
                "id": "datastore-1",
                "type": "datastore",
                "parentId": "zone-1",
                "data": {"label": "Orders", "dataStoreType": "sql"},
            },
            {
                "id": "datastore-2",
                "type": "datastore",
                "parentId": "zone-1",
                "data": {"label": "Odd", "dataStoreType": "abacus"},
            },
            {"id": "bad", "type": "cloud", "data": {"label": "Dropped"}},
        ]
        edges = [
            {
                "id": "edge-1",
                "source": "process-2",
                "target": "process-1",
                "data": {
                    "label": "Set points",
                    "flowType": "signal",
                    "protocol": "Modbus",
                    "encrypted": True,
                    "authentication": ["certificate"],
                },
            },
            {
                "id": "edge-2",
                "source": "process-1",
                "target": "process-2",
                "data": {
                    "label": "Readings",
                    "protocol": "HTTPS",
                    "authenticated": True,
                },
            },
            {"id": "edge-3", "source": "process-1", "target": "bad", "data": {}},
            {
                "id": "boundary-1",
                "type": "trustBoundary",
                "source": "zone-1",
                "target": "zone-2",
                "sourceHandle": "right-source",
                "targetHandle": "left-target",
                "data": {
                    "label": "Plant edge",
                    "boundaryType": "network",
                    "authenticationMethods": ["mtls", "bogus"],
                    "accessControlMethods": ["rbac", "made-up"],
                },
            },
            {
                "id": "boundary-2",
                "type": "trustBoundary",
                "source": "zone-1",
                "target": "process-1",
                "data": {"label": "Not between zones"},
            },
            {
                "id": "edge-4",
                "type": "wormhole",
                "source": "process-1",
                "target": "process-2",
                "data": {},
            },
        ]
        nodes, edges = _validate_and_resolve(nodes, edges, self.threat_model)
        by_id = {node["id"]: node["data"] for node in nodes}
        self.assertNotIn("bad", by_id)
        self.assertEqual(
            by_id["zone-1"],
            {"label": "Plant", "zone_type": "physical", "trust_level": 75},
        )
        self.assertEqual(by_id["zone-2"], {"label": "Odd"})
        self.assertEqual(by_id["process-1"]["kind"], "device")
        self.assertNotIn("kind", by_id["process-2"])
        self.assertNotIn("data_store_type", by_id["process-2"])
        self.assertNotIn("dataStoreType", by_id["process-2"])
        self.assertEqual(by_id["datastore-1"]["data_store_type"], "sql")
        self.assertEqual(by_id["datastore-2"], {"label": "Odd"})

        signal, readings, boundary = edges
        self.assertEqual(
            signal["data"],
            {
                "label": "Set points",
                "flow_type": "signal",
                "authentication": ["certificate"],
            },
        )
        self.assertEqual(
            readings["data"],
            {
                "label": "Readings",
                "protocol": "HTTPS",
                "authentication": ["unspecified"],
            },
        )
        self.assertEqual(
            boundary["data"],
            {
                "label": "Plant edge",
                "boundary_type": "network",
                "authentication_methods": ["mtls"],
                "access_control_methods": ["rbac"],
            },
        )
        self.assertEqual(len(edges), 3)
        self.assertNotIn("sourceHandle", boundary)
        self.assertNotIn("targetHandle", boundary)

        # The layout pass names handles on data flows only; zone nodes have
        # unnamed handles, so a boundary with a handle name would not draw.
        nodes, edges = _fix_layout(nodes, edges, {"components": []})
        signal, readings, boundary = edges
        self.assertEqual(signal["sourceHandle"], "right-source")
        self.assertNotIn("sourceHandle", boundary)
        self.assertNotIn("targetHandle", boundary)

    def test_data_store_types_export_to_spec_values(self):
        from apps.diagrams.ai.prompts import EDITOR_DATA_STORE_TYPES
        from apps.threat_models.tmbom.spec_values import DATA_STORE_TYPE_TO_SPEC

        self.assertEqual(
            set(EDITOR_DATA_STORE_TYPES) - set(DATA_STORE_TYPE_TO_SPEC), set()
        )


class SuggestParserTests(SimpleTestCase):
    def test_suggestions_are_read_from_fenced_json(self):
        raw = (
            "Here you go:\n```json\n"
            '{"suggestions": [{"id": 3, "severity": "HIGH"}, "junk"]}\n```'
        )
        self.assertEqual(_parse_selections(raw), [{"id": 3, "severity": "HIGH"}])

    def test_unparseable_replies_give_no_suggestions(self):
        self.assertEqual(_parse_selections("no json here"), [])
        self.assertEqual(_parse_selections('{"suggestions": "all"}'), [])

    def test_levels_are_validated(self):
        self.assertEqual(_coerce_severity("HIGH", "medium"), "high")
        self.assertEqual(_coerce_severity("info", "medium"), "info")
        self.assertEqual(_coerce_severity("apocalyptic", "medium"), "medium")
        self.assertEqual(_coerce_severity(None, "low"), "low")
