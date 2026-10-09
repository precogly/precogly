"""The first adapter slice: blueprint structure out and back, zero schema errors."""

import base64
import json

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.diagrams.models import DFD
from apps.organizations.models import (
    Organization,
    OrganizationMember,
    Team,
    TeamMembership,
)
from apps.systems.models import (
    Boundary,
    ComponentDataAsset,
    DataAsset,
    Flow,
    OrgsystemComponent,
    Zone,
)
from apps.threat_models.models import Blueprint, OutOfScopeItem, ThreatModel, UseCase
from apps.threat_models.tmbom import TmBomAdapter, TmBomImportError
from apps.threat_models.tmbom.spec_values import PRECOGLY_DFD_MEDIA_TYPE
from apps.threat_models.tmbom.testing import assert_valid_tmbom

User = get_user_model()


def build_model(organization, user):
    """A model with two blueprints and every structural row type."""
    threat_model = ThreatModel.objects.create(
        name="Payments",
        description="Card capture",
        organization=organization,
        created_by=user,
    )
    blueprint = threat_model.default_blueprint
    blueprint.scope_description = "The card path only"
    blueprint.save()

    dmz = Zone.objects.create(blueprint=blueprint, name="DMZ", trust_level=30)
    internal = Zone.objects.create(
        blueprint=blueprint, name="Internal", trust_level=70, parent=dmz
    )
    Boundary.objects.create(
        blueprint=blueprint, zone_a=dmz, zone_b=internal, label="Edge"
    )

    customer = OrgsystemComponent.objects.create(
        blueprint=blueprint,
        name="Customer",
        category="external_human_actor",
        actor_type="customer",
    )
    api = OrgsystemComponent.objects.create(
        blueprint=blueprint,
        name="API",
        category="process",
        zone=dmz,
        description="Public API",
        data_sensitivity_level="high",
    )
    database = OrgsystemComponent.objects.create(
        blueprint=blueprint,
        name="Database",
        category="datastore",
        data_store_type="relational",
        zone=internal,
    )
    Flow.objects.create(
        blueprint=blueprint,
        source_component=customer,
        dest_component=api,
        label="Login",
        protocol="HTTPS",
        encrypted=True,
    )
    Flow.objects.create(
        blueprint=blueprint,
        source_component=api,
        dest_component=database,
    )
    records = DataAsset.objects.create(
        blueprint=blueprint,
        name="Card records",
        classification="confidential",
        compliance_tags=["PCI DSS"],
    )
    ComponentDataAsset.objects.create(
        component=database, data_asset=records, data_state="at_rest", encrypted=True
    )
    OutOfScopeItem.objects.create(
        blueprint=blueprint, name="Database", reason="Managed"
    )
    OutOfScopeItem.objects.create(
        blueprint=blueprint, name="Mainframe", reason="Separate model"
    )
    DFD.objects.create(
        blueprint=blueprint,
        name="Primary",
        diagram_type="level1",
        is_primary=True,
        canvas_data={
            "nodes": [
                {
                    "id": "z1",
                    "type": "trustZone",
                    "data": {"label": "DMZ", "trust_zone_id": dmz.id},
                },
                {
                    "id": "n1",
                    "type": "process",
                    "parent_id": "z1",
                    "data": {"label": "API", "component_id": api.id},
                },
            ],
            "edges": [],
        },
    )
    UseCase.objects.create(
        threat_model=threat_model,
        name="Pay",
        flow_data={
            "preconditions": ["Logged in"],
            "main_flow": [{"ordinal": 1, "description": "Enter card"}, "Confirm"],
            "alternative_flows": [{"name": "Declined", "condition": "Bank refuses"}],
        },
    )

    second = Blueprint.objects.create(
        threat_model=threat_model,
        name="Network view",
        model_types=["network"],
        display_order=1,
    )
    OrgsystemComponent.objects.create(
        blueprint=second, name="Firewall", category="process"
    )
    return threat_model


class ExportTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="exporter",
            email="exporter@org.test",
            password="x",
            first_name="Ada",
        )
        cls.threat_model = build_model(cls.organization, cls.user)

    def test_export_validates_and_carries_every_structural_row(self):
        document = TmBomAdapter().export_data(self.threat_model)
        assert_valid_tmbom(document, context="export of the test model")

        self.assertEqual(document["metadata"]["component"]["name"], "Payments")
        self.assertEqual(
            document["metadata"]["authors"][0]["email"], "exporter@org.test"
        )
        self.assertEqual(len(document["blueprints"]), 2)

        first = document["blueprints"][0]
        self.assertEqual(first["name"], "Payments")
        self.assertEqual(first["modelTypes"], ["data-flow"])
        self.assertEqual({a["name"] for a in first["assets"]}, {"Customer", "API"})
        self.assertEqual(first["dataStores"][0]["type"], "relational")
        self.assertEqual(
            first["dataSets"][0]["dataProfiles"][0]["classification"], "confidential"
        )
        self.assertEqual(first["dataSets"][0]["placements"][0]["encrypted"], True)
        self.assertEqual(len(first["zones"]), 2)
        self.assertEqual(first["boundaries"][0]["name"], "Edge")
        self.assertEqual(
            {f["name"] for f in first["flows"]}, {"Login", "API to Database"}
        )
        self.assertEqual(
            first["scope"]["excludedComponents"], [first["dataStores"][0]["bom-ref"]]
        )
        self.assertEqual(
            first["scope"]["properties"][0]["name"], "precogly:out-of-scope"
        )
        self.assertEqual(first["visualizations"][0]["type"], {"type": "data-flow"})
        self.assertEqual(
            first["visualizations"][0]["attachment"]["mediaType"],
            PRECOGLY_DFD_MEDIA_TYPE,
        )
        self.assertEqual(document["blueprints"][1]["modelTypes"], ["network"])

        use_case = document["definitions"]["useCases"][0]
        self.assertEqual(
            use_case["mainFlow"][0], {"number": 1, "description": "Enter card"}
        )
        self.assertEqual(
            use_case["mainFlow"][1], {"number": 2, "description": "Confirm"}
        )

    def test_canvas_attachment_carries_refs(self):
        document = TmBomAdapter().export_data(self.threat_model)
        visualization = document["blueprints"][0]["visualizations"][0]
        canvas = json.loads(base64.b64decode(visualization["attachment"]["content"]))
        refs_in_canvas = {node["data"]["bom_ref"] for node in canvas["nodes"]}
        zone_refs = {z["bom-ref"] for z in document["blueprints"][0]["zones"]}
        asset_refs = {a["bom-ref"] for a in document["blueprints"][0]["assets"]}
        self.assertTrue(refs_in_canvas & zone_refs)
        self.assertTrue(refs_in_canvas & asset_refs)

    def test_imported_ref_is_re_emitted(self):
        api = OrgsystemComponent.objects.get(name="API")
        api.format_metadata = {"cyclonedx": {"bom_ref": "asset-from-elsewhere"}}
        api.save()
        document = TmBomAdapter().export_data(self.threat_model)
        names = {a["bom-ref"]: a["name"] for a in document["blueprints"][0]["assets"]}
        self.assertEqual(names["asset-from-elsewhere"], "API")
        assert_valid_tmbom(document)


class RoundTripTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="importer", email="importer@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        cls.team = Team.objects.create(organization=cls.organization, name="Core")
        TeamMembership.objects.filter(user=cls.user).delete()
        TeamMembership.objects.create(team=cls.team, user=cls.user, role="lead")
        cls.source_model = build_model(cls.organization, cls.user)

    def test_structure_survives_a_round_trip(self):
        adapter = TmBomAdapter()
        document = adapter.export_data(self.source_model)
        imported, summary = adapter.import_data(document, self.organization, self.user)

        self.assertNotEqual(imported.id, self.source_model.id)
        self.assertEqual(imported.name, "Payments")
        self.assertEqual(imported.owning_team, self.team)
        self.assertEqual(imported.blueprints.count(), 2)
        self.assertEqual(summary["blueprints"], 2)
        self.assertEqual(summary["components"], 4)
        self.assertEqual(summary["flows"], 2)
        self.assertEqual(summary["zones"], 2)
        self.assertEqual(summary["boundaries"], 1)
        self.assertEqual(summary["data_assets"], 1)
        self.assertEqual(summary["out_of_scope_items"], 2)
        self.assertEqual(summary["diagrams"], 1)
        self.assertEqual(summary["use_cases"], 1)
        self.assertNotIn("warnings", summary)

        first = imported.default_blueprint
        self.assertEqual(first.scope_description, "The card path only")
        internal = first.zones.get(name="Internal")
        self.assertEqual(internal.parent.name, "DMZ")
        database = first.components.get(name="Database")
        self.assertEqual(database.category, "datastore")
        self.assertEqual(database.data_store_type, "relational")
        self.assertEqual(database.zone, internal)
        customer = first.components.get(name="Customer")
        self.assertEqual(customer.category, "external_human_actor")
        self.assertEqual(customer.actor_type, "customer")
        self.assertEqual(
            first.components.get(name="API").data_sensitivity_level, "high"
        )
        login = first.flows.get(label="Login")
        self.assertTrue(login.encrypted)
        self.assertEqual(login.protocol, "HTTPS")
        self.assertEqual(first.data_assets.get().compliance_tags, ["PCI DSS"])
        self.assertTrue(
            ComponentDataAsset.objects.filter(
                component=database, encrypted=True
            ).exists()
        )
        self.assertEqual(
            set(first.out_of_scope_items.values_list("name", flat=True)),
            {"Database", "Mainframe"},
        )
        dfd = first.dfds.get()
        self.assertTrue(dfd.is_primary)
        node_ids = {n["data"].get("component_id") for n in dfd.canvas_data["nodes"]}
        self.assertIn(first.components.get(name="API").id, node_ids)
        self.assertNotIn("bom_ref", dfd.canvas_data["nodes"][0]["data"])
        self.assertEqual(
            imported.blueprints.get(name="Network view").model_types, ["network"]
        )

        # The second export matches the first in everything but ids and time.
        again = adapter.export_data(imported)
        assert_valid_tmbom(again)
        self.assertEqual(
            [b["name"] for b in again["blueprints"]],
            [b["name"] for b in document["blueprints"]],
        )
        self.assertEqual(
            {a["bom-ref"] for a in again["blueprints"][0]["assets"]},
            {a["bom-ref"] for a in document["blueprints"][0]["assets"]},
        )

    def test_other_tools_documents_import_with_warnings(self):
        document = {
            "specFormat": "CycloneDX",
            "specVersion": "2.0",
            "blueprints": [
                {
                    "name": "Other tool",
                    "modelTypes": ["data-flow", "not-a-type"],
                    "zones": [{"bom-ref": "z1", "name": "Edge", "type": "trust"}],
                    "assets": [
                        {
                            "bom-ref": "a1",
                            "name": "Gateway",
                            "type": "gateway",
                            "zone": "z1",
                        },
                        {"bom-ref": "a2", "name": "User", "type": "actor"},
                    ],
                    "dataStores": [
                        {"bom-ref": "d1", "name": "Ledger", "type": "ledger"}
                    ],
                    "flows": [
                        {
                            "bom-ref": "f1",
                            "name": "Use",
                            "type": "data",
                            "source": "a2",
                            "destination": "a1",
                        },
                        {
                            "bom-ref": "f2",
                            "name": "Broken",
                            "type": "data",
                            "source": "a1",
                            "destination": "nope",
                        },
                    ],
                    "boundaries": [{"bom-ref": "b1", "zones": ["z1", "missing"]}],
                }
            ],
            "controls": [{"bom-ref": "c1", "name": "A control"}],
        }
        imported, summary = TmBomAdapter().import_data(
            document, self.organization, self.user
        )
        blueprint = imported.default_blueprint
        self.assertEqual(blueprint.name, "Other tool")
        self.assertEqual(blueprint.model_types, ["data-flow"])
        self.assertEqual(blueprint.components.get(name="Gateway").category, "process")
        self.assertEqual(
            blueprint.components.get(name="User").category, "external_human_actor"
        )
        self.assertEqual(
            blueprint.components.get(name="Ledger").data_store_type, "ledger"
        )
        self.assertEqual(blueprint.flows.count(), 1)
        self.assertEqual(blueprint.boundaries.count(), 0)
        warnings = "\n".join(summary["warnings"])
        self.assertIn("not-a-type", warnings)
        self.assertIn("Broken", warnings)
        self.assertIn("Boundary", warnings)
        imported_control = imported.countermeasures.get()
        self.assertEqual(imported_control.countermeasure_name, "A control")
        self.assertEqual(imported_control.status, "gap")

    def test_a_non_tmbom_file_is_refused(self):
        with self.assertRaises(TmBomImportError):
            TmBomAdapter().import_data(
                {"specFormat": "SPDX"}, self.organization, self.user
            )
        with self.assertRaises(TmBomImportError):
            TmBomAdapter().import_data(
                ["not", "an", "object"], self.organization, self.user
            )
