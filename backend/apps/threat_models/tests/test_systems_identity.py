"""Systems, serial number, version and relationships (step 13, section 4.9)."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.diagrams.models import DFD
from apps.diagrams.services import sync_dfd_nodes_to_components
from apps.organizations.models import (
    Organization,
    OrganizationMember,
    Team,
    TeamMembership,
)
from apps.systems.models import Orgsystem, OrgsystemComponent, Zone
from apps.threat_models.models import (
    ThreatModel,
    ThreatModelRelationship,
    ThreatModelState,
)
from apps.threat_models.tmbom import TmBomAdapter
from apps.threat_models.tmbom.testing import assert_valid_tmbom
from apps.threats.services import create_instance_threat, create_risk

User = get_user_model()


class Fixture(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.other_organization = Organization.objects.create(
            name="Other", domain="other.test"
        )
        cls.security = User.objects.create_user(
            username="sec", email="sec@org.test", password="x"
        )
        cls.member = User.objects.create_user(
            username="dev", email="dev@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.security, role="security_team"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.member, role="member"
        )
        OrganizationMember.objects.filter(user=cls.member).exclude(
            organization=cls.organization
        ).delete()
        cls.team = Team.objects.create(organization=cls.organization, name="Core")
        TeamMembership.objects.filter(user=cls.member).delete()
        TeamMembership.objects.create(team=cls.team, user=cls.member, role="lead")
        cls.payments = Orgsystem.objects.create(
            organization=cls.organization, name="Payments", lifecycle_state="production"
        )
        cls.foreign_system = Orgsystem.objects.create(
            organization=cls.other_organization, name="Foreign"
        )
        cls.threat_model = ThreatModel.objects.create(
            name="TM",
            organization=cls.organization,
            owning_team=cls.team,
            primary_system=cls.payments,
        )

    def api_client(self, user):
        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(user).access_token}"
        )
        return client


class SystemTests(Fixture):
    def test_primary_system_must_belong_to_the_organization(self):
        client = self.api_client(self.security)
        refused = client.patch(
            f"/api/threat-models/{self.threat_model.id}/",
            {"primary_system": self.foreign_system.id},
            format="json",
        )
        self.assertEqual(refused.status_code, 400)
        detail = client.get(f"/api/threat-models/{self.threat_model.id}/").data
        self.assertEqual(
            (
                detail["primary_system"],
                detail["primary_system_name"],
                detail["version"],
            ),
            (self.payments.id, "Payments", 1),
        )
        self.assertEqual(str(self.threat_model.serial_number), detail["serial_number"])
        created = client.post(
            "/api/threat-models/",
            {
                "name": "New",
                "organization": self.organization.id,
                "primary_system": self.foreign_system.id,
            },
            format="json",
        )
        self.assertEqual(created.status_code, 400)

    def test_scope_nodes_become_system_assets_and_never_touch_the_inventory(self):
        ledger_system = Orgsystem.objects.create(
            organization=self.organization, name="Ledger system"
        )
        inventory_before = Orgsystem.objects.count()
        dfd = DFD.objects.create(
            blueprint=self.threat_model.default_blueprint,
            name="D",
            is_primary=True,
            canvas_data={
                "nodes": [
                    {
                        "id": "s1",
                        "type": "systemScope",
                        "position": {"x": 0, "y": 0},
                        "data": {"label": "Payments", "orgsystem_id": ledger_system.id},
                    },
                    {
                        "id": "s2",
                        "type": "systemScope",
                        "position": {"x": 0, "y": 0},
                        "parent_id": "s1",
                        "data": {"label": "Ledger"},
                    },
                    {
                        "id": "n1",
                        "type": "process",
                        "position": {"x": 0, "y": 0},
                        "parent_id": "s2",
                        "data": {"label": "API"},
                    },
                    {
                        "id": "n2",
                        "type": "process",
                        "position": {"x": 0, "y": 0},
                        "parent_id": "s1",
                        "data": {"label": "Worker"},
                    },
                    {
                        # The panel's own choice wins over the nesting rule.
                        "id": "s3",
                        "type": "systemScope",
                        "position": {"x": 0, "y": 0},
                        "data": {"label": "Satellite", "kind": "subsystem"},
                    },
                ],
                "edges": [],
            },
        )
        sync_dfd_nodes_to_components(dfd, self.threat_model.default_blueprint)
        blueprint = self.threat_model.default_blueprint
        payments = blueprint.components.get(name="Payments")
        ledger = blueprint.components.get(name="Ledger")
        self.assertEqual((payments.kind, payments.orgsystem), ("system", ledger_system))
        self.assertEqual(
            (ledger.kind, ledger.parent_component), ("subsystem", payments)
        )
        self.assertEqual(blueprint.components.get(name="Satellite").kind, "subsystem")
        self.assertEqual(blueprint.components.get(name="API").parent_component, ledger)
        self.assertEqual(
            blueprint.components.get(name="Worker").parent_component, payments
        )
        self.assertEqual(Orgsystem.objects.count(), inventory_before)
        node_ids = {
            n["id"]: n["data"].get("component_id") for n in dfd.canvas_data["nodes"]
        }
        self.assertEqual(node_ids["s1"], payments.id)

        # Removing the scope node removes the asset, not the inventory row.
        old = dfd.canvas_data
        dfd.canvas_data = {
            "nodes": [n for n in old["nodes"] if n["id"] not in ("s1", "s2")],
            "edges": [],
        }
        for node in dfd.canvas_data["nodes"]:
            node.pop("parent_id", None)
        sync_dfd_nodes_to_components(dfd, blueprint, old_canvas_data=old)
        self.assertFalse(blueprint.components.filter(name="Payments").exists())
        self.assertEqual(Orgsystem.objects.count(), inventory_before)
        # Deleting the inventory row unlinks system assets and deletes nothing else.
        canvas = dfd.canvas_data
        dfd.canvas_data = {
            "nodes": [
                *canvas["nodes"],
                {
                    "id": "s3",
                    "type": "systemScope",
                    "position": {"x": 0, "y": 0},
                    "data": {"label": "Linked", "orgsystem_id": ledger_system.id},
                },
            ],
            "edges": [],
        }
        sync_dfd_nodes_to_components(dfd, blueprint, old_canvas_data=canvas)
        ledger_system.delete()
        self.assertIsNone(blueprint.components.get(name="Linked").orgsystem)
        self.assertTrue(blueprint.components.filter(name="API").exists())

    def test_permissions_reach_the_model_through_the_new_keys(self):
        zone = Zone.objects.create(
            blueprint=self.threat_model.default_blueprint, name="Z"
        )
        api = OrgsystemComponent.objects.create(
            blueprint=self.threat_model.default_blueprint, name="API"
        )
        threat = create_instance_threat(
            self.threat_model, targets=[api], threat_name="T"
        )
        risk = create_risk(self.threat_model, name="R", level="low")
        member = self.api_client(self.member)
        self.assertEqual(
            member.patch(
                f"/api/zones/{zone.id}/", {"name": "Z2"}, format="json"
            ).status_code,
            200,
        )
        self.assertEqual(
            member.patch(
                f"/api/threats/{threat.id}/", {"triage_status": "accept"}, format="json"
            ).status_code,
            200,
        )
        self.assertEqual(
            member.patch(
                f"/api/threat-models/{self.threat_model.id}/risks/{risk.id}/",
                {"status": "assessed"},
                format="json",
            ).status_code,
            200,
        )
        other_model = ThreatModel.objects.create(
            name="Other", organization=self.organization
        )
        other_zone = Zone.objects.create(
            blueprint=other_model.default_blueprint, name="Z"
        )
        self.assertEqual(
            member.patch(
                f"/api/zones/{other_zone.id}/", {"name": "Z2"}, format="json"
            ).status_code,
            403,
        )
        library = member.post(
            "/api/threat-library/", {"name": "X", "description": "d"}, format="json"
        )
        self.assertEqual(library.status_code, 403)


class IdentityExportTests(Fixture):
    def test_serial_number_primary_system_relationships_and_version(self):
        target = ThreatModel.objects.create(
            name="Ledger", organization=self.organization, description="The ledger"
        )
        ThreatModelRelationship.objects.create(
            source_threat_model=self.threat_model,
            target_threat_model=target,
            relation_type="depends_on",
        )
        ThreatModelRelationship.objects.create(
            source_threat_model=self.threat_model,
            target_threat_model=target,
            relation_type="subsystem_of",
        )
        adapter = TmBomAdapter()
        document = adapter.export_data(self.threat_model)
        assert_valid_tmbom(document, context="step 13 export")
        self.assertEqual(
            document["serialNumber"], f"urn:uuid:{self.threat_model.serial_number}"
        )
        self.assertEqual(document["version"], 1)
        component = document["metadata"]["component"]
        self.assertEqual(component["name"], "Payments")
        properties = {p["name"]: p["value"] for p in component["properties"]}
        self.assertEqual(properties["precogly:criticality"], "moderate")
        self.assertEqual(properties["precogly:lifecycle-state"], "production")
        first = document["blueprints"][0]
        model_asset = next(a for a in first["assets"] if a["name"] == "Ledger")
        self.assertEqual(model_asset["type"], "system")
        self.assertEqual(
            model_asset["externalReferences"][0],
            {"type": "threat-model", "url": f"urn:cdx:{target.serial_number}/1"},
        )
        self.assertEqual(
            {r.get("dependsOn", r.get("contains"))[0] for r in first["relationships"]},
            {model_asset["bom-ref"], component["bom-ref"]},
        )

        # Same content: same version. Changed content: version 2.
        self.assertEqual(adapter.export_data(self.threat_model)["version"], 1)
        Zone.objects.create(blueprint=self.threat_model.default_blueprint, name="DMZ")
        self.assertEqual(adapter.export_data(self.threat_model)["version"], 2)
        self.assertEqual(
            ThreatModelState.objects.get(threat_model=self.threat_model).version, 2
        )
        # Another model's version moving does not move ours.
        ThreatModelState.objects.filter(threat_model=target).update(version=5)
        self.assertEqual(adapter.export_data(self.threat_model)["version"], 2)

        imported, summary = adapter.import_data(
            document, self.organization, self.security
        )
        self.assertNotEqual(imported.serial_number, self.threat_model.serial_number)
        self.assertEqual(
            imported.format_metadata["cyclonedx"]["imported_serial_number"],
            document["serialNumber"],
        )
        self.assertEqual(ThreatModelState.objects.get(threat_model=imported).version, 1)
        self.assertEqual(imported.name, "Payments")
        self.assertEqual(
            set(
                imported.outgoing_relationships.values_list(
                    "target_threat_model__name", "relation_type"
                )
            ),
            {("Ledger", "depends_on"), ("Ledger", "subsystem_of")},
        )
        self.assertFalse(imported.components.filter(name="Ledger").exists())
        self.assertEqual(summary["relationships"], 2)

    def test_unresolvable_links_keep_the_asset_and_warn(self):
        document = {
            "specFormat": "CycloneDX",
            "specVersion": "2.0",
            "serialNumber": "urn:uuid:11111111-1111-4111-8111-111111111111",
            "version": 3,
            "blueprints": [
                {
                    "name": "Other",
                    "modelTypes": ["data-flow"],
                    "assets": [
                        {
                            "bom-ref": "sys-x",
                            "name": "Elsewhere",
                            "type": "system",
                            "externalReferences": [
                                {
                                    "type": "threat-model",
                                    "url": "urn:cdx:22222222-2222-4222-8222-222222222222/1",
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        imported, summary = TmBomAdapter().import_data(
            document, self.organization, self.security
        )
        self.assertTrue(imported.components.filter(name="Elsewhere").exists())
        self.assertEqual(imported.outgoing_relationships.count(), 0)
        self.assertIn("serial number", "\n".join(summary["warnings"]))
        self.assertEqual(imported.format_metadata["cyclonedx"]["imported_version"], 3)

    def _linking_document(self, url):
        return {
            "specFormat": "CycloneDX",
            "specVersion": "2.0",
            "blueprints": [
                {
                    "name": "Other",
                    "modelTypes": ["data-flow"],
                    "assets": [
                        {
                            "bom-ref": "sys-x",
                            "name": "Elsewhere",
                            "type": "system",
                            "externalReferences": [
                                {"type": "threat-model", "url": url}
                            ],
                        }
                    ],
                }
            ],
        }

    def test_a_malformed_bom_link_warns_and_the_import_goes_through(self):
        """R21: 36 characters that are not a UUID are not looked up."""
        imported, summary = TmBomAdapter().import_data(
            self._linking_document("urn:cdx:" + "-" * 36 + "/1"),
            self.organization,
            self.security,
        )
        self.assertTrue(imported.components.filter(name="Elsewhere").exists())
        self.assertIn("is not a BOM-Link", "\n".join(summary["warnings"]))

    def test_a_bom_link_does_not_reach_a_model_the_importer_cannot_see(self):
        """R20: matching goes through visible_to, not the whole organization."""
        other_team = Team.objects.create(organization=self.organization, name="Vault")
        hidden = ThreatModel.objects.create(
            name="Hidden", organization=self.organization, owning_team=other_team
        )
        imported, summary = TmBomAdapter().import_data(
            self._linking_document(f"urn:cdx:{hidden.serial_number}/1"),
            self.organization,
            self.member,
        )
        self.assertEqual(imported.outgoing_relationships.count(), 0)
        self.assertIn("no model here has serial number", "\n".join(summary["warnings"]))

        as_security, _summary = TmBomAdapter().import_data(
            self._linking_document(f"urn:cdx:{hidden.serial_number}/1"),
            self.organization,
            self.security,
        )
        self.assertEqual(
            list(
                as_security.outgoing_relationships.values_list(
                    "target_threat_model", flat=True
                )
            ),
            [hidden.id],
        )
