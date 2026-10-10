"""Step 14: the whole adapter at once (plan 9.9, 9.10, 9.11, H17).

The reference model exports to a valid TM-BOM, imports back to the same rows
and the same document, keeps content it does not model, repairs stale refs,
generates a DFD when a document has none, and the field coverage check pins
the list of model fields the adapter deliberately leaves out.
"""

import copy
import json
import os
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.diagrams.models import DFD
from apps.diagrams.services import sync_dfd_nodes_to_components
from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import Boundary, Flow, OrgsystemComponent, Zone
from apps.threat_models.digest import SNAPSHOT_FIELDS
from apps.threat_models.tmbom import TmBomAdapter
from apps.threat_models.tmbom.coverage import FIELD_HOMES, NOT_EXPORTED
from apps.threat_models.tmbom.importer.document import import_document
from apps.threat_models.tmbom.properties import PROPERTY_PREFIX, registered_names
from apps.threat_models.tmbom.testing import assert_valid_tmbom
from apps.threats.models import InstanceCountermeasure, InstanceThreat, Risk

from .tmbom_reference import build_reference_model, canonical

User = get_user_model()
FIXTURE = Path(__file__).parent / "fixtures" / "tmbom" / "reference-model.cdx.json"


def as_lines(document: dict) -> list[str]:
    """Canonical JSON as lines, so a failed comparison prints a readable diff."""
    return json.dumps(canonical(document), indent=1, sort_keys=True).splitlines()


def dump(name: str, document: dict) -> None:
    """Write a canonical document to ``TMBOM_DUMP_DIR`` for diffing by hand."""
    directory = os.environ.get("TMBOM_DUMP_DIR")
    if directory:
        Path(directory).mkdir(parents=True, exist_ok=True)
        (Path(directory) / f"{name}.json").write_text("\n".join(as_lines(document)))


class _ReferenceModelTests(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="owner", email="owner@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        cls.threat_model = build_reference_model(cls.organization, cls.user)

    def export(self, threat_model=None, warnings=None):
        document = TmBomAdapter().export_data(
            threat_model or self.threat_model, warnings=warnings
        )
        assert_valid_tmbom(document)
        return document

    def import_copy(self, document):
        threat_model, _summary = import_document(
            copy.deepcopy(document), self.organization, self.user
        )
        return threat_model


class RoundTripTests(_ReferenceModelTests):
    def test_export_import_export_is_stable(self):
        first = self.export()
        imported = self.import_copy(first)
        second = self.export(imported)
        dump("first", first)
        dump("second", second)
        self.assertEqual(as_lines(first), as_lines(second))

    def test_import_recreates_every_row_type(self):
        imported = self.import_copy(self.export())
        blueprint = imported.default_blueprint
        counts = {
            "zones": Zone.objects.filter(blueprint=blueprint).count(),
            "boundaries": Boundary.objects.filter(blueprint=blueprint).count(),
            "components": OrgsystemComponent.objects.filter(
                blueprint=blueprint
            ).count(),
            "flows": Flow.objects.filter(blueprint=blueprint).count(),
            "threats": InstanceThreat.objects.filter(threat_model=imported).count(),
            "controls": InstanceCountermeasure.objects.filter(
                threat_model=imported
            ).count(),
            "risks": Risk.objects.filter(threat_model=imported).count(),
        }
        self.assertEqual(
            counts,
            {
                "zones": 3,
                "boundaries": 2,
                "components": 5,
                "flows": 3,
                "threats": 3,
                "controls": 2,
                "risks": 1,
            },
        )
        self.assertEqual(
            sorted(
                InstanceThreat.objects.filter(threat_model=imported).values_list(
                    "number", flat=True
                )
            ),
            sorted(
                InstanceThreat.objects.filter(
                    threat_model=self.threat_model
                ).values_list("number", flat=True)
            ),
        )
        self.assertEqual(imported.primary_system.name, "Payments platform")
        self.assertEqual(imported.risk_scoring_method, "owasp-risk-rating")
        self.assertEqual(sorted(imported.methodologies), ["Our own", "STRIDE"])

    def test_reference_fixture_matches_the_current_export(self):
        """The checked-in fixture is the builder's export, modulo refs and dates (9.10).

        Regenerate it with ``TMBOM_WRITE_FIXTURE=1`` when the adapter changes
        on purpose; the diff is then reviewed like any other change.
        """
        if os.environ.get("TMBOM_WRITE_FIXTURE"):
            FIXTURE.write_text(
                json.dumps(self.export(), indent=2, sort_keys=False) + "\n"
            )
        fixture = json.loads(FIXTURE.read_text())
        assert_valid_tmbom(fixture, context="fixture")
        self.assertEqual(as_lines(fixture), as_lines(self.export()))

    def test_reference_fixture_imports_and_re_exports_the_same_document(self):
        fixture = json.loads(FIXTURE.read_text())
        imported = self.import_copy(fixture)
        self.assertEqual(as_lines(fixture), as_lines(self.export(imported)))


class PassthroughTests(_ReferenceModelTests):
    """Group B content (9.9) comes back identical, with refs that resolve."""

    def _scenarios(self, document):
        return {s["name"]: s for s in document["threats"]["scenarios"]}

    def _decorated_document(self):
        document = self.export()
        scenarios = self._scenarios(document)
        decorated = scenarios["SQL injection"]
        decorated["externalReferences"] = [
            {"type": "advisories", "url": "https://advisories.example/1"}
        ]
        decorated["motivation"] = ["financial"]
        decorated["properties"] = [
            *decorated.get("properties", []),
            {"name": "vendor:tracking", "value": "JIRA-1"},
        ]
        risk_ref = document["risks"]["risks"][0]["bom-ref"]
        scenarios["Backup theft"]["relatedRisks"] = [risk_ref]
        document["externalReferences"] = [
            {"type": "documentation", "url": "https://docs.example"}
        ]
        assert_valid_tmbom(document, context="decorated")
        return document

    def test_unknown_content_survives_import_and_export(self):
        document = self._decorated_document()
        imported = self.import_copy(document)
        second = self.export(imported)
        decorated = self._scenarios(second)["SQL injection"]
        self.assertEqual(
            decorated["externalReferences"],
            [{"type": "advisories", "url": "https://advisories.example/1"}],
        )
        self.assertEqual(decorated["motivation"], ["financial"])
        self.assertIn(
            {"name": "vendor:tracking", "value": "JIRA-1"}, decorated["properties"]
        )
        self.assertEqual(second["externalReferences"], document["externalReferences"])
        self.assertEqual(as_lines(document), as_lines(second))

    def test_kept_refs_point_at_the_re_exported_elements(self):
        document = self._decorated_document()
        imported = self.import_copy(document)
        second = self.export(imported)
        risk_ref = second["risks"]["risks"][0]["bom-ref"]
        self.assertEqual(
            self._scenarios(second)["Backup theft"]["relatedRisks"], [risk_ref]
        )

    def test_stale_refs_are_dropped_with_a_warning(self):
        document = self._decorated_document()
        imported = self.import_copy(document)
        Risk.objects.filter(threat_model=imported).delete()
        warnings = []
        second = self.export(imported, warnings=warnings)
        self.assertNotIn("relatedRisks", self._scenarios(second)["Backup theft"])
        self.assertTrue(
            any("relatedRisks" in warning for warning in warnings), warnings
        )

    def test_the_export_endpoint_lists_what_it_left_out(self):
        """R17: the download names the stale refs it removed."""
        import json

        from rest_framework.test import APIClient

        document = self._decorated_document()
        imported = self.import_copy(document)
        Risk.objects.filter(threat_model=imported).delete()
        client = APIClient()
        client.force_authenticate(self.user)
        response = client.get(f"/api/threat-models/{imported.id}/export/cyclonedx/")
        self.assertEqual(response.status_code, 200)
        warnings = json.loads(response["X-Export-Warnings"])
        self.assertTrue(
            any("relatedRisks" in warning for warning in warnings), warnings
        )

        clean = client.get(
            f"/api/threat-models/{self.threat_model.id}/export/cyclonedx/"
        )
        self.assertEqual(json.loads(clean["X-Export-Warnings"]), [])

    def _group_b_document(self):
        """The reference export plus every group B section Precogly keeps but
        does not model (9.7, 9.9): attack trees, attack paths, abuse cases,
        risk appetites, assessments and blueprint behaviors."""
        document = self.export()
        actor_ref = document["blueprints"][0]["actors"][0]["bom-ref"]
        risk_ref = document["risks"]["risks"][0]["bom-ref"]
        threats = document["threats"]
        threats["attackTrees"] = [
            {
                "bom-ref": "tree-1",
                "name": "Steal card data",
                "root": "tree-node-1",
                "nodes": [
                    {
                        "bom-ref": "tree-node-1",
                        "name": "Get card data",
                        "children": ["tree-node-2"],
                    },
                    {"bom-ref": "tree-node-2", "name": "Phish an operator"},
                ],
            }
        ]
        threats["attackPaths"] = [
            {
                "bom-ref": "path-1",
                "name": "Phishing to database",
                "actor": actor_ref,
                "relatedRisks": [risk_ref],
                "steps": [{"description": "Send a phishing mail"}],
            }
        ]
        threats["abuseCases"] = [
            {
                "bom-ref": "abuse-1",
                "name": "Insider exports card data",
                "abuser": actor_ref,
            }
        ]
        document["risks"]["riskAppetites"] = [
            {
                "bom-ref": "appetite-1",
                "level": "cautious",
                "statement": "Little appetite for card data loss",
            }
        ]
        document["risks"]["assessments"] = [
            {
                "bom-ref": "assessment-1",
                "type": ["security"],
                "cadence": "periodic",
                "timestamp": "2026-01-01T00:00:00Z",
                "risks": [risk_ref],
            }
        ]
        document["blueprints"][0]["behaviors"] = {"graphs": [], "instances": []}
        assert_valid_tmbom(document, context="group B")
        return document

    def test_group_b_sections_survive_a_round_trip(self):
        """R37: kept sections come back identical, with refs that resolve."""
        from apps.threat_models.tmbom.validation import check_ref_integrity

        document = self._group_b_document()
        second = self.export(self.import_copy(document))
        self.assertEqual(check_ref_integrity(second), [])
        actor_ref = second["blueprints"][0]["actors"][0]["bom-ref"]
        risk_ref = second["risks"]["risks"][0]["bom-ref"]
        for section, key in (
            ("threats", "attackTrees"),
            ("threats", "abuseCases"),
            ("risks", "riskAppetites"),
        ):
            with self.subTest(key=key):
                self.assertEqual(second[section][key], document[section][key])
        path = second["threats"]["attackPaths"][0]
        self.assertEqual((path["actor"], path["relatedRisks"]), (actor_ref, [risk_ref]))
        self.assertEqual(second["threats"]["abuseCases"][0]["abuser"], actor_ref)
        self.assertEqual(second["risks"]["assessments"][0]["risks"], [risk_ref])
        self.assertEqual(
            second["blueprints"][0]["behaviors"], document["blueprints"][0]["behaviors"]
        )
        self.assertEqual(as_lines(document), as_lines(second))

    def test_kept_refs_on_a_control_that_point_into_kept_content_round_trip(self):
        """R48 and R31: refs kept on a row resolve to kept elements and come back."""
        from apps.threat_models.tmbom.validation import check_ref_integrity

        document = self._group_b_document()
        control = document["controls"][0]
        control["appliesTo"] = [*control.get("appliesTo", []), "tree-1"]
        control["implementedBy"] = [*control.get("implementedBy", []), "path-1"]
        assert_valid_tmbom(document, context="control refs into kept content")

        second = self.export(self.import_copy(document))
        self.assertEqual(check_ref_integrity(second), [])
        exported = next(
            entry for entry in second["controls"] if entry["name"] == control["name"]
        )
        self.assertIn("tree-1", exported["appliesTo"])
        self.assertIn("path-1", exported["implementedBy"])


class DfdGenerationTests(_ReferenceModelTests):
    """A document without a visualization gets a canvas that syncs to no change (9.11)."""

    def _rows(self, threat_model):
        blueprint = threat_model.default_blueprint
        fields = lambda model: [  # noqa: E731
            f.name
            for f in model._meta.concrete_fields
            if f.name not in ("id", "created_at", "updated_at", "edge_id")
            and not f.many_to_one
        ]
        snapshot = {}
        for label, model, order in (
            ("zones", Zone, "name"),
            ("components", OrgsystemComponent, "name"),
            ("flows", Flow, "label"),
            ("boundaries", Boundary, "label"),
        ):
            rows = model.objects.filter(blueprint=blueprint).order_by(order)
            snapshot[label] = [
                {name: getattr(row, name) for name in fields(model)}
                | {"links": _link_names(row)}
                for row in rows
            ]
        return snapshot

    def test_import_without_visualization_generates_a_canvas_that_round_trips(self):
        document = self.export()
        for blueprint in document["blueprints"]:
            blueprint.pop("visualizations", None)
        assert_valid_tmbom(document, context="no visualization")
        imported = self.import_copy(document)
        dfd = DFD.objects.get(blueprint=imported.default_blueprint, is_primary=True)
        node_labels = {node["data"]["label"] for node in dfd.canvas_data["nodes"]}
        self.assertTrue(
            {"API", "Database", "DMZ", "Core", "Internet"} <= node_labels, node_labels
        )
        self.assertEqual(len(dfd.canvas_data["edges"]), 3 + 2)  # flows + boundaries

        before = self._rows(imported)
        sync_dfd_nodes_to_components(
            dfd, imported.default_blueprint, old_canvas_data=dfd.canvas_data
        )
        after = self._rows(imported)
        self.assertEqual(before, after)
        # The re-export carries the generated canvas the input did not have.
        second = self.export(imported)
        for blueprint in second["blueprints"]:
            blueprint.pop("visualizations", None)
        self.assertEqual(as_lines(document), as_lines(second))


def _link_names(row):
    if isinstance(row, Zone):
        return {"parent": row.parent.name if row.parent else None}
    if isinstance(row, OrgsystemComponent):
        return {"zone": row.zone.name if row.zone else None}
    if isinstance(row, Flow):
        return {"source": row.source_component.name, "dest": row.dest_component.name}
    return {"zone_a": row.zone_a.name, "zone_b": row.zone_b.name}


class FieldCoverageTests(TestCase):
    """Every snapshot field has a listed home, and every property home is registered (H17)."""

    def test_every_snapshot_field_has_a_home(self):
        unlisted = {}
        for label, (fields, _excluded) in SNAPSHOT_FIELDS.items():
            homes = FIELD_HOMES.get(label)
            if homes is None:
                unlisted[label] = list(fields)
                continue
            missing = [name for name in fields if name not in homes]
            if missing:
                unlisted[label] = missing
        self.assertEqual(unlisted, {}, f"fields with no listed TM-BOM home: {unlisted}")

    def test_listed_homes_are_real_fields(self):
        stale = {
            label: sorted(set(homes) - set(SNAPSHOT_FIELDS.get(label, ([], []))[0]))
            for label, homes in FIELD_HOMES.items()
        }
        self.assertEqual({k: v for k, v in stale.items() if v}, {})
        self.assertEqual(set(FIELD_HOMES) - set(SNAPSHOT_FIELDS), set())

    def test_property_homes_are_registered(self):
        registered = registered_names()
        unknown = []
        for label, homes in FIELD_HOMES.items():
            for name, home in homes.items():
                if isinstance(home, tuple):
                    self.assertEqual(home[0], NOT_EXPORTED)
                    self.assertTrue(home[1], f"{label}.{name} needs a reason")
                    continue
                for token in home.replace(",", " ").split():
                    if token.startswith(PROPERTY_PREFIX) and token not in registered:
                        unknown.append(f"{label}.{name}: {token}")
        self.assertEqual(unknown, [])
