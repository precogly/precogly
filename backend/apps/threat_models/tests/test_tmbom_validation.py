"""The pinned schema loads, validates, and reports errors by path."""

from django.test import SimpleTestCase

from apps.threat_models.tmbom.properties import (
    PROPERTY_PREFIX,
    REGISTRY,
    PrecoglyProperty,
    PropertyOwner,
    PropertyValueType,
)
from apps.threat_models.tmbom.schema import (
    PINNED_COMMIT,
    SCHEMA_ID,
    SCHEMA_PATH,
    load_schema,
)
from apps.threat_models.tmbom.spec_values import REF_KEYS
from apps.threat_models.tmbom.testing import assert_valid_tmbom
from apps.threat_models.tmbom.validation import (
    check_ref_integrity,
    ref_keys_in_schema,
    validate_document,
)

MINIMAL_VALID_DOCUMENT = {
    "specFormat": "CycloneDX",
    "specVersion": "2.0",
}


class PinnedSchemaTests(SimpleTestCase):
    def test_schema_file_is_the_bundled_2_0_schema(self):
        schema = load_schema()
        self.assertEqual(schema["$id"], SCHEMA_ID)
        self.assertTrue(SCHEMA_PATH.exists())
        self.assertRegex(PINNED_COMMIT, r"^[0-9a-f]{40}$")

    def test_minimal_document_has_no_errors(self):
        self.assertEqual(validate_document(MINIMAL_VALID_DOCUMENT), [])
        assert_valid_tmbom(MINIMAL_VALID_DOCUMENT)

    def test_errors_carry_the_json_path(self):
        document = {
            **MINIMAL_VALID_DOCUMENT,
            "blueprints": [{"bom-ref": "blueprint-1", "modelTypes": ["data-flow"]}],
        }
        errors = validate_document(document)
        self.assertTrue(errors)
        self.assertEqual(errors[0].path, "blueprints/0")
        self.assertIn("name", errors[0].message)

    def test_format_keywords_are_checked(self):
        """R49: a value that breaks a ``format`` keyword is an error."""
        document = {
            **MINIMAL_VALID_DOCUMENT,
            "metadata": {"authors": [{"name": "Dana", "email": "not an address"}]},
        }
        errors = validate_document(document)
        self.assertTrue(
            any(error.path == "metadata/authors/0/email" for error in errors), errors
        )
        document["metadata"]["authors"][0]["email"] = "dana@example.com"
        self.assertEqual(validate_document(document), [])

    def test_assert_valid_tmbom_lists_every_error(self):
        document = {"specFormat": "CycloneDX"}
        with self.assertRaises(AssertionError) as raised:
            assert_valid_tmbom(document, context="in test")
        self.assertIn("specVersion", str(raised.exception))
        self.assertIn("in test", str(raised.exception))


class RefIntegrityTests(SimpleTestCase):
    def test_duplicate_bom_refs_are_reported_with_both_paths(self):
        document = {
            **MINIMAL_VALID_DOCUMENT,
            "controls": [
                {"bom-ref": "control-1", "name": "A"},
                {"bom-ref": "control-1", "name": "B"},
            ],
        }
        findings = check_ref_integrity(document)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, "controls/1/bom-ref")
        self.assertIn("controls/0", findings[0].message)

    def test_unique_refs_pass(self):
        document = {
            **MINIMAL_VALID_DOCUMENT,
            "controls": [
                {"bom-ref": "control-1", "name": "A"},
                {"bom-ref": "control-2", "name": "B"},
            ],
        }
        self.assertEqual(check_ref_integrity(document), [])

    def test_ref_keys_match_the_pinned_schema(self):
        """R18: every ref field the schema defines is checked, none by hand."""
        self.assertEqual(set(REF_KEYS), set(ref_keys_in_schema()))
        self.assertEqual(len(REF_KEYS), len(set(REF_KEYS)))

    def test_dangling_attack_tree_and_abuse_case_refs_are_found(self):
        document = {
            **MINIMAL_VALID_DOCUMENT,
            "threats": {
                "attackTrees": [{"bom-ref": "tree-1", "root": "node-gone"}],
                "abuseCases": [
                    {"bom-ref": "abuse-1", "abuser": "actor-gone", "children": []}
                ],
            },
        }
        messages = [str(finding) for finding in check_ref_integrity(document)]
        self.assertEqual(
            messages,
            [
                "threats/attackTrees/0/root: reference 'node-gone' resolves to nothing",
                "threats/abuseCases/0/abuser: reference 'actor-gone' resolves to nothing",
            ],
        )

    def test_urls_are_not_read_as_refs(self):
        document = {
            **MINIMAL_VALID_DOCUMENT,
            "externalReferences": [{"type": "website", "url": "https://example.com"}],
        }
        self.assertEqual(check_ref_integrity(document), [])


class PropertyRegistryTests(SimpleTestCase):
    def test_every_entry_is_prefixed_and_unique_per_owner(self):
        seen = set()
        for entry in REGISTRY:
            self.assertTrue(entry.name.startswith(PROPERTY_PREFIX))
            self.assertNotIn((entry.name, entry.owner), seen)
            seen.add((entry.name, entry.owner))

    def test_unprefixed_name_is_refused(self):
        with self.assertRaises(ValueError):
            PrecoglyProperty(
                name="number",
                owner=PropertyOwner.SCENARIO,
                value_type=PropertyValueType.STRING,
                description="",
            )


class StaleRefRepairTests(SimpleTestCase):
    """R19: kept content loses only stale refs, and the warnings say where."""

    def repair(self, value, key):
        from apps.threat_models.tmbom.passthrough import _kept, _repair

        warnings = []
        repaired = _repair(value, {"gone"}, "threats section", warnings, key)
        return (repaired if _kept(value, repaired) else None), warnings

    def test_a_name_equal_to_a_stale_ref_stays(self):
        repaired, warnings = self.repair(
            [{"bom-ref": "tree-1", "name": "gone", "root": "gone"}], "attackTrees"
        )
        self.assertEqual(repaired, [{"bom-ref": "tree-1", "name": "gone"}])
        self.assertEqual(
            warnings,
            [
                "threats section, attackTrees 'gone': dropped root 'gone'; "
                "it no longer resolves."
            ],
        )

    def test_an_entry_that_loses_a_required_ref_is_left_out(self):
        repaired, warnings = self.repair(
            [
                {"bom-ref": "rel-1", "ref": "gone", "type": "depends-on"},
                {"bom-ref": "rel-2", "ref": "kept", "type": "depends-on"},
            ],
            "relationships",
        )
        self.assertEqual(
            repaired, [{"bom-ref": "rel-2", "ref": "kept", "type": "depends-on"}]
        )
        self.assertIn(
            "threats section, relationships 'rel-1': left out of the file; "
            "its ref no longer resolves.",
            warnings,
        )

    def test_a_list_that_loses_every_ref_goes(self):
        repaired, warnings = self.repair(["gone"], "relatedRisks")
        self.assertIsNone(repaired)
        self.assertEqual(
            warnings,
            [
                "threats section: removed 'gone' from relatedRisks; it no longer resolves."
            ],
        )


class SpecValuesTests(SimpleTestCase):
    """R50, plan 9.6: every ``spec_values`` list matches the pinned schema.

    Each list names the schema enum it mirrors. A re-pin that changes an enum
    fails here, and the guest editor's generated copy follows through
    ``frontend/scripts/generate-cyclonedx-spec.mjs``.
    """

    BLUEPRINT = "/$defs/cyclonedx-blueprint-2.0/$defs"
    EXACT = {
        "ASSET_TYPES": f"{BLUEPRINT}/asset/properties/type/oneOf/0",
        "BOUNDARY_TYPES": f"{BLUEPRINT}/boundary/properties/type/oneOf/0",
        "DATA_STORE_TYPES": f"{BLUEPRINT}/dataStore/properties/type/oneOf/0",
        "FLOW_TYPES": f"{BLUEPRINT}/flow/properties/type/oneOf/0",
        "MODEL_TYPES": f"{BLUEPRINT}/modelType/oneOf/0",
        "VISUALIZATION_TYPES": (
            f"{BLUEPRINT}/visualizationType/oneOf/0/properties/type"
        ),
        "ZONE_TYPES": f"{BLUEPRINT}/zone/properties/type/oneOf/0",
        "CONTROL_CATEGORIES": (
            "/$defs/cyclonedx-control-2.0/$defs/control/properties/category/oneOf/0"
        ),
        "IMPLEMENTATION_STATUSES": (
            "/$defs/cyclonedx-control-2.0/$defs/implementationStatus/oneOf/0"
        ),
        "DATA_CLASSIFICATIONS": (
            "/$defs/cyclonedx-data-2.0/$defs/dataClassification/oneOf/0"
        ),
        "METADATA_COMPONENT_TYPES": (
            "/$defs/cyclonedx-component-2.0/$defs/component/properties/type"
        ),
        "PERSONA_ARCHETYPES": (
            "/$defs/cyclonedx-party-2.0/$defs/persona/properties/archetype/oneOf/0"
        ),
        "SCENARIO_ACCESS_LEVELS": (
            "/$defs/cyclonedx-threat-2.0/$defs/threatScenario/properties/accessLevel"
        ),
        "SCENARIO_INTENTS": (
            "/$defs/cyclonedx-threat-2.0/$defs/threatScenario/properties/intent"
        ),
        "THREAT_ORIGINS": (
            "/$defs/cyclonedx-threat-2.0/$defs/threat/properties/origin/oneOf/0"
        ),
        "THREAT_TAXONOMIES": (
            "/$defs/cyclonedx-threat-2.0/$defs/threat/properties/categories"
            "/items/properties/taxonomy"
        ),
        "TRUST_LEVELS": (
            "/$defs/cyclonedx-threat-2.0/$defs/trustBoundary/properties/trustLevel"
        ),
    }
    # Lists that are a chosen part of a larger enum, on purpose.
    SUBSET = {
        "ATTACKER_ARCHETYPES": EXACT["PERSONA_ARCHETYPES"],
        "EXTERNAL_REFERENCE_TYPES": (
            "/$defs/cyclonedx-common-2.0/$defs/externalReference/properties/type"
        ),
    }

    def schema_enum(self, pointer: str) -> set:
        node = load_schema()
        for part in pointer.strip("/").split("/"):
            node = node[int(part)] if isinstance(node, list) else node[part]
        return set(node["enum"])

    def test_lists_equal_their_schema_enums(self):
        from apps.threat_models.tmbom import spec_values

        for name, pointer in self.EXACT.items():
            with self.subTest(name=name):
                self.assertEqual(
                    set(getattr(spec_values, name)), self.schema_enum(pointer)
                )
        for name, pointer in self.SUBSET.items():
            with self.subTest(name=name):
                self.assertLessEqual(
                    set(getattr(spec_values, name)), self.schema_enum(pointer)
                )
