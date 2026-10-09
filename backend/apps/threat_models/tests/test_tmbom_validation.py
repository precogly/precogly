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
from apps.threat_models.tmbom.testing import assert_valid_tmbom
from apps.threat_models.tmbom.validation import (
    check_ref_integrity,
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
