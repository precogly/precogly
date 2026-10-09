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
