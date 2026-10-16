"""Import warnings say how to fix the file (any tool's output, not one vendor's).

The importer stays strict and the export stays valid 2.0; these tests only
check that a warning names what to write instead.
"""

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase

from apps.organizations.models import Organization, OrganizationMember
from apps.threat_models.tmbom import TmBomAdapter
from apps.threat_models.tmbom.import_hints import (
    STANDARD_REQUIREMENTS,
    custom_properties_warning,
    schema_hint,
    with_hint,
)
from apps.threat_models.tmbom.validation import SchemaError, validate_document

User = get_user_model()


class SchemaHintTests(SimpleTestCase):
    def test_a_missing_required_field_says_what_to_add(self):
        error = SchemaError(
            path="blueprints/0", message="'modelTypes' is a required property"
        )
        self.assertIn('["data-flow"]', schema_hint(error))
        generic = SchemaError(
            path="controls/0", message="'name' is a required property"
        )
        self.assertEqual(schema_hint(generic), 'Add "name" to this object.')

    def test_a_standard_requirement_in_the_wrong_list_points_at_standards(self):
        error = SchemaError(
            path="definitions/requirements/0",
            message="Additional properties are not allowed ('identifier', 'source' were unexpected)",
        )
        self.assertIn(STANDARD_REQUIREMENTS, schema_hint(error))

    def test_other_unexpected_fields_point_at_properties(self):
        error = SchemaError(
            path="controls/0",
            message="Additional properties are not allowed ('vendorField' was unexpected)",
        )
        self.assertIn('"properties"', schema_hint(error))

    def test_an_object_in_satisfies_asks_for_a_reference(self):
        error = SchemaError(
            path="controls/2/satisfies/0",
            message="{'reference': 'AC-4'} is not of type 'string'",
        )
        self.assertIn("bom-ref", schema_hint(error))

    def test_a_message_that_says_enough_gets_no_hint(self):
        error = SchemaError(
            path="controls/0/status", message="'done' is not one of ['planned']"
        )
        self.assertIsNone(schema_hint(error))
        self.assertEqual(with_hint(error), f"Schema: {error}")


class CustomPropertiesWarningTests(SimpleTestCase):
    def test_lists_the_properties_it_does_not_read_with_counts(self):
        document = {
            "controls": [
                {"properties": [{"name": "vendor:due", "value": "2026-01-01"}]},
                {"properties": [{"name": "vendor:due", "value": "2026-02-01"}]},
            ],
            "metadata": {"properties": [{"name": "vendor:system", "value": "x"}]},
        }
        warning = custom_properties_warning(document)
        self.assertIn("vendor:due (2)", warning)
        self.assertIn("vendor:system (1)", warning)
        self.assertIn("precogly:due-date", warning)

    def test_precogly_properties_alone_raise_nothing(self):
        document = {
            "controls": [{"properties": [{"name": "precogly:number", "value": "1"}]}],
            "metadata": {
                "properties": [{"name": "precogly-guest:session", "value": "x"}]
            },
        }
        self.assertIsNone(custom_properties_warning(document))


class ImportWarningTests(TestCase):
    """End to end: the shapes migrating tools commonly write."""

    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="u", email="u@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )

    def _warnings(self, document) -> str:
        _, summary = TmBomAdapter().import_data(document, self.organization, self.user)
        return "\n".join(summary.get("warnings", []))

    def _document(self, **sections) -> dict:
        return {
            "specFormat": "CycloneDX",
            "specVersion": "2.0",
            "metadata": {
                "component": {"type": "application", "bom-ref": "sys", "name": "Shop"}
            },
            "blueprints": [
                {"bom-ref": "bp", "name": "Main", "modelTypes": ["data-flow"]}
            ],
            **sections,
        }

    def test_a_requirement_under_definitions_requirements_says_where_it_belongs(self):
        warnings = self._warnings(
            self._document(
                definitions={
                    "requirements": [
                        {"bom-ref": "req-ac2", "identifier": "AC-2", "name": "Accounts"}
                    ]
                },
                controls=[
                    {
                        "bom-ref": "c1",
                        "name": "Account reviews",
                        "status": "implemented",
                        "satisfies": ["req-ac2"],
                    }
                ],
            )
        )
        self.assertIn("engineering requirement", warnings)
        self.assertIn(STANDARD_REQUIREMENTS, warnings)

    def test_a_dangling_satisfies_ref_says_to_define_it(self):
        warnings = self._warnings(
            self._document(
                controls=[
                    {
                        "bom-ref": "c1",
                        "name": "Backups",
                        "status": "planned",
                        "satisfies": ["req-missing"],
                    }
                ]
            )
        )
        self.assertIn("No requirement has that bom-ref", warnings)

    def test_custom_properties_and_bad_dates_are_named(self):
        warnings = self._warnings(
            self._document(
                controls=[
                    {
                        "bom-ref": "c1",
                        "name": "Encrypt at rest",
                        "status": "planned",
                        "properties": [
                            {"name": "tool:target-date", "value": "2026-12-31"},
                            {"name": "precogly:due-date", "value": "31/12/2026"},
                        ],
                    }
                ]
            )
        )
        self.assertIn("tool:target-date (1)", warnings)
        # Not every custom property survives export, so the warning must not promise it.
        self.assertIn("Most are written back on export, but not", warnings)
        self.assertIn("YYYY-MM-DD", warnings)

    def test_an_unknown_status_lists_the_ones_precogly_reads(self):
        warnings = self._warnings(
            self._document(
                controls=[{"bom-ref": "c1", "name": "MFA", "status": "done"}]
            )
        )
        self.assertIn("Statuses Precogly reads:", warnings)
        self.assertIn("implemented", warnings)

    def test_the_document_used_here_is_otherwise_valid(self):
        self.assertEqual(validate_document(self._document()), [])
