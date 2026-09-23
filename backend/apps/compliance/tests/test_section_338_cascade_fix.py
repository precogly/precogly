"""
Tests for precogly/precogly#338: a typo'd/renamed section_code on a
compliance-pack reimport used to CASCADE-delete every CountermeasureLibrary
Standard / StandardRequirementMapping row that referenced the old
StandardRequirement -- the same failure family as #318 (pack reimport
silently destroying downstream data via a hard delete instead of leaving
stale rows for update_or_create to reconcile).

Root cause, confirmed by reading apps/packs/services.py::_load_frameworks():
on every framework (re)import it prunes StandardRequirement rows whose
section_code isn't in the freshly-parsed YAML
(`StandardRequirement.objects.filter(framework=framework).exclude(
section_code__in=incoming_section_codes).delete()`), to drop items that were
genuinely removed from the pack. A section_code that changed for any other
reason (typo fixed, renamed) looks identical to "removed" from that query's
point of view, so the old row gets deleted -- and under CASCADE, so did
everything that pointed at it.

Fix (matching precogly/precogly#318's precedent, see apps/compliance/
models.py): CountermeasureLibraryStandard.requirement and
StandardRequirementMapping.from_requirement/to_requirement changed from
CASCADE to SET_NULL, matching the on_delete already used one model over for
the same relationship (InstanceCountermeasureStandard.requirement). The
mapping row survives with requirement=None instead of being destroyed.
"""

from django.test import TestCase

from apps.compliance.models import (
    CountermeasureLibraryStandard,
    StandardFramework,
    StandardRequirement,
    StandardRequirementMapping,
)
from apps.packs.models import LibraryPack
from apps.packs.services import _load_frameworks
from apps.threats.models import CountermeasureLibrary


class SectionCodeRenameNoLongerCascadesTests(TestCase):
    """End-to-end repro through the real reimport path
    (apps.packs.services._load_frameworks), not just a direct model-level
    delete -- this is the actual code path #338 was filed against."""

    @classmethod
    def setUpTestData(cls):
        cls.pack = LibraryPack.objects.create(
            slug="section-338-test-pack",
            name="Section 338 Test Pack",
            description="",
            pack_type=LibraryPack.PackType.COMPLIANCE,
            version="1.0.0",
            author="test",
        )
        cls.cm_pack = LibraryPack.objects.create(
            slug="section-338-test-cm-pack",
            name="Section 338 Test CM Pack",
            description="",
            pack_type=LibraryPack.PackType.COUNTERMEASURE,
            version="1.0.0",
            author="test",
        )

        # Import the framework for the first time via the real loader, with
        # the section_code that will later be "typo'd"/renamed.
        _load_frameworks(
            cls.pack,
            {
                "frameworks": [
                    {
                        "slug": "section-338-framework",
                        "name": "Section 338 Framework",
                        "version": "1.0",
                        "issuer": "Test",
                        "requirements": [
                            {
                                "section_code": "V.A",
                                "description": "Original requirement",
                            },
                        ],
                    }
                ],
            },
        )
        cls.framework = StandardFramework.objects.get(slug="section-338-framework")
        cls.requirement_va = StandardRequirement.objects.get(
            framework=cls.framework,
            section_code="V.A",
        )

        # A second framework + requirement, so StandardRequirementMapping
        # (cross-framework) can be exercised too, not just
        # CountermeasureLibraryStandard.
        cls.other_framework = StandardFramework.objects.create(
            slug="section-338-other-framework",
            name="Section 338 Other Framework",
            version="1.0",
            issuer="Test",
        )
        cls.requirement_x1 = StandardRequirement.objects.create(
            framework=cls.other_framework,
            section_code="X.1",
            description="Cross-framework target",
        )

        cls.countermeasure = CountermeasureLibrary.objects.create(
            source_pack=cls.cm_pack,
            slug="section-338-countermeasure",
            qualified_slug="section-338-test-cm-pack/section-338-countermeasure",
            name="Section 338 Countermeasure",
            description="",
            control_functions=["preventive"],
        )

    def test_countermeasure_mapping_survives_section_code_rename(self):
        mapping = CountermeasureLibraryStandard.objects.create(
            countermeasure_library=self.countermeasure,
            requirement=self.requirement_va,
            sufficiency=CountermeasureLibraryStandard.Sufficiency.FULL,
        )

        # Reimport the framework with "V.A" renamed to "V.A1" (a typo fix,
        # or an honest rename -- indistinguishable from "removed" to the
        # prune-stale-requirements query in _load_frameworks()).
        _load_frameworks(
            self.pack,
            {
                "frameworks": [
                    {
                        "slug": "section-338-framework",
                        "name": "Section 338 Framework",
                        "version": "1.0",
                        "issuer": "Test",
                        "requirements": [
                            {
                                "section_code": "V.A1",
                                "description": "Renamed requirement",
                            },
                        ],
                    }
                ],
            },
        )

        # The old requirement really is gone -- that part of the prune is
        # correct and intentional, not what #338 is about.
        self.assertFalse(
            StandardRequirement.objects.filter(
                framework=self.framework,
                section_code="V.A",
            ).exists()
        )
        self.assertTrue(
            StandardRequirement.objects.filter(
                framework=self.framework,
                section_code="V.A1",
            ).exists()
        )

        # The bug: under CASCADE this row would have been silently deleted
        # along with the old requirement. It must survive.
        mapping.refresh_from_db()
        self.assertIsNone(mapping.requirement)
        self.assertEqual(
            mapping.sufficiency, CountermeasureLibraryStandard.Sufficiency.FULL
        )
        self.assertTrue(
            CountermeasureLibraryStandard.objects.filter(pk=mapping.pk).exists()
        )

    def test_cross_framework_mapping_survives_section_code_rename_on_either_side(self):
        from_mapping = StandardRequirementMapping.objects.create(
            from_requirement=self.requirement_va,
            to_requirement=self.requirement_x1,
            sufficiency=StandardRequirementMapping.Sufficiency.PARTIAL,
            source_pack=self.pack,
        )

        _load_frameworks(
            self.pack,
            {
                "frameworks": [
                    {
                        "slug": "section-338-framework",
                        "name": "Section 338 Framework",
                        "version": "1.0",
                        "issuer": "Test",
                        "requirements": [
                            {
                                "section_code": "V.A1",
                                "description": "Renamed requirement",
                            },
                        ],
                    }
                ],
            },
        )

        from_mapping.refresh_from_db()
        self.assertIsNone(from_mapping.from_requirement)
        # The other side (never renamed) is untouched.
        self.assertEqual(from_mapping.to_requirement_id, self.requirement_x1.id)
        self.assertTrue(
            StandardRequirementMapping.objects.filter(pk=from_mapping.pk).exists()
        )

    def test_unrelated_requirement_and_mapping_untouched_by_rename(self):
        """Reimporting framework A with a renamed section_code must not
        affect requirements/mappings that belong to a different framework
        entirely (sanity check on the prune query's own `framework=`
        scoping, independent of the CASCADE fix itself)."""
        cross_mapping = StandardRequirementMapping.objects.create(
            from_requirement=self.requirement_x1,
            to_requirement=self.requirement_va,
            sufficiency=StandardRequirementMapping.Sufficiency.FULL,
            source_pack=self.pack,
        )

        _load_frameworks(
            self.pack,
            {
                "frameworks": [
                    {
                        "slug": "section-338-framework",
                        "name": "Section 338 Framework",
                        "version": "1.0",
                        "issuer": "Test",
                        "requirements": [
                            {
                                "section_code": "V.A1",
                                "description": "Renamed requirement",
                            },
                        ],
                    }
                ],
            },
        )

        # requirement_x1 belongs to other_framework, never reimported here.
        self.requirement_x1.refresh_from_db()
        self.assertEqual(self.requirement_x1.section_code, "X.1")

        cross_mapping.refresh_from_db()
        self.assertEqual(cross_mapping.from_requirement_id, self.requirement_x1.id)
        # Only the renamed side (to_requirement, which pointed at V.A) is nulled.
        self.assertIsNone(cross_mapping.to_requirement)


class OrphanedMappingConsumersDontCrashTests(TestCase):
    """The SET_NULL fix only closes the data-loss bug if every consumer of
    these two models tolerates requirement/from_requirement/to_requirement
    being None -- audited across apps/packs/services.py,
    apps/compliance/serializers.py, apps/threat_models/compliance_service.py,
    and apps/diagrams/services.py. This exercises the ones with real test
    seams without a full DB fixture for every call site."""

    @classmethod
    def setUpTestData(cls):
        cls.pack = LibraryPack.objects.create(
            slug="section-338-consumers-pack",
            name="Section 338 Consumers Pack",
            description="",
            pack_type=LibraryPack.PackType.COMPLIANCE,
            version="1.0.0",
            author="test",
        )
        cls.cm_pack = LibraryPack.objects.create(
            slug="section-338-consumers-cm-pack",
            name="Section 338 Consumers CM Pack",
            description="",
            pack_type=LibraryPack.PackType.COUNTERMEASURE,
            version="1.0.0",
            author="test",
        )
        cls.framework = StandardFramework.objects.create(
            slug="section-338-consumers-framework",
            name="Consumers Framework",
            version="1.0",
            issuer="Test",
        )
        cls.requirement = StandardRequirement.objects.create(
            framework=cls.framework,
            section_code="C.1",
            description="",
        )
        cls.countermeasure = CountermeasureLibrary.objects.create(
            source_pack=cls.cm_pack,
            slug="section-338-consumers-cm",
            qualified_slug="section-338-consumers-cm-pack/section-338-consumers-cm",
            name="Consumers Countermeasure",
            description="",
            control_functions=["preventive"],
        )
        # One live mapping, one orphaned (requirement already nulled) --
        # exercises both branches in a single queryset.
        cls.live_mapping = CountermeasureLibraryStandard.objects.create(
            countermeasure_library=cls.countermeasure,
            requirement=cls.requirement,
            sufficiency=CountermeasureLibraryStandard.Sufficiency.FULL,
        )
        other_requirement = StandardRequirement.objects.create(
            framework=cls.framework,
            section_code="C.2",
            description="",
        )
        cls.orphaned_mapping = CountermeasureLibraryStandard.objects.create(
            countermeasure_library=cls.countermeasure,
            requirement=other_requirement,
            sufficiency=CountermeasureLibraryStandard.Sufficiency.PARTIAL,
        )
        other_requirement.delete()  # SET_NULL fires; orphaned_mapping.requirement -> None

    def test_get_active_overlays_for_pack_skips_orphaned_mappings(self):
        from apps.packs.services import get_active_overlays_for_pack

        self.orphaned_mapping.refresh_from_db()
        self.assertIsNone(self.orphaned_mapping.requirement)

        overlays = get_active_overlays_for_pack(self.cm_pack)
        self.assertEqual(len(overlays), 1)
        self.assertEqual(overlays[0].framework_id, self.framework.slug)
        self.assertEqual(overlays[0].mapping_count, 1)

    def test_serializer_returns_null_fields_for_orphaned_mapping(self):
        """Serializer .data uses the plain (snake_case) field names declared
        in the Meta class -- camelCase conversion happens one layer up, in
        the response renderer, not on direct .data access."""
        from apps.compliance.serializers import CountermeasureLibraryStandardSerializer

        self.orphaned_mapping.refresh_from_db()
        data = CountermeasureLibraryStandardSerializer(self.orphaned_mapping).data
        self.assertIsNone(data["requirement_code"])
        self.assertIsNone(data["framework_name"])

        live_data = CountermeasureLibraryStandardSerializer(self.live_mapping).data
        self.assertEqual(live_data["requirement_code"], "C.1")
        self.assertEqual(live_data["framework_name"], self.framework.name)

    def test_str_does_not_crash_on_orphaned_rows(self):
        self.orphaned_mapping.refresh_from_db()
        # Must not raise.
        str(self.orphaned_mapping)

        mapping = StandardRequirementMapping.objects.create(
            from_requirement=None,
            to_requirement=self.requirement,
            sufficiency=StandardRequirementMapping.Sufficiency.PARTIAL,
        )
        str(mapping)
