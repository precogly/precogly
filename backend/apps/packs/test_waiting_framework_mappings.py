"""Compliance mappings to a framework that is not imported yet (catalog plan C8a).

The import dialog now ticks every overlay, including those for frameworks that
are not imported. These tests pin the server side that change relies on:

  Importing a pack that maps to a framework not imported yet validates with a
  warning ("overlay will be stored as pending"), so these imports pass
  accept_warnings, the "Import anyway" a user chooses.

  - item 3: a selected overlay for a missing framework is stored as waiting
    (PendingFrameworkOverlay) and turns on when the framework is imported, and a
    re-import of the mapping pack keeps it waiting;
  - item 4: re-importing the standards pack with force keeps the mappings that
    point at it, which the "Install <version>" button relies on;
  - a waiting mapping that names a requirement code the framework lacks: what
    happens is recorded, not required.
"""

import tempfile
from pathlib import Path

from django.test import TestCase

from apps.compliance.models import CountermeasureLibraryStandard
from apps.packs.fake_catalog import write_pack_folder
from apps.packs.models import PendingFrameworkOverlay
from apps.packs.services import ImportResult, import_pack_from_path


def write_standards_pack(root: Path, version: str = "1.0.0") -> Path:
    pack_dir = root / f"std-{version}" / "std"
    pack_dir.mkdir(parents=True)
    (pack_dir / "pack.yaml").write_text(
        "pack:\n"
        "  schema_version: 1\n"
        "  slug: std\n"
        "  name: Standard\n"
        f"  version: {version}\n"
        "  pack_type: compliance\n"
        "frameworks:\n"
        "- slug: std-1\n"
        "  name: Standard One\n"
        "  version: '1'\n"
        "  issuer: Test\n"
        "  requirements:\n"
        "  - section_code: R1\n"
        "    description: First requirement\n"
        "  - section_code: R2\n"
        "    description: Second requirement\n"
    )
    return pack_dir


def write_mapping_pack(root: Path, requirement_codes: list[str]) -> Path:
    return write_pack_folder(
        root / "lib",
        {"slug": "lib", "name": "Library", "version": "1.0.0", "pack_type": "full"},
        {
            "countermeasures.yaml": {
                "countermeasures": [
                    {
                        "id": "c1",
                        "name": "Control one",
                        "description": "x",
                        "control_functions": ["preventive"],
                    }
                ]
            },
            "joins/countermeasures-std.yaml": {
                "framework": "std-1",
                "mappings": [
                    {
                        "countermeasure": "c1",
                        "requirements": requirement_codes,
                        "sufficiency": "full",
                    }
                ],
            },
        },
    )


class WaitingFrameworkMappingTests(TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def import_ok(self, pack_dir: Path, **options) -> ImportResult:
        result = import_pack_from_path(pack_dir, **options)
        self.assertIsInstance(
            result, ImportResult, getattr(result, "to_dict", lambda: result)()
        )
        self.assertTrue(result.success, result.message)
        return result

    def mapped_codes(self) -> set[str]:
        return set(
            CountermeasureLibraryStandard.objects.filter(
                countermeasure_library__slug="c1"
            ).values_list("requirement__section_code", flat=True)
        )

    def test_a_selected_overlay_for_a_missing_framework_waits_and_then_turns_on(self):
        mapping_pack = write_mapping_pack(self.root, ["R1", "R2"])

        self.import_ok(mapping_pack, selected_overlays=["std-1"], accept_warnings=True)
        self.assertTrue(
            PendingFrameworkOverlay.objects.filter(
                pack__slug="lib", framework_slug="std-1"
            ).exists()
        )
        self.assertEqual(self.mapped_codes(), set())

        # A re-import of the mapping pack keeps the waiting row.
        self.import_ok(
            mapping_pack, force=True, selected_overlays=["std-1"], accept_warnings=True
        )
        self.assertTrue(
            PendingFrameworkOverlay.objects.filter(
                pack__slug="lib", framework_slug="std-1"
            ).exists()
        )

        self.import_ok(write_standards_pack(self.root))
        self.assertEqual(self.mapped_codes(), {"R1", "R2"})

    def test_an_unselected_overlay_for_a_missing_framework_is_dropped(self):
        # The old dialog's behaviour: the framework was not imported, so it was
        # unticked, and nothing was kept for later.
        self.import_ok(
            write_mapping_pack(self.root, ["R1"]),
            selected_overlays=[],
            accept_warnings=True,
        )
        self.assertFalse(
            PendingFrameworkOverlay.objects.filter(pack__slug="lib").exists()
        )
        self.import_ok(write_standards_pack(self.root))
        self.assertEqual(self.mapped_codes(), set())

    def test_a_forced_reimport_of_the_standards_pack_keeps_its_mappings(self):
        self.import_ok(write_standards_pack(self.root, "1.0.0"))
        self.import_ok(write_mapping_pack(self.root, ["R1", "R2"]))
        mappings_before = CountermeasureLibraryStandard.objects.count()
        self.assertEqual(self.mapped_codes(), {"R1", "R2"})

        self.import_ok(write_standards_pack(self.root, "1.1.0"), force=True)

        self.assertEqual(CountermeasureLibraryStandard.objects.count(), mappings_before)
        self.assertEqual(self.mapped_codes(), {"R1", "R2"})

    def test_a_waiting_mapping_with_a_code_the_framework_lacks(self):
        """Records today's behaviour; see the issue draft on silent drops."""
        self.import_ok(
            write_mapping_pack(self.root, ["R1", "R9"]),
            selected_overlays=["std-1"],
            accept_warnings=True,
        )

        with self.assertNoLogs("apps.packs.services", level="WARNING"):
            result = self.import_ok(write_standards_pack(self.root))

        # R1 turns on. R9 is dropped: no log line at warning level, and nothing
        # in the framework import's own warnings.
        self.assertEqual(self.mapped_codes(), {"R1"})
        self.assertFalse(any("R9" in warning for warning in result.warnings))
