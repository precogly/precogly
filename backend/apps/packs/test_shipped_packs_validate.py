"""Every shipped pack validates with zero errors (plan section 6, M19, S2).

The packs are validated and imported in the seed's order (taxonomies,
standards, threat libraries, worksheets), so cross-pack references, taxonomy
joins and framework overlays resolve the way they do for the seed. Warnings
count as failures too: the seed skips a pack that validates with a warning,
so a warning on a shipped pack is a pack the demo database would not get.
"""

from pathlib import Path

from django.test import TestCase

from apps.packs.services import get_libraries_path, import_pack_from_path, validate_pack

PACK_GROUPS = ("taxonomies", "standards", "threat-libraries", "worksheets")


def shipped_pack_paths() -> list[Path]:
    root = get_libraries_path()
    paths = []
    for group in PACK_GROUPS:
        paths.extend(sorted(p.parent for p in (root / group).glob("*/pack.yaml")))
    return paths


class ShippedPacksValidateTests(TestCase):
    def test_every_shipped_pack_validates_and_imports(self):
        root = get_libraries_path()
        pack_paths = shipped_pack_paths()
        self.assertTrue(pack_paths, f"no packs found under {root}")

        failures = []
        for pack_path in pack_paths:
            relative = pack_path.relative_to(root)
            result = validate_pack(pack_path)
            for error in result.errors:
                failures.append(f"{relative}: {error.file}: {error.message}")
            for warning in result.warnings:
                failures.append(
                    f"{relative} (warning): {warning.file}: {warning.message}"
                )
            if result.errors:
                continue
            imported = import_pack_from_path(pack_path, skip_validation=True)
            if not imported.success:
                failures.append(f"{relative}: import failed: {imported.message}")

        self.assertEqual(failures, [], "\n" + "\n".join(failures))
