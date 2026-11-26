"""After a taxonomy pack is imported, catalog packs' taxonomy links are rebuilt (C6).

A catalog pack maps a threat to CWE-2 while the imported CWE pack only has
CWE-1, so that link waits. Importing a CWE version that adds CWE-2 re-reads the
catalog pack's joins (downloading it again) and the link turns on.
"""

import tempfile
from pathlib import Path
from unittest import mock

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.packs.fake_catalog import CATALOG_URL, FakeCatalog
from apps.packs.services import import_pack_with_dependencies
from apps.threats.models import ThreatLibraryTaxonomyEntry


def cwe_pack(version: str, codes: list[str]) -> tuple[dict, dict]:
    return (
        {"slug": "cwe", "name": "CWE", "pack_type": "taxonomy", "version": version},
        {
            "taxonomy.yaml": {
                "taxonomies": [
                    {
                        "slug": "cwe",
                        "name": "CWE",
                        "entries": [
                            {"external_id": code, "title": code} for code in codes
                        ],
                    }
                ]
            }
        },
    )


def library_pack(version: str = "1.0.0") -> tuple[dict, dict]:
    return (
        {"slug": "lib", "name": "Library", "pack_type": "full", "version": version},
        {
            "components.yaml": {
                "components": [
                    {
                        "id": "svc",
                        "name": "Service",
                        "category": "process",
                        "type": "Service",
                    }
                ]
            },
            "threats.yaml": {
                "threats": [{"id": "t1", "name": "Threat one", "description": "x"}]
            },
            "joins/components-threats.yaml": {
                "mappings": [
                    {
                        "component": "svc",
                        "threats": [{"threat": "t1", "applies_to": "component"}],
                    }
                ]
            },
            "joins/threats-cwe.yaml": {
                "taxonomy": "cwe",
                "mappings": [{"threat": "t1", "entries": ["CWE-1", "CWE-2"]}],
            },
        },
    )


class CatalogTaxonomyReconcileTests(TestCase):
    def setUp(self):
        self.enterContext(override_settings(PACK_CATALOG_URL=CATALOG_URL))
        self.work_dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.work_dir / "libraries" / "packs").mkdir(parents=True)
        self.enterContext(
            override_settings(LIBRARIES_PATH=str(self.work_dir / "libraries"))
        )
        self.mock_get = self.enterContext(mock.patch("apps.packs.catalog.requests.get"))
        self.serve(cwe_pack("1.0.0", ["CWE-1"]), library_pack("1.0.0"))

        self.assertEqual(import_pack_with_dependencies("cwe").status, "imported")
        outcome = import_pack_with_dependencies("lib", accept_warnings=True)
        self.assertEqual(outcome.status, "imported", outcome.result)
        self.assertEqual(self.linked_codes(), {"CWE-1"})

    def serve(self, *packs, failing: tuple[str, ...] = ()):
        """Publish a new catalog with these packs (as a new release would)."""
        cache.clear()
        self.catalog = FakeCatalog(
            self.work_dir / f"catalog-{len(list(self.work_dir.iterdir()))}"
        )
        for pack_meta, files in packs:
            category = (
                "taxonomies"
                if pack_meta["pack_type"] == "taxonomy"
                else "threat-libraries"
            )
            self.catalog.add_pack(category, pack_meta, files)
        for slug in failing:
            self.catalog.fail_download_of(slug)
        self.mock_get.side_effect = self.catalog.fake_get

    def linked_codes(self) -> set[str]:
        return set(
            ThreatLibraryTaxonomyEntry.objects.filter(
                threat_library__slug="t1"
            ).values_list("taxonomy_entry__external_id", flat=True)
        )

    def test_a_taxonomy_update_activates_the_waiting_link(self):
        self.serve(cwe_pack("1.1.0", ["CWE-1", "CWE-2"]), library_pack("1.0.0"))

        outcome = import_pack_with_dependencies("cwe", force=True)

        self.assertEqual(outcome.status, "imported")
        self.assertEqual(self.linked_codes(), {"CWE-1", "CWE-2"})
        self.assertIn("threat-libraries__lib-1.0.0.tar.gz", self.catalog.downloads)

    def test_a_catalog_pack_at_another_version_is_skipped_and_logged(self):
        self.serve(cwe_pack("1.1.0", ["CWE-1", "CWE-2"]), library_pack("2.0.0"))

        with self.assertLogs("apps.packs.services", level="INFO") as logs:
            outcome = import_pack_with_dependencies("cwe", force=True)

        self.assertEqual(outcome.status, "imported")
        self.assertEqual(self.linked_codes(), {"CWE-1"})
        self.assertNotIn("threat-libraries__lib-2.0.0.tar.gz", self.catalog.downloads)
        self.assertTrue(
            any(
                "Not re-reading joins of lib: imported version 1.0.0, catalog version 2.0.0"
                in line
                for line in logs.output
            )
        )

    def test_a_download_failure_does_not_fail_the_taxonomy_import(self):
        self.serve(
            cwe_pack("1.1.0", ["CWE-1", "CWE-2"]),
            library_pack("1.0.0"),
            failing=("lib",),
        )

        with self.assertLogs("apps.packs.services", level="WARNING") as logs:
            outcome = import_pack_with_dependencies("cwe", force=True)

        self.assertEqual(outcome.status, "imported")
        self.assertEqual(self.linked_codes(), {"CWE-1"})
        self.assertTrue(
            any("Not re-reading joins of lib" in line for line in logs.output)
        )
