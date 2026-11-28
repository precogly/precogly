"""Importing a pack imports its missing dependencies first (catalog plan C5).

Packs are served by a fake catalog (apps/packs/fake_catalog.py) next to a
bundled STRIDE on disk. Nothing reaches the network.
"""

import tempfile
from pathlib import Path
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.organizations.models import Organization, OrganizationMember
from apps.packs.fake_catalog import CATALOG_URL, FakeCatalog, write_pack_folder
from apps.packs.models import LibraryPack
from apps.packs.services import import_pack_with_dependencies
from apps.threat_models.models import ThreatModel, ThreatModelLibraryPack

User = get_user_model()

ONE_COMPONENT = {
    "components.yaml": {
        "components": [
            {"id": "thing", "name": "Thing", "category": "process", "type": "Service"}
        ]
    }
}


def broken_files() -> dict:
    """A join naming a component the pack does not have: a validation error."""
    return {
        **ONE_COMPONENT,
        "threats.yaml": {
            "threats": [{"id": "threat-one", "name": "Threat one", "description": "x"}]
        },
        "joins/components-threats.yaml": {
            "mappings": [
                {
                    "component": "no-such-component",
                    "threats": [{"threat": "threat-one", "applies_to": "component"}],
                }
            ]
        },
    }


class ImportWithDependenciesTests(TestCase):
    def setUp(self):
        self.enterContext(override_settings(PACK_CATALOG_URL=CATALOG_URL))
        cache.clear()
        work_dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.libraries_dir = work_dir / "libraries"
        write_pack_folder(
            self.libraries_dir / "packs" / "demo-taxonomies" / "stride-taxonomy",
            {
                "slug": "stride-taxonomy",
                "name": "STRIDE",
                "version": "1.0.0",
                "pack_type": "taxonomy",
            },
            {
                "taxonomy.yaml": {
                    "taxonomies": [{"slug": "stride", "name": "STRIDE", "entries": []}]
                }
            },
        )
        self.enterContext(override_settings(LIBRARIES_PATH=str(self.libraries_dir)))
        self.catalog = FakeCatalog(work_dir / "catalog-source")
        self.enterContext(
            mock.patch(
                "apps.packs.catalog.requests.get", side_effect=self.catalog.fake_get
            )
        )
        self.temporary_root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(
            mock.patch.object(tempfile, "tempdir", str(self.temporary_root))
        )

        organization = Organization.objects.create(name="Org", domain="org.test")
        self.user = User.objects.create_user(username="lead", email="lead@org.test")
        OrganizationMember.objects.create(
            organization=organization,
            user=self.user,
            role=OrganizationMember.Role.SECURITY_TEAM,
        )
        self.threat_model = ThreatModel.objects.create(
            name="TM", organization=organization
        )

    def add(self, slug, depends_on=(), files=None, **pack_meta):
        self.catalog.add_pack(
            "threat-libraries",
            {
                "slug": slug,
                "pack_type": "technology",
                "depends_on": list(depends_on),
                **pack_meta,
            },
            files if files is not None else ONE_COMPONENT,
        )

    def imported_slugs(self) -> set[str]:
        return set(LibraryPack.objects.values_list("slug", flat=True))

    def assert_no_download_left(self):
        self.assertEqual(list(self.temporary_root.iterdir()), [])

    def test_two_missing_dependencies_are_imported_in_order(self):
        self.add("base")
        self.add("middle", depends_on=["threat-libraries/base"])
        self.add("top", depends_on=["threat-libraries/middle", "base"])

        outcome = import_pack_with_dependencies("top")

        self.assertEqual(outcome.status, "imported", outcome.message)
        self.assertEqual(outcome.dependencies_imported, ["base", "middle"])
        self.assertEqual(self.imported_slugs(), {"base", "middle", "top"})
        connected = set(
            ThreatModelLibraryPack.objects.filter(
                threat_model=self.threat_model
            ).values_list("library_pack__slug", flat=True)
        )
        self.assertEqual(connected, {"base", "middle", "top"})
        self.assert_no_download_left()

    def test_a_dependency_already_imported_is_not_imported_again(self):
        self.add("base")
        self.add("top", depends_on=["base"])
        self.assertEqual(import_pack_with_dependencies("base").status, "imported")
        downloads_before = len(self.catalog.downloads)

        outcome = import_pack_with_dependencies("top")

        self.assertEqual(outcome.status, "imported")
        self.assertEqual(outcome.dependencies_imported, [])
        self.assertEqual(
            self.catalog.downloads[downloads_before:],
            ["threat-libraries__top-1.0.0.tar.gz"],
        )

    def test_a_dependency_with_an_error_stops_the_import(self):
        self.add("good")
        self.add("broken", files=broken_files())
        self.add("top", depends_on=["good", "broken"])

        outcome = import_pack_with_dependencies("top")

        self.assertEqual(outcome.status, "dependency_failed")
        self.assertEqual(outcome.failed_dependency, "broken")
        self.assertEqual(outcome.dependencies_imported, ["good"])
        self.assertEqual(outcome.not_imported, ["top"])
        self.assertTrue(outcome.result.errors)
        self.assertEqual(self.imported_slugs(), {"good"})
        self.assert_no_download_left()

    def test_a_dependency_with_only_a_warning_stops_it_even_with_import_anyway(self):
        self.add("odd", pack_type="not-a-real-type")
        self.add("top", depends_on=["odd"])

        outcome = import_pack_with_dependencies("top", accept_warnings=True)

        self.assertEqual(outcome.status, "dependency_failed")
        self.assertEqual(outcome.failed_dependency, "odd")
        self.assertFalse(outcome.result.errors)
        self.assertTrue(outcome.result.warnings)
        self.assertEqual(self.imported_slugs(), set())

    def test_a_cycle_is_reported(self):
        self.add("one", depends_on=["two"])
        self.add("two", depends_on=["one"])

        outcome = import_pack_with_dependencies("one")

        self.assertEqual(outcome.status, "cycle")
        self.assertIn("one -> two -> one", outcome.message)
        self.assertEqual(self.imported_slugs(), set())

    def test_a_catalog_pack_on_the_bundled_stride(self):
        self.add("azure", depends_on=["taxonomies/stride-taxonomy"])

        outcome = import_pack_with_dependencies("azure")

        self.assertEqual(outcome.status, "imported", outcome.message)
        self.assertEqual(outcome.dependencies_imported, ["stride-taxonomy"])
        self.assertEqual(
            self.catalog.downloads, ["threat-libraries__azure-1.0.0.tar.gz"]
        )
        self.assertEqual(self.imported_slugs(), {"stride-taxonomy", "azure"})

    def test_a_download_failure_on_a_dependency_stops_the_import(self):
        self.add("base")
        self.add("top", depends_on=["base"])
        self.catalog.fail_download_of("base")

        outcome = import_pack_with_dependencies("top")

        self.assertEqual(outcome.status, "download_failed")
        self.assertEqual(outcome.failed_dependency, "base")
        self.assertIn("could not be downloaded", outcome.message)
        self.assertEqual(self.imported_slugs(), set())
        self.assert_no_download_left()

    def _chain_of_three(self):
        self.add("first")
        self.add("second", depends_on=["first"])
        self.add("third", depends_on=["second"])
        self.add("top", depends_on=["third"])

    def test_a_failure_in_the_middle_of_a_chain_says_what_was_and_was_not_imported(
        self,
    ):
        self.add("first")
        self.add("second", depends_on=["first"], files=broken_files())
        self.add("third", depends_on=["second"])
        self.add("top", depends_on=["third"])

        api_client = APIClient()
        api_client.force_authenticate(user=self.user)
        response = api_client.post(
            "/api/packs/import_single/",
            {"slug": "top"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        body = response.json()
        self.assertEqual(body["failedDependency"], "second")
        self.assertEqual(body["dependenciesImported"], ["first"])
        self.assertEqual(body["notImported"], ["third", "top"])
        self.assertTrue(body["validation"]["errors"])

    def test_the_same_lists_on_a_download_failure_in_the_middle(self):
        self._chain_of_three()
        self.catalog.fail_download_of("second")

        api_client = APIClient()
        api_client.force_authenticate(user=self.user)
        response = api_client.post(
            "/api/packs/import_single/",
            {"slug": "top"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 502)
        body = response.json()
        self.assertEqual(body["failedDependency"], "second")
        self.assertEqual(body["dependenciesImported"], ["first"])
        self.assertEqual(body["notImported"], ["third", "top"])
        self.assertIn("could not be downloaded", body["error"])

    def test_a_successful_import_lists_its_dependencies(self):
        self._chain_of_three()

        api_client = APIClient()
        api_client.force_authenticate(user=self.user)
        response = api_client.post(
            "/api/packs/import_single/",
            {"slug": "top"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(
            response.json()["dependenciesImported"], ["first", "second", "third"]
        )
