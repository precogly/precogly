"""The packs API: responses that the Libraries page relies on."""

import tempfile
from pathlib import Path
from unittest import mock

import requests
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from rest_framework.test import APITestCase

from apps.organizations.models import Organization, OrganizationMember
from apps.packs.fake_catalog import CATALOG_URL, FakeCatalog, write_pack_folder
from apps.packs.models import LibraryPack

User = get_user_model()


class PreviewOfAnImportedPackTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(username="u", email="u@org.test")
        OrganizationMember.objects.create(organization=organization, user=cls.user)
        cls.pack = LibraryPack.objects.create(
            slug="aws",
            name="AWS",
            pack_type=LibraryPack.PackType.FULL,
            version="4.0.0",
            author="Precogly",
        )

    def test_a_pack_whose_files_are_gone_is_a_404_with_a_message(self):
        # Imported before the packs moved to precogly/library-packs: the
        # database has it, this server's packs folder does not.
        self.client.force_authenticate(user=self.user)
        with tempfile.TemporaryDirectory() as empty_libraries:
            (Path(empty_libraries) / "packs").mkdir()
            with override_settings(LIBRARIES_PATH=empty_libraries):
                response = self.client.get(f"/api/packs/{self.pack.id}/preview/")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {"error": "Source files for pack 'aws' are not available on this server"},
        )


class CatalogPackViewsTests(APITestCase):
    """Preview, overlay list and validate download a catalog pack once each."""

    @classmethod
    def setUpTestData(cls):
        organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(username="lead", email="lead@org.test")
        OrganizationMember.objects.create(
            organization=organization,
            user=cls.user,
            role=OrganizationMember.Role.SECURITY_TEAM,
        )

    def setUp(self):
        self.enterContext(override_settings(PACK_CATALOG_URL=CATALOG_URL))
        cache.clear()
        work_dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        write_pack_folder(
            work_dir / "libraries" / "packs" / "demo-taxonomies" / "stride-taxonomy",
            {"slug": "stride-taxonomy", "name": "STRIDE", "pack_type": "taxonomy"},
            {
                "taxonomy.yaml": {
                    "taxonomies": [{"slug": "stride", "name": "STRIDE", "entries": []}]
                }
            },
        )
        self.enterContext(override_settings(LIBRARIES_PATH=str(work_dir / "libraries")))
        self.catalog = FakeCatalog(work_dir / "catalog-source")
        self.catalog.add_pack("taxonomies", {"slug": "cwe", "pack_type": "taxonomy"})
        self.catalog.add_pack(
            "threat-libraries",
            {
                "slug": "azure",
                "name": "Azure",
                "pack_type": "technology",
                "depends_on": ["taxonomies/stride-taxonomy", "taxonomies/cwe"],
            },
            {
                "components.yaml": {
                    "components": [
                        {
                            "id": "vm",
                            "name": "Virtual Machine",
                            "category": "process",
                            "type": "Compute",
                        }
                    ]
                },
                "joins/countermeasures-nist-csf.yaml": {
                    "framework": "nist-csf-2",
                    "mappings": [],
                },
            },
        )
        self.enterContext(
            mock.patch(
                "apps.packs.catalog.requests.get", side_effect=self.catalog.fake_get
            )
        )
        self.temporary_root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(
            mock.patch.object(tempfile, "tempdir", str(self.temporary_root))
        )
        self.client.force_authenticate(user=self.user)

    def assert_one_download_and_nothing_left(self):
        self.assertEqual(
            self.catalog.downloads, ["threat-libraries__azure-1.0.0.tar.gz"]
        )
        self.assertEqual(list(self.temporary_root.iterdir()), [])

    def test_preview_of_a_catalog_pack(self):
        response = self.client.get(
            "/api/packs/preview_from_source/", {"path": "threat-libraries/azure"}
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["pack"]["name"], "Azure")
        self.assertEqual(
            [component["name"] for component in response.json()["components"]],
            ["Virtual Machine"],
        )
        self.assert_one_download_and_nothing_left()

    def test_overlays_of_a_catalog_pack(self):
        response = self.client.get(
            "/api/packs/available_overlays/", {"path": "threat-libraries/azure"}
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            [overlay["frameworkId"] for overlay in response.json()["overlays"]],
            ["nist-csf-2"],
        )
        self.assert_one_download_and_nothing_left()

    def test_validate_lists_the_dependencies_not_imported_yet(self):
        response = self.client.post(
            "/api/packs/validate/", {"slug": "azure"}, format="json"
        )

        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertEqual(
            sorted(body["pendingDependencies"]), ["cwe", "stride-taxonomy"]
        )
        # STRIDE is on disk, so only the catalog dependency is "not found".
        dependency_warnings = [
            warning["message"]
            for warning in body["warnings"]
            if warning["field"] == "depends_on"
        ]
        self.assertEqual(
            dependency_warnings, ["Dependency 'cwe' not found on disk or in database"]
        )
        self.assert_one_download_and_nothing_left()

    def test_a_download_failure_is_a_502_with_the_message(self):
        self.catalog.fail_download_of("azure")

        responses = [
            self.client.get(
                "/api/packs/preview_from_source/", {"path": "threat-libraries/azure"}
            ),
            self.client.get(
                "/api/packs/available_overlays/", {"path": "threat-libraries/azure"}
            ),
            self.client.post("/api/packs/validate/", {"slug": "azure"}, format="json"),
        ]

        for response in responses:
            self.assertEqual(response.status_code, 502)
            self.assertEqual(
                response.json(),
                {
                    "error": "Pack 'azure' could not be downloaded from the pack library."
                },
            )
        self.assertEqual(list(self.temporary_root.iterdir()), [])

    def test_an_unknown_or_escaping_path_is_a_404(self):
        for unknown_path in (
            "threat-libraries/nothing",
            "../../etc",
            "demo-taxonomies/../../..",
        ):
            with self.subTest(unknown_path):
                response = self.client.get(
                    "/api/packs/preview_from_source/", {"path": unknown_path}
                )
                self.assertEqual(response.status_code, 404)
        self.assertEqual(self.catalog.downloads, [])


class PackListCatalogFlagsTests(APITestCase):
    """available_from_source says whether the catalog is on, reachable and which release."""

    @classmethod
    def setUpTestData(cls):
        organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(username="reader", email="reader@org.test")
        OrganizationMember.objects.create(organization=organization, user=cls.user)

    def setUp(self):
        cache.clear()
        work_dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        write_pack_folder(
            work_dir / "libraries" / "packs" / "demo-threat-libraries" / "demo-aws",
            {"slug": "demo-aws", "name": "Demo: AWS", "pack_type": "full"},
        )
        self.enterContext(override_settings(LIBRARIES_PATH=str(work_dir / "libraries")))
        self.catalog = FakeCatalog(work_dir / "catalog-source")
        self.catalog.add_pack(
            "threat-libraries", {"slug": "azure", "pack_type": "technology"}
        )
        self.mock_get = self.enterContext(mock.patch("apps.packs.catalog.requests.get"))
        self.client.force_authenticate(user=self.user)

    def list_packs(self) -> dict:
        response = self.client.get("/api/packs/available_from_source/")
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_catalog_off(self):
        self.enterContext(override_settings(PACK_CATALOG_URL=""))
        body = self.list_packs()
        self.assertEqual(
            (body["catalogEnabled"], body["catalogAvailable"], body["catalogRelease"]),
            (False, False, ""),
        )
        self.assertEqual([pack["slug"] for pack in body["packs"]], ["demo-aws"])
        self.mock_get.assert_not_called()

    def test_catalog_unreachable(self):
        self.enterContext(override_settings(PACK_CATALOG_URL=CATALOG_URL))
        self.mock_get.side_effect = requests.ConnectionError("refused")
        body = self.list_packs()
        self.assertEqual(
            (body["catalogEnabled"], body["catalogAvailable"], body["catalogRelease"]),
            (True, False, ""),
        )
        self.assertEqual([pack["slug"] for pack in body["packs"]], ["demo-aws"])

    def test_catalog_fine(self):
        self.enterContext(override_settings(PACK_CATALOG_URL=CATALOG_URL))
        self.mock_get.side_effect = self.catalog.fake_get
        body = self.list_packs()
        self.assertEqual(
            (body["catalogEnabled"], body["catalogAvailable"], body["catalogRelease"]),
            (True, True, "v-test"),
        )
        self.assertEqual(
            {pack["slug"]: pack["source"] for pack in body["packs"]},
            {"demo-aws": "bundled", "azure": "catalog"},
        )
        self.assertEqual(body["total"], 2)
        self.assertEqual(self.catalog.downloads, [], "listing downloads no pack")
