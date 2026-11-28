"""The pack catalog: loading catalog.json and downloading one pack safely.

No test touches the network: requests.get is replaced with a fake response,
and every archive is built inside the test.
"""

import hashlib
import io
import json
import tarfile
import tempfile
from pathlib import Path
from unittest import mock

import requests
from django.core.cache import cache
from django.test import SimpleTestCase, override_settings

from apps.packs import catalog
from apps.packs.catalog import (
    CatalogEntry,
    CatalogPackError,
    archive_url,
    configured_catalog_url,
    downloaded_pack,
    load_catalog,
)
from apps.packs.fake_catalog import FakeResponse

CATALOG_URL = "https://packs.example.test/releases/download/v1/catalog.json"
LATEST_URL = (
    "https://github.com/precogly/library-packs/releases/latest/download/catalog.json"
)
PACK_YAML = b"pack:\n  slug: azure\n  version: 2.0.0\n  name: Azure\n"


def catalog_document(packs: list[dict], **overrides) -> bytes:
    document = {"catalogVersion": 1, "release": "v2026.11.26.1", "packs": packs}
    document.update(overrides)
    return json.dumps(document).encode()


def raw_entry(slug: str = "azure", **overrides) -> dict:
    entry = {
        "slug": slug,
        "path": f"threat-libraries/{slug}",
        "name": slug.title(),
        "description": "A pack",
        "version": "2.0.0",
        "packType": "technology",
        "schemaVersion": 1,
        "author": "Precogly",
        "tags": ["cloud"],
        "componentCount": 3,
        "threatCount": 0,
        "countermeasureCount": 0,
        "taxonomyCount": 0,
        "dependsOn": ["taxonomies/stride-taxonomy"],
        "archive": f"threat-libraries__{slug}-2.0.0.tar.gz",
        "archiveSize": 100,
        "sha256": "a" * 64,
    }
    entry.update(overrides)
    return entry


def build_archive(members: list[tuple[tarfile.TarInfo, bytes | None]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for member_info, content in members:
            if content is not None:
                member_info.size = len(content)
                archive.addfile(member_info, io.BytesIO(content))
            else:
                archive.addfile(member_info)
    return buffer.getvalue()


def file_member(name: str, content: bytes) -> tuple[tarfile.TarInfo, bytes]:
    return tarfile.TarInfo(name), content


def directory_member(name: str) -> tuple[tarfile.TarInfo, None]:
    member_info = tarfile.TarInfo(name)
    member_info.type = tarfile.DIRTYPE
    return member_info, None


def good_archive(extra_members=(), pack_yaml: bytes = PACK_YAML) -> bytes:
    return build_archive(
        [
            directory_member("azure"),
            file_member("azure/pack.yaml", pack_yaml),
            file_member("azure/icons/vm.svg", b"<svg/>"),
            *extra_members,
        ]
    )


def entry_for(archive_bytes: bytes, **overrides) -> CatalogEntry:
    values = {
        "slug": "azure",
        "path": "threat-libraries/azure",
        "name": "Azure",
        "description": "",
        "version": "2.0.0",
        "pack_type": "technology",
        "schema_version": 1,
        "author": "",
        "tags": [],
        "component_count": 0,
        "threat_count": 0,
        "countermeasure_count": 0,
        "taxonomy_count": 0,
        "depends_on": [],
        "archive": "threat-libraries__azure-2.0.0.tar.gz",
        "archive_size": len(archive_bytes),
        "sha256": hashlib.sha256(archive_bytes).hexdigest(),
        "release": "v1",
    }
    values.update(overrides)
    return CatalogEntry(**values)


class LoadCatalogTests(SimpleTestCase):
    def setUp(self):
        self.enterContext(override_settings(PACK_CATALOG_URL=CATALOG_URL))
        cache.clear()

    @mock.patch("apps.packs.catalog.requests.get")
    def test_a_good_catalog_loads_once(self, mock_get):
        mock_get.return_value = FakeResponse(catalog_document([raw_entry()]))

        first = load_catalog()
        second = load_catalog()

        self.assertTrue(first.available)
        self.assertTrue(first.enabled)
        self.assertEqual(first.release, "v2026.11.26.1")
        self.assertEqual([entry.slug for entry in first.entries], ["azure"])
        entry = first.entries[0]
        self.assertEqual(entry.depends_on, ["taxonomies/stride-taxonomy"])
        self.assertEqual(entry.release, "v2026.11.26.1")
        self.assertEqual(entry.component_count, 3)
        self.assertEqual(second, first)
        self.assertEqual(mock_get.call_count, 1)
        self.assertEqual(mock_get.call_args.kwargs["timeout"], 5)
        self.assertTrue(mock_get.call_args.kwargs["stream"])

    @mock.patch("apps.packs.catalog.requests.get")
    def test_failures_give_unavailable_and_are_remembered(self, mock_get):
        failures = {
            "unreachable": requests.ConnectionError("refused"),
            "timeout": requests.Timeout("slow"),
            "http error": FakeResponse(b"", status_code=404),
            "bad json": FakeResponse(b"{not json"),
            "unknown catalogVersion": FakeResponse(
                catalog_document([], catalogVersion=2)
            ),
            "bad release name": FakeResponse(catalog_document([], release="../x")),
            "too large": FakeResponse(
                b"x", headers={"Content-Length": str(3 * 1024 * 1024)}
            ),
        }
        for failure_name, outcome in failures.items():
            with self.subTest(failure_name):
                cache.clear()
                mock_get.reset_mock()
                if isinstance(outcome, Exception):
                    mock_get.side_effect = outcome
                else:
                    mock_get.side_effect = None
                    mock_get.return_value = outcome

                first = load_catalog()
                second = load_catalog()

                self.assertFalse(first.available)
                self.assertTrue(first.enabled)
                self.assertEqual(first.entries, [])
                self.assertFalse(second.available)
                self.assertEqual(
                    mock_get.call_count, 1, "the failure should be remembered"
                )

    @mock.patch("apps.packs.catalog.requests.get")
    def test_bad_entries_are_dropped_and_the_rest_kept(self, mock_get):
        bad_entries = [
            raw_entry("Bad_Slug"),
            raw_entry("demo-aws"),
            raw_entry("p1", path="../p1"),
            raw_entry("p2", path="threat-libraries/other"),
            raw_entry("p3", path="a/b/p3"),
            raw_entry("p4", archive="../../other/file.tar.gz"),
            raw_entry("p5", archive="p5.zip"),
            raw_entry("p6", sha256="A" * 64),
            raw_entry("p7", sha256="abc"),
            raw_entry("p8", archiveSize=0),
            raw_entry("p9", archiveSize=21 * 1024 * 1024),
            raw_entry("p10", archiveSize="100"),
            "not an object",
            raw_entry("azure", name="Second Azure"),
        ]
        mock_get.return_value = FakeResponse(
            catalog_document([raw_entry("azure"), *bad_entries, raw_entry("gcp")])
        )

        result = load_catalog()

        self.assertTrue(result.available)
        self.assertEqual([entry.slug for entry in result.entries], ["azure", "gcp"])
        self.assertEqual(
            result.entries[0].name,
            "Azure",
            "the first of two same-slug entries is kept",
        )

    @mock.patch("apps.packs.catalog.requests.get")
    def test_the_added_counts_are_read_and_default_to_zero(self, mock_get):
        mock_get.return_value = FakeResponse(
            catalog_document(
                [
                    raw_entry(
                        "cra",
                        frameworkCount=1,
                        requirementCount=28,
                        taxonomyEntryCount=0,
                        templateCount=0,
                    ),
                    raw_entry("older"),
                ]
            )
        )

        cra, older = load_catalog().entries

        self.assertEqual((cra.framework_count, cra.requirement_count), (1, 28))
        self.assertEqual(
            (
                older.framework_count,
                older.requirement_count,
                older.taxonomy_entry_count,
                older.template_count,
            ),
            (0, 0, 0, 0),
        )

    def test_an_address_that_is_not_http_turns_the_catalog_off(self):
        for address in ("file:///etc/passwd", "ftp://host/catalog.json", "", "   "):
            with self.subTest(address):
                self.assertEqual(configured_catalog_url(address), "")
                with override_settings(PACK_CATALOG_URL=address):
                    result = load_catalog()
                self.assertFalse(result.enabled)
                self.assertFalse(result.available)

    def test_the_source_name_and_links(self):
        cases = {
            LATEST_URL: (
                "precogly/library-packs",
                "https://github.com/precogly/library-packs/releases/tag/v2026.11.26.2",
                "https://github.com/precogly/library-packs/tree/v2026.11.26.2/packs/",
            ),
            "https://github.com/precogly/library-packs/releases/download/v1/catalog.json": (
                "precogly/library-packs",
                "https://github.com/precogly/library-packs/releases/tag/v2026.11.26.2",
                "https://github.com/precogly/library-packs/tree/v2026.11.26.2/packs/",
            ),
            "http://packs.example.internal/library/catalog.json": (
                "packs.example.internal",
                "",
                "",
            ),
        }
        for address, expected in cases.items():
            with self.subTest(address):
                source = catalog.catalog_source(address, "v2026.11.26.2")
                self.assertEqual(
                    (source.name, source.release_url, source.packs_url), expected
                )
        self.assertIsNone(catalog.catalog_source("", "v1"))

    def test_archive_urls(self):
        entry = entry_for(b"x", release="v2026.11.26.1")
        self.assertEqual(
            archive_url(entry, LATEST_URL),
            "https://github.com/precogly/library-packs/releases/download/v2026.11.26.1/"
            "threat-libraries__azure-2.0.0.tar.gz",
        )
        self.assertEqual(
            archive_url(entry, "http://intranet.test/packs/catalog.json?token=1"),
            "http://intranet.test/packs/threat-libraries__azure-2.0.0.tar.gz",
        )


class DownloadedPackTests(SimpleTestCase):
    def setUp(self):
        self.enterContext(override_settings(PACK_CATALOG_URL=CATALOG_URL))
        self.temporary_root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(
            mock.patch.object(tempfile, "tempdir", str(self.temporary_root))
        )
        self.mock_get = self.enterContext(mock.patch("apps.packs.catalog.requests.get"))

    def assert_nothing_left_behind(self):
        self.assertEqual(list(self.temporary_root.iterdir()), [])

    def serve(self, archive_bytes: bytes, headers: dict | None = None):
        self.mock_get.return_value = FakeResponse(archive_bytes, headers=headers)

    def test_the_happy_path_yields_the_pack_folder_and_removes_it(self):
        archive_bytes = good_archive()
        self.serve(archive_bytes)

        with downloaded_pack(entry_for(archive_bytes)) as pack_dir:
            self.assertEqual(pack_dir.name, "azure")
            self.assertTrue((pack_dir / "pack.yaml").is_file())
            self.assertTrue((pack_dir / "icons" / "vm.svg").is_file())
            self.assertTrue(str(pack_dir).startswith(str(self.temporary_root)))

        self.assertEqual(
            self.mock_get.call_args.args[0],
            "https://packs.example.test/releases/download/v1/threat-libraries__azure-2.0.0.tar.gz",
        )
        self.assert_nothing_left_behind()

    def assert_refused(
        self, archive_bytes: bytes, entry: CatalogEntry | None = None, headers=None
    ):
        self.serve(archive_bytes, headers)
        with (
            self.assertRaises(CatalogPackError) as raised,
            downloaded_pack(entry or entry_for(archive_bytes)),
        ):
            self.fail("the pack should have been refused")
        message = str(raised.exception)
        self.assertNotIn(str(self.temporary_root), message)
        self.assertNotIn("precogly-pack-", message)
        self.assert_nothing_left_behind()
        return message

    def test_a_hash_mismatch_is_refused(self):
        archive_bytes = good_archive()
        message = self.assert_refused(
            archive_bytes, entry_for(archive_bytes, sha256="0" * 64)
        )
        self.assertIn("checksum", message)

    def test_a_size_mismatch_is_refused(self):
        archive_bytes = good_archive()
        self.assert_refused(
            archive_bytes, entry_for(archive_bytes, archive_size=len(archive_bytes) + 1)
        )

    @override_settings(PACK_DOWNLOAD_MAX_BYTES=1000)
    def test_a_size_over_the_limit_by_header_is_refused(self):
        archive_bytes = good_archive()
        message = self.assert_refused(archive_bytes, headers={"Content-Length": "5000"})
        self.assertIn("download limit", message)

    @override_settings(PACK_DOWNLOAD_MAX_BYTES=100)
    def test_a_size_over_the_limit_while_reading_is_refused(self):
        archive_bytes = good_archive() + b"\0" * 200
        message = self.assert_refused(archive_bytes)
        self.assertIn("download limit", message)

    def test_a_dot_dot_path_is_refused(self):
        self.assert_refused(
            good_archive([file_member("azure/../../escape.yaml", b"x: 1")])
        )

    def test_an_absolute_path_is_refused(self):
        self.assert_refused(good_archive([file_member("/etc/escape.yaml", b"x: 1")]))

    def test_a_symlink_is_refused(self):
        link_info = tarfile.TarInfo("azure/link.yaml")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "/etc/passwd"
        self.assert_refused(good_archive([(link_info, None)]))

    def test_a_hard_link_is_refused(self):
        link_info = tarfile.TarInfo("azure/hard.yaml")
        link_info.type = tarfile.LNKTYPE
        link_info.linkname = "azure/pack.yaml"
        self.assert_refused(good_archive([(link_info, None)]))

    def test_a_python_file_is_refused(self):
        self.assert_refused(good_archive([file_member("azure/run.py", b"print('x')")]))

    def test_a_first_segment_that_is_not_the_slug_is_refused(self):
        self.assert_refused(good_archive([file_member("other/pack.yaml", b"x: 1")]))

    def test_an_unpacked_size_over_the_limit_is_refused(self):
        with mock.patch.object(catalog, "UNPACKED_MAX_BYTES", 50):
            message = self.assert_refused(
                good_archive([file_member("azure/big.yaml", b"a: " + b"x" * 100)])
            )
        self.assertIn("too large", message)

    def test_too_many_members_are_refused(self):
        with mock.patch.object(catalog, "UNPACKED_MAX_MEMBERS", 2):
            message = self.assert_refused(good_archive())
        self.assertIn("too many files", message)

    def test_a_pack_yaml_slug_that_differs_from_the_entry_is_refused(self):
        self.assert_refused(
            good_archive(pack_yaml=b"pack:\n  slug: other\n  version: 2.0.0\n")
        )

    def test_a_pack_yaml_version_that_differs_from_the_entry_is_refused(self):
        self.assert_refused(
            good_archive(pack_yaml=b"pack:\n  slug: azure\n  version: 9.9.9\n")
        )

    def test_a_download_failure_is_a_safe_error(self):
        self.mock_get.side_effect = requests.ConnectionError("refused by 10.0.0.1")
        with (
            self.assertRaises(CatalogPackError) as raised,
            downloaded_pack(entry_for(b"x")),
        ):
            self.fail("the download should have failed")
        self.assertNotIn("10.0.0.1", str(raised.exception))
        self.assert_nothing_left_behind()

    @override_settings(PACK_CATALOG_URL="")
    def test_a_catalog_that_is_off_downloads_nothing(self):
        with self.assertRaises(CatalogPackError), downloaded_pack(entry_for(b"x")):
            self.fail("nothing should be downloaded")
        self.mock_get.assert_not_called()
