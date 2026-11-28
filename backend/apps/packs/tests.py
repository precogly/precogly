"""Tests for path-based pack discovery, O(1) lookup (issue #33),
taxonomy reference validation (issue #26), and pack validation gaps (issue #10)."""

import tempfile
from pathlib import Path
from unittest import mock

import yaml
from django.test import SimpleTestCase, override_settings

from apps.packs.catalog import CatalogEntry, CatalogResult
from apps.packs.services import (
    ImportResult,
    _dependency_slug,
    _find_pack_dir,
    _find_pack_dir_by_slug,
    _is_valid_slug,
    discover_available_packs,
    discover_packs_from_source,
    get_libraries_path,
    validate_pack,
)


def _empty_pack_queryset():
    """Stand-in for LibraryPack.objects.all() that yields nothing.

    discover_packs_from_source() reads installed packs from the DB to
    flag is_in_database; tests covering on-disk discovery don't care
    about that signal, so we mock the queryset instead of spinning up a
    real database.
    """
    return iter([])


def _write_pack(base_dir: Path, relative_path: str, slug: str, **overrides) -> Path:
    """Create a minimal pack on disk under base_dir/relative_path."""
    pack_dir = base_dir / relative_path
    pack_dir.mkdir(parents=True, exist_ok=True)

    pack_meta = {
        "slug": slug,
        "name": slug,
        "version": "1.0.0",
        "pack_type": "technology",
        "author": "Test",
    }
    pack_meta.update(overrides)

    pack_yaml = pack_dir / "pack.yaml"
    pack_yaml.write_text(yaml.safe_dump({"pack": pack_meta}))
    return pack_dir


class FindPackDirTests(SimpleTestCase):
    """_find_pack_dir is O(1): it only checks the path it was given."""

    def test_resolves_top_level_pack(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _write_pack(base, "aws", slug="aws")

            result = _find_pack_dir(base, "aws")

            self.assertEqual(result, base / "aws")

    def test_resolves_nested_pack(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _write_pack(base, "frameworks/nist-csf", slug="nist-csf")

            result = _find_pack_dir(base, "frameworks/nist-csf")

            self.assertEqual(result, base / "frameworks" / "nist-csf")

    def test_returns_none_for_missing_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)

            self.assertIsNone(_find_pack_dir(base, "does-not-exist"))

    def test_returns_none_when_pack_yaml_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "empty-dir").mkdir()

            self.assertIsNone(_find_pack_dir(base, "empty-dir"))

    def test_does_not_recursively_scan(self):
        # If two packs share a slug under different paths, _find_pack_dir
        # must return the directory at the requested path, not any
        # other matching slug elsewhere in the tree.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _write_pack(base, "frameworks/nist-csf", slug="nist-csf")
            _write_pack(base, "demo/nist-csf", slug="nist-csf")

            framework_dir = _find_pack_dir(base, "frameworks/nist-csf")
            demo_dir = _find_pack_dir(base, "demo/nist-csf")

            self.assertEqual(framework_dir, base / "frameworks" / "nist-csf")
            self.assertEqual(demo_dir, base / "demo" / "nist-csf")
            self.assertNotEqual(framework_dir, demo_dir)


class DiscoveryAndDisambiguationTests(SimpleTestCase):
    """discover_packs_from_source computes relative_path from the filesystem."""

    def _patch_db_and_path(self, base):
        return mock.patch.multiple(
            "apps.packs.services",
            get_libraries_path=mock.MagicMock(return_value=base),
            LibraryPack=mock.MagicMock(
                objects=mock.MagicMock(
                    all=mock.MagicMock(return_value=_empty_pack_queryset()),
                )
            ),
        )

    def test_duplicate_slugs_under_different_paths_are_both_discovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with self._patch_db_and_path(base):
                _write_pack(base, "frameworks/nist-csf", slug="nist-csf")
                _write_pack(base, "demo/nist-csf", slug="nist-csf")

                packs = discover_packs_from_source()
                nist_packs = [p for p in packs if p.slug == "nist-csf"]

                self.assertEqual(len(nist_packs), 2)
                paths = {p.relative_path for p in nist_packs}
                self.assertEqual(
                    paths,
                    {"frameworks/nist-csf", "demo/nist-csf"},
                )

    def test_relative_path_computed_from_filesystem(self):
        # relative_path should match the actual directory location,
        # regardless of what's in pack.yaml.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with self._patch_db_and_path(base):
                _write_pack(base, "frameworks/owasp", slug="owasp")

                packs = discover_packs_from_source()
                owasp = next(p for p in packs if p.slug == "owasp")

                self.assertEqual(owasp.relative_path, "frameworks/owasp")

    def test_depends_on_path_key_is_ignored(self):
        # A dependency is a slug. A `path` key no longer picks a folder: the
        # result reports where the pack with that slug actually is.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with self._patch_db_and_path(base):
                _write_pack(base, "demo/nist-csf", slug="nist-csf")
                _write_pack(
                    base,
                    "consumer",
                    slug="consumer",
                    depends_on=[
                        {
                            "pack": "nist-csf",
                            "path": "frameworks/nist-csf",
                        }
                    ],
                )

                packs = discover_packs_from_source()
                consumer = next(p for p in packs if p.slug == "consumer")

                self.assertEqual(len(consumer.depends_on), 1)
                dep = consumer.depends_on[0]
                self.assertEqual(dep["slug"], "nist-csf")
                self.assertEqual(dep["path"], "demo/nist-csf")

    def test_path_format_dependency_finds_the_pack_in_another_folder(self):
        # The full aws pack says taxonomies/stride-taxonomy; the app bundles
        # STRIDE at demo-taxonomies/stride-taxonomy.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with self._patch_db_and_path(base):
                _write_pack(
                    base,
                    "demo-taxonomies/stride-taxonomy",
                    slug="stride-taxonomy",
                    name="STRIDE Taxonomy",
                )
                _write_pack(
                    base,
                    "threat-libraries/aws",
                    slug="aws",
                    depends_on=["taxonomies/stride-taxonomy"],
                )

                packs = discover_packs_from_source()
                aws = next(p for p in packs if p.slug == "aws")

                self.assertEqual(
                    aws.depends_on,
                    [
                        {
                            "slug": "stride-taxonomy",
                            "path": "demo-taxonomies/stride-taxonomy",
                            "name": "STRIDE Taxonomy",
                            "is_imported": False,
                        }
                    ],
                )

    def test_missing_dependency_has_an_empty_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with self._patch_db_and_path(base):
                _write_pack(
                    base, "consumer", slug="consumer", depends_on=["taxonomies/cwe"]
                )

                consumer = discover_packs_from_source()[0]

                self.assertEqual(
                    consumer.depends_on,
                    [{"slug": "cwe", "path": "", "name": "cwe", "is_imported": False}],
                )

    def test_path_format_string_depends_on_resolves(self):
        # depends_on with path-format strings like "taxonomies/stride-taxonomy"
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with self._patch_db_and_path(base):
                _write_pack(base, "taxonomies/stride-taxonomy", slug="stride-taxonomy")
                _write_pack(
                    base,
                    "consumer",
                    slug="consumer",
                    depends_on=["taxonomies/stride-taxonomy"],
                )

                packs = discover_packs_from_source()
                consumer = next(p for p in packs if p.slug == "consumer")

                self.assertEqual(len(consumer.depends_on), 1)
                dep = consumer.depends_on[0]
                self.assertEqual(dep["slug"], "stride-taxonomy")
                self.assertEqual(dep["path"], "taxonomies/stride-taxonomy")


def _catalog_entry(slug: str, version: str = "2.0.0", **overrides) -> CatalogEntry:
    values = {
        "slug": slug,
        "path": f"threat-libraries/{slug}",
        "name": slug.upper(),
        "description": "",
        "version": version,
        "pack_type": "full",
        "schema_version": 1,
        "author": "",
        "tags": [],
        "component_count": 1,
        "threat_count": 2,
        "countermeasure_count": 3,
        "taxonomy_count": 0,
        "depends_on": [],
        "archive": f"threat-libraries__{slug}-{version}.tar.gz",
        "archive_size": 10,
        "sha256": "a" * 64,
        "release": "v1",
    }
    values.update(overrides)
    return CatalogEntry(**values)


def _installed(*slug_versions):
    """Stand-in LibraryPack rows with slug and version."""
    return iter(
        [mock.Mock(slug=slug, version=version) for slug, version in slug_versions]
    )


class MergedDiscoveryTests(SimpleTestCase):
    """discover_available_packs lists bundled packs and catalog packs together."""

    def _discover(self, base, catalog_entries, installed=(), available=True):
        catalog_result = CatalogResult(
            entries=list(catalog_entries),
            release="v1" if available else "",
            available=available,
            enabled=True,
        )
        with (
            mock.patch("apps.packs.services.get_libraries_path", return_value=base),
            mock.patch("apps.packs.services.load_catalog", return_value=catalog_result),
            mock.patch("apps.packs.services.LibraryPack") as library_pack_model,
        ):
            library_pack_model.objects.all.return_value = _installed(*installed)
            return discover_available_packs()

    def test_bundled_and_catalog_packs_are_both_listed_with_their_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _write_pack(base, "demo-taxonomies/stride-taxonomy", slug="stride-taxonomy")

            packs, catalog_result = self._discover(base, [_catalog_entry("azure")])

            sources = {pack.slug: (pack.source, pack.relative_path) for pack in packs}
            self.assertEqual(
                sources,
                {
                    "stride-taxonomy": ("bundled", "demo-taxonomies/stride-taxonomy"),
                    "azure": ("catalog", "threat-libraries/azure"),
                },
            )
            azure = next(pack for pack in packs if pack.slug == "azure")
            self.assertEqual(azure.path, "")
            self.assertEqual(
                (azure.component_count, azure.threat_count, azure.countermeasure_count),
                (1, 2, 3),
            )
            self.assertTrue(catalog_result.available)

    def test_a_slug_in_both_places_is_the_bundled_pack_whatever_the_versions(self):
        for catalog_version in ("0.1.0", "1.0.0", "9.0.0"):
            with (
                self.subTest(catalog_version=catalog_version),
                tempfile.TemporaryDirectory() as tmp,
            ):
                base = Path(tmp)
                _write_pack(
                    base, "demo-taxonomies/stride-taxonomy", slug="stride-taxonomy"
                )
                catalog_stride = _catalog_entry(
                    "stride-taxonomy",
                    version=catalog_version,
                    path="taxonomies/stride-taxonomy",
                )

                packs, _ = self._discover(base, [catalog_stride])

                self.assertEqual(len(packs), 1)
                self.assertEqual(packs[0].source, "bundled")
                self.assertEqual(packs[0].version, "1.0.0")

    def test_a_catalog_dependency_resolves_to_the_bundled_stride(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _write_pack(
                base,
                "demo-taxonomies/stride-taxonomy",
                slug="stride-taxonomy",
                name="STRIDE Taxonomy",
            )
            azure = _catalog_entry("azure", depends_on=["taxonomies/stride-taxonomy"])

            packs, _ = self._discover(
                base, [azure], installed=[("stride-taxonomy", "1.0.0")]
            )

            azure_info = next(pack for pack in packs if pack.slug == "azure")
            self.assertEqual(
                azure_info.depends_on,
                [
                    {
                        "slug": "stride-taxonomy",
                        "path": "demo-taxonomies/stride-taxonomy",
                        "name": "STRIDE Taxonomy",
                        "is_imported": True,
                    }
                ],
            )

    def test_a_catalog_pack_in_the_database_carries_its_installed_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            packs, _ = self._discover(
                Path(tmp),
                [_catalog_entry("aws", version="4.1.0")],
                installed=[("aws", "4.0.0")],
            )

            aws = packs[0]
            self.assertTrue(aws.is_in_database)
            self.assertEqual(aws.database_version, "4.0.0")
            self.assertTrue(aws.to_dict()["needs_update"])
            self.assertEqual(aws.to_dict()["source"], "catalog")

    def test_bundled_packs_carry_the_same_counts_as_the_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            standard_dir = base / "demo-standards" / "demo-asvs"
            standard_dir.mkdir(parents=True)
            (standard_dir / "pack.yaml").write_text(
                yaml.safe_dump(
                    {
                        "pack": {
                            "slug": "demo-asvs",
                            "name": "ASVS",
                            "version": "1.0.0",
                        },
                        "frameworks": [
                            {
                                "slug": "a",
                                "requirements": [
                                    {"section_code": "1"},
                                    {"section_code": "2"},
                                ],
                            },
                            {"slug": "b", "requirements": [{"section_code": "3"}]},
                        ],
                    }
                )
            )
            taxonomy_dir = _write_pack(
                base, "demo-taxonomies/stride-taxonomy", slug="stride-taxonomy"
            )
            (taxonomy_dir / "taxonomy.yaml").write_text(
                yaml.safe_dump(
                    {
                        "taxonomies": [
                            {"slug": "stride", "entries": [{"external_id": "s"}] * 6}
                        ]
                    }
                )
            )
            library_dir = _write_pack(
                base, "demo-threat-libraries/demo-aws", slug="demo-aws"
            )
            (library_dir / "dfd-templates").mkdir()
            for template_name in ("one", "two"):
                (library_dir / "dfd-templates" / f"{template_name}.yaml").write_text(
                    "template: {}\n"
                )

            packs, _ = self._discover(
                base, [_catalog_entry("cra", framework_count=1, requirement_count=28)]
            )

            counts = {
                pack.slug: (
                    pack.framework_count,
                    pack.requirement_count,
                    pack.taxonomy_entry_count,
                    pack.template_count,
                )
                for pack in packs
            }
            self.assertEqual(
                counts,
                {
                    "demo-asvs": (2, 3, 0, 0),
                    "stride-taxonomy": (0, 0, 6, 0),
                    "demo-aws": (0, 0, 0, 2),
                    "cra": (1, 28, 0, 0),
                },
            )
            self.assertEqual(
                next(pack for pack in packs if pack.slug == "cra").to_dict()[
                    "requirement_count"
                ],
                28,
            )

    def test_a_catalog_that_is_off_or_unavailable_lists_only_bundled_packs(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _write_pack(base, "demo-threat-libraries/demo-aws", slug="demo-aws")

            packs, catalog_result = self._discover(base, [], available=False)

            self.assertEqual([pack.slug for pack in packs], ["demo-aws"])
            self.assertFalse(catalog_result.available)


class TaxonomyReferenceValidationTests(SimpleTestCase):
    """validate_pack catches bad taxonomy slugs in joins/threats-*.yaml (#26)."""

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    def test_validate_rejects_unknown_taxonomy_reference(self, mock_taxonomy_model):
        mock_taxonomy_model.objects.values_list.return_value = []

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "bad-pack", slug="bad-pack")

            joins_dir = pack_dir / "joins"
            joins_dir.mkdir()
            join_data = {"taxonomy": "nonexistent-taxonomy", "mappings": []}
            (joins_dir / "threats-foo.yaml").write_text(yaml.safe_dump(join_data))

            result = validate_pack(pack_dir)

            taxonomy_errors = [e for e in result.errors if e.ref_type == "taxonomy"]
            self.assertEqual(len(taxonomy_errors), 1)
            self.assertEqual(taxonomy_errors[0].reference, "nonexistent-taxonomy")
            self.assertIn("taxonomy.yaml", taxonomy_errors[0].message)
            self.assertIn("not from the pack slug", taxonomy_errors[0].message)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    def test_validate_accepts_valid_taxonomy_reference(self, mock_taxonomy_model):
        mock_taxonomy_model.objects.values_list.return_value = []

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "good-pack", slug="good-pack")

            # Pack defines its own taxonomy
            tax_data = {"taxonomies": [{"slug": "cwe", "name": "CWE", "entries": []}]}
            (pack_dir / "taxonomy.yaml").write_text(yaml.safe_dump(tax_data))

            joins_dir = pack_dir / "joins"
            joins_dir.mkdir()
            join_data = {"taxonomy": "cwe", "mappings": []}
            (joins_dir / "threats-cwe.yaml").write_text(yaml.safe_dump(join_data))

            result = validate_pack(pack_dir)

            taxonomy_errors = [e for e in result.errors if e.ref_type == "taxonomy"]
            self.assertEqual(len(taxonomy_errors), 0)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    @mock.patch("apps.packs.services.get_libraries_path")
    def test_validate_accepts_taxonomy_from_dependency(
        self, mock_get_libraries_path, mock_lp, mock_taxonomy_model
    ):
        mock_taxonomy_model.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            mock_get_libraries_path.return_value = base

            # Dependency pack provides the taxonomy
            dep_dir = _write_pack(
                base, "cwe-taxonomy", slug="cwe-taxonomy", pack_type="taxonomy"
            )
            tax_data = {"taxonomies": [{"slug": "cwe", "name": "CWE", "entries": []}]}
            (dep_dir / "taxonomy.yaml").write_text(yaml.safe_dump(tax_data))

            # Downstream pack references the dependency's taxonomy
            pack_dir = _write_pack(
                base,
                "cwe",
                slug="cwe",
                pack_type="threat",
                depends_on=["cwe-taxonomy"],
            )
            joins_dir = pack_dir / "joins"
            joins_dir.mkdir()
            join_data = {"taxonomy": "cwe", "mappings": []}
            (joins_dir / "threats-cwe.yaml").write_text(yaml.safe_dump(join_data))

            result = validate_pack(pack_dir)

            taxonomy_errors = [e for e in result.errors if e.ref_type == "taxonomy"]
            self.assertEqual(len(taxonomy_errors), 0)


# =========================================================================
# Phase 2: Duplicate ID detection (issue #10)
# =========================================================================


class DuplicateIdValidationTests(SimpleTestCase):
    """validate_pack catches duplicate IDs that would cause silent overwrites."""

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    def test_duplicate_component_ids_are_errors(self, mock_lp, mock_taxonomy):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "dup-pack", slug="dup-pack")

            comp_data = {
                "components": [
                    {"id": "web-server", "name": "Web Server", "category": "process"},
                    {
                        "id": "web-server",
                        "name": "Web Server Copy",
                        "category": "process",
                    },
                ]
            }
            (pack_dir / "components.yaml").write_text(yaml.safe_dump(comp_data))

            result = validate_pack(pack_dir)

            dup_errors = [
                e for e in result.errors if "Duplicate component id" in e.message
            ]
            self.assertEqual(len(dup_errors), 1)
            self.assertIn("web-server", dup_errors[0].message)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    def test_duplicate_threat_ids_are_errors(self, mock_lp, mock_taxonomy):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "dup-pack", slug="dup-pack")

            threat_data = {
                "threats": [
                    {"id": "sql-injection", "name": "SQL Injection"},
                    {"id": "sql-injection", "name": "SQL Injection 2"},
                ]
            }
            (pack_dir / "threats.yaml").write_text(yaml.safe_dump(threat_data))

            result = validate_pack(pack_dir)

            dup_errors = [
                e for e in result.errors if "Duplicate threat id" in e.message
            ]
            self.assertEqual(len(dup_errors), 1)
            self.assertIn("sql-injection", dup_errors[0].message)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    def test_duplicate_countermeasure_ids_are_errors(self, mock_lp, mock_taxonomy):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "dup-pack", slug="dup-pack")

            cm_data = {
                "countermeasures": [
                    {
                        "slug": "mfa",
                        "name": "MFA",
                        "control_type": "preventive",
                        "cost": "low",
                    },
                    {
                        "slug": "mfa",
                        "name": "MFA duplicate",
                        "control_type": "preventive",
                        "cost": "low",
                    },
                ]
            }
            (pack_dir / "countermeasures.yaml").write_text(yaml.safe_dump(cm_data))

            result = validate_pack(pack_dir)

            dup_errors = [
                e for e in result.errors if "Duplicate countermeasure id" in e.message
            ]
            self.assertEqual(len(dup_errors), 1)
            self.assertIn("mfa", dup_errors[0].message)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    def test_duplicate_framework_section_codes_are_errors(self, mock_lp, mock_taxonomy):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pack_dir = base / "fw-pack"
            pack_dir.mkdir()

            pack_yaml = {
                "pack": {
                    "slug": "fw-pack",
                    "name": "fw-pack",
                    "version": "1.0.0",
                    "pack_type": "compliance",
                },
                "frameworks": [
                    {
                        "slug": "test-fw",
                        "name": "Test Framework",
                        "requirements": [
                            {"section_code": "1.1", "description": "First"},
                            {"section_code": "1.1", "description": "Duplicate"},
                        ],
                    }
                ],
            }
            (pack_dir / "pack.yaml").write_text(yaml.safe_dump(pack_yaml))

            result = validate_pack(pack_dir)

            dup_errors = [
                e for e in result.errors if "Duplicate section_code" in e.message
            ]
            self.assertEqual(len(dup_errors), 1)
            self.assertIn("1.1", dup_errors[0].message)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    def test_duplicate_taxonomy_external_ids_are_errors(self, mock_lp, mock_taxonomy):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "tax-pack", slug="tax-pack")

            tax_data = {
                "taxonomies": [
                    {
                        "slug": "cwe",
                        "name": "CWE",
                        "entries": [
                            {"external_id": "CWE-79", "title": "XSS"},
                            {"external_id": "CWE-79", "title": "XSS duplicate"},
                        ],
                    }
                ]
            }
            (pack_dir / "taxonomy.yaml").write_text(yaml.safe_dump(tax_data))

            result = validate_pack(pack_dir)

            dup_errors = [
                e for e in result.errors if "Duplicate external_id" in e.message
            ]
            self.assertEqual(len(dup_errors), 1)
            self.assertIn("CWE-79", dup_errors[0].message)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    def test_unique_ids_pass_validation(self, mock_lp, mock_taxonomy):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "clean-pack", slug="clean-pack")

            comp_data = {
                "components": [
                    {"id": "web-server", "name": "Web Server", "category": "process"},
                    {"id": "database", "name": "Database", "category": "datastore"},
                ]
            }
            (pack_dir / "components.yaml").write_text(yaml.safe_dump(comp_data))

            result = validate_pack(pack_dir)

            dup_errors = [e for e in result.errors if "Duplicate" in e.message]
            self.assertEqual(len(dup_errors), 0)


# =========================================================================
# Phase 3: Overlay section_code validation (issue #10)
# =========================================================================


class OverlaySectionCodeValidationTests(SimpleTestCase):
    """validate_pack checks overlay section_codes against framework requirements."""

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    @mock.patch("apps.compliance.models.StandardRequirement")
    @mock.patch("apps.compliance.models.StandardFramework")
    def test_invalid_section_code_is_error(
        self, mock_fw, mock_req, mock_lp, mock_taxonomy
    ):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        # Framework exists
        mock_framework_instance = mock.MagicMock()
        mock_fw.objects.filter.return_value.first.return_value = mock_framework_instance

        # Framework has requirements — but not the one we reference
        mock_req.objects.filter.return_value.values_list.return_value = ["1.1", "1.2"]

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "overlay-pack", slug="overlay-pack")

            joins_dir = pack_dir / "joins"
            joins_dir.mkdir()
            overlay_data = {
                "framework": "nist-csf",
                "mappings": [
                    {"countermeasure": "mfa", "requirements": ["1.1", "BOGUS"]},
                ],
            }
            (joins_dir / "countermeasures-nist-csf.yaml").write_text(
                yaml.safe_dump(overlay_data)
            )

            result = validate_pack(pack_dir)

            section_errors = [
                e
                for e in result.errors
                if "section_code" in e.message and "BOGUS" in e.message
            ]
            self.assertEqual(len(section_errors), 1)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    @mock.patch("apps.compliance.models.StandardFramework")
    def test_missing_framework_is_warning(self, mock_fw, mock_lp, mock_taxonomy):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        # Framework does NOT exist
        mock_fw.objects.filter.return_value.first.return_value = None

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "overlay-pack", slug="overlay-pack")

            joins_dir = pack_dir / "joins"
            joins_dir.mkdir()
            overlay_data = {
                "framework": "nonexistent-fw",
                "mappings": [
                    {"countermeasure": "mfa", "requirements": ["1.1"]},
                ],
            }
            (joins_dir / "countermeasures-nonexistent-fw.yaml").write_text(
                yaml.safe_dump(overlay_data)
            )

            result = validate_pack(pack_dir)

            fw_warnings = [
                w
                for w in result.warnings
                if "nonexistent-fw" in w.message and "not found" in w.message
            ]
            self.assertEqual(len(fw_warnings), 1)
            # Should NOT be an error
            fw_errors = [e for e in result.errors if "nonexistent-fw" in e.message]
            self.assertEqual(len(fw_errors), 0)


# =========================================================================
# Phase 4: depends_on validation (issue #10)
# =========================================================================


class DependsOnValidationTests(SimpleTestCase):
    """validate_pack warns when depends_on references can't be found."""

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    @mock.patch("apps.packs.services.get_libraries_path")
    def test_missing_dependency_is_warning(
        self, mock_get_libraries_path, mock_lp, mock_taxonomy
    ):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            mock_get_libraries_path.return_value = base

            pack_dir = _write_pack(
                base,
                "dep-pack",
                slug="dep-pack",
                depends_on=["nonexistent-dep"],
            )

            result = validate_pack(pack_dir)

            dep_warnings = [
                w
                for w in result.warnings
                if "nonexistent-dep" in w.message and "depends_on" in w.field
            ]
            self.assertEqual(len(dep_warnings), 1)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    @mock.patch("apps.packs.services.get_libraries_path")
    def test_found_dependency_no_warning(
        self, mock_get_libraries_path, mock_lp, mock_taxonomy
    ):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            mock_get_libraries_path.return_value = base

            # Create the dependency pack on disk
            _write_pack(base, "stride-taxonomy", slug="stride-taxonomy")

            pack_dir = _write_pack(
                base,
                "dep-pack",
                slug="dep-pack",
                depends_on=["stride-taxonomy"],
            )

            result = validate_pack(pack_dir)

            dep_warnings = [
                w
                for w in result.warnings
                if "stride-taxonomy" in w.message and "depends_on" in w.field
            ]
            self.assertEqual(len(dep_warnings), 0)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    @mock.patch("apps.packs.services.get_libraries_path")
    def test_missing_dependency_is_not_error(
        self, mock_get_libraries_path, mock_lp, mock_taxonomy
    ):
        """Missing dependencies are warnings, not errors — import should still succeed."""
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            mock_get_libraries_path.return_value = base

            pack_dir = _write_pack(
                base,
                "dep-pack",
                slug="dep-pack",
                depends_on=["ghost-pack"],
            )

            result = validate_pack(pack_dir)

            dep_errors = [e for e in result.errors if "ghost-pack" in e.message]
            self.assertEqual(len(dep_errors), 0)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    @mock.patch("apps.packs.services.get_libraries_path")
    def test_path_format_depends_on_resolves(
        self, mock_get_libraries_path, mock_lp, mock_taxonomy
    ):
        """depends_on with path-format strings (e.g. 'taxonomies/stride-taxonomy') should resolve."""
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            mock_get_libraries_path.return_value = base

            # Create the dependency at the path
            _write_pack(base, "taxonomies/stride-taxonomy", slug="stride-taxonomy")

            pack_dir = _write_pack(
                base,
                "dep-pack",
                slug="dep-pack",
                depends_on=["taxonomies/stride-taxonomy"],
            )

            result = validate_pack(pack_dir)

            dep_warnings = [
                w
                for w in result.warnings
                if "stride-taxonomy" in w.message and "depends_on" in w.field
            ]
            self.assertEqual(len(dep_warnings), 0)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    @mock.patch("apps.packs.services.get_libraries_path")
    def test_path_format_dependency_in_another_folder_resolves(
        self, mock_get_libraries_path, mock_lp, mock_taxonomy
    ):
        """taxonomies/stride-taxonomy finds STRIDE at demo-taxonomies/, and its
        taxonomy slugs are known with an empty database."""
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            mock_get_libraries_path.return_value = base

            stride_dir = _write_pack(
                base, "demo-taxonomies/stride-taxonomy", slug="stride-taxonomy"
            )
            (stride_dir / "taxonomy.yaml").write_text(
                yaml.safe_dump(
                    {
                        "taxonomies": [
                            {"slug": "stride", "name": "STRIDE", "entries": []}
                        ]
                    }
                )
            )
            pack_dir = _write_pack(
                base,
                "threat-libraries/aws",
                slug="aws",
                depends_on=["taxonomies/stride-taxonomy"],
            )
            joins_dir = pack_dir / "joins"
            joins_dir.mkdir()
            (joins_dir / "threats-stride.yaml").write_text(
                yaml.safe_dump({"taxonomy": "stride", "mappings": []})
            )

            result = validate_pack(pack_dir)

            self.assertEqual(
                [w.message for w in result.warnings if w.field == "depends_on"], []
            )
            self.assertEqual(
                [e.message for e in result.errors if e.ref_type == "taxonomy"], []
            )


class DependencySlugTests(SimpleTestCase):
    """_dependency_slug: a dependency is a slug, whatever folder it names."""

    def test_entries(self):
        cases = [
            ("stride-taxonomy", "stride-taxonomy"),
            ("taxonomies/stride-taxonomy", "stride-taxonomy"),
            ("a/b/cwe", "cwe"),
            (" taxonomies/cwe/ ", "cwe"),
            ({"pack": "cwe", "version": "^1.0.0"}, "cwe"),
            ({"slug": "capec"}, "capec"),
            ({"pack": "cwe", "path": "elsewhere/other"}, "cwe"),
            ({"version": "1.0.0"}, ""),
            (None, ""),
            (42, ""),
        ]
        for entry, expected_slug in cases:
            with self.subTest(entry=entry):
                self.assertEqual(_dependency_slug(entry), expected_slug)


class FindPackDirBySlugTests(SimpleTestCase):
    def test_finds_by_folder_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _write_pack(base, "demo-taxonomies/stride-taxonomy", slug="stride-taxonomy")

            self.assertEqual(
                _find_pack_dir_by_slug(base, "stride-taxonomy"),
                base / "demo-taxonomies" / "stride-taxonomy",
            )

    def test_finds_a_pack_whose_folder_has_another_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _write_pack(base, "standards/asvs-folder", slug="owasp-asvs")

            self.assertEqual(
                _find_pack_dir_by_slug(base, "owasp-asvs"),
                base / "standards" / "asvs-folder",
            )

    def test_missing_or_empty_slug(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _write_pack(base, "taxonomies/cwe", slug="cwe")

            self.assertIsNone(_find_pack_dir_by_slug(base, "capec"))
            self.assertIsNone(_find_pack_dir_by_slug(base, ""))
            self.assertIsNone(_find_pack_dir_by_slug(base / "missing", "cwe"))


# =========================================================================
# Phase 5: Slug format validation (issue #10)
# =========================================================================


class SlugFormatValidationTests(SimpleTestCase):
    """validate_pack warns on non-conforming slug formats."""

    def test_is_valid_slug_accepts_good_slugs(self):
        self.assertTrue(_is_valid_slug("aws"))
        self.assertTrue(_is_valid_slug("aws-core"))
        self.assertTrue(_is_valid_slug("base-stride"))
        self.assertTrue(_is_valid_slug("a1-b2-c3"))

    def test_is_valid_slug_rejects_bad_slugs(self):
        self.assertFalse(_is_valid_slug("AWS"))
        self.assertFalse(_is_valid_slug("my_pack"))
        self.assertFalse(_is_valid_slug("my.pack"))
        self.assertFalse(_is_valid_slug("-leading-hyphen"))
        self.assertFalse(_is_valid_slug("trailing-hyphen-"))
        self.assertFalse(_is_valid_slug("double--hyphen"))
        self.assertFalse(_is_valid_slug(""))

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    def test_bad_pack_slug_is_warning(self, mock_lp, mock_taxonomy):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "Bad_Pack", slug="Bad_Pack")

            result = validate_pack(pack_dir)

            slug_warnings = [
                w
                for w in result.warnings
                if "Bad_Pack" in w.message and "slug" in w.field
            ]
            self.assertEqual(len(slug_warnings), 1)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    def test_bad_component_id_is_warning(self, mock_lp, mock_taxonomy):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "slug-pack", slug="slug-pack")

            comp_data = {
                "components": [
                    {"id": "aws_lambda", "name": "Lambda", "category": "process"},
                ]
            }
            (pack_dir / "components.yaml").write_text(yaml.safe_dump(comp_data))

            result = validate_pack(pack_dir)

            slug_warnings = [
                w
                for w in result.warnings
                if "aws_lambda" in w.message and "slug format" in w.message
            ]
            self.assertEqual(len(slug_warnings), 1)

    @mock.patch("apps.packs.services.ExternalTaxonomy")
    @mock.patch("apps.packs.services.LibraryPack")
    def test_good_slug_no_warning(self, mock_lp, mock_taxonomy):
        mock_taxonomy.objects.values_list.return_value = []
        mock_lp.objects.filter.return_value.exists.return_value = False

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = _write_pack(Path(tmp), "good-pack", slug="good-pack")

            comp_data = {
                "components": [
                    {"id": "web-server", "name": "Web Server", "category": "process"},
                ]
            }
            (pack_dir / "components.yaml").write_text(yaml.safe_dump(comp_data))

            result = validate_pack(pack_dir)

            slug_warnings = [w for w in result.warnings if "slug format" in w.message]
            self.assertEqual(len(slug_warnings), 0)


# =========================================================================
# Phase 1: ImportResult warnings (issue #10)
# =========================================================================


class ImportResultWarningsTests(SimpleTestCase):
    """ImportResult exposes warnings field in dataclass and to_dict()."""

    def test_import_result_has_warnings_field(self):
        result = ImportResult(
            success=True,
            pack_slug="test",
            pack_name="Test",
            version="1.0.0",
            message="OK",
            warnings=["something was skipped"],
        )
        self.assertEqual(result.warnings, ["something was skipped"])

    def test_import_result_to_dict_includes_warnings(self):
        result = ImportResult(
            success=True,
            pack_slug="test",
            pack_name="Test",
            version="1.0.0",
            message="OK",
            warnings=["warn1", "warn2"],
        )
        d = result.to_dict()
        self.assertIn("warnings", d)
        self.assertEqual(d["warnings"], ["warn1", "warn2"])

    def test_import_result_warnings_default_empty(self):
        result = ImportResult(
            success=True,
            pack_slug="test",
            pack_name="Test",
            version="1.0.0",
            message="OK",
        )
        self.assertEqual(result.warnings, [])
        self.assertEqual(result.to_dict()["warnings"], [])


class GetLibrariesPathTests(SimpleTestCase):
    """The pack sources come from settings.LIBRARIES_PATH and nowhere else.

    The path used to be guessed from BASE_DIR with a fallback, which found nothing
    under a container that mounts the directory elsewhere. Every catalog then came
    up empty and looked like an unseeded database.
    """

    @override_settings(LIBRARIES_PATH="/mounted/elsewhere")
    def test_reads_the_configured_location(self):
        self.assertEqual(get_libraries_path(), Path("/mounted/elsewhere/packs"))

    @override_settings(LIBRARIES_PATH=Path("/mounted/elsewhere"))
    def test_accepts_a_path_as_well_as_a_string(self):
        self.assertEqual(get_libraries_path(), Path("/mounted/elsewhere/packs"))

    @override_settings(LIBRARIES_PATH="/nowhere/at/all")
    def test_does_not_fall_back_when_the_location_is_missing(self):
        """A configured path that does not exist is returned, not searched around.

        Callers report the path they were given, which is the only thing that tells
        an operator which mount is wrong.
        """
        libraries_path = get_libraries_path()
        self.assertFalse(libraries_path.exists())
        self.assertEqual(libraries_path, Path("/nowhere/at/all/packs"))
