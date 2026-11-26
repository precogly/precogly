"""Every pack on disk validates and imports with zero errors and zero warnings.

Here that is the three demo packs bundled with the app. The precogly/library-packs
CI runs this same test against its full set, with LIBRARIES_PATH pointing at its
checkout, so the test discovers every pack.yaml instead of naming folders.

Packs are imported in dependency order, so cross-pack references, taxonomy joins
and framework overlays resolve the way they do when a user imports a pack and its
dependencies. A pack comes after:
  1. every pack its depends_on names (by slug), and
  2. the pack that defines a framework or taxonomy one of its join files points
     at: `framework:` in countermeasures-*.yaml, `framework:` and
     `source_framework:` in requirements-*.yaml, `taxonomy:` in threats-*.yaml.
Ties go taxonomy packs first, then compliance packs, then the rest, then by
path, so the order is stable.

Warnings count as failures too: the seed skips a pack that validates with a
warning, so a warning on a shipped pack is a pack the demo database would not get.
"""

import heapq
import tempfile
from pathlib import Path

import yaml
from django.test import SimpleTestCase, TestCase

from apps.packs.services import (
    _dependency_slug,
    get_libraries_path,
    import_pack_from_path,
    validate_pack,
)

TYPE_ORDER = {"taxonomy": 0, "compliance": 1}


def _read_yaml(file_path: Path) -> dict:
    try:
        return yaml.safe_load(file_path.read_text()) or {}
    except (OSError, yaml.YAMLError):
        return {}


def _overlay_targets(pack_dir: Path) -> tuple[set[str], set[str]]:
    """The framework slugs and taxonomy slugs this pack's join files point at."""
    framework_slugs: set[str] = set()
    taxonomy_slugs: set[str] = set()
    for join_file in sorted((pack_dir / "joins").glob("*.yaml")):
        header = _read_yaml(join_file)
        if join_file.name.startswith("countermeasures-"):
            framework_slugs.add(header.get("framework"))
        elif join_file.name.startswith("requirements-"):
            framework_slugs.add(header.get("framework"))
            framework_slugs.add(header.get("source_framework"))
        elif join_file.name.startswith("threats-"):
            taxonomy_slugs.add(header.get("taxonomy"))
    return framework_slugs - {None}, taxonomy_slugs - {None}


def packs_in_import_order(root: Path) -> list[Path]:
    """Every pack folder under root, each after the packs it needs."""
    pack_dirs = sorted(pack_yaml.parent for pack_yaml in root.rglob("pack.yaml"))
    pack_meta_by_dir = {
        pack_dir: _read_yaml(pack_dir / "pack.yaml").get("pack") or {}
        for pack_dir in pack_dirs
    }
    pack_dir_by_slug: dict[str, Path] = {}
    pack_dir_by_framework: dict[str, Path] = {}
    pack_dir_by_taxonomy: dict[str, Path] = {}
    for pack_dir in pack_dirs:
        pack_dir_by_slug.setdefault(
            pack_meta_by_dir[pack_dir].get("slug", pack_dir.name), pack_dir
        )
        for framework in _read_yaml(pack_dir / "pack.yaml").get("frameworks") or []:
            pack_dir_by_framework.setdefault(framework.get("slug"), pack_dir)
        for taxonomy in _read_yaml(pack_dir / "taxonomy.yaml").get("taxonomies") or []:
            pack_dir_by_taxonomy.setdefault(taxonomy.get("slug"), pack_dir)

    # An overlay target no pack on disk defines adds no edge: the importer keeps
    # such overlays as pending, and whether that is a warning is the validator's call.
    needed_packs: dict[Path, set[Path]] = {}
    for pack_dir in pack_dirs:
        framework_slugs, taxonomy_slugs = _overlay_targets(pack_dir)
        needed = {
            pack_dir_by_slug.get(_dependency_slug(entry))
            for entry in pack_meta_by_dir[pack_dir].get("depends_on") or []
        }
        needed |= {pack_dir_by_framework.get(slug) for slug in framework_slugs}
        needed |= {pack_dir_by_taxonomy.get(slug) for slug in taxonomy_slugs}
        needed_packs[pack_dir] = needed - {None, pack_dir}

    def tie_break(pack_dir: Path) -> tuple[int, str]:
        pack_type = pack_meta_by_dir[pack_dir].get("pack_type", "")
        return (TYPE_ORDER.get(pack_type, 2), pack_dir.relative_to(root).as_posix())

    waiting_count = {pack_dir: len(needed) for pack_dir, needed in needed_packs.items()}
    needed_by: dict[Path, list[Path]] = {pack_dir: [] for pack_dir in pack_dirs}
    for pack_dir, needed in needed_packs.items():
        for needed_pack in needed:
            needed_by[needed_pack].append(pack_dir)

    ready = [
        (tie_break(pack_dir), pack_dir)
        for pack_dir, count in waiting_count.items()
        if count == 0
    ]
    heapq.heapify(ready)
    ordered: list[Path] = []
    while ready:
        _, pack_dir = heapq.heappop(ready)
        ordered.append(pack_dir)
        for dependent in needed_by[pack_dir]:
            waiting_count[dependent] -= 1
            if waiting_count[dependent] == 0:
                heapq.heappush(ready, (tie_break(dependent), dependent))

    if len(ordered) != len(pack_dirs):
        stuck = sorted(
            pack_dir.relative_to(root).as_posix()
            for pack_dir in pack_dirs
            if pack_dir not in ordered
        )
        raise AssertionError(
            "packs depend on each other in a cycle (directly or through overlays): "
            + ", ".join(stuck)
        )
    return ordered


class ShippedPacksValidateTests(TestCase):
    def test_every_shipped_pack_validates_and_imports(self):
        root = get_libraries_path()
        pack_paths = packs_in_import_order(root)
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


class ImportOrderTests(SimpleTestCase):
    def _write(self, root: Path, relative: str, pack: dict, extra_files=None) -> None:
        pack_dir = root / relative
        pack_dir.mkdir(parents=True)
        (pack_dir / "pack.yaml").write_text(yaml.safe_dump(pack))
        for file_name, document in (extra_files or {}).items():
            (pack_dir / file_name).parent.mkdir(parents=True, exist_ok=True)
            (pack_dir / file_name).write_text(yaml.safe_dump(document))

    def test_dependencies_and_overlay_targets_come_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Like pci-dss mapping to owasp-aisvs, but named so the alphabet would
            # put the mapping pack first: only the overlay edge can order them.
            self._write(
                root,
                "standards/aaa-pci",
                {"pack": {"slug": "aaa-pci", "pack_type": "compliance"}},
                {
                    "joins/requirements-aisvs.yaml": {
                        "framework": "zzz-aisvs-1",
                        "source_framework": "aaa-pci-4",
                        "mappings": [],
                    }
                },
            )
            self._write(
                root,
                "standards/zzz-aisvs",
                {
                    "pack": {"slug": "zzz-aisvs", "pack_type": "compliance"},
                    "frameworks": [{"slug": "zzz-aisvs-1"}],
                },
            )
            self._write(
                root,
                "threat-libraries/aws",
                {
                    "pack": {
                        "slug": "aws",
                        "pack_type": "full",
                        "depends_on": ["taxonomies/stride-taxonomy"],
                    }
                },
                {"joins/threats-cwe.yaml": {"taxonomy": "cwe", "mappings": []}},
            )
            self._write(
                root,
                "demo-taxonomies/stride-taxonomy",
                {"pack": {"slug": "stride-taxonomy", "pack_type": "taxonomy"}},
            )
            self._write(
                root,
                "zzz/cwe-pack",
                {"pack": {"slug": "cwe-pack", "pack_type": "full"}},
                {"taxonomy.yaml": {"taxonomies": [{"slug": "cwe"}]}},
            )

            order = [
                path.relative_to(root).as_posix()
                for path in packs_in_import_order(root)
            ]

            self.assertLess(
                order.index("standards/zzz-aisvs"), order.index("standards/aaa-pci")
            )
            self.assertLess(
                order.index("demo-taxonomies/stride-taxonomy"),
                order.index("threat-libraries/aws"),
            )
            self.assertLess(
                order.index("zzz/cwe-pack"), order.index("threat-libraries/aws")
            )
            self.assertEqual(order[0], "demo-taxonomies/stride-taxonomy")

    def test_a_cycle_fails_with_the_packs_named(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write(root, "a/one", {"pack": {"slug": "one", "depends_on": ["two"]}})
            self._write(root, "a/two", {"pack": {"slug": "two", "depends_on": ["one"]}})

            with self.assertRaises(AssertionError) as raised:
                packs_in_import_order(root)

            self.assertIn("a/one, a/two", str(raised.exception))
