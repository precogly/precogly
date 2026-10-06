"""Pack-level icon (`pack.yaml`'s `icon:` path -> `LibraryPack.icon_svg`).

Mirrors the existing per-component `icon_svg` mechanism (`ComponentLibrary`)
so packs can declare a default icon without any new rendering path: the
importer reads the referenced SVG file's raw markup into a `TextField`, and
the frontend renders it via `SvgIcon`'s base64 `<img>` data URI — never
`dangerouslySetInnerHTML` — so a malicious pack's SVG can't execute script
in the app (see the fix for issue #516).
"""

import tempfile
from pathlib import Path

from django.test import TestCase

from apps.packs.models import LibraryPack
from apps.packs.services import _create_or_update_pack

SAMPLE_SVG = '<svg xmlns="http://www.w3.org/2000/svg"><circle r="1"/></svg>'


class PackIconSvgImportTests(TestCase):
    """`_create_or_update_pack` loads `icon:` relative to the pack directory."""

    def test_icon_path_is_read_into_icon_svg(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = Path(tmp)
            icons_dir = pack_dir / "icons"
            icons_dir.mkdir()
            (icons_dir / "logo.svg").write_text(SAMPLE_SVG)

            pack_data = {
                "pack": {
                    "slug": "icon-pack",
                    "name": "Icon Pack",
                    "version": "1.0.0",
                    "pack_type": "technology",
                    "author": "Test",
                    "icon": "icons/logo.svg",
                }
            }

            library_pack = _create_or_update_pack(pack_data, pack_dir)

        self.assertEqual(library_pack.icon_svg, SAMPLE_SVG)

    def test_missing_icon_key_leaves_icon_svg_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = Path(tmp)
            pack_data = {
                "pack": {
                    "slug": "no-icon-pack",
                    "name": "No Icon Pack",
                    "version": "1.0.0",
                    "pack_type": "technology",
                    "author": "Test",
                }
            }

            library_pack = _create_or_update_pack(pack_data, pack_dir)

        self.assertEqual(library_pack.icon_svg, "")

    def test_missing_icon_file_warns_and_leaves_icon_svg_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = Path(tmp)
            pack_data = {
                "pack": {
                    "slug": "broken-icon-pack",
                    "name": "Broken Icon Pack",
                    "version": "1.0.0",
                    "pack_type": "technology",
                    "author": "Test",
                    "icon": "icons/missing.svg",
                }
            }
            warnings: list[str] = []

            library_pack = _create_or_update_pack(pack_data, pack_dir, warnings)

        self.assertEqual(library_pack.icon_svg, "")
        self.assertEqual(warnings, [])

    def test_reimport_updates_icon_svg(self):
        LibraryPack.objects.create(
            slug="icon-pack",
            name="Icon Pack",
            version="0.9.0",
            pack_type="technology",
            author="Test",
            icon_svg="<svg>old</svg>",
        )

        with tempfile.TemporaryDirectory() as tmp:
            pack_dir = Path(tmp)
            icons_dir = pack_dir / "icons"
            icons_dir.mkdir()
            (icons_dir / "logo.svg").write_text(SAMPLE_SVG)

            pack_data = {
                "pack": {
                    "slug": "icon-pack",
                    "name": "Icon Pack",
                    "version": "1.0.0",
                    "pack_type": "technology",
                    "author": "Test",
                    "icon": "icons/logo.svg",
                }
            }

            library_pack = _create_or_update_pack(pack_data, pack_dir)

        self.assertEqual(library_pack.icon_svg, SAMPLE_SVG)
