"""A pack catalog for tests: real pack folders served through a fake requests.get.

Packs are written as folders, archived the way library-packs releases them
(paths start at the slug), and listed in a catalog.json whose sizes and hashes
match. Patch `apps.packs.catalog.requests.get` with `fake_get` and set
PACK_CATALOG_URL to CATALOG_URL. Nothing reaches the network.
"""

import hashlib
import io
import json
import tarfile
from pathlib import Path

import requests
import yaml

CATALOG_URL = "https://packs.example.test/releases/download/v-test/catalog.json"
ARCHIVE_BASE_URL = "https://packs.example.test/releases/download/v-test/"


class FakeResponse:
    """Enough of requests.Response for streamed reads."""

    def __init__(
        self, body: bytes = b"", status_code: int = 200, headers: dict | None = None
    ):
        self.body = body
        self.status_code = status_code
        self.headers = headers if headers is not None else {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}")

    def iter_content(self, chunk_size=1):
        for start in range(0, len(self.body), chunk_size):
            yield self.body[start : start + chunk_size]

    def __enter__(self):
        return self

    def __exit__(self, *exception_info):
        return False


def write_pack_folder(
    pack_dir: Path, pack_meta: dict, files: dict | None = None
) -> Path:
    """Write pack.yaml plus extra files ({relative path: YAML-able document or text})."""
    pack_dir.mkdir(parents=True, exist_ok=True)
    (pack_dir / "pack.yaml").write_text(
        yaml.safe_dump({"pack": {"schema_version": 1, **pack_meta}})
    )
    for relative_name, content in (files or {}).items():
        target = pack_dir / relative_name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            content if isinstance(content, str) else yaml.safe_dump(content)
        )
    return pack_dir


class FakeCatalog:
    def __init__(self, work_dir: Path):
        self.work_dir = work_dir
        self.raw_entries: list[dict] = []
        self.archives: dict[str, bytes] = {}
        self.downloads: list[str] = []
        self.failing_archives: set[str] = set()
        self.catalog_fetches = 0

    def add_pack(
        self, category: str, pack_meta: dict, files: dict | None = None
    ) -> dict:
        """Add one pack. pack_meta needs at least slug; version defaults to 1.0.0."""
        pack_meta = {"version": "1.0.0", "name": pack_meta["slug"], **pack_meta}
        slug = pack_meta["slug"]
        pack_dir = write_pack_folder(self.work_dir / category / slug, pack_meta, files)

        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            archive.add(pack_dir, arcname=slug)
        archive_bytes = buffer.getvalue()
        archive_name = f"{category}__{slug}-{pack_meta['version']}.tar.gz"
        self.archives[archive_name] = archive_bytes

        def count_items(file_name: str, key: str) -> int:
            document = (files or {}).get(file_name)
            return len(document.get(key, [])) if isinstance(document, dict) else 0

        raw_entry = {
            "slug": slug,
            "path": f"{category}/{slug}",
            "name": pack_meta["name"],
            "description": pack_meta.get("description", ""),
            "version": str(pack_meta["version"]),
            "packType": pack_meta.get("pack_type", "technology"),
            "schemaVersion": 1,
            "author": "",
            "tags": [],
            # Counted from the files, as library-packs' build_release.py does.
            "componentCount": count_items("components.yaml", "components"),
            "threatCount": count_items("threats.yaml", "threats"),
            "countermeasureCount": count_items(
                "countermeasures.yaml", "countermeasures"
            ),
            "taxonomyCount": count_items("taxonomy.yaml", "taxonomies"),
            "dependsOn": pack_meta.get("depends_on", []),
            "archive": archive_name,
            "archiveSize": len(archive_bytes),
            "sha256": hashlib.sha256(archive_bytes).hexdigest(),
        }
        self.raw_entries.append(raw_entry)
        return raw_entry

    def fail_download_of(self, slug: str) -> None:
        self.failing_archives.add(
            next(
                entry["archive"] for entry in self.raw_entries if entry["slug"] == slug
            )
        )

    def catalog_bytes(self) -> bytes:
        return json.dumps(
            {"catalogVersion": 1, "release": "v-test", "packs": self.raw_entries}
        ).encode()

    def fake_get(self, url, **request_options):
        if url == CATALOG_URL:
            self.catalog_fetches += 1
            return FakeResponse(self.catalog_bytes())
        if url.startswith(ARCHIVE_BASE_URL):
            archive_name = url[len(ARCHIVE_BASE_URL) :]
            if archive_name in self.failing_archives:
                raise requests.ConnectionError("download refused")
            if archive_name in self.archives:
                self.downloads.append(archive_name)
                return FakeResponse(self.archives[archive_name])
        return FakeResponse(b"", status_code=404)
