"""The pack catalog: the full packs published by precogly/library-packs.

A release of library-packs holds catalog.json, which lists every pack, and one
.tar.gz archive per pack (docs/catalog-format.md in that repo). The app reads
the catalog to list the packs, and downloads one archive only to preview,
validate or import that pack.

Everything here treats the catalog and the archives as untrusted input:
  - the only address used is settings.PACK_CATALOG_URL; no request names one,
  - catalog fields that end up in a URL or a path are checked against strict
    patterns, and a bad entry is dropped rather than used,
  - an archive must match the size and SHA-256 the catalog gives, and is
    unpacked into a temporary folder with per-member checks plus Python's
    "data" extraction filter, and the folder is removed after the request.

Nothing is kept on disk between requests. The catalog itself is kept in
Django's cache for PACK_CATALOG_TTL_SECONDS.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit, urlunsplit

import requests
import yaml
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)

SUPPORTED_CATALOG_VERSION = 1
CATALOG_FETCH_TIMEOUT_SECONDS = 5
ARCHIVE_CONNECT_TIMEOUT_SECONDS = 5
ARCHIVE_READ_TIMEOUT_SECONDS = 30
CATALOG_MAX_BYTES = 2 * 1024 * 1024
UNPACKED_MAX_BYTES = 100 * 1024 * 1024
UNPACKED_MAX_MEMBERS = 2000
FAILED_FETCH_MEMORY_SECONDS = 60
DOWNLOAD_CHUNK_BYTES = 64 * 1024
ALLOWED_PACK_FILE_SUFFIXES = {".yaml", ".yml", ".svg", ".md"}
DEMO_SLUG_PREFIX = "demo-"
LATEST_RELEASE_CATALOG_SUFFIX = "/releases/latest/download/catalog.json"

# Same pattern as _SLUG_RE in services.py. Repeated rather than imported:
# services imports this module.
_SLUG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
_ARCHIVE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.tar\.gz$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RELEASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

_reported_bad_catalog_urls: set[str] = set()


class CatalogPackError(Exception):
    """A catalog pack could not be downloaded or unpacked.

    The message is safe to show a user: no stack trace and no file system path.
    """


@dataclass(frozen=True)
class CatalogEntry:
    slug: str
    path: str  # "threat-libraries/azure"
    name: str
    description: str
    version: str
    pack_type: str
    schema_version: int
    author: str
    tags: list[str]
    component_count: int
    threat_count: int
    countermeasure_count: int
    taxonomy_count: int
    depends_on: list  # raw entries, as in pack.yaml
    archive: str
    archive_size: int
    sha256: str
    # The release this entry was read from. The archive is downloaded from that
    # release, so a newer release published in between cannot mix the two.
    release: str
    # Added to catalogVersion 1 later; a catalog without them gives 0.
    taxonomy_entry_count: int = 0
    framework_count: int = 0
    requirement_count: int = 0
    template_count: int = 0


@dataclass(frozen=True)
class CatalogResult:
    entries: list[CatalogEntry]
    release: str
    available: bool  # False when the fetch failed or the catalog is off
    enabled: bool  # False when PACK_CATALOG_URL is empty


def configured_catalog_url(catalog_url: str | None = None) -> str:
    """The catalog address to use, or "" when the catalog is off.

    Only http:// and https:// addresses are used. Anything else, a file://
    address for example, counts as off and is logged once.
    """
    url = (settings.PACK_CATALOG_URL if catalog_url is None else catalog_url) or ""
    url = url.strip()
    if not url:
        return ""
    if urlsplit(url).scheme.lower() not in ("http", "https"):
        if url not in _reported_bad_catalog_urls:
            _reported_bad_catalog_urls.add(url)
            logger.warning(
                "PACK_CATALOG_URL must start with http:// or https://; "
                "the pack catalog is off. Got: %s",
                url,
            )
        return ""
    return url


def _cache_key(catalog_url: str) -> str:
    return "packs:catalog:" + hashlib.sha256(catalog_url.encode()).hexdigest()


def _read_limited(response: requests.Response, max_bytes: int, what: str) -> bytes:
    """Read a streamed body, refusing one larger than max_bytes."""
    declared_length = response.headers.get("Content-Length")
    if (
        declared_length
        and declared_length.isdigit()
        and int(declared_length) > max_bytes
    ):
        raise ValueError(f"{what} is larger than {max_bytes} bytes")
    chunks = []
    received_bytes = 0
    for chunk in response.iter_content(chunk_size=DOWNLOAD_CHUNK_BYTES):
        received_bytes += len(chunk)
        if received_bytes > max_bytes:
            raise ValueError(f"{what} is larger than {max_bytes} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def _text(raw: dict, key: str, default: str = "") -> str:
    value = raw.get(key, default)
    return value if isinstance(value, str) else default


def _count(raw: dict, key: str) -> int:
    value = raw.get(key, 0)
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        else 0
    )


def _entry_from_raw(raw: object, release: str) -> CatalogEntry:
    """Check one catalog entry. Raises ValueError naming what is wrong."""
    if not isinstance(raw, dict):
        raise ValueError("entry is not an object")
    slug = raw.get("slug")
    if not isinstance(slug, str) or not _SLUG_RE.match(slug):
        raise ValueError(f"slug {slug!r} is not a valid slug")
    if slug.startswith(DEMO_SLUG_PREFIX):
        raise ValueError(
            f"slug {slug!r} uses the demo- prefix reserved for bundled packs"
        )
    path = raw.get("path")
    path_parts = path.split("/") if isinstance(path, str) else []
    if (
        len(path_parts) != 2
        or not all(_SLUG_RE.match(part) for part in path_parts)
        or path_parts[1] != slug
    ):
        raise ValueError(f"path {path!r} is not <category>/{slug}")
    archive = raw.get("archive")
    if not isinstance(archive, str) or not _ARCHIVE_NAME_RE.match(archive):
        raise ValueError(f"archive {archive!r} is not a plain .tar.gz file name")
    sha256 = raw.get("sha256")
    if not isinstance(sha256, str) or not _SHA256_RE.match(sha256):
        raise ValueError("sha256 is not 64 lowercase hex characters")
    archive_size = raw.get("archiveSize")
    if (
        not isinstance(archive_size, int)
        or isinstance(archive_size, bool)
        or archive_size <= 0
        or archive_size > settings.PACK_DOWNLOAD_MAX_BYTES
    ):
        raise ValueError(
            f"archiveSize {archive_size!r} is not between 1 and the download limit"
        )
    version = raw.get("version", "0.0.0")
    tags = raw.get("tags") or []
    depends_on = raw.get("dependsOn") or []
    schema_version = raw.get("schemaVersion", 1)
    return CatalogEntry(
        slug=slug,
        path=path,
        name=_text(raw, "name", slug) or slug,
        description=_text(raw, "description"),
        version=str(version),
        pack_type=_text(raw, "packType", "technology") or "technology",
        schema_version=schema_version if isinstance(schema_version, int) else 1,
        author=_text(raw, "author"),
        tags=[tag for tag in tags if isinstance(tag, str)]
        if isinstance(tags, list)
        else [],
        component_count=_count(raw, "componentCount"),
        threat_count=_count(raw, "threatCount"),
        countermeasure_count=_count(raw, "countermeasureCount"),
        taxonomy_count=_count(raw, "taxonomyCount"),
        depends_on=[entry for entry in depends_on if isinstance(entry, str | dict)]
        if isinstance(depends_on, list)
        else [],
        archive=archive,
        archive_size=archive_size,
        sha256=sha256,
        release=release,
        taxonomy_entry_count=_count(raw, "taxonomyEntryCount"),
        framework_count=_count(raw, "frameworkCount"),
        requirement_count=_count(raw, "requirementCount"),
        template_count=_count(raw, "templateCount"),
    )


def _parse_catalog(document: object) -> CatalogResult:
    """Check a catalog document. Raises ValueError when the whole catalog is unusable."""
    if not isinstance(document, dict):
        raise ValueError("catalog is not a JSON object")
    catalog_version = document.get("catalogVersion")
    if catalog_version != SUPPORTED_CATALOG_VERSION:
        raise ValueError(
            f"catalogVersion {catalog_version!r} is not supported "
            f"(this app reads version {SUPPORTED_CATALOG_VERSION})"
        )
    release = document.get("release")
    if not isinstance(release, str) or not _RELEASE_RE.match(release):
        raise ValueError(f"release {release!r} is not a valid release name")
    raw_entries = document.get("packs")
    if not isinstance(raw_entries, list):
        raise ValueError("packs is not a list")

    entries: list[CatalogEntry] = []
    seen_slugs: set[str] = set()
    for position, raw_entry in enumerate(raw_entries):
        try:
            entry = _entry_from_raw(raw_entry, release)
        except ValueError as reason:
            logger.warning("Pack catalog entry %d dropped: %s", position, reason)
            continue
        if entry.slug in seen_slugs:
            logger.warning(
                "Pack catalog entry %d dropped: slug %r appears twice",
                position,
                entry.slug,
            )
            continue
        seen_slugs.add(entry.slug)
        entries.append(entry)
    return CatalogResult(entries=entries, release=release, available=True, enabled=True)


def load_catalog(catalog_url: str | None = None) -> CatalogResult:
    """The catalog's packs, from the cache or one fetch. Never raises.

    catalog_url defaults to settings.PACK_CATALOG_URL. Taking it as an argument
    keeps a later list of catalogs a change in one place.
    """
    url = configured_catalog_url(catalog_url)
    if not url:
        return CatalogResult(entries=[], release="", available=False, enabled=False)

    cache_key = _cache_key(url)
    cached_result = cache.get(cache_key)
    if cached_result is not None:
        return cached_result
    unavailable = CatalogResult(entries=[], release="", available=False, enabled=True)
    if cache.get(cache_key + ":failed"):
        return unavailable

    try:
        with requests.get(
            url, timeout=CATALOG_FETCH_TIMEOUT_SECONDS, stream=True
        ) as response:
            response.raise_for_status()
            body = _read_limited(response, CATALOG_MAX_BYTES, "catalog.json")
        result = _parse_catalog(json.loads(body))
    except Exception as error:  # a network, HTTP, size or format failure
        logger.warning("Pack catalog unavailable from %s: %s", url, error)
        cache.set(cache_key + ":failed", True, FAILED_FETCH_MEMORY_SECONDS)
        return unavailable

    cache.set(cache_key, result, settings.PACK_CATALOG_TTL_SECONDS)
    return result


def archive_url(entry: CatalogEntry, catalog_url: str) -> str:
    """Where entry's archive is downloaded from.

    For GitHub's latest-release address, the archive comes from the release the
    entry was read from. Otherwise it sits in the same folder as catalog.json.
    Only the archive name and the release name, both pattern-checked, come from
    the catalog.
    """
    parts = urlsplit(catalog_url)
    if parts.path.endswith(LATEST_RELEASE_CATALOG_SUFFIX):
        base_path = parts.path[: -len(LATEST_RELEASE_CATALOG_SUFFIX)]
        archive_path = f"{base_path}/releases/download/{entry.release}/{entry.archive}"
    else:
        archive_path = parts.path.rsplit("/", 1)[0] + "/" + entry.archive
    return urlunsplit((parts.scheme, parts.netloc, archive_path, "", ""))


def _download_archive(entry: CatalogEntry, url: str, destination: Path) -> None:
    max_bytes = settings.PACK_DOWNLOAD_MAX_BYTES
    digest = hashlib.sha256()
    received_bytes = 0
    try:
        with requests.get(
            url,
            timeout=(ARCHIVE_CONNECT_TIMEOUT_SECONDS, ARCHIVE_READ_TIMEOUT_SECONDS),
            stream=True,
        ) as response:
            response.raise_for_status()
            declared_length = response.headers.get("Content-Length")
            if (
                declared_length
                and declared_length.isdigit()
                and int(declared_length) > max_bytes
            ):
                raise CatalogPackError(
                    f"Pack '{entry.slug}' is larger than the download limit."
                )
            with destination.open("wb") as archive_file:
                for chunk in response.iter_content(chunk_size=DOWNLOAD_CHUNK_BYTES):
                    received_bytes += len(chunk)
                    if received_bytes > max_bytes:
                        raise CatalogPackError(
                            f"Pack '{entry.slug}' is larger than the download limit."
                        )
                    digest.update(chunk)
                    archive_file.write(chunk)
    except requests.RequestException as error:
        logger.warning("Download of pack %s from %s failed: %s", entry.slug, url, error)
        raise CatalogPackError(
            f"Pack '{entry.slug}' could not be downloaded from the pack library."
        ) from None
    if received_bytes != entry.archive_size or digest.hexdigest() != entry.sha256:
        logger.warning(
            "Pack %s from %s does not match the catalog (%d bytes, sha256 %s)",
            entry.slug,
            url,
            received_bytes,
            digest.hexdigest(),
        )
        raise CatalogPackError(
            f"Pack '{entry.slug}' does not match the pack library's checksum. Nothing was imported."
        )


def _unpack_archive(entry: CatalogEntry, archive_path: Path, unpack_dir: Path) -> None:
    refused = CatalogPackError(
        f"Pack '{entry.slug}' contains files that are not allowed."
    )
    member_count = 0
    unpacked_bytes = 0
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            for member in archive:
                member_count += 1
                if member_count > UNPACKED_MAX_MEMBERS:
                    raise CatalogPackError(f"Pack '{entry.slug}' has too many files.")
                if not (member.isfile() or member.isdir()):
                    raise refused
                member_path = PurePosixPath(member.name)
                if (
                    member_path.is_absolute()
                    or ".." in member_path.parts
                    or not member_path.parts
                    or member_path.parts[0] != entry.slug
                ):
                    raise refused
                if (
                    member.isfile()
                    and member_path.suffix.lower() not in ALLOWED_PACK_FILE_SUFFIXES
                ):
                    raise refused
                unpacked_bytes += member.size
                if unpacked_bytes > UNPACKED_MAX_BYTES:
                    raise CatalogPackError(
                        f"Pack '{entry.slug}' is too large when unpacked."
                    )
                archive.extract(member, unpack_dir, filter="data")
    except (tarfile.TarError, EOFError, OSError) as error:
        logger.warning("Pack %s could not be unpacked: %s", entry.slug, error)
        raise CatalogPackError(f"Pack '{entry.slug}' could not be unpacked.") from None


def _check_unpacked_pack(entry: CatalogEntry, pack_dir: Path) -> None:
    mismatch = CatalogPackError(
        f"Pack '{entry.slug}' does not match its catalog entry."
    )
    pack_yaml = pack_dir / "pack.yaml"
    if not pack_yaml.is_file():
        raise mismatch
    try:
        pack_meta = (yaml.safe_load(pack_yaml.read_text()) or {}).get("pack") or {}
    except (yaml.YAMLError, UnicodeDecodeError, AttributeError):
        raise mismatch from None
    if (
        pack_meta.get("slug") != entry.slug
        or str(pack_meta.get("version", "0.0.0")) != entry.version
    ):
        raise mismatch


@contextmanager
def downloaded_pack(
    entry: CatalogEntry, catalog_url: str | None = None
) -> Iterator[Path]:
    """Download and unpack one pack into a temporary folder, yield the pack
    folder, and remove everything on exit."""
    url = configured_catalog_url(catalog_url)
    if not url:
        raise CatalogPackError("The pack library is turned off on this server.")
    with tempfile.TemporaryDirectory(prefix="precogly-pack-") as temporary_root:
        archive_path = Path(temporary_root) / "pack.tar.gz"
        unpack_dir = Path(temporary_root) / "unpacked"
        unpack_dir.mkdir()
        _download_archive(entry, archive_url(entry, url), archive_path)
        _unpack_archive(entry, archive_path, unpack_dir)
        pack_dir = unpack_dir / entry.slug
        _check_unpacked_pack(entry, pack_dir)
        yield pack_dir
