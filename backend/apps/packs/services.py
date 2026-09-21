"""
Pack discovery and import services.

This module provides services for:
- Discovering packs from the libraries folder
- Importing packs from YAML files into the database
- Syncing pack metadata from source files
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from django.conf import settings
from django.db import transaction

from apps.diagrams.models import DFDTemplatesLibrary
from apps.systems.models import ComponentLibrary
from apps.threats.models import (
    ComponentLibraryThreat,
    CountermeasureLibrary,
    ExternalTaxonomy,
    TaxonomyEntry,
    ThreatLibrary,
    ThreatLibraryTaxonomyEntry,
)

from .models import (
    LibraryPack,
    LibraryPackDependency,
    PendingFrameworkOverlay,
    PendingRequirementOverlay,
    PendingTaxonomyOverlay,
)

logger = logging.getLogger(__name__)


def _find_pack_dir(base_path: Path, pack_path: str) -> Path | None:
    """
    Resolve a pack's directory from its relative path.

    The path is relative to the libraries/packs root. This is an O(1)
    lookup: no scanning or YAML parsing of unrelated packs is needed.

    Returns None if the directory does not exist or has no pack.yaml.
    """
    if not pack_path:
        return None
    pack_dir = base_path / pack_path
    if pack_dir.is_dir() and (pack_dir / "pack.yaml").exists():
        return pack_dir
    return None


@dataclass
class PackInfo:
    """Information about a pack discovered from the libraries folder."""

    slug: str
    name: str
    description: str
    version: str
    pack_type: str
    schema_version: int = 1
    author: str = ""
    tags: list = field(default_factory=list)
    # Absolute filesystem path to the pack directory (for callers that
    # need to load files from disk).
    path: str = ""
    # Relative path from libraries/packs root, computed from filesystem
    # location. Used for O(1) lookup and dependency disambiguation.
    relative_path: str = ""
    is_in_database: bool = False
    database_version: str | None = None
    component_count: int = 0
    threat_count: int = 0
    countermeasure_count: int = 0
    taxonomy_count: int = 0
    depends_on: list = field(default_factory=list)

    def to_dict(self):
        return {
            "slug": self.slug,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "pack_type": self.pack_type,
            "schema_version": self.schema_version,
            "author": self.author,
            "tags": self.tags,
            "path": self.path,
            "relative_path": self.relative_path,
            "is_in_database": self.is_in_database,
            "database_version": self.database_version,
            "needs_update": self.is_in_database
            and self.database_version != self.version,
            "component_count": self.component_count,
            "threat_count": self.threat_count,
            "countermeasure_count": self.countermeasure_count,
            "taxonomy_count": self.taxonomy_count,
            "depends_on": self.depends_on,
        }


@dataclass
class ImportResult:
    """Result of a pack import operation."""

    success: bool
    pack_slug: str
    pack_name: str
    version: str
    message: str
    components_created: int = 0
    threats_created: int = 0
    countermeasures_created: int = 0
    templates_created: int = 0
    taxonomies_created: int = 0
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    def to_dict(self):
        return {
            "success": self.success,
            "pack_slug": self.pack_slug,
            "pack_name": self.pack_name,
            "version": self.version,
            "message": self.message,
            "components_created": self.components_created,
            "threats_created": self.threats_created,
            "countermeasures_created": self.countermeasures_created,
            "templates_created": self.templates_created,
            "taxonomies_created": self.taxonomies_created,
            "errors": self.errors,
            "warnings": self.warnings,
        }


def get_libraries_path() -> Path:
    """Get the path to the pack sources, under settings.LIBRARIES_PATH.

    One configured location rather than a search: where the directory is mounted is
    a deployment decision, and a search that ends up somewhere empty is
    indistinguishable from a database nobody has seeded.
    """
    return Path(settings.LIBRARIES_PATH) / "packs"


SUPPORTED_SCHEMA_VERSIONS = {1}

_SLUG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def _is_valid_slug(value: str) -> bool:
    """Check if a value matches the slug format: lowercase alphanumeric with hyphens."""
    return bool(_SLUG_RE.match(value))


def _count_items_in_file(file_path: Path, key: str) -> int:
    """Count items in a YAML file under a specific key."""
    if not file_path.exists():
        return 0
    try:
        with open(file_path) as f:
            data = yaml.safe_load(f) or {}
        return len(data.get(key, []))
    except Exception:
        return 0


def _discover_pack(
    pack_dir: Path, libraries_path: Path, existing_packs: dict
) -> PackInfo | None:
    """Discover a pack from its directory.

    The relative path is computed from the pack's actual filesystem
    location, so packs never need to declare where they live.
    """
    pack_yaml = pack_dir / "pack.yaml"
    if not pack_yaml.exists():
        return None

    try:
        with open(pack_yaml) as f:
            pack_data = yaml.safe_load(f)

        pack_meta = pack_data.get("pack", {})
        slug = pack_meta.get("slug", pack_dir.name)
        relative_path = str(pack_dir.relative_to(libraries_path)).replace("\\", "/")

        # Count items from separate files
        component_count = _count_items_in_file(
            pack_dir / "components.yaml", "components"
        )
        threat_count = _count_items_in_file(pack_dir / "threats.yaml", "threats")
        countermeasure_count = _count_items_in_file(
            pack_dir / "countermeasures.yaml", "countermeasures"
        )
        taxonomy_count = _count_items_in_file(pack_dir / "taxonomy.yaml", "taxonomies")

        return PackInfo(
            slug=slug,
            name=pack_meta.get("name", slug),
            description=pack_meta.get("description", ""),
            version=pack_meta.get("version", "0.0.0"),
            pack_type=pack_meta.get("pack_type", "technology"),
            schema_version=pack_meta.get("schema_version", 1),
            author=pack_meta.get("author", ""),
            tags=pack_meta.get("tags", []),
            path=str(pack_dir),
            relative_path=relative_path,
            is_in_database=slug in existing_packs,
            database_version=existing_packs.get(slug),
            component_count=component_count,
            threat_count=threat_count,
            countermeasure_count=countermeasure_count,
            taxonomy_count=taxonomy_count,
            depends_on=pack_meta.get("depends_on", []),
        )
    except Exception as e:
        logger.error(f"Error reading pack {pack_dir}: {e}")
        return None


def discover_packs_from_source() -> list[PackInfo]:
    """
    Discover all packs from the libraries folder.

    Scans the libraries/packs directory for packs and returns
    information about each pack found, including whether it exists in
    the database and if it needs updating.
    """
    libraries_path = get_libraries_path()
    packs = []

    if not libraries_path.exists():
        logger.warning(f"Libraries path does not exist: {libraries_path}")
        return packs

    # Get existing packs from database for comparison
    existing_packs = {p.slug: p.version for p in LibraryPack.objects.all()}

    # Scan for pack directories - support both flat and categorized structures
    def scan_directory(base_dir: Path):
        """Recursively scan for pack directories."""
        for item in base_dir.iterdir():
            if not item.is_dir():
                continue

            # Check if this directory is a pack (has pack.yaml)
            if (item / "pack.yaml").exists():
                pack_info = _discover_pack(item, libraries_path, existing_packs)
                if pack_info:
                    packs.append(pack_info)
            else:
                # This might be a category directory, scan it recursively
                scan_directory(item)

    scan_directory(libraries_path)

    # Resolve depends_on entries to {slug, name, is_imported} dicts.
    # Dependencies can reference packs in two ways:
    #   1. By slug only (legacy): `depends_on: [pack-slug]` or
    #      `depends_on: [{pack: pack-slug, version: "^1.0.0"}]`
    #   2. By slug + path (disambiguating): `depends_on: [{pack: pack-slug,
    #      path: frameworks/pack-slug, version: "^1.0.0"}]`
    # The path-based form is required when multiple packs share a slug on
    # disk; without it, the resolver picks the first match.
    pack_by_path = {p.relative_path: p for p in packs if p.relative_path}
    pack_by_slug: dict[str, PackInfo] = {}
    for p in packs:
        # Keep the first occurrence — disambiguation happens via `path`.
        pack_by_slug.setdefault(p.slug, p)

    for pack_info in packs:
        resolved_dependencies = []
        for dep_entry in pack_info.depends_on:
            if isinstance(dep_entry, str):
                dep_slug = dep_entry.split("/")[-1] if "/" in dep_entry else dep_entry
                dep_path = dep_entry if "/" in dep_entry else ""
            else:
                dep_slug = dep_entry.get("pack", dep_entry.get("slug", ""))
                dep_path = dep_entry.get("path", "")

            dep = pack_by_path.get(dep_path) if dep_path else pack_by_slug.get(dep_slug)
            resolved_dependencies.append(
                {
                    "slug": dep_slug,
                    "path": dep_path or (dep.relative_path if dep else ""),
                    "name": dep.name if dep else dep_slug,
                    "is_imported": dep_slug in existing_packs,
                }
            )
        pack_info.depends_on = resolved_dependencies

    return packs


def get_pack_preview_from_source(pack_relative_path: str) -> dict | None:
    """
    Get full pack content for preview from the libraries folder.

    Reads pack metadata from pack.yaml and components/threats/countermeasures
    from their respective YAML files. Uses the pack's relative path from the
    libraries/packs root for O(1) directory lookup.

    Args:
        pack_relative_path: Relative path from libraries/packs root (e.g. "threat-libraries/aws",
            "standards/nist-csf")

    Returns:
        Dictionary with pack metadata, components, threats, and countermeasures
        or None if pack not found
    """
    libraries_path = get_libraries_path()

    if not libraries_path.exists():
        return None

    pack_dir = _find_pack_dir(libraries_path, pack_relative_path)
    if not pack_dir:
        return None

    try:
        pack_yaml = pack_dir / "pack.yaml"
        with open(pack_yaml) as f:
            pack_data = yaml.safe_load(f)

        return _extract_pack_preview(pack_dir, pack_data)
    except Exception as e:
        logger.error(f"Error reading pack {pack_dir}: {e}")
        return None


def get_pack_preview_from_database(pack: "LibraryPack") -> dict | None:
    """
    Get full pack content for preview from a database pack.

    Reads preview data from the source YAML files rather than the database,
    ensuring consistent results regardless of how the pack was imported.
    Scans the libraries tree to find the pack directory by slug.

    Args:
        pack: The LibraryPack model instance

    Returns:
        Dictionary with pack metadata, components, threats, and countermeasures
        or None if pack not found on disk
    """
    libraries_path = get_libraries_path()
    if not libraries_path.exists():
        return None

    for pack_yaml in libraries_path.rglob("pack.yaml"):
        try:
            with open(pack_yaml) as f:
                pack_data = yaml.safe_load(f)
            if pack_data.get("pack", {}).get("slug") == pack.slug:
                return _extract_pack_preview(pack_yaml.parent, pack_data)
        except Exception:
            logger.debug("Failed to read pack.yaml at %s", pack_yaml)
            continue

    return None


def _extract_pack_preview(pack_dir: Path, pack_data: dict) -> dict:
    """
    Extract preview data from separate YAML files.

    Reads components/threats/countermeasures from their respective files
    in the pack directory.

    Args:
        pack_dir: Path to the pack directory
        pack_data: The pack.yaml content as a dictionary

    Returns:
        Structured preview dictionary with snake_case keys (auto-converted by middleware)
    """
    pack_meta = pack_data.get("pack", {})

    # Load components from components.yaml
    components = []
    components_file = pack_dir / "components.yaml"
    if components_file.exists():
        try:
            with open(components_file) as f:
                comp_data = yaml.safe_load(f) or {}
            for comp in comp_data.get("components", []):
                components.append(
                    {
                        "slug": comp.get("slug", comp.get("id", "")),
                        "name": comp.get("name", ""),
                        "category": comp.get("category", ""),
                        "component_type": comp.get(
                            "type", comp.get("component_type", "")
                        ),
                        "description": comp.get("description", ""),
                    }
                )
        except Exception as e:
            logger.error(f"Error reading components.yaml in {pack_dir}: {e}")

    # Load threats from threats.yaml
    threats = []
    threats_file = pack_dir / "threats.yaml"
    if threats_file.exists():
        try:
            with open(threats_file) as f:
                threat_data = yaml.safe_load(f) or {}
            for threat in threat_data.get("threats", []):
                threats.append(
                    {
                        "slug": threat.get("slug", threat.get("id", "")),
                        "name": threat.get("name", ""),
                        "taxonomy_entries": [],
                        "severity": threat.get("severity", ""),
                        "description": threat.get("description", ""),
                    }
                )
        except Exception as e:
            logger.error(f"Error reading threats.yaml in {pack_dir}: {e}")

    # Build taxonomy entries from join files
    joins_dir = pack_dir / "joins"
    if joins_dir.exists():
        threat_slug_to_idx = {t["slug"]: i for i, t in enumerate(threats)}
        for join_file in joins_dir.glob("threats-*.yaml"):
            if join_file.name == "threats-countermeasures.yaml":
                continue
            try:
                with open(join_file) as f:
                    join_data = yaml.safe_load(f) or {}
                taxonomy_slug = join_data.get("taxonomy", "")
                for mapping in join_data.get("mappings", []):
                    threat_ref = mapping.get("threat", "")
                    idx = threat_slug_to_idx.get(threat_ref)
                    if idx is None:
                        continue
                    for entry_id in mapping.get("entries", []):
                        title = str(entry_id).replace("-", " ").title()
                        threats[idx]["taxonomy_entries"].append(
                            {
                                "taxonomy_slug": taxonomy_slug,
                                "external_id": str(entry_id),
                                "title": title,
                            }
                        )
            except Exception as e:
                logger.error(f"Error reading join file {join_file}: {e}")

    # Load countermeasures from countermeasures.yaml
    countermeasures = []
    cm_file = pack_dir / "countermeasures.yaml"
    if cm_file.exists():
        try:
            with open(cm_file) as f:
                cm_data = yaml.safe_load(f) or {}
            for cm in cm_data.get("countermeasures", []):
                countermeasures.append(
                    {
                        "slug": cm.get("slug", cm.get("id", "")),
                        "name": cm.get("name", ""),
                        "control_type": cm.get("control_type", ""),
                        "control_functions": cm.get("control_functions")
                        or ([cm["control_type"]] if cm.get("control_type") else []),
                        "control_nature": cm.get("control_nature", ""),
                        "cost": cm.get("cost", ""),
                        "default_status": cm.get("default_status", "gap"),
                        "description": cm.get("description", ""),
                    }
                )
        except Exception as e:
            logger.error(f"Error reading countermeasures.yaml in {pack_dir}: {e}")

    # Extract requirements from frameworks section (for compliance packs)
    requirements = []
    for framework in pack_data.get("frameworks", []):
        for req in framework.get("requirements", []):
            requirements.append(
                {
                    "section_code": req.get("section_code", ""),
                    "description": req.get("description", ""),
                    "framework_name": framework.get("name", ""),
                }
            )

    # Load taxonomies from taxonomy.yaml
    taxonomies = []
    taxonomy_file = pack_dir / "taxonomy.yaml"
    if taxonomy_file.exists():
        try:
            with open(taxonomy_file) as f:
                tax_data = yaml.safe_load(f) or {}
            for taxonomy in tax_data.get("taxonomies", []):
                raw_entries = taxonomy.get("entries", [])
                entries = [
                    {
                        "external_id": entry.get("external_id", ""),
                        "title": entry.get("title", ""),
                        "description": entry.get("description", ""),
                    }
                    for entry in raw_entries
                ]
                taxonomies.append(
                    {
                        "slug": taxonomy.get("slug", ""),
                        "name": taxonomy.get("name", ""),
                        "description": taxonomy.get("description", ""),
                        "entry_count": len(raw_entries),
                        "entries": entries,
                    }
                )
        except Exception as e:
            logger.error(f"Error reading taxonomy.yaml in {pack_dir}: {e}")

    return {
        "pack": {
            "slug": pack_meta.get("slug", ""),
            "name": pack_meta.get("name", ""),
            "description": pack_meta.get("description", ""),
            "version": pack_meta.get("version", ""),
            "pack_type": pack_meta.get("pack_type", ""),
            "author": pack_meta.get("author", ""),
            "tags": pack_meta.get("tags", []),
        },
        "components": components,
        "threats": threats,
        "countermeasures": countermeasures,
        "requirements": requirements,
        "taxonomies": taxonomies,
    }


@dataclass
class ValidationError:
    """A reference validation error."""

    file: str
    line: int | None
    ref_type: str  # 'component', 'threat', 'countermeasure', 'template_component'
    reference: str
    message: str


@dataclass
class ValidationWarning:
    """A structural validation warning that allows import with user confirmation."""

    file: str
    field: str
    message: str
    suggestion: str


@dataclass
class ValidationResult:
    """Result of pack validation."""

    success: bool
    pack_slug: str
    pack_name: str
    version: str
    errors: list[ValidationError] = field(default_factory=list)
    warnings: list[ValidationWarning] = field(default_factory=list)

    def to_dict(self):
        return {
            "success": self.success,
            "pack_slug": self.pack_slug,
            "pack_name": self.pack_name,
            "version": self.version,
            "errors": [
                {
                    "file": e.file,
                    "line": e.line,
                    "ref_type": e.ref_type,
                    "reference": e.reference,
                    "message": e.message,
                }
                for e in self.errors
            ],
            "warnings": [
                {
                    "file": w.file,
                    "field": w.field,
                    "message": w.message,
                    "suggestion": w.suggestion,
                }
                for w in self.warnings
            ],
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
        }


def validate_pack(pack_path: Path) -> ValidationResult:
    """
    Validate a pack's structure and references without importing.

    Performs two categories of checks:
    1. Structural checks: metadata, enum values, slug vs id key usage
    2. Reference checks: cross-file references in joins and templates

    Errors block import entirely. Warnings allow "Import Anyway".

    Args:
        pack_path: Path to the pack directory

    Returns:
        ValidationResult with any errors or warnings found
    """
    pack_yaml = pack_path / "pack.yaml"

    if not pack_yaml.exists():
        return ValidationResult(
            success=False,
            pack_slug="",
            pack_name="",
            version="",
            errors=[
                ValidationError(
                    file="pack.yaml",
                    line=None,
                    ref_type="pack",
                    reference="",
                    message="pack.yaml not found",
                )
            ],
        )

    try:
        with open(pack_yaml) as f:
            pack_data = yaml.safe_load(f)
    except Exception as e:
        return ValidationResult(
            success=False,
            pack_slug="",
            pack_name="",
            version="",
            errors=[
                ValidationError(
                    file="pack.yaml",
                    line=None,
                    ref_type="pack",
                    reference="",
                    message=f"Failed to parse pack.yaml: {e}",
                )
            ],
        )

    pack_meta = pack_data.get("pack", {})
    slug = pack_meta.get("slug", "")
    name = pack_meta.get("name", slug)
    version = pack_meta.get("version", "0.0.0")

    errors = []
    warnings = []

    # Structural checks

    # Required metadata fields
    required_metadata = ["slug", "name", "version", "pack_type"]
    for required_field in required_metadata:
        if required_field not in pack_meta:
            errors.append(
                ValidationError(
                    file="pack.yaml",
                    line=None,
                    ref_type="pack",
                    reference=required_field,
                    message=f"Missing required field: {required_field}",
                )
            )

    # Schema version check
    schema_version = pack_meta.get("schema_version")
    if schema_version is None:
        warnings.append(
            ValidationWarning(
                file="pack.yaml",
                field="schema_version",
                message="Missing schema_version field",
                suggestion="Add 'schema_version: 1' to the pack section. This will be required in a future release.",
            )
        )
    elif schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        errors.append(
            ValidationError(
                file="pack.yaml",
                line=None,
                ref_type="pack",
                reference="schema_version",
                message=(
                    f"Unsupported schema_version: {schema_version}."
                    f" Supported versions: {sorted(SUPPORTED_SCHEMA_VERSIONS)}"
                ),
            )
        )

    # Pack slug format
    if slug and not _is_valid_slug(slug):
        warnings.append(
            ValidationWarning(
                file="pack.yaml",
                field="slug",
                message=f"Pack slug '{slug}' does not match expected format",
                suggestion="Slugs should be lowercase alphanumeric with hyphens (e.g. 'my-pack-name').",
            )
        )

    # Valid pack_type enum
    valid_pack_types = {
        "technology",
        "threat",
        "countermeasure",
        "compliance",
        "template",
        "full",
        "taxonomy",
    }
    pack_type_value = pack_meta.get("pack_type", "")
    if pack_type_value and pack_type_value not in valid_pack_types:
        warnings.append(
            ValidationWarning(
                file="pack.yaml",
                field="pack_type",
                message=f"Unknown pack_type: '{pack_type_value}'",
                suggestion=f"Use one of: {', '.join(sorted(valid_pack_types))}",
            )
        )

    # Validate depends_on entries exist on disk or in DB
    depends_on_entries = pack_meta.get("depends_on", [])
    if depends_on_entries:
        libraries_path = get_libraries_path()
        for dep_entry in depends_on_entries:
            if isinstance(dep_entry, str):
                dep_slug = dep_entry.split("/")[-1] if "/" in dep_entry else dep_entry
                dep_path = dep_entry
            else:
                dep_slug = dep_entry.get("pack", dep_entry.get("slug", ""))
                dep_path = dep_entry.get("path", dep_slug)

            # Check on disk
            dep_dir = _find_pack_dir(libraries_path, dep_path)
            if not dep_dir and dep_path != dep_slug:
                dep_dir = _find_pack_dir(libraries_path, dep_slug)
            # Check in DB
            dep_in_db = LibraryPack.objects.filter(slug=dep_slug).exists()

            if not dep_dir and not dep_in_db:
                warnings.append(
                    ValidationWarning(
                        file="pack.yaml",
                        field="depends_on",
                        message=f"Dependency '{dep_slug}' not found on disk or in database",
                        suggestion="Import the dependency pack first or verify the slug/path is correct.",
                    )
                )

    # Framework entries use 'slug' not 'id'; check for duplicate section_codes
    for framework_data in pack_data.get("frameworks", []):
        if "id" in framework_data and "slug" not in framework_data:
            warnings.append(
                ValidationWarning(
                    file="pack.yaml",
                    field="frameworks[].id",
                    message=f"Framework uses 'id' instead of 'slug' (id: '{framework_data['id']}')",
                    suggestion="Rename 'id' to 'slug'. Frameworks use 'slug' because they are shared across packs.",
                )
            )
        fw_slug = framework_data.get("slug", framework_data.get("id", ""))
        if fw_slug and not _is_valid_slug(fw_slug):
            warnings.append(
                ValidationWarning(
                    file="pack.yaml",
                    field="frameworks[].slug",
                    message=f"Framework slug '{fw_slug}' does not match slug format",
                    suggestion="Slugs should be lowercase alphanumeric with hyphens (e.g. 'my-framework').",
                )
            )
        seen_section_codes: set[str] = set()
        for req in framework_data.get("requirements", []):
            section_code = req.get("section_code", "")
            if section_code:
                if section_code in seen_section_codes:
                    errors.append(
                        ValidationError(
                            file="pack.yaml",
                            line=None,
                            ref_type="framework",
                            reference=section_code,
                            message=f"Duplicate section_code '{section_code}' in framework '{fw_slug}'",
                        )
                    )
                else:
                    seen_section_codes.add(section_code)

    # Taxonomy entries use 'slug' not 'id'; check for duplicate external_ids
    taxonomy_file = pack_path / "taxonomy.yaml"
    if taxonomy_file.exists():
        try:
            with open(taxonomy_file) as f:
                tax_data = yaml.safe_load(f) or {}
            for taxonomy_data in tax_data.get("taxonomies", []):
                if "id" in taxonomy_data and "slug" not in taxonomy_data:
                    warnings.append(
                        ValidationWarning(
                            file="taxonomy.yaml",
                            field="taxonomies[].id",
                            message=f"Taxonomy uses 'id' instead of 'slug' (id: '{taxonomy_data['id']}')",
                            suggestion=(
                                "Rename 'id' to 'slug'. Taxonomies use 'slug'"
                                " because they are shared across packs."
                            ),
                        )
                    )
                tax_slug = taxonomy_data.get("slug", taxonomy_data.get("id", ""))
                if tax_slug and not _is_valid_slug(tax_slug):
                    warnings.append(
                        ValidationWarning(
                            file="taxonomy.yaml",
                            field="taxonomies[].slug",
                            message=f"Taxonomy slug '{tax_slug}' does not match slug format",
                            suggestion="Slugs should be lowercase alphanumeric with hyphens (e.g. 'my-taxonomy').",
                        )
                    )
                seen_external_ids: set[str] = set()
                for entry in taxonomy_data.get("entries", []):
                    external_id = str(entry.get("external_id", ""))
                    if external_id:
                        if external_id in seen_external_ids:
                            errors.append(
                                ValidationError(
                                    file="taxonomy.yaml",
                                    line=None,
                                    ref_type="taxonomy",
                                    reference=external_id,
                                    message=f"Duplicate external_id '{external_id}' in taxonomy '{tax_slug}'",
                                )
                            )
                        else:
                            seen_external_ids.add(external_id)
        except Exception:
            logger.debug(
                "Parse error in taxonomy file, caught in reference checks below"
            )

    # Components must have 'id', check for duplicates
    components_file = pack_path / "components.yaml"
    if components_file.exists():
        try:
            with open(components_file) as f:
                comp_data = yaml.safe_load(f) or {}
            valid_categories = {
                "process",
                "datastore",
                "external_human_actor",
                "external_system_actor",
            }
            seen_component_ids: set[str] = set()
            for i, comp in enumerate(comp_data.get("components", [])):
                if "id" not in comp and "slug" not in comp:
                    errors.append(
                        ValidationError(
                            file="components.yaml",
                            line=None,
                            ref_type="component",
                            reference=f"components[{i}]",
                            message=f"Component at index {i} has no 'id' field",
                        )
                    )
                else:
                    comp_id = comp.get("id", comp.get("slug", ""))
                    if comp_id in seen_component_ids:
                        errors.append(
                            ValidationError(
                                file="components.yaml",
                                line=None,
                                ref_type="component",
                                reference=comp_id,
                                message=f"Duplicate component id '{comp_id}' at index {i}",
                            )
                        )
                    else:
                        seen_component_ids.add(comp_id)
                    if comp_id and not _is_valid_slug(comp_id):
                        warnings.append(
                            ValidationWarning(
                                file="components.yaml",
                                field="id",
                                message=f"Component id '{comp_id}' does not match slug format",
                                suggestion="Slugs should be lowercase alphanumeric with hyphens (e.g. 'my-component').",
                            )
                        )
                category_value = comp.get("category", "")
                if category_value and category_value not in valid_categories:
                    warnings.append(
                        ValidationWarning(
                            file="components.yaml",
                            field="category",
                            message=(
                                f"Component '{comp.get('id', comp.get('slug', f'[{i}]'))}'"
                                f" has unknown category: '{category_value}'"
                            ),
                            suggestion=f"Use one of: {', '.join(sorted(valid_categories))}",
                        )
                    )
        except Exception:
            logger.debug("Failed to parse components.yaml for validation")

    # Threats must have 'id', check for duplicates
    threats_file = pack_path / "threats.yaml"
    if threats_file.exists():
        try:
            with open(threats_file) as f:
                threat_data = yaml.safe_load(f) or {}
            seen_threat_ids: set[str] = set()
            for i, threat in enumerate(threat_data.get("threats", [])):
                if "id" not in threat and "slug" not in threat:
                    errors.append(
                        ValidationError(
                            file="threats.yaml",
                            line=None,
                            ref_type="threat",
                            reference=f"threats[{i}]",
                            message=f"Threat at index {i} has no 'id' field",
                        )
                    )
                else:
                    threat_id = threat.get("id", threat.get("slug", ""))
                    if threat_id in seen_threat_ids:
                        errors.append(
                            ValidationError(
                                file="threats.yaml",
                                line=None,
                                ref_type="threat",
                                reference=threat_id,
                                message=f"Duplicate threat id '{threat_id}' at index {i}",
                            )
                        )
                    else:
                        seen_threat_ids.add(threat_id)
                    if threat_id and not _is_valid_slug(threat_id):
                        warnings.append(
                            ValidationWarning(
                                file="threats.yaml",
                                field="id",
                                message=f"Threat id '{threat_id}' does not match slug format",
                                suggestion="Slugs should be lowercase alphanumeric with hyphens (e.g. 'my-threat').",
                            )
                        )
        except Exception:
            logger.debug("Failed to parse threats.yaml for validation")

    # Countermeasures must have 'id', check for duplicates, and validate control fields/cost enums
    valid_control_functions = {
        "preventive",
        "detective",
        "corrective",
        "deterrent",
        "recovery",
        "compensating",
    }
    valid_control_natures = {"technical", "administrative", "physical"}
    valid_costs = {"low", "medium", "high"}
    cm_file = pack_path / "countermeasures.yaml"
    if cm_file.exists():
        try:
            with open(cm_file) as f:
                cm_data_raw = yaml.safe_load(f) or {}
            seen_cm_ids: set[str] = set()
            for i, cm in enumerate(cm_data_raw.get("countermeasures", [])):
                cm_id = cm.get("id", cm.get("slug", ""))
                if "id" not in cm and "slug" not in cm:
                    errors.append(
                        ValidationError(
                            file="countermeasures.yaml",
                            line=None,
                            ref_type="countermeasure",
                            reference=f"countermeasures[{i}]",
                            message=f"Countermeasure at index {i} has no 'id' field",
                        )
                    )
                elif cm_id:
                    if cm_id in seen_cm_ids:
                        errors.append(
                            ValidationError(
                                file="countermeasures.yaml",
                                line=None,
                                ref_type="countermeasure",
                                reference=cm_id,
                                message=f"Duplicate countermeasure id '{cm_id}' at index {i}",
                            )
                        )
                    else:
                        seen_cm_ids.add(cm_id)
                    if not _is_valid_slug(cm_id):
                        warnings.append(
                            ValidationWarning(
                                file="countermeasures.yaml",
                                field="id",
                                message=f"Countermeasure id '{cm_id}' does not match slug format",
                                suggestion=(
                                    "Slugs should be lowercase alphanumeric"
                                    " with hyphens (e.g. 'my-countermeasure')."
                                ),
                            )
                        )
                control_functions_value = cm.get("control_functions", [])
                if isinstance(control_functions_value, list):
                    for fn in control_functions_value:
                        if fn not in valid_control_functions:
                            warnings.append(
                                ValidationWarning(
                                    file="countermeasures.yaml",
                                    field="control_functions",
                                    message=(
                                        f"Countermeasure '{cm_id or f'[{i}]'}'"
                                        f" has unknown control function: '{fn}'"
                                    ),
                                    suggestion=f"Use one of: {', '.join(sorted(valid_control_functions))}",
                                )
                            )
                control_nature_value = cm.get("control_nature", "")
                if (
                    control_nature_value
                    and control_nature_value not in valid_control_natures
                ):
                    warnings.append(
                        ValidationWarning(
                            file="countermeasures.yaml",
                            field="control_nature",
                            message=(
                                f"Countermeasure '{cm_id or f'[{i}]'}'"
                                f" has unknown control_nature: '{control_nature_value}'"
                            ),
                            suggestion=f"Use one of: {', '.join(sorted(valid_control_natures))}",
                        )
                    )
                control_type_value = cm.get("control_type", "")
                if (
                    control_type_value
                    and control_type_value not in valid_control_functions
                ):
                    warnings.append(
                        ValidationWarning(
                            file="countermeasures.yaml",
                            field="control_type",
                            message=(
                                f"Countermeasure '{cm_id or f'[{i}]'}'"
                                f" has unknown control_type: '{control_type_value}'"
                                " (legacy field, prefer control_functions)"
                            ),
                            suggestion=(
                                "Use control_functions with one of:"
                                f" {', '.join(sorted(valid_control_functions))}"
                            ),
                        )
                    )
                cost_value = cm.get("cost", "")
                if cost_value and cost_value not in valid_costs:
                    warnings.append(
                        ValidationWarning(
                            file="countermeasures.yaml",
                            field="cost",
                            message=f"Countermeasure '{cm_id or f'[{i}]'}' has unknown cost: '{cost_value}'",
                            suggestion=f"Use one of: {', '.join(sorted(valid_costs))}",
                        )
                    )
        except Exception:
            logger.debug("Failed to parse countermeasures.yaml for validation")

    # =========================================================================
    # Reference checks (existing logic)
    # =========================================================================

    # Collect all defined items in this pack
    pack_components = set()
    pack_threats = set()
    pack_countermeasures = set()

    # Load components from components.yaml
    components_file = pack_path / "components.yaml"
    if components_file.exists():
        try:
            with open(components_file) as f:
                comp_data = yaml.safe_load(f) or {}
            for comp in comp_data.get("components", []):
                comp_id = comp.get("id", comp.get("slug", ""))
                if comp_id:
                    pack_components.add(comp_id)
        except Exception as e:
            errors.append(
                ValidationError(
                    file="components.yaml",
                    line=None,
                    ref_type="component",
                    reference="",
                    message=f"Failed to parse: {e}",
                )
            )

    # Load threats from threats.yaml
    threats_file = pack_path / "threats.yaml"
    if threats_file.exists():
        try:
            with open(threats_file) as f:
                threat_data = yaml.safe_load(f) or {}
            for threat in threat_data.get("threats", []):
                threat_id = threat.get("id", threat.get("slug", ""))
                if threat_id:
                    pack_threats.add(threat_id)
        except Exception as e:
            errors.append(
                ValidationError(
                    file="threats.yaml",
                    line=None,
                    ref_type="threat",
                    reference="",
                    message=f"Failed to parse: {e}",
                )
            )

    # Load countermeasures from countermeasures.yaml
    cm_file = pack_path / "countermeasures.yaml"
    if cm_file.exists():
        try:
            with open(cm_file) as f:
                cm_data = yaml.safe_load(f) or {}
            for cm in cm_data.get("countermeasures", []):
                cm_id = cm.get("id", cm.get("slug", ""))
                if cm_id:
                    pack_countermeasures.add(cm_id)
        except Exception as e:
            errors.append(
                ValidationError(
                    file="countermeasures.yaml",
                    line=None,
                    ref_type="countermeasure",
                    reference="",
                    message=f"Failed to parse: {e}",
                )
            )

    # Validate joins
    joins_dir = pack_path / "joins"
    if joins_dir.exists():
        # Validate component-threat joins
        ct_file = joins_dir / "components-threats.yaml"
        if ct_file.exists():
            try:
                with open(ct_file) as f:
                    ct_data = yaml.safe_load(f) or {}
                for mapping in ct_data.get("mappings", []):
                    comp_ref = mapping.get("component", "")
                    if (
                        comp_ref
                        and "/" not in comp_ref
                        and comp_ref not in pack_components
                    ):
                        errors.append(
                            ValidationError(
                                file="joins/components-threats.yaml",
                                line=None,
                                ref_type="component",
                                reference=comp_ref,
                                message=f"Component '{comp_ref}' not found in pack",
                            )
                        )

                    for threat_entry in mapping.get("threats", []):
                        if not isinstance(threat_entry, dict):
                            errors.append(
                                ValidationError(
                                    file="joins/components-threats.yaml",
                                    line=None,
                                    ref_type="threat",
                                    reference=str(threat_entry),
                                    message=(
                                        f"Invalid threat entry format: expected a dict "
                                        f"with 'threat' and 'applies_to' keys, got "
                                        f"{type(threat_entry).__name__} '{threat_entry}'"
                                    ),
                                )
                            )
                            continue
                        threat_ref = threat_entry.get("threat", "")
                        if (
                            threat_ref
                            and "/" not in threat_ref
                            and threat_ref not in pack_threats
                            and not _resolve_threat_reference_exists(slug, threat_ref)
                        ):
                            errors.append(
                                ValidationError(
                                    file="joins/components-threats.yaml",
                                    line=None,
                                    ref_type="threat",
                                    reference=threat_ref,
                                    message=f"Threat '{threat_ref}' not found in pack or database",
                                )
                            )
            except Exception as e:
                errors.append(
                    ValidationError(
                        file="joins/components-threats.yaml",
                        line=None,
                        ref_type="join",
                        reference="",
                        message=f"Failed to parse: {e}",
                    )
                )

        # Validate threat-countermeasure joins
        tc_file = joins_dir / "threats-countermeasures.yaml"
        if tc_file.exists():
            try:
                with open(tc_file) as f:
                    tc_data = yaml.safe_load(f) or {}
                for mapping in tc_data.get("mappings", []):
                    threat_ref = mapping.get("threat", "")
                    if (
                        threat_ref
                        and "/" not in threat_ref
                        and threat_ref not in pack_threats
                        and not _resolve_threat_reference_exists(slug, threat_ref)
                    ):
                        errors.append(
                            ValidationError(
                                file="joins/threats-countermeasures.yaml",
                                line=None,
                                ref_type="threat",
                                reference=threat_ref,
                                message=f"Threat '{threat_ref}' not found in pack or database",
                            )
                        )

                    for cm_ref in mapping.get("countermeasures", []):
                        if (
                            "/" not in cm_ref
                            and cm_ref not in pack_countermeasures
                            and not _resolve_countermeasure_reference_exists(
                                slug, cm_ref
                            )
                        ):
                            errors.append(
                                ValidationError(
                                    file="joins/threats-countermeasures.yaml",
                                    line=None,
                                    ref_type="countermeasure",
                                    reference=cm_ref,
                                    message=f"Countermeasure '{cm_ref}' not found in pack or database",
                                )
                            )
            except Exception as e:
                errors.append(
                    ValidationError(
                        file="joins/threats-countermeasures.yaml",
                        line=None,
                        ref_type="join",
                        reference="",
                        message=f"Failed to parse: {e}",
                    )
                )

        # Validate threat-taxonomy joins
        # Build pool of known taxonomy slugs
        known_taxonomy_slugs = set()

        # From this pack's own taxonomy.yaml
        if taxonomy_file.exists():
            try:
                with open(taxonomy_file) as f:
                    own_tax_data = yaml.safe_load(f) or {}
                for t in own_tax_data.get("taxonomies", []):
                    if t.get("slug"):
                        known_taxonomy_slugs.add(t["slug"])
            except Exception:
                logger.debug("Failed to parse taxonomy.yaml for validation")

        # From dependency packs' taxonomy.yaml files
        dep_entries = pack_meta.get("depends_on", [])
        if dep_entries:
            libraries_path = get_libraries_path()
            for dep_entry in dep_entries:
                if isinstance(dep_entry, str):
                    dep_slug = dep_entry
                    dep_path = dep_entry
                else:
                    dep_slug = dep_entry.get("pack", dep_entry.get("slug", ""))
                    dep_path = dep_entry.get("path", dep_slug)

                dep_dir = _find_pack_dir(libraries_path, dep_path)
                if not dep_dir and dep_path != dep_slug:
                    dep_dir = _find_pack_dir(libraries_path, dep_slug)
                if not dep_dir:
                    # Fallback: search for pack with matching slug
                    for nested_pack_yaml in libraries_path.glob("**/pack.yaml"):
                        try:
                            with open(nested_pack_yaml) as f:
                                nested_pack_data = yaml.safe_load(f) or {}
                            if nested_pack_data.get("pack", {}).get("slug") == dep_slug:
                                dep_dir = nested_pack_yaml.parent
                                break
                        except Exception:
                            logger.debug("Failed to read %s", nested_pack_yaml)
                            continue

                if dep_dir:
                    dep_tax_file = dep_dir / "taxonomy.yaml"
                    if dep_tax_file.exists():
                        try:
                            with open(dep_tax_file) as f:
                                dep_tax_data = yaml.safe_load(f) or {}
                            for t in dep_tax_data.get("taxonomies", []):
                                if t.get("slug"):
                                    known_taxonomy_slugs.add(t["slug"])
                        except Exception:
                            logger.debug(
                                "Failed to parse dep taxonomy %s", dep_tax_file
                            )

        # Fallback: also check database for already-imported taxonomies
        db_taxonomy_slugs = set(ExternalTaxonomy.objects.values_list("slug", flat=True))
        known_taxonomy_slugs |= db_taxonomy_slugs

        for join_file in joins_dir.glob("threats-*.yaml"):
            if join_file.name == "threats-countermeasures.yaml":
                continue
            try:
                with open(join_file) as f:
                    join_data = yaml.safe_load(f) or {}
                taxonomy_ref = join_data.get("taxonomy", "")
                if taxonomy_ref and taxonomy_ref not in known_taxonomy_slugs:
                    errors.append(
                        ValidationError(
                            file=f"joins/{join_file.name}",
                            line=None,
                            ref_type="taxonomy",
                            reference=taxonomy_ref,
                            message=(
                                f"Taxonomy '{taxonomy_ref}' not found. "
                                f"Note: taxonomy slugs come from taxonomy.yaml, "
                                f"not from the pack slug. "
                                f"Available taxonomies: {sorted(known_taxonomy_slugs)}"
                            ),
                        )
                    )

                # Also validate threat references in mappings
                for mapping in join_data.get("mappings", []):
                    threat_ref = mapping.get("threat", "")
                    if (
                        threat_ref
                        and "/" not in threat_ref
                        and threat_ref not in pack_threats
                        and not _resolve_threat_reference_exists(slug, threat_ref)
                    ):
                        errors.append(
                            ValidationError(
                                file=f"joins/{join_file.name}",
                                line=None,
                                ref_type="threat",
                                reference=threat_ref,
                                message=f"Threat '{threat_ref}' not found in pack or database",
                            )
                        )
            except Exception as e:
                errors.append(
                    ValidationError(
                        file=f"joins/{join_file.name}",
                        line=None,
                        ref_type="join",
                        reference="",
                        message=f"Failed to parse: {e}",
                    )
                )

    # Validate overlay section_codes against frameworks in the DB
    if joins_dir.exists():
        from apps.compliance.models import StandardFramework, StandardRequirement

        for overlay_file in joins_dir.glob("countermeasures-*.yaml"):
            if "threats" in overlay_file.name:
                continue
            try:
                with open(overlay_file) as f:
                    overlay_data = yaml.safe_load(f) or {}
                framework_slug = overlay_data.get("framework", "")
                if not framework_slug:
                    continue

                framework = StandardFramework.objects.filter(
                    slug=framework_slug
                ).first()
                if not framework:
                    warnings.append(
                        ValidationWarning(
                            file=f"joins/{overlay_file.name}",
                            field="framework",
                            message=(
                                f"Framework '{framework_slug}' not found in database"
                                " (overlay will be stored as pending)"
                            ),
                            suggestion=(
                                "Import the framework pack first, or the overlay will"
                                " activate automatically when the framework is imported."
                            ),
                        )
                    )
                    continue

                # Framework exists — validate each section_code
                framework_section_codes = set(
                    StandardRequirement.objects.filter(framework=framework).values_list(
                        "section_code", flat=True
                    )
                )
                for mapping in overlay_data.get("mappings", []):
                    for req_code in mapping.get("requirements", []):
                        if str(req_code) not in framework_section_codes:
                            errors.append(
                                ValidationError(
                                    file=f"joins/{overlay_file.name}",
                                    line=None,
                                    ref_type="framework",
                                    reference=str(req_code),
                                    message=f"section_code '{req_code}' not found in framework '{framework_slug}'",
                                )
                            )
            except Exception as e:
                errors.append(
                    ValidationError(
                        file=f"joins/{overlay_file.name}",
                        line=None,
                        ref_type="overlay",
                        reference="",
                        message=f"Failed to parse: {e}",
                    )
                )

    # Validate DFD templates
    templates_dir = pack_path / "dfd-templates"

    if templates_dir.exists():
        for template_file in list(templates_dir.glob("*.yaml")) + list(
            templates_dir.glob("*.yml")
        ):
            try:
                with open(template_file) as f:
                    template_data = yaml.safe_load(f)

                canvas_data = template_data.get("canvas_data", {})
                for node in canvas_data.get("nodes", []):
                    comp_ref = node.get("data", {}).get("component_ref")
                    if (
                        comp_ref
                        and "/" not in comp_ref
                        and comp_ref not in pack_components
                        and not _resolve_component_reference_exists(slug, comp_ref)
                    ):
                        errors.append(
                            ValidationError(
                                file=f"dfd-templates/{template_file.name}",
                                line=None,
                                ref_type="template_component",
                                reference=comp_ref,
                                message=f"Component '{comp_ref}' not found in pack or database",
                            )
                        )
            except Exception as e:
                errors.append(
                    ValidationError(
                        file=f"dfd-templates/{template_file.name}",
                        line=None,
                        ref_type="template",
                        reference="",
                        message=f"Failed to parse: {e}",
                    )
                )

    return ValidationResult(
        success=len(errors) == 0,
        pack_slug=slug,
        pack_name=name,
        version=version,
        errors=errors,
        warnings=warnings,
    )


# Backwards-compatible alias
validate_pack_references = validate_pack


def _resolve_component_reference_exists(pack_slug: str, ref: str) -> bool:
    """Check if a component reference exists in the database."""
    if "/" in ref:
        return ComponentLibrary.objects.filter(qualified_slug=ref).exists()
    else:
        qualified_slug = f"{pack_slug}/{ref}"
        return ComponentLibrary.objects.filter(qualified_slug=qualified_slug).exists()


def _resolve_threat_reference_exists(pack_slug: str, ref: str) -> bool:
    """Check if a threat reference exists in the database."""
    if "/" in ref:
        return ThreatLibrary.objects.filter(qualified_slug=ref).exists()
    else:
        qualified_slug = f"{pack_slug}/{ref}"
        if ThreatLibrary.objects.filter(qualified_slug=qualified_slug).exists():
            return True
        # Also check global threats
        return ThreatLibrary.objects.filter(qualified_slug=f"global/{ref}").exists()


def _resolve_countermeasure_reference_exists(pack_slug: str, ref: str) -> bool:
    """Check if a countermeasure reference exists in the database."""
    if "/" in ref:
        return CountermeasureLibrary.objects.filter(qualified_slug=ref).exists()
    else:
        qualified_slug = f"{pack_slug}/{ref}"
        return CountermeasureLibrary.objects.filter(
            qualified_slug=qualified_slug
        ).exists()


def import_pack_from_path(
    pack_path: Path,
    force: bool = False,
    selected_overlays: list[str] | None = None,
    dry_run: bool = False,
    skip_validation: bool = False,
) -> ImportResult | ValidationResult:
    """
    Import a pack from a directory path.

    Args:
        pack_path: Path to the pack directory containing pack.yaml
        force: If True, reinstall even if pack exists
        selected_overlays: Optional list of framework IDs to load overlays for.
                          If None, all overlays are loaded. If empty list, no overlays.
        dry_run: If True, validate references without importing
        skip_validation: If True, skip pre-import validation (used by batch sync)

    Returns:
        ImportResult with details of the import operation, or ValidationResult if dry_run
    """
    if dry_run:
        return validate_pack(pack_path)
    return _import_pack(pack_path, force, selected_overlays, skip_validation)


def _import_pack(
    pack_path: Path,
    force: bool = False,
    selected_overlays: list[str] | None = None,
    skip_validation: bool = False,
) -> ImportResult | ValidationResult:
    """
    Import a pack from a directory path.

    Expects multi-file structure:
    - pack.yaml: Metadata only
    - components.yaml: Component definitions
    - threats.yaml: Threat definitions
    - countermeasures.yaml: Countermeasure definitions
    - joins/: Relationship mappings
    - dfd-templates/: DFD templates

    Args:
        pack_path: Path to the pack directory
        force: If True, reinstall even if pack exists
        selected_overlays: Optional list of framework IDs to load overlays for.
                          If None, all overlays are loaded. If empty list, no overlays.
        skip_validation: If True, skip pre-import validation
    """
    import_warnings: list[str] = []
    # Run validation before import unless skipped
    if not skip_validation:
        validation_result = validate_pack(pack_path)
        if not validation_result.success or validation_result.warnings:
            return validation_result

    pack_yaml = pack_path / "pack.yaml"

    if not pack_yaml.exists():
        return ImportResult(
            success=False,
            pack_slug="",
            pack_name="",
            version="",
            message=f"pack.yaml not found in {pack_path}",
            errors=[f"pack.yaml not found in {pack_path}"],
        )

    try:
        with open(pack_yaml) as f:
            pack_data = yaml.safe_load(f)
    except Exception as e:
        return ImportResult(
            success=False,
            pack_slug="",
            pack_name="",
            version="",
            message=f"Failed to parse pack.yaml: {e}",
            errors=[str(e)],
        )

    pack_meta = pack_data.get("pack", {})
    slug = pack_meta.get("slug", "")
    name = pack_meta.get("name", slug)
    version = pack_meta.get("version", "0.0.0")

    # Validate required fields
    required_fields = ["slug", "name", "version", "pack_type"]
    missing = [f for f in required_fields if f not in pack_meta]
    if missing:
        return ImportResult(
            success=False,
            pack_slug=slug,
            pack_name=name,
            version=version,
            message=f"Missing required fields: {missing}",
            errors=[f"Missing required field: {f}" for f in missing],
        )

    # Check if pack exists
    existing = LibraryPack.objects.filter(slug=slug).first()

    if existing and not force:
        # Count items in database
        active_components = ComponentLibrary.objects.filter(
            source_pack=existing
        ).count()
        active_threats = ThreatLibrary.objects.filter(source_pack=existing).count()
        active_countermeasures = CountermeasureLibrary.objects.filter(
            source_pack=existing
        ).count()
        active_taxonomies = ExternalTaxonomy.objects.filter(
            source_pack=existing
        ).count()
        active_templates = DFDTemplatesLibrary.objects.filter(
            source_pack=existing
        ).count()

        has_active_items = (
            active_components > 0
            or active_threats > 0
            or active_countermeasures > 0
            or active_taxonomies > 0
            or active_templates > 0
        )

        if has_active_items:
            if version != existing.version:
                return ImportResult(
                    success=False,
                    pack_slug=slug,
                    pack_name=name,
                    version=existing.version,
                    message=(
                        f"Pack '{slug}' has a newer version on disk"
                        f" (v{version} != v{existing.version})."
                        " Use force=True to upgrade."
                    ),
                )
            return ImportResult(
                success=True,
                pack_slug=slug,
                pack_name=name,
                version=existing.version,
                message=f"Pack '{slug}' already exists (v{existing.version}). Use force=True to reimport.",
            )
        else:
            logger.info(f"Pack '{slug}' exists but has no items. Creating items...")

    try:
        with transaction.atomic():
            # Hard delete existing items if forcing reinstall
            if existing and force:
                logger.warning(
                    "Force reimporting pack '%s' — existing component, threat,"
                    " and countermeasure instance links will be orphaned"
                    " (set to NULL).",
                    slug,
                )
                _hard_delete_pack_items(existing)

            # Create/update LibraryPack
            library_pack = _create_or_update_pack(pack_data, pack_path, import_warnings)

            # Process dependencies
            _process_dependencies(library_pack, pack_data)

            # Load taxonomies (before threats, since threats reference taxonomy entries)
            taxonomy_file = pack_path / "taxonomy.yaml"
            taxonomies_count = _load_taxonomy(
                library_pack, taxonomy_file, import_warnings
            )

            # Load components
            components_file = pack_path / "components.yaml"
            components_count = _load_components(
                library_pack, components_file, import_warnings
            )

            # Load threats
            threats_file = pack_path / "threats.yaml"
            threats_count = _load_threats(library_pack, threats_file, import_warnings)

            # Load countermeasures
            cm_file = pack_path / "countermeasures.yaml"
            countermeasures_count = _load_countermeasures(
                library_pack, cm_file, import_warnings
            )

            # Phase 2: Load join files
            joins_dir = pack_path / "joins"
            if joins_dir.exists():
                _load_component_threat_joins(
                    library_pack, joins_dir / "components-threats.yaml", import_warnings
                )
                _load_threat_countermeasure_joins(
                    library_pack,
                    joins_dir / "threats-countermeasures.yaml",
                    import_warnings,
                )

                # Load threat-taxonomy joins
                for join_file in joins_dir.glob("threats-*.yaml"):
                    if join_file.name == "threats-countermeasures.yaml":
                        continue
                    _load_threat_taxonomy_joins(
                        library_pack, join_file, import_warnings
                    )

                # Phase 3: Load framework overlays
                for join_file in joins_dir.glob("countermeasures-*.yaml"):
                    if "threats" in join_file.name:
                        continue
                    # Check if we should load this overlay
                    if selected_overlays is not None:
                        # Read the framework ID from the file to check against selected list
                        try:
                            with open(join_file) as f:
                                overlay_data = yaml.safe_load(f) or {}
                            framework_id = overlay_data.get("framework", "")
                            if framework_id not in selected_overlays:
                                logger.info(
                                    "Skipping overlay %s (framework %s not selected)",
                                    join_file.name,
                                    framework_id,
                                )
                                continue
                        except Exception as e:
                            logger.error(
                                f"Error reading overlay file {join_file.name}: {e}"
                            )
                            continue
                    logger.info(f"Loading framework overlay: {join_file.name}")
                    mappings_count = _load_framework_overlay(
                        library_pack, join_file, import_warnings
                    )
                    logger.info(
                        f"Loaded {mappings_count} mappings from {join_file.name}"
                    )

                # Phase 3b: Load requirement overlays
                for join_file in joins_dir.glob("requirements-*.yaml"):
                    logger.info(f"Loading requirement overlay: {join_file.name}")
                    req_mappings_count = _load_requirement_overlay(
                        library_pack, join_file, import_warnings
                    )
                    logger.info(
                        f"Loaded {req_mappings_count} requirement mappings "
                        f"from {join_file.name}"
                    )

            # Phase 4: Load DFD templates
            templates_count = _load_templates(
                library_pack, pack_path / "dfd-templates", import_warnings
            )

            # Phase 5: Load frameworks and requirements (for compliance packs)
            _load_frameworks(library_pack, pack_data, import_warnings)

        # Outside the transaction, so this reads committed data.
        #
        # `import_single` imports one pack at a time and never reached the
        # third pass in `sync_all_packs_from_source()`, so importing a
        # taxonomy pack on its own left every referencing pack's joins
        # unresolved, and re-importing one CASCADE-deleted the joins pointing
        # into it with nothing to rebuild them. Reconciling after the commit
        # is what makes a single-pack import see the rest of the catalog as
        # it now stands, rather than re-reading the same snapshot that
        # produced the gap.
        #
        # Scoped to taxonomy packs, since only they own `ExternalTaxonomy`
        # rows and so only they can invalidate or satisfy another pack's
        # joins. Every other pack type leaves the taxonomy catalog untouched,
        # and scanning all packs' join files after an unrelated import would
        # be pure cost.
        #
        # Deliberately not also gated on `existing and force`. That would
        # cover only the re-import half of the problem, and this function's
        # own docstring names the other half: a join fails to resolve when
        # "the taxonomy pack owning the referenced code has not been imported
        # yet", which is a first import, where `existing` is None and `force`
        # is False. Those joins are parked as PendingTaxonomyOverlay rows, and
        # this pass is what settles them.
        #
        # Best effort: this pack's own import has already committed and
        # succeeded, so a failure here is logged rather than raised.
        if pack_meta.get("pack_type", "") == "taxonomy":
            try:
                reconcile_taxonomy_joins_from_source()
            except Exception:
                logger.exception(
                    f"Taxonomy join reconciliation failed after importing pack "
                    f"'{slug}'. The pack itself imported successfully; only the "
                    f"catalog-wide retry failed."
                )

        return ImportResult(
            success=True,
            pack_slug=slug,
            pack_name=name,
            version=version,
            message=f"Successfully imported {name} v{version} (v2 format)",
            components_created=components_count,
            threats_created=threats_count,
            countermeasures_created=countermeasures_count,
            templates_created=templates_count,
            taxonomies_created=taxonomies_count,
            warnings=import_warnings,
        )

    except Exception as e:
        logger.exception(f"Failed to import v2 pack {slug}")
        return ImportResult(
            success=False,
            pack_slug=slug,
            pack_name=name,
            version=version,
            message=f"Import failed: {e}",
            errors=[str(e)],
        )


def sync_all_packs_from_source(
    force: bool = False,
) -> list[ImportResult | ValidationResult]:
    """
    Sync all packs from the libraries folder to the database.

    Args:
        force: If True, reinstall all packs even if they exist

    Returns:
        List of ImportResult for each pack processed
    """
    packs = discover_packs_from_source()
    results = []

    for pack_info in packs:
        # Skip if already in database, not forcing, and version unchanged
        if (
            pack_info.is_in_database
            and not force
            and pack_info.database_version == pack_info.version
        ):
            results.append(
                ImportResult(
                    success=True,
                    pack_slug=pack_info.slug,
                    pack_name=pack_info.name,
                    version=pack_info.version,
                    message=f"Pack already up to date (v{pack_info.version})",
                )
            )
            continue

        # Validate before importing — skip packs with issues
        validation_result = validate_pack(Path(pack_info.path))
        if not validation_result.success or validation_result.warnings:
            validation_result.success = False
            results.append(validation_result)
            continue

        # Import the pack (already validated above)
        result = import_pack_from_path(
            Path(pack_info.path),
            force=force,
            skip_validation=True,
        )
        results.append(result)

    # Second pass: re-apply cross-framework requirement overlays.
    # During force re-import, activation can create mappings using stale
    # framework objects from the previous run. When those frameworks are
    # later re-imported, CASCADE deletes destroy the mappings and the
    # pending overlay has already been consumed. Re-loading from disk
    # after all frameworks exist fixes this ordering issue.
    if force:
        for pack_info in packs:
            pack = LibraryPack.objects.filter(slug=pack_info.slug).first()
            if not pack:
                continue
            joins_dir = Path(pack_info.path) / "joins"
            if not joins_dir.exists():
                continue
            for join_file in joins_dir.glob("requirements-*.yaml"):
                _load_requirement_overlay(pack, join_file)

    # Third pass: re-apply taxonomy joins.
    # Same ordering issue as requirement overlays — taxonomy packs may
    # be re-imported after the threat packs that reference them, causing
    # CASCADE deletes to destroy the mappings. Re-loading from disk
    # after all taxonomies exist fixes this.
    #
    # Deliberately outside the `if force:` block above. A non-forced sync
    # skips any pack whose version is unchanged, but it still re-imports
    # packs whose version *did* change — and a taxonomy pack's re-import
    # CASCADE-deletes every join pointing into it. If the pack carrying
    # those joins was skipped, nothing rebuilds them, so the taxonomy is
    # left correct with nothing referring to it. Re-reading the joins is
    # idempotent (`_load_threat_taxonomy_joins` writes through
    # get_or_create/update_or_create), so running it unconditionally only
    # costs the re-read.
    reconcile_taxonomy_joins_from_source(packs)

    # Fourth pass: re-apply cross-pack threat-countermeasure and
    # component-threat joins. Same ordering issue as taxonomy joins:
    # pack A may reference threats/countermeasures from pack B via
    # qualified slugs (e.g. "ai/llm-prompt-injection"), but pack B
    # may not have been imported yet when pack A's joins were loaded.
    # Re-reading the joins once all packs are in the database resolves
    # every cross-pack reference that was missed on the first pass.
    reconcile_cross_pack_joins_from_source(packs)

    return results


def reconcile_cross_pack_joins_from_source(
    packs: list["PackInfo"] | None = None,
) -> int:
    """Re-apply every pack's component-threat and threat-countermeasure joins.

    Cross-pack joins (those using qualified slugs like "ai/llm-prompt-injection")
    resolve by database lookup. If the referenced pack has not been imported yet,
    the lookup returns None and a warning is logged. Re-reading the joins after
    all packs are imported resolves these dangling references.

    Both loaders are idempotent (update_or_create / M2M .add()), so re-running
    for already-resolved joins is a harmless no-op.

    Returns:
        Total number of join matches resolved across all packs.
    """
    if packs is None:
        packs = discover_packs_from_source()

    total = 0
    for pack_info in packs:
        pack = LibraryPack.objects.filter(slug=pack_info.slug).first()
        if not pack:
            continue
        joins_dir = Path(pack_info.path) / "joins"
        if not joins_dir.exists():
            continue

        components_threats_file = joins_dir / "components-threats.yaml"
        if components_threats_file.exists():
            total += _load_component_threat_joins(pack, components_threats_file)

        threats_countermeasures_file = joins_dir / "threats-countermeasures.yaml"
        if threats_countermeasures_file.exists():
            total += _load_threat_countermeasure_joins(
                pack, threats_countermeasures_file
            )

    return total


def reconcile_taxonomy_joins_from_source(
    packs: list["PackInfo"] | None = None,
) -> int:
    """Re-apply every pack's threat-taxonomy joins from disk.

    A threat-taxonomy join is resolved by looking up the referenced
    `TaxonomyEntry` at the moment its own pack is imported. That lookup can
    fail for reasons outside the pack being imported: most often the taxonomy
    pack owning the referenced code has not been imported yet, or is
    re-imported afterwards to add the code in question. The join is then
    recorded as a `PendingTaxonomyOverlay` with a warning, and the pack's own
    import still reports success.

    Re-reading every pack's joins once the whole catalog is in its final state
    closes that gap. Every write is get_or_create/update_or_create, so
    re-running it for a join that already resolved is a no-op.

    Args:
        packs: Packs to reconcile. Runs its own `discover_packs_from_source()`
            if omitted.

    Returns:
        Number of threat-taxonomy join matches resolved across every pack,
        including joins that already existed and were simply re-confirmed.
    """
    if packs is None:
        packs = discover_packs_from_source()

    total = 0
    for pack_info in packs:
        pack = LibraryPack.objects.filter(slug=pack_info.slug).first()
        if not pack:
            continue
        joins_dir = Path(pack_info.path) / "joins"
        if not joins_dir.exists():
            continue
        for join_file in joins_dir.glob("threats-*.yaml"):
            if join_file.name == "threats-countermeasures.yaml":
                continue
            total += _load_threat_taxonomy_joins(pack, join_file)

    return total


# =============================================================================
# Private helper functions
# =============================================================================


def _hard_delete_pack_items(pack: LibraryPack):
    """Hard delete all library items from a pack.

    Note: Instance models use SET_NULL for library FKs, so deleting library items
    will orphan instances but not delete them. This preserves user work.
    """
    from apps.compliance.models import StandardFramework, StandardRequirementMapping

    ComponentLibrary.objects.filter(source_pack=pack).delete()
    ThreatLibrary.objects.filter(source_pack=pack).delete()
    CountermeasureLibrary.objects.filter(source_pack=pack).delete()
    DFDTemplatesLibrary.objects.filter(source_pack=pack).delete()
    ExternalTaxonomy.objects.filter(source_pack=pack).delete()
    StandardRequirementMapping.objects.filter(source_pack=pack).delete()
    PendingRequirementOverlay.objects.filter(pack=pack).delete()
    PendingTaxonomyOverlay.objects.filter(pack=pack).delete()
    StandardFramework.objects.filter(source_pack=pack).delete()


def _create_or_update_pack(
    pack_data: dict, pack_path: Path, import_warnings: list[str] | None = None
) -> LibraryPack:
    """Create or update the LibraryPack record."""
    pack = pack_data["pack"]
    slug = pack["slug"]

    icon_svg = ""
    icon_path = pack.get("icon", "")
    if icon_path:
        icon_file = pack_path / icon_path
        if icon_file.exists():
            try:
                icon_svg = icon_file.read_text(encoding="utf-8")
            except Exception as e:
                msg = f"Could not read pack icon '{icon_path}' for '{slug}': {e}"
                logger.warning(msg)
                if import_warnings is not None:
                    import_warnings.append(msg)

    library_pack, _ = LibraryPack.objects.update_or_create(
        slug=slug,
        defaults={
            "name": pack["name"],
            "description": pack.get("description", ""),
            "version": pack["version"],
            "pack_type": pack["pack_type"],
            "author": pack.get("author", ""),
            "icon_svg": icon_svg,
            "tags": pack.get("tags", []),
        },
    )

    return library_pack


def _process_dependencies(library_pack: LibraryPack, pack_data: dict):
    """Process pack dependencies with version constraints.

    Dependencies may include an optional `path` field for disambiguating
    between packs that share a slug on disk. The DB enforces slug
    uniqueness, so once imported a slug refers to exactly one pack —
    `path` is informational here and only affects which pack on disk we
    consider the dependency target. We log when path is given but the
    matching pack isn't yet imported, since the dependency record will
    be created without it.
    """
    depends_on = pack_data.get("pack", {}).get("depends_on", [])

    # Clear existing dependencies
    LibraryPackDependency.objects.filter(pack=library_pack).delete()

    for dep in depends_on:
        if isinstance(dep, str):
            dep_slug = dep.split("/")[-1] if "/" in dep else dep
        else:
            dep_slug = dep.get("pack", dep.get("slug", ""))

        # Find the dependency pack (may not exist yet). Slug uniqueness
        # in the DB makes the lookup unambiguous regardless of how many
        # disk variants share the slug.
        dep_pack = LibraryPack.objects.filter(slug=dep_slug).first()
        if dep_pack:
            LibraryPackDependency.objects.create(
                pack=library_pack,
                depends_on_pack=dep_pack,
            )


def _resolve_threat_reference(
    library_pack: LibraryPack, threat_ref: str
) -> ThreatLibrary | None:
    """Resolve a threat reference (slug or qualified slug)."""
    if "/" in threat_ref:
        return ThreatLibrary.objects.filter(qualified_slug=threat_ref).first()

    # Try current pack first
    qualified = f"{library_pack.slug}/{threat_ref}"
    threat = ThreatLibrary.objects.filter(qualified_slug=qualified).first()

    if not threat:
        # Try global
        threat = ThreatLibrary.objects.filter(
            qualified_slug=f"global/{threat_ref}"
        ).first()

    return threat


# =============================================================================
# V2 Format Loader Functions
# =============================================================================


def _load_threat_taxonomy_joins(
    library_pack: LibraryPack, file_path: Path, import_warnings: list[str] | None = None
) -> int:
    """Load threat-taxonomy mappings from joins/threats-{taxonomy}.yaml."""
    if import_warnings is None:
        import_warnings = []
    if not file_path.exists():
        return 0

    try:
        with open(file_path) as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        logger.error(f"Error loading threat taxonomy join {file_path}: {e}")
        return 0

    taxonomy_slug = data.get("taxonomy", "")
    if not taxonomy_slug:
        msg = f"No taxonomy specified in {file_path}"
        logger.warning(msg)
        import_warnings.append(msg)
        return 0

    taxonomy_exists = ExternalTaxonomy.objects.filter(slug=taxonomy_slug).exists()

    if not taxonomy_exists:
        # Store as pending overlay for later activation
        logger.info(
            f"Taxonomy '{taxonomy_slug}' not found. Storing overlay as pending."
        )
        mapping_count = len(data.get("mappings", []))
        PendingTaxonomyOverlay.objects.update_or_create(
            pack=library_pack,
            taxonomy_slug=taxonomy_slug,
            defaults={
                "overlay_file_name": file_path.name,
                "overlay_data": data,
                "mapping_count": mapping_count,
            },
        )
        return 0

    # Taxonomy exists - ensure pending overlay is stored for future re-activation
    # (e.g. if the taxonomy is unimported then re-imported later)
    mapping_count = len(data.get("mappings", []))
    PendingTaxonomyOverlay.objects.update_or_create(
        pack=library_pack,
        taxonomy_slug=taxonomy_slug,
        defaults={
            "overlay_file_name": file_path.name,
            "overlay_data": data,
            "mapping_count": mapping_count,
        },
    )

    count = 0
    for mapping in data.get("mappings", []):
        threat_ref = mapping.get("threat", "")
        if not threat_ref:
            continue

        threat_obj = _resolve_threat_reference(library_pack, threat_ref)
        if not threat_obj:
            msg = f"Threat not found: {threat_ref}"
            logger.warning(msg)
            import_warnings.append(msg)
            continue

        for external_id in mapping.get("entries", []):
            try:
                taxonomy_entry = TaxonomyEntry.objects.get(
                    taxonomy__slug=taxonomy_slug,
                    external_id=str(external_id),
                )
                ThreatLibraryTaxonomyEntry.objects.get_or_create(
                    threat_library=threat_obj,
                    taxonomy_entry=taxonomy_entry,
                )
                count += 1
            except TaxonomyEntry.DoesNotExist:
                msg = (
                    f"Taxonomy entry {taxonomy_slug}:{external_id} not found. "
                    f"Check that '{taxonomy_slug}' matches the slug in taxonomy.yaml "
                    f"(not the pack slug). Import the taxonomy pack first if not yet imported."
                )
                logger.warning(msg)
                import_warnings.append(msg)

    return count


def _load_taxonomy(
    library_pack: LibraryPack, file_path: Path, import_warnings: list[str] | None = None
) -> int:
    """Load taxonomies and entries from taxonomy.yaml."""
    if import_warnings is None:
        import_warnings = []
    if not file_path.exists():
        return 0

    try:
        with open(file_path) as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        logger.error(f"Error loading taxonomy.yaml: {e}")
        return 0

    count = 0
    for taxonomy_data in data.get("taxonomies", []):
        slug = taxonomy_data.get("slug", "")
        if not slug:
            msg = "Skipping taxonomy without slug"
            logger.warning(msg)
            import_warnings.append(msg)
            continue

        existing_taxonomy = ExternalTaxonomy.objects.filter(slug=slug).first()
        is_new_taxonomy = existing_taxonomy is None
        if (
            existing_taxonomy
            and existing_taxonomy.source_pack
            and existing_taxonomy.source_pack != library_pack
        ):
            msg = (
                f"Taxonomy '{slug}' source_pack changing"
                f" from '{existing_taxonomy.source_pack.slug}'"
                f" to '{library_pack.slug}'"
            )
            logger.warning(msg)
            import_warnings.append(msg)

        taxonomy_obj, _ = ExternalTaxonomy.objects.update_or_create(
            slug=slug,
            defaults={
                "source_pack": library_pack,
                "name": taxonomy_data.get("name", slug),
                "description": taxonomy_data.get("description", ""),
                "source_url": taxonomy_data.get("source_url", ""),
                "version": taxonomy_data.get("version", ""),
            },
        )

        for entry_data in taxonomy_data.get("entries", []):
            external_id = entry_data.get("external_id", "")
            if not external_id:
                continue
            TaxonomyEntry.objects.update_or_create(
                taxonomy=taxonomy_obj,
                external_id=str(external_id),
                defaults={
                    "title": entry_data.get("title", external_id),
                    "description": entry_data.get("description", ""),
                    "reference_url": entry_data.get("reference_url", ""),
                },
            )

        # Activate pending taxonomy overlays for newly created taxonomies
        if is_new_taxonomy:
            result = activate_pending_taxonomy_overlays(slug)
            if result.get("total_mappings", 0) > 0:
                logger.info(
                    f"Activated {result['total_mappings']} pending taxonomy overlay "
                    f"mappings for taxonomy '{slug}'"
                )

        count += 1

    return count


def activate_pending_taxonomy_overlays(taxonomy_slug: str) -> dict:
    """
    Activate all pending taxonomy overlays for a newly installed taxonomy.

    Called when a taxonomy is installed to apply any taxonomy join overlays
    that were waiting for this taxonomy.

    Args:
        taxonomy_slug: The slug of the taxonomy that was just installed

    Returns:
        Dictionary with activation results including counts per pack
    """
    taxonomy = ExternalTaxonomy.objects.filter(slug=taxonomy_slug).first()
    if not taxonomy:
        logger.error(
            f"Cannot activate taxonomy overlays: Taxonomy '{taxonomy_slug}' not found"
        )
        return {"success": False, "error": "Taxonomy not found", "activated": 0}

    pending_overlays = PendingTaxonomyOverlay.objects.filter(
        taxonomy_slug=taxonomy_slug
    )

    results = {
        "success": True,
        "taxonomy": taxonomy_slug,
        "taxonomy_name": taxonomy.name,
        "packs_activated": [],
        "total_mappings": 0,
    }

    for pending in pending_overlays:
        pack = pending.pack
        data = pending.overlay_data
        mappings_applied = 0

        for mapping in data.get("mappings", []):
            threat_ref = mapping.get("threat", "")
            if not threat_ref:
                continue

            threat_obj = _resolve_threat_reference(pack, threat_ref)
            if not threat_obj:
                logger.warning(
                    f"Threat not found during taxonomy activation: {threat_ref}"
                )
                continue

            for external_id in mapping.get("entries", []):
                try:
                    taxonomy_entry = TaxonomyEntry.objects.get(
                        taxonomy__slug=taxonomy_slug,
                        external_id=str(external_id),
                    )
                    ThreatLibraryTaxonomyEntry.objects.get_or_create(
                        threat_library=threat_obj,
                        taxonomy_entry=taxonomy_entry,
                    )
                    mappings_applied += 1
                except TaxonomyEntry.DoesNotExist:
                    logger.warning(
                        f"Taxonomy entry {taxonomy_slug}:{external_id} not found "
                        f"during activation"
                    )

        results["packs_activated"].append(
            {
                "pack_slug": pack.slug,
                "pack_name": pack.name,
                "mappings_applied": mappings_applied,
            }
        )
        results["total_mappings"] += mappings_applied

        # Keep pending overlay for future re-activation (e.g. taxonomy unimport/re-import).
        # CASCADE on pack FK handles cleanup when the source pack is unimported.

    logger.info(
        f"Activated {len(results['packs_activated'])} pending taxonomy overlays "
        f"for taxonomy '{taxonomy_slug}' "
        f"with {results['total_mappings']} total mappings"
    )

    return results


def _load_components(
    library_pack: LibraryPack, file_path: Path, import_warnings: list[str] | None = None
) -> int:
    """Load components from components.yaml.

    Uses a two-pass approach to handle parent references:
      Pass 1: Create/update all ComponentLibrary records with parent=None.
      Pass 2: Resolve parent slug references and set the FK.
    """
    if import_warnings is None:
        import_warnings = []
    if not file_path.exists():
        return 0

    try:
        with open(file_path) as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        logger.error(f"Error loading components.yaml: {e}")
        return 0

    components_list = data.get("components", [])

    # Pass 1: Create/update all records without parent
    slug_to_instance = {}
    count = 0
    for comp in components_list:
        comp_id = comp.get("id", comp.get("slug", ""))
        if not comp_id:
            msg = f"Skipping component without id: {comp}"
            logger.warning(msg)
            import_warnings.append(msg)
            continue

        qualified_slug = f"{library_pack.slug}/{comp_id}"

        icon_svg = ""
        icon_path = comp.get("icon", "")
        if icon_path:
            icon_file = file_path.parent / icon_path
            if icon_file.exists():
                try:
                    icon_svg = icon_file.read_text(encoding="utf-8")
                except Exception as e:
                    msg = f"Could not read icon '{icon_path}' for '{comp_id}': {e}"
                    logger.warning(msg)
                    import_warnings.append(msg)

        instance, _ = ComponentLibrary.objects.update_or_create(
            qualified_slug=qualified_slug,
            defaults={
                "source_pack": library_pack,
                "slug": comp_id,
                "name": comp.get("name", comp_id),
                "category": comp.get("category", "process"),
                "component_type": comp.get("type", comp.get("component_type", "")),
                "provider": comp.get("provider", ""),
                "icon_svg": icon_svg,
                "customization_status": "original",
                "parent": None,
            },
        )
        slug_to_instance[comp_id] = instance
        count += 1

    # Pass 2: Resolve parent references
    for comp in components_list:
        parent_slug = comp.get("parent")
        if not parent_slug:
            continue

        comp_id = comp.get("id", comp.get("slug", ""))
        child_instance = slug_to_instance.get(comp_id)
        parent_instance = slug_to_instance.get(parent_slug)

        if not child_instance or not parent_instance:
            msg = (
                f"Cannot resolve parent '{parent_slug}' for component "
                f"'{comp_id}' — skipping parent assignment."
            )
            logger.warning(msg)
            import_warnings.append(msg)
            continue

        if child_instance.category != ComponentLibrary.Category.PROCESS:
            msg = (
                f"Component '{comp_id}' has category '{child_instance.category}' "
                f"but only process components can have a parent — skipping."
            )
            logger.warning(msg)
            import_warnings.append(msg)
            continue

        if parent_instance.category != ComponentLibrary.Category.PROCESS:
            msg = (
                f"Parent '{parent_slug}' has category '{parent_instance.category}' "
                f"but only process components can be parents — skipping."
            )
            logger.warning(msg)
            import_warnings.append(msg)
            continue

        child_instance.parent = parent_instance
        try:
            child_instance.full_clean()
            child_instance.save(update_fields=["parent"])
        except Exception as e:
            msg = f"Invalid parent assignment '{parent_slug}' -> '{comp_id}': {e}"
            logger.warning(msg)
            import_warnings.append(msg)
            child_instance.parent = None
            child_instance.save(update_fields=["parent"])

    return count


def _load_threats(
    library_pack: LibraryPack, file_path: Path, import_warnings: list[str] | None = None
) -> int:
    """Load threats from threats.yaml (v2 format)."""
    if import_warnings is None:
        import_warnings = []
    if not file_path.exists():
        return 0

    try:
        with open(file_path) as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        logger.error(f"Error loading threats.yaml: {e}")
        return 0

    count = 0
    for threat in data.get("threats", []):
        threat_id = threat.get("id", threat.get("slug", ""))
        if not threat_id:
            msg = f"Skipping threat without id: {threat}"
            logger.warning(msg)
            import_warnings.append(msg)
            continue

        qualified_slug = f"{library_pack.slug}/{threat_id}"

        ThreatLibrary.objects.update_or_create(
            qualified_slug=qualified_slug,
            defaults={
                "source_pack": library_pack,
                "slug": threat_id,
                "name": threat.get("name", threat_id),
                "description": threat.get("description", ""),
                "customization_status": "original",
            },
        )

        count += 1

    return count


def _load_countermeasures(
    library_pack: LibraryPack, file_path: Path, import_warnings: list[str] | None = None
) -> int:
    """Load countermeasures from countermeasures.yaml (v2 format)."""
    if import_warnings is None:
        import_warnings = []
    if not file_path.exists():
        return 0

    try:
        with open(file_path) as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        logger.error(f"Error loading countermeasures.yaml: {e}")
        return 0

    count = 0
    for cm in data.get("countermeasures", []):
        cm_id = cm.get("id", cm.get("slug", ""))
        if not cm_id:
            msg = f"Skipping countermeasure without id: {cm}"
            logger.warning(msg)
            import_warnings.append(msg)
            continue

        qualified_slug = f"{library_pack.slug}/{cm_id}"

        CountermeasureLibrary.objects.update_or_create(
            qualified_slug=qualified_slug,
            defaults={
                "source_pack": library_pack,
                "slug": cm_id,
                "name": cm.get("name", cm_id),
                "description": cm.get("description", ""),
                "control_functions": cm.get("control_functions")
                or ([cm["control_type"]] if cm.get("control_type") else ["preventive"]),
                "control_nature": cm.get("control_nature", ""),
                "cost": cm.get("cost", "medium"),
                "default_status": cm.get("default_status", "gap"),
                "customization_status": "original",
            },
        )
        count += 1

    return count


def _load_frameworks(
    library_pack: LibraryPack, pack_data: dict, import_warnings: list[str] | None = None
) -> int:
    """
    Load frameworks and requirements from pack.yaml.

    For compliance packs, the pack.yaml contains a 'frameworks' section
    with framework definitions and their requirements.

    After creating a framework, activates any pending overlays that were
    waiting for this framework.
    """
    if import_warnings is None:
        import_warnings = []
    from apps.compliance.models import StandardFramework, StandardRequirement

    frameworks = pack_data.get("frameworks", [])
    if not frameworks:
        return 0

    count = 0
    created_frameworks = []

    for framework_data in frameworks:
        framework_slug = framework_data.get("slug", "")
        if not framework_slug:
            msg = f"Skipping framework without slug: {framework_data}"
            logger.warning(msg)
            import_warnings.append(msg)
            continue

        # Check if this is a new framework
        is_new = not StandardFramework.objects.filter(slug=framework_slug).exists()

        # Create or update the framework
        framework, _ = StandardFramework.objects.update_or_create(
            slug=framework_slug,
            defaults={
                "source_pack": library_pack,
                "name": framework_data.get("name", framework_slug),
                "version": framework_data.get("version", ""),
                "issuer": framework_data.get("issuer", ""),
                "description": framework_data.get("description", ""),
            },
        )

        if is_new:
            created_frameworks.append(framework_slug)

        # Purge stale requirements no longer in the pack YAML
        incoming_section_codes = {
            req.get("section_code", "")
            for req in framework_data.get("requirements", [])
        }
        incoming_section_codes.discard("")

        stale_count, _ = (
            StandardRequirement.objects.filter(framework=framework)
            .exclude(section_code__in=incoming_section_codes)
            .delete()
        )

        if stale_count:
            logger.info(
                f"Purged {stale_count} stale requirements from framework '{framework_slug}'"
            )

        # Create or update requirements for this framework
        for req_data in framework_data.get("requirements", []):
            section_code = req_data.get("section_code", "")
            if not section_code:
                continue

            StandardRequirement.objects.update_or_create(
                framework=framework,
                section_code=section_code,
                defaults={
                    "description": req_data.get("description", ""),
                },
            )
            count += 1

    # Activate pending overlays for newly created frameworks
    for framework_slug in created_frameworks:
        result = activate_pending_overlays_for_framework(framework_slug)
        if result.get("total_mappings", 0) > 0:
            logger.info(
                f"Activated {result['total_mappings']} pending overlay mappings "
                f"for framework '{framework_slug}'"
            )

        req_result = activate_pending_requirement_overlays_for_framework(framework_slug)
        if req_result.get("total_mappings", 0) > 0:
            logger.info(
                f"Activated {req_result['total_mappings']} pending requirement "
                f"overlay mappings for framework '{framework_slug}'"
            )

    return count


def _load_component_threat_joins(
    library_pack: LibraryPack, file_path: Path, import_warnings: list[str] | None = None
) -> int:
    """Load component-threat mappings from joins/components-threats.yaml."""
    if import_warnings is None:
        import_warnings = []
    if not file_path.exists():
        return 0

    try:
        with open(file_path) as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        logger.error(f"Error loading components-threats.yaml: {e}")
        return 0

    count = 0
    for mapping in data.get("mappings", []):
        component_ref = mapping.get("component", "")
        if not component_ref:
            continue

        component = _resolve_component_reference(library_pack, component_ref)
        if not component:
            msg = f"Component not found: {component_ref}"
            logger.warning(msg)
            import_warnings.append(msg)
            continue

        for threat_entry in mapping.get("threats", []):
            # Expect dict format: {threat: "threat-id", applies_to: "component|flow|both"}
            if not isinstance(threat_entry, dict):
                msg = f"Invalid threat entry format (expected dict): {threat_entry}"
                logger.warning(msg)
                import_warnings.append(msg)
                continue

            threat_ref = threat_entry.get("threat", "")
            applies_to = threat_entry.get("applies_to", "component")

            threat = _resolve_threat_reference(library_pack, threat_ref)
            if not threat:
                msg = f"Threat not found: {threat_ref}"
                logger.warning(msg)
                import_warnings.append(msg)
                continue

            ComponentLibraryThreat.objects.update_or_create(
                component_library=component,
                threat_library=threat,
                defaults={
                    "default_severity": mapping.get("severity", "medium"),
                    "applies_to": applies_to,
                },
            )
            count += 1

    return count


def _load_threat_countermeasure_joins(
    library_pack: LibraryPack, file_path: Path, import_warnings: list[str] | None = None
) -> int:
    """Load threat-countermeasure mappings from joins/threats-countermeasures.yaml."""
    if import_warnings is None:
        import_warnings = []
    if not file_path.exists():
        return 0

    try:
        with open(file_path) as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        logger.error(f"Error loading threats-countermeasures.yaml: {e}")
        return 0

    count = 0
    for mapping in data.get("mappings", []):
        threat_ref = mapping.get("threat", "")
        if not threat_ref:
            continue

        threat = _resolve_threat_reference(library_pack, threat_ref)
        if not threat:
            msg = f"Threat not found: {threat_ref}"
            logger.warning(msg)
            import_warnings.append(msg)
            continue

        for cm_ref in mapping.get("countermeasures", []):
            countermeasure = _resolve_countermeasure_reference(library_pack, cm_ref)
            if not countermeasure:
                msg = f"Countermeasure not found: {cm_ref}"
                logger.warning(msg)
                import_warnings.append(msg)
                continue

            countermeasure.applicable_threats.add(threat)
            count += 1

    return count


def _load_framework_overlay(
    library_pack: LibraryPack, file_path: Path, import_warnings: list[str] | None = None
) -> int:
    """
    Load framework overlay from joins/countermeasures-{framework}.yaml.

    Framework overlays map countermeasures to framework requirements.
    If the framework doesn't exist, stores the overlay as pending for later activation.
    """
    if import_warnings is None:
        import_warnings = []
    if not file_path.exists():
        return 0

    try:
        with open(file_path) as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        logger.error(f"Error loading framework overlay {file_path}: {e}")
        return 0

    framework_id = data.get("framework", "")
    if not framework_id:
        msg = f"No framework specified in {file_path}"
        logger.warning(msg)
        import_warnings.append(msg)
        return 0

    # Import here to avoid circular imports
    from apps.compliance.models import StandardFramework, StandardRequirement

    # Find the framework
    framework = StandardFramework.objects.filter(slug=framework_id).first()
    if not framework:
        # Store as pending overlay for later activation
        logger.info(
            f"Framework '{framework_id}' not found. Storing overlay as pending."
        )
        mapping_count = len(data.get("mappings", []))
        PendingFrameworkOverlay.objects.update_or_create(
            pack=library_pack,
            framework_slug=framework_id,
            defaults={
                "overlay_file_name": file_path.name,
                "overlay_data": data,
                "mapping_count": mapping_count,
            },
        )
        return 0

    # Framework exists - ensure pending overlay is stored for future re-activation
    # (e.g. if the framework is unimported then re-imported later)
    mapping_count = len(data.get("mappings", []))
    PendingFrameworkOverlay.objects.update_or_create(
        pack=library_pack,
        framework_slug=framework_id,
        defaults={
            "overlay_file_name": file_path.name,
            "overlay_data": data,
            "mapping_count": mapping_count,
        },
    )

    count = 0
    for mapping in data.get("mappings", []):
        cm_ref = mapping.get("countermeasure", "")
        if not cm_ref:
            continue

        countermeasure = _resolve_countermeasure_reference(library_pack, cm_ref)
        if not countermeasure:
            msg = f"Countermeasure not found: {cm_ref}"
            logger.warning(msg)
            import_warnings.append(msg)
            continue

        for req_code in mapping.get("requirements", []):
            requirement = StandardRequirement.objects.filter(
                framework=framework,
                section_code=str(req_code),
            ).first()

            if requirement:
                from apps.compliance.models import CountermeasureLibraryStandard

                CountermeasureLibraryStandard.objects.get_or_create(
                    countermeasure_library=countermeasure,
                    requirement=requirement,
                    defaults={
                        "sufficiency": mapping.get("sufficiency", "full"),
                    },
                )
                count += 1
            else:
                msg = (
                    f"Requirement '{req_code}' not found in framework '{framework_id}'"
                )
                logger.warning(msg)
                import_warnings.append(msg)

    return count


def _load_requirement_overlay(
    library_pack: LibraryPack, file_path: Path, import_warnings: list[str] | None = None
) -> int:
    """
    Load requirement overlay from joins/requirements-{target-framework}.yaml.

    Requirement overlays map requirements from one framework to another.
    If either framework doesn't exist, stores as pending for later activation.

    YAML schema:
        framework: iec-81001-5-1          # target framework slug
        source_framework: caa-3305        # source framework slug
        mappings:
          - requirement: "CAA3305-524B(b)(1)"
            entries:
              - "6.2.1"
              - "9.2"
            sufficiency: partial
    """
    if import_warnings is None:
        import_warnings = []
    if not file_path.exists():
        return 0

    try:
        with open(file_path) as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        logger.error(f"Error loading requirement overlay {file_path}: {e}")
        return 0

    target_framework_slug = data.get("framework", "")
    source_framework_slug = data.get("source_framework", "")
    if not target_framework_slug or not source_framework_slug:
        msg = f"Missing 'framework' or 'source_framework' in {file_path}"
        logger.warning(msg)
        import_warnings.append(msg)
        return 0

    from apps.compliance.models import (
        StandardFramework,
        StandardRequirement,
        StandardRequirementMapping,
    )

    source_framework = StandardFramework.objects.filter(
        slug=source_framework_slug
    ).first()
    target_framework = StandardFramework.objects.filter(
        slug=target_framework_slug
    ).first()

    if not source_framework or not target_framework:
        missing = []
        if not source_framework:
            missing.append(source_framework_slug)
        if not target_framework:
            missing.append(target_framework_slug)
        logger.info(
            f"Framework(s) {missing} not found. Storing requirement overlay as pending."
        )
        mapping_count = len(data.get("mappings", []))
        PendingRequirementOverlay.objects.update_or_create(
            pack=library_pack,
            source_framework_slug=source_framework_slug,
            target_framework_slug=target_framework_slug,
            defaults={
                "overlay_file_name": file_path.name,
                "overlay_data": data,
                "mapping_count": mapping_count,
            },
        )
        return 0

    # Both frameworks exist - ensure pending overlay is stored for future re-activation
    # (e.g. if either framework is unimported then re-imported later)
    mapping_count = len(data.get("mappings", []))
    PendingRequirementOverlay.objects.update_or_create(
        pack=library_pack,
        source_framework_slug=source_framework_slug,
        target_framework_slug=target_framework_slug,
        defaults={
            "overlay_file_name": file_path.name,
            "overlay_data": data,
            "mapping_count": mapping_count,
        },
    )

    count = 0
    for mapping in data.get("mappings", []):
        from_section_code = mapping.get("requirement", "")
        if not from_section_code:
            continue

        from_requirement = StandardRequirement.objects.filter(
            framework=source_framework,
            section_code=str(from_section_code),
        ).first()

        if not from_requirement:
            msg = (
                f"Source requirement '{from_section_code}' not found "
                f"in framework '{source_framework_slug}'"
            )
            logger.warning(msg)
            import_warnings.append(msg)
            continue

        sufficiency = mapping.get("sufficiency", "partial")

        for to_section_code in mapping.get("entries", []):
            to_requirement = StandardRequirement.objects.filter(
                framework=target_framework,
                section_code=str(to_section_code),
            ).first()

            if to_requirement:
                StandardRequirementMapping.objects.get_or_create(
                    from_requirement=from_requirement,
                    to_requirement=to_requirement,
                    defaults={
                        "sufficiency": sufficiency,
                        "source_pack": library_pack,
                    },
                )
                count += 1
            else:
                msg = (
                    f"Target requirement '{to_section_code}' not found "
                    f"in framework '{target_framework_slug}'"
                )
                logger.warning(msg)
                import_warnings.append(msg)

    return count


def activate_pending_overlays_for_framework(framework_slug: str) -> dict:
    """
    Activate all pending overlays for a newly installed framework.

    Called when a framework is installed to apply any overlays that were
    waiting for this framework.

    Args:
        framework_slug: The slug of the framework that was just installed

    Returns:
        Dictionary with activation results including counts per pack
    """
    from apps.compliance.models import (
        CountermeasureLibraryStandard,
        StandardFramework,
        StandardRequirement,
    )

    framework = StandardFramework.objects.filter(slug=framework_slug).first()
    if not framework:
        logger.error(
            f"Cannot activate overlays: Framework '{framework_slug}' not found"
        )
        return {"success": False, "error": "Framework not found", "activated": 0}

    pending_overlays = PendingFrameworkOverlay.objects.filter(
        framework_slug=framework_slug
    )

    results = {
        "success": True,
        "framework": framework_slug,
        "framework_name": framework.name,
        "packs_activated": [],
        "total_mappings": 0,
    }

    for pending in pending_overlays:
        pack = pending.pack
        data = pending.overlay_data
        mappings_applied = 0

        for mapping in data.get("mappings", []):
            cm_ref = mapping.get("countermeasure", "")
            if not cm_ref:
                continue

            countermeasure = _resolve_countermeasure_reference(pack, cm_ref)
            if not countermeasure:
                logger.warning(f"Countermeasure not found during activation: {cm_ref}")
                continue

            for req_code in mapping.get("requirements", []):
                requirement = StandardRequirement.objects.filter(
                    framework=framework,
                    section_code=str(req_code),
                ).first()

                if requirement:
                    CountermeasureLibraryStandard.objects.get_or_create(
                        countermeasure_library=countermeasure,
                        requirement=requirement,
                        defaults={
                            "sufficiency": mapping.get("sufficiency", "full"),
                        },
                    )
                    mappings_applied += 1

        results["packs_activated"].append(
            {
                "pack_slug": pack.slug,
                "pack_name": pack.name,
                "mappings_applied": mappings_applied,
            }
        )
        results["total_mappings"] += mappings_applied

        # Keep pending overlay for future re-activation (e.g. framework unimport/re-import).
        # CASCADE on pack FK handles cleanup when the source pack is unimported.

    logger.info(
        f"Activated {len(results['packs_activated'])} pending overlays for framework '{framework_slug}' "
        f"with {results['total_mappings']} total mappings"
    )

    return results


def activate_pending_requirement_overlays_for_framework(framework_slug: str) -> dict:
    """
    Activate all pending requirement overlays that reference the given framework
    (either as source or target).

    Called when a framework is installed to apply any requirement overlays
    that were waiting for this framework.

    Args:
        framework_slug: The slug of the framework that was just installed

    Returns:
        Dictionary with activation results including counts per pack
    """
    from django.db.models import Q

    from apps.compliance.models import (
        StandardFramework,
        StandardRequirement,
        StandardRequirementMapping,
    )

    framework = StandardFramework.objects.filter(slug=framework_slug).first()
    if not framework:
        logger.error(
            f"Cannot activate requirement overlays: "
            f"Framework '{framework_slug}' not found"
        )
        return {"success": False, "error": "Framework not found", "activated": 0}

    # Find pending overlays where this framework is either source or target
    pending_overlays = PendingRequirementOverlay.objects.filter(
        Q(source_framework_slug=framework_slug)
        | Q(target_framework_slug=framework_slug)
    )

    results = {
        "success": True,
        "framework": framework_slug,
        "framework_name": framework.name,
        "packs_activated": [],
        "total_mappings": 0,
    }

    for pending in pending_overlays:
        data = pending.overlay_data
        source_fw_slug = data.get("source_framework", "")
        target_fw_slug = data.get("framework", "")

        source_fw = StandardFramework.objects.filter(slug=source_fw_slug).first()
        target_fw = StandardFramework.objects.filter(slug=target_fw_slug).first()

        if not source_fw or not target_fw:
            # Still missing the other framework, skip
            continue

        pack = pending.pack
        mappings_applied = 0

        for mapping in data.get("mappings", []):
            from_section_code = mapping.get("requirement", "")
            if not from_section_code:
                continue

            from_requirement = StandardRequirement.objects.filter(
                framework=source_fw,
                section_code=str(from_section_code),
            ).first()

            if not from_requirement:
                logger.warning(
                    f"Source requirement '{from_section_code}' not found "
                    f"during activation in framework '{source_fw_slug}'"
                )
                continue

            sufficiency = mapping.get("sufficiency", "partial")

            for to_section_code in mapping.get("entries", []):
                to_requirement = StandardRequirement.objects.filter(
                    framework=target_fw,
                    section_code=str(to_section_code),
                ).first()

                if to_requirement:
                    StandardRequirementMapping.objects.get_or_create(
                        from_requirement=from_requirement,
                        to_requirement=to_requirement,
                        defaults={
                            "sufficiency": sufficiency,
                            "source_pack": pack,
                        },
                    )
                    mappings_applied += 1

        results["packs_activated"].append(
            {
                "pack_slug": pack.slug,
                "pack_name": pack.name,
                "mappings_applied": mappings_applied,
            }
        )
        results["total_mappings"] += mappings_applied

        # Keep pending overlay for future re-activation (e.g. framework unimport/re-import).
        # CASCADE on pack FK handles cleanup when the source pack is unimported.

    logger.info(
        f"Activated {len(results['packs_activated'])} pending requirement overlays "
        f"for framework '{framework_slug}' "
        f"with {results['total_mappings']} total mappings"
    )

    return results


def get_pending_overlays_for_pack(pack: LibraryPack) -> list[dict]:
    """
    Get pending overlays for a pack.

    Args:
        pack: The LibraryPack to check

    Returns:
        List of pending overlay info dicts
    """
    pending = PendingFrameworkOverlay.objects.filter(pack=pack)
    return [
        {
            "framework_slug": p.framework_slug,
            "overlay_file_name": p.overlay_file_name,
            "mapping_count": p.mapping_count,
        }
        for p in pending
    ]


def _load_templates(
    library_pack: LibraryPack,
    templates_dir: Path,
    import_warnings: list[str] | None = None,
) -> int:
    """
    Load DFD templates from dfd-templates/ directory.

    Templates use component_ref to reference components from components.yaml.
    """
    if import_warnings is None:
        import_warnings = []
    if not templates_dir.exists():
        return 0

    template_files = list(templates_dir.glob("*.yaml")) + list(
        templates_dir.glob("*.yml")
    )
    count = 0

    for template_file in template_files:
        try:
            with open(template_file) as f:
                template_data = yaml.safe_load(f)

            template = template_data.get("template", {})
            slug = template.get("id", template.get("slug", template_file.stem))
            qualified_slug = f"{library_pack.slug}/{slug}"

            # Validate component_refs if present
            canvas_data = template_data.get("canvas_data", {})
            _validate_template_component_refs(
                library_pack, canvas_data, template_file.name, import_warnings
            )

            DFDTemplatesLibrary.objects.update_or_create(
                qualified_slug=qualified_slug,
                defaults={
                    "source_pack": library_pack,
                    "slug": slug,
                    "name": template.get("name", slug),
                    "description": template.get("description", ""),
                    "category": template.get("category", "webapp"),
                    "diagram_type": template.get("diagram_type", "level1"),
                    "canvas_data": canvas_data,
                    "customization_status": "original",
                },
            )
            count += 1
        except Exception:
            logger.exception(f"Error loading template {template_file.name}")

    if template_files and count == 0:
        logger.error(
            f"All {len(template_files)} templates failed to load for pack '{library_pack.slug}'. "
            f"Check that migrations are up to date: python manage.py migrate"
        )

    return count


def _validate_template_component_refs(
    library_pack: LibraryPack,
    canvas_data: dict,
    template_name: str,
    import_warnings: list[str] | None = None,
) -> None:
    """Validate that component_refs in template nodes exist."""
    if import_warnings is None:
        import_warnings = []
    nodes = canvas_data.get("nodes", [])

    for node in nodes:
        component_ref = node.get("data", {}).get("component_ref")
        if component_ref:
            component = _resolve_component_reference(library_pack, component_ref)
            if not component:
                msg = f"Template '{template_name}' references unknown component: {component_ref}"
                logger.warning(msg)
                import_warnings.append(msg)


def _resolve_component_reference(
    library_pack: LibraryPack, ref: str
) -> ComponentLibrary | None:
    """
    Resolve a component reference.

    Supports:
    - 'aws_lambda' → looks in current pack
    - 'generic/database' → looks in generic pack (cross-pack reference)
    """
    if "/" in ref:
        # Cross-pack reference
        return ComponentLibrary.objects.filter(qualified_slug=ref).first()
    else:
        # Current pack reference
        qualified_slug = f"{library_pack.slug}/{ref}"
        return ComponentLibrary.objects.filter(qualified_slug=qualified_slug).first()


def _resolve_countermeasure_reference(
    library_pack: LibraryPack, ref: str
) -> CountermeasureLibrary | None:
    """
    Resolve a countermeasure reference.

    Supports:
    - 'encrypt_at_rest' → looks in current pack
    - 'aws/s3-block-public-access' → looks in aws pack (cross-pack reference)
    """
    if "/" in ref:
        # Cross-pack reference
        return CountermeasureLibrary.objects.filter(qualified_slug=ref).first()
    else:
        # Current pack reference
        qualified_slug = f"{library_pack.slug}/{ref}"
        return CountermeasureLibrary.objects.filter(
            qualified_slug=qualified_slug
        ).first()


# =============================================================================
# Overlay Discovery Functions
# =============================================================================


@dataclass
class OverlayInfo:
    """Information about an available framework overlay in a pack."""

    framework_id: str
    framework_name: str
    mapping_count: int
    framework_exists: bool


@dataclass
class ActiveOverlayInfo:
    """Information about an active framework overlay for an installed pack."""

    framework_id: str
    framework_name: str
    mapping_count: int


def get_active_overlays_for_pack(pack: LibraryPack) -> list[ActiveOverlayInfo]:
    """
    Get active framework overlays for an installed pack.

    Queries the database for CountermeasureLibraryStandard records
    that map this pack's countermeasures to framework requirements.

    Args:
        pack: The LibraryPack to check

    Returns:
        List of ActiveOverlayInfo with framework_id, framework_name, and mapping_count
    """
    from apps.compliance.models import CountermeasureLibraryStandard

    # Get all mappings for this pack's countermeasures.
    # `requirement` can now be None: an orphaned mapping left behind when a
    # compliance-pack reimport removed the requirement it pointed at, SET_NULL'd
    # rather than CASCADE-deleted (see apps/compliance/models.py). Excluded here
    # rather than null-guarded in the loop below, because an orphaned mapping is
    # not mapped to any framework requirement any more and so should not count as
    # an active overlay for this pack.
    mappings = (
        CountermeasureLibraryStandard.objects.filter(
            countermeasure_library__source_pack=pack
        )
        .exclude(requirement__isnull=True)
        .select_related("requirement__framework")
    )

    # Group by framework
    framework_counts: dict[int, dict] = {}
    for mapping in mappings:
        framework = mapping.requirement.framework
        if framework.id not in framework_counts:
            framework_counts[framework.id] = {
                "framework_id": framework.slug,
                "framework_name": framework.name,
                "mapping_count": 0,
            }
        framework_counts[framework.id]["mapping_count"] += 1

    return [
        ActiveOverlayInfo(
            framework_id=info["framework_id"],
            framework_name=info["framework_name"],
            mapping_count=info["mapping_count"],
        )
        for info in framework_counts.values()
    ]


def get_available_overlays_for_pack(pack_relative_path: str) -> list[OverlayInfo]:
    """
    Get available framework overlays for a pack.

    Scans the pack's joins/ directory for countermeasures-*.yaml files
    and returns information about each overlay. Uses the pack's relative
    path from the libraries/packs root for O(1) directory lookup.

    Args:
        pack_relative_path: Relative path from libraries/packs root (e.g. "threat-libraries/aws")

    Returns:
        List of OverlayInfo with framework_id, framework_name, mapping_count, framework_exists
    """
    from apps.compliance.models import StandardFramework

    libraries_path = get_libraries_path()

    if not libraries_path.exists():
        return []

    pack_dir = _find_pack_dir(libraries_path, pack_relative_path)
    if not pack_dir:
        return []

    joins_dir = pack_dir / "joins"
    if not joins_dir.exists():
        return []

    # Get installed frameworks for checking existence
    installed_frameworks = set(StandardFramework.objects.values_list("slug", flat=True))

    overlays = []
    for join_file in joins_dir.glob("countermeasures-*.yaml"):
        # Skip the threat-countermeasure join file
        if "threats" in join_file.name:
            continue

        try:
            with open(join_file) as f:
                data = yaml.safe_load(f) or {}

            framework_id = data.get("framework", "")
            if not framework_id:
                continue

            # Count mappings
            mappings = data.get("mappings", [])
            mapping_count = len(mappings)

            # Check if framework exists
            framework_exists = framework_id in installed_frameworks

            # Get framework name if it exists
            framework_name = framework_id
            if framework_exists:
                framework = StandardFramework.objects.filter(slug=framework_id).first()
                if framework:
                    framework_name = framework.name

            overlays.append(
                OverlayInfo(
                    framework_id=framework_id,
                    framework_name=framework_name,
                    mapping_count=mapping_count,
                    framework_exists=framework_exists,
                )
            )
        except Exception as e:
            logger.error(f"Error reading overlay file {join_file}: {e}")
            continue

    return overlays
