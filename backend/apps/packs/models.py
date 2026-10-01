"""
Library Packs models - Bundles of technologies, threats, countermeasures, and templates.

Packs enable:
- Community-contributed library bundles
- Industry-specific starter kits (banking, healthcare, etc.)
- Version-controlled library updates
"""

from django.contrib.postgres.fields import ArrayField
from django.db import models

from apps.core.models import TimestampedModel
from apps.core.tenancy import Tenancy


class LibraryPack(TimestampedModel):
    """
    A bundle of library items (technologies, threats, countermeasures, templates)
    that can be installed together by an organization.
    """

    # A pack is the unit of shipped content. "Installed by an organization" above
    # describes a link recorded elsewhere (`ThreatModelLibraryPack`), not ownership of
    # the pack row.
    tenancy = Tenancy.SHARED_REFERENCE

    class PackType(models.TextChoices):
        TECHNOLOGY = "technology", "Technology Pack"
        THREAT = "threat", "Threat Pack"
        COUNTERMEASURE = "countermeasure", "Countermeasure Pack"
        COMPLIANCE = "compliance", "Compliance Pack"
        TEMPLATE = "template", "DFD Template Pack"
        FULL = "full", "Full Stack Pack"  # Contains multiple types
        TAXONOMY = "taxonomy", "Taxonomy Pack"

    # Identity
    slug = models.SlugField(
        max_length=100,
        unique=True,
        help_text="Unique identifier, e.g., 'banking-technologies'",
    )
    name = models.CharField(max_length=255)
    description = models.TextField()

    # Classification
    pack_type = models.CharField(max_length=20, choices=PackType.choices)

    # Versioning
    version = models.CharField(
        max_length=20, help_text="Semantic version, e.g., '1.2.0'"
    )

    # Metadata
    author = models.CharField(max_length=255, help_text="Author or organization name")

    # Presentation: optional pack-level icon, loaded from an SVG file
    # referenced by `pack.yaml`'s `icon:` key (path relative to the pack
    # directory). Rendered by the frontend as a base64 data URI
    # (see `SvgIcon`) — never injected as raw markup — so it carries the
    # same XSS-safety guarantee as `ComponentLibrary.icon_svg`.
    icon_svg = models.TextField(
        blank=True,
        default="",
        help_text="Inline SVG markup for the pack's icon, loaded from pack.yaml's icon: path.",
    )

    # Targeting
    tags = ArrayField(
        models.CharField(max_length=50),
        default=list,
        blank=True,
        help_text="Tags for search/filtering, e.g., ['aws', 'cloud', 'serverless']",
    )

    class Meta:
        ordering = ["name"]
        verbose_name = "Library Pack"
        verbose_name_plural = "Library Packs"

    def __str__(self):
        return f"{self.name} v{self.version}"


class LibraryPackDependency(TimestampedModel):
    """Explicit dependency between packs."""

    tenancy = Tenancy.SHARED_REFERENCE

    pack = models.ForeignKey(
        LibraryPack,
        on_delete=models.CASCADE,
        related_name="dependencies",
        help_text="The pack that has the dependency",
    )
    depends_on_pack = models.ForeignKey(
        LibraryPack,
        on_delete=models.CASCADE,
        related_name="dependents",
        help_text="The pack being depended upon",
    )

    class Meta:
        unique_together = ["pack", "depends_on_pack"]
        verbose_name = "Pack Dependency"
        verbose_name_plural = "Pack Dependencies"

    def __str__(self):
        return f"{self.pack.slug} -> {self.depends_on_pack.slug}"


class PendingFrameworkOverlay(TimestampedModel):
    """
    Stores framework overlays that couldn't be applied because the framework
    wasn't installed when the pack was imported.

    When a framework is later installed, pending overlays for that framework
    can be activated automatically.
    """

    # Staging for a pack import, keyed only by pack and slug. No organization is
    # involved on either side.
    tenancy = Tenancy.SHARED_REFERENCE

    pack = models.ForeignKey(
        LibraryPack,
        on_delete=models.CASCADE,
        related_name="pending_overlays",
        help_text="The pack that contains this overlay",
    )
    framework_slug = models.CharField(
        max_length=100,
        help_text="The slug of the framework this overlay maps to",
    )
    overlay_file_name = models.CharField(
        max_length=255,
        help_text="Name of the overlay file (e.g., 'countermeasures-owasp-2021.yaml')",
    )
    overlay_data = models.JSONField(
        default=dict,
        help_text="The raw overlay data from the YAML file",
    )
    mapping_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of mappings in this overlay",
    )

    class Meta:
        unique_together = ["pack", "framework_slug"]
        verbose_name = "Pending Framework Overlay"
        verbose_name_plural = "Pending Framework Overlays"
        ordering = ["pack", "framework_slug"]

    def __str__(self):
        return f"{self.pack.slug} -> {self.framework_slug} (pending)"


class PendingRequirementOverlay(TimestampedModel):
    """
    Stores requirement-to-requirement overlays that could not be applied
    because one or both frameworks were not installed when the pack was imported.

    When a framework is later installed, pending requirement overlays
    referencing that framework can be activated automatically.
    """

    tenancy = Tenancy.SHARED_REFERENCE

    pack = models.ForeignKey(
        LibraryPack,
        on_delete=models.CASCADE,
        related_name="pending_requirement_overlays",
        help_text="The pack that contains this overlay",
    )
    source_framework_slug = models.CharField(
        max_length=100,
        help_text="The slug of the source framework (from_requirement side)",
    )
    target_framework_slug = models.CharField(
        max_length=100,
        help_text="The slug of the target framework (to_requirement side)",
    )
    overlay_file_name = models.CharField(
        max_length=255,
        help_text="Name of the overlay file (e.g., 'requirements-iec-81001-5-1.yaml')",
    )
    overlay_data = models.JSONField(
        default=dict,
        help_text="The raw overlay data from the YAML file",
    )
    mapping_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of mappings in this overlay",
    )

    class Meta:
        unique_together = ["pack", "source_framework_slug", "target_framework_slug"]
        verbose_name = "Pending Requirement Overlay"
        verbose_name_plural = "Pending Requirement Overlays"
        ordering = ["pack", "source_framework_slug", "target_framework_slug"]

    def __str__(self):
        return (
            f"{self.pack.slug}: {self.source_framework_slug} -> "
            f"{self.target_framework_slug} (pending)"
        )


class PendingTaxonomyOverlay(TimestampedModel):
    """
    Stores taxonomy join overlays that couldn't be applied because the
    taxonomy wasn't installed when the pack was imported.

    When a taxonomy is later installed, pending overlays for that taxonomy
    can be activated automatically.
    """

    tenancy = Tenancy.SHARED_REFERENCE

    pack = models.ForeignKey(
        LibraryPack,
        on_delete=models.CASCADE,
        related_name="pending_taxonomy_overlays",
        help_text="The pack that contains this overlay",
    )
    taxonomy_slug = models.CharField(
        max_length=100,
        help_text="The slug of the taxonomy this overlay maps to",
    )
    overlay_file_name = models.CharField(
        max_length=255,
        help_text="Name of the overlay file (e.g., 'threats-mitre-atlas.yaml')",
    )
    overlay_data = models.JSONField(
        default=dict,
        help_text="The raw overlay data from the YAML file",
    )
    mapping_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of mappings in this overlay",
    )

    class Meta:
        unique_together = ["pack", "taxonomy_slug"]
        verbose_name = "Pending Taxonomy Overlay"
        verbose_name_plural = "Pending Taxonomy Overlays"
        ordering = ["pack", "taxonomy_slug"]

    def __str__(self):
        return f"{self.pack.slug} -> {self.taxonomy_slug} (pending)"
