"""
Diagrams models - DFDs and DFD templates.
"""

from django.conf import settings
from django.db import models

from apps.core.models import TimestampedModel
from apps.core.tenancy import Tenancy


class DFDTemplatesLibrary(TimestampedModel):
    """DFD template library."""

    tenancy = Tenancy.MIXED

    class DiagramType(models.TextChoices):
        CONTEXT = "context", "Context"
        LEVEL1 = "level1", "Level 1"
        LEVEL2 = "level2", "Level 2"

    class CustomizationStatus(models.TextChoices):
        ORIGINAL = "original", "Original (from pack)"
        CUSTOMIZED = "customized", "Customized (user edited)"
        DETACHED = "detached", "Detached (unlinked from pack)"

    source_pack = models.ForeignKey(
        "packs.LibraryPack",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="dfd_templates",
        help_text="Pack this item came from (null = custom or legacy)",
    )
    slug = models.SlugField(
        max_length=100,
        blank=True,
        help_text="Unique identifier within pack, e.g., 'banking-webapp-l1'",
    )
    # `null=True` is required by `unique_dfdtemplate_qualified_slug` below. Postgres
    # treats NULLs as distinct under a unique index, so any number of rows may carry no
    # qualified slug; `blank=True` with `""` would make the second such row collide
    # with the first. DJ001 cannot see the constraint.
    qualified_slug = models.CharField(  # noqa: DJ001
        max_length=200,
        null=True,
        blank=True,
        db_index=True,
        help_text="Namespace-safe identifier, e.g., 'banking-templates/webapp-l1'",
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    category = models.CharField(
        max_length=50,
        help_text="Freeform category (e.g., webapp, serverless, microservices)",
    )
    diagram_type = models.CharField(max_length=20, choices=DiagramType.choices)
    maintained_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="maintained_templates",
    )
    # Store the ReactFlow JSON structure
    canvas_data = models.JSONField(default=dict, blank=True)

    # Customization tracking (for update vs fork handling)
    customization_status = models.CharField(
        max_length=20,
        choices=CustomizationStatus.choices,
        default=CustomizationStatus.ORIGINAL,
    )
    base_item_qualified_slug = models.CharField(
        max_length=200,
        blank=True,
        db_index=True,
        help_text="Original item this was forked/customized from",
    )

    class Meta:
        verbose_name_plural = "DFD templates library"
        ordering = ["category", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["qualified_slug"],
                name="unique_dfdtemplate_qualified_slug",
            ),
        ]

    def __str__(self):
        return f"{self.name} ({self.category})"

    def save(self, *args, **kwargs):
        # Auto-generate qualified_slug if not set
        if not self.qualified_slug and self.slug:
            if self.source_pack:
                self.qualified_slug = f"{self.source_pack.slug}/{self.slug}"
            else:
                self.qualified_slug = f"custom/{self.slug}"
        super().save(*args, **kwargs)


class DFD(TimestampedModel):
    """Data Flow Diagram."""

    tenancy = Tenancy.TENANT_OWNED

    class DiagramType(models.TextChoices):
        CONTEXT = "context", "Context"
        LEVEL1 = "level1", "Level 1"
        LEVEL2 = "level2", "Level 2"

    name = models.CharField(max_length=255)
    diagram_type = models.CharField(
        max_length=20,
        choices=DiagramType.choices,
        default=DiagramType.LEVEL1,
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="updated_dfds",
    )
    template_library = models.ForeignKey(
        DFDTemplatesLibrary,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="instantiated_dfds",
    )
    # A DFD is a visualization of one blueprint. The blueprint's primary DFD is
    # the one that syncs to rows; the others are reference views.
    blueprint = models.ForeignKey(
        "threat_models.Blueprint",
        on_delete=models.CASCADE,
        related_name="dfds",
    )
    is_primary = models.BooleanField(
        default=False,
        help_text="Only the primary DFD of a blueprint syncs nodes to components/threats.",
    )
    # Store the ReactFlow JSON structure (nodes, edges)
    canvas_data = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "DFD"
        verbose_name_plural = "DFDs"
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(
                fields=["blueprint"],
                condition=models.Q(is_primary=True),
                name="unique_primary_dfd_per_blueprint",
            ),
        ]

    @property
    def threat_model(self):
        return self.blueprint.threat_model

    def __str__(self):
        return f"{self.name} ({self.diagram_type})"
