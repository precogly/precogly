"""
Systems models - Orgsystems, components, data flows.
"""

from django.contrib.postgres.fields import ArrayField
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from apps.core.models import TimestampedModel
from apps.core.tenancy import Tenancy
from apps.organizations.models import Organization
from apps.systems.crossing import (
    ASSET_TYPES,
    BOUNDARY_TYPES,
    FLOW_TYPES,
    ZONE_TYPES,
    kind_for_category,
)


class Orgsystem(TimestampedModel):
    """Organizational system being modeled."""

    tenancy = Tenancy.TENANT_OWNED

    class Criticality(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    class LifecycleState(models.TextChoices):
        DEVELOPMENT = "development", "Development"
        PRODUCTION = "production", "Production"
        DECOMMISSIONED = "decommissioned", "Decommissioned"

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="orgsystems",
    )
    name = models.CharField(max_length=255)
    owner = models.CharField(max_length=255, blank=True)
    criticality = models.CharField(
        max_length=20,
        choices=Criticality.choices,
        default=Criticality.MEDIUM,
    )
    lifecycle_state = models.CharField(
        max_length=20,
        choices=LifecycleState.choices,
        default=LifecycleState.DEVELOPMENT,
    )
    description = models.TextField(blank=True, default="")
    format_metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class IntegrationSource(TimestampedModel):
    """External integration source for component discovery."""

    tenancy = Tenancy.TENANT_OWNED

    class SourceType(models.TextChoices):
        GITHUB = "github", "GitHub"
        CSPM = "cspm", "CSPM"
        TERRAFORM = "terraform", "Terraform"
        SBOM = "sbom", "SBOM"
        MANUAL = "manual", "Manual"

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        INACTIVE = "inactive", "Inactive"
        ERROR = "error", "Error"

    orgsystem = models.ForeignKey(
        Orgsystem,
        on_delete=models.CASCADE,
        related_name="integration_sources",
    )
    name = models.CharField(max_length=255)
    source_type = models.CharField(max_length=20, choices=SourceType.choices)
    connection_details = models.JSONField(default=dict, blank=True)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.ACTIVE,
    )
    last_sync_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return f"{self.name} ({self.source_type})"


class Zone(TimestampedModel):
    """Trust zone (named security region)."""

    tenancy = Tenancy.TENANT_OWNED

    # A zone belongs to exactly one blueprint. The organization is reached
    # through `blueprint.threat_model.organization`, a chain with no nullable
    # step, which is what #404 and #406 needed (an unscoped reverse lookup
    # through `components` read and wrote across tenants).
    blueprint = models.ForeignKey(
        "threat_models.Blueprint",
        on_delete=models.CASCADE,
        related_name="zones",
    )
    name = models.CharField(max_length=255)
    zone_type = models.CharField(
        max_length=20,
        choices=[(value, value) for value in ZONE_TYPES],
        default="trust",
        help_text="CycloneDX zone type",
    )
    # Null means "not set" (F13). Meaningful on trust and network zones; the
    # editor starts a new trust zone at 50.
    trust_level = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text="0-100 scale, null when not set",
    )
    description = models.TextField(blank=True)
    format_metadata = models.JSONField(default=dict, blank=True)
    parent = models.ForeignKey(
        "self",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="children",
    )

    class Meta:
        verbose_name_plural = "Zones"
        ordering = ["name"]

    def __str__(self):
        return self.name


class Boundary(TimestampedModel):
    """Security boundary between two trust zones."""

    tenancy = Tenancy.TENANT_OWNED

    # Carries its own blueprint rather than reading it off `zone_a`: the two zones
    # are separate rows and this column, with the same-blueprint validation in the
    # serializer and in sync, is what stops a boundary being drawn between
    # blueprints or organizations. Lifecycle still comes from the zones, which cascade.
    blueprint = models.ForeignKey(
        "threat_models.Blueprint",
        on_delete=models.CASCADE,
        related_name="boundaries",
    )
    zone_a = models.ForeignKey(
        Zone,
        on_delete=models.CASCADE,
        related_name="boundaries_as_source",
    )
    zone_b = models.ForeignKey(
        Zone,
        on_delete=models.CASCADE,
        related_name="boundaries_as_target",
    )
    label = models.CharField(max_length=255, blank=True)
    description = models.TextField(blank=True)
    edge_id = models.CharField(
        max_length=100,
        blank=True,
        db_index=True,
        help_text="DFD edge ID this boundary was created from",
    )
    format_metadata = models.JSONField(default=dict, blank=True)
    boundary_type = models.CharField(
        max_length=20,
        choices=[(value, value) for value in BOUNDARY_TYPES],
        default="trust",
        help_text="CycloneDX boundary type",
    )

    # Crossing requirements, shaped like the spec (section 4.5). The lists hold
    # spec values or custom names; `none` cannot sit beside other values. The
    # booleans are exported only when true (M14, S4).
    authentication = models.JSONField(default=list, blank=True)
    authorization = models.JSONField(default=list, blank=True)
    data_validation = models.BooleanField(default=False)
    data_transformation = models.BooleanField(default=False)
    logging = models.BooleanField(default=False)
    monitoring = models.BooleanField(default=False)
    rate_limit = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Policy text; blank means none",
    )
    protocols = models.JSONField(default=list, blank=True)
    session_management = models.JSONField(
        default=dict, blank=True, help_text="The spec's nine sessionManagement keys"
    )

    # No unique rule on the zone pair (M11): a network boundary and a trust
    # boundary between the same two zones are both normal.
    class Meta:
        verbose_name_plural = "Boundaries"
        ordering = ["zone_a", "zone_b"]

    @property
    def requires_authentication(self) -> bool:
        from .crossing import requires

        return requires(self.authentication)

    @property
    def requires_authorization(self) -> bool:
        from .crossing import requires

        return requires(self.authorization)

    def __str__(self):
        return self.label or f"{self.zone_a} <-> {self.zone_b}"


class ComponentLibrary(TimestampedModel):
    """Reusable component templates."""

    # `customization_status` records one tenant's edits to a shipped row, and every
    # tenant then reads the edited row.
    tenancy = Tenancy.MIXED

    class Category(models.TextChoices):
        PROCESS = "process", "Process"
        DATASTORE = "datastore", "Data Store"
        EXTERNAL_HUMAN_ACTOR = "external_human_actor", "External Human Actor"
        EXTERNAL_SYSTEM_ACTOR = "external_system_actor", "External System Actor"

    class CustomizationStatus(models.TextChoices):
        ORIGINAL = "original", "Original (from pack)"
        CUSTOMIZED = "customized", "Customized (user edited)"
        DETACHED = "detached", "Detached (unlinked from pack)"

    source_pack = models.ForeignKey(
        "packs.LibraryPack",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="components",
        help_text="Pack this item came from (null = custom or legacy)",
    )
    slug = models.SlugField(
        max_length=100,
        blank=True,
        help_text="Unique identifier within pack, e.g., 'aws-s3'",
    )
    # `null=True` is required by `unique_component_qualified_slug` below. Postgres
    # treats NULLs as distinct under a unique index, so any number of rows may carry no
    # qualified slug; `blank=True` with `""` would make the second such row collide
    # with the first. DJ001 cannot see the constraint.
    qualified_slug = models.CharField(  # noqa: DJ001
        max_length=200,
        null=True,
        blank=True,
        db_index=True,
        help_text="Namespace-safe identifier, e.g., 'aws-technologies/s3'",
    )
    name = models.CharField(max_length=255)
    category = models.CharField(max_length=30, choices=Category.choices)
    kind = models.CharField(
        max_length=30,
        blank=True,
        default="",
        choices=[(value, value) for value in ASSET_TYPES],
        help_text="CycloneDX asset type; blank derives from the category",
    )
    component_type = models.CharField(max_length=100)
    provider = models.CharField(max_length=100, blank=True)
    icon_svg = models.TextField(blank=True, default="")

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

    # Backward compatibility for renamed slugs
    aliases = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True,
        help_text="Previous slugs for backward compatibility",
    )

    # Parent component hierarchy (process-only, max 3 levels)
    parent = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="children",
        help_text="Parent component in hierarchy (process category only)",
    )

    MAX_HIERARCHY_DEPTH = 3

    class Meta:
        verbose_name_plural = "Component libraries"
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(
                fields=["qualified_slug"],
                name="unique_component_qualified_slug",
            ),
        ]

    def __str__(self):
        return f"{self.name} ({self.category})"

    def clean(self):
        super().clean()
        if self.parent:
            if self.category != self.Category.PROCESS:
                raise ValidationError(
                    {"parent": "Only process-category components can have a parent."}
                )
            if self.parent.category != self.Category.PROCESS:
                raise ValidationError(
                    {"parent": "Parent must be a process-category component."}
                )
            if self.parent_id == self.pk:
                raise ValidationError(
                    {"parent": "A component cannot be its own parent."}
                )
            self._validate_no_circular_reference()
            self._validate_max_depth()

    def _validate_no_circular_reference(self):
        """Walk up the parent chain to detect cycles."""
        visited = {self.pk}
        current = self.parent
        while current is not None:
            if current.pk in visited:
                raise ValidationError({"parent": "Circular parent reference detected."})
            visited.add(current.pk)
            current = current.parent

    def _validate_max_depth(self):
        """Ensure total hierarchy depth does not exceed MAX_HIERARCHY_DEPTH."""
        # Count levels above (ancestors)
        ancestor_depth = 0
        current = self.parent
        while current is not None:
            ancestor_depth += 1
            current = current.parent

        # Count levels below (descendants)
        descendant_depth = self._get_descendant_depth()

        # Total depth = ancestors + self + descendants
        total_depth = ancestor_depth + 1 + descendant_depth
        if total_depth > self.MAX_HIERARCHY_DEPTH:
            raise ValidationError(
                {
                    "parent": f"Hierarchy depth would exceed maximum of "
                    f"{self.MAX_HIERARCHY_DEPTH} levels."
                }
            )

    def _get_descendant_depth(self):
        """Return the deepest level of descendants below this node."""
        max_depth = 0
        for child in self.children.all():
            child_depth = 1 + child._get_descendant_depth()
            max_depth = max(max_depth, child_depth)
        return max_depth

    @property
    def effective_kind(self) -> str:
        return self.kind or kind_for_category(self.category)

    def save(self, *args, **kwargs):
        # Auto-generate qualified_slug if not set
        if not self.qualified_slug and self.slug:
            if self.source_pack:
                self.qualified_slug = f"{self.source_pack.slug}/{self.slug}"
            else:
                self.qualified_slug = f"custom/{self.slug}"
        super().save(*args, **kwargs)


class OrgsystemComponent(TimestampedModel):
    """Component instance, optionally linked to an orgsystem."""

    # The organization is reached through `blueprint.threat_model`; `orgsystem` is
    # an optional inventory link, not a tenancy path (it was the nullable key that
    # made #227 possible).
    tenancy = Tenancy.TENANT_OWNED

    # Set only on system and subsystem assets: "this asset stands for that
    # inventory system" (section 4.9). Not a tenancy path. SET_NULL, so deleting
    # an inventory system unlinks the assets and never deletes components (H5).
    orgsystem = models.ForeignKey(
        Orgsystem,
        on_delete=models.SET_NULL,
        related_name="components",
        null=True,
        blank=True,
        help_text="The inventory system a system or subsystem asset stands for",
    )
    component_library = models.ForeignKey(
        ComponentLibrary,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="instances",
        help_text="Null means orphaned/custom component (library item was removed)",
    )
    name = models.CharField(max_length=255)
    zone = models.ForeignKey(
        Zone,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="components",
    )
    source_integration = models.ForeignKey(
        IntegrationSource,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="discovered_components",
    )
    blueprint = models.ForeignKey(
        "threat_models.Blueprint",
        on_delete=models.CASCADE,
        related_name="components",
        help_text="The structural model this component belongs to",
    )

    description = models.TextField(blank=True, default="")
    actor_type = models.CharField(max_length=20, blank=True, default="")
    data_store_type = models.CharField(max_length=20, blank=True, default="")
    data_sensitivity_level = models.CharField(max_length=20, blank=True, default="")
    parent_component = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="children",
    )
    format_metadata = models.JSONField(default=dict, blank=True)

    # Metadata copied from library on creation (for self-sufficiency if orphaned)
    # TODO: drop `null=True` and migrate existing NULLs to "". `component_type` and
    # `provider` below are copied from the library the same way and both spell "not
    # set" as `blank=True` alone, so this field is the odd one of the three.
    category = models.CharField(  # noqa: DJ001
        max_length=30,
        blank=True,
        null=True,
        help_text="Copied from ComponentLibrary.category on creation",
    )
    component_type = models.CharField(
        max_length=100,
        blank=True,
        help_text="Copied from ComponentLibrary.component_type on creation",
    )
    provider = models.CharField(
        max_length=100,
        blank=True,
        help_text="Copied from ComponentLibrary.provider on creation",
    )
    kind = models.CharField(
        max_length=30,
        blank=True,
        default="",
        choices=[(value, value) for value in ASSET_TYPES],
        help_text="CycloneDX asset type; copied from the library, editable; blank derives from the category",
    )

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    @property
    def effective_kind(self) -> str:
        return self.kind or kind_for_category(self.category)


class DataAsset(TimestampedModel):
    """Data asset with classification."""

    tenancy = Tenancy.TENANT_OWNED

    class Sensitivity(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"

    blueprint = models.ForeignKey(
        "threat_models.Blueprint",
        on_delete=models.CASCADE,
        related_name="data_assets",
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default="")
    classification = models.CharField(max_length=100)
    confidentiality = models.CharField(
        max_length=10,
        choices=Sensitivity.choices,
        default=Sensitivity.MEDIUM,
    )
    integrity = models.CharField(
        max_length=10,
        choices=Sensitivity.choices,
        default=Sensitivity.MEDIUM,
    )
    availability = models.CharField(
        max_length=10,
        choices=Sensitivity.choices,
        default=Sensitivity.MEDIUM,
    )
    compliance_tags = models.JSONField(default=list, blank=True)
    data_sensitivity = models.JSONField(default=list, blank=True)
    format_metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if self.data_sensitivity:
            seen = set()
            normalized = []
            for tag in self.data_sensitivity:
                t = str(tag).strip().lower()
                if t and t not in seen:
                    seen.add(t)
                    normalized.append(t)
            self.data_sensitivity = normalized
        super().save(*args, **kwargs)


class ComponentDataAsset(TimestampedModel):
    """Association between component and data asset."""

    tenancy = Tenancy.TENANT_OWNED

    class DataState(models.TextChoices):
        AT_REST = "at_rest", "At Rest"
        PROCESSED = "processed", "Processed"

    component = models.ForeignKey(
        OrgsystemComponent,
        on_delete=models.CASCADE,
        related_name="data_assets",
    )
    data_asset = models.ForeignKey(
        DataAsset,
        on_delete=models.CASCADE,
        related_name="component_associations",
    )
    data_state = models.CharField(
        max_length=20,
        choices=DataState.choices,
        default=DataState.PROCESSED,
    )
    volume = models.CharField(max_length=100, blank=True)
    encrypted = models.BooleanField(default=False)

    class Meta:
        unique_together = ["component", "data_asset"]

    def __str__(self):
        return f"{self.component} - {self.data_asset}"


class Flow(TimestampedModel):
    """Data flow between components."""

    tenancy = Tenancy.TENANT_OWNED

    blueprint = models.ForeignKey(
        "threat_models.Blueprint",
        on_delete=models.CASCADE,
        related_name="flows",
    )
    source_component = models.ForeignKey(
        OrgsystemComponent,
        on_delete=models.CASCADE,
        related_name="outgoing_flows",
    )
    dest_component = models.ForeignKey(
        OrgsystemComponent,
        on_delete=models.CASCADE,
        related_name="incoming_flows",
    )
    label = models.CharField(
        max_length=255,
        blank=True,
        help_text="Display label for the data flow",
    )
    edge_id = models.CharField(
        max_length=100,
        blank=True,
        db_index=True,
        help_text="DFD edge ID this flow was created from",
    )
    description = models.TextField(blank=True, default="")
    flow_type = models.CharField(
        max_length=20,
        choices=[(value, value) for value in FLOW_TYPES],
        default="data",
        help_text="CycloneDX flow type",
    )
    # Shown for data-like types only (data, message, event).
    protocol = models.CharField(max_length=50, blank=True)
    port = models.IntegerField(null=True, blank=True)
    encrypted = models.BooleanField(default=False)
    # Lists of spec values or custom names, with the boundary's rule (I5):
    # authenticated means not empty and not `none`.
    authentication = models.JSONField(default=list, blank=True)
    authorization = models.JSONField(default=list, blank=True)
    # True when a Boundary row separates the two ends (H19); set by sync.
    crosses_boundary = models.BooleanField(default=False)
    has_sensitive_data = models.BooleanField(default=False)
    data_classification = models.JSONField(default=list, blank=True)
    format_metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["source_component", "dest_component"]

    def __str__(self):
        if self.label:
            return self.label
        return f"{self.source_component} -> {self.dest_component}"

    @property
    def is_data_like(self) -> bool:
        from .crossing import is_data_like

        return is_data_like(self.flow_type)

    @property
    def requires_authentication(self) -> bool:
        from .crossing import requires

        return requires(self.authentication)

    def save(self, *args, **kwargs):
        if self.data_classification:
            seen = set()
            normalized = []
            for tag in self.data_classification:
                t = str(tag).strip().lower()
                if t and t not in seen:
                    seen.add(t)
                    normalized.append(t)
            self.data_classification = normalized
        super().save(*args, **kwargs)


class FlowAsset(TimestampedModel):
    """Data assets transported in a data flow."""

    tenancy = Tenancy.TENANT_OWNED

    class ProtectionMethod(models.TextChoices):
        ENCRYPTED = "encrypted", "Encrypted"
        MASKED = "masked", "Masked"
        TOKENIZED = "tokenized", "Tokenized"
        HASHED = "hashed", "Hashed"
        NONE = "none", "None"

    flow = models.ForeignKey(
        Flow,
        on_delete=models.CASCADE,
        related_name="assets",
    )
    data_asset = models.ForeignKey(
        DataAsset,
        on_delete=models.CASCADE,
        related_name="flow_associations",
    )
    protection_method = models.CharField(
        max_length=20,
        choices=ProtectionMethod.choices,
        default=ProtectionMethod.NONE,
    )
    encryption_type = models.CharField(max_length=50, blank=True)
    format = models.CharField(max_length=50, blank=True)
    sensitivity_override = models.CharField(max_length=20, blank=True)

    class Meta:
        unique_together = ["flow", "data_asset"]

    def __str__(self):
        return f"{self.flow} - {self.data_asset}"
