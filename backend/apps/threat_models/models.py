"""
Threat model domain models.
"""

import uuid

from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.core.validators import RegexValidator
from django.db import models
from django.db.models.signals import post_delete
from django.dispatch import receiver

from apps.compliance.models import StandardFramework
from apps.core.models import TimestampedModel
from apps.core.tenancy import Tenancy
from apps.organizations.models import Organization


class ThreatModelQuerySet(models.QuerySet):
    """Queries about who may read which threat models."""

    def visible_to(self, user):
        """Narrow to the threat models `user` is allowed to read.

        Organization membership is the outer bound. Within it, a security team member
        reads every model; everyone else reads the models their teams own, plus the
        ones owned by no team — `owning_team` is nullable for records predating the
        field, and there is no team on them to check against.

        This queryset is the entire read boundary. `CanWrite` and `IsSecurityTeam` both
        return `True` for safe methods (`apps/core/permissions.py`), so nothing else
        narrows a read, and the MCP endpoint has no permission classes running at all —
        it resolves a user from a bearer token and calls this.
        """
        org_ids = user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        visible = self.filter(organization_id__in=org_ids)

        # Security team status is not scoped to an organization: being on one
        # organization's security team grants full visibility in every organization the
        # user belongs to, including ones where they are a plain member. That is
        # precogly/precogly#209, still open. Reproduced here deliberately — this method
        # exists to give the rule one home, not to change it.
        if user.organization_memberships.filter(role="security_team").exists():
            return visible

        team_ids = user.team_memberships.values_list("team_id", flat=True)
        return visible.filter(
            models.Q(owning_team_id__in=team_ids) | models.Q(owning_team__isnull=True)
        )

    def for_listing(self):
        """What ``ThreatModelListSerializer`` reads, in a fixed number of queries.

        Shared by the list endpoint and the MCP reader (R40): the related rows
        come in one join and the blueprint count as an annotation, so the
        query count does not grow with the number of models.
        """
        return self.select_related(
            "created_by",
            "organization",
            "owning_team",
            "owning_team__business_unit",
            "primary_system",
            "review",
            "state",
        ).annotate(listed_blueprint_count=models.Count("blueprints", distinct=True))


LIFECYCLE_PHASES = (
    "design",
    "pre-build",
    "build",
    "post-build",
    "operations",
    "discovery",
    "decommission",
)
# The spec's validityPeriod.reviewFrequency pattern: years, months, weeks, days.
REVIEW_FREQUENCY_PATTERN = r"^P(?!$)(\d+Y)?(\d+M)?(\d+W)?(\d+D)?$"

METHODOLOGIES = (
    "STRIDE",
    "LINDDUN",
    "PASTA",
    "MAESTRO",
    "OWASP",
    "TRIKE",
    "VAST",
    "ATFAA",
    "attack-tree",
)


def default_methodologies():
    return ["STRIDE"]


class ThreatModel(TimestampedModel):
    """Threat model."""

    # One of the seven models carrying `organization` directly, and the anchor most of
    # the rest of the schema reaches an organization through.
    tenancy = Tenancy.TENANT_OWNED

    objects = ThreatModelQuerySet.as_manager()

    class Criticality(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="threat_models",
    )
    # The one system the model is about (item 12); same organization (M13).
    # RESTRICT, not PROTECT: an organization delete takes both (K1).
    primary_system = models.ForeignKey(
        "systems.Orgsystem",
        on_delete=models.RESTRICT,
        null=True,
        blank=True,
        related_name="primary_threat_models",
    )
    # The document identity: a BOM-Link points at it (item 12, H13).
    serial_number = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    owning_team = models.ForeignKey(
        "organizations.Team",
        on_delete=models.PROTECT,
        related_name="threat_models",
        null=True,
        blank=True,
        help_text="Team that owns this threat model (nullable during migration)",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_threat_models",
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    criticality = models.CharField(
        max_length=20,
        choices=Criticality.choices,
        default=Criticality.MEDIUM,
    )
    risk_scoring_method = models.CharField(
        max_length=20,
        choices=[
            ("qualitative-matrix", "Likelihood x Impact (5x5 Matrix)"),
            ("owasp-risk-rating", "OWASP Risk Rating"),
            ("fair", "FAIR"),
            ("mozilla-rra", "Mozilla Rapid Risk Assessment"),
        ],
        default="qualitative-matrix",
        help_text="Scoring methodology used for all risks in this threat model",
    )
    format_metadata = models.JSONField(default=dict, blank=True)
    # Store system context, progress, etc.
    workspace_data = models.JSONField(default=dict, blank=True)
    # The threat modelling methodologies in use: spec values or custom names
    # (section 4.8, item 9).
    methodologies = ArrayField(
        models.CharField(max_length=100),
        default=default_methodologies,
        blank=True,
    )
    # Lifecycle and validity (section 4.8, item 10). Review state is in
    # ``ThreatModelReview``, counters and version in ``ThreatModelState`` (H4).
    lifecycle_phase = models.CharField(
        max_length=20,
        choices=[(value, value) for value in LIFECYCLE_PHASES],
        blank=True,
        default="",
    )
    valid_from = models.DateTimeField(null=True, blank=True)
    valid_until = models.DateTimeField(null=True, blank=True)
    review_frequency = models.CharField(
        max_length=40,
        blank=True,
        default="",
        validators=[
            RegexValidator(
                REVIEW_FREQUENCY_PATTERN,
                "Use an ISO 8601 duration of years, months, weeks or days, such as P6M.",
            )
        ],
        help_text="ISO 8601 duration, e.g. P6M",
    )

    class Meta:
        ordering = ["-updated_at"]

    def __str__(self):
        return self.name

    # The structural rows (components, zones, boundaries, flows, data assets,
    # diagrams, out-of-scope items) belong to a Blueprint, not to the model.
    # These properties read across every blueprint of the model, which is what
    # most readers want: "every component in this threat model". A writer must
    # pick a blueprint.

    @property
    def default_blueprint(self):
        """The first blueprint; every model has at least one (created on save)."""
        return self.blueprints.order_by("display_order", "created_at", "id").first()

    @property
    def dfds(self):
        from apps.diagrams.models import DFD

        return DFD.objects.filter(blueprint__threat_model=self)

    @property
    def components(self):
        from apps.systems.models import OrgsystemComponent

        return OrgsystemComponent.objects.filter(blueprint__threat_model=self)

    @property
    def flows(self):
        from apps.systems.models import Flow

        return Flow.objects.filter(blueprint__threat_model=self)

    @property
    def zones(self):
        from apps.systems.models import Zone

        return Zone.objects.filter(blueprint__threat_model=self)

    @property
    def boundaries(self):
        from apps.systems.models import Boundary

        return Boundary.objects.filter(blueprint__threat_model=self)

    @property
    def data_assets(self):
        from apps.systems.models import DataAsset

        return DataAsset.objects.filter(blueprint__threat_model=self)

    @property
    def out_of_scope_items(self):
        return OutOfScopeItem.objects.filter(blueprint__threat_model=self)


# The CycloneDX 2.0 blueprint model types. A blueprint declares at least one.
MODEL_TYPES = (
    "architecture",
    "behavioral",
    "conceptual",
    "data-flow",
    "deployment",
    "logical",
    "network",
    "operational",
    "physical",
    "process",
)
DEFAULT_MODEL_TYPE = "data-flow"


def default_model_types():
    return [DEFAULT_MODEL_TYPE]


class Blueprint(TimestampedModel):
    """One structural model of the system: its components, zones, boundaries,
    flows, data assets and diagrams.

    A threat model is the document; its blueprints are the structural views
    (a data flow view, a network view, a variant per region). Threats, controls
    and risks stay on the threat model and may target rows of any blueprint.
    Every model has at least one blueprint, created with it.
    """

    tenancy = Tenancy.TENANT_OWNED

    threat_model = models.ForeignKey(
        ThreatModel,
        on_delete=models.CASCADE,
        related_name="blueprints",
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    model_types = models.JSONField(
        default=default_model_types,
        blank=True,
        help_text="CycloneDX model types this blueprint represents; at least one",
    )
    scope_description = models.TextField(blank=True)
    display_order = models.PositiveIntegerField(default=0)
    format_metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        # No unique rule on the name: the spec allows duplicates (H14).
        ordering = ["display_order", "created_at", "id"]

    def __str__(self):
        return f"{self.name} ({self.threat_model})"


ASSUMPTION_TOPICS = (
    "availability",
    "business",
    "compliance",
    "operational",
    "performance",
    "security",
    "technical",
)


class Assumption(TimestampedModel):
    """An assumption a blueprint rests on (section 4.8, item 6)."""

    tenancy = Tenancy.TENANT_OWNED

    class Validity(models.TextChoices):
        UNVERIFIED = "unverified", "Unverified"
        VERIFIED = "verified", "Verified"
        INVALID = "invalid", "Invalid"
        UNKNOWN = "unknown", "Unknown"

    blueprint = models.ForeignKey(
        Blueprint, on_delete=models.CASCADE, related_name="assumptions"
    )
    description = models.TextField()
    topic = models.CharField(
        max_length=20,
        choices=[(value, value) for value in ASSUMPTION_TOPICS],
        blank=True,
        default="",
    )
    validity = models.CharField(
        max_length=20, choices=Validity.choices, default=Validity.UNVERIFIED
    )
    impact = models.TextField(blank=True, default="")
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="owned_assumptions",
    )
    owner_name = models.CharField(
        max_length=255, blank=True, default="", help_text="An owner who is not a user"
    )
    validation_method = models.TextField(blank=True, default="")
    validation_date = models.DateTimeField(null=True, blank=True)
    display_order = models.PositiveIntegerField(default=0)
    format_metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["display_order", "id"]

    def __str__(self):
        return self.description[:60]


class AssumptionComponent(TimestampedModel):
    """A component an assumption relates to (spec ``relatedAssets``, M13)."""

    tenancy = Tenancy.TENANT_OWNED

    assumption = models.ForeignKey(
        Assumption, on_delete=models.CASCADE, related_name="component_links"
    )
    component = models.ForeignKey(
        "systems.OrgsystemComponent",
        on_delete=models.CASCADE,
        related_name="assumption_links",
    )
    display_order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["display_order", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["assumption", "component"], name="unique_assumption_component"
            ),
        ]


class BusinessObjective(TimestampedModel):
    """A business objective threats and risks relate to (section 4.8, item 8).

    No unique rule on the name: the spec allows duplicates (H14).
    """

    tenancy = Tenancy.TENANT_OWNED

    class Criticality(models.TextChoices):
        MINIMAL = "minimal", "Minimal"
        LOW = "low", "Low"
        MODERATE = "moderate", "Moderate"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    threat_model = models.ForeignKey(
        ThreatModel, on_delete=models.CASCADE, related_name="business_objectives"
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default="")
    criticality = models.CharField(
        max_length=20, choices=Criticality.choices, blank=True, default=""
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="owned_business_objectives",
    )
    owner_name = models.CharField(max_length=255, blank=True, default="")
    display_order = models.PositiveIntegerField(default=0)
    format_metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["display_order", "id"]

    def __str__(self):
        return self.name


class ThreatModelReview(TimestampedModel):
    """Who reviewed and approved a model, kept off the model row (H4, F21).

    ``approval_digest`` is the content digest at the moment of approval
    (``threat_models.digest.model_digest``); the review endpoint compares it
    with the current digest to say whether the model changed since (L5).
    Written only by the review service. One row per model, created with it.
    """

    tenancy = Tenancy.TENANT_OWNED

    threat_model = models.OneToOneField(
        ThreatModel, on_delete=models.CASCADE, related_name="review"
    )
    reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reviewed_threat_models",
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    approver = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="approved_threat_models",
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    approval_digest = models.CharField(max_length=64, blank=True, default="")

    def __str__(self):
        return f"review of {self.threat_model}"


class ThreatModelState(TimestampedModel):
    """Counters a model carries, kept off the model row (H4, I7).

    A whole-row save of a threat model from a stale copy must not move a
    counter back, so the counters live here and are written only under a row
    lock by ``threat_models.numbering``. One row per model, created with it.
    """

    tenancy = Tenancy.TENANT_OWNED

    threat_model = models.OneToOneField(
        ThreatModel,
        on_delete=models.CASCADE,
        related_name="state",
    )
    next_threat_number = models.PositiveIntegerField(default=1)
    next_countermeasure_number = models.PositiveIntegerField(default=1)
    # The document version and the digest of the last exported document (M2,
    # N2): the version is raised by an export only when the digest changed.
    version = models.PositiveIntegerField(default=1)
    export_digest = models.CharField(max_length=64, blank=True, default="")

    def __str__(self):
        return f"state of {self.threat_model}"


class ThreatModelLibraryPack(models.Model):
    """Association between threat model and library pack."""

    # The link is tenant-owned even though the pack it names is not: which packs a
    # threat model has connected is that organization's business.
    tenancy = Tenancy.TENANT_OWNED

    threat_model = models.ForeignKey(
        ThreatModel,
        on_delete=models.CASCADE,
        related_name="pack_associations",
    )
    library_pack = models.ForeignKey(
        "packs.LibraryPack",
        on_delete=models.CASCADE,
        related_name="threat_model_associations",
    )

    class Meta:
        unique_together = ["threat_model", "library_pack"]

    def __str__(self):
        return f"{self.threat_model} - {self.library_pack}"


class ThreatModelRelationship(TimestampedModel):
    """Relationship between threat models."""

    tenancy = Tenancy.TENANT_OWNED

    class RelationType(models.TextChoices):
        DEPENDS_ON = "depends_on", "Depends On"
        SUBSYSTEM_OF = "subsystem_of", "Subsystem Of"
        RELATED_TO = "related_to", "Related To"
        SUPERSEDED_BY = "superseded_by", "Superseded By"

    source_threat_model = models.ForeignKey(
        ThreatModel,
        on_delete=models.CASCADE,
        related_name="outgoing_relationships",
    )
    target_threat_model = models.ForeignKey(
        ThreatModel,
        on_delete=models.CASCADE,
        related_name="incoming_relationships",
    )
    relation_type = models.CharField(max_length=20, choices=RelationType.choices)

    class Meta:
        unique_together = [
            "source_threat_model",
            "target_threat_model",
            "relation_type",
        ]

    def __str__(self):
        return f"{self.source_threat_model} {self.relation_type} {self.target_threat_model}"


class ThreatModelFramework(models.Model):
    """Association between threat model and compliance framework."""

    tenancy = Tenancy.TENANT_OWNED

    threat_model = models.ForeignKey(
        ThreatModel,
        on_delete=models.CASCADE,
        related_name="framework_associations",
    )
    framework = models.ForeignKey(
        StandardFramework,
        on_delete=models.CASCADE,
        related_name="threat_model_associations",
    )

    class Meta:
        unique_together = ["threat_model", "framework"]

    def __str__(self):
        return f"{self.threat_model} - {self.framework}"


class ThreatModelReferenceImage(TimestampedModel):
    """Reference image for threat model (whiteboard photos, architecture diagrams, etc.)."""

    tenancy = Tenancy.TENANT_OWNED

    threat_model = models.ForeignKey(
        ThreatModel,
        on_delete=models.CASCADE,
        related_name="reference_images",
    )
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="uploaded_reference_images",
    )
    image = models.ImageField(
        upload_to="reference_images/%Y/%m/",
        help_text="Reference image file (JPEG, PNG, WebP)",
    )
    filename = models.CharField(
        max_length=255,
        help_text="Original filename for display",
    )
    description = models.TextField(
        blank=True,
        help_text="Optional description of what this image shows",
    )
    display_order = models.PositiveIntegerField(
        default=0,
        help_text="Order in gallery (lower = first)",
    )

    class Meta:
        ordering = ["display_order", "-created_at"]

    def __str__(self):
        return f"{self.filename} - {self.threat_model.name}"


class OutOfScopeItem(TimestampedModel):
    """Something a blueprint deliberately leaves out (the spec's scope exclusion)."""

    tenancy = Tenancy.TENANT_OWNED

    blueprint = models.ForeignKey(
        Blueprint,
        on_delete=models.CASCADE,
        related_name="out_of_scope_items",
    )
    name = models.CharField(max_length=255)
    reason = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class UseCase(TimestampedModel):
    """Use case associated with a threat model (CycloneDX 2.0 TM-BOM)."""

    tenancy = Tenancy.TENANT_OWNED

    threat_model = models.ForeignKey(
        ThreatModel,
        on_delete=models.CASCADE,
        related_name="use_cases",
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    flow_data = models.JSONField(
        default=dict,
        blank=True,
        help_text="Structured use case data: preconditions, postconditions, "
        "success_criteria, main_flow, alternative_flows, exceptions",
    )
    format_metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


@receiver(post_delete, sender=ThreatModelReferenceImage)
def delete_reference_image_file(sender, instance, **kwargs):
    """
    Delete the image file from storage when the model instance is deleted.
    """
    if instance.image:
        # Delete the file from storage
        instance.image.delete(save=False)
