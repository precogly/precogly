"""
Threats models - threat library, countermeasures, instances.
"""

from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from apps.core.models import TimestampedModel
from apps.core.tenancy import Tenancy
from apps.systems.models import (
    Boundary,
    ComponentLibrary,
    Flow,
    OrgsystemComponent,
    Zone,
)


class ThreatLibrary(TimestampedModel):
    """Threat template/definition."""

    tenancy = Tenancy.MIXED

    class CustomizationStatus(models.TextChoices):
        ORIGINAL = "original", "Original (from pack)"
        CUSTOMIZED = "customized", "Customized (user edited)"
        DETACHED = "detached", "Detached (unlinked from pack)"

    source_pack = models.ForeignKey(
        "packs.LibraryPack",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="threats",
        help_text="Pack this item came from (null = custom or legacy)",
    )
    slug = models.SlugField(
        max_length=100,
        blank=True,
        help_text="Unique identifier within pack, e.g., 'sql-injection'",
    )
    # `null=True` is required by `unique_threat_qualified_slug` below. Postgres treats
    # NULLs as distinct under a unique index, so any number of rows may carry no
    # qualified slug; `blank=True` with `""` would make the second such row collide
    # with the first. DJ001 cannot see the constraint.
    qualified_slug = models.CharField(  # noqa: DJ001
        max_length=200,
        null=True,
        blank=True,
        db_index=True,
        help_text="Namespace-safe identifier, e.g., 'owasp-top10/sql-injection'",
    )
    name = models.CharField(max_length=255)
    description = models.TextField()

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

    class Meta:
        verbose_name_plural = "Threat library"
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(
                fields=["qualified_slug"],
                name="unique_threat_qualified_slug",
            ),
        ]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        # Auto-generate qualified_slug if not set
        if not self.qualified_slug and self.slug:
            if self.source_pack:
                self.qualified_slug = f"{self.source_pack.slug}/{self.slug}"
            else:
                self.qualified_slug = f"custom/{self.slug}"
        super().save(*args, **kwargs)


class ExternalTaxonomy(TimestampedModel):
    """External threat classification taxonomy (STRIDE, CAPEC, CWE, etc.)."""

    tenancy = Tenancy.SHARED_REFERENCE

    source_pack = models.ForeignKey(
        "packs.LibraryPack",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="taxonomies",
    )
    slug = models.SlugField(max_length=100, unique=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    source_url = models.URLField(blank=True)
    version = models.CharField(max_length=20, blank=True)

    class Meta:
        verbose_name_plural = "External taxonomies"
        ordering = ["name"]

    def __str__(self):
        return self.name


class TaxonomyEntry(TimestampedModel):
    """Single entry within a taxonomy (e.g., STRIDE:tampering, CAPEC:66)."""

    tenancy = Tenancy.SHARED_REFERENCE

    taxonomy = models.ForeignKey(
        ExternalTaxonomy,
        on_delete=models.CASCADE,
        related_name="entries",
    )
    external_id = models.CharField(
        max_length=100,
        help_text="Normalized ID: 'tampering', '66', 'CWE-89', 'T1059'",
    )
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    reference_url = models.URLField(blank=True)

    class Meta:
        unique_together = ["taxonomy", "external_id"]
        ordering = ["taxonomy", "external_id"]

    def __str__(self):
        return f"{self.taxonomy.slug}:{self.external_id}"


class ThreatLibraryTaxonomyEntry(TimestampedModel):
    """M2M join: links a ThreatLibrary to one or more TaxonomyEntry records."""

    tenancy = Tenancy.SHARED_REFERENCE

    threat_library = models.ForeignKey(
        ThreatLibrary,
        on_delete=models.CASCADE,
        related_name="taxonomy_entries",
    )
    taxonomy_entry = models.ForeignKey(
        TaxonomyEntry,
        on_delete=models.CASCADE,
        related_name="threat_libraries",
    )

    class Meta:
        unique_together = ["threat_library", "taxonomy_entry"]

    def __str__(self):
        return f"{self.threat_library} -> {self.taxonomy_entry}"


class ComponentLibraryThreat(TimestampedModel):
    """Association between component library and threats."""

    tenancy = Tenancy.SHARED_REFERENCE

    class AppliesTo(models.TextChoices):
        COMPONENT = "component", "Component"
        FLOW = "flow", "Data Flow"
        BOTH = "both", "Both"

    component_library = models.ForeignKey(
        ComponentLibrary,
        on_delete=models.CASCADE,
        related_name="threats",
    )
    threat_library = models.ForeignKey(
        ThreatLibrary,
        on_delete=models.CASCADE,
        related_name="component_associations",
    )
    default_level = models.CharField(
        max_length=20,
        choices=[
            ("info", "Info"),
            ("low", "Low"),
            ("medium", "Medium"),
            ("high", "High"),
            ("critical", "Critical"),
        ],
        default="medium",
        help_text="Level of the generated scenario (CycloneDX riskScore.level)",
    )
    applies_to = models.CharField(
        max_length=20,
        choices=AppliesTo.choices,
        default=AppliesTo.COMPONENT,
    )
    flow_types = models.JSONField(
        default=list,
        blank=True,
        help_text="Flow types the link applies to; empty means data-like flows only, 'any' means all",
    )

    class Meta:
        unique_together = ["component_library", "threat_library"]

    def __str__(self):
        return f"{self.component_library} - {self.threat_library}"


class CountermeasureLibrary(TimestampedModel):
    """Countermeasure/control template."""

    tenancy = Tenancy.MIXED

    class Cost(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"

    class CustomizationStatus(models.TextChoices):
        ORIGINAL = "original", "Original (from pack)"
        CUSTOMIZED = "customized", "Customized (user edited)"
        DETACHED = "detached", "Detached (unlinked from pack)"

    source_pack = models.ForeignKey(
        "packs.LibraryPack",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="countermeasures",
        help_text="Pack this item came from (null = custom or legacy)",
    )
    slug = models.SlugField(
        max_length=100,
        blank=True,
        help_text="Unique identifier within pack, e.g., 'encryption-at-rest'",
    )
    # `null=True` is required by `unique_countermeasure_qualified_slug` below, for the
    # same reason as `ThreatLibrary.qualified_slug`.
    qualified_slug = models.CharField(  # noqa: DJ001
        max_length=200,
        null=True,
        blank=True,
        db_index=True,
        help_text="Namespace-safe identifier, e.g., 'security-controls/encryption-at-rest'",
    )
    name = models.CharField(max_length=255)
    description = models.TextField()
    control_functions = models.JSONField(
        default=list,
        blank=True,
        help_text="List of control functions, e.g. ['preventive', 'detective']",
    )
    control_nature = models.CharField(
        max_length=20,
        blank=True,
        default="",
        help_text="Control nature: technical, administrative, or physical",
    )
    default_status = models.CharField(
        max_length=20,
        choices=[("gap", "Gap"), ("platform", "Platform")],
        default="gap",
    )
    cost = models.CharField(max_length=20, choices=Cost.choices, default=Cost.MEDIUM)
    applicable_threats = models.ManyToManyField(
        "ThreatLibrary",
        blank=True,
        related_name="applicable_countermeasures",
        help_text="Threats this countermeasure can mitigate",
    )

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

    class Meta:
        verbose_name_plural = "Countermeasure library"
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(
                fields=["qualified_slug"],
                name="unique_countermeasure_qualified_slug",
            ),
        ]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        # Auto-generate qualified_slug if not set
        if not self.qualified_slug and self.slug:
            if self.source_pack:
                self.qualified_slug = f"{self.source_pack.slug}/{self.slug}"
            else:
                self.qualified_slug = f"custom/{self.slug}"
        super().save(*args, **kwargs)


class ThreatIntent(models.TextChoices):
    """Attacker intent classification (CycloneDX 2.0 TM-BOM)."""

    ACCIDENTAL = "accidental", "Accidental"
    OPPORTUNISTIC = "opportunistic", "Opportunistic"
    TARGETED = "targeted", "Targeted"
    PERSISTENT = "persistent", "Persistent"


class ThreatAccessLevel(models.TextChoices):
    """Access level required for threat (CycloneDX 2.0 TM-BOM)."""

    NONE = "none", "None"
    EXTERNAL = "external", "External"
    INTERNAL = "internal", "Internal"
    PRIVILEGED = "privileged", "Privileged"
    PHYSICAL = "physical", "Physical"


class TriageStatus(models.TextChoices):
    """Threat triage decision status."""

    OPEN = "open", "Open"
    ACCEPT = "accept", "Accept"
    MITIGATE = "mitigate", "Mitigate"
    DELEGATE = "delegate", "Delegate"
    ELIMINATE = "eliminate", "Eliminate"


ACTIVE_TRIAGE_STATUSES = (TriageStatus.OPEN, TriageStatus.MITIGATE)


class TargetRefMixin(models.Model):
    """Exactly one of component, flow, zone or boundary (plan section 4.1).

    Four real foreign keys instead of a generic relation, so joins, filters and
    integrity all work. Concrete subclasses name their owner field and call
    ``target_constraints`` to get the exactly-one check and the per-key unique
    rules.
    """

    component = models.ForeignKey(
        OrgsystemComponent,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="%(class)s_targets",
    )
    flow = models.ForeignKey(
        Flow,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="%(class)s_targets",
    )
    zone = models.ForeignKey(
        Zone,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="%(class)s_targets",
    )
    boundary = models.ForeignKey(
        Boundary,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="%(class)s_targets",
    )
    display_order = models.PositiveIntegerField(default=0)

    TARGET_KINDS = ("component", "flow", "zone", "boundary")

    class Meta:
        abstract = True

    @classmethod
    def target_constraints(cls, owner_field: str, prefix: str):
        exactly_one = models.Q()
        for kind in cls.TARGET_KINDS:
            clause = models.Q(**{f"{kind}__isnull": False})
            for other in cls.TARGET_KINDS:
                if other != kind:
                    clause &= models.Q(**{f"{other}__isnull": True})
            exactly_one |= clause
        constraints = [
            models.CheckConstraint(
                check=exactly_one, name=f"{prefix}_exactly_one_target"
            )
        ]
        for kind in cls.TARGET_KINDS:
            constraints.append(
                models.UniqueConstraint(
                    fields=[owner_field, kind],
                    condition=models.Q(**{f"{kind}__isnull": False}),
                    name=f"{prefix}_unique_{kind}",
                )
            )
        return constraints

    @property
    def target_kind(self) -> str:
        for kind in self.TARGET_KINDS:
            if getattr(self, f"{kind}_id") is not None:
                return kind
        return ""

    @property
    def target(self):
        kind = self.target_kind
        return getattr(self, kind) if kind else None

    @property
    def target_id(self):
        kind = self.target_kind
        return getattr(self, f"{kind}_id") if kind else None


class Rating(TimestampedModel):
    """One rating, shaped on the CycloneDX ``rating`` object (#31 comment, 2.1).

    Holds a threat's rating and a risk's inherent, residual and target
    ratings. ``level`` is the one value comparable across methods; ``score``
    stays on the method's native scale and is null for level-only ratings.
    ``organization`` is set by ``apply_rating`` from the owner's threat model,
    never from a request body.
    """

    tenancy = Tenancy.TENANT_OWNED

    class Level(models.TextChoices):  # CycloneDX riskScore.level
        INFO = "info", "Info"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    class LikelihoodLevel(models.TextChoices):  # CycloneDX likelihood.level
        VERY_LOW = "very-low", "Very low"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        VERY_HIGH = "very-high", "Very high"
        CERTAIN = "certain", "Certain"

    class ImpactLevel(models.TextChoices):  # CycloneDX impact.level
        NEGLIGIBLE = "negligible", "Negligible"
        LOW = "low", "Low"
        MODERATE = "moderate", "Moderate"
        MAJOR = "major", "Major"
        CATASTROPHIC = "catastrophic", "Catastrophic"

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="+"
    )
    methodology = models.CharField(
        max_length=40, help_text="CycloneDX methodology value, or a custom name"
    )
    level = models.CharField(max_length=10, choices=Level.choices, db_index=True)
    score = models.FloatField(null=True, blank=True, db_index=True)

    likelihood_level = models.CharField(
        max_length=10, choices=LikelihoodLevel.choices, blank=True
    )
    likelihood_score = models.FloatField(null=True, blank=True)
    likelihood_factors = models.JSONField(default=list, blank=True)
    likelihood_extra = models.JSONField(default=dict, blank=True)

    impact_level = models.CharField(
        max_length=12, choices=ImpactLevel.choices, blank=True
    )
    impact_score = models.FloatField(null=True, blank=True)
    impact_factors = models.JSONField(default=list, blank=True)
    impact_extra = models.JSONField(default=dict, blank=True)

    rationale = models.TextField(blank=True)

    LEVEL_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    class Meta:
        ordering = ["id"]

    def __str__(self):
        score = f" {self.score:g}" if self.score is not None else ""
        return f"{self.level}{score} ({self.methodology})"


class InstanceThreat(TimestampedModel):
    """A threat scenario of a threat model: the attack story on its targets.

    One table for every scenario, whatever it targets (plan section 4.1). A
    scenario has zero or many targets through ``InstanceThreatTarget``; with
    ``whole_system`` set it has none and applies to the whole system. The two
    states are exclusive and the flag is explicit, so losing targets can never
    turn a scenario into a whole-system one by accident (H9).
    """

    tenancy = Tenancy.TENANT_OWNED

    class Status(models.TextChoices):
        EXPOSED = "exposed", "Exposed"
        ADDRESSABLE = "addressable", "Addressable"
        MITIGATED = "mitigated", "Mitigated"

    threat_model = models.ForeignKey(
        "threat_models.ThreatModel",
        on_delete=models.CASCADE,
        related_name="threats",
    )
    number = models.PositiveIntegerField(
        help_text="Unique within the threat model, assigned once, never reused (T7 is 7)"
    )
    whole_system = models.BooleanField(
        default=False,
        help_text="True: applies to the whole system and has no targets",
    )
    auto_generated = models.BooleanField(
        default=False,
        help_text="Set by library generation, cleared on the first user edit",
    )
    threat_library = models.ForeignKey(
        ThreatLibrary,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="instances",
        help_text="Null means orphaned/custom threat (library item was removed)",
    )
    # The scenario's one rating (section 4.2, K1): RESTRICT, so a rating a
    # scenario points at cannot be deleted on its own, while an organization
    # delete that takes both in one operation goes through.
    rating = models.OneToOneField(Rating, on_delete=models.RESTRICT, related_name="+")
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.EXPOSED,
    )

    # Triage decision
    triage_status = models.CharField(
        max_length=20,
        choices=TriageStatus.choices,
        default=TriageStatus.OPEN,
    )
    decision_rationale = models.TextField(
        blank=True,
        default="",
        help_text="Rationale for triage decision (recommended for accept/delegate/eliminate)",
    )

    format_metadata = models.JSONField(default=dict, blank=True)
    display_order = models.PositiveIntegerField(default=0)

    # Metadata copied from library on creation (for self-sufficiency if orphaned)
    threat_name = models.CharField(
        max_length=255,
        blank=True,
        help_text="Copied from ThreatLibrary.name on creation",
    )
    threat_description = models.TextField(
        blank=True,
        help_text="Copied from ThreatLibrary.description on creation",
    )
    taxonomy_snapshot = models.JSONField(
        blank=True,
        default=list,
        help_text="Snapshot of taxonomy entries at creation time",
    )

    impact_description = models.TextField(
        blank=True,
        default="",
        help_text="Narrative description of what the attacker achieves",
    )
    # The scenario's actor: a persona of this model, or free text, never both (K3).
    actor_persona = models.ForeignKey(
        "ThreatPersona",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="threats",
    )
    threat_actor_text = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="Free-text threat actor (e.g. 'state actor', 'hacktivist')",
    )
    intent = models.CharField(
        max_length=20,
        choices=ThreatIntent.choices,
        blank=True,
        default="",
        help_text="Attacker intent: accidental, opportunistic, targeted, or persistent",
    )
    access_level = models.CharField(
        max_length=20,
        choices=ThreatAccessLevel.choices,
        blank=True,
        default="",
        help_text="Access level required: none, external, internal, privileged, or physical",
    )

    class Meta:
        ordering = ["display_order", "created_at", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["threat_model", "number"], name="unique_threat_number_per_model"
            ),
            models.CheckConstraint(
                check=models.Q(actor_persona__isnull=True)
                | models.Q(threat_actor_text=""),
                name="threat_actor_persona_or_text",
            ),
        ]

    def __str__(self):
        return f"T{self.number} {self.threat_name or self.threat_library or ''}".strip()

    def save(self, *args, **kwargs):
        if self.number is None and self.threat_model_id:
            from apps.threat_models.numbering import THREATS, allocate_numbers

            self.number = allocate_numbers(self.threat_model_id, THREATS, 1)[0]
        if self.rating_id is None and self.threat_model_id:
            # A direct create (admin, a test) gets a level-only medium rating;
            # the service is the normal path and rates from the inputs.
            self.rating = Rating.objects.create(
                organization_id=self.threat_model.organization_id,
                methodology="manual",
                level=Rating.Level.MEDIUM,
            )
        super().save(*args, **kwargs)

    @property
    def display_number(self) -> str:
        return f"T{self.number}"


class InstanceThreatTarget(TargetRefMixin):
    """One target of a scenario: a component, flow, zone or boundary."""

    tenancy = Tenancy.TENANT_OWNED

    threat = models.ForeignKey(
        InstanceThreat,
        on_delete=models.CASCADE,
        related_name="targets",
    )

    class Meta:
        ordering = ["display_order", "id"]
        constraints = TargetRefMixin.target_constraints("threat", "threat_target")

    def __str__(self):
        return f"{self.threat} -> {self.target_kind} {self.target_id}"


class InstanceCountermeasure(TimestampedModel):
    """Unified countermeasure instance scoped to a threat model, linked to threats via junction table."""

    tenancy = Tenancy.TENANT_OWNED

    class Status(models.TextChoices):
        GAP = "gap", "Gap"
        PLANNED = "planned", "Planned"
        IN_PROGRESS = "in_progress", "In Progress"
        IMPLEMENTED = "implemented", "Implemented"
        VERIFIED = "verified", "Verified"
        WAIVED = "waived", "Waived"
        PLATFORM = "platform", "Platform"
        DECOMMISSIONED = "decommissioned", "Decommissioned"

    threat_model = models.ForeignKey(
        "threat_models.ThreatModel",
        on_delete=models.CASCADE,
        related_name="countermeasures",
    )
    countermeasure_library = models.ForeignKey(
        CountermeasureLibrary,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="instances",
        help_text="Null means orphaned/custom countermeasure (library item was removed)",
    )
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.GAP)
    verified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="verified_countermeasures",
    )
    evidence_url = models.URLField(blank=True)
    required_for_release = models.BooleanField(default=False)
    assigned_owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_countermeasures",
    )

    # Metadata copied from library on creation (for self-sufficiency if orphaned)
    countermeasure_name = models.CharField(
        max_length=255,
        blank=True,
        help_text="Copied from CountermeasureLibrary.name on creation",
    )
    countermeasure_description = models.TextField(
        blank=True,
        help_text="Copied from CountermeasureLibrary.description on creation",
    )
    control_functions = models.JSONField(
        default=list,
        blank=True,
        help_text="Copied from CountermeasureLibrary.control_functions on creation",
    )
    control_nature = models.CharField(
        max_length=20,
        blank=True,
        default="",
        help_text="Copied from CountermeasureLibrary.control_nature on creation",
    )
    effectiveness = models.FloatField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)],
        help_text="User-assessed control effectiveness (0.0-1.0). Null = not yet assessed.",
    )
    priority = models.CharField(max_length=10, default="none", blank=True)
    due_date = models.DateField(
        null=True, blank=True, help_text="Target completion date"
    )
    external_ticket_url = models.URLField(
        blank=True, help_text="Link to Jira/GitHub/etc. ticket"
    )
    format_metadata = models.JSONField(default=dict, blank=True)
    auto_generated = models.BooleanField(
        default=False,
        help_text="Set by library generation, cleared on the first user edit",
    )
    number = models.PositiveIntegerField(
        help_text="Unique within the threat model, assigned once, never reused (C3 is 3)"
    )
    implemented_by_party = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="The provider that implements the control, as text (until a party model exists)",
    )
    source = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Where the control came from: a compliance tool, a pentest, a vendor list",
    )

    class Meta:
        ordering = ["created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["threat_model", "number"],
                name="unique_countermeasure_number_per_model",
            ),
        ]

    def __str__(self):
        return f"CM:{self.countermeasure_name or self.countermeasure_library}"

    def save(self, *args, **kwargs):
        # The service allocates numbers; a direct create (admin, a test) gets
        # one here so a row can never be saved without its number.
        if self.number is None and self.threat_model_id:
            from apps.threat_models.numbering import COUNTERMEASURES, allocate_numbers

            self.number = allocate_numbers(self.threat_model_id, COUNTERMEASURES, 1)[0]
        super().save(*args, **kwargs)

    @property
    def display_number(self) -> str:
        return f"C{self.number}"

    @property
    def days_overdue(self) -> int | None:
        """Days past ``due_date`` for a control that is not yet in effect, else None.

        From PR #559: a POA&M scheduled completion date and the due date are
        the same thing under different vocabulary, so one field serves both.
        """
        if self.due_date and self.status not in (
            self.Status.IMPLEMENTED,
            self.Status.VERIFIED,
            self.Status.PLATFORM,
        ):
            from datetime import date

            delta = (date.today() - self.due_date).days
            return delta if delta > 0 else None
        return None


class InstanceCountermeasureTarget(TargetRefMixin):
    """Where a control applies (``appliesTo``). No rows means the whole system.

    Targets say scope; they never change a threat's status (plan section 4.3,
    L4). Coverage is only ever by explicit threat links.
    """

    tenancy = Tenancy.TENANT_OWNED

    countermeasure = models.ForeignKey(
        InstanceCountermeasure,
        on_delete=models.CASCADE,
        related_name="targets",
    )

    class Meta:
        ordering = ["display_order", "id"]
        constraints = TargetRefMixin.target_constraints(
            "countermeasure", "countermeasure_target"
        )

    def __str__(self):
        return f"{self.countermeasure} applies to {self.target_kind} {self.target_id}"


class InstanceCountermeasureProvider(TimestampedModel):
    """A component that implements a control (``implementedBy``, G10)."""

    tenancy = Tenancy.TENANT_OWNED

    countermeasure = models.ForeignKey(
        InstanceCountermeasure,
        on_delete=models.CASCADE,
        related_name="provider_links",
    )
    component = models.ForeignKey(
        OrgsystemComponent,
        on_delete=models.CASCADE,
        related_name="implemented_countermeasure_links",
    )
    display_order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["display_order", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["countermeasure", "component"],
                name="unique_countermeasure_provider",
            ),
        ]

    def __str__(self):
        return f"{self.countermeasure} implemented by {self.component}"


class CountermeasureThreatLink(TimestampedModel):
    """A countermeasure explicitly linked to a threat scenario."""

    tenancy = Tenancy.TENANT_OWNED

    countermeasure = models.ForeignKey(
        InstanceCountermeasure,
        on_delete=models.CASCADE,
        related_name="threat_links",
    )
    threat = models.ForeignKey(
        InstanceThreat,
        on_delete=models.CASCADE,
        related_name="countermeasure_links",
    )
    display_order = models.PositiveIntegerField(default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["countermeasure", "threat"],
                name="unique_cm_threat_link",
            ),
        ]
        ordering = ["display_order", "created_at"]

    def __str__(self):
        return f"{self.countermeasure} -> {self.threat}"


class VerificationTest(TimestampedModel):
    """Verification test for countermeasures."""

    # Tenant-owned despite reading like a template: `last_run_at`, `passed`, and
    # `evidence` are one organization's test result, not a definition. Like Zone it
    # carries no foreign key saying so — it is reached only through
    # `InstanceCountermeasureTest` — and `/api/verification-tests/` serves it. Suspected
    # to leak the same way #404 does; unverified.
    tenancy = Tenancy.TENANT_OWNED

    class Method(models.TextChoices):
        PENTEST = "pentest", "Penetration Test"
        AUTO = "auto", "Automated Scan"
        CODE_REVIEW = "code_review", "Code Review"

    name = models.CharField(max_length=255)
    method = models.CharField(max_length=20, choices=Method.choices)
    last_run_at = models.DateTimeField(null=True, blank=True)
    passed = models.BooleanField(default=False)
    evidence = models.TextField(blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class InstanceCountermeasureTest(TimestampedModel):
    """Association between countermeasure and verification test."""

    tenancy = Tenancy.TENANT_OWNED

    countermeasure = models.ForeignKey(
        InstanceCountermeasure,
        on_delete=models.CASCADE,
        related_name="tests",
    )
    verification_test = models.ForeignKey(
        VerificationTest,
        on_delete=models.CASCADE,
        related_name="countermeasure_tests",
    )
    tested_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ["countermeasure", "verification_test"]
        ordering = ["-tested_at"]

    def __str__(self):
        return f"{self.countermeasure} - {self.verification_test}"


class CountermeasureComment(TimestampedModel):
    """Comment/history log entry for a countermeasure instance."""

    tenancy = Tenancy.TENANT_OWNED

    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="countermeasure_comments",
    )
    countermeasure = models.ForeignKey(
        InstanceCountermeasure,
        on_delete=models.CASCADE,
        related_name="comments",
    )
    body = models.TextField()
    # Optional: record what changed (e.g., "status: gap → planned")
    change_summary = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"Comment on {self.countermeasure} by {self.author}"


class PentestFinding(TimestampedModel):
    """Pentest finding for reconciliation."""

    tenancy = Tenancy.TENANT_OWNED

    class ReconciliationStatus(models.TextChoices):
        MATCHED = "matched", "Matched"
        UNPREDICTED = "unpredicted", "Unpredicted"
        FALSE_POSITIVE = "false_positive", "False Positive"

    threat_model = models.ForeignKey(
        "threat_models.ThreatModel",
        on_delete=models.CASCADE,
        related_name="pentest_findings",
    )
    finding_description = models.TextField()
    severity = models.CharField(max_length=20)
    matched_threat_library = models.ForeignKey(
        ThreatLibrary,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="matched_pentest_findings",
    )
    matched_countermeasure = models.ForeignKey(
        InstanceCountermeasure,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="pentest_findings",
    )
    reconciliation_status = models.CharField(
        max_length=20,
        choices=ReconciliationStatus.choices,
        default=ReconciliationStatus.UNPREDICTED,
    )

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Finding: {self.finding_description[:50]}..."


class InstanceCountermeasureStandard(TimestampedModel):
    """Instance-level compliance mapping for countermeasures.

    Allows overriding library-level compliance mappings for specific countermeasure instances.
    Instance mappings take precedence over library mappings for the same requirement.
    """

    # The override belongs to whoever made it, even though both things it names —
    # a library countermeasure and a published requirement — are shared.
    tenancy = Tenancy.TENANT_OWNED

    class Sufficiency(models.TextChoices):
        FULL = "full", "Full"
        PARTIAL = "partial", "Partial"

    countermeasure = models.ForeignKey(
        InstanceCountermeasure,
        on_delete=models.CASCADE,
        related_name="instance_standard_mappings",
    )
    requirement = models.ForeignKey(
        "compliance.StandardRequirement",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="instance_countermeasure_mappings",
    )
    sufficiency = models.CharField(
        max_length=10,
        choices=Sufficiency.choices,
        default=Sufficiency.PARTIAL,
    )

    # Snapshot fields — populated on creation, used as fallback when requirement is NULL
    section_code = models.CharField(max_length=50, blank=True, default="")
    framework_name = models.CharField(max_length=255, blank=True, default="")
    requirement_description = models.TextField(blank=True, default="")

    class Meta:
        unique_together = ["countermeasure", "requirement"]
        verbose_name = "Countermeasure compliance mapping"
        verbose_name_plural = "Countermeasure compliance mappings"

    def __str__(self):
        return f"{self.countermeasure} - {self.requirement} ({self.sufficiency})"


def build_taxonomy_snapshot(threat_library):
    """Build a snapshot list of taxonomy entries for a threat library."""
    if not threat_library:
        return []
    return [
        {
            "taxonomy_slug": join.taxonomy_entry.taxonomy.slug,
            "external_id": join.taxonomy_entry.external_id,
            "title": join.taxonomy_entry.title,
        }
        for join in threat_library.taxonomy_entries.select_related(
            "taxonomy_entry__taxonomy"
        ).all()
    ]


class Risk(TimestampedModel):
    """Business-level risk that aggregates multiple threat instances."""

    tenancy = Tenancy.TENANT_OWNED

    class Status(models.TextChoices):  # CycloneDX risk.status
        IDENTIFIED = "identified", "Identified"
        ASSESSED = "assessed", "Assessed"
        MITIGATED = "mitigated", "Mitigated"
        ACCEPTED = "accepted", "Accepted"
        TRANSFERRED = "transferred", "Transferred"
        RETIRED = "retired", "Retired"

    threat_model = models.ForeignKey(
        "threat_models.ThreatModel",
        on_delete=models.CASCADE,
        related_name="risks",
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    # Where the risk is in its lifecycle (section 4.7). The derived `exposure`
    # (what the threats look like) is a different question and is not stored.
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.IDENTIFIED
    )
    statement = models.TextField(
        blank=True, default="", help_text="Source, event and impact in one sentence"
    )
    # The three ratings of the CycloneDX risk (section 4.2). Inherent is
    # RESTRICT for the same reason as the scenario's rating (K1).
    inherent = models.OneToOneField(Rating, on_delete=models.RESTRICT, related_name="+")
    residual = models.OneToOneField(
        Rating, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    target = models.OneToOneField(
        Rating, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    domains = models.JSONField(
        default=list,
        blank=True,
        help_text="Risk domains, e.g. ['security', 'compliance']",
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="owned_risks",
    )
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_risks",
    )
    format_metadata = models.JSONField(default=dict)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["threat_model", "name"],
                name="unique_risk_per_threat_model",
            ),
        ]

    def __str__(self):
        return f"{self.name} ({self.inherent.level})"

    def save(self, *args, **kwargs):
        if self.inherent_id is None and self.threat_model_id:
            self.inherent = Rating.objects.create(
                organization_id=self.threat_model.organization_id,
                methodology="manual",
                level=Rating.Level.MEDIUM,
            )
        super().save(*args, **kwargs)


class ThreatPersona(TimestampedModel):
    """Threat persona scoped to a specific threat model."""

    tenancy = Tenancy.TENANT_OWNED

    threat_model = models.ForeignKey(
        "threat_models.ThreatModel",
        on_delete=models.CASCADE,
        related_name="threat_personas",
    )
    symbolic_name = models.SlugField(
        max_length=100,
        help_text="Machine-readable identifier, e.g., 'malicious-insider'",
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default="")
    is_person = models.BooleanField(default=True)
    malicious_intent = models.BooleanField(default=True)
    skill_level = models.CharField(max_length=100, blank=True, default="")
    motivation = models.TextField(blank=True, default="")
    resources = models.TextField(blank=True, default="")
    objectives = models.TextField(blank=True, default="")
    format_metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text="Extra fields from JSON for round-trip fidelity",
    )

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(
                fields=["threat_model", "symbolic_name"],
                name="unique_persona_per_threat_model",
            ),
        ]

    def __str__(self):
        return self.name


class ThreatSource(TimestampedModel):
    """Global reference table for threat sources (e.g., NIST SP 800-30r1)."""

    tenancy = Tenancy.SHARED_REFERENCE

    slug = models.SlugField(max_length=50, unique=True)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class ThreatSourceLink(TimestampedModel):
    """A threat source cited by a threat scenario."""

    # The source is shared; which threat instance cites it is not.
    tenancy = Tenancy.TENANT_OWNED

    source = models.ForeignKey(
        ThreatSource,
        on_delete=models.CASCADE,
        related_name="threat_links",
    )
    threat = models.ForeignKey(
        InstanceThreat,
        on_delete=models.CASCADE,
        related_name="source_links",
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["source", "threat"], name="unique_source_threat"
            ),
        ]

    def __str__(self):
        return f"{self.source.name} -> {self.threat}"


class InstanceThreatTaxonomyEntry(TimestampedModel):
    """Instance-level taxonomy entry on a threat scenario.

    Supplements library-level taxonomy associations (ThreatLibraryTaxonomyEntry)
    with user-added entries on individual scenarios.
    """

    tenancy = Tenancy.TENANT_OWNED

    taxonomy_entry = models.ForeignKey(
        TaxonomyEntry,
        on_delete=models.CASCADE,
        related_name="instance_threat_links",
    )
    threat = models.ForeignKey(
        InstanceThreat,
        on_delete=models.CASCADE,
        related_name="instance_taxonomy_links",
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["taxonomy_entry", "threat"], name="unique_taxonomy_threat"
            ),
        ]

    def __str__(self):
        return f"{self.taxonomy_entry} -> {self.threat}"


class RiskResponse(TimestampedModel):
    """Structured risk response (CycloneDX 2.0 TM-BOM)."""

    tenancy = Tenancy.TENANT_OWNED

    class Strategy(models.TextChoices):
        AVOID = "avoid", "Avoid"
        REDUCE = "reduce", "Reduce"
        TRANSFER = "transfer", "Transfer"
        ACCEPT = "accept", "Accept"

    class Status(models.TextChoices):
        PLANNED = "planned", "Planned"
        IN_PROGRESS = "in_progress", "In Progress"
        IMPLEMENTED = "implemented", "Implemented"
        VERIFIED = "verified", "Verified"

    risk = models.ForeignKey(
        Risk,
        on_delete=models.CASCADE,
        related_name="responses",
    )
    strategy = models.CharField(max_length=20, choices=Strategy.choices)
    description = models.TextField(blank=True)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PLANNED,
    )
    effectiveness = models.FloatField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)],
    )

    class Cost(models.TextChoices):
        TRIVIAL = "trivial", "Trivial"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        EXTREME = "extreme", "Extreme"

    class Priority(models.TextChoices):
        NONE = "none", "None"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    cost = models.CharField(max_length=20, choices=Cost.choices, blank=True, default="")
    priority = models.CharField(
        max_length=20, choices=Priority.choices, blank=True, default=""
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="owned_risk_responses",
    )
    target_date = models.DateTimeField(null=True, blank=True)
    format_metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"{self.risk.name} - {self.strategy}"


class InstanceThreatBusinessObjective(TimestampedModel):
    """A business objective a scenario puts at risk (spec
    ``threat.relatedBusinessObjectives``, M13)."""

    tenancy = Tenancy.TENANT_OWNED

    threat = models.ForeignKey(
        InstanceThreat,
        on_delete=models.CASCADE,
        related_name="business_objective_links",
    )
    business_objective = models.ForeignKey(
        "threat_models.BusinessObjective",
        on_delete=models.CASCADE,
        related_name="threat_links",
    )
    display_order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["display_order", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["threat", "business_objective"],
                name="unique_threat_business_objective",
            ),
        ]


class RiskBusinessObjective(TimestampedModel):
    """A business objective a risk puts at risk (spec ``risk.relatedBusinessObjectives``)."""

    tenancy = Tenancy.TENANT_OWNED

    risk = models.ForeignKey(
        Risk, on_delete=models.CASCADE, related_name="business_objective_links"
    )
    business_objective = models.ForeignKey(
        "threat_models.BusinessObjective",
        on_delete=models.CASCADE,
        related_name="risk_links",
    )
    display_order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["display_order", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["risk", "business_objective"],
                name="unique_risk_business_objective",
            ),
        ]


class RiskResponseCountermeasure(TimestampedModel):
    """A control a risk response relies on (spec ``riskResponse.controls``, D6, M13)."""

    tenancy = Tenancy.TENANT_OWNED

    response = models.ForeignKey(
        RiskResponse, on_delete=models.CASCADE, related_name="countermeasure_links"
    )
    countermeasure = models.ForeignKey(
        InstanceCountermeasure,
        on_delete=models.CASCADE,
        related_name="risk_response_links",
    )
    display_order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["display_order", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["response", "countermeasure"],
                name="unique_risk_response_countermeasure",
            ),
        ]

    def __str__(self):
        return f"{self.response} relies on {self.countermeasure}"


class RiskThreat(TimestampedModel):
    """Junction table linking a Risk to threat scenarios."""

    tenancy = Tenancy.TENANT_OWNED

    risk = models.ForeignKey(
        Risk,
        on_delete=models.CASCADE,
        related_name="risk_threats",
    )
    threat = models.ForeignKey(
        InstanceThreat,
        on_delete=models.CASCADE,
        related_name="risk_links",
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["risk", "threat"], name="unique_risk_threat"
            ),
        ]

    def __str__(self):
        return f"{self.risk.name} <- {self.threat}"
