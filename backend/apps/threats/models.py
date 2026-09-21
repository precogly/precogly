"""
Threats models - threat library, countermeasures, instances.
"""

from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from apps.core.models import TimestampedModel
from apps.core.tenancy import Tenancy
from apps.systems.models import ComponentLibrary, DataFlow, OrgsystemComponent


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
    default_severity = models.CharField(max_length=20, default="medium")
    applies_to = models.CharField(
        max_length=20,
        choices=AppliesTo.choices,
        default=AppliesTo.COMPONENT,
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


class ComponentInstanceThreat(TimestampedModel):
    """Threat instance for a specific component."""

    tenancy = Tenancy.TENANT_OWNED

    class Severity(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    class Status(models.TextChoices):
        EXPOSED = "exposed", "Exposed"
        ADDRESSABLE = "addressable", "Addressable"
        MITIGATED = "mitigated", "Mitigated"

    component = models.ForeignKey(
        OrgsystemComponent,
        on_delete=models.CASCADE,
        related_name="threats",
    )
    threat_library = models.ForeignKey(
        ThreatLibrary,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="component_instances",
        help_text="Null means orphaned/custom threat (library item was removed)",
    )
    inherent_severity = models.CharField(max_length=20, choices=Severity.choices)
    residual_severity = models.CharField(
        max_length=20,
        choices=Severity.choices,
        blank=True,
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.EXPOSED,
    )
    severity_scoring_metadata = models.JSONField(default=dict, blank=True)

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
        unique_together = ["component", "threat_library"]
        ordering = ["component", "display_order", "created_at"]

    def __str__(self):
        return f"{self.component} - {self.threat_library}"


class DataFlowInstanceThreat(TimestampedModel):
    """Threat instance for a specific data flow."""

    tenancy = Tenancy.TENANT_OWNED

    class Severity(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    class Status(models.TextChoices):
        EXPOSED = "exposed", "Exposed"
        ADDRESSABLE = "addressable", "Addressable"
        MITIGATED = "mitigated", "Mitigated"

    data_flow = models.ForeignKey(
        DataFlow,
        on_delete=models.CASCADE,
        related_name="threats",
    )
    threat_library = models.ForeignKey(
        ThreatLibrary,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="flow_instances",
        help_text="Null means orphaned/custom threat (library item was removed)",
    )
    inherent_severity = models.CharField(max_length=20, choices=Severity.choices)
    residual_severity = models.CharField(
        max_length=20,
        choices=Severity.choices,
        blank=True,
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.EXPOSED,
    )
    severity_scoring_metadata = models.JSONField(default=dict, blank=True)

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
        unique_together = ["data_flow", "threat_library"]
        ordering = ["data_flow", "display_order", "created_at"]

    def __str__(self):
        return f"{self.data_flow} - {self.threat_library}"


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

    class Source(models.TextChoices):
        MANUAL = "manual", "Manual"
        VAULT_IMPORT = "vault_import", "Vault Import"
        PENTEST = "pentest", "Pentest"

    source = models.CharField(
        max_length=20,
        choices=Source.choices,
        default=Source.MANUAL,
        help_text="Where this countermeasure instance originated",
    )
    poam_id = models.CharField(
        max_length=50,
        blank=True,
        db_index=True,
        help_text="OSCAL POA&M identifier (e.g. from a vault-derived CDX import)",
    )
    scheduled_completion = models.DateField(
        null=True,
        blank=True,
        help_text="POA&M OSCAL scheduled-completion-date, distinct from due_date",
    )

    @property
    def days_overdue(self) -> int | None:
        """Days past scheduled_completion for an unresolved countermeasure, else None."""
        if self.scheduled_completion and self.status not in (
            self.Status.IMPLEMENTED,
            self.Status.VERIFIED,
        ):
            from datetime import date

            delta = (date.today() - self.scheduled_completion).days
            return delta if delta > 0 else None
        return None

    # Zone inheritance tracking
    is_inherited = models.BooleanField(default=False)
    inherited_from_component_name = models.CharField(max_length=255, blank=True)
    inherited_from_zone_name = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"CM:{self.countermeasure_name or self.countermeasure_library}"


class CountermeasureThreatLink(TimestampedModel):
    """Polymorphic junction table linking a countermeasure to component and/or flow threats."""

    tenancy = Tenancy.TENANT_OWNED

    countermeasure = models.ForeignKey(
        InstanceCountermeasure,
        on_delete=models.CASCADE,
        related_name="threat_links",
    )
    component_threat = models.ForeignKey(
        ComponentInstanceThreat,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="countermeasure_links",
    )
    flow_threat = models.ForeignKey(
        DataFlowInstanceThreat,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="countermeasure_links",
    )
    display_order = models.PositiveIntegerField(default=0)

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=(
                    models.Q(component_threat__isnull=False, flow_threat__isnull=True)
                    | models.Q(component_threat__isnull=True, flow_threat__isnull=False)
                ),
                name="cm_link_exactly_one_threat_fk",
            ),
            models.UniqueConstraint(
                fields=["countermeasure", "component_threat"],
                condition=models.Q(component_threat__isnull=False),
                name="unique_cm_component_threat_link",
            ),
            models.UniqueConstraint(
                fields=["countermeasure", "flow_threat"],
                condition=models.Q(flow_threat__isnull=False),
                name="unique_cm_flow_threat_link",
            ),
        ]
        ordering = ["display_order", "created_at"]

    def __str__(self):
        threat = self.component_threat or self.flow_threat
        return f"{self.countermeasure} -> {threat}"


class VerificationTest(TimestampedModel):
    """Verification test for countermeasures."""

    # Tenant-owned despite reading like a template: `last_run_at`, `passed`, and
    # `evidence` are one organization's test result, not a definition. Like TrustZone it
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

    class Level(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    class Response(models.TextChoices):
        ACCEPT = "accept", "Accept"
        MITIGATE = "mitigate", "Mitigate"
        TRANSFER = "transfer", "Transfer"
        AVOID = "avoid", "Avoid"

    threat_model = models.ForeignKey(
        "threat_models.ThreatModel",
        on_delete=models.CASCADE,
        related_name="risks",
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    scoring_metadata = models.JSONField(default=dict)
    inherent_score = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)],
    )
    inherent_level = models.CharField(max_length=10, choices=Level.choices)
    residual_score = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
    )
    residual_level = models.CharField(
        max_length=10,
        choices=Level.choices,
        blank=True,
    )
    # TODO: drop `null=True` and migrate existing NULLs to "". `residual_level` two
    # fields up is the same shape and spells "not set" as `blank=True` alone, so this
    # model carries two spellings for it.
    #
    # Backend and frontend have to land together. `RiskViewSet.bulk_update` writes
    # NULL deliberately — `request.data["response"] or None` — and the risk board
    # filters with `r.response === col.response` against a column whose key is `null`,
    # so a stored "" would drop every cleared risk off the board.
    response = models.CharField(  # noqa: DJ001
        max_length=20,
        choices=Response.choices,
        null=True,
        blank=True,
        help_text="Risk response strategy per NIST IR 8286",
    )
    domains = models.JSONField(
        default=list,
        blank=True,
        help_text="Risk domains, e.g. ['security', 'compliance']",
    )
    target_score = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text="Target risk score after planned mitigations",
    )
    target_level = models.CharField(
        max_length=10,
        choices=Level.choices,
        blank=True,
        help_text="Target risk level after planned mitigations",
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
        ordering = ["-inherent_score"]
        constraints = [
            models.UniqueConstraint(
                fields=["threat_model", "name"],
                name="unique_risk_per_threat_model",
            ),
        ]

    def __str__(self):
        return f"{self.name} ({self.inherent_level})"


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


class ThreatPersonaLink(TimestampedModel):
    """Links a ThreatPersona to a threat instance (dual-FK pattern)."""

    tenancy = Tenancy.TENANT_OWNED

    persona = models.ForeignKey(
        ThreatPersona,
        on_delete=models.CASCADE,
        related_name="threat_links",
    )
    component_threat = models.ForeignKey(
        ComponentInstanceThreat,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="persona_links",
    )
    flow_threat = models.ForeignKey(
        DataFlowInstanceThreat,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="persona_links",
    )

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=(
                    models.Q(component_threat__isnull=False, flow_threat__isnull=True)
                    | models.Q(component_threat__isnull=True, flow_threat__isnull=False)
                ),
                name="persona_link_exactly_one_fk",
            ),
            models.UniqueConstraint(
                fields=["persona", "component_threat"],
                condition=models.Q(component_threat__isnull=False),
                name="unique_persona_component_threat",
            ),
            models.UniqueConstraint(
                fields=["persona", "flow_threat"],
                condition=models.Q(flow_threat__isnull=False),
                name="unique_persona_flow_threat",
            ),
        ]

    def __str__(self):
        threat = self.component_threat or self.flow_threat
        return f"{self.persona.name} -> {threat}"


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
    """Links a ThreatSource to a threat instance (dual-FK pattern)."""

    # The source is shared; which threat instance cites it is not.
    tenancy = Tenancy.TENANT_OWNED

    source = models.ForeignKey(
        ThreatSource,
        on_delete=models.CASCADE,
        related_name="threat_links",
    )
    component_threat = models.ForeignKey(
        ComponentInstanceThreat,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="source_links",
    )
    flow_threat = models.ForeignKey(
        DataFlowInstanceThreat,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="source_links",
    )

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=(
                    models.Q(component_threat__isnull=False, flow_threat__isnull=True)
                    | models.Q(component_threat__isnull=True, flow_threat__isnull=False)
                ),
                name="source_link_exactly_one_fk",
            ),
            models.UniqueConstraint(
                fields=["source", "component_threat"],
                condition=models.Q(component_threat__isnull=False),
                name="unique_source_component_threat",
            ),
            models.UniqueConstraint(
                fields=["source", "flow_threat"],
                condition=models.Q(flow_threat__isnull=False),
                name="unique_source_flow_threat",
            ),
        ]

    def __str__(self):
        threat = self.component_threat or self.flow_threat
        return f"{self.source.name} -> {threat}"


class InstanceThreatTaxonomyEntry(TimestampedModel):
    """Instance-level taxonomy entry for a threat instance (dual-FK pattern).

    Supplements library-level taxonomy associations (ThreatLibraryTaxonomyEntry)
    with user-added entries on individual threat instances.
    """

    tenancy = Tenancy.TENANT_OWNED

    taxonomy_entry = models.ForeignKey(
        TaxonomyEntry,
        on_delete=models.CASCADE,
        related_name="instance_threat_links",
    )
    component_threat = models.ForeignKey(
        ComponentInstanceThreat,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="instance_taxonomy_links",
    )
    flow_threat = models.ForeignKey(
        DataFlowInstanceThreat,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="instance_taxonomy_links",
    )

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=(
                    models.Q(component_threat__isnull=False, flow_threat__isnull=True)
                    | models.Q(component_threat__isnull=True, flow_threat__isnull=False)
                ),
                name="taxonomy_link_exactly_one_fk",
            ),
            models.UniqueConstraint(
                fields=["taxonomy_entry", "component_threat"],
                condition=models.Q(component_threat__isnull=False),
                name="unique_taxonomy_component_threat",
            ),
            models.UniqueConstraint(
                fields=["taxonomy_entry", "flow_threat"],
                condition=models.Q(flow_threat__isnull=False),
                name="unique_taxonomy_flow_threat",
            ),
        ]

    def __str__(self):
        threat = self.component_threat or self.flow_threat
        return f"{self.taxonomy_entry} -> {threat}"


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
    cost = models.CharField(max_length=20, blank=True)
    priority = models.CharField(max_length=20, blank=True)
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


class RiskThreat(TimestampedModel):
    """Junction table linking a Risk to threat instances."""

    tenancy = Tenancy.TENANT_OWNED

    risk = models.ForeignKey(
        Risk,
        on_delete=models.CASCADE,
        related_name="risk_threats",
    )
    component_threat = models.ForeignKey(
        ComponentInstanceThreat,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="risk_links",
    )
    flow_threat = models.ForeignKey(
        DataFlowInstanceThreat,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="risk_links",
    )

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=(
                    models.Q(component_threat__isnull=False, flow_threat__isnull=True)
                    | models.Q(component_threat__isnull=True, flow_threat__isnull=False)
                ),
                name="risk_threat_exactly_one_fk",
            ),
            models.UniqueConstraint(
                fields=["risk", "component_threat"],
                condition=models.Q(component_threat__isnull=False),
                name="unique_risk_component_threat",
            ),
            models.UniqueConstraint(
                fields=["risk", "flow_threat"],
                condition=models.Q(flow_threat__isnull=False),
                name="unique_risk_flow_threat",
            ),
        ]

    def __str__(self):
        threat = self.component_threat or self.flow_threat
        return f"{self.risk.name} <- {threat}"
