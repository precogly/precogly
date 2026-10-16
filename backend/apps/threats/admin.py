from django.contrib import admin

from .models import (
    ComponentLibraryThreat,
    CountermeasureLibrary,
    ExternalTaxonomy,
    InstanceCountermeasure,
    InstanceThreat,
    InstanceThreatTarget,
    InstanceThreatTaxonomyEntry,
    PentestFinding,
    Rating,
    Risk,
    RiskResponse,
    RiskThreat,
    TaxonomyEntry,
    ThreatLibrary,
    ThreatLibraryTaxonomyEntry,
    ThreatPersona,
    ThreatSource,
    ThreatSourceLink,
    VerificationTest,
)


@admin.register(ThreatLibrary)
class ThreatLibraryAdmin(admin.ModelAdmin):
    list_display = ["name", "source_pack"]
    list_filter = ["source_pack"]
    search_fields = ["name", "description"]


@admin.register(ComponentLibraryThreat)
class ComponentLibraryThreatAdmin(admin.ModelAdmin):
    list_display = [
        "component_library",
        "threat_library",
        "default_level",
        "applies_to",
    ]
    list_filter = ["applies_to", "default_level"]


@admin.register(CountermeasureLibrary)
class CountermeasureLibraryAdmin(admin.ModelAdmin):
    list_display = ["name", "control_nature", "cost"]
    list_filter = ["control_nature", "cost"]
    search_fields = ["name", "description"]


class InstanceThreatTargetInline(admin.TabularInline):
    model = InstanceThreatTarget
    extra = 0


@admin.register(InstanceThreat)
class InstanceThreatAdmin(admin.ModelAdmin):
    list_display = [
        "display_number",
        "threat_model",
        "threat_name",
        "threat_library",
        "whole_system",
        "status",
        "rating",
        "auto_generated",
    ]
    list_filter = ["status", "rating__level", "whole_system", "auto_generated"]
    search_fields = ["threat_name", "number"]
    inlines = [InstanceThreatTargetInline]


@admin.register(InstanceCountermeasure)
class InstanceCountermeasureAdmin(admin.ModelAdmin):
    list_display = [
        "threat_model",
        "countermeasure_library",
        "status",
        "assigned_owner",
    ]
    list_filter = ["status", "required_for_release"]


@admin.register(VerificationTest)
class VerificationTestAdmin(admin.ModelAdmin):
    list_display = ["name", "method", "passed", "last_run_at"]
    list_filter = ["method", "passed"]


@admin.register(ExternalTaxonomy)
class ExternalTaxonomyAdmin(admin.ModelAdmin):
    list_display = ["name", "slug", "version"]
    search_fields = ["name", "slug"]


@admin.register(TaxonomyEntry)
class TaxonomyEntryAdmin(admin.ModelAdmin):
    list_display = ["taxonomy", "external_id", "title"]
    list_filter = ["taxonomy"]
    search_fields = ["external_id", "title"]


@admin.register(ThreatLibraryTaxonomyEntry)
class ThreatLibraryTaxonomyEntryAdmin(admin.ModelAdmin):
    list_display = ["threat_library", "taxonomy_entry"]
    list_filter = ["taxonomy_entry__taxonomy"]


@admin.register(PentestFinding)
class PentestFindingAdmin(admin.ModelAdmin):
    list_display = [
        "finding_description",
        "severity",
        "reconciliation_status",
        "threat_model",
    ]
    list_filter = ["reconciliation_status", "severity"]


@admin.register(Rating)
class RatingAdmin(admin.ModelAdmin):
    list_display = ["id", "organization", "methodology", "level", "score"]
    list_filter = ["methodology", "level"]


@admin.register(Risk)
class RiskAdmin(admin.ModelAdmin):
    list_display = ["name", "threat_model", "status", "inherent", "residual", "owner"]
    list_filter = ["status", "inherent__level", "residual__level"]
    search_fields = ["name", "description"]


@admin.register(RiskResponse)
class RiskResponseAdmin(admin.ModelAdmin):
    list_display = ["risk", "strategy", "status", "priority", "owner", "target_date"]
    list_filter = ["strategy", "status", "priority"]


@admin.register(RiskThreat)
class RiskThreatAdmin(admin.ModelAdmin):
    list_display = ["risk", "threat"]
    list_filter = ["risk__threat_model"]


@admin.register(ThreatPersona)
class ThreatPersonaAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "symbolic_name",
        "threat_model",
        "is_person",
        "malicious_intent",
    ]
    list_filter = ["is_person", "malicious_intent"]
    search_fields = ["name", "symbolic_name"]


@admin.register(ThreatSource)
class ThreatSourceAdmin(admin.ModelAdmin):
    list_display = ["name", "slug"]
    search_fields = ["name", "slug"]


@admin.register(ThreatSourceLink)
class ThreatSourceLinkAdmin(admin.ModelAdmin):
    list_display = ["source", "threat"]


@admin.register(InstanceThreatTaxonomyEntry)
class InstanceThreatTaxonomyEntryAdmin(admin.ModelAdmin):
    list_display = ["taxonomy_entry", "threat"]
    list_filter = ["taxonomy_entry__taxonomy"]
