from django.contrib import admin

from .models import (
    Boundary,
    ComponentDataAsset,
    ComponentLibrary,
    DataAsset,
    Flow,
    FlowAsset,
    IntegrationSource,
    Orgsystem,
    OrgsystemComponent,
    Zone,
)


@admin.register(Orgsystem)
class OrgsystemAdmin(admin.ModelAdmin):
    list_display = ["name", "organization", "criticality", "lifecycle_state"]
    list_filter = ["criticality", "lifecycle_state", "organization"]
    search_fields = ["name", "owner"]


@admin.register(IntegrationSource)
class IntegrationSourceAdmin(admin.ModelAdmin):
    list_display = ["name", "orgsystem", "source_type", "status", "last_sync_at"]
    list_filter = ["source_type", "status"]
    search_fields = ["name"]


@admin.register(Zone)
class ZoneAdmin(admin.ModelAdmin):
    list_display = ["name", "blueprint", "zone_type", "trust_level", "parent"]
    list_filter = ["zone_type"]
    search_fields = ["name"]


@admin.register(Boundary)
class BoundaryAdmin(admin.ModelAdmin):
    list_display = ["label", "blueprint", "zone_a", "zone_b"]
    list_filter = ["blueprint"]
    search_fields = ["label"]


@admin.register(ComponentLibrary)
class ComponentLibraryAdmin(admin.ModelAdmin):
    list_display = ["name", "category", "kind", "component_type", "provider"]
    list_filter = ["category", "kind", "provider"]
    search_fields = ["name", "component_type"]


@admin.register(OrgsystemComponent)
class OrgsystemComponentAdmin(admin.ModelAdmin):
    list_display = ["name", "blueprint", "orgsystem", "component_library", "zone"]
    list_filter = ["blueprint", "orgsystem"]
    search_fields = ["name"]


@admin.register(DataAsset)
class DataAssetAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "classification",
        "confidentiality",
        "integrity",
        "availability",
    ]
    list_filter = ["classification", "confidentiality"]
    search_fields = ["name"]


@admin.register(ComponentDataAsset)
class ComponentDataAssetAdmin(admin.ModelAdmin):
    list_display = ["component", "data_asset", "data_state"]
    list_filter = ["data_state"]


@admin.register(Flow)
class FlowAdmin(admin.ModelAdmin):
    list_display = [
        "source_component",
        "dest_component",
        "protocol",
        "crosses_boundary",
    ]
    list_filter = ["flow_type", "crosses_boundary", "protocol"]


@admin.register(FlowAsset)
class FlowAssetAdmin(admin.ModelAdmin):
    list_display = ["flow", "data_asset", "protection_method"]
    list_filter = ["protection_method"]
