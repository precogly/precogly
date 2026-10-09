from django.contrib import admin

from .models import (
    Blueprint,
    OutOfScopeItem,
    ThreatModel,
    ThreatModelFramework,
    ThreatModelReferenceImage,
    ThreatModelRelationship,
)


@admin.register(ThreatModel)
class ThreatModelAdmin(admin.ModelAdmin):
    list_display = ["name", "organization", "created_by", "updated_at"]
    list_filter = ["organization"]
    search_fields = ["name", "description"]
    readonly_fields = ["created_at", "updated_at"]


@admin.register(ThreatModelRelationship)
class ThreatModelRelationshipAdmin(admin.ModelAdmin):
    list_display = ["source_threat_model", "relation_type", "target_threat_model"]
    list_filter = ["relation_type"]


@admin.register(ThreatModelReferenceImage)
class ThreatModelReferenceImageAdmin(admin.ModelAdmin):
    list_display = [
        "filename",
        "threat_model",
        "uploaded_by",
        "display_order",
        "created_at",
    ]
    list_filter = ["threat_model", "uploaded_by"]
    search_fields = ["filename", "description"]
    readonly_fields = ["created_at", "uploaded_by"]


@admin.register(ThreatModelFramework)
class ThreatModelFrameworkAdmin(admin.ModelAdmin):
    list_display = ["threat_model", "framework"]
    list_filter = ["framework"]


@admin.register(Blueprint)
class BlueprintAdmin(admin.ModelAdmin):
    list_display = ["name", "threat_model", "display_order", "updated_at"]
    list_filter = ["threat_model"]
    search_fields = ["name", "description"]


@admin.register(OutOfScopeItem)
class OutOfScopeItemAdmin(admin.ModelAdmin):
    list_display = ["name", "blueprint", "created_at"]
    list_filter = ["blueprint"]
    search_fields = ["name", "reason"]
