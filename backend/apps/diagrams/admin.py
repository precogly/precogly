from django.contrib import admin

from .models import DFD, DFDTemplatesLibrary


@admin.register(DFDTemplatesLibrary)
class DFDTemplatesLibraryAdmin(admin.ModelAdmin):
    list_display = ["name", "category", "diagram_type", "maintained_by"]
    list_filter = ["category", "diagram_type"]
    search_fields = ["name", "description"]


@admin.register(DFD)
class DFDAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "diagram_type",
        "is_primary",
        "blueprint",
        "updated_by",
        "updated_at",
    ]
    list_filter = ["diagram_type", "is_primary"]
    search_fields = ["name"]
