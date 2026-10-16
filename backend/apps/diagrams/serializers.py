"""
Serializers for diagrams app.
"""

from rest_framework import serializers

from .models import DFD, DFDTemplatesLibrary


class DFDSerializer(serializers.ModelSerializer):
    """Serializer for DFD model.

    `blueprint` is set by the view on create (from `blueprint_id`, or the
    threat model's default blueprint when only `threat_model_id` is given) and
    never changes afterwards. `threat_model` is derived for readers.
    """

    updated_by_email = serializers.EmailField(source="updated_by.email", read_only=True)
    threat_model = serializers.IntegerField(
        source="blueprint.threat_model_id", read_only=True
    )

    class Meta:
        model = DFD
        fields = [
            "id",
            "name",
            "diagram_type",
            "blueprint",
            "threat_model",
            "is_primary",
            "canvas_data",
            "template_library",
            "updated_by",
            "updated_by_email",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "blueprint",
            "threat_model",
            "created_at",
            "updated_at",
            "updated_by_email",
        ]


class DFDListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for DFD listing."""

    class Meta:
        model = DFD
        fields = ["id", "name", "diagram_type", "blueprint", "is_primary", "updated_at"]


class DFDTemplatesLibrarySerializer(serializers.ModelSerializer):
    """Serializer for DFD templates."""

    source_pack_name = serializers.CharField(source="source_pack.name", read_only=True)
    source_pack_slug = serializers.CharField(source="source_pack.slug", read_only=True)

    class Meta:
        model = DFDTemplatesLibrary
        fields = [
            "id",
            "name",
            "description",
            "category",
            "diagram_type",
            "canvas_data",
            "source_pack",
            "source_pack_name",
            "source_pack_slug",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "source_pack_name",
            "source_pack_slug",
        ]
