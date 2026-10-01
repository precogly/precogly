"""
Serializers for packs app.
"""

from rest_framework import serializers

from apps.systems.models import ComponentLibrary
from apps.threats.models import CountermeasureLibrary, ExternalTaxonomy, ThreatLibrary
from apps.diagrams.models import DFDTemplatesLibrary
from apps.compliance.models import StandardFramework

from .models import LibraryPack, LibraryPackDependency


def _check_is_imported(pack):
    """Check if pack has library items in the database."""
    return (
        ComponentLibrary.objects.filter(source_pack=pack).exists()
        or ThreatLibrary.objects.filter(source_pack=pack).exists()
        or CountermeasureLibrary.objects.filter(source_pack=pack).exists()
        or StandardFramework.objects.filter(source_pack=pack).exists()
        or ExternalTaxonomy.objects.filter(source_pack=pack).exists()
    )


class LibraryPackDependencySerializer(serializers.ModelSerializer):
    """Serializer for pack dependencies."""

    depends_on_pack_name = serializers.CharField(
        source="depends_on_pack.name", read_only=True
    )
    depends_on_pack_slug = serializers.CharField(
        source="depends_on_pack.slug", read_only=True
    )

    class Meta:
        model = LibraryPackDependency
        fields = [
            "id",
            "depends_on_pack",
            "depends_on_pack_name",
            "depends_on_pack_slug",
        ]
        read_only_fields = ["id"]


class LibraryPackListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for pack listing."""

    is_imported = serializers.SerializerMethodField()

    class Meta:
        model = LibraryPack
        fields = [
            "id",
            "slug",
            "name",
            "description",
            "version",
            "pack_type",
            "author",
            "icon_svg",
            "tags",
            "is_imported",
        ]

    def get_is_imported(self, obj):
        return _check_is_imported(obj)


class LibraryPackDetailSerializer(serializers.ModelSerializer):
    """Full serializer for pack detail view."""

    dependencies = LibraryPackDependencySerializer(many=True, read_only=True)
    content_summary = serializers.SerializerMethodField()
    is_imported = serializers.SerializerMethodField()

    class Meta:
        model = LibraryPack
        fields = [
            "id",
            "slug",
            "name",
            "description",
            "version",
            "pack_type",
            "author",
            "icon_svg",
            "tags",
            "dependencies",
            "content_summary",
            "is_imported",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def get_content_summary(self, obj):
        """Return count of items in the pack from database records."""
        return {
            "components": ComponentLibrary.objects.filter(source_pack=obj).count(),
            "threats": ThreatLibrary.objects.filter(source_pack=obj).count(),
            "countermeasures": CountermeasureLibrary.objects.filter(source_pack=obj).count(),
            "templates": DFDTemplatesLibrary.objects.filter(source_pack=obj).count(),
            "taxonomies": ExternalTaxonomy.objects.filter(source_pack=obj).count(),
        }

    def get_is_imported(self, obj):
        return _check_is_imported(obj)


class PackDependencyTreeSerializer(serializers.Serializer):
    """Serializer for showing dependencies before import."""

    pack = LibraryPackListSerializer()
    dependencies = serializers.ListField(child=serializers.DictField())
    missing_dependencies = serializers.ListField(child=serializers.CharField())
    all_satisfied = serializers.BooleanField()
