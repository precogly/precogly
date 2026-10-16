"""
Serializers for systems app.

Components, zones, boundaries, flows and data assets belong to a Blueprint.
Every serializer below exposes `blueprint` and refuses a row whose related
rows (a zone's parent, a boundary's zones, a flow's ends, a component's zone)
sit in another blueprint.
"""

from rest_framework import serializers

from .crossing import clean_session_management, clean_type_list, is_data_like
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


def _same_blueprint(blueprint, *related):
    """True when every related row that is set belongs to `blueprint`."""
    return all(row is None or row.blueprint_id == blueprint.id for row in related)


def _refuse_blueprint_change(serializer, attrs):
    """A row stays in the blueprint it was created in.

    Moving one would leave its children, boundaries, flows and threat targets
    pointing across blueprints, and nothing re-checks them.
    """
    instance = serializer.instance
    if (
        instance is not None
        and "blueprint" in attrs
        and attrs["blueprint"].id != instance.blueprint_id
    ):
        raise serializers.ValidationError(
            {"blueprint": "A row cannot move to another blueprint."}
        )


def _refuse_cross_blueprint_asset(owner, data_asset, field_name):
    """A data asset link joins a component or flow to an asset of its own blueprint."""
    if (
        owner is not None
        and data_asset is not None
        and owner.blueprint_id != data_asset.blueprint_id
    ):
        raise serializers.ValidationError(
            {
                "data_asset": f"The data asset must belong to the {field_name}'s blueprint."
            }
        )


class OrgsystemUsageMixin:
    """Usage counts of an inventory system (plan J1): the threat models whose
    primary system it is and the system assets linked to it. The viewset
    annotates both; a row without the annotation (the response to a create)
    counts them. The two fields are declared on each serializer, because DRF
    only collects fields declared on serializer classes."""

    def get_primary_model_count(self, obj):
        annotated = getattr(obj, "primary_model_count", None)
        if annotated is not None:
            return annotated
        return obj.primary_threat_models.count()

    def get_linked_component_count(self, obj):
        annotated = getattr(obj, "linked_component_count", None)
        if annotated is not None:
            return annotated
        return obj.components.count()


class OrgsystemSerializer(OrgsystemUsageMixin, serializers.ModelSerializer):
    """Serializer for Orgsystem model."""

    # Map to frontend expected fields for response
    type = serializers.SerializerMethodField()
    environment = serializers.CharField(source="lifecycle_state", read_only=True)
    primary_model_count = serializers.SerializerMethodField()
    linked_component_count = serializers.SerializerMethodField()
    primary_models = serializers.SerializerMethodField()

    class Meta:
        model = Orgsystem
        fields = [
            "id",
            "name",
            "description",
            "owner",
            "type",
            "environment",
            "criticality",
            "lifecycle_state",
            "format_metadata",
            "organization",
            "primary_model_count",
            "linked_component_count",
            "primary_models",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "format_metadata",
            "id",
            "organization",
            "created_at",
            "updated_at",
        ]

    def get_type(self, obj):
        """Return type for frontend compatibility."""
        return "system"

    def get_primary_models(self, obj):
        """The threat models whose primary system this is, as ``{id, name}``."""
        return list(obj.primary_threat_models.order_by("name").values("id", "name"))

    def create(self, validated_data):
        """Auto-populate organization from the request user."""
        request = self.context.get("request")
        if request and hasattr(request, "user"):
            # Get user's first organization membership
            membership = request.user.organization_memberships.first()
            if membership:
                validated_data["organization"] = membership.organization
            else:
                raise serializers.ValidationError(
                    {"organization": "User has no organization membership."}
                )
        return super().create(validated_data)


class OrgsystemListSerializer(OrgsystemUsageMixin, serializers.ModelSerializer):
    """Lightweight serializer for Orgsystem listing."""

    # Map to frontend expected fields
    type = serializers.SerializerMethodField()
    environment = serializers.CharField(source="lifecycle_state")
    primary_model_count = serializers.SerializerMethodField()
    linked_component_count = serializers.SerializerMethodField()

    class Meta:
        model = Orgsystem
        fields = [
            "id",
            "name",
            "description",
            "type",
            "owner",
            "environment",
            "criticality",
            "lifecycle_state",
            "primary_model_count",
            "linked_component_count",
        ]

    def get_type(self, obj):
        """Return type based on lifecycle state."""
        return "system"


class ZoneSerializer(serializers.ModelSerializer):
    """Serializer for Zone model."""

    class Meta:
        model = Zone
        fields = [
            "id",
            "blueprint",
            "name",
            "zone_type",
            "trust_level",
            "description",
            "format_metadata",
            "parent",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["format_metadata", "id", "created_at", "updated_at"]

    def validate(self, attrs):
        _refuse_blueprint_change(self, attrs)
        blueprint = attrs.get("blueprint") or getattr(self.instance, "blueprint", None)
        parent = attrs.get("parent", getattr(self.instance, "parent", None))
        if blueprint is not None and not _same_blueprint(blueprint, parent):
            raise serializers.ValidationError(
                {"parent": "The parent zone must belong to the same blueprint."}
            )
        return attrs


class BoundarySerializer(serializers.ModelSerializer):
    """Serializer for Boundary model."""

    zone_a_name = serializers.CharField(source="zone_a.name", read_only=True)
    zone_b_name = serializers.CharField(source="zone_b.name", read_only=True)
    requires_authentication = serializers.BooleanField(read_only=True)
    requires_authorization = serializers.BooleanField(read_only=True)

    class Meta:
        model = Boundary
        fields = [
            "id",
            "blueprint",
            "zone_a",
            "zone_a_name",
            "zone_b",
            "zone_b_name",
            "label",
            "description",
            "edge_id",
            "boundary_type",
            "authentication",
            "authorization",
            "requires_authentication",
            "requires_authorization",
            "data_validation",
            "data_transformation",
            "logging",
            "monitoring",
            "rate_limit",
            "protocols",
            "session_management",
            "format_metadata",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "format_metadata",
            "id",
            "created_at",
            "updated_at",
            "zone_a_name",
            "zone_b_name",
            "requires_authentication",
            "requires_authorization",
        ]

    def validate_authentication(self, value):
        try:
            return clean_type_list(value, field="authentication")
        except ValueError as error:
            raise serializers.ValidationError(str(error)) from error

    def validate_authorization(self, value):
        try:
            return clean_type_list(value, field="authorization")
        except ValueError as error:
            raise serializers.ValidationError(str(error)) from error

    def validate_protocols(self, value):
        try:
            return clean_type_list(value, field="protocols")
        except ValueError as error:
            raise serializers.ValidationError(str(error)) from error

    def validate_session_management(self, value):
        try:
            return clean_session_management(value)
        except ValueError as error:
            raise serializers.ValidationError(str(error)) from error

    def validate(self, attrs):
        _refuse_blueprint_change(self, attrs)
        blueprint = attrs.get("blueprint") or getattr(self.instance, "blueprint", None)
        zone_a = attrs.get("zone_a", getattr(self.instance, "zone_a", None))
        zone_b = attrs.get("zone_b", getattr(self.instance, "zone_b", None))
        if blueprint is not None and not _same_blueprint(blueprint, zone_a, zone_b):
            raise serializers.ValidationError(
                {"zones": "Both zones must belong to the boundary's blueprint."}
            )
        return attrs


class ComponentLibrarySerializer(serializers.ModelSerializer):
    """Serializer for ComponentLibrary model."""

    source_pack_name = serializers.CharField(source="source_pack.name", read_only=True)
    source_pack_slug = serializers.CharField(source="source_pack.slug", read_only=True)

    class Meta:
        model = ComponentLibrary
        fields = [
            "id",
            "slug",
            "qualified_slug",
            "name",
            "category",
            "kind",
            "effective_kind",
            "component_type",
            "provider",
            "icon_svg",
            "source_pack",
            "source_pack_name",
            "source_pack_slug",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "qualified_slug",
            "icon_svg",
            "effective_kind",
            "created_at",
            "updated_at",
            "source_pack_name",
            "source_pack_slug",
        ]


class OrgsystemComponentSerializer(serializers.ModelSerializer):
    """Serializer for OrgsystemComponent model."""

    component_library_name = serializers.CharField(
        source="component_library.name", read_only=True
    )
    threat_model = serializers.IntegerField(
        source="blueprint.threat_model_id", read_only=True
    )

    class Meta:
        model = OrgsystemComponent
        fields = [
            "id",
            "name",
            "description",
            "category",
            "kind",
            "effective_kind",
            "actor_type",
            "data_store_type",
            "data_sensitivity_level",
            "orgsystem",
            "component_library",
            "component_library_name",
            "zone",
            "source_integration",
            "blueprint",
            "threat_model",
            "parent_component",
            "format_metadata",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "format_metadata",
            "id",
            "created_at",
            "updated_at",
            "component_library_name",
            "effective_kind",
            "threat_model",
        ]

    def validate(self, attrs):
        _refuse_blueprint_change(self, attrs)
        blueprint = attrs.get("blueprint") or getattr(self.instance, "blueprint", None)
        zone = attrs.get("zone", getattr(self.instance, "zone", None))
        parent = attrs.get(
            "parent_component", getattr(self.instance, "parent_component", None)
        )
        if blueprint is not None and not _same_blueprint(blueprint, zone, parent):
            raise serializers.ValidationError(
                {
                    "blueprint": "The zone and the parent component must belong "
                    "to the component's blueprint."
                }
            )
        organization_id = blueprint.threat_model.organization_id if blueprint else None
        orgsystem = attrs.get("orgsystem")
        if orgsystem is not None and orgsystem.organization_id != organization_id:
            raise serializers.ValidationError(
                {"orgsystem": "The system must belong to this model's organization."}
            )
        source = attrs.get("source_integration")
        if source is not None and source.orgsystem.organization_id != organization_id:
            raise serializers.ValidationError(
                {
                    "source_integration": "The integration must belong to this "
                    "model's organization."
                }
            )
        return attrs


class DataAssetSerializer(serializers.ModelSerializer):
    """Serializer for DataAsset model."""

    threat_model = serializers.IntegerField(
        source="blueprint.threat_model_id", read_only=True
    )

    class Meta:
        model = DataAsset
        fields = [
            "id",
            "name",
            "description",
            "classification",
            "confidentiality",
            "integrity",
            "availability",
            "compliance_tags",
            "data_sensitivity",
            "blueprint",
            "threat_model",
            "format_metadata",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "format_metadata",
            "id",
            "created_at",
            "updated_at",
            "threat_model",
        ]

    def validate(self, attrs):
        _refuse_blueprint_change(self, attrs)
        return attrs


class FlowSerializer(serializers.ModelSerializer):
    """Serializer for Flow model.

    `blueprint` may be left out on create: it defaults to the source
    component's blueprint, which both ends must share.
    """

    source_component_name = serializers.CharField(
        source="source_component.name", read_only=True
    )
    dest_component_name = serializers.CharField(
        source="dest_component.name", read_only=True
    )
    requires_authentication = serializers.BooleanField(read_only=True)

    class Meta:
        model = Flow
        fields = [
            "id",
            "blueprint",
            "source_component",
            "source_component_name",
            "dest_component",
            "dest_component_name",
            "label",
            "description",
            "edge_id",
            "flow_type",
            "protocol",
            "port",
            "encrypted",
            "authentication",
            "authorization",
            "requires_authentication",
            "crosses_boundary",
            "has_sensitive_data",
            "data_classification",
            "format_metadata",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "format_metadata",
            "id",
            "created_at",
            "updated_at",
            "source_component_name",
            "dest_component_name",
            "requires_authentication",
            "crosses_boundary",
        ]
        extra_kwargs = {"blueprint": {"required": False}}

    def validate_authentication(self, value):
        try:
            return clean_type_list(value, field="authentication")
        except ValueError as error:
            raise serializers.ValidationError(str(error)) from error

    def validate_authorization(self, value):
        try:
            return clean_type_list(value, field="authorization")
        except ValueError as error:
            raise serializers.ValidationError(str(error)) from error

    def validate(self, attrs):
        source = attrs.get(
            "source_component", getattr(self.instance, "source_component", None)
        )
        dest = attrs.get(
            "dest_component", getattr(self.instance, "dest_component", None)
        )
        _refuse_blueprint_change(self, attrs)
        blueprint = attrs.get("blueprint") or getattr(self.instance, "blueprint", None)
        if blueprint is None and source is not None:
            blueprint = source.blueprint
            attrs["blueprint"] = blueprint
        if blueprint is not None and not _same_blueprint(blueprint, source, dest):
            raise serializers.ValidationError(
                {
                    "blueprint": "Both ends of a flow must belong to the flow's blueprint."
                }
            )
        # The DFD sync rule (section 4.6): protocol, port and encryption
        # describe data-like flows only, so other types carry none (R23).
        flow_type = attrs.get("flow_type", getattr(self.instance, "flow_type", "data"))
        if not is_data_like(flow_type):
            attrs.update(protocol="", port=None, encrypted=False)
        return attrs


class IntegrationSourceSerializer(serializers.ModelSerializer):
    """Serializer for IntegrationSource model."""

    class Meta:
        model = IntegrationSource
        fields = [
            "id",
            "name",
            "source_type",
            "connection_details",
            "status",
            "last_sync_at",
            "orgsystem",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class ComponentDataAssetSerializer(serializers.ModelSerializer):
    """Serializer for ComponentDataAsset model."""

    component_name = serializers.CharField(source="component.name", read_only=True)
    data_asset_name = serializers.CharField(source="data_asset.name", read_only=True)

    class Meta:
        model = ComponentDataAsset
        fields = [
            "id",
            "component",
            "component_name",
            "data_asset",
            "data_asset_name",
            "data_state",
            "volume",
            "encrypted",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "component_name",
            "data_asset_name",
        ]

    def validate(self, attrs):
        _refuse_cross_blueprint_asset(
            attrs.get("component", getattr(self.instance, "component", None)),
            attrs.get("data_asset", getattr(self.instance, "data_asset", None)),
            "component",
        )
        return attrs


class FlowAssetSerializer(serializers.ModelSerializer):
    """Serializer for FlowAsset model."""

    flow_name = serializers.SerializerMethodField()
    data_asset_name = serializers.CharField(source="data_asset.name", read_only=True)

    class Meta:
        model = FlowAsset
        fields = [
            "id",
            "flow",
            "flow_name",
            "data_asset",
            "data_asset_name",
            "protection_method",
            "encryption_type",
            "format",
            "sensitivity_override",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "flow_name",
            "data_asset_name",
        ]

    def validate(self, attrs):
        _refuse_cross_blueprint_asset(
            attrs.get("flow", getattr(self.instance, "flow", None)),
            attrs.get("data_asset", getattr(self.instance, "data_asset", None)),
            "flow",
        )
        return attrs

    def get_flow_name(self, obj):
        """Return 'source → dest' label for the data flow."""
        flow = obj.flow
        return f"{flow.source_component.name} → {flow.dest_component.name}"
