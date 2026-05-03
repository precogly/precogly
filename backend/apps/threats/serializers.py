"""
Serializers for threats app.
"""

from django.db import transaction
from rest_framework import serializers

from .models import (
    ComponentInstanceCountermeasure,
    ComponentInstanceCountermeasureStandard,
    ComponentInstanceThreat,
    ComponentLibraryThreat,
    CountermeasureLibrary,
    DataFlowInstanceThreat,
    ExternalTaxonomy,
    FlowInstanceCountermeasure,
    FlowInstanceCountermeasureStandard,
    PentestFinding,
    Risk,
    RiskThreat,
    TaxonomyEntry,
    ThreatLibrary,
    VerificationTest,
    build_taxonomy_snapshot,
)
from .scoring.registry import get_scoring_methods
from .services import (
    calculate_inherent_score,
    compute_residual_score,
    derive_risk_status,
    recalculate_risk,
)


class ExternalTaxonomySerializer(serializers.ModelSerializer):
    """Serializer for ExternalTaxonomy model."""

    entry_count = serializers.SerializerMethodField()

    class Meta:
        model = ExternalTaxonomy
        fields = ["id", "slug", "name", "description", "source_url", "version", "source_pack", "entry_count"]
        read_only_fields = ["id"]

    def get_entry_count(self, obj):
        return obj.entries.count()


class TaxonomyEntryNestedSerializer(serializers.ModelSerializer):
    """Nested read-only serializer for taxonomy entries."""

    taxonomy_slug = serializers.CharField(source="taxonomy.slug", read_only=True)
    taxonomy_name = serializers.CharField(source="taxonomy.name", read_only=True)

    class Meta:
        model = TaxonomyEntry
        fields = ["id", "taxonomy_slug", "taxonomy_name", "external_id", "title", "reference_url"]


class ThreatLibrarySerializer(serializers.ModelSerializer):
    """Serializer for ThreatLibrary model."""

    source_pack_name = serializers.CharField(source="source_pack.name", read_only=True)
    source_pack_slug = serializers.CharField(source="source_pack.slug", read_only=True)
    taxonomy_entries = serializers.SerializerMethodField()

    class Meta:
        model = ThreatLibrary
        fields = [
            "id",
            "name",
            "description",
            "source_pack",
            "source_pack_name",
            "source_pack_slug",
            "taxonomy_entries",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at", "source_pack_name", "source_pack_slug", "taxonomy_entries"]

    def get_taxonomy_entries(self, obj):
        joins = obj.taxonomy_entries.select_related("taxonomy_entry__taxonomy").all()
        return TaxonomyEntryNestedSerializer(
            [j.taxonomy_entry for j in joins], many=True
        ).data


class ThreatLibraryListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for threat library listing."""

    source_pack_name = serializers.CharField(source="source_pack.name", read_only=True)
    source_pack_slug = serializers.CharField(source="source_pack.slug", read_only=True)
    taxonomy_entries = serializers.SerializerMethodField()

    class Meta:
        model = ThreatLibrary
        fields = [
            "id", "name", "description",
            "source_pack", "source_pack_name", "source_pack_slug",
            "taxonomy_entries",
        ]

    def get_taxonomy_entries(self, obj):
        joins = obj.taxonomy_entries.select_related("taxonomy_entry__taxonomy").all()
        return TaxonomyEntryNestedSerializer(
            [j.taxonomy_entry for j in joins], many=True
        ).data


class CountermeasureLibrarySerializer(serializers.ModelSerializer):
    """Serializer for CountermeasureLibrary model."""

    source_pack_name = serializers.CharField(source="source_pack.name", read_only=True)
    source_pack_slug = serializers.CharField(source="source_pack.slug", read_only=True)

    class Meta:
        model = CountermeasureLibrary
        fields = [
            "id",
            "organization",
            "name",
            "description",
            "control_type",
            "cost",
            "default_status",
            "source_pack",
            "source_pack_name",
            "source_pack_slug",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at", "source_pack_name", "source_pack_slug"]


class CountermeasureLibraryListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for countermeasure library listing."""

    source_pack_name = serializers.CharField(source="source_pack.name", read_only=True)
    source_pack_slug = serializers.CharField(source="source_pack.slug", read_only=True)

    class Meta:
        model = CountermeasureLibrary
        fields = ["id", "name", "control_type", "cost", "default_status", "source_pack", "source_pack_name", "source_pack_slug"]


class ComponentLibraryThreatSerializer(serializers.ModelSerializer):
    """Serializer for ComponentLibraryThreat associations."""

    threat_name = serializers.CharField(source="threat_library.name", read_only=True)
    component_name = serializers.CharField(
        source="component_library.name", read_only=True
    )

    class Meta:
        model = ComponentLibraryThreat
        fields = [
            "id",
            "component_library",
            "component_name",
            "threat_library",
            "threat_name",
            "default_severity",
            "applies_to",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at", "threat_name", "component_name"]


class ComponentInstanceThreatSerializer(serializers.ModelSerializer):
    """Serializer for ComponentInstanceThreat."""

    # Read fields - prefer model's own fields, fallback to threat_library
    threat_name_display = serializers.SerializerMethodField()
    taxonomy_entries = serializers.SerializerMethodField()
    component_name = serializers.CharField(source="component.name", read_only=True)
    countermeasures = serializers.SerializerMethodField()

    # Write fields - accept threat_name for custom threats
    threat_name = serializers.CharField(required=False, allow_blank=True, write_only=True)

    class Meta:
        model = ComponentInstanceThreat
        fields = [
            "id",
            "component",
            "component_name",
            "threat_library",
            "threat_name",
            "threat_name_display",
            "taxonomy_entries",
            "inherent_severity",
            "residual_severity",
            "status",
            "severity_scoring_metadata",
            "is_dismissed",
            "dismissal_reason",
            "format_metadata",
            "display_order",
            "countermeasures",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "threat_name_display",
            "taxonomy_entries",
            "component_name",
            "countermeasures",
        ]

    def get_threat_name_display(self, obj):
        """Return threat name from model field or threat_library."""
        if obj.threat_name:
            return obj.threat_name
        if obj.threat_library:
            return obj.threat_library.name
        return None

    def get_taxonomy_entries(self, obj):
        """Return taxonomy entries from linked threat_library, fallback to snapshot."""
        if obj.threat_library:
            joins = obj.threat_library.taxonomy_entries.select_related(
                "taxonomy_entry__taxonomy"
            ).all()
            return TaxonomyEntryNestedSerializer(
                [j.taxonomy_entry for j in joins], many=True
            ).data
        return obj.taxonomy_snapshot

    def get_countermeasures(self, obj):
        """Nested countermeasures (resolved at request time; serializer class is defined below)."""
        qs = obj.countermeasures.all().order_by("display_order", "created_at")
        return ComponentInstanceCountermeasureSerializer(qs, many=True).data

    def create(self, validated_data):
        threat_library = validated_data.get("threat_library")
        if threat_library and "taxonomy_snapshot" not in validated_data:
            validated_data["taxonomy_snapshot"] = build_taxonomy_snapshot(threat_library)
        return super().create(validated_data)


class DataFlowInstanceThreatSerializer(serializers.ModelSerializer):
    """Serializer for DataFlowInstanceThreat."""

    # Read fields - prefer model's own fields, fallback to threat_library
    threat_name_display = serializers.SerializerMethodField()
    taxonomy_entries = serializers.SerializerMethodField()
    flow_label = serializers.CharField(source="data_flow.label", read_only=True)

    # Write fields - accept threat_name for custom threats
    threat_name = serializers.CharField(required=False, allow_blank=True, write_only=True)

    class Meta:
        model = DataFlowInstanceThreat
        fields = [
            "id",
            "data_flow",
            "flow_label",
            "threat_library",
            "threat_name",
            "threat_name_display",
            "taxonomy_entries",
            "inherent_severity",
            "residual_severity",
            "status",
            "severity_scoring_metadata",
            "is_dismissed",
            "dismissal_reason",
            "format_metadata",
            "display_order",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "threat_name_display",
            "taxonomy_entries",
            "flow_label",
        ]

    def get_threat_name_display(self, obj):
        """Return threat name from model field or threat_library."""
        if obj.threat_name:
            return obj.threat_name
        if obj.threat_library:
            return obj.threat_library.name
        return None

    def get_taxonomy_entries(self, obj):
        """Return taxonomy entries from linked threat_library, fallback to snapshot."""
        if obj.threat_library:
            joins = obj.threat_library.taxonomy_entries.select_related(
                "taxonomy_entry__taxonomy"
            ).all()
            return TaxonomyEntryNestedSerializer(
                [j.taxonomy_entry for j in joins], many=True
            ).data
        return obj.taxonomy_snapshot

    def create(self, validated_data):
        threat_library = validated_data.get("threat_library")
        if threat_library and "taxonomy_snapshot" not in validated_data:
            validated_data["taxonomy_snapshot"] = build_taxonomy_snapshot(threat_library)
        return super().create(validated_data)


class ComponentInstanceCountermeasureSerializer(serializers.ModelSerializer):
    """Serializer for ComponentInstanceCountermeasure."""

    # Read fields - prefer model's own fields, fallback to countermeasure_library
    countermeasure_name_display = serializers.SerializerMethodField()
    control_type_display = serializers.SerializerMethodField()
    verified_by_email = serializers.EmailField(
        source="verified_by.email", read_only=True
    )
    assigned_owner_email = serializers.EmailField(
        source="assigned_owner.email", read_only=True
    )

    # Write fields - accept custom countermeasure data
    countermeasure_name = serializers.CharField(required=False, allow_blank=True, write_only=True)
    countermeasure_description = serializers.CharField(required=False, allow_blank=True, write_only=True)
    control_type = serializers.CharField(required=False, allow_blank=True, write_only=True)

    class Meta:
        model = ComponentInstanceCountermeasure
        fields = [
            "id",
            "instance_threat",
            "countermeasure_library",
            "countermeasure_name",
            "countermeasure_name_display",
            "countermeasure_description",
            "control_type",
            "control_type_display",
            "effectiveness",
            "status",
            "priority",
            "verified_by",
            "verified_by_email",
            "evidence_url",
            "required_for_release",
            "assigned_owner",
            "assigned_owner_email",
            "format_metadata",
            "display_order",
            "is_inherited",
            "inherited_from_component_name",
            "inherited_from_zone_name",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "countermeasure_name_display",
            "control_type_display",
            "verified_by_email",
            "assigned_owner_email",
        ]

    def get_countermeasure_name_display(self, obj):
        """Return countermeasure name from model field or countermeasure_library."""
        if obj.countermeasure_name:
            return obj.countermeasure_name
        if obj.countermeasure_library:
            return obj.countermeasure_library.name
        return None

    def get_control_type_display(self, obj):
        """Return control type from model field or countermeasure_library."""
        if obj.control_type:
            return obj.control_type
        if obj.countermeasure_library:
            return obj.countermeasure_library.control_type
        return None


class FlowInstanceCountermeasureSerializer(serializers.ModelSerializer):
    """Serializer for FlowInstanceCountermeasure."""

    # Read fields - prefer model's own fields, fallback to countermeasure_library
    countermeasure_name_display = serializers.SerializerMethodField()
    control_type_display = serializers.SerializerMethodField()
    verified_by_email = serializers.EmailField(
        source="verified_by.email", read_only=True
    )
    assigned_owner_email = serializers.EmailField(
        source="assigned_owner.email", read_only=True
    )

    # Write fields - accept custom countermeasure data
    countermeasure_name = serializers.CharField(required=False, allow_blank=True, write_only=True)
    countermeasure_description = serializers.CharField(required=False, allow_blank=True, write_only=True)
    control_type = serializers.CharField(required=False, allow_blank=True, write_only=True)

    class Meta:
        model = FlowInstanceCountermeasure
        fields = [
            "id",
            "flow_threat",
            "countermeasure_library",
            "countermeasure_name",
            "countermeasure_name_display",
            "countermeasure_description",
            "control_type",
            "control_type_display",
            "effectiveness",
            "status",
            "priority",
            "verified_by",
            "verified_by_email",
            "evidence_url",
            "required_for_release",
            "assigned_owner",
            "assigned_owner_email",
            "format_metadata",
            "display_order",
            "is_inherited",
            "inherited_from_component_name",
            "inherited_from_zone_name",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "countermeasure_name_display",
            "control_type_display",
            "verified_by_email",
            "assigned_owner_email",
        ]

    def get_countermeasure_name_display(self, obj):
        """Return countermeasure name from model field or countermeasure_library."""
        if obj.countermeasure_name:
            return obj.countermeasure_name
        if obj.countermeasure_library:
            return obj.countermeasure_library.name
        return None

    def get_control_type_display(self, obj):
        """Return control type from model field or countermeasure_library."""
        if obj.control_type:
            return obj.control_type
        if obj.countermeasure_library:
            return obj.countermeasure_library.control_type
        return None


class VerificationTestSerializer(serializers.ModelSerializer):
    """Serializer for VerificationTest."""

    class Meta:
        model = VerificationTest
        fields = [
            "id",
            "name",
            "method",
            "last_run_at",
            "passed",
            "evidence",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class PentestFindingSerializer(serializers.ModelSerializer):
    """Serializer for PentestFinding."""

    matched_threat_name = serializers.CharField(
        source="matched_threat_library.name", read_only=True
    )

    class Meta:
        model = PentestFinding
        fields = [
            "id",
            "threat_model",
            "finding_description",
            "severity",
            "matched_threat_library",
            "matched_threat_name",
            "matched_component_countermeasure",
            "matched_flow_countermeasure",
            "reconciliation_status",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at", "matched_threat_name"]


class ComponentInstanceCountermeasureStandardSerializer(serializers.ModelSerializer):
    """Serializer for ComponentInstanceCountermeasureStandard (instance-level compliance mappings)."""

    framework_name = serializers.SerializerMethodField()
    framework_slug = serializers.SerializerMethodField()
    section_code = serializers.SerializerMethodField()
    requirement_description = serializers.SerializerMethodField()

    class Meta:
        model = ComponentInstanceCountermeasureStandard
        fields = [
            "id",
            "component_countermeasure",
            "requirement",
            "framework_name",
            "framework_slug",
            "section_code",
            "requirement_description",
            "sufficiency",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "framework_name",
            "framework_slug",
            "section_code",
            "requirement_description",
        ]

    def get_framework_name(self, obj):
        if obj.requirement and obj.requirement.framework:
            return obj.requirement.framework.name
        return obj.framework_name

    def get_framework_slug(self, obj):
        if obj.requirement and obj.requirement.framework:
            return obj.requirement.framework.slug
        return ""

    def get_section_code(self, obj):
        if obj.requirement:
            return obj.requirement.section_code
        return obj.section_code

    def get_requirement_description(self, obj):
        if obj.requirement:
            return obj.requirement.description
        return obj.requirement_description

    def create(self, validated_data):
        requirement = validated_data.get("requirement")
        if requirement:
            validated_data["section_code"] = requirement.section_code
            validated_data["framework_name"] = requirement.framework.name
            validated_data["requirement_description"] = requirement.description
        return super().create(validated_data)


class FlowInstanceCountermeasureStandardSerializer(serializers.ModelSerializer):
    """Serializer for FlowInstanceCountermeasureStandard (instance-level compliance mappings)."""

    framework_name = serializers.SerializerMethodField()
    framework_slug = serializers.SerializerMethodField()
    section_code = serializers.SerializerMethodField()
    requirement_description = serializers.SerializerMethodField()

    class Meta:
        model = FlowInstanceCountermeasureStandard
        fields = [
            "id",
            "flow_countermeasure",
            "requirement",
            "framework_name",
            "framework_slug",
            "section_code",
            "requirement_description",
            "sufficiency",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "framework_name",
            "framework_slug",
            "section_code",
            "requirement_description",
        ]

    def get_framework_name(self, obj):
        if obj.requirement and obj.requirement.framework:
            return obj.requirement.framework.name
        return obj.framework_name

    def get_framework_slug(self, obj):
        if obj.requirement and obj.requirement.framework:
            return obj.requirement.framework.slug
        return ""

    def get_section_code(self, obj):
        if obj.requirement:
            return obj.requirement.section_code
        return obj.section_code

    def get_requirement_description(self, obj):
        if obj.requirement:
            return obj.requirement.description
        return obj.requirement_description

    def create(self, validated_data):
        requirement = validated_data.get("requirement")
        if requirement:
            validated_data["section_code"] = requirement.section_code
            validated_data["framework_name"] = requirement.framework.name
            validated_data["requirement_description"] = requirement.description
        return super().create(validated_data)


class RiskListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for risk listing."""

    scoring_method = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    threat_count = serializers.SerializerMethodField()
    owner_email = serializers.EmailField(source="owner.email", read_only=True, default=None)
    assigned_to_email = serializers.EmailField(source="assigned_to.email", read_only=True, default=None)

    class Meta:
        model = Risk
        fields = [
            "id",
            "name",
            "description",
            "scoring_method",
            "inherent_score",
            "inherent_level",
            "residual_score",
            "residual_level",
            "status",
            "threat_count",
            "owner",
            "owner_email",
            "assigned_to",
            "assigned_to_email",
            "created_at",
            "updated_at",
        ]

    def get_scoring_method(self, obj):
        return obj.threat_model.risk_scoring_method

    def get_status(self, obj):
        return derive_risk_status(obj)

    def get_threat_count(self, obj):
        return obj.risk_threats.count()


class RiskDetailSerializer(serializers.ModelSerializer):
    """Full serializer for risk detail/create/update."""

    scoring_method = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    owner_email = serializers.EmailField(source="owner.email", read_only=True, default=None)
    assigned_to_email = serializers.EmailField(source="assigned_to.email", read_only=True, default=None)
    threats = serializers.SerializerMethodField()

    # Write-only fields for inline threat linking
    component_threat_ids = serializers.ListField(
        child=serializers.IntegerField(), write_only=True, required=False, default=[]
    )
    flow_threat_ids = serializers.ListField(
        child=serializers.IntegerField(), write_only=True, required=False, default=[]
    )

    class Meta:
        model = Risk
        fields = [
            "id",
            "name",
            "description",
            "scoring_method",
            "scoring_metadata",
            "inherent_score",
            "inherent_level",
            "residual_score",
            "residual_level",
            "status",
            "threats",
            "owner",
            "owner_email",
            "assigned_to",
            "assigned_to_email",
            "format_metadata",
            "component_threat_ids",
            "flow_threat_ids",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "inherent_score",
            "inherent_level",
            "residual_score",
            "residual_level",
            "created_at",
            "updated_at",
        ]

    def _get_scoring_method(self):
        """Get scoring method from threat model context."""
        threat_model = self.context.get("threat_model")
        if threat_model:
            return threat_model.risk_scoring_method
        return "tm_library"

    def get_scoring_method(self, obj):
        return obj.threat_model.risk_scoring_method

    def get_status(self, obj):
        return derive_risk_status(obj)

    def get_threats(self, obj):
        """Return linked threats with basic info."""
        result = []
        for risk_threat in obj.risk_threats.select_related("component_threat", "flow_threat").all():
            threat = risk_threat.component_threat or risk_threat.flow_threat
            if threat:
                result.append({
                    "risk_threat_id": risk_threat.id,
                    "threat_id": threat.id,
                    "threat_type": "component" if risk_threat.component_threat else "flow",
                    "threat_name": threat.threat_name,
                    "status": threat.status,
                    "is_dismissed": threat.is_dismissed,
                })
        return result

    def validate_scoring_metadata(self, value):
        """Validate scoring_metadata against the ThreatModel's scoring method."""
        method_key = self._get_scoring_method()
        methods = get_scoring_methods()
        method_config = methods.get(method_key)
        if method_config and method_config["engine"]:
            engine = method_config["engine"]()
            engine.validate_inputs(value)
        return value

    def validate(self, attrs):
        """Cross-field validation: verify threat IDs belong to the same threat_model."""
        threat_model = self.context.get("threat_model")
        component_threat_ids = attrs.get("component_threat_ids", [])
        flow_threat_ids = attrs.get("flow_threat_ids", [])

        if threat_model and component_threat_ids:
            valid_count = ComponentInstanceThreat.objects.filter(
                id__in=component_threat_ids,
            ).count()
            if valid_count != len(component_threat_ids):
                raise serializers.ValidationError({
                    "component_threat_ids": "One or more component threats were not found."
                })

        if threat_model and flow_threat_ids:
            valid_count = DataFlowInstanceThreat.objects.filter(
                id__in=flow_threat_ids,
            ).count()
            if valid_count != len(flow_threat_ids):
                raise serializers.ValidationError({
                    "flow_threat_ids": "One or more flow threats were not found."
                })

        return attrs

    def create(self, validated_data):
        component_threat_ids = validated_data.pop("component_threat_ids", [])
        flow_threat_ids = validated_data.pop("flow_threat_ids", [])

        scoring_method = self._get_scoring_method()
        scoring_metadata = validated_data.get("scoring_metadata", {})

        # Compute inherent score via engine
        score, level = calculate_inherent_score(scoring_method, scoring_metadata)
        if score is not None:
            validated_data["inherent_score"] = score
            validated_data["inherent_level"] = level
        elif "inherent_score" not in validated_data:
            raise serializers.ValidationError({
                "inherent_score": "inherent_score is required for custom/unsupported scoring methods."
            })
        else:
            from .scoring.registry import score_to_level
            validated_data["inherent_level"] = score_to_level(validated_data["inherent_score"])

        with transaction.atomic():
            risk = Risk.objects.create(**validated_data)

            # Create RiskThreat junction rows
            risk_threat_rows = []
            for threat_id in component_threat_ids:
                risk_threat_rows.append(RiskThreat(risk=risk, component_threat_id=threat_id))
            for threat_id in flow_threat_ids:
                risk_threat_rows.append(RiskThreat(risk=risk, flow_threat_id=threat_id))
            if risk_threat_rows:
                RiskThreat.objects.bulk_create(risk_threat_rows)

            # Compute residual score
            recalculate_risk(risk)
            risk.refresh_from_db()

        return risk

    def update(self, instance, validated_data):
        validated_data.pop("component_threat_ids", None)
        validated_data.pop("flow_threat_ids", None)

        scoring_method = instance.threat_model.risk_scoring_method
        scoring_metadata = validated_data.get("scoring_metadata", instance.scoring_metadata)

        # Recompute inherent score if scoring metadata changed
        if "scoring_metadata" in validated_data:
            score, level = calculate_inherent_score(scoring_method, scoring_metadata)
            if score is not None:
                validated_data["inherent_score"] = score
                validated_data["inherent_level"] = level

        instance = super().update(instance, validated_data)
        recalculate_risk(instance)
        instance.refresh_from_db()
        return instance


class RiskThreatSerializer(serializers.ModelSerializer):
    """Lightweight serializer for RiskThreat entries."""

    threat_id = serializers.SerializerMethodField()
    threat_type = serializers.SerializerMethodField()
    threat_name = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    is_dismissed = serializers.SerializerMethodField()

    class Meta:
        model = RiskThreat
        fields = [
            "id",
            "threat_id",
            "threat_type",
            "threat_name",
            "status",
            "is_dismissed",
        ]

    def _get_threat(self, obj):
        return obj.component_threat or obj.flow_threat

    def get_threat_id(self, obj):
        threat = self._get_threat(obj)
        return threat.id if threat else None

    def get_threat_type(self, obj):
        return "component" if obj.component_threat else "flow"

    def get_threat_name(self, obj):
        threat = self._get_threat(obj)
        return threat.threat_name if threat else None

    def get_status(self, obj):
        threat = self._get_threat(obj)
        return threat.status if threat else None

    def get_is_dismissed(self, obj):
        threat = self._get_threat(obj)
        return threat.is_dismissed if threat else None
