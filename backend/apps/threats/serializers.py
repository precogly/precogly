"""
Serializers for threats app.
"""

from django.db import transaction
from rest_framework import serializers

from .models import (
    ComponentInstanceThreat,
    ComponentLibraryThreat,
    CountermeasureComment,
    CountermeasureLibrary,
    CountermeasureThreatLink,
    DataFlowInstanceThreat,
    ExternalTaxonomy,
    InstanceCountermeasure,
    InstanceCountermeasureStandard,
    InstanceThreatTaxonomyEntry,
    PentestFinding,
    Risk,
    RiskThreat,
    TaxonomyEntry,
    ThreatLibrary,
    ThreatPersona,
    ThreatSource,
    VerificationTest,
    build_taxonomy_snapshot,
)
from .scoring.registry import get_scoring_methods
from .services import (
    calculate_inherent_score,
    recalculate_risk,
)


class ExternalTaxonomySerializer(serializers.ModelSerializer):
    """Serializer for ExternalTaxonomy model."""

    entry_count = serializers.SerializerMethodField()

    class Meta:
        model = ExternalTaxonomy
        fields = [
            "id",
            "slug",
            "name",
            "description",
            "source_url",
            "version",
            "source_pack",
            "entry_count",
        ]
        read_only_fields = ["id"]

    def get_entry_count(self, obj):
        return obj.entries.count()


class TaxonomyEntryNestedSerializer(serializers.ModelSerializer):
    """Nested read-only serializer for taxonomy entries."""

    taxonomy_slug = serializers.CharField(source="taxonomy.slug", read_only=True)
    taxonomy_name = serializers.CharField(source="taxonomy.name", read_only=True)

    class Meta:
        model = TaxonomyEntry
        fields = [
            "id",
            "taxonomy_slug",
            "taxonomy_name",
            "external_id",
            "title",
            "reference_url",
        ]


def _build_taxonomy_entry_dict(entry, source):
    """Build a taxonomy entry dict with source provenance."""
    return {
        "id": entry.id,
        "taxonomy_slug": entry.taxonomy.slug,
        "taxonomy_name": entry.taxonomy.name,
        "external_id": entry.external_id,
        "title": entry.title,
        "reference_url": entry.reference_url,
        "source": source,
    }


def _merge_taxonomy_entries(threat_instance):
    """Merge library + instance taxonomy entries, fall back to snapshot.

    Returns a list of dicts with a 'source' field indicating provenance.
    Deduplicates by (taxonomy_slug, external_id); instance entries
    supplement library entries for the same key.
    """
    seen = {}

    if threat_instance.threat_library:
        for join in threat_instance.threat_library.taxonomy_entries.select_related(
            "taxonomy_entry__taxonomy"
        ).all():
            entry = join.taxonomy_entry
            key = (entry.taxonomy.slug, entry.external_id)
            seen[key] = _build_taxonomy_entry_dict(entry, "library")

    for link in threat_instance.instance_taxonomy_links.select_related(
        "taxonomy_entry__taxonomy"
    ).all():
        entry = link.taxonomy_entry
        key = (entry.taxonomy.slug, entry.external_id)
        if key not in seen:
            seen[key] = _build_taxonomy_entry_dict(entry, "instance")

    if not seen:
        for snap in threat_instance.taxonomy_snapshot:
            key = (snap.get("taxonomy_slug", ""), snap.get("external_id", ""))
            if key not in seen:
                seen[key] = {
                    "taxonomy_slug": snap.get("taxonomy_slug", ""),
                    "taxonomy_name": snap.get("taxonomy_name", ""),
                    "external_id": snap.get("external_id", ""),
                    "title": snap.get("title", ""),
                    "reference_url": snap.get("reference_url", ""),
                    "source": "snapshot",
                }

    return list(seen.values())


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
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "source_pack_name",
            "source_pack_slug",
            "taxonomy_entries",
        ]

    def get_taxonomy_entries(self, obj):
        joins = obj.taxonomy_entries.all()
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
            "id",
            "name",
            "description",
            "source_pack",
            "source_pack_name",
            "source_pack_slug",
            "taxonomy_entries",
        ]

    def get_taxonomy_entries(self, obj):
        joins = obj.taxonomy_entries.all()
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
            "name",
            "description",
            "control_functions",
            "control_nature",
            "cost",
            "default_status",
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


class CountermeasureLibraryListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for countermeasure library listing."""

    source_pack_name = serializers.CharField(source="source_pack.name", read_only=True)
    source_pack_slug = serializers.CharField(source="source_pack.slug", read_only=True)

    class Meta:
        model = CountermeasureLibrary
        fields = [
            "id",
            "name",
            "description",
            "control_functions",
            "control_nature",
            "cost",
            "default_status",
            "source_pack",
            "source_pack_name",
            "source_pack_slug",
        ]


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
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "threat_name",
            "component_name",
        ]


class ComponentInstanceThreatSerializer(serializers.ModelSerializer):
    """Serializer for ComponentInstanceThreat."""

    # Read fields - prefer model's own fields, fallback to threat_library
    threat_name_display = serializers.SerializerMethodField()
    taxonomy_entries = serializers.SerializerMethodField()
    component_name = serializers.CharField(source="component.name", read_only=True)
    threat_personas = serializers.SerializerMethodField()
    threat_sources = serializers.SerializerMethodField()

    # Write fields - accept threat_name/threat_description for custom threats
    threat_name = serializers.CharField(
        required=False, allow_blank=True, write_only=True
    )
    threat_description = serializers.CharField(
        required=False, allow_blank=True, write_only=True
    )

    class Meta:
        model = ComponentInstanceThreat
        fields = [
            "id",
            "component",
            "component_name",
            "threat_library",
            "threat_name",
            "threat_description",
            "threat_name_display",
            "taxonomy_entries",
            "inherent_severity",
            "residual_severity",
            "status",
            "severity_scoring_metadata",
            "triage_status",
            "decision_rationale",
            "format_metadata",
            "display_order",
            "impact_description",
            "threat_actor_text",
            "threat_personas",
            "threat_sources",
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
            "threat_personas",
            "threat_sources",
        ]

    def get_threat_name_display(self, obj):
        """Return threat name from model field or threat_library."""
        if obj.threat_name:
            return obj.threat_name
        if obj.threat_library:
            return obj.threat_library.name
        return None

    def get_taxonomy_entries(self, obj):
        """Merge library + instance taxonomy entries, fall back to snapshot."""
        return _merge_taxonomy_entries(obj)

    def get_threat_personas(self, obj):
        return [
            {"id": link.persona.id, "name": link.persona.name}
            for link in obj.persona_links.select_related("persona").all()
        ]

    def get_threat_sources(self, obj):
        return [
            {"id": link.source.id, "name": link.source.name, "slug": link.source.slug}
            for link in obj.source_links.select_related("source").all()
        ]

    def create(self, validated_data):
        threat_library = validated_data.get("threat_library")
        if threat_library and "taxonomy_snapshot" not in validated_data:
            validated_data["taxonomy_snapshot"] = build_taxonomy_snapshot(
                threat_library
            )
        return super().create(validated_data)


class DataFlowInstanceThreatSerializer(serializers.ModelSerializer):
    """Serializer for DataFlowInstanceThreat."""

    # Read fields - prefer model's own fields, fallback to threat_library
    threat_name_display = serializers.SerializerMethodField()
    taxonomy_entries = serializers.SerializerMethodField()
    flow_label = serializers.CharField(source="data_flow.label", read_only=True)
    threat_personas = serializers.SerializerMethodField()
    threat_sources = serializers.SerializerMethodField()

    # Write fields - accept threat_name/threat_description for custom threats
    threat_name = serializers.CharField(
        required=False, allow_blank=True, write_only=True
    )
    threat_description = serializers.CharField(
        required=False, allow_blank=True, write_only=True
    )

    class Meta:
        model = DataFlowInstanceThreat
        fields = [
            "id",
            "data_flow",
            "flow_label",
            "threat_library",
            "threat_name",
            "threat_description",
            "threat_name_display",
            "taxonomy_entries",
            "inherent_severity",
            "residual_severity",
            "status",
            "severity_scoring_metadata",
            "triage_status",
            "decision_rationale",
            "format_metadata",
            "display_order",
            "impact_description",
            "threat_actor_text",
            "threat_personas",
            "threat_sources",
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
            "threat_personas",
            "threat_sources",
        ]

    def get_threat_name_display(self, obj):
        """Return threat name from model field or threat_library."""
        if obj.threat_name:
            return obj.threat_name
        if obj.threat_library:
            return obj.threat_library.name
        return None

    def get_taxonomy_entries(self, obj):
        """Merge library + instance taxonomy entries, fall back to snapshot."""
        return _merge_taxonomy_entries(obj)

    def get_threat_personas(self, obj):
        return [
            {"id": link.persona.id, "name": link.persona.name}
            for link in obj.persona_links.select_related("persona").all()
        ]

    def get_threat_sources(self, obj):
        return [
            {"id": link.source.id, "name": link.source.name, "slug": link.source.slug}
            for link in obj.source_links.select_related("source").all()
        ]

    def create(self, validated_data):
        threat_library = validated_data.get("threat_library")
        if threat_library and "taxonomy_snapshot" not in validated_data:
            validated_data["taxonomy_snapshot"] = build_taxonomy_snapshot(
                threat_library
            )
        return super().create(validated_data)


class CountermeasureThreatLinkSerializer(serializers.ModelSerializer):
    """Read-only serializer for linked threats on a countermeasure."""

    threat_id = serializers.SerializerMethodField()
    threat_name = serializers.SerializerMethodField()
    component_name = serializers.SerializerMethodField()
    flow_label = serializers.SerializerMethodField()

    class Meta:
        model = CountermeasureThreatLink
        fields = [
            "id",
            "threat_id",
            "threat_name",
            "component_name",
            "flow_label",
            "display_order",
        ]
        read_only_fields = fields

    def get_threat_id(self, obj):
        threat = obj.component_threat or obj.flow_threat
        return threat.id if threat else None

    def get_threat_name(self, obj):
        threat = obj.component_threat or obj.flow_threat
        if not threat:
            return None
        return threat.threat_name or (
            threat.threat_library.name if threat.threat_library else None
        )

    def get_component_name(self, obj):
        if obj.component_threat:
            return (
                obj.component_threat.component.name
                if obj.component_threat.component
                else None
            )
        return None

    def get_flow_label(self, obj):
        if obj.flow_threat:
            return (
                obj.flow_threat.data_flow.label if obj.flow_threat.data_flow else None
            )
        return None


class InstanceCountermeasureSerializer(serializers.ModelSerializer):
    """Serializer for InstanceCountermeasure."""

    # Read fields - prefer model's own fields, fallback to countermeasure_library
    countermeasure_name_display = serializers.SerializerMethodField()
    control_functions_display = serializers.SerializerMethodField()
    control_nature_display = serializers.SerializerMethodField()
    days_overdue = serializers.ReadOnlyField()
    verified_by_email = serializers.EmailField(
        source="verified_by.email", read_only=True
    )
    assigned_owner_email = serializers.EmailField(
        source="assigned_owner.email", read_only=True
    )
    threat_links = CountermeasureThreatLinkSerializer(many=True, read_only=True)

    # Write fields - accept custom countermeasure data
    countermeasure_name = serializers.CharField(
        required=False, allow_blank=True, write_only=True
    )
    countermeasure_description = serializers.CharField(
        required=False, allow_blank=True, write_only=True
    )
    control_functions = serializers.ListField(
        child=serializers.CharField(), required=False, write_only=True
    )
    control_nature = serializers.CharField(
        required=False, allow_blank=True, write_only=True
    )
    threat_id = serializers.IntegerField(write_only=True, required=False)
    threat_type = serializers.ChoiceField(
        choices=["component", "flow", "dataflow"],
        write_only=True,
        required=False,
    )

    class Meta:
        model = InstanceCountermeasure
        fields = [
            "id",
            "threat_model",
            "countermeasure_library",
            "countermeasure_name",
            "countermeasure_name_display",
            "countermeasure_description",
            "control_functions",
            "control_functions_display",
            "control_nature",
            "control_nature_display",
            "effectiveness",
            "status",
            "priority",
            "due_date",
            "external_ticket_url",
            "poam_id",
            "scheduled_completion",
            "days_overdue",
            "source",
            "verified_by",
            "verified_by_email",
            "evidence_url",
            "required_for_release",
            "assigned_owner",
            "assigned_owner_email",
            "format_metadata",
            "threat_links",
            "threat_id",
            "threat_type",
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
            "control_functions_display",
            "control_nature_display",
            "days_overdue",
            "verified_by_email",
            "assigned_owner_email",
            "threat_links",
        ]

    def get_countermeasure_name_display(self, obj):
        """Return countermeasure name from model field or countermeasure_library."""
        if obj.countermeasure_name:
            return obj.countermeasure_name
        if obj.countermeasure_library:
            return obj.countermeasure_library.name
        return None

    def get_control_functions_display(self, obj):
        """Return control functions from model field or countermeasure_library."""
        if obj.control_functions:
            return obj.control_functions
        if obj.countermeasure_library:
            return obj.countermeasure_library.control_functions
        return []

    def get_control_nature_display(self, obj):
        """Return control nature from model field or countermeasure_library."""
        if obj.control_nature:
            return obj.control_nature
        if obj.countermeasure_library:
            return obj.countermeasure_library.control_nature
        return ""

    def create(self, validated_data):
        threat_id = validated_data.pop("threat_id", None)
        threat_type = validated_data.pop("threat_type", "component")
        instance = super().create(validated_data)
        if threat_id:
            link_kwargs = {"countermeasure": instance}
            if threat_type in ("flow", "dataflow"):
                link_kwargs["flow_threat_id"] = threat_id
            else:
                link_kwargs["component_threat_id"] = threat_id
            CountermeasureThreatLink.objects.get_or_create(**link_kwargs)
        return instance


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
            "matched_countermeasure",
            "reconciliation_status",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at", "matched_threat_name"]


class InstanceCountermeasureStandardSerializer(serializers.ModelSerializer):
    """Serializer for InstanceCountermeasureStandard (instance-level compliance mappings)."""

    framework_name = serializers.SerializerMethodField()
    framework_slug = serializers.SerializerMethodField()
    section_code = serializers.SerializerMethodField()
    requirement_description = serializers.SerializerMethodField()

    class Meta:
        model = InstanceCountermeasureStandard
        fields = [
            "id",
            "countermeasure",
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


class InstanceThreatTaxonomyEntrySerializer(serializers.ModelSerializer):
    """Serializer for instance-level taxonomy entries on threat instances."""

    taxonomy_slug = serializers.CharField(
        source="taxonomy_entry.taxonomy.slug", read_only=True
    )
    taxonomy_name = serializers.CharField(
        source="taxonomy_entry.taxonomy.name", read_only=True
    )
    external_id = serializers.CharField(
        source="taxonomy_entry.external_id", read_only=True
    )
    title = serializers.CharField(source="taxonomy_entry.title", read_only=True)
    reference_url = serializers.URLField(
        source="taxonomy_entry.reference_url", read_only=True
    )

    class Meta:
        model = InstanceThreatTaxonomyEntry
        fields = [
            "id",
            "taxonomy_entry",
            "component_threat",
            "flow_threat",
            "taxonomy_slug",
            "taxonomy_name",
            "external_id",
            "title",
            "reference_url",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "taxonomy_slug",
            "taxonomy_name",
            "external_id",
            "title",
            "reference_url",
        ]

    def validate(self, data):
        component_threat = data.get("component_threat")
        flow_threat = data.get("flow_threat")
        if bool(component_threat) == bool(flow_threat):
            raise serializers.ValidationError(
                "Exactly one of component_threat or flow_threat must be provided."
            )
        return data

    def create(self, validated_data):
        from django.db import IntegrityError

        try:
            return super().create(validated_data)
        except IntegrityError as err:
            raise serializers.ValidationError(
                "This taxonomy entry is already linked to this threat."
            ) from err


class CountermeasureCommentSerializer(serializers.ModelSerializer):
    """Serializer for CountermeasureComment."""

    author_email = serializers.EmailField(
        source="author.email", read_only=True, default=None
    )

    class Meta:
        model = CountermeasureComment
        fields = [
            "id",
            "author",
            "author_email",
            "countermeasure",
            "body",
            "change_summary",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "author", "author_email", "created_at", "updated_at"]

    def create(self, validated_data):
        validated_data["author"] = self.context["request"].user
        return super().create(validated_data)


class RiskListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for risk listing."""

    scoring_method = serializers.SerializerMethodField()
    threat_count = serializers.SerializerMethodField()
    owner_email = serializers.EmailField(
        source="owner.email", read_only=True, default=None
    )
    assigned_to_email = serializers.EmailField(
        source="assigned_to.email", read_only=True, default=None
    )

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
            "response",
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

    def get_threat_count(self, obj):
        return obj.risk_threats.count()


class RiskDetailSerializer(serializers.ModelSerializer):
    """Full serializer for risk detail/create/update."""

    scoring_method = serializers.SerializerMethodField()
    owner_email = serializers.EmailField(
        source="owner.email", read_only=True, default=None
    )
    assigned_to_email = serializers.EmailField(
        source="assigned_to.email", read_only=True, default=None
    )
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
            "response",
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

    def get_threats(self, obj):
        """Return linked threats with basic info."""
        result = []
        for risk_threat in obj.risk_threats.select_related(
            "component_threat", "flow_threat"
        ).all():
            threat = risk_threat.component_threat or risk_threat.flow_threat
            if threat:
                result.append(
                    {
                        "risk_threat_id": risk_threat.id,
                        "threat_id": threat.id,
                        "threat_type": "component"
                        if risk_threat.component_threat
                        else "flow",
                        "threat_name": threat.threat_name,
                        "status": threat.status,
                        "triage_status": threat.triage_status,
                    }
                )
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
                raise serializers.ValidationError(
                    {
                        "component_threat_ids": "One or more component threats were not found."
                    }
                )

        if threat_model and flow_threat_ids:
            valid_count = DataFlowInstanceThreat.objects.filter(
                id__in=flow_threat_ids,
            ).count()
            if valid_count != len(flow_threat_ids):
                raise serializers.ValidationError(
                    {"flow_threat_ids": "One or more flow threats were not found."}
                )

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
            raise serializers.ValidationError(
                {
                    "inherent_score": "inherent_score is required for custom/unsupported scoring methods."
                }
            )
        else:
            from .scoring.registry import score_to_level

            validated_data["inherent_level"] = score_to_level(
                validated_data["inherent_score"]
            )

        with transaction.atomic():
            risk = Risk.objects.create(**validated_data)

            # Create RiskThreat junction rows
            risk_threat_rows = []
            for threat_id in component_threat_ids:
                risk_threat_rows.append(
                    RiskThreat(risk=risk, component_threat_id=threat_id)
                )
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
        scoring_metadata = validated_data.get(
            "scoring_metadata", instance.scoring_metadata
        )

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
    triage_status = serializers.SerializerMethodField()

    class Meta:
        model = RiskThreat
        fields = [
            "id",
            "threat_id",
            "threat_type",
            "threat_name",
            "status",
            "triage_status",
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

    def get_triage_status(self, obj):
        threat = self._get_threat(obj)
        return threat.triage_status if threat else None


class ThreatPersonaSerializer(serializers.ModelSerializer):
    """Serializer for ThreatPersona CRUD."""

    class Meta:
        model = ThreatPersona
        fields = [
            "id",
            "threat_model",
            "symbolic_name",
            "name",
            "description",
            "is_person",
            "malicious_intent",
            "skill_level",
            "motivation",
            "resources",
            "objectives",
            "format_metadata",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class ThreatSourceSerializer(serializers.ModelSerializer):
    """Read-only serializer for ThreatSource reference data."""

    class Meta:
        model = ThreatSource
        fields = [
            "id",
            "slug",
            "name",
            "description",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "slug",
            "name",
            "description",
            "created_at",
            "updated_at",
        ]
