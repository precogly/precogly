"""
Serializers for threat_models app.
"""

from django.db.models import Q
from rest_framework import serializers

from apps.compliance.models import StandardFramework
from apps.core.scope import refuse_users_outside

from .models import (
    MODEL_TYPES,
    Assumption,
    AssumptionComponent,
    Blueprint,
    BusinessObjective,
    OutOfScopeItem,
    ThreatModel,
    ThreatModelFramework,
    ThreatModelLibraryPack,
    ThreatModelReferenceImage,
    ThreatModelRelationship,
    ThreatModelReview,
    ThreatModelState,
    UseCase,
)
from .relationships import add_relationship, relationships_of


class ThreatModelReferenceImageSerializer(serializers.ModelSerializer):
    """Serializer for ThreatModelReferenceImage model."""

    image_url = serializers.SerializerMethodField()
    uploaded_by_email = serializers.CharField(
        source="uploaded_by.email", read_only=True
    )

    class Meta:
        model = ThreatModelReferenceImage
        fields = [
            "id",
            "threat_model",
            "image",
            "image_url",
            "filename",
            "description",
            "display_order",
            "uploaded_by",
            "uploaded_by_email",
            "created_at",
        ]
        read_only_fields = ["id", "threat_model", "uploaded_by", "created_at"]

    def get_image_url(self, obj):
        if obj.image:
            return obj.image.url
        return None


class ThreatModelReferenceImageUploadSerializer(serializers.ModelSerializer):
    """Serializer for uploading reference images."""

    class Meta:
        model = ThreatModelReferenceImage
        fields = ["image", "filename", "description"]


class BlueprintSerializer(serializers.ModelSerializer):
    """One structural model of a threat model."""

    class Meta:
        model = Blueprint
        fields = [
            "id",
            "threat_model",
            "name",
            "description",
            "model_types",
            "scope_description",
            "display_order",
            "format_metadata",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "threat_model",
            "format_metadata",
            "created_at",
            "updated_at",
        ]

    def validate_model_types(self, value):
        if not isinstance(value, list) or not value:
            raise serializers.ValidationError("At least one model type is required.")
        unknown = [entry for entry in value if entry not in MODEL_TYPES]
        if unknown:
            raise serializers.ValidationError(
                f"Unknown model type(s): {', '.join(map(str, unknown))}. "
                f"Choose from: {', '.join(MODEL_TYPES)}."
            )
        return value


class ThreatModelFieldsMixin:
    """Shared computed fields for ThreatModel serializers."""

    def get_owner(self, obj):
        """Get owner email from created_by user."""
        if obj.created_by:
            return obj.created_by.email
        return None

    def get_business_unit_name(self, obj):
        """Get business unit name via owning team, if any."""
        team = obj.owning_team
        if team and team.business_unit_id:
            return team.business_unit.name
        return None

    def get_frameworks(self, obj):
        """Frameworks the model's countermeasures map to (library or instance).

        A list serializer fills ``frameworks_by_model`` for the whole page at
        once (R40); a single model is looked up on its own.
        """
        by_model = self.context.get("frameworks_by_model")
        if by_model is None:
            by_model = frameworks_by_model([obj.pk])
        return by_model.get(obj.pk, [])


def frameworks_by_model(threat_model_ids) -> dict:
    """``{threat model id: [framework, ...]}`` in three queries, whatever the count.

    Traverses countermeasure -> library -> standard mappings -> requirement ->
    framework, and countermeasure -> instance mappings -> requirement ->
    framework. Each list holds unique frameworks in the frameworks' order.
    """
    from apps.threats.models import InstanceCountermeasure

    ids_by_model: dict = {}
    for path in (
        "countermeasure_library__standard_mappings__requirement__framework_id",
        "instance_standard_mappings__requirement__framework_id",
    ):
        rows = (
            InstanceCountermeasure.objects.filter(threat_model_id__in=threat_model_ids)
            .exclude(**{f"{path}__isnull": True})
            .values_list("threat_model_id", path)
        )
        for threat_model_id, framework_id in rows:
            ids_by_model.setdefault(threat_model_id, set()).add(framework_id)
    all_ids = set().union(*ids_by_model.values()) if ids_by_model else set()
    if not all_ids:
        return {}
    frameworks = list(
        StandardFramework.objects.filter(id__in=all_ids).values("id", "name", "version")
    )
    return {
        threat_model_id: [
            {"id": fw["id"], "name": fw["name"], "version": fw["version"] or ""}
            for fw in frameworks
            if fw["id"] in framework_ids
        ]
        for threat_model_id, framework_ids in ids_by_model.items()
    }


class ThreatModelListOfRowsSerializer(serializers.ListSerializer):
    """Looks up every row's frameworks in one go before serializing the page."""

    def to_representation(self, data):
        rows = list(data.all() if hasattr(data, "all") else data)
        self.context["frameworks_by_model"] = frameworks_by_model(
            [row.pk for row in rows]
        )
        return super().to_representation(rows)


def validate_methodologies(value):
    """Spec methodology values or non-empty custom names, deduplicated."""
    if not isinstance(value, list):
        raise serializers.ValidationError("methodologies must be a list.")
    cleaned = []
    for item in value:
        name = item.get("name") if isinstance(item, dict) else item
        if not isinstance(name, str) or not name.strip():
            raise serializers.ValidationError(
                "Each methodology must be a non-empty name."
            )
        name = name.strip()
        if name not in cleaned:
            cleaned.append(name)
    return cleaned


class AssumptionSerializer(serializers.ModelSerializer):
    """An assumption of a blueprint; ``component_ids`` must be of the same blueprint."""

    owner_email = serializers.EmailField(
        source="owner.email", read_only=True, default=None
    )
    component_ids = serializers.ListField(
        child=serializers.IntegerField(), required=False
    )

    class Meta:
        model = Assumption
        fields = [
            "id",
            "blueprint",
            "description",
            "topic",
            "validity",
            "impact",
            "owner",
            "owner_email",
            "owner_name",
            "validation_method",
            "validation_date",
            "component_ids",
            "display_order",
            "format_metadata",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "owner_email",
            "format_metadata",
            "created_at",
            "updated_at",
        ]
        extra_kwargs = {"blueprint": {"required": False}}

    def to_representation(self, instance):
        data = super().to_representation(instance)
        links = list(instance.component_links.all())
        data["component_ids"] = [link.component_id for link in links]
        data["components"] = [
            {"id": link.component_id, "name": link.component.name} for link in links
        ]
        return data

    def validate(self, attrs):
        from apps.systems.models import OrgsystemComponent

        threat_model = self.context.get("threat_model")
        blueprint = attrs.get("blueprint") or getattr(self.instance, "blueprint", None)
        if blueprint is None and threat_model is not None:
            blueprint = threat_model.default_blueprint
            attrs["blueprint"] = blueprint
        if blueprint is None:
            raise serializers.ValidationError({"blueprint": "This field is required."})
        if threat_model is not None and blueprint.threat_model_id != threat_model.id:
            raise serializers.ValidationError(
                {"blueprint": "The blueprint is not part of this threat model."}
            )
        refuse_users_outside(attrs, blueprint.threat_model.organization_id, "owner")
        if "component_ids" in attrs:
            wanted = list(dict.fromkeys(attrs["component_ids"]))
            found = {
                c.id: c
                for c in OrgsystemComponent.objects.filter(
                    id__in=wanted, blueprint=blueprint
                )
            }
            missing = [i for i in wanted if i not in found]
            if missing:
                raise serializers.ValidationError(
                    {
                        "component_ids": f"component(s) {missing} are not part of "
                        "this blueprint."
                    }
                )
            attrs["component_ids"] = [found[i] for i in wanted]
        elif (
            self.instance is not None
            and blueprint.id != self.instance.blueprint_id
            and self.instance.component_links.exclude(
                component__blueprint=blueprint
            ).exists()
        ):
            # A move must not keep links into the old blueprint (plan 5.9, R42).
            raise serializers.ValidationError(
                {
                    "component_ids": "The assumption links components of its "
                    "current blueprint; send component_ids for the new one "
                    "(an empty list to clear them)."
                }
            )
        return attrs

    def _sync_components(self, instance, components):
        wanted = {c.id for c in components}
        existing = {link.component_id: link for link in instance.component_links.all()}
        for position, component in enumerate(components):
            link = existing.get(component.id)
            if link is None:
                AssumptionComponent.objects.create(
                    assumption=instance, component=component, display_order=position
                )
            elif link.display_order != position:
                link.display_order = position
                link.save(update_fields=["display_order"])
        for component_id, link in existing.items():
            if component_id not in wanted:
                link.delete()

    def create(self, validated_data):
        components = validated_data.pop("component_ids", [])
        instance = super().create(validated_data)
        self._sync_components(instance, components)
        return instance

    def update(self, instance, validated_data):
        components = validated_data.pop("component_ids", None)
        instance = super().update(instance, validated_data)
        if components is not None:
            self._sync_components(instance, components)
            instance.refresh_from_db()
        return instance


class UseCaseSerializer(serializers.ModelSerializer):
    """Read-only: use cases are import and export only (plan J14)."""

    class Meta:
        model = UseCase
        fields = ["id", "name", "description", "flow_data", "created_at", "updated_at"]
        read_only_fields = fields


class BusinessObjectiveSerializer(serializers.ModelSerializer):
    owner_email = serializers.EmailField(
        source="owner.email", read_only=True, default=None
    )
    threat_count = serializers.SerializerMethodField()
    risk_count = serializers.SerializerMethodField()

    class Meta:
        model = BusinessObjective
        fields = [
            "id",
            "threat_model",
            "name",
            "description",
            "criticality",
            "owner",
            "owner_email",
            "owner_name",
            "display_order",
            "threat_count",
            "risk_count",
            "format_metadata",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "threat_model",
            "owner_email",
            "threat_count",
            "risk_count",
            "format_metadata",
            "created_at",
            "updated_at",
        ]

    def validate(self, attrs):
        threat_model = self.context.get("threat_model") or getattr(
            self.instance, "threat_model", None
        )
        refuse_users_outside(
            attrs, getattr(threat_model, "organization_id", None), "owner"
        )
        return attrs

    def get_threat_count(self, obj):
        return obj.threat_links.count()

    def get_risk_count(self, obj):
        return obj.risk_links.count()


class ThreatModelSerializer(ThreatModelFieldsMixin, serializers.ModelSerializer):
    """Serializer for ThreatModel model."""

    created_by_email = serializers.EmailField(source="created_by.email", read_only=True)
    organization_name = serializers.CharField(
        source="organization.name", read_only=True
    )
    owning_team_name = serializers.CharField(
        source="owning_team.name", read_only=True, allow_null=True
    )
    business_unit_name = serializers.SerializerMethodField()
    dfds = serializers.SerializerMethodField()
    owner = serializers.SerializerMethodField()
    frameworks = serializers.SerializerMethodField()
    primary_system_name = serializers.CharField(
        source="primary_system.name", read_only=True, default=None
    )
    version = serializers.SerializerMethodField()
    pack_ids = serializers.SerializerMethodField()
    connected_packs = serializers.SerializerMethodField()
    referenced_model_ids = serializers.SerializerMethodField()
    related_models = serializers.SerializerMethodField()
    reference_images = ThreatModelReferenceImageSerializer(many=True, read_only=True)
    blueprints = BlueprintSerializer(many=True, read_only=True)
    approved_at = serializers.SerializerMethodField()

    def get_approved_at(self, obj):
        review = ThreatModelReview.objects.filter(threat_model=obj).first()
        return review.approved_at if review is not None else None

    class Meta:
        model = ThreatModel
        fields = [
            "id",
            "name",
            "description",
            "criticality",
            "organization",
            "organization_name",
            "owning_team",
            "owning_team_name",
            "business_unit_name",
            "created_by",
            "created_by_email",
            "owner",
            "workspace_data",
            "methodologies",
            "lifecycle_phase",
            "valid_from",
            "valid_until",
            "review_frequency",
            "approved_at",
            "format_metadata",
            "blueprints",
            "dfds",
            "frameworks",
            "primary_system",
            "primary_system_name",
            "serial_number",
            "version",
            "pack_ids",
            "connected_packs",
            "referenced_model_ids",
            "related_models",
            "reference_images",
            "risk_scoring_method",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "format_metadata",
            "id",
            "serial_number",
            "version",
            "primary_system_name",
            "created_at",
            "updated_at",
            "created_by_email",
            "owner",
            "organization_name",
            "owning_team_name",
            "business_unit_name",
        ]

    def validate(self, attrs):
        validate_scoring_method_change(self.instance, attrs.get("risk_scoring_method"))
        if (
            self.instance is not None
            and "organization" in attrs
            and attrs["organization"].id != self.instance.organization_id
        ):
            raise serializers.ValidationError(
                {"organization": "A threat model cannot move to another organization."}
            )
        return attrs

    def validate_owning_team(self, value):
        """Validate owning_team belongs to the same organization as the threat model."""
        if (
            value
            and self.instance
            and value.organization_id != self.instance.organization_id
        ):
            raise serializers.ValidationError(
                "Team does not belong to the selected organization."
            )
        return value

    def validate_methodologies(self, value):
        return validate_methodologies(value)

    def get_dfds(self, obj):
        """Get associated DFDs with canvas_data for threat analysis."""
        from apps.diagrams.serializers import DFDSerializer

        return DFDSerializer(obj.dfds.all(), many=True).data

    def get_version(self, obj):
        state = ThreatModelState.objects.filter(threat_model=obj).first()
        return state.version if state is not None else 1

    def validate_primary_system(self, value):
        """The primary system must belong to the model's organization (M13)."""
        if value is None:
            return value
        organization_id = (
            self.instance.organization_id
            if self.instance is not None
            else getattr(self.initial_data.get("organization"), "pk", None)
        )
        if organization_id is None and self.instance is None:
            raw = self.initial_data.get("organization")
            organization_id = int(raw) if raw not in (None, "") else None
        if organization_id is not None and value.organization_id != organization_id:
            raise serializers.ValidationError(
                "The primary system must belong to the threat model's organization."
            )
        return value

    def get_pack_ids(self, obj):
        """Get associated library pack IDs."""
        associations = obj.pack_associations.all()
        return [assoc.library_pack_id for assoc in associations]

    def get_connected_packs(self, obj):
        """Get connected pack details for overview display."""
        associations = obj.pack_associations.select_related("library_pack").all()
        return [
            {
                "id": assoc.library_pack_id,
                "name": assoc.library_pack.name,
                "slug": assoc.library_pack.slug,
                "version": assoc.library_pack.version,
                "pack_type": assoc.library_pack.pack_type,
            }
            for assoc in associations
        ]

    def get_referenced_model_ids(self, obj):
        """The ids of the models this one points at, whatever the relation type,
        each once. ``related_models`` carries the type and direction."""
        seen = []
        for relationship in obj.outgoing_relationships.order_by("id"):
            target_id = str(relationship.target_threat_model_id)
            if target_id not in seen:
                seen.append(target_id)
        return seen

    def get_related_models(self, obj):
        """Every relationship the model takes part in (plan J15): ``model``
        is the other end, ``direction`` is ``outgoing`` when this model is the
        source and ``incoming`` when it is the target."""
        return relationships_of(obj)

    @staticmethod
    def _safe_percentage(numerator, denominator):
        """Return percentage (0-100), returning 0 when denominator is 0."""
        if denominator == 0:
            return 0
        return round((numerator / denominator) * 100)

    def _extract_scope_ids(self, instance):
        """The model's scope, read from the rows' blueprint keys (F30).

        Every blueprint counts. Nothing here reads canvas JSON any more, so the
        completion status agrees with the analysis screen and the report.
        """
        components = list(instance.components.values_list("id", "category"))
        component_ids = [component_id for component_id, _ in components]
        has_process_or_datastore = any(
            category in ("process", "datastore", None, "") for _, category in components
        )
        dataflow_ids = list(instance.flows.values_list("id", flat=True))
        zone_count = instance.zones.count()

        return {
            "component_ids": component_ids,
            "dataflow_ids": dataflow_ids,
            "has_process_or_datastore": has_process_or_datastore,
            "has_zone": zone_count > 0,
            "has_edges": bool(dataflow_ids),
            "zone_count": zone_count,
        }

    def _compute_completion_status(self, instance):
        """Compute enhanced completion status with system definition, coverage, and quality signals."""
        from apps.threats.models import (
            ACTIVE_TRIAGE_STATUSES,
            InstanceCountermeasure,
            InstanceThreat,
        )

        scope = self._extract_scope_ids(instance)
        component_ids = scope["component_ids"]
        dataflow_ids = scope["dataflow_ids"]

        # --- System Definition ---
        asset_count = instance.data_assets.count()
        component_count = len(component_ids)
        trust_zone_count = scope["zone_count"]
        dataflow_count = len(dataflow_ids)

        system_definition = [
            {
                "id": "assets_defined",
                "label": "Data assets defined",
                "checked": asset_count > 0,
                "count": asset_count,
                "count_label": f"{asset_count} Asset{'s' if asset_count != 1 else ''}",
            },
            {
                "id": "components_identified",
                "label": "Components identified",
                "checked": scope["has_process_or_datastore"],
                "count": component_count,
                "count_label": f"{component_count} Component{'s' if component_count != 1 else ''}",
            },
            {
                "id": "trust_boundaries_identified",
                "label": "Zones and boundaries identified",
                "checked": scope["has_zone"],
                "count": trust_zone_count,
                "count_label": f"{trust_zone_count} Zone{'s' if trust_zone_count != 1 else ''}",
            },
            {
                "id": "data_flows_defined",
                "label": "Flows defined",
                "checked": scope["has_edges"],
                "count": dataflow_count,
                "count_label": f"{dataflow_count} Flow{'s' if dataflow_count != 1 else ''}",
            },
        ]

        # --- Coverage --- every scenario counts once (plan section 5.3)
        active_threats = InstanceThreat.objects.filter(
            threat_model=instance, triage_status__in=ACTIVE_TRIAGE_STATUSES
        )
        targets_with_threats = (
            active_threats.filter(targets__component_id__in=component_ids)
            .values("targets__component_id")
            .distinct()
            .count()
            + active_threats.filter(targets__flow_id__in=dataflow_ids)
            .values("targets__flow_id")
            .distinct()
            .count()
        )
        total_targets = component_count + dataflow_count
        total_threats = active_threats.count()
        threats_with_cm = (
            active_threats.filter(countermeasure_links__isnull=False).distinct().count()
        )

        # Countermeasures with owners (using threat_model FK on unified model)
        total_countermeasures = InstanceCountermeasure.objects.filter(
            threat_model=instance
        ).count()

        cm_with_owner = InstanceCountermeasure.objects.filter(
            threat_model=instance,
            assigned_owner__isnull=False,
        ).count()

        coverage = [
            {
                "id": "threats_linked_targets",
                "label": "Threats linked to components and flows",
                "numerator": targets_with_threats,
                "denominator": total_targets,
                "percentage": self._safe_percentage(
                    targets_with_threats, total_targets
                ),
            },
            {
                "id": "countermeasures_assigned",
                "label": "Countermeasures assigned",
                "numerator": threats_with_cm,
                "denominator": total_threats,
                "percentage": self._safe_percentage(threats_with_cm, total_threats),
            },
            {
                "id": "owners_assigned",
                "label": "Owners assigned",
                "numerator": cm_with_owner,
                "denominator": total_countermeasures,
                "percentage": self._safe_percentage(
                    cm_with_owner, total_countermeasures
                ),
            },
        ]

        # --- Quality Signals ---
        quality_signals = self._compute_quality_signals(
            instance, component_ids, dataflow_ids
        )

        assumption_rows = Assumption.objects.filter(blueprint__threat_model=instance)
        assumptions = {
            "total": assumption_rows.count(),
            "unverified": assumption_rows.filter(
                validity__in=[
                    Assumption.Validity.UNVERIFIED,
                    Assumption.Validity.UNKNOWN,
                ]
            ).count(),
        }

        return {
            "system_definition": system_definition,
            "coverage": coverage,
            "quality_signals": quality_signals,
            "assumptions": assumptions,
        }

    def _compute_quality_signals(self, instance, component_ids, dataflow_ids):
        """Compute quality signals by cross-checking entries against installed library packs."""
        from apps.systems.models import OrgsystemComponent
        from apps.threats.models import (
            ACTIVE_TRIAGE_STATUSES,
            ComponentLibraryThreat,
            CountermeasureLibrary,
            CountermeasureThreatLink,
            InstanceThreat,
        )

        # Only compute when the threat model has connected packs
        connected_pack_ids = set(
            instance.pack_associations.values_list("library_pack_id", flat=True)
        )
        if not connected_pack_ids:
            return []

        signals = []

        # --- Check 1: Components not backed by any installed pack ---
        components = OrgsystemComponent.objects.filter(
            id__in=component_ids
        ).select_related("component_library")

        flagged_components = []
        for comp in components:
            if (
                comp.component_library is None
                or comp.component_library.source_pack_id not in connected_pack_ids
            ):
                flagged_components.append(
                    {
                        "id": comp.id,
                        "name": comp.name,
                        "detail": "No pack association",
                    }
                )

        signals.append(
            {
                "id": "components_not_in_pack",
                "status": "ok" if not flagged_components else "warning",
                "ok_label": "All components match installed pack types",
                "warning_label": (
                    f"{len(flagged_components)} component"
                    f"{'s' if len(flagged_components) != 1 else ''}"
                    " not backed by any installed pack"
                ),
                "flagged_items": flagged_components,
            }
        )

        # --- Check 2: Threats not backed by pack relationships ---
        valid_component_threat_pairs = set(
            ComponentLibraryThreat.objects.values_list(
                "component_library_id", "threat_library_id"
            )
        )
        valid_flow_threat_pairs = set(
            ComponentLibraryThreat.objects.filter(
                applies_to__in=["flow", "both"]
            ).values_list("component_library_id", "threat_library_id")
        )

        flagged_threats = []
        threats = (
            InstanceThreat.objects.filter(
                threat_model=instance, triage_status__in=ACTIVE_TRIAGE_STATUSES
            )
            .select_related("threat_library")
            .prefetch_related(
                "targets__component__component_library",
                "targets__flow__source_component__component_library",
                "targets__flow__dest_component__component_library",
            )
        )
        for threat in threats:
            name = threat.threat_name or (
                threat.threat_library.name if threat.threat_library else "Unknown"
            )
            threat_lib_id = threat.threat_library_id
            if not threat_lib_id:
                flagged_threats.append(
                    {
                        "id": threat.id,
                        "name": threat.threat_name or "Custom threat",
                        "detail": threat.display_number,
                    }
                )
                continue
            for target_row in threat.targets.all():
                kind = target_row.target_kind
                if kind == "component":
                    component = target_row.component
                    comp_lib_id = component.component_library_id
                    if (
                        comp_lib_id
                        and (comp_lib_id, threat_lib_id)
                        not in valid_component_threat_pairs
                    ):
                        flagged_threats.append(
                            {
                                "id": threat.id,
                                "name": name,
                                "detail": f"Component: {component.name}",
                            }
                        )
                elif kind == "flow":
                    flow = target_row.flow
                    ends = [
                        end.component_library_id
                        for end in (flow.source_component, flow.dest_component)
                        if end is not None and end.component_library_id
                    ]
                    if ends and not any(
                        (lib_id, threat_lib_id) in valid_flow_threat_pairs
                        for lib_id in ends
                    ):
                        flagged_threats.append(
                            {"id": threat.id, "name": name, "detail": f"Flow: {flow}"}
                        )

        signals.append(
            {
                "id": "threats_not_in_pack",
                "status": "ok" if not flagged_threats else "warning",
                "ok_label": "All threats match installed pack relationships",
                "warning_label": (
                    f"{len(flagged_threats)} threat"
                    f"{'s' if len(flagged_threats) != 1 else ''}"
                    " not backed by pack relationships"
                ),
                "flagged_items": flagged_threats,
            }
        )

        # --- Check 3: Countermeasures not backed by pack relationships ---
        valid_cm_pairs = set(
            CountermeasureLibrary.applicable_threats.through.objects.values_list(
                "threatlibrary_id", "countermeasurelibrary_id"
            )
        )

        flagged_countermeasures = []
        links = CountermeasureThreatLink.objects.filter(
            threat__threat_model=instance
        ).select_related(
            "threat__threat_library", "countermeasure__countermeasure_library"
        )
        for link in links:
            threat_lib_id = link.threat.threat_library_id
            cm_lib_id = link.countermeasure.countermeasure_library_id
            if (
                threat_lib_id
                and cm_lib_id
                and (threat_lib_id, cm_lib_id) not in valid_cm_pairs
            ):
                threat_name = link.threat.threat_name or (
                    link.threat.threat_library.name
                    if link.threat.threat_library
                    else "Unknown"
                )
                flagged_countermeasures.append(
                    {
                        "id": link.countermeasure.id,
                        "name": link.countermeasure.countermeasure_library.name
                        if link.countermeasure.countermeasure_library
                        else "Unknown",
                        "detail": f"Threat: {threat_name}",
                    }
                )

        signals.append(
            {
                "id": "countermeasures_not_in_pack",
                "status": "ok" if not flagged_countermeasures else "warning",
                "ok_label": "All countermeasures match installed pack relationships",
                "warning_label": (
                    f"{len(flagged_countermeasures)} countermeasure"
                    f"{'s' if len(flagged_countermeasures) != 1 else ''}"
                    " not backed by pack relationships"
                ),
                "flagged_items": flagged_countermeasures,
            }
        )

        return signals

    def _flatten_to_legacy_checklist(self, completion_status):
        """Convert completion_status to legacy progress_checklist format for backward compatibility."""
        checklist = []
        for item in completion_status["system_definition"]:
            checklist.append(
                {
                    "id": item["id"],
                    "label": item["label"],
                    "checked": item["checked"],
                    "auto_computed": True,
                }
            )
        for item in completion_status["coverage"]:
            checklist.append(
                {
                    "id": item["id"],
                    "label": item["label"],
                    "checked": item["numerator"] > 0,
                    "auto_computed": True,
                }
            )
        return checklist

    def to_representation(self, instance):
        """Override to inject computed completion status into workspace_data."""
        data = super().to_representation(instance)
        workspace_data = data.get("workspace_data") or {}
        completion_status = self._compute_completion_status(instance)
        workspace_data["completion_status"] = completion_status
        workspace_data["progress_checklist"] = self._flatten_to_legacy_checklist(
            completion_status
        )
        data["workspace_data"] = workspace_data
        return data


class ThreatModelListSerializer(ThreatModelFieldsMixin, serializers.ModelSerializer):
    """Lightweight serializer for ThreatModel listing."""

    owner = serializers.SerializerMethodField()
    owning_team_name = serializers.CharField(
        source="owning_team.name", read_only=True, allow_null=True
    )
    business_unit_name = serializers.SerializerMethodField()
    frameworks = serializers.SerializerMethodField()

    approved_at = serializers.SerializerMethodField()

    def get_approved_at(self, obj):
        # The reverse one-to-one is joined by ``for_listing``; a missing row
        # raises an AttributeError subclass, hence getattr.
        review = getattr(obj, "review", None)
        return review.approved_at if review is not None else None

    primary_system_name = serializers.CharField(
        source="primary_system.name", read_only=True, default=None
    )
    version = serializers.SerializerMethodField()
    blueprint_count = serializers.SerializerMethodField()

    def get_version(self, obj):
        state = getattr(obj, "state", None)
        return state.version if state is not None else 1

    def get_blueprint_count(self, obj):
        annotated = getattr(obj, "listed_blueprint_count", None)
        return annotated if annotated is not None else obj.blueprints.count()

    class Meta:
        model = ThreatModel
        list_serializer_class = ThreatModelListOfRowsSerializer
        fields = [
            "id",
            "name",
            "description",
            "criticality",
            "owner",
            "owning_team",
            "owning_team_name",
            "business_unit_name",
            "frameworks",
            "methodologies",
            "lifecycle_phase",
            "approved_at",
            "primary_system_name",
            "serial_number",
            "version",
            "blueprint_count",
            "risk_scoring_method",
            "created_at",
            "updated_at",
        ]


def validate_scoring_method_change(instance, new_method):
    """A model's methodology is fixed once it has risks (#31 comment, 2.1)."""
    if (
        instance is None
        or new_method is None
        or new_method == instance.risk_scoring_method
    ):
        return
    if instance.risks.exists():
        raise serializers.ValidationError(
            {
                "risk_scoring_method": "Delete or re-rate existing risks before "
                "changing the methodology."
            }
        )


class ThreatModelCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating ThreatModel."""

    framework_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=False,
        default=list,
    )
    referenced_model_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=False,
        default=list,
    )

    class Meta:
        model = ThreatModel
        fields = [
            "id",
            "name",
            "description",
            "organization",
            "owning_team",
            "criticality",
            "framework_ids",
            "primary_system",
            "referenced_model_ids",
            "methodologies",
            "risk_scoring_method",
        ]
        read_only_fields = ["id"]
        extra_kwargs = {
            "organization": {"required": False},
            "owning_team": {"required": False},
            "criticality": {"required": False},
        }

    def validate_methodologies(self, value):
        return validate_methodologies(value)

    def validate_organization(self, organization):
        user = self.context["request"].user
        if (
            organization is not None
            and not user.organization_memberships.filter(
                organization=organization
            ).exists()
        ):
            raise serializers.ValidationError(
                "You are not a member of this organization."
            )
        return organization

    def validate_referenced_model_ids(self, value):
        """Every referenced model is one the caller can read (``visible_to``)."""
        wanted = list(dict.fromkeys(value))
        found = {
            model.id: model
            for model in ThreatModel.objects.visible_to(
                self.context["request"].user
            ).filter(id__in=wanted)
        }
        missing = [model_id for model_id in wanted if model_id not in found]
        if missing:
            raise serializers.ValidationError(f"Threat model(s) {missing} not found.")
        return [found[model_id] for model_id in wanted]

    def create(self, validated_data):
        """Create threat model with all relationships."""
        framework_ids = validated_data.pop("framework_ids", [])
        referenced_model_ids = validated_data.pop("referenced_model_ids", [])

        # Set created_by from request user
        user = self.context["request"].user
        validated_data["created_by"] = user

        # Auto-assign organization from user's first membership if not provided
        if (
            "organization" not in validated_data
            or validated_data["organization"] is None
        ):
            first_membership = user.organization_memberships.first()
            if first_membership:
                validated_data["organization"] = first_membership.organization
            else:
                raise serializers.ValidationError(
                    {"organization": "User has no organization membership."}
                )

        # Auto-assign owning_team if not provided
        if "owning_team" not in validated_data or validated_data["owning_team"] is None:
            from apps.organizations.models import TeamMembership

            org = validated_data["organization"]
            user_team_memberships = TeamMembership.objects.filter(
                user=user,
                team__organization=org,
            ).select_related("team")
            if user_team_memberships.count() == 1:
                validated_data["owning_team"] = user_team_memberships.first().team

        primary_system = validated_data.get("primary_system")
        if (
            primary_system is not None
            and primary_system.organization_id != validated_data["organization"].id
        ):
            raise serializers.ValidationError(
                {
                    "primary_system": "The primary system must belong to the organization."
                }
            )

        # Validate owning_team belongs to the same organization
        owning_team = validated_data.get("owning_team")
        if (
            owning_team
            and owning_team.organization_id != validated_data["organization"].id
        ):
            raise serializers.ValidationError(
                {"owning_team": "Team does not belong to the selected organization."}
            )

        organization = validated_data["organization"]
        foreign_models = [
            model.id
            for model in referenced_model_ids
            if model.organization_id != organization.id
        ]
        if foreign_models:
            raise serializers.ValidationError(
                {
                    "referenced_model_ids": "Related threat models must belong to "
                    f"the same organization: {foreign_models}."
                }
            )
        usable_framework_ids = set(
            StandardFramework.objects.filter(id__in=framework_ids)
            .filter(
                Q(threat_model__isnull=True)
                | Q(threat_model__organization=organization)
            )
            .values_list("id", flat=True)
        )
        unusable_framework_ids = [
            framework_id
            for framework_id in framework_ids
            if framework_id not in usable_framework_ids
        ]
        if unusable_framework_ids:
            raise serializers.ValidationError(
                {"framework_ids": f"Framework(s) {unusable_framework_ids} not found."}
            )

        # workspace_data now holds only the progress checklist; everything
        # else lives in model fields and has its own endpoints.
        validated_data["workspace_data"] = {
            "progress_checklist": [],
        }

        # Create the threat model
        threat_model = super().create(validated_data)

        # Create framework associations
        for framework_id in framework_ids:
            ThreatModelFramework.objects.create(
                threat_model=threat_model,
                framework_id=framework_id,
            )

        # Create threat model references (organization checked above)
        for referenced_model in referenced_model_ids:
            add_relationship(
                threat_model,
                referenced_model,
                ThreatModelRelationship.RelationType.RELATED_TO,
            )

        # Auto-connect all imported packs
        from apps.packs.models import LibraryPack

        imported_packs = LibraryPack.objects.all()
        ThreatModelLibraryPack.objects.bulk_create(
            [
                ThreatModelLibraryPack(threat_model=threat_model, library_pack=pack)
                for pack in imported_packs
            ],
            ignore_conflicts=True,
        )

        return threat_model


class OutOfScopeItemSerializer(serializers.ModelSerializer):
    """Serializer for OutOfScopeItem model.

    `blueprint` is optional on create; the view defaults it to the threat
    model's default blueprint and refuses one from another model.
    """

    threat_model = serializers.IntegerField(
        source="blueprint.threat_model_id", read_only=True
    )

    class Meta:
        model = OutOfScopeItem
        fields = [
            "id",
            "threat_model",
            "blueprint",
            "name",
            "reason",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "threat_model", "created_at", "updated_at"]
        extra_kwargs = {"blueprint": {"required": False}}
