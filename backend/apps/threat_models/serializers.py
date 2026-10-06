"""
Serializers for threat_models app.
"""

from rest_framework import serializers

from .models import (
    OutOfScopeItem,
    ThreatModel,
    ThreatModelFramework,
    ThreatModelLibraryPack,
    ThreatModelOrgsystem,
    ThreatModelReferenceImage,
    ThreatModelRelationship,
)


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
        """Derive frameworks from countermeasure compliance mappings.

        Traverses: threat model -> components/dataflows -> threats ->
        countermeasures -> countermeasure_library -> standard_mappings ->
        requirement -> framework. Returns unique frameworks.
        """
        from apps.compliance.models import StandardFramework
        from apps.threats.models import InstanceCountermeasure

        # Library-level mappings (using threat_model FK)
        library_fw_ids = set(
            InstanceCountermeasure.objects.filter(
                threat_model=obj,
                countermeasure_library__standard_mappings__requirement__framework__isnull=False,
            ).values_list(
                "countermeasure_library__standard_mappings__requirement__framework_id",
                flat=True,
            )
        )

        # Instance-level mappings
        instance_fw_ids = set(
            InstanceCountermeasure.objects.filter(
                threat_model=obj,
                instance_standard_mappings__requirement__framework__isnull=False,
            ).values_list(
                "instance_standard_mappings__requirement__framework_id",
                flat=True,
            )
        )

        all_framework_ids = library_fw_ids | instance_fw_ids

        if not all_framework_ids:
            return []

        frameworks = StandardFramework.objects.filter(id__in=all_framework_ids).values(
            "id", "name", "version"
        )
        return [
            {"id": fw["id"], "name": fw["name"], "version": fw["version"] or ""}
            for fw in frameworks
        ]


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
    system_ids = serializers.SerializerMethodField()
    pack_ids = serializers.SerializerMethodField()
    connected_packs = serializers.SerializerMethodField()
    referenced_model_ids = serializers.SerializerMethodField()
    reference_images = ThreatModelReferenceImageSerializer(many=True, read_only=True)
    can_write = serializers.SerializerMethodField()

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
            "assumptions",
            "format_metadata",
            "scope_locked",
            "scope_locked_at",
            "dfds",
            "frameworks",
            "system_ids",
            "pack_ids",
            "connected_packs",
            "referenced_model_ids",
            "reference_images",
            "can_write",
            "risk_scoring_method",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "created_by_email",
            "owner",
            "organization_name",
            "owning_team_name",
            "business_unit_name",
            "can_write",
        ]

    def get_can_write(self, obj):
        """Return the backend's object-level write decision for this request."""
        from apps.core.permissions import CanWrite

        request = self.context.get("request")
        if request is None:
            return False
        return CanWrite.user_can_write(request.user, obj)

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

    def validate_assumptions(self, value):
        """Validate assumptions list structure."""
        if not isinstance(value, list):
            raise serializers.ValidationError("Assumptions must be a list.")
        valid_validity = {"unconfirmed", "confirmed", "rejected"}
        for idx, entry in enumerate(value):
            if not isinstance(entry, dict):
                raise serializers.ValidationError(
                    f"Assumption [{idx}] must be an object."
                )
            if not entry.get("description", "").strip():
                raise serializers.ValidationError(
                    f"Assumption [{idx}] must have a non-empty description."
                )
            if entry.get("validity", "unconfirmed") not in valid_validity:
                raise serializers.ValidationError(
                    f"Assumption [{idx}] validity must be one of: {', '.join(valid_validity)}."
                )
            if "topics" not in entry:
                entry["topics"] = []
        return value

    def get_dfds(self, obj):
        """Get associated DFDs with canvas_data for threat analysis."""
        from apps.diagrams.serializers import DFDSerializer

        return DFDSerializer(obj.dfds.all(), many=True).data

    def get_system_ids(self, obj):
        """Get associated system IDs."""
        associations = obj.orgsystem_associations.all()
        return [str(assoc.orgsystem_id) for assoc in associations]

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
        """Get referenced threat model IDs."""
        associations = obj.outgoing_relationships.filter(
            relation_type=ThreatModelRelationship.RelationType.RELATED_TO
        ).all()
        return [str(assoc.target_threat_model_id) for assoc in associations]

    @staticmethod
    def _safe_percentage(numerator, denominator):
        """Return percentage (0-100), returning 0 when denominator is 0."""
        if denominator == 0:
            return 0
        return round((numerator / denominator) * 100)

    def _extract_scope_ids(self, instance):
        """Extract component_ids, dataflow_ids, and canvas metadata from DFD data."""
        from apps.systems.models import OrgsystemComponent

        dfds = instance.dfds.filter(is_primary=True)
        component_ids = set()
        dataflow_ids = set()
        has_process_or_datastore = False
        has_trust_zone = False
        has_edges = False
        trust_zone_count = 0

        for dfd in dfds:
            canvas_data = dfd.canvas_data or {}
            for node in canvas_data.get("nodes", []):
                node_type = node.get("type", "")
                if node_type in ("process", "datastore"):
                    has_process_or_datastore = True
                if node_type == "trustZone":
                    has_trust_zone = True
                    trust_zone_count += 1
                component_id = node.get("data", {}).get("component_id")
                if component_id:
                    component_ids.add(component_id)

            edges = canvas_data.get("edges", [])
            if edges:
                has_edges = True
            for edge in edges:
                dataflow_id = edge.get("data", {}).get("dataflow_id")
                if dataflow_id:
                    dataflow_ids.add(dataflow_id)

        # Include analysis-only components
        analysis_component_ids = (
            OrgsystemComponent.objects.filter(threat_model=instance)
            .exclude(id__in=component_ids)
            .values_list("id", flat=True)
        )
        component_ids.update(analysis_component_ids)

        # Include trust zones from components in scope (DB-level, DFD-independent)
        db_zone_ids = (
            OrgsystemComponent.objects.filter(
                threat_model=instance,
                trust_zone__isnull=False,
            )
            .values_list("trust_zone_id", flat=True)
            .distinct()
        )
        db_zone_count = len(db_zone_ids)
        trust_zone_count = max(trust_zone_count, db_zone_count)
        has_trust_zone = has_trust_zone or db_zone_count > 0

        return {
            "component_ids": list(component_ids),
            "dataflow_ids": list(dataflow_ids),
            "has_process_or_datastore": has_process_or_datastore,
            "has_trust_zone": has_trust_zone,
            "has_edges": has_edges,
            "trust_zone_count": trust_zone_count,
        }

    def _compute_completion_status(self, instance):
        """Compute enhanced completion status with system definition, coverage, and quality signals."""
        from apps.threats.models import (
            ACTIVE_TRIAGE_STATUSES,
            ComponentInstanceThreat,
            DataFlowInstanceThreat,
            InstanceCountermeasure,
        )

        scope = self._extract_scope_ids(instance)
        component_ids = scope["component_ids"]
        dataflow_ids = scope["dataflow_ids"]

        # --- System Definition ---
        asset_count = instance.data_assets.count()
        component_count = len(component_ids)
        trust_zone_count = scope["trust_zone_count"]
        dataflow_count = len(dataflow_ids)

        system_definition = [
            {
                "id": "assets_defined",
                "label": "Primary assets defined",
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
                "label": "Trust boundaries identified",
                "checked": scope["has_trust_zone"],
                "count": trust_zone_count,
                "count_label": f"{trust_zone_count} Boundar{'ies' if trust_zone_count != 1 else 'y'}",
            },
            {
                "id": "data_flows_defined",
                "label": "Data flows defined",
                "checked": scope["has_edges"],
                "count": dataflow_count,
                "count_label": f"{dataflow_count} Flow{'s' if dataflow_count != 1 else ''}",
            },
        ]

        # --- Coverage ---
        # Components with >= 1 active threat
        components_with_threats = (
            ComponentInstanceThreat.objects.filter(
                component_id__in=component_ids, triage_status__in=ACTIVE_TRIAGE_STATUSES
            )
            .values("component_id")
            .distinct()
            .count()
            if component_ids
            else 0
        )

        # Flows with >= 1 active threat
        flows_with_threats = (
            DataFlowInstanceThreat.objects.filter(
                data_flow_id__in=dataflow_ids, triage_status__in=ACTIVE_TRIAGE_STATUSES
            )
            .values("data_flow_id")
            .distinct()
            .count()
            if dataflow_ids
            else 0
        )

        # Total active threats (for countermeasure coverage)
        component_threat_count = (
            ComponentInstanceThreat.objects.filter(
                component_id__in=component_ids, triage_status__in=ACTIVE_TRIAGE_STATUSES
            ).count()
            if component_ids
            else 0
        )
        flow_threat_count = (
            DataFlowInstanceThreat.objects.filter(
                data_flow_id__in=dataflow_ids, triage_status__in=ACTIVE_TRIAGE_STATUSES
            ).count()
            if dataflow_ids
            else 0
        )
        total_threats = component_threat_count + flow_threat_count

        # Threats with >= 1 countermeasure (via junction table)
        component_threats_with_cm = (
            ComponentInstanceThreat.objects.filter(
                component_id__in=component_ids,
                triage_status__in=ACTIVE_TRIAGE_STATUSES,
                countermeasure_links__isnull=False,
            )
            .distinct()
            .count()
            if component_ids
            else 0
        )
        flow_threats_with_cm = (
            DataFlowInstanceThreat.objects.filter(
                data_flow_id__in=dataflow_ids,
                triage_status__in=ACTIVE_TRIAGE_STATUSES,
                countermeasure_links__isnull=False,
            )
            .distinct()
            .count()
            if dataflow_ids
            else 0
        )
        threats_with_cm = component_threats_with_cm + flow_threats_with_cm

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
                "id": "threats_linked_components",
                "label": "Threats linked to components",
                "numerator": components_with_threats,
                "denominator": component_count,
                "percentage": self._safe_percentage(
                    components_with_threats, component_count
                ),
            },
            {
                "id": "threats_linked_flows",
                "label": "Threats linked to flows",
                "numerator": flows_with_threats,
                "denominator": dataflow_count,
                "percentage": self._safe_percentage(flows_with_threats, dataflow_count),
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

        return {
            "system_definition": system_definition,
            "coverage": coverage,
            "quality_signals": quality_signals,
        }

    def _compute_quality_signals(self, instance, component_ids, dataflow_ids):
        """Compute quality signals by cross-checking entries against installed library packs."""
        from apps.systems.models import OrgsystemComponent
        from apps.threats.models import (
            ACTIVE_TRIAGE_STATUSES,
            ComponentInstanceThreat,
            ComponentLibraryThreat,
            CountermeasureLibrary,
            CountermeasureThreatLink,
            DataFlowInstanceThreat,
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
        # For flows, include pairs with applies_to in ("flow", "both")
        valid_flow_threat_pairs = set(
            ComponentLibraryThreat.objects.filter(
                applies_to__in=["flow", "both"]
            ).values_list("component_library_id", "threat_library_id")
        )

        flagged_threats = []

        # Check component threats
        component_threats = ComponentInstanceThreat.objects.filter(
            component_id__in=component_ids, triage_status__in=ACTIVE_TRIAGE_STATUSES
        ).select_related("component__component_library", "threat_library")

        for ct in component_threats:
            comp_lib_id = (
                ct.component.component_library_id
                if ct.component.component_library_id
                else None
            )
            threat_lib_id = ct.threat_library_id
            if comp_lib_id and threat_lib_id:
                if (comp_lib_id, threat_lib_id) not in valid_component_threat_pairs:
                    flagged_threats.append(
                        {
                            "id": ct.id,
                            "name": ct.threat_name
                            or (
                                ct.threat_library.name
                                if ct.threat_library
                                else "Unknown"
                            ),
                            "detail": f"Component: {ct.component.name}",
                        }
                    )
            elif not threat_lib_id:
                # Custom threat (no library link) — flag it
                flagged_threats.append(
                    {
                        "id": ct.id,
                        "name": ct.threat_name or "Custom threat",
                        "detail": f"Component: {ct.component.name}",
                    }
                )

        # Check flow threats — a flow threat is valid if EITHER endpoint's
        # component library has the mapping (since flows connect two components)
        flow_threats = DataFlowInstanceThreat.objects.filter(
            data_flow_id__in=dataflow_ids, triage_status__in=ACTIVE_TRIAGE_STATUSES
        ).select_related(
            "data_flow__source_component__component_library",
            "data_flow__dest_component__component_library",
            "threat_library",
        )

        for ft in flow_threats:
            threat_lib_id = ft.threat_library_id
            source_lib_id = (
                ft.data_flow.source_component.component_library_id
                if ft.data_flow.source_component
                and ft.data_flow.source_component.component_library_id
                else None
            )
            dest_lib_id = (
                ft.data_flow.dest_component.component_library_id
                if ft.data_flow.dest_component
                and ft.data_flow.dest_component.component_library_id
                else None
            )

            # Build a readable flow description
            flow_desc = ft.data_flow.label
            if not flow_desc:
                src_name = (
                    ft.data_flow.source_component.name
                    if ft.data_flow.source_component
                    else "?"
                )
                dst_name = (
                    ft.data_flow.dest_component.name
                    if ft.data_flow.dest_component
                    else "?"
                )
                flow_desc = f"{src_name} \u2192 {dst_name}"

            if threat_lib_id:
                # Valid if either source or dest component has this threat mapping
                source_valid = (
                    source_lib_id
                    and (source_lib_id, threat_lib_id) in valid_flow_threat_pairs
                )
                dest_valid = (
                    dest_lib_id
                    and (dest_lib_id, threat_lib_id) in valid_flow_threat_pairs
                )
                # Only flag if at least one endpoint has a library (otherwise it's a custom component issue)
                if (
                    not source_valid
                    and not dest_valid
                    and (source_lib_id or dest_lib_id)
                ):
                    flagged_threats.append(
                        {
                            "id": ft.id,
                            "name": ft.threat_name
                            or (
                                ft.threat_library.name
                                if ft.threat_library
                                else "Unknown"
                            ),
                            "detail": f"Flow: {flow_desc}",
                        }
                    )
            else:
                # Custom threat (no library link)
                flagged_threats.append(
                    {
                        "id": ft.id,
                        "name": ft.threat_name or "Custom threat",
                        "detail": f"Flow: {flow_desc}",
                    }
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

        # Component countermeasures (via unified junction table)
        component_cm_links = CountermeasureThreatLink.objects.filter(
            component_threat__component_id__in=component_ids
        ).select_related(
            "component_threat__threat_library",
            "countermeasure__countermeasure_library",
        )

        for link in component_cm_links:
            threat_lib_id = link.component_threat.threat_library_id
            cm_lib_id = link.countermeasure.countermeasure_library_id
            if (
                threat_lib_id
                and cm_lib_id
                and (threat_lib_id, cm_lib_id) not in valid_cm_pairs
            ):
                threat_name = link.component_threat.threat_name or (
                    link.component_threat.threat_library.name
                    if link.component_threat.threat_library
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

        # Flow countermeasures (via unified junction table)
        flow_cm_links = CountermeasureThreatLink.objects.filter(
            flow_threat__data_flow_id__in=dataflow_ids
        ).select_related(
            "flow_threat__threat_library",
            "countermeasure__countermeasure_library",
        )

        for link in flow_cm_links:
            threat_lib_id = link.flow_threat.threat_library_id
            cm_lib_id = link.countermeasure.countermeasure_library_id
            if (
                threat_lib_id
                and cm_lib_id
                and (threat_lib_id, cm_lib_id) not in valid_cm_pairs
            ):
                threat_name = link.flow_threat.threat_name or (
                    link.flow_threat.threat_library.name
                    if link.flow_threat.threat_library
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

    class Meta:
        model = ThreatModel
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
            "risk_scoring_method",
            "created_at",
            "updated_at",
        ]


class ThreatModelCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating ThreatModel."""

    framework_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=False,
        default=list,
    )
    system_ids = serializers.ListField(
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
            "system_ids",
            "referenced_model_ids",
        ]
        read_only_fields = ["id"]
        extra_kwargs = {
            "organization": {"required": False},
            "owning_team": {"required": False},
            "criticality": {"required": False},
        }

    def create(self, validated_data):
        """Create threat model with all relationships."""
        framework_ids = validated_data.pop("framework_ids", [])
        system_ids = validated_data.pop("system_ids", [])
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

        # Validate owning_team belongs to the same organization
        owning_team = validated_data.get("owning_team")
        if (
            owning_team
            and owning_team.organization_id != validated_data["organization"].id
        ):
            raise serializers.ValidationError(
                {"owning_team": "Team does not belong to the selected organization."}
            )

        # Initialize workspace_data — only progressChecklist remains here;
        # status, description, scope_locked, assets, out_of_scope_items
        # are now managed via dedicated model fields and API endpoints.
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

        # Create system associations
        for system_id in system_ids:
            ThreatModelOrgsystem.objects.create(
                threat_model=threat_model,
                orgsystem_id=system_id,
            )

        # Create threat model references
        for ref_model_id in referenced_model_ids:
            ThreatModelRelationship.objects.create(
                source_threat_model=threat_model,
                target_threat_model_id=ref_model_id,
                relation_type=ThreatModelRelationship.RelationType.RELATED_TO,
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
    """Serializer for OutOfScopeItem model."""

    class Meta:
        model = OutOfScopeItem
        fields = [
            "id",
            "threat_model",
            "name",
            "reason",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "threat_model", "created_at", "updated_at"]
