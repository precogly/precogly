"""
Views for threats app.
"""

import contextlib

from django.db.models import Prefetch, Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.ai import AIDisabledError, AIProviderError
from apps.ai.resolver import organization_for_component, resolve_config
from apps.core.permissions import CanWrite, IsSecurityTeam
from apps.systems.models import OrgsystemComponent
from apps.threat_models.models import ThreatModel
from apps.threats.ai.suggest import suggest_component_threats

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
    ThreatLibraryTaxonomyEntry,
    ThreatPersona,
    ThreatSource,
    VerificationTest,
)
from .scoring.registry import get_scoring_methods_list
from .serializers import (
    ComponentInstanceThreatSerializer,
    ComponentLibraryThreatSerializer,
    CountermeasureCommentSerializer,
    CountermeasureLibraryListSerializer,
    CountermeasureLibrarySerializer,
    DataFlowInstanceThreatSerializer,
    ExternalTaxonomySerializer,
    InstanceCountermeasureSerializer,
    InstanceCountermeasureStandardSerializer,
    InstanceThreatTaxonomyEntrySerializer,
    PentestFindingSerializer,
    RiskDetailSerializer,
    RiskListSerializer,
    TaxonomyEntryNestedSerializer,
    ThreatLibraryListSerializer,
    ThreatLibrarySerializer,
    ThreatPersonaSerializer,
    ThreatSourceSerializer,
    VerificationTestSerializer,
)
from .services import (
    recalculate_all_threats_for_countermeasure,
    recalculate_risk,
    recalculate_risks_for_threat,
    recalculate_threat_status,
)


def _is_security_team(user):
    """Check if user has Security Team role in any organization."""
    return user.organization_memberships.filter(role="security_team").exists()


def _truthy(value) -> bool:
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _check_platform_status_permission(user, current_status=None, new_status=None):
    """Raise PermissionDenied if non-Security Team user tries to set or remove platform status."""
    if (
        new_status == "platform" or current_status == "platform"
    ) and not _is_security_team(user):
        raise PermissionDenied(
            "Only Security Team members can assign or remove platform status."
        )


class ThreatLibraryViewSet(viewsets.ModelViewSet):
    """ViewSet for ThreatLibrary CRUD operations."""

    permission_classes = [IsAuthenticated, IsSecurityTeam]
    pagination_class = None  # Return all items without pagination
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_fields = []
    search_fields = ["name", "description"]
    ordering_fields = ["name", "created_at"]
    ordering = ["name"]

    def get_queryset(self):
        """Return threats, optionally filtered by component's library and/or connected packs.

        Query params:
            component_id: If provided, returns only threats linked to that
            component's component_library via ComponentLibraryThreat.
            Falls back to all threats if the component has no library.
            threat_model: If provided, filters to threats from connected packs
            (or with no source pack).
        """
        queryset = (
            ThreatLibrary.objects.all()
            .select_related("source_pack")
            .prefetch_related(
                Prefetch(
                    "taxonomy_entries",
                    queryset=ThreatLibraryTaxonomyEntry.objects.select_related(
                        "taxonomy_entry__taxonomy"
                    ),
                )
            )
        )

        component_id = self.request.query_params.get("component_id")
        if component_id:
            try:
                component = OrgsystemComponent.objects.get(pk=component_id)
            except (OrgsystemComponent.DoesNotExist, ValueError):
                return queryset

            if component.component_library_id:
                # A component library maps both the threats a component carries
                # itself and the ones its connections carry (an API gateway maps
                # eavesdropping and replay so its *flows* inherit them). Only the
                # component-scoped ones belong on the component, so this mirrors
                # the filter in `apps.threats.ai.suggest.candidate_library_threats`
                # — without it the picker offers flow threats on a component and
                # they get added there.
                threat_ids = ComponentLibraryThreat.objects.filter(
                    component_library_id=component.component_library_id,
                    applies_to__in=[
                        ComponentLibraryThreat.AppliesTo.COMPONENT,
                        ComponentLibraryThreat.AppliesTo.BOTH,
                    ],
                ).values_list("threat_library_id", flat=True)
                queryset = queryset.filter(id__in=threat_ids)

        threat_model_id = self.request.query_params.get("threat_model")
        if threat_model_id:
            from apps.threat_models.models import ThreatModelLibraryPack

            connected_pack_ids = ThreatModelLibraryPack.objects.filter(
                threat_model_id=threat_model_id
            ).values_list("library_pack_id", flat=True)
            queryset = queryset.filter(
                Q(source_pack_id__in=connected_pack_ids) | Q(source_pack__isnull=True)
            )

        return queryset

    def get_serializer_class(self):
        """Return appropriate serializer."""
        if self.action == "list":
            return ThreatLibraryListSerializer
        return ThreatLibrarySerializer


class CountermeasureLibraryViewSet(viewsets.ModelViewSet):
    """ViewSet for CountermeasureLibrary CRUD operations."""

    permission_classes = [IsAuthenticated, IsSecurityTeam]
    pagination_class = None  # Return all items without pagination
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_fields = ["control_nature", "cost"]
    search_fields = ["name", "description"]
    ordering_fields = ["name", "created_at"]
    ordering = ["name"]

    def get_queryset(self):
        """Return countermeasures, optionally filtered by connected packs.

        Query params:
            threat_model: If provided, filters to countermeasures from connected
            packs (or with no source pack).
        """
        queryset = CountermeasureLibrary.objects.all().select_related("source_pack")

        threat_model_id = self.request.query_params.get("threat_model")
        if threat_model_id:
            from apps.threat_models.models import ThreatModelLibraryPack

            connected_pack_ids = ThreatModelLibraryPack.objects.filter(
                threat_model_id=threat_model_id
            ).values_list("library_pack_id", flat=True)
            queryset = queryset.filter(
                Q(source_pack_id__in=connected_pack_ids) | Q(source_pack__isnull=True)
            )

        return queryset

    def get_serializer_class(self):
        """Return appropriate serializer."""
        if self.action == "list":
            return CountermeasureLibraryListSerializer
        return CountermeasureLibrarySerializer


class ComponentLibraryThreatViewSet(viewsets.ModelViewSet):
    """ViewSet for ComponentLibraryThreat associations."""

    queryset = ComponentLibraryThreat.objects.select_related(
        "component_library", "threat_library"
    ).all()
    serializer_class = ComponentLibraryThreatSerializer
    permission_classes = [IsAuthenticated, IsSecurityTeam]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["component_library", "threat_library", "applies_to"]


class ComponentInstanceThreatViewSet(viewsets.ModelViewSet):
    """ViewSet for ComponentInstanceThreat."""

    serializer_class = ComponentInstanceThreatSerializer
    permission_classes = [IsAuthenticated, CanWrite]

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return (
            ComponentInstanceThreat.objects.filter(
                Q(component__orgsystem__organization_id__in=org_ids)
                | Q(
                    component__orgsystem__isnull=True,
                    component__threat_model__organization_id__in=org_ids,
                )
            )
            .select_related("component", "threat_library")
            .prefetch_related("instance_taxonomy_links__taxonomy_entry__taxonomy")
        )

    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ["component", "threat_library", "status", "inherent_severity"]
    ordering_fields = ["inherent_severity", "status", "created_at"]
    ordering = ["-inherent_severity"]

    @action(detail=True, methods=["get"])
    def suggested_countermeasures(self, request, pk=None):
        """
        Get suggested countermeasures for this threat instance.

        Queries CountermeasureLibrary.applicable_threats to find countermeasures
        that can mitigate this threat type.

        Returns:
            - suggested: countermeasures not yet applied
            - applied: countermeasures already applied to this threat instance
        """
        instance_threat = self.get_object()
        threat_library = instance_threat.threat_library

        # Get countermeasures applicable to this threat type
        applicable_countermeasures = CountermeasureLibrary.objects.filter(
            applicable_threats=threat_library,
        )

        # Get countermeasures already applied to this instance (via junction table)
        applied_ids = set(
            CountermeasureThreatLink.objects.filter(
                component_threat=instance_threat
            ).values_list("countermeasure__countermeasure_library_id", flat=True)
        )

        suggested = []
        applied = []

        for cm in applicable_countermeasures:
            if cm.id in applied_ids:
                applied.append(cm)
            else:
                suggested.append(cm)

        return Response(
            {
                "threat_id": instance_threat.id,
                "threat_name": threat_library.name,
                "suggested": CountermeasureLibraryListSerializer(
                    suggested, many=True
                ).data,
                "applied": CountermeasureLibraryListSerializer(applied, many=True).data,
                "suggested_count": len(suggested),
                "applied_count": len(applied),
            }
        )

    @action(detail=True, methods=["post"])
    def apply_countermeasure(self, request, pk=None):
        """
        Apply a countermeasure to this threat instance.

        Request body:
            - countermeasure_library_id: ID of the library countermeasure to create+link
            - existing_countermeasure_id: ID of an existing countermeasure instance to link
            - status: optional, defaults to 'gap' (only used with countermeasure_library_id)
        """
        instance_threat = self.get_object()

        # Option 1: Link an existing countermeasure instance
        existing_countermeasure_id = request.data.get("existing_countermeasure_id")
        if existing_countermeasure_id:
            try:
                existing_cm = InstanceCountermeasure.objects.get(
                    id=existing_countermeasure_id
                )
            except InstanceCountermeasure.DoesNotExist:
                return Response(
                    {"error": "Countermeasure instance not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )
            _link, link_created = CountermeasureThreatLink.objects.get_or_create(
                countermeasure=existing_cm,
                component_threat=instance_threat,
            )
            if not link_created:
                return Response(
                    {"error": "Countermeasure already linked to this threat"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            recalculate_threat_status(instance_threat)
            return Response(
                {
                    "countermeasure": InstanceCountermeasureSerializer(
                        existing_cm
                    ).data,
                    "message": "Linked existing countermeasure to threat",
                },
                status=status.HTTP_201_CREATED,
            )

        # Option 2: Create new countermeasure instance from library + link
        countermeasure_id = request.data.get("countermeasure_library_id")
        if not countermeasure_id:
            return Response(
                {
                    "error": "countermeasure_library_id or existing_countermeasure_id is required"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            countermeasure = CountermeasureLibrary.objects.get(id=countermeasure_id)
        except CountermeasureLibrary.DoesNotExist:
            return Response(
                {"error": "Countermeasure not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Block non-Security Team users from explicitly setting platform status.
        requested_status = request.data.get("status")
        if requested_status == "platform":
            _check_platform_status_permission(request.user, new_status="platform")

        # Derive threat_model from the threat's component
        threat_model = instance_threat.component.threat_model or (
            instance_threat.component.orgsystem.threat_models.first()
            if instance_threat.component.orgsystem
            else None
        )

        effective_status = requested_status or countermeasure.default_status
        instance_cm = InstanceCountermeasure.objects.create(
            threat_model=threat_model,
            countermeasure_library=countermeasure,
            countermeasure_name=countermeasure.name,
            countermeasure_description=countermeasure.description,
            control_functions=countermeasure.control_functions,
            control_nature=countermeasure.control_nature,
            status=effective_status,
        )

        # Create junction link
        CountermeasureThreatLink.objects.create(
            countermeasure=instance_cm,
            component_threat=instance_threat,
        )

        # Recalculate threat status
        recalculate_threat_status(instance_threat)

        return Response(
            {
                "countermeasure": InstanceCountermeasureSerializer(instance_cm).data,
                "message": f"Applied countermeasure '{countermeasure.name}' to threat",
            },
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["post"])
    def recalculate_status(self, request, pk=None):
        """
        Recalculate the threat status based on applied countermeasures.

        Status logic:
            - EXPOSED: No countermeasures applied OR any countermeasure is a gap
            - ADDRESSABLE: Some countermeasures are planned/waived (none are gaps)
            - MITIGATED: All countermeasures are verified or platform
        """
        instance_threat = self.get_object()
        new_status = recalculate_threat_status(instance_threat)

        return Response(
            {
                "threat_id": instance_threat.id,
                "old_status": instance_threat.status,
                "new_status": new_status,
                "message": f"Status updated to {new_status}",
            }
        )

    @action(detail=False, methods=["post"])
    def reorder(self, request):
        """Bulk-update display_order for component threats."""
        ordered_ids = request.data.get("ordered_ids", [])
        if not ordered_ids or not isinstance(ordered_ids, list):
            return Response(
                {"error": "ordered_ids list is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        queryset = self.get_queryset()
        existing_ids = set(
            queryset.filter(id__in=ordered_ids).values_list("id", flat=True)
        )
        if len(existing_ids) != len(ordered_ids):
            return Response(
                {"error": "Some IDs not found or not accessible"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        instances = []
        for position, threat_id in enumerate(ordered_ids):
            instances.append(
                ComponentInstanceThreat(id=threat_id, display_order=position)
            )
        ComponentInstanceThreat.objects.bulk_update(instances, ["display_order"])
        return Response({"status": "ok", "updated": len(ordered_ids)})

    @action(detail=False, methods=["post"])
    def suggest(self, request):
        """Return AI-ranked, grounded threat candidates for a component.

        Unlike ``generate_threats`` (which mechanically attaches every library
        threat for the component's type), this ranks the most relevant ones,
        explains why each applies, and proposes a per-component severity. It
        persists nothing — the caller reviews the candidates and accepts them
        through the normal create path. Suggestions are grounded in installed
        packs, so the model can only select real threats, never invent them.
        """
        component_id = request.data.get("component_id")
        if not component_id:
            return Response(
                {"error": "component_id is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Scope the component to the requesting user's organizations, mirroring
        # this viewset's own queryset (org-owned components, plus unassigned
        # components reachable through their threat model).
        org_ids = request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        component = (
            OrgsystemComponent.objects.filter(
                Q(orgsystem__organization_id__in=org_ids)
                | Q(
                    orgsystem__isnull=True,
                    threat_model__organization_id__in=org_ids,
                ),
                id=component_id,
            )
            .select_related("component_library")
            .first()
        )
        if component is None:
            return Response(
                {"error": "Component not found or not accessible"},
                status=status.HTTP_404_NOT_FOUND,
            )

        try:
            suggestions = suggest_component_threats(component, user=request.user)
        except AIDisabledError as err:
            return Response(
                {"error": str(err)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except AIProviderError as err:
            # The model is enabled but unreachable/misbehaving; 503 signals a
            # transient/operational problem the user can act on (start the
            # model, fix the URL) rather than a bug in their request.
            return Response(
                {"error": str(err)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        return Response({"component": component.id, "suggestions": suggestions})

    @action(detail=False, methods=["get"])
    def ai_availability(self, request):
        """Report whether AI suggestions are available for a component's org.

        The "suggest threats" affordance has to render its enabled/disabled
        state *before* the user clicks, so an unconfigured tenant can be routed
        to the provider settings instead of firing a request that would only
        return a 400. This is a cheap config lookup — it never builds a provider
        or probes the network; an enabled-but-unreachable model still surfaces
        later as a 503 from ``suggest``.
        """
        component_id = request.query_params.get("component_id")
        if not component_id:
            return Response(
                {"error": "component_id is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Same org scoping as ``suggest`` so availability can't leak across
        # tenants: a user only learns about components their orgs can reach.
        org_ids = request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        component = OrgsystemComponent.objects.filter(
            Q(orgsystem__organization_id__in=org_ids)
            | Q(
                orgsystem__isnull=True,
                threat_model__organization_id__in=org_ids,
            ),
            id=component_id,
        ).first()
        if component is None:
            return Response(
                {"error": "Component not found or not accessible"},
                status=status.HTTP_404_NOT_FOUND,
            )

        # ``resolve_config`` applies the org -> settings-fallback -> off
        # precedence and raises when nothing serves this org; that exception is
        # exactly the "AI is off here" signal the owl needs.
        try:
            resolve_config(organization_for_component(component))
        except AIDisabledError as err:
            return Response({"available": False, "reason": str(err)})
        return Response({"available": True, "reason": None})


class DataFlowInstanceThreatViewSet(viewsets.ModelViewSet):
    """ViewSet for DataFlowInstanceThreat."""

    serializer_class = DataFlowInstanceThreatSerializer
    permission_classes = [IsAuthenticated, CanWrite]

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return (
            DataFlowInstanceThreat.objects.filter(
                Q(data_flow__source_component__orgsystem__organization_id__in=org_ids)
                | Q(
                    data_flow__source_component__orgsystem__isnull=True,
                    data_flow__source_component__threat_model__organization_id__in=org_ids,
                )
            )
            .select_related("data_flow", "threat_library")
            .prefetch_related("instance_taxonomy_links__taxonomy_entry__taxonomy")
        )

    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ["data_flow", "threat_library", "status", "inherent_severity"]
    ordering_fields = ["inherent_severity", "status", "created_at"]
    ordering = ["-inherent_severity"]

    @action(detail=True, methods=["post"])
    def apply_countermeasure(self, request, pk=None):
        """Apply a countermeasure to this flow threat instance."""
        flow_threat = self.get_object()

        # Option 1: Link an existing countermeasure instance
        existing_countermeasure_id = request.data.get("existing_countermeasure_id")
        if existing_countermeasure_id:
            try:
                existing_cm = InstanceCountermeasure.objects.get(
                    id=existing_countermeasure_id
                )
            except InstanceCountermeasure.DoesNotExist:
                return Response(
                    {"error": "Countermeasure instance not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )
            _link, link_created = CountermeasureThreatLink.objects.get_or_create(
                countermeasure=existing_cm,
                flow_threat=flow_threat,
            )
            if not link_created:
                return Response(
                    {"error": "Countermeasure already linked to this threat"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            recalculate_threat_status(flow_threat)
            return Response(
                {
                    "countermeasure": InstanceCountermeasureSerializer(
                        existing_cm
                    ).data,
                    "message": "Linked existing countermeasure to flow threat",
                },
                status=status.HTTP_201_CREATED,
            )

        # Option 2: Create new countermeasure from library + link
        countermeasure_id = request.data.get("countermeasure_library_id")
        if not countermeasure_id:
            return Response(
                {
                    "error": "countermeasure_library_id or existing_countermeasure_id is required"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            countermeasure = CountermeasureLibrary.objects.get(id=countermeasure_id)
        except CountermeasureLibrary.DoesNotExist:
            return Response(
                {"error": "Countermeasure not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        requested_status = request.data.get("status")
        if requested_status == "platform":
            _check_platform_status_permission(request.user, new_status="platform")

        # Derive threat_model from the flow's source component
        source_component = (
            flow_threat.data_flow.source_component if flow_threat.data_flow else None
        )
        threat_model = None
        if source_component:
            threat_model = getattr(source_component, "threat_model", None)

        effective_status = requested_status or countermeasure.default_status
        instance_cm = InstanceCountermeasure.objects.create(
            threat_model=threat_model,
            countermeasure_library=countermeasure,
            countermeasure_name=countermeasure.name,
            countermeasure_description=countermeasure.description,
            control_functions=countermeasure.control_functions,
            control_nature=countermeasure.control_nature,
            status=effective_status,
        )

        CountermeasureThreatLink.objects.create(
            countermeasure=instance_cm,
            flow_threat=flow_threat,
        )

        recalculate_threat_status(flow_threat)

        return Response(
            {
                "countermeasure": InstanceCountermeasureSerializer(instance_cm).data,
                "message": f"Applied countermeasure '{countermeasure.name}' to flow threat",
            },
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["post"])
    def recalculate_status(self, request, pk=None):
        """Recalculate the flow threat status based on applied countermeasures."""
        flow_threat = self.get_object()
        new_status = recalculate_threat_status(flow_threat)

        return Response(
            {
                "threat_id": flow_threat.id,
                "old_status": flow_threat.status,
                "new_status": new_status,
                "message": f"Status updated to {new_status}",
            }
        )

    @action(detail=False, methods=["post"])
    def reorder(self, request):
        """Bulk-update display_order for flow threats."""
        ordered_ids = request.data.get("ordered_ids", [])
        if not ordered_ids or not isinstance(ordered_ids, list):
            return Response(
                {"error": "ordered_ids list is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        queryset = self.get_queryset()
        existing_ids = set(
            queryset.filter(id__in=ordered_ids).values_list("id", flat=True)
        )
        if len(existing_ids) != len(ordered_ids):
            return Response(
                {"error": "Some IDs not found or not accessible"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        instances = []
        for position, threat_id in enumerate(ordered_ids):
            instances.append(
                DataFlowInstanceThreat(id=threat_id, display_order=position)
            )
        DataFlowInstanceThreat.objects.bulk_update(instances, ["display_order"])
        return Response({"status": "ok", "updated": len(ordered_ids)})


class InstanceCountermeasureViewSet(viewsets.ModelViewSet):
    """Unified ViewSet for InstanceCountermeasure (component and flow)."""

    serializer_class = InstanceCountermeasureSerializer
    permission_classes = [IsAuthenticated, CanWrite]

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        qs = (
            InstanceCountermeasure.objects.filter(
                threat_model__organization_id__in=org_ids
            )
            .select_related(
                "threat_model",
                "countermeasure_library",
                "verified_by",
                "assigned_owner",
            )
            .prefetch_related(
                "threat_links__component_threat__component",
                "threat_links__flow_threat__data_flow",
            )
        )
        if _truthy(self.request.query_params.get("has_poam")):
            qs = qs.exclude(poam_id="")
        if _truthy(self.request.query_params.get("overdue")):
            from datetime import date

            qs = qs.filter(
                scheduled_completion__lt=date.today(),
            ).exclude(
                status__in=[
                    InstanceCountermeasure.Status.IMPLEMENTED,
                    InstanceCountermeasure.Status.VERIFIED,
                ]
            )
        return qs

    filter_backends = [DjangoFilterBackend]
    filterset_fields = [
        "threat_model",
        "countermeasure_library",
        "status",
        "required_for_release",
    ]

    def perform_update(self, serializer):
        new_status = serializer.validated_data.get("status")
        if new_status is not None:
            current_status = serializer.instance.status
            _check_platform_status_permission(
                self.request.user, current_status, new_status
            )
        instance = serializer.save()
        recalculate_all_threats_for_countermeasure(instance)

    @action(detail=True, methods=["post"])
    def link(self, request, pk=None):
        """Link this countermeasure to an additional threat (component or flow)."""
        countermeasure = self.get_object()
        threat_id = request.data.get("threat_id")
        threat_type = request.data.get("threat_type", "component")
        if not threat_id:
            return Response(
                {"error": "threat_id is required"}, status=status.HTTP_400_BAD_REQUEST
            )

        link_kwargs = {"countermeasure": countermeasure}
        if threat_type in ("flow", "dataflow"):
            try:
                threat = DataFlowInstanceThreat.objects.get(id=threat_id)
            except DataFlowInstanceThreat.DoesNotExist:
                return Response(
                    {"error": "Threat not found"}, status=status.HTTP_404_NOT_FOUND
                )
            link_kwargs["flow_threat"] = threat
        else:
            try:
                threat = ComponentInstanceThreat.objects.get(id=threat_id)
            except ComponentInstanceThreat.DoesNotExist:
                return Response(
                    {"error": "Threat not found"}, status=status.HTTP_404_NOT_FOUND
                )
            link_kwargs["component_threat"] = threat

        link, created = CountermeasureThreatLink.objects.get_or_create(**link_kwargs)
        if not created:
            return Response(
                {"error": "Already linked"}, status=status.HTTP_400_BAD_REQUEST
            )
        recalculate_threat_status(threat)
        return Response(
            {"status": "linked", "link_id": link.id}, status=status.HTTP_201_CREATED
        )

    @action(detail=True, methods=["post"])
    def unlink(self, request, pk=None):
        """Unlink this countermeasure from a threat. Deletes countermeasure if last link."""
        countermeasure = self.get_object()
        threat_id = request.data.get("threat_id")
        threat_type = request.data.get("threat_type", "component")
        if not threat_id:
            return Response(
                {"error": "threat_id is required"}, status=status.HTTP_400_BAD_REQUEST
            )

        if threat_type in ("flow", "dataflow"):
            deleted_count, _ = CountermeasureThreatLink.objects.filter(
                countermeasure=countermeasure,
                flow_threat_id=threat_id,
            ).delete()
        else:
            deleted_count, _ = CountermeasureThreatLink.objects.filter(
                countermeasure=countermeasure,
                component_threat_id=threat_id,
            ).delete()

        if deleted_count == 0:
            return Response(
                {"error": "Link not found"}, status=status.HTTP_404_NOT_FOUND
            )

        # Recalculate the threat we just unlinked from
        try:
            if threat_type in ("flow", "dataflow"):
                threat = DataFlowInstanceThreat.objects.get(id=threat_id)
                recalculate_threat_status(threat)
                recalculate_risks_for_threat(threat, threat_type="flow")
            else:
                threat = ComponentInstanceThreat.objects.get(id=threat_id)
                recalculate_threat_status(threat)
                recalculate_risks_for_threat(threat, threat_type="component")
        except (
            ComponentInstanceThreat.DoesNotExist,
            DataFlowInstanceThreat.DoesNotExist,
        ):
            pass

        # If no more links remain, cascade-delete the countermeasure
        remaining_links = countermeasure.threat_links.count()
        if remaining_links == 0:
            countermeasure.delete()
            return Response(
                {
                    "status": "deleted",
                    "message": "Last link removed, countermeasure deleted",
                }
            )

        return Response({"status": "unlinked", "remaining_links": remaining_links})

    @action(detail=False, methods=["post"])
    def reorder(self, request):
        """Bulk-update display_order on junction table for countermeasures within a threat."""
        threat_id = request.data.get("threat_id")
        threat_type = request.data.get("threat_type", "component")
        ordered_ids = request.data.get("ordered_ids", [])
        if not ordered_ids or not isinstance(ordered_ids, list):
            return Response(
                {"error": "ordered_ids list is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if threat_type in ("flow", "dataflow"):
            links = CountermeasureThreatLink.objects.filter(
                flow_threat_id=threat_id,
                countermeasure_id__in=ordered_ids,
            )
        else:
            links = CountermeasureThreatLink.objects.filter(
                component_threat_id=threat_id,
                countermeasure_id__in=ordered_ids,
            )
        if links.count() != len(ordered_ids):
            return Response(
                {"error": "Some IDs not found or not accessible"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        instances = []
        for position, cm_id in enumerate(ordered_ids):
            link = CountermeasureThreatLink(
                id=links.filter(countermeasure_id=cm_id)
                .values_list("id", flat=True)
                .first()
            )
            link.display_order = position
            instances.append(link)
        CountermeasureThreatLink.objects.bulk_update(instances, ["display_order"])
        return Response({"status": "ok", "updated": len(ordered_ids)})


class VerificationTestViewSet(viewsets.ModelViewSet):
    """ViewSet for VerificationTest."""

    serializer_class = VerificationTestSerializer
    permission_classes = [IsAuthenticated, CanWrite]

    def get_queryset(self):
        from .models import InstanceCountermeasureTest

        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        test_ids = InstanceCountermeasureTest.objects.filter(
            countermeasure__threat_model__organization_id__in=org_ids
        ).values_list("verification_test_id", flat=True)
        return VerificationTest.objects.filter(id__in=test_ids)

    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["method", "passed"]
    search_fields = ["name"]


class PentestFindingViewSet(viewsets.ModelViewSet):
    """ViewSet for PentestFinding."""

    serializer_class = PentestFindingSerializer
    permission_classes = [IsAuthenticated, CanWrite]

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return PentestFinding.objects.filter(
            threat_model__organization_id__in=org_ids
        ).select_related(
            "threat_model",
            "matched_threat_library",
            "matched_countermeasure",
        )

    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ["threat_model", "reconciliation_status", "severity"]
    ordering_fields = ["severity", "created_at"]
    ordering = ["-created_at"]


class InstanceCountermeasureStandardViewSet(viewsets.ModelViewSet):
    """ViewSet for InstanceCountermeasureStandard (instance-level compliance mappings).

    These mappings override library-level compliance mappings for specific countermeasure instances.
    """

    serializer_class = InstanceCountermeasureStandardSerializer
    permission_classes = [IsAuthenticated, CanWrite]

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return InstanceCountermeasureStandard.objects.filter(
            countermeasure__threat_model__organization_id__in=org_ids
        ).select_related(
            "countermeasure",
            "requirement",
            "requirement__framework",
        )

    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["countermeasure", "requirement", "sufficiency"]


class InstanceThreatTaxonomyEntryViewSet(viewsets.ModelViewSet):
    """CRUD for instance-level taxonomy entries on threat instances."""

    serializer_class = InstanceThreatTaxonomyEntrySerializer
    permission_classes = [IsAuthenticated, CanWrite]

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return InstanceThreatTaxonomyEntry.objects.filter(
            Q(component_threat__component__orgsystem__organization_id__in=org_ids)
            | Q(
                component_threat__component__orgsystem__isnull=True,
                component_threat__component__threat_model__organization_id__in=org_ids,
            )
            | Q(
                flow_threat__data_flow__source_component__orgsystem__organization_id__in=org_ids
            )
            | Q(
                flow_threat__data_flow__source_component__orgsystem__isnull=True,
                flow_threat__data_flow__source_component__threat_model__organization_id__in=org_ids,
            )
        ).select_related(
            "taxonomy_entry",
            "taxonomy_entry__taxonomy",
            "component_threat",
            "flow_threat",
        )

    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["component_threat", "flow_threat", "taxonomy_entry"]


class ExternalTaxonomyViewSet(viewsets.ReadOnlyModelViewSet):
    """Read-only ViewSet for ExternalTaxonomy."""

    queryset = ExternalTaxonomy.objects.all()
    serializer_class = ExternalTaxonomySerializer
    permission_classes = [IsAuthenticated]
    pagination_class = None
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["source_pack"]


class TaxonomyEntryViewSet(viewsets.ReadOnlyModelViewSet):
    """Read-only ViewSet for TaxonomyEntry."""

    queryset = TaxonomyEntry.objects.select_related("taxonomy").all()
    serializer_class = TaxonomyEntryNestedSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = None
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["taxonomy__slug"]
    search_fields = ["external_id", "title"]


class RiskViewSet(viewsets.ModelViewSet):
    """ViewSet for Risk CRUD operations, nested under threat models."""

    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_fields = ["inherent_level", "residual_level", "owner", "assigned_to"]
    search_fields = ["name", "description"]
    ordering_fields = ["inherent_score", "residual_score", "created_at", "name"]
    ordering = ["-inherent_score"]

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return Risk.objects.filter(
            threat_model_id=self.kwargs["threat_model_pk"],
            threat_model__organization_id__in=org_ids,
        ).select_related("owner", "assigned_to", "threat_model")

    def get_serializer_class(self):
        if self.action == "list":
            return RiskListSerializer
        return RiskDetailSerializer

    def get_serializer_context(self):
        context = super().get_serializer_context()
        threat_model_pk = self.kwargs.get("threat_model_pk")
        if threat_model_pk:
            with contextlib.suppress(ThreatModel.DoesNotExist):
                context["threat_model"] = ThreatModel.objects.get(pk=threat_model_pk)
        return context

    def perform_create(self, serializer):
        serializer.save(threat_model_id=self.kwargs["threat_model_pk"])

    @action(detail=True, methods=["post"])
    def recalculate(self, request, threat_model_pk=None, pk=None):
        """Recompute residual score and level for this risk."""
        risk = self.get_object()
        recalculate_risk(risk)
        risk.refresh_from_db()
        serializer = RiskDetailSerializer(risk, context=self.get_serializer_context())
        return Response(serializer.data)

    @action(detail=True, methods=["post"], url_path="add-threats")
    def add_threats(self, request, threat_model_pk=None, pk=None):
        """Bulk link threats to this risk."""
        risk = self.get_object()
        component_threat_ids = request.data.get("component_threat_ids", [])
        flow_threat_ids = request.data.get("flow_threat_ids", [])

        valid_component_ids = set(
            ComponentInstanceThreat.objects.filter(
                id__in=component_threat_ids,
                component__threat_model_id=threat_model_pk,
            ).values_list("id", flat=True)
        )
        valid_flow_ids = set(
            DataFlowInstanceThreat.objects.filter(
                id__in=flow_threat_ids,
                data_flow__source_component__threat_model_id=threat_model_pk,
            ).values_list("id", flat=True)
        )

        rejected = (set(component_threat_ids) - valid_component_ids) | (
            set(flow_threat_ids) - valid_flow_ids
        )
        if rejected:
            return Response(
                {
                    "error": "Some threat IDs do not belong to this threat model.",
                    "rejected_ids": sorted(rejected),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        risk_threat_rows = []
        for threat_id in valid_component_ids:
            if not RiskThreat.objects.filter(
                risk=risk, component_threat_id=threat_id
            ).exists():
                risk_threat_rows.append(
                    RiskThreat(risk=risk, component_threat_id=threat_id)
                )
        for threat_id in valid_flow_ids:
            if not RiskThreat.objects.filter(
                risk=risk, flow_threat_id=threat_id
            ).exists():
                risk_threat_rows.append(RiskThreat(risk=risk, flow_threat_id=threat_id))

        if risk_threat_rows:
            RiskThreat.objects.bulk_create(risk_threat_rows)

        recalculate_risk(risk)
        risk.refresh_from_db()
        serializer = RiskDetailSerializer(risk, context=self.get_serializer_context())
        return Response(serializer.data)

    @action(detail=True, methods=["post"], url_path="remove-threats")
    def remove_threats(self, request, threat_model_pk=None, pk=None):
        """Bulk unlink threats from this risk."""
        risk = self.get_object()
        component_threat_ids = request.data.get("component_threat_ids", [])
        flow_threat_ids = request.data.get("flow_threat_ids", [])

        if component_threat_ids:
            RiskThreat.objects.filter(
                risk=risk, component_threat_id__in=component_threat_ids
            ).delete()
        if flow_threat_ids:
            RiskThreat.objects.filter(
                risk=risk, flow_threat_id__in=flow_threat_ids
            ).delete()

        recalculate_risk(risk)
        risk.refresh_from_db()
        serializer = RiskDetailSerializer(risk, context=self.get_serializer_context())
        return Response(serializer.data)

    @action(detail=False, methods=["post"], url_path="bulk-update")
    def bulk_update(self, request, threat_model_pk=None):
        """
        Bulk update response or owner on multiple risks.

        Request body:
            risk_ids: list of risk IDs
            response: optional risk response strategy (accept/mitigate/transfer/avoid, null to clear)
            owner: optional owner user ID (null to clear)
        """
        risk_ids = request.data.get("risk_ids", [])
        if not risk_ids:
            return Response(
                {"error": "risk_ids is required"}, status=status.HTTP_400_BAD_REQUEST
            )

        queryset = self.get_queryset().filter(id__in=risk_ids)
        if queryset.count() != len(risk_ids):
            return Response(
                {"error": "Some risk IDs not found"}, status=status.HTTP_400_BAD_REQUEST
            )

        update_fields = {}
        if "response" in request.data:
            update_fields["response"] = request.data["response"] or None
        if "owner" in request.data:
            update_fields["owner_id"] = request.data["owner"]

        if not update_fields:
            return Response(
                {"error": "No fields to update"}, status=status.HTTP_400_BAD_REQUEST
            )

        updated = queryset.update(**update_fields)
        return Response({"updated": updated})


class CountermeasureCommentViewSet(viewsets.ModelViewSet):
    """ViewSet for CountermeasureComment (comment/history log on countermeasures)."""

    serializer_class = CountermeasureCommentSerializer
    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["countermeasure"]

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return CountermeasureComment.objects.filter(
            countermeasure__threat_model__organization_id__in=org_ids
        ).select_related("author")


class ThreatPersonaViewSet(viewsets.ModelViewSet):
    """CRUD ViewSet for ThreatPersona, scoped to a threat model."""

    serializer_class = ThreatPersonaSerializer
    permission_classes = [IsAuthenticated, CanWrite]
    pagination_class = None
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    search_fields = ["name", "symbolic_name"]

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return ThreatPersona.objects.filter(
            threat_model_id=self.kwargs["threat_model_pk"],
            threat_model__organization_id__in=org_ids,
        )

    def perform_create(self, serializer):
        serializer.save(threat_model_id=self.kwargs["threat_model_pk"])


class ThreatSourceViewSet(viewsets.ReadOnlyModelViewSet):
    """Read-only ViewSet for ThreatSource reference data."""

    queryset = ThreatSource.objects.all()
    serializer_class = ThreatSourceSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = None


class ScoringMethodsView(APIView):
    """Read-only endpoint returning available scoring methods."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(get_scoring_methods_list())
