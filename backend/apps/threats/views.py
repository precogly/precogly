"""
Views for threats app.
"""

from django.db.models import Prefetch, Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from rest_framework.exceptions import PermissionDenied

from apps.core.permissions import CanWrite, IsSecurityTeam
from apps.threat_models.models import ThreatModel

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
)
from .scoring.registry import get_scoring_methods_list


def _is_security_team(user):
    """Check if user has Security Team role in any organization."""
    return user.organization_memberships.filter(role="security_team").exists()


def _check_platform_status_permission(user, current_status=None, new_status=None):
    """Raise PermissionDenied if non-Security Team user tries to set or remove platform status."""
    if (new_status == "platform" or current_status == "platform") and not _is_security_team(user):
        raise PermissionDenied(
            "Only Security Team members can assign or remove platform status."
        )
from .serializers import (
    ComponentInstanceCountermeasureSerializer,
    ComponentInstanceCountermeasureStandardSerializer,
    ComponentInstanceThreatSerializer,
    ComponentLibraryThreatSerializer,
    CountermeasureLibraryListSerializer,
    CountermeasureLibrarySerializer,
    DataFlowInstanceThreatSerializer,
    ExternalTaxonomySerializer,
    FlowInstanceCountermeasureSerializer,
    FlowInstanceCountermeasureStandardSerializer,
    PentestFindingSerializer,
    RiskDetailSerializer,
    RiskListSerializer,
    TaxonomyEntryNestedSerializer,
    ThreatLibraryListSerializer,
    ThreatLibrarySerializer,
    VerificationTestSerializer,
)
from .services import recalculate_risk, recalculate_risks_for_threat, recalculate_threat_status


class ThreatLibraryViewSet(viewsets.ModelViewSet):
    """ViewSet for ThreatLibrary CRUD operations."""

    permission_classes = [IsAuthenticated, IsSecurityTeam]
    pagination_class = None  # Return all items without pagination
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = []
    search_fields = ["name", "description"]
    ordering_fields = ["name", "created_at"]
    ordering = ["name"]

    def get_queryset(self):
        """Return all threats in the library."""
        return ThreatLibrary.objects.all().select_related("source_pack")

    def get_serializer_class(self):
        """Return appropriate serializer."""
        if self.action == "list":
            return ThreatLibraryListSerializer
        return ThreatLibrarySerializer


class CountermeasureLibraryViewSet(viewsets.ModelViewSet):
    """ViewSet for CountermeasureLibrary CRUD operations."""

    permission_classes = [IsAuthenticated, IsSecurityTeam]
    pagination_class = None  # Return all items without pagination
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["control_type", "cost"]
    search_fields = ["name", "description"]
    ordering_fields = ["name", "control_type", "created_at"]
    ordering = ["name"]

    def get_queryset(self):
        """Return all countermeasures in the library."""
        return CountermeasureLibrary.objects.all().select_related("source_pack")

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
        cm_qs = ComponentInstanceCountermeasure.objects.select_related(
            "countermeasure_library",
            "assigned_owner",
            "verified_by",
        ).order_by("display_order", "created_at")
        return ComponentInstanceThreat.objects.filter(
            Q(component__orgsystem__organization_id__in=org_ids)
            | Q(component__orgsystem__isnull=True,
                component__threat_model__organization_id__in=org_ids)
        ).select_related("component", "threat_library").prefetch_related(
            Prefetch("countermeasures", queryset=cm_qs),
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

        # Get countermeasures already applied to this instance
        applied_ids = set(
            instance_threat.countermeasures.values_list(
                "countermeasure_library_id", flat=True
            )
        )

        suggested = []
        applied = []

        for cm in applicable_countermeasures:
            if cm.id in applied_ids:
                applied.append(cm)
            else:
                suggested.append(cm)

        return Response({
            "threat_id": instance_threat.id,
            "threat_name": threat_library.name,
            "suggested": CountermeasureLibraryListSerializer(suggested, many=True).data,
            "applied": CountermeasureLibraryListSerializer(applied, many=True).data,
            "suggested_count": len(suggested),
            "applied_count": len(applied),
        })

    @action(detail=True, methods=["post"])
    def apply_countermeasure(self, request, pk=None):
        """
        Apply a suggested countermeasure to this threat instance.

        Request body:
            - countermeasure_library_id: ID of the countermeasure to apply
            - status: optional, defaults to 'gap'
        """
        instance_threat = self.get_object()
        countermeasure_id = request.data.get("countermeasure_library_id")

        if not countermeasure_id:
            return Response(
                {"error": "countermeasure_library_id is required"},
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
        # Library defaults (default_status=platform) are allowed through.
        requested_status = request.data.get("status")
        if requested_status == "platform":
            _check_platform_status_permission(request.user, new_status="platform")

        # Create or get the instance countermeasure
        effective_status = requested_status or countermeasure.default_status
        instance_cm, created = ComponentInstanceCountermeasure.objects.get_or_create(
            instance_threat=instance_threat,
            countermeasure_library=countermeasure,
            defaults={
                "status": effective_status,
            },
        )

        if not created:
            return Response(
                {"error": "Countermeasure already applied to this threat"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Recalculate threat status
        recalculate_threat_status(instance_threat)

        return Response({
            "countermeasure": ComponentInstanceCountermeasureSerializer(instance_cm).data,
            "message": f"Applied countermeasure '{countermeasure.name}' to threat",
        }, status=status.HTTP_201_CREATED)

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

        return Response({
            "threat_id": instance_threat.id,
            "old_status": instance_threat.status,
            "new_status": new_status,
            "message": f"Status updated to {new_status}",
        })

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
        existing_ids = set(queryset.filter(id__in=ordered_ids).values_list("id", flat=True))
        if len(existing_ids) != len(ordered_ids):
            return Response(
                {"error": "Some IDs not found or not accessible"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        instances = []
        for position, threat_id in enumerate(ordered_ids):
            instances.append(ComponentInstanceThreat(id=threat_id, display_order=position))
        ComponentInstanceThreat.objects.bulk_update(instances, ["display_order"])
        return Response({"status": "ok", "updated": len(ordered_ids)})


class DataFlowInstanceThreatViewSet(viewsets.ModelViewSet):
    """ViewSet for DataFlowInstanceThreat."""

    serializer_class = DataFlowInstanceThreatSerializer
    permission_classes = [IsAuthenticated, CanWrite]

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return DataFlowInstanceThreat.objects.filter(
            Q(data_flow__source_component__orgsystem__organization_id__in=org_ids)
            | Q(data_flow__source_component__orgsystem__isnull=True,
                data_flow__source_component__threat_model__organization_id__in=org_ids)
        ).select_related("data_flow", "threat_library")
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ["data_flow", "threat_library", "status", "inherent_severity"]
    ordering_fields = ["inherent_severity", "status", "created_at"]
    ordering = ["-inherent_severity"]

    @action(detail=True, methods=["post"])
    def apply_countermeasure(self, request, pk=None):
        """Apply a suggested countermeasure to this flow threat instance."""
        flow_threat = self.get_object()
        countermeasure_id = request.data.get("countermeasure_library_id")

        if not countermeasure_id:
            return Response(
                {"error": "countermeasure_library_id is required"},
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
        # Library defaults (default_status=platform) are allowed through.
        requested_status = request.data.get("status")
        if requested_status == "platform":
            _check_platform_status_permission(request.user, new_status="platform")

        effective_status = requested_status or countermeasure.default_status
        instance_cm, created = FlowInstanceCountermeasure.objects.get_or_create(
            flow_threat=flow_threat,
            countermeasure_library=countermeasure,
            defaults={
                "status": effective_status,
            },
        )

        if not created:
            return Response(
                {"error": "Countermeasure already applied to this threat"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        recalculate_threat_status(flow_threat)

        return Response({
            "countermeasure": FlowInstanceCountermeasureSerializer(instance_cm).data,
            "message": f"Applied countermeasure '{countermeasure.name}' to flow threat",
        }, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"])
    def recalculate_status(self, request, pk=None):
        """Recalculate the flow threat status based on applied countermeasures."""
        flow_threat = self.get_object()
        new_status = recalculate_threat_status(flow_threat)

        return Response({
            "threat_id": flow_threat.id,
            "old_status": flow_threat.status,
            "new_status": new_status,
            "message": f"Status updated to {new_status}",
        })

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
        existing_ids = set(queryset.filter(id__in=ordered_ids).values_list("id", flat=True))
        if len(existing_ids) != len(ordered_ids):
            return Response(
                {"error": "Some IDs not found or not accessible"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        instances = []
        for position, threat_id in enumerate(ordered_ids):
            instances.append(DataFlowInstanceThreat(id=threat_id, display_order=position))
        DataFlowInstanceThreat.objects.bulk_update(instances, ["display_order"])
        return Response({"status": "ok", "updated": len(ordered_ids)})


class ComponentInstanceCountermeasureViewSet(viewsets.ModelViewSet):
    """ViewSet for ComponentInstanceCountermeasure."""

    serializer_class = ComponentInstanceCountermeasureSerializer
    permission_classes = [IsAuthenticated, CanWrite]

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return ComponentInstanceCountermeasure.objects.filter(
            Q(instance_threat__component__orgsystem__organization_id__in=org_ids)
            | Q(instance_threat__component__orgsystem__isnull=True,
                instance_threat__component__threat_model__organization_id__in=org_ids)
        ).select_related(
            "instance_threat",
            "countermeasure_library",
            "verified_by",
            "assigned_owner",
        )
    filter_backends = [DjangoFilterBackend]
    filterset_fields = [
        "instance_threat",
        "countermeasure_library",
        "status",
        "required_for_release",
    ]

    def perform_update(self, serializer):
        new_status = serializer.validated_data.get("status")
        if new_status is not None:
            current_status = serializer.instance.status
            _check_platform_status_permission(self.request.user, current_status, new_status)
        instance = serializer.save()
        recalculate_threat_status(instance.instance_threat)
        recalculate_risks_for_threat(instance.instance_threat, threat_type="component")

    @action(detail=False, methods=["post"])
    def reorder(self, request):
        """Bulk-update display_order for component countermeasures."""
        ordered_ids = request.data.get("ordered_ids", [])
        if not ordered_ids or not isinstance(ordered_ids, list):
            return Response(
                {"error": "ordered_ids list is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        queryset = self.get_queryset()
        existing_ids = set(queryset.filter(id__in=ordered_ids).values_list("id", flat=True))
        if len(existing_ids) != len(ordered_ids):
            return Response(
                {"error": "Some IDs not found or not accessible"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        instances = []
        for position, cm_id in enumerate(ordered_ids):
            instances.append(ComponentInstanceCountermeasure(id=cm_id, display_order=position))
        ComponentInstanceCountermeasure.objects.bulk_update(instances, ["display_order"])
        return Response({"status": "ok", "updated": len(ordered_ids)})


class FlowInstanceCountermeasureViewSet(viewsets.ModelViewSet):
    """ViewSet for FlowInstanceCountermeasure."""

    serializer_class = FlowInstanceCountermeasureSerializer
    permission_classes = [IsAuthenticated, CanWrite]

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return FlowInstanceCountermeasure.objects.filter(
            Q(flow_threat__data_flow__source_component__orgsystem__organization_id__in=org_ids)
            | Q(flow_threat__data_flow__source_component__orgsystem__isnull=True,
                flow_threat__data_flow__source_component__threat_model__organization_id__in=org_ids)
        ).select_related(
            "flow_threat",
            "countermeasure_library",
            "verified_by",
            "assigned_owner",
        )
    filter_backends = [DjangoFilterBackend]
    filterset_fields = [
        "flow_threat",
        "countermeasure_library",
        "status",
        "required_for_release",
    ]

    def perform_update(self, serializer):
        new_status = serializer.validated_data.get("status")
        if new_status is not None:
            current_status = serializer.instance.status
            _check_platform_status_permission(self.request.user, current_status, new_status)
        instance = serializer.save()
        recalculate_risks_for_threat(instance.flow_threat, threat_type="flow")

    @action(detail=False, methods=["post"])
    def reorder(self, request):
        """Bulk-update display_order for flow countermeasures."""
        ordered_ids = request.data.get("ordered_ids", [])
        if not ordered_ids or not isinstance(ordered_ids, list):
            return Response(
                {"error": "ordered_ids list is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        queryset = self.get_queryset()
        existing_ids = set(queryset.filter(id__in=ordered_ids).values_list("id", flat=True))
        if len(existing_ids) != len(ordered_ids):
            return Response(
                {"error": "Some IDs not found or not accessible"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        instances = []
        for position, cm_id in enumerate(ordered_ids):
            instances.append(FlowInstanceCountermeasure(id=cm_id, display_order=position))
        FlowInstanceCountermeasure.objects.bulk_update(instances, ["display_order"])
        return Response({"status": "ok", "updated": len(ordered_ids)})


class VerificationTestViewSet(viewsets.ModelViewSet):
    """ViewSet for VerificationTest."""

    serializer_class = VerificationTestSerializer
    permission_classes = [IsAuthenticated, CanWrite]

    def get_queryset(self):
        from .models import ComponentInstanceCountermeasureTest, FlowInstanceCountermeasureTest

        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        component_test_ids = ComponentInstanceCountermeasureTest.objects.filter(
            Q(component_countermeasure__instance_threat__component__orgsystem__organization_id__in=org_ids)
            | Q(component_countermeasure__instance_threat__component__orgsystem__isnull=True,
                component_countermeasure__instance_threat__component__threat_model__organization_id__in=org_ids)
        ).values_list("test_id", flat=True)
        flow_test_ids = FlowInstanceCountermeasureTest.objects.filter(
            Q(flow_countermeasure__flow_threat__data_flow__source_component__orgsystem__organization_id__in=org_ids)
            | Q(flow_countermeasure__flow_threat__data_flow__source_component__orgsystem__isnull=True,
                flow_countermeasure__flow_threat__data_flow__source_component__threat_model__organization_id__in=org_ids)
        ).values_list("test_id", flat=True)
        return VerificationTest.objects.filter(
            Q(id__in=component_test_ids) | Q(id__in=flow_test_ids)
        )
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
            "matched_component_countermeasure",
            "matched_flow_countermeasure",
        )
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ["threat_model", "reconciliation_status", "severity"]
    ordering_fields = ["severity", "created_at"]
    ordering = ["-created_at"]


class ComponentInstanceCountermeasureStandardViewSet(viewsets.ModelViewSet):
    """ViewSet for ComponentInstanceCountermeasureStandard (instance-level compliance mappings).

    These mappings override library-level compliance mappings for specific countermeasure instances.
    """

    serializer_class = ComponentInstanceCountermeasureStandardSerializer
    permission_classes = [IsAuthenticated, CanWrite]

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return ComponentInstanceCountermeasureStandard.objects.filter(
            Q(component_countermeasure__instance_threat__component__orgsystem__organization_id__in=org_ids)
            | Q(component_countermeasure__instance_threat__component__orgsystem__isnull=True,
                component_countermeasure__instance_threat__component__threat_model__organization_id__in=org_ids)
        ).select_related(
            "component_countermeasure",
            "requirement",
            "requirement__framework",
        )
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["component_countermeasure", "requirement", "sufficiency"]


class FlowInstanceCountermeasureStandardViewSet(viewsets.ModelViewSet):
    """ViewSet for FlowInstanceCountermeasureStandard (instance-level compliance mappings).

    These mappings override library-level compliance mappings for specific flow countermeasure instances.
    """

    serializer_class = FlowInstanceCountermeasureStandardSerializer
    permission_classes = [IsAuthenticated, CanWrite]

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return FlowInstanceCountermeasureStandard.objects.filter(
            Q(flow_countermeasure__flow_threat__data_flow__source_component__orgsystem__organization_id__in=org_ids)
            | Q(flow_countermeasure__flow_threat__data_flow__source_component__orgsystem__isnull=True,
                flow_countermeasure__flow_threat__data_flow__source_component__threat_model__organization_id__in=org_ids)
        ).select_related(
            "flow_countermeasure",
            "requirement",
            "requirement__framework",
        )
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["flow_countermeasure", "requirement", "sufficiency"]


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
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
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
            try:
                context["threat_model"] = ThreatModel.objects.get(pk=threat_model_pk)
            except ThreatModel.DoesNotExist:
                pass
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

        risk_threat_rows = []
        for threat_id in component_threat_ids:
            if not RiskThreat.objects.filter(risk=risk, component_threat_id=threat_id).exists():
                risk_threat_rows.append(RiskThreat(risk=risk, component_threat_id=threat_id))
        for threat_id in flow_threat_ids:
            if not RiskThreat.objects.filter(risk=risk, flow_threat_id=threat_id).exists():
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


class ScoringMethodsView(APIView):
    """Read-only endpoint returning available scoring methods."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(get_scoring_methods_list())
