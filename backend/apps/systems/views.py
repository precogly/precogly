"""
Views for systems app.
"""

from django.db import transaction
from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from apps.core.permissions import CanWrite, IsSecurityTeam

from apps.threats.models import ComponentInstanceThreat, ComponentLibraryThreat, build_taxonomy_snapshot
from apps.threats.serializers import ComponentInstanceThreatSerializer

from .models import (
    ComponentDataAsset,
    ComponentLibrary,
    DataAsset,
    DataFlow,
    DataFlowAsset,
    IntegrationSource,
    Orgsystem,
    OrgsystemComponent,
    TrustBoundary,
    TrustZone,
)
from .serializers import (
    ComponentDataAssetSerializer,
    ComponentLibrarySerializer,
    DataAssetSerializer,
    DataFlowAssetSerializer,
    DataFlowSerializer,
    IntegrationSourceSerializer,
    OrgsystemComponentSerializer,
    OrgsystemListSerializer,
    OrgsystemSerializer,
    TrustBoundarySerializer,
    TrustZoneSerializer,
)


class OrgsystemViewSet(viewsets.ModelViewSet):
    """ViewSet for Orgsystem CRUD operations."""

    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["criticality", "lifecycle_state", "organization"]
    search_fields = ["name", "owner"]
    ordering_fields = ["name", "created_at", "criticality"]
    ordering = ["name"]

    def get_queryset(self):
        """Filter by user's organizations."""
        user = self.request.user
        org_ids = user.organization_memberships.values_list("organization_id", flat=True)
        return Orgsystem.objects.filter(organization_id__in=org_ids).select_related(
            "organization"
        )

    def get_serializer_class(self):
        """Return appropriate serializer."""
        if self.action == "list":
            return OrgsystemListSerializer
        return OrgsystemSerializer


class TrustZoneViewSet(viewsets.ModelViewSet):
    """ViewSet for TrustZone CRUD operations."""

    serializer_class = TrustZoneSerializer
    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    search_fields = ["name", "description"]

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        threat_model_id = self.request.query_params.get("threat_model")
        if threat_model_id:
            return TrustZone.objects.filter(
                components__threat_model_id=threat_model_id,
                components__threat_model__organization_id__in=org_ids,
            ).distinct()
        # Default: zones reachable through any component in user's org
        return TrustZone.objects.filter(
            Q(components__orgsystem__organization_id__in=org_ids)
            | Q(components__threat_model__organization_id__in=org_ids)
        ).distinct()


class TrustBoundaryViewSet(viewsets.ModelViewSet):
    """ViewSet for TrustBoundary CRUD operations."""

    serializer_class = TrustBoundarySerializer
    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["zone_a", "zone_b"]
    search_fields = ["label"]

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return TrustBoundary.objects.filter(
            Q(zone_a__components__orgsystem__organization_id__in=org_ids)
            | Q(zone_b__components__orgsystem__organization_id__in=org_ids)
        ).distinct()


class ComponentLibraryViewSet(viewsets.ModelViewSet):
    """ViewSet for ComponentLibrary (shared component templates)."""

    serializer_class = ComponentLibrarySerializer
    permission_classes = [IsAuthenticated, IsSecurityTeam]
    pagination_class = None
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["category", "component_type", "provider"]
    search_fields = ["name", "component_type", "slug"]

    def get_queryset(self):
        """
        Get all component library entries.

        Returns all components that have been imported into the database.
        Optionally filtered by a threat model's connected packs.
        """
        qs = ComponentLibrary.objects.all().select_related("source_pack").order_by("name")
        threat_model_id = self.request.query_params.get("threat_model")
        if threat_model_id:
            from apps.threat_models.models import ThreatModelLibraryPack

            connected_pack_ids = ThreatModelLibraryPack.objects.filter(
                threat_model_id=threat_model_id
            ).values_list("library_pack_id", flat=True)
            qs = qs.filter(
                Q(source_pack_id__in=connected_pack_ids)
                | Q(source_pack__isnull=True)
            )
        return qs


class OrgsystemComponentViewSet(viewsets.ModelViewSet):
    """ViewSet for OrgsystemComponent CRUD operations."""

    serializer_class = OrgsystemComponentSerializer
    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["orgsystem", "trust_zone", "threat_model"]
    search_fields = ["name"]

    def perform_create(self, serializer):
        """Auto-assign orgsystem from the threat model when not explicitly provided."""
        instance = serializer.save()
        if instance.orgsystem_id is None and instance.threat_model_id:
            from apps.threat_models.models import ThreatModelOrgsystem
            association = ThreatModelOrgsystem.objects.filter(
                threat_model_id=instance.threat_model_id
            ).select_related("orgsystem").first()
            if association:
                instance.orgsystem = association.orgsystem
                instance.save(update_fields=["orgsystem"])

    def get_queryset(self):
        """
        Filter by user's organizations.

        Includes components where:
        - orgsystem belongs to user's organization, OR
        - orgsystem is NULL (unassigned components)
        """
        user = self.request.user
        org_ids = user.organization_memberships.values_list("organization_id", flat=True)
        return OrgsystemComponent.objects.filter(
            Q(orgsystem__organization_id__in=org_ids)
            | Q(orgsystem__isnull=True, threat_model__organization_id__in=org_ids)
        ).select_related("component_library", "trust_zone")

    @action(detail=True, methods=["patch"])
    def assign_system(self, request, pk=None):
        """
        Assign a component to a system (or unassign with null).

        Request body:
            orgsystemId: int | null - System ID to assign, or null to unassign
        """
        component = self.get_object()
        orgsystem_id = request.data.get("orgsystemId")

        if orgsystem_id:
            # Validate system belongs to user's organization
            user = self.request.user
            org_ids = list(user.organization_memberships.values_list("organization_id", flat=True))
            try:
                system = Orgsystem.objects.get(id=orgsystem_id, organization_id__in=org_ids)
                component.orgsystem = system
            except Orgsystem.DoesNotExist:
                return Response(
                    {"error": "System not found or access denied"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:
            component.orgsystem = None

        component.save()
        return Response({"status": "updated", "orgsystemId": orgsystem_id})

    @action(detail=True, methods=["post"])
    def generate_threats(self, request, pk=None):
        """
        Auto-generate threats for this component based on its library type.

        Delegates to _generate_threats_for_component() in diagrams/services.py
        to keep threat creation logic in a single place.

        Returns:
            - created_count: number of newly created threat instances
            - total: total threats now associated with this component
        """
        component = self.get_object()

        if not component.component_library:
            return Response(
                {"error": "Component has no library type assigned"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        from apps.diagrams.services import _generate_threats_for_component

        with transaction.atomic():
            created_count = _generate_threats_for_component(component)

        total = ComponentInstanceThreat.objects.filter(component=component).count()

        return Response({
            "created_count": created_count,
            "existing_count": total - created_count,
            "total": total,
            "message": f"Generated {created_count} new threats, {total - created_count} already existed",
        })


class DataAssetViewSet(viewsets.ModelViewSet):
    """ViewSet for DataAsset CRUD operations."""

    serializer_class = DataAssetSerializer
    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["classification", "confidentiality", "threat_model"]
    search_fields = ["name"]

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return DataAsset.objects.filter(
            threat_model__organization_id__in=org_ids
        )


class DataFlowViewSet(viewsets.ModelViewSet):
    """ViewSet for DataFlow CRUD operations."""

    serializer_class = DataFlowSerializer
    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["crosses_trust_zone", "protocol"]

    def get_queryset(self):
        """Filter by user's organizations."""
        user = self.request.user
        org_ids = user.organization_memberships.values_list("organization_id", flat=True)
        return DataFlow.objects.filter(
            source_component__orgsystem__organization_id__in=org_ids
        ).select_related("source_component", "dest_component")


class IntegrationSourceViewSet(viewsets.ModelViewSet):
    """ViewSet for IntegrationSource CRUD operations."""

    serializer_class = IntegrationSourceSerializer
    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["source_type", "status", "orgsystem"]
    search_fields = ["name"]

    def get_queryset(self):
        """Filter by user's organizations."""
        user = self.request.user
        org_ids = user.organization_memberships.values_list("organization_id", flat=True)
        return IntegrationSource.objects.filter(
            orgsystem__organization_id__in=org_ids
        ).select_related("orgsystem")


class ComponentDataAssetViewSet(viewsets.ModelViewSet):
    """ViewSet for ComponentDataAsset CRUD operations."""

    serializer_class = ComponentDataAssetSerializer
    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["component", "data_asset"]
    ordering = ["id"]

    def get_queryset(self):
        """Filter by user's organizations."""
        user = self.request.user
        org_ids = user.organization_memberships.values_list("organization_id", flat=True)
        return ComponentDataAsset.objects.filter(
            Q(component__orgsystem__organization_id__in=org_ids)
            | Q(
                component__orgsystem__isnull=True,
                component__threat_model__organization_id__in=org_ids,
            )
        ).select_related("component", "data_asset")


class DataFlowAssetViewSet(viewsets.ModelViewSet):
    """ViewSet for DataFlowAsset CRUD operations."""

    serializer_class = DataFlowAssetSerializer
    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["data_flow", "data_asset"]

    def get_queryset(self):
        """Filter by user's organizations via data flow's source component."""
        user = self.request.user
        org_ids = user.organization_memberships.values_list("organization_id", flat=True)
        return DataFlowAsset.objects.filter(
            data_flow__source_component__orgsystem__organization_id__in=org_ids
        ).select_related(
            "data_flow__source_component", "data_flow__dest_component", "data_asset"
        )
