"""
Views for systems app.

Every model-scoped queryset here reaches the organization through one path,
`blueprint__threat_model__organization`, with no nullable step. The
`?threat_model=` and `?blueprint=` filters narrow within that scope; they
never replace it (precogly/precogly#404).
"""

from django.db import transaction
from django.db.models import Count, Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from apps.core.permissions import CanWrite, WritableParentsMixin
from apps.threats.models import InstanceThreat
from apps.threats.services import scope_loss_warnings

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
from .serializers import (
    BoundarySerializer,
    ComponentDataAssetSerializer,
    ComponentLibrarySerializer,
    DataAssetSerializer,
    FlowAssetSerializer,
    FlowSerializer,
    IntegrationSourceSerializer,
    OrgsystemComponentSerializer,
    OrgsystemListSerializer,
    OrgsystemSerializer,
    ZoneSerializer,
)


class BlueprintScopedMixin(WritableParentsMixin):
    """Queryset scoping for rows that belong to a blueprint.

    `blueprint_path` is the lookup from the model to its blueprint key
    (`"blueprint"` for direct rows, `"component__blueprint"` for rows that hang
    off a component, and so on). `writable_parent_fields` are the keys a
    create or PATCH may send that lead to a blueprint; each is checked against
    the caller's write access to that blueprint's model.
    """

    blueprint_path = "blueprint"
    writable_parent_fields = ("blueprint",)

    def _organization_ids(self):
        return self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )

    def scope_queryset(self, queryset):
        path = self.blueprint_path
        queryset = queryset.filter(
            **{f"{path}__threat_model__organization_id__in": self._organization_ids()}
        )
        threat_model_id = self.request.query_params.get("threat_model")
        if threat_model_id:
            queryset = queryset.filter(**{f"{path}__threat_model_id": threat_model_id})
        blueprint_id = self.request.query_params.get("blueprint")
        if blueprint_id:
            queryset = queryset.filter(**{f"{path}_id": blueprint_id})
        return queryset


class ScopeLossWarningMixin:
    """A delete that takes away a control's last target says so (section 4.3).

    `scope_loss_ids(instance)` returns the row ids the delete removes, as
    keyword arguments for `scope_loss_warnings`. The response is 204 as usual,
    or 200 with `{"warnings": [...]}` when a control now applies to the whole
    system.
    """

    def scope_loss_ids(self, instance):
        raise NotImplementedError

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        with transaction.atomic():
            warnings = scope_loss_warnings(**self.scope_loss_ids(instance))
            self.perform_destroy(instance)
        if warnings:
            return Response({"warnings": warnings}, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_204_NO_CONTENT)


def recompute_crossings(blueprint):
    """Recompute every flow's ``crosses_boundary`` in ``blueprint`` (H19, R23).

    Run after any API write that can move a flow end across a boundary: a
    flow's ends, a component's zone, a zone's parent, a boundary's zones.
    """
    from apps.diagrams.services import update_crosses_boundary

    update_crosses_boundary(blueprint)


class RecomputeCrossingsMixin:
    """Keep ``crosses_boundary`` true to the rows after creates, updates and deletes."""

    def perform_create(self, serializer):
        with transaction.atomic():
            super().perform_create(serializer)
            recompute_crossings(serializer.instance.blueprint)

    def perform_update(self, serializer):
        with transaction.atomic():
            super().perform_update(serializer)
            recompute_crossings(serializer.instance.blueprint)

    def perform_destroy(self, instance):
        blueprint = instance.blueprint
        with transaction.atomic():
            super().perform_destroy(instance)
            recompute_crossings(blueprint)


def zone_subtree_ids(zone):
    """The zone and every zone nested under it (children cascade with it)."""
    ids = {zone.id}
    frontier = [zone.id]
    while frontier:
        frontier = list(
            Zone.objects.filter(parent_id__in=frontier)
            .exclude(id__in=ids)
            .values_list("id", flat=True)
        )
        ids.update(frontier)
    return ids


class OrgsystemViewSet(viewsets.ModelViewSet):
    """ViewSet for Orgsystem CRUD operations."""

    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_fields = ["criticality", "lifecycle_state", "organization"]
    search_fields = ["name", "owner"]
    ordering_fields = ["name", "created_at", "criticality"]
    ordering = ["name"]

    def get_queryset(self):
        """Filter by user's organizations."""
        user = self.request.user
        org_ids = user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return (
            Orgsystem.objects.filter(organization_id__in=org_ids)
            .select_related("organization")
            .annotate(
                primary_model_count=Count("primary_threat_models", distinct=True),
                linked_component_count=Count("components", distinct=True),
            )
        )

    def get_serializer_class(self):
        """Return appropriate serializer."""
        if self.action == "list":
            return OrgsystemListSerializer
        return OrgsystemSerializer

    def destroy(self, request, *args, **kwargs):
        """Refuse to delete a system that is some model's primary system (409,
        naming the models; the key is RESTRICT, plan J1). Linked system assets
        are only unlinked (SET_NULL, H5)."""
        system = self.get_object()
        primary_models = list(
            system.primary_threat_models.order_by("name").values("id", "name")
        )
        if primary_models:
            names = ", ".join(model["name"] for model in primary_models)
            return Response(
                {
                    "error": f"'{system.name}' is the primary system of {names}. "
                    "Change those models' primary system before deleting it.",
                    "models": primary_models,
                },
                status=status.HTTP_409_CONFLICT,
            )
        return super().destroy(request, *args, **kwargs)


class ZoneViewSet(
    ScopeLossWarningMixin,
    RecomputeCrossingsMixin,
    BlueprintScopedMixin,
    viewsets.ModelViewSet,
):
    """ViewSet for Zone CRUD operations."""

    serializer_class = ZoneSerializer
    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["parent", "zone_type"]
    search_fields = ["name", "description"]

    def get_queryset(self):
        return self.scope_queryset(Zone.objects.all()).select_related("blueprint")

    def scope_loss_ids(self, instance):
        return {"zone_ids": zone_subtree_ids(instance)}


class BoundaryViewSet(
    ScopeLossWarningMixin,
    RecomputeCrossingsMixin,
    BlueprintScopedMixin,
    viewsets.ModelViewSet,
):
    """ViewSet for Boundary CRUD operations."""

    serializer_class = BoundarySerializer
    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["zone_a", "zone_b", "boundary_type"]
    search_fields = ["label"]

    def get_queryset(self):
        return self.scope_queryset(Boundary.objects.all()).select_related(
            "zone_a", "zone_b"
        )

    def scope_loss_ids(self, instance):
        return {"boundary_ids": [instance.id]}


class ComponentLibraryViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for ComponentLibrary (shared component templates)."""

    serializer_class = ComponentLibrarySerializer
    permission_classes = [IsAuthenticated]
    pagination_class = None
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["category", "kind", "component_type", "provider"]
    search_fields = ["name", "component_type", "slug"]

    def get_queryset(self):
        """
        Get all component library entries.

        Returns all components that have been imported into the database.
        Optionally filtered by a threat model's connected packs.
        """
        qs = (
            ComponentLibrary.objects.all()
            .select_related("source_pack")
            .order_by("name")
        )
        threat_model_id = self.request.query_params.get("threat_model")
        if threat_model_id:
            from apps.threat_models.models import ThreatModelLibraryPack

            connected_pack_ids = ThreatModelLibraryPack.objects.filter(
                threat_model_id=threat_model_id
            ).values_list("library_pack_id", flat=True)
            qs = qs.filter(
                Q(source_pack_id__in=connected_pack_ids) | Q(source_pack__isnull=True)
            )
        return qs


class OrgsystemComponentViewSet(
    ScopeLossWarningMixin,
    RecomputeCrossingsMixin,
    BlueprintScopedMixin,
    viewsets.ModelViewSet,
):
    """ViewSet for OrgsystemComponent CRUD operations."""

    serializer_class = OrgsystemComponentSerializer
    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["orgsystem", "zone", "kind"]
    search_fields = ["name"]

    def get_queryset(self):
        return self.scope_queryset(OrgsystemComponent.objects.all()).select_related(
            "component_library", "zone", "blueprint"
        )

    def scope_loss_ids(self, instance):
        # Flows to and from the component cascade; the helper covers them.
        return {"component_ids": [instance.id]}

    @action(detail=True, methods=["post"])
    def generate_threats(self, request, pk=None):
        """
        Auto-generate threats for this component based on its library type.

        Delegates to ensure_generated_threats() in threats/services.py, the one
        place instance threats are generated.

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

        from apps.threats.services import ensure_generated_threats

        with transaction.atomic():
            created_count = ensure_generated_threats(component)

        total = InstanceThreat.objects.filter(targets__component=component).count()

        return Response(
            {
                "created_count": created_count,
                "existing_count": total - created_count,
                "total": total,
                "message": f"Generated {created_count} new threats, {total - created_count} already existed",
            }
        )


class DataAssetViewSet(BlueprintScopedMixin, viewsets.ModelViewSet):
    """ViewSet for DataAsset CRUD operations."""

    serializer_class = DataAssetSerializer
    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["classification", "confidentiality"]
    search_fields = ["name"]

    def get_queryset(self):
        return self.scope_queryset(DataAsset.objects.all())


class FlowViewSet(
    ScopeLossWarningMixin,
    RecomputeCrossingsMixin,
    BlueprintScopedMixin,
    viewsets.ModelViewSet,
):
    """ViewSet for Flow CRUD operations."""

    serializer_class = FlowSerializer
    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["crosses_boundary", "protocol", "flow_type"]

    def get_queryset(self):
        return self.scope_queryset(Flow.objects.all()).select_related(
            "source_component", "dest_component"
        )

    def scope_loss_ids(self, instance):
        return {"flow_ids": [instance.id]}

    def perform_create(self, serializer):
        """A new flow gets its library threats, as one drawn on the DFD does."""
        from apps.threats.services import ensure_generated_threats

        with transaction.atomic():
            super().perform_create(serializer)
            ensure_generated_threats(serializer.instance)

    def perform_update(self, serializer):
        """A type or ends change regenerates threats, as DFD sync does (R23)."""
        from apps.threats.services import (
            ensure_generated_threats,
            remove_threats_that_stopped_applying,
        )

        flow = serializer.instance
        before = (flow.flow_type, flow.source_component_id, flow.dest_component_id)
        with transaction.atomic():
            super().perform_update(serializer)
            flow.refresh_from_db()
            after = (flow.flow_type, flow.source_component_id, flow.dest_component_id)
            if after != before:
                remove_threats_that_stopped_applying(flow)
                ensure_generated_threats(flow)


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
        org_ids = user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return IntegrationSource.objects.filter(
            orgsystem__organization_id__in=org_ids
        ).select_related("orgsystem")


class ComponentDataAssetViewSet(BlueprintScopedMixin, viewsets.ModelViewSet):
    """ViewSet for ComponentDataAsset CRUD operations."""

    serializer_class = ComponentDataAssetSerializer
    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["component", "data_asset"]
    ordering = ["id"]
    blueprint_path = "component__blueprint"
    writable_parent_fields = ("component", "data_asset")

    def get_queryset(self):
        return self.scope_queryset(ComponentDataAsset.objects.all()).select_related(
            "component", "data_asset"
        )


class FlowAssetViewSet(BlueprintScopedMixin, viewsets.ModelViewSet):
    """ViewSet for FlowAsset CRUD operations."""

    serializer_class = FlowAssetSerializer
    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["flow", "data_asset"]
    blueprint_path = "flow__blueprint"
    writable_parent_fields = ("flow", "data_asset")

    def get_queryset(self):
        return (
            self.scope_queryset(FlowAsset.objects.all())
            .select_related(
                "flow__source_component", "flow__dest_component", "data_asset"
            )
            .order_by("id")
        )
