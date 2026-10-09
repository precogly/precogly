"""
Views for diagrams app.
"""

from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from apps.ai.providers.base import AIDisabledError, AIProviderError
from apps.ai.resolver import resolve_config
from apps.core.permissions import CanWrite
from apps.threat_models.models import Blueprint, ThreatModel

from .ai import analyze_architecture_image, generate_dfd_from_analysis
from .canvas import normalize_canvas
from .models import DFD, DFDTemplatesLibrary
from .serializers import (
    DFDListSerializer,
    DFDSerializer,
    DFDTemplatesLibrarySerializer,
)
from .services import sync_dfd_nodes_to_components

# Image types accepted for architecture diagram analysis.
_ACCEPTED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp"}
_MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 10 MB


class DFDViewSet(viewsets.ModelViewSet):
    """ViewSet for DFD CRUD operations."""

    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_fields = ["diagram_type"]
    search_fields = ["name"]
    ordering_fields = ["name", "created_at", "updated_at"]
    ordering = ["-updated_at"]

    def get_queryset(self):
        """Get DFDs accessible to the user."""
        user = self.request.user
        # Get organizations the user belongs to
        org_ids = user.organization_memberships.values_list(
            "organization_id", flat=True
        )

        queryset = DFD.objects.filter(
            blueprint__threat_model__organization_id__in=org_ids
        ).select_related("updated_by", "blueprint", "blueprint__threat_model")
        threat_model_id = self.request.query_params.get("threat_model")
        if threat_model_id:
            queryset = queryset.filter(blueprint__threat_model_id=threat_model_id)
        blueprint_id = self.request.query_params.get("blueprint")
        if blueprint_id:
            queryset = queryset.filter(blueprint_id=blueprint_id)
        return queryset

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == "list":
            return DFDListSerializer
        return DFDSerializer

    def create(self, request, *args, **kwargs):
        """
        Create a DFD for a blueprint.

        Takes `blueprint_id`, or `threat_model_id` for that model's default
        blueprint. Both are scoped to the caller's organizations. The first DFD
        of a blueprint becomes its primary diagram, the one that syncs to rows.
        """
        blueprint_id = request.data.get("blueprint_id")
        threat_model_id = request.data.get("threat_model_id")
        if not blueprint_id and not threat_model_id:
            return Response(
                {
                    "error": "blueprint_id or threat_model_id is required. "
                    "DFDs cannot be created without a blueprint."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        org_ids = request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        if blueprint_id:
            blueprint = (
                Blueprint.objects.filter(
                    id=blueprint_id, threat_model__organization_id__in=org_ids
                )
                .select_related("threat_model")
                .first()
            )
            if blueprint is None:
                return Response(
                    {"error": "Blueprint not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:
            threat_model = ThreatModel.objects.filter(
                id=threat_model_id, organization_id__in=org_ids
            ).first()
            if threat_model is None:
                return Response(
                    {"error": "Threat model not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )
            blueprint = threat_model.default_blueprint

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        is_first_dfd = not blueprint.dfds.exists()
        serializer.save(
            updated_by=request.user,
            blueprint=blueprint,
            is_primary=is_first_dfd,
        )

        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    def perform_update(self, serializer):
        """Set updated_by to current user and sync nodes to components (primary only)."""
        # Capture canvas state before save so sync can detect deleted nodes/edges
        dfd_before_save = self.get_object()
        old_canvas_data = dfd_before_save.canvas_data or {}

        dfd = serializer.save(updated_by=self.request.user)

        # Only the primary DFD of a blueprint syncs nodes to rows
        self._sync_warnings = []
        if dfd.is_primary:
            result = sync_dfd_nodes_to_components(
                dfd, dfd.blueprint, old_canvas_data=old_canvas_data
            )
            self._sync_warnings = result.get("warnings", [])

    def update(self, request, *args, **kwargs):
        """A save that left a control without scope says so (section 4.3)."""
        response = super().update(request, *args, **kwargs)
        warnings = getattr(self, "_sync_warnings", [])
        if warnings and isinstance(response.data, dict):
            response.data["sync_warnings"] = warnings
        return response

    @action(detail=False, methods=["post"])
    def create_for_threat_model(self, request):
        """Create a DFD and associate it with a threat model. Delegates to create()."""
        return self.create(request)

    @action(detail=True, methods=["get"])
    def delete_preview(self, request, pk=None):
        """
        Preview what will be deleted when this DFD is deleted.

        Returns information about:
        - Threat model that owns this DFD
        - Node and component counts
        - Orphaned components that could be deleted
        """
        from apps.systems.models import OrgsystemComponent

        dfd = self.get_object()
        canvas_data = dfd.canvas_data or {}
        nodes = canvas_data.get("nodes", [])

        threat_model = dfd.blueprint.threat_model
        affected_threat_models = [
            {"id": str(threat_model.id), "name": threat_model.name}
        ]

        # Extract component IDs from nodes
        component_ids = []
        for node in nodes:
            comp_id = node.get("data", {}).get("component_id")
            if comp_id:
                component_ids.append(comp_id)

        # Find orphaned components (components only referenced by this DFD within the same blueprint)
        orphaned_components = []
        if component_ids:
            sibling_dfds = dfd.blueprint.dfds.exclude(id=dfd.id)

            sibling_component_ids = set()
            for sibling_dfd in sibling_dfds:
                sibling_canvas = sibling_dfd.canvas_data or {}
                for node in sibling_canvas.get("nodes", []):
                    comp_id = node.get("data", {}).get("component_id")
                    if comp_id:
                        sibling_component_ids.add(comp_id)

            orphaned_component_ids = set(component_ids) - sibling_component_ids

            if orphaned_component_ids:
                orphaned_comps = OrgsystemComponent.objects.filter(
                    id__in=orphaned_component_ids
                ).select_related("component_library")

                for comp in orphaned_comps:
                    orphaned_components.append(
                        {
                            "id": comp.id,
                            "name": comp.name,
                            "library_name": comp.component_library.name
                            if comp.component_library
                            else None,
                        }
                    )

        return Response(
            {
                "dfd": {
                    "id": str(dfd.id),
                    "name": dfd.name,
                    "node_count": len(nodes),
                    "component_count": len(component_ids),
                },
                "affected_threat_models": affected_threat_models,
                "orphaned_components": orphaned_components,
                "orphaned_component_count": len(orphaned_components),
            }
        )

    @action(detail=False, methods=["get"], url_path="ai-availability")
    def ai_availability(self, request):
        """Report whether AI-powered DFD generation is available for an org."""
        threat_model_id = request.query_params.get("threat_model_id")
        if not threat_model_id:
            return Response(
                {"error": "threat_model_id query parameter is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        org_ids = request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        threat_model = ThreatModel.objects.filter(
            id=threat_model_id, organization_id__in=org_ids
        ).first()
        if threat_model is None:
            return Response(
                {"error": "Threat model not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        try:
            resolve_config(threat_model.organization)
        except AIDisabledError as err:
            return Response({"available": False, "reason": str(err)})
        return Response({"available": True, "reason": None})

    @action(detail=False, methods=["post"], url_path="analyze-image")
    def analyze_image(self, request):
        """Analyze an architecture diagram image and extract components."""
        image = request.FILES.get("image")
        app_name = request.data.get("app_name", "").strip()
        app_description = request.data.get("app_description", "").strip()
        threat_model_id = request.data.get("threat_model_id")

        if not image:
            return Response(
                {"error": "An image file is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not app_name:
            return Response(
                {"error": "app_name is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not threat_model_id:
            return Response(
                {"error": "threat_model_id is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate image type and size.
        if image.content_type not in _ACCEPTED_IMAGE_TYPES:
            return Response(
                {
                    "error": f"Unsupported image type: {image.content_type}. Accepted: JPEG, PNG, WebP."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        if image.size > _MAX_IMAGE_SIZE:
            return Response(
                {"error": "Image must be 10 MB or smaller."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Scope threat model to user's orgs.
        org_ids = request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        threat_model = (
            ThreatModel.objects.filter(id=threat_model_id, organization_id__in=org_ids)
            .select_related("organization")
            .first()
        )
        if threat_model is None:
            return Response(
                {"error": "Threat model not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        try:
            result = analyze_architecture_image(
                image_bytes=image.read(),
                image_content_type=image.content_type,
                app_name=app_name,
                app_description=app_description,
                organization=threat_model.organization,
                user=request.user,
            )
        except AIDisabledError as err:
            return Response({"error": str(err)}, status=status.HTTP_400_BAD_REQUEST)
        except AIProviderError as err:
            return Response(
                {"error": str(err)}, status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        return Response(result)

    @action(detail=False, methods=["post"], url_path="generate-dfd")
    def generate_dfd(self, request):
        """Generate DFD canvas data from an analysis and user answers."""
        threat_model_id = request.data.get("threat_model_id")
        analysis = request.data.get("analysis")
        answers = request.data.get("answers", [])

        if not threat_model_id:
            return Response(
                {"error": "threat_model_id is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not analysis or not isinstance(analysis, dict):
            return Response(
                {"error": "analysis object is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        org_ids = request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        threat_model = (
            ThreatModel.objects.filter(id=threat_model_id, organization_id__in=org_ids)
            .select_related("organization")
            .first()
        )
        if threat_model is None:
            return Response(
                {"error": "Threat model not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        try:
            canvas_data = generate_dfd_from_analysis(
                analysis=analysis,
                answers=answers if isinstance(answers, list) else [],
                threat_model=threat_model,
                organization=threat_model.organization,
                user=request.user,
            )
        except AIDisabledError as err:
            return Response({"error": str(err)}, status=status.HTTP_400_BAD_REQUEST)
        except AIProviderError as err:
            return Response(
                {"error": str(err)}, status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        return Response(canvas_data)

    def destroy(self, request, *args, **kwargs):
        """
        Delete a DFD with optional orphaned component cleanup.

        Query params:
        - delete_orphaned_components: If "true", also delete components
          that are only referenced by this DFD.
        """
        from apps.systems.models import OrgsystemComponent

        dfd = self.get_object()
        delete_orphaned = (
            request.query_params.get("delete_orphaned_components", "").lower() == "true"
        )

        # Capture primary state before deletion for auto-promotion
        was_primary = dfd.is_primary
        blueprint = dfd.blueprint

        orphaned_deleted_count = 0

        if delete_orphaned:
            canvas_data = dfd.canvas_data or {}
            nodes = canvas_data.get("nodes", [])

            component_ids = []
            for node in nodes:
                comp_id = node.get("data", {}).get("component_id")
                if comp_id:
                    component_ids.append(comp_id)

            if component_ids:
                sibling_dfds = blueprint.dfds.exclude(id=dfd.id)
                sibling_component_ids = set()
                for sibling_dfd in sibling_dfds:
                    sibling_canvas = sibling_dfd.canvas_data or {}
                    for node in sibling_canvas.get("nodes", []):
                        comp_id = node.get("data", {}).get("component_id")
                        if comp_id:
                            sibling_component_ids.add(comp_id)

                orphaned_component_ids = set(component_ids) - sibling_component_ids
                if orphaned_component_ids:
                    orphaned_deleted_count, _ = OrgsystemComponent.objects.filter(
                        id__in=orphaned_component_ids, blueprint=blueprint
                    ).delete()

        # Delete the DFD (cascades via FK)
        dfd.delete()

        # Auto-promote the next DFD of the blueprint if the deleted one was primary
        if was_primary:
            next_dfd = blueprint.dfds.order_by("created_at").first()
            if next_dfd:
                next_dfd.is_primary = True
                next_dfd.save(update_fields=["is_primary"])

        return Response(
            {
                "status": "deleted",
                "orphaned_components_deleted": orphaned_deleted_count,
            },
            status=status.HTTP_200_OK,
        )


class DFDTemplatesLibraryViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for browsing DFD templates (read-only)."""

    serializer_class = DFDTemplatesLibrarySerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["category", "diagram_type"]
    search_fields = ["name", "description"]

    def get_queryset(self):
        """Get available DFD templates, optionally filtered by connected packs."""
        qs = DFDTemplatesLibrary.objects.all().select_related("source_pack")
        threat_model_id = self.request.query_params.get("threat_model")
        if threat_model_id:
            from apps.packs.models import LibraryPack
            from apps.threat_models.models import ThreatModelLibraryPack

            connected_pack_ids = ThreatModelLibraryPack.objects.filter(
                threat_model_id=threat_model_id
            ).values_list("library_pack_id", flat=True)

            # A template is gated on its pack being connected so that the
            # `component_ref`s in it resolve: the `resolved` action below turns
            # them into component_library ids, and inserting an AWS template
            # without the AWS pack yields components that point at nothing.
            #
            # A template pack ships no components at all — it is worksheets, not
            # a technology domain — so nothing in its templates can fail to
            # resolve and there is nothing for a connection to supply. Gating
            # those too would make a facilitator connect a STRIDE worksheet to
            # their threat model as though it described their stack.
            qs = qs.filter(
                Q(source_pack_id__in=connected_pack_ids)
                | Q(source_pack__isnull=True)
                | Q(source_pack__pack_type=LibraryPack.PackType.TEMPLATE)
            )
        return qs

    @action(detail=True, methods=["get"])
    def resolved(self, request, pk=None):
        """
        Get template with resolved component_refs.

        Returns the template's canvas_data with component_ref values resolved
        to actual component_library_id values for nodes that reference components.
        """
        from apps.systems.models import ComponentLibrary

        template = self.get_object()
        canvas_data = normalize_canvas(template.canvas_data)

        source_pack = template.source_pack

        resolved_data = {
            "nodes": [],
            "edges": canvas_data.get("edges", []),
        }

        resolution_results = []

        for node in canvas_data.get("nodes", []):
            resolved_node = {**node}
            node_data = node.get("data", {})
            component_ref = node_data.get("component_ref")

            if component_ref:
                component_library = None

                if source_pack:
                    qualified_slug = f"{source_pack.slug}/{component_ref}"
                    component_library = ComponentLibrary.objects.filter(
                        qualified_slug=qualified_slug,
                    ).first()

                if not component_library and "/" in component_ref:
                    component_library = ComponentLibrary.objects.filter(
                        qualified_slug=component_ref,
                    ).first()

                if component_library:
                    resolved_node["data"] = {
                        **node_data,
                        "component_library_id": component_library.id,
                        "component_library_name": component_library.name,
                    }
                    resolution_results.append(
                        {
                            "node_id": node.get("id"),
                            "component_ref": component_ref,
                            "resolved": True,
                            "component_library_id": component_library.id,
                            "component_library_name": component_library.name,
                        }
                    )
                else:
                    resolution_results.append(
                        {
                            "node_id": node.get("id"),
                            "component_ref": component_ref,
                            "resolved": False,
                            "error": f"Component not found: {component_ref}",
                        }
                    )

            resolved_data["nodes"].append(resolved_node)

        return Response(
            {
                "id": template.id,
                "name": template.name,
                "description": template.description,
                "category": template.category,
                "diagramType": template.diagram_type,
                "canvasData": resolved_data,
                "sourcePackId": source_pack.id if source_pack else None,
                "sourcePackName": source_pack.name if source_pack else None,
                "resolutionResults": resolution_results,
                "allResolved": all(
                    r.get("resolved", False) for r in resolution_results if r
                ),
            }
        )
