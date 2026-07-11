"""
Views for packs app.
"""

from pathlib import Path

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from django.db import transaction

from apps.core.permissions import IsSecurityTeam
from apps.diagrams.models import DFDTemplatesLibrary

from .models import LibraryPack
from .serializers import (
    LibraryPackDetailSerializer,
    LibraryPackListSerializer,
)
from .services import (
    ValidationResult,
    discover_packs_from_source,
    get_available_overlays_for_pack,
    get_pack_preview_from_database,
    get_pack_preview_from_source,
    import_pack_from_path,
    sync_all_packs_from_source,
    validate_pack,
)


class LibraryPackViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for browsing and installing library packs.

    list: Browse all published packs
    retrieve: Get pack details
    install: Install a pack for the user's organization
    check_dependencies: Check if dependencies are satisfied
    """

    permission_classes = [IsAuthenticated]
    pagination_class = None
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["pack_type"]
    search_fields = ["name", "description", "author", "tags"]
    ordering_fields = ["name", "created_at"]
    ordering = ["name"]

    def get_queryset(self):
        """Return all packs, optionally filtered by tag."""
        queryset = LibraryPack.objects.all()

        # Filter by tag if provided
        tag = self.request.query_params.get("tag")
        if tag:
            queryset = queryset.filter(tags__contains=[tag])

        return queryset.prefetch_related("dependencies__depends_on_pack")

    def get_serializer_class(self):
        """Return appropriate serializer."""
        if self.action == "list":
            return LibraryPackListSerializer
        return LibraryPackDetailSerializer

    @action(detail=True, methods=["get"])
    def check_dependencies(self, request, pk=None):
        """
        Check if all dependencies are satisfied for import.
        Returns the dependency tree and any missing dependencies.
        """
        pack = self.get_object()

        # Get imported packs (packs in database)
        imported_pack_ids = set(LibraryPack.objects.values_list("id", flat=True))

        # Build dependency tree
        dependencies = []
        missing_dependencies = []

        for dep in pack.dependencies.all():
            dep_pack = dep.depends_on_pack
            is_imported = dep_pack.id in imported_pack_ids

            dependencies.append(
                {
                    "pack_id": dep_pack.id,
                    "slug": dep_pack.slug,
                    "name": dep_pack.name,
                    "version": dep_pack.version,
                    "is_imported": is_imported,
                }
            )

            if not is_imported:
                missing_dependencies.append(dep_pack.slug)

        response_data = {
            "pack": LibraryPackDetailSerializer(pack, context={"request": request}).data,
            "dependencies": dependencies,
            "missing_dependencies": missing_dependencies,
            "all_satisfied": len(missing_dependencies) == 0,
        }

        return Response(response_data)


    @action(detail=False, methods=["get"])
    def available_from_source(self, request):
        """
        List packs available in the libraries folder.

        Returns packs found in libraries/packs that can be synced to the database.
        Includes information about whether each pack is already in the database
        and if it needs updating.
        """
        packs = discover_packs_from_source()
        return Response({
            "packs": [p.to_dict() for p in packs],
            "total": len(packs),
            "in_database": sum(1 for p in packs if p.is_in_database),
            "needs_update": sum(1 for p in packs if p.is_in_database and p.database_version != p.version),
        })

    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated, IsSecurityTeam])
    def sync_from_source(self, request):
        """
        Sync packs from the libraries folder to the database.

        This imports/updates all packs found in the libraries/packs directory.
        Set force=true to reimport all packs even if they already exist.
        """
        force = request.data.get("force", False)

        results = sync_all_packs_from_source(force=force)

        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success]

        # Auto-connect all successfully synced packs to all threat models
        if successful:
            from apps.threat_models.models import ThreatModel, ThreatModelLibraryPack

            synced_slugs = [r.pack_slug for r in successful]
            synced_packs = LibraryPack.objects.filter(slug__in=synced_slugs)
            threat_models = ThreatModel.objects.all()
            associations = [
                ThreatModelLibraryPack(threat_model=tm, library_pack=pack)
                for tm in threat_models
                for pack in synced_packs
            ]
            if associations:
                ThreatModelLibraryPack.objects.bulk_create(
                    associations, ignore_conflicts=True
                )

        return Response({
            "results": [r.to_dict() for r in results],
            "summary": {
                "total": len(results),
                "successful": len(successful),
                "failed": len(failed),
            },
            "message": f"Synced {len(successful)} packs, {len(failed)} failed",
        })

    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated, IsSecurityTeam])
    def import_single(self, request):
        """
        Import a single pack from the libraries folder by slug.

        Provide the pack slug in the request body:
        {"slug": "aws-technologies", "force": false, "selectedOverlays": ["owasp-2021", "nist-csf"]}

        The selectedOverlays field is optional:
        - If omitted (null/undefined), all overlays will be loaded
        - If empty list [], no overlays will be loaded
        - If list of framework IDs, only those overlays will be loaded
        """
        slug = request.data.get("slug")
        force = request.data.get("force", False)
        selected_overlays = request.data.get("selected_overlays")  # camelCase auto-converted by middleware
        skip_validation = request.data.get("skip_validation", False)

        if not slug:
            return Response(
                {"error": "Pack slug is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Find the pack in available sources
        packs = discover_packs_from_source()
        pack_info = next((p for p in packs if p.slug == slug), None)

        if not pack_info:
            return Response(
                {"error": f"Pack '{slug}' not found in libraries folder"},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Import the pack
        result = import_pack_from_path(
            Path(pack_info.path),
            force=force,
            selected_overlays=selected_overlays,
            skip_validation=skip_validation,
        )

        # Handle ValidationResult (returned when validation finds issues)
        if isinstance(result, ValidationResult):
            if not result.success:
                # Errors block import entirely
                return Response(result.to_dict(), status=status.HTTP_400_BAD_REQUEST)
            # Warnings only: return 422 so frontend can show "Import Anyway" dialog
            return Response(result.to_dict(), status=422)

        if result.success:
            # Auto-connect to all existing threat models
            from apps.threat_models.models import ThreatModel, ThreatModelLibraryPack

            library_pack = LibraryPack.objects.filter(slug=slug).first()
            if library_pack:
                threat_models = ThreatModel.objects.all()
                ThreatModelLibraryPack.objects.bulk_create(
                    [
                        ThreatModelLibraryPack(
                            threat_model=tm, library_pack=library_pack
                        )
                        for tm in threat_models
                    ],
                    ignore_conflicts=True,
                )
            return Response(result.to_dict(), status=status.HTTP_201_CREATED)
        else:
            return Response(result.to_dict(), status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=["get"])
    def preview(self, request, pk=None):
        """
        Get full pack contents for preview (database packs).

        Returns pack metadata along with all components, threats, and countermeasures.
        """
        pack = self.get_object()
        preview_data = get_pack_preview_from_database(pack)
        if preview_data is None:
            return Response(
                {"detail": "Pack source files not found on disk."},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(preview_data)

    @action(detail=False, methods=["get"])
    def preview_from_source(self, request):
        """
        Get full pack contents for preview (source packs by path).

        Query parameters:
            path: The pack's relative path from libraries/packs root
                  (e.g. "demo/aws-mini", "standards/nist-csf")

        Returns pack metadata along with all components, threats, and countermeasures.
        """
        pack_path = request.query_params.get("path")

        if not pack_path:
            return Response(
                {"error": "Pack path is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        preview_data = get_pack_preview_from_source(pack_path)

        if not preview_data:
            return Response(
                {"error": f"Pack at '{pack_path}' not found in libraries folder"},
                status=status.HTTP_404_NOT_FOUND,
            )

        return Response(preview_data)

    @action(detail=False, methods=["get"])
    def available_overlays(self, request):
        """
        Get available framework overlays for a pack before installation.

        Query parameters:
            path: The pack's relative path from libraries/packs root
                  (e.g. "demo/aws-mini", "standards/nist-csf")

        Returns list of overlays with framework_id, framework_name, mapping_count,
        and whether the framework is installed.
        """
        pack_path = request.query_params.get("path")

        if not pack_path:
            return Response(
                {"error": "Pack path is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        overlays = get_available_overlays_for_pack(pack_path)

        return Response({
            "overlays": [
                {
                    "framework_id": o.framework_id,
                    "framework_name": o.framework_name,
                    "mapping_count": o.mapping_count,
                    "framework_exists": o.framework_exists,
                }
                for o in overlays
            ],
            "total": len(overlays),
            "available_count": sum(1 for o in overlays if o.framework_exists),
        })

    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated, IsSecurityTeam])
    def validate(self, request):
        """
        Validate a pack's references without importing (dry-run).

        Provide the pack slug in the request body:
        {"slug": "aws-technologies"}

        Returns validation results including any reference errors.
        """
        slug = request.data.get("slug")

        if not slug:
            return Response(
                {"error": "Pack slug is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Find the pack in available sources
        packs = discover_packs_from_source()
        pack_info = next((p for p in packs if p.slug == slug), None)

        if not pack_info:
            return Response(
                {"error": f"Pack '{slug}' not found in libraries folder"},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Run validation
        result = validate_pack(Path(pack_info.path))

        return Response(result.to_dict())

    @action(detail=True, methods=["delete"], permission_classes=[IsAuthenticated, IsSecurityTeam])
    def unimport(self, request, pk=None):
        """
        Unimport a pack by deleting all its library items and the pack record.

        This will:
        1. Delete all ComponentLibrary entries from this pack
        2. Delete all ThreatLibrary entries from this pack
        3. Delete all CountermeasureLibrary entries from this pack
        4. Delete the LibraryPack record itself

        Note: Instances (ComponentInstanceThreat, etc.) that reference the deleted
        library items will have their library FK set to NULL but remain intact
        with their copied metadata.

        Query parameters:
            dry_run: If "true", returns what would be deleted without actually deleting
        """
        from apps.compliance.models import StandardFramework
        from apps.systems.models import ComponentLibrary
        from apps.threats.models import CountermeasureLibrary, ExternalTaxonomy, ThreatLibrary

        pack = self.get_object()
        dry_run = request.query_params.get("dry_run", "false").lower() == "true"

        # Check if any other packs depend on this pack
        dependent_packs = list(
            pack.dependents.all()
            .select_related("pack")
            .values_list("pack__slug", flat=True)
        )
        if dependent_packs:
            return Response(
                {
                    "error": "Cannot unimport: other packs depend on this one",
                    "dependent_packs": dependent_packs,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Count what will be deleted
        component_count = ComponentLibrary.objects.filter(source_pack=pack).count()
        threat_count = ThreatLibrary.objects.filter(source_pack=pack).count()
        countermeasure_count = CountermeasureLibrary.objects.filter(source_pack=pack).count()
        template_count = DFDTemplatesLibrary.objects.filter(source_pack=pack).count()
        taxonomy_count = ExternalTaxonomy.objects.filter(source_pack=pack).count()
        framework_count = StandardFramework.objects.filter(source_pack=pack).count()

        summary = {
            "pack": {
                "id": pack.id,
                "slug": pack.slug,
                "name": pack.name,
                "version": pack.version,
            },
            "to_delete": {
                "components": component_count,
                "threats": threat_count,
                "countermeasures": countermeasure_count,
                "templates": template_count,
                "taxonomies": taxonomy_count,
                "frameworks": framework_count,
            },
            "dry_run": dry_run,
        }

        if dry_run:
            summary["message"] = "Dry run - no changes made"
            return Response(summary)

        # Perform the deletion within a transaction
        with transaction.atomic():
            # Delete library items (order matters for FK constraints)
            # Countermeasures reference threats via M2M, so delete them first
            CountermeasureLibrary.objects.filter(source_pack=pack).delete()
            # Threats can now be deleted
            ThreatLibrary.objects.filter(source_pack=pack).delete()
            # Components can now be deleted (ComponentLibraryThreat cascades)
            ComponentLibrary.objects.filter(source_pack=pack).delete()
            # Delete DFD templates from this pack
            DFDTemplatesLibrary.objects.filter(source_pack=pack).delete()
            # Delete taxonomy and compliance data from this pack
            ExternalTaxonomy.objects.filter(source_pack=pack).delete()
            StandardFramework.objects.filter(source_pack=pack).delete()
            # Finally delete the pack itself
            pack.delete()

        summary["message"] = "Pack unimported successfully"
        summary["deleted"] = True

        return Response(summary)
