"""
Views for packs app.
"""

from django.db import transaction
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from apps.core.permissions import IsSecurityTeam
from apps.diagrams.models import DFDTemplatesLibrary

from .catalog import CatalogPackError, catalog_source
from .models import LibraryPack
from .serializers import (
    LibraryPackDetailSerializer,
    LibraryPackListSerializer,
)
from .services import (
    ValidationResult,
    discover_available_packs,
    get_available_overlays_for_pack,
    get_pack_preview_from_database,
    get_pack_preview_from_source,
    import_pack_with_dependencies,
    open_discovered_pack,
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
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
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
            "pack": LibraryPackDetailSerializer(
                pack, context={"request": request}
            ).data,
            "dependencies": dependencies,
            "missing_dependencies": missing_dependencies,
            "all_satisfied": len(missing_dependencies) == 0,
        }

        return Response(response_data)

    @action(detail=False, methods=["get"])
    def available_from_source(self, request):
        """
        List packs that can be imported: bundled or catalog.

        Bundled packs are the demo packs on this server's disk. Catalog packs
        come from the pack catalog (settings.PACK_CATALOG_URL); listing them
        downloads only catalog.json. Each pack has a `source` of "bundled" or
        "catalog" and says whether it is in the database and if the versions
        differ. `catalog_enabled` is false when the catalog is turned off,
        `catalog_available` false when it could not be fetched, and
        `catalog_release` names the release listed.
        """
        packs, catalog_result = discover_available_packs()
        source = catalog_source(release=catalog_result.release)
        return Response(
            {
                "catalog_enabled": catalog_result.enabled,
                "catalog_available": catalog_result.available,
                "catalog_release": catalog_result.release,
                # Where the catalog packs come from: "precogly/library-packs"
                # with links to the release and its packs folder, or the host
                # of a self-hosted catalog with no links.
                "catalog_source_name": source.name if source else "",
                "catalog_release_url": source.release_url if source else "",
                "catalog_packs_url": source.packs_url if source else "",
                "packs": [p.to_dict() for p in packs],
                "total": len(packs),
                "in_database": sum(1 for p in packs if p.is_in_database),
                "needs_update": sum(
                    1
                    for p in packs
                    if p.is_in_database and p.database_version != p.version
                ),
            }
        )

    @action(
        detail=False,
        methods=["post"],
        permission_classes=[IsAuthenticated, IsSecurityTeam],
    )
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

        return Response(
            {
                "results": [r.to_dict() for r in results],
                "summary": {
                    "total": len(results),
                    "successful": len(successful),
                    "failed": len(failed),
                },
                "message": f"Synced {len(successful)} packs, {len(failed)} failed",
            }
        )

    @action(
        detail=False,
        methods=["post"],
        permission_classes=[IsAuthenticated, IsSecurityTeam],
    )
    def import_single(self, request):
        """
        Import a bundled or catalog pack by slug, its missing dependencies first.

        Dependencies are imported with all their overlays and never with
        "Import anyway". When one fails, the response is 400 (or 502 when a
        download failed) with `failed_dependency`, `dependencies_imported` and
        `not_imported`, and the requested pack is not imported.

        Provide the pack slug in the request body:
        {"slug": "aws-technologies", "force": false, "selectedOverlays": ["owasp-2021", "nist-csf"]}

        The selectedOverlays field is optional:
        - If omitted (null/undefined), all overlays will be loaded
        - If empty list [], no overlays will be loaded
        - If list of framework IDs, only those overlays will be loaded
        """
        slug = request.data.get("slug")
        force = request.data.get("force", False)
        selected_overlays = request.data.get(
            "selected_overlays"
        )  # camelCase auto-converted by middleware
        # "Import anyway" accepts warnings only; errors always refuse (S2).
        accept_warnings = bool(request.data.get("skip_validation", False))

        if not slug:
            return Response(
                {"error": "Pack slug is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        outcome = import_pack_with_dependencies(
            slug,
            force=force,
            selected_overlays=selected_overlays,
            accept_warnings=accept_warnings,
        )
        progress = {
            "dependencies_imported": outcome.dependencies_imported,
        }
        if outcome.status != "imported":
            progress["not_imported"] = outcome.not_imported

        if outcome.status == "not_found":
            return Response(
                {"error": outcome.message}, status=status.HTTP_404_NOT_FOUND
            )
        if outcome.status == "cycle":
            return Response(
                {"error": outcome.message}, status=status.HTTP_400_BAD_REQUEST
            )
        if outcome.status == "download_failed":
            return Response(
                {
                    "error": outcome.message,
                    "failed_dependency": outcome.failed_dependency,
                    **progress,
                },
                status=status.HTTP_502_BAD_GATEWAY,
            )
        if outcome.status == "dependency_failed":
            # Never 422: "Import anyway" must not be offered for a dependency.
            # `validation` only when the dependency failed validation; when it
            # validated but its import failed, the import's own message goes in
            # `error`, since the page reads `validation` as a validation result.
            failed_validation = isinstance(outcome.result, ValidationResult)
            error_message = outcome.message
            if not failed_validation and outcome.result.message:
                error_message = f"{outcome.message} {outcome.result.message}"
            return Response(
                {
                    "error": error_message,
                    "failed_dependency": outcome.failed_dependency,
                    "validation": outcome.result.to_dict()
                    if failed_validation
                    else None,
                    **progress,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        result = outcome.result
        if isinstance(result, ValidationResult):
            if not result.success:
                # Errors block import entirely
                return Response(
                    {**result.to_dict(), **progress},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            # Warnings only: return 422 so frontend can show "Import Anyway" dialog
            return Response({**result.to_dict(), **progress}, status=422)

        if result.success:
            # Connected to every threat model by import_pack_with_dependencies.
            return Response(
                {**result.to_dict(), **progress}, status=status.HTTP_201_CREATED
            )
        return Response(
            {**result.to_dict(), **progress}, status=status.HTTP_400_BAD_REQUEST
        )

    @action(detail=True, methods=["get"])
    def preview(self, request, pk=None):
        """
        Get full pack contents for preview (database packs).

        The contents come from the pack's files: bundled on this server, or
        downloaded from the pack catalog. Returns pack metadata along with all
        components, threats, and countermeasures; 404 when neither has the
        pack; 502 when a catalog download fails.
        """
        pack = self.get_object()
        try:
            preview_data = get_pack_preview_from_database(pack)
        except CatalogPackError as error:
            return _download_failed(error)
        if preview_data is None:
            # Imported earlier, but its files are no longer on this server (for
            # example a pack that moved to precogly/library-packs).
            return Response(
                {
                    "error": f"Source files for pack '{pack.slug}' are not "
                    "available on this server"
                },
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(preview_data)

    @action(detail=False, methods=["get"])
    def preview_from_source(self, request):
        """
        Get full pack contents for preview (bundled or catalog packs by path).

        Query parameters:
            path: The pack's path as the pack list gives it
                  (e.g. "demo-threat-libraries/demo-aws", "threat-libraries/azure")

        Returns pack metadata along with all components, threats, and
        countermeasures. A catalog pack is downloaded for the request; 502 when
        that fails.
        """
        pack_path = request.query_params.get("path")

        if not pack_path:
            return Response(
                {"error": "Pack path is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            preview_data = get_pack_preview_from_source(pack_path)
        except CatalogPackError as error:
            return _download_failed(error)

        if not preview_data:
            return Response(
                {
                    "error": f"Pack at '{pack_path}' not found among bundled or catalog packs"
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        return Response(preview_data)

    @action(detail=False, methods=["get"])
    def available_overlays(self, request):
        """
        Get available framework overlays for a bundled or catalog pack before
        installation.

        Query parameters:
            path: The pack's path as the pack list gives it
                  (e.g. "demo-threat-libraries/demo-aws", "threat-libraries/azure")

        Returns list of overlays with framework_id, framework_name, mapping_count,
        and whether the framework is installed. A catalog pack is downloaded for
        the request; 502 when that fails.
        """
        pack_path = request.query_params.get("path")

        if not pack_path:
            return Response(
                {"error": "Pack path is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            overlays = get_available_overlays_for_pack(pack_path)
        except CatalogPackError as error:
            return _download_failed(error)

        return Response(
            {
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
            }
        )

    @action(
        detail=False,
        methods=["post"],
        permission_classes=[IsAuthenticated, IsSecurityTeam],
    )
    def validate(self, request):
        """
        Validate a bundled or catalog pack's references without importing (dry-run).

        Provide the pack slug in the request body:
        {"slug": "aws-technologies"}

        Returns validation results including any reference errors, plus
        `pending_dependencies`: dependencies that are listed but not imported
        yet, which import brings in first. 502 when a catalog download fails.
        """
        slug = request.data.get("slug")

        if not slug:
            return Response(
                {"error": "Pack slug is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Find the pack among bundled and catalog packs
        packs, catalog_result = discover_available_packs()
        pack_info = next((p for p in packs if p.slug == slug), None)

        if not pack_info:
            return Response(
                {"error": f"Pack '{slug}' not found among bundled or catalog packs"},
                status=status.HTTP_404_NOT_FOUND,
            )

        try:
            with open_discovered_pack(pack_info, catalog_result) as pack_dir:
                result = validate_pack(pack_dir)
        except CatalogPackError as error:
            return _download_failed(error)

        # A catalog pack's catalog dependencies are on neither disk nor in the
        # database until imported, so validate_pack reports them as not found.
        # Import brings them in first; this list lets the page say so.
        listed_slugs = {listed.slug for listed in packs}
        response_body = result.to_dict()
        response_body["pending_dependencies"] = [
            dependency["slug"]
            for dependency in pack_info.depends_on
            if dependency["slug"] in listed_slugs and not dependency["is_imported"]
        ]
        return Response(response_body)

    @action(
        detail=True,
        methods=["delete"],
        permission_classes=[IsAuthenticated, IsSecurityTeam],
    )
    def unimport(self, request, pk=None):
        """
        Unimport a pack by deleting all its library items and the pack record.

        This will:
        1. Delete all ComponentLibrary entries from this pack
        2. Delete all ThreatLibrary entries from this pack
        3. Delete all CountermeasureLibrary entries from this pack
        4. Delete the LibraryPack record itself

        Note: Instances (InstanceThreat targets, etc.) that reference the deleted
        library items will have their library FK set to NULL but remain intact
        with their copied metadata.

        Query parameters:
            dry_run: If "true", returns what would be deleted without actually deleting
        """
        from apps.compliance.models import StandardFramework
        from apps.systems.models import ComponentLibrary
        from apps.threats.models import (
            CountermeasureLibrary,
            ExternalTaxonomy,
            ThreatLibrary,
        )

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
        countermeasure_count = CountermeasureLibrary.objects.filter(
            source_pack=pack
        ).count()
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


def _download_failed(error: CatalogPackError) -> Response:
    """A catalog pack could not be downloaded or failed its checks."""
    return Response({"error": str(error)}, status=status.HTTP_502_BAD_GATEWAY)
