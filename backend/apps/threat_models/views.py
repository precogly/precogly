"""
Views for threat_models app.
"""

import json
import logging

from django.db import transaction
from django.db.models import Q
from django.http import JsonResponse
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.parsers import JSONParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from apps.core.permissions import CanWrite, IsSecurityTeam

from .models import (
    Assumption,
    Blueprint,
    BusinessObjective,
    OutOfScopeItem,
    ThreatModel,
    ThreatModelLibraryPack,
    ThreatModelReferenceImage,
    ThreatModelRelationship,
    UseCase,
)
from .relationships import (
    RELATION_TYPES,
    RelationshipError,
    add_relationship,
    relationship_payload,
    remove_relationship,
)
from .review import approve, mark_reviewed, review_state, revoke_approval
from .serializers import (
    AssumptionSerializer,
    BlueprintSerializer,
    BusinessObjectiveSerializer,
    OutOfScopeItemSerializer,
    ThreatModelCreateSerializer,
    ThreatModelListSerializer,
    ThreatModelReferenceImageSerializer,
    ThreatModelReferenceImageUploadSerializer,
    ThreatModelSerializer,
    UseCaseSerializer,
)

logger = logging.getLogger(__name__)


class ThreatModelViewSet(viewsets.ModelViewSet):
    """ViewSet for ThreatModel CRUD operations."""

    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_fields = ["organization"]
    search_fields = ["name", "description"]
    ordering_fields = ["name", "created_at", "updated_at"]
    ordering = ["-updated_at"]

    def get_queryset(self):
        """Filter threat models by user's team memberships within their orgs.
        Security team members see all threat models in their org.

        Who may read what is `ThreatModelQuerySet.visible_to`, which the MCP endpoint
        calls as well — it has no request and no permission classes, so the rule has to
        live somewhere both can reach.
        """
        queryset = ThreatModel.objects.visible_to(self.request.user).select_related(
            "created_by", "organization", "owning_team", "owning_team__business_unit"
        )

        # Optional further filter by specific team
        owning_team_id = self.request.query_params.get("owning_team")
        if owning_team_id:
            queryset = queryset.filter(
                Q(owning_team_id=owning_team_id) | Q(owning_team__isnull=True)
            )

        return queryset

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == "list":
            return ThreatModelListSerializer
        elif self.action == "create":
            return ThreatModelCreateSerializer
        return ThreatModelSerializer

    def perform_create(self, serializer):
        """Set created_by to current user."""
        serializer.save(created_by=self.request.user)

    def perform_destroy(self, instance):
        """Delete the threat model; blueprints, rows, threats and DFDs cascade."""
        with transaction.atomic():
            instance.delete()

    @action(detail=True, methods=["get"])
    def delete_preview(self, request, pk=None):
        """
        Preview what will be deleted when this threat model is deleted.

        Returns information about DFDs, components, threats, and countermeasures
        that will be deleted.
        """
        from apps.threats.models import InstanceCountermeasure, InstanceThreat

        threat_model = self.get_object()

        dfds_to_delete = [
            {
                "id": str(dfd.id),
                "name": dfd.name,
                "node_count": len((dfd.canvas_data or {}).get("nodes", [])),
            }
            for dfd in threat_model.dfds.all()
        ]
        component_ids_to_delete = set(
            threat_model.components.values_list("id", flat=True)
        )
        dataflow_count = threat_model.flows.count()
        threat_count = InstanceThreat.objects.filter(threat_model=threat_model).count()

        # Count all countermeasures in this threat model
        countermeasure_count = InstanceCountermeasure.objects.filter(
            threat_model=threat_model
        ).count()

        return Response(
            {
                "threat_model": {
                    "id": str(threat_model.id),
                    "name": threat_model.name,
                },
                "dfds_to_delete": dfds_to_delete,
                "total_dfds": len(dfds_to_delete),
                "components_to_delete": len(component_ids_to_delete),
                "flows_to_delete": dataflow_count,
                "threats_to_delete": threat_count,
                "countermeasures_to_delete": countermeasure_count,
            }
        )

    @action(detail=True, methods=["post"])
    def remove_pack(self, request, pk=None):
        """Remove a pack from this threat model."""
        from apps.packs.models import LibraryPack, LibraryPackDependency

        threat_model = self.get_object()
        pack_id = request.data.get("pack_id")

        if not pack_id:
            return Response(
                {"error": "pack_id is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        deleted, _ = ThreatModelLibraryPack.objects.filter(
            threat_model=threat_model, library_pack_id=pack_id
        ).delete()

        if not deleted:
            return Response(
                {"error": "Pack not associated with this threat model"},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Build dependency warnings
        dependency_warnings = []
        try:
            removed_pack = LibraryPack.objects.get(id=pack_id)
        except LibraryPack.DoesNotExist:
            removed_pack = None

        if removed_pack:
            connected_pack_ids = set(
                ThreatModelLibraryPack.objects.filter(
                    threat_model=threat_model
                ).values_list("library_pack_id", flat=True)
            )

            # Packs that depend on the removed pack
            dependent_deps = LibraryPackDependency.objects.filter(
                depends_on_pack=removed_pack,
                pack_id__in=connected_pack_ids,
            ).select_related("pack")
            for dep in dependent_deps:
                dependency_warnings.append(
                    {
                        "pack": dep.pack.name,
                        "message": (
                            f"{dep.pack.name} (still connected) depends on {removed_pack.name}. "
                            f"Threat and countermeasure generation from {removed_pack.name} "
                            f"will no longer apply to this threat model."
                        ),
                    }
                )

            # Packs the removed pack depends on: check if any other connected
            # pack also depends on them
            child_deps = LibraryPackDependency.objects.filter(
                pack=removed_pack,
            ).select_related("depends_on_pack")
            for dep in child_deps:
                child_pack = dep.depends_on_pack
                other_dependents = LibraryPackDependency.objects.filter(
                    depends_on_pack=child_pack,
                    pack_id__in=connected_pack_ids,
                ).exists()
                if not other_dependents:
                    dependency_warnings.append(
                        {
                            "pack": child_pack.name,
                            "message": (
                                f"{child_pack.name} was a dependency of {removed_pack.name} "
                                f"and no other connected pack uses it. "
                                f"Consider removing it too if it is no longer needed."
                            ),
                        }
                    )

        return Response(
            {
                "status": "pack removed",
                "dependency_warnings": dependency_warnings,
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["post"])
    def add_pack(self, request, pk=None):
        """Add a pack to this threat model.

        After connecting the pack, scans existing components on the TM
        whose component_library belongs to the newly connected pack and
        generates threats and countermeasures for each.
        """
        from apps.packs.models import LibraryPack
        from apps.systems.models import OrgsystemComponent
        from apps.threats.services import ensure_generated_threats

        threat_model = self.get_object()
        pack_id = request.data.get("pack_id")

        if not pack_id:
            return Response(
                {"error": "pack_id is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            library_pack = LibraryPack.objects.get(id=pack_id)
        except LibraryPack.DoesNotExist:
            return Response(
                {"error": "Pack not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        _, created = ThreatModelLibraryPack.objects.get_or_create(
            threat_model=threat_model, library_pack=library_pack
        )

        # Auto-materialize threats for existing components from this pack
        threats_created = 0
        components_matched = 0
        if created:
            matching_components = OrgsystemComponent.objects.filter(
                blueprint__threat_model=threat_model,
                component_library__source_pack=library_pack,
            )
            with transaction.atomic():
                for component in matching_components:
                    components_matched += 1
                    threats_created += ensure_generated_threats(component)

        return Response(
            {
                "status": "pack added",
                "components_matched": components_matched,
                "threats_created": threats_created,
            },
            status=status.HTTP_200_OK,
        )

    @staticmethod
    def _relation_type_from(request):
        """The ``relation_type`` of a relationship request (default
        ``related_to``), or ``None`` when the value is not a known type."""
        relation_type = request.data.get(
            "relation_type", ThreatModelRelationship.RelationType.RELATED_TO
        )
        if relation_type not in RELATION_TYPES:
            return None
        return relation_type

    @action(detail=True, methods=["post"])
    def add_referenced_model(self, request, pk=None):
        """Add a relationship from this model to ``target_model_id`` of type
        ``relation_type`` (plan J15). The rules live in ``relationships.py``."""
        threat_model = self.get_object()
        target_model_id = request.data.get("target_model_id")

        if not target_model_id:
            return Response(
                {"error": "target_model_id is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        relation_type = self._relation_type_from(request)
        if relation_type is None:
            return Response(
                {"error": "relation_type must be one of " + ", ".join(RELATION_TYPES)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if str(target_model_id) == str(threat_model.id):
            return Response(
                {"error": "A threat model cannot reference itself"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            target_model = ThreatModel.objects.get(
                id=target_model_id,
                organization=threat_model.organization,
            )
        except ThreatModel.DoesNotExist:
            return Response(
                {"error": "Target threat model not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        try:
            relationship, created = add_relationship(
                threat_model, target_model, relation_type
            )
        except RelationshipError as error:
            return Response({"error": str(error)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(
            {
                "status": "reference added",
                "created": created,
                "relationship": relationship_payload(relationship, threat_model),
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["post"])
    def remove_referenced_model(self, request, pk=None):
        """Remove exactly the relationship ``this relation_type target``."""
        threat_model = self.get_object()
        target_model_id = request.data.get("target_model_id")

        if not target_model_id:
            return Response(
                {"error": "target_model_id is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        relation_type = self._relation_type_from(request)
        if relation_type is None:
            return Response(
                {"error": "relation_type must be one of " + ", ".join(RELATION_TYPES)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        deleted = remove_relationship(threat_model, target_model_id, relation_type)

        if deleted:
            return Response({"status": "reference removed"}, status=status.HTTP_200_OK)
        return Response(
            {"error": "Reference not found"},
            status=status.HTTP_404_NOT_FOUND,
        )

    @action(detail=True, methods=["post"], url_path="generate-threats")
    def generate_threats(self, request, pk=None):
        """Add the library threats every component and flow of the model is
        missing (plan L7). A generated threat deleted earlier comes back."""
        from apps.threats.services import ensure_generated_threats

        threat_model = self.get_object()
        created = 0
        targets = 0
        with transaction.atomic():
            for target in [
                *threat_model.components.select_related("component_library"),
                *threat_model.flows.all(),
            ]:
                targets += 1
                created += ensure_generated_threats(target)
        return Response({"created": created, "targets": targets})

    @action(detail=True, methods=["get"], url_path="countermeasures-in-use")
    def countermeasures_in_use(self, request, pk=None):
        """List all countermeasure instances active in this threat model."""
        from apps.threats.models import InstanceCountermeasure

        from .analysis_service import serialize_targets, threat_display_name

        threat_model = self.get_object()
        countermeasures = (
            InstanceCountermeasure.objects.filter(threat_model=threat_model)
            .select_related("countermeasure_library", "assigned_owner")
            .prefetch_related(
                "threat_links__threat__threat_library",
                "threat_links__threat__targets__component",
                "threat_links__threat__targets__flow__source_component",
                "threat_links__threat__targets__flow__dest_component",
                "threat_links__threat__targets__zone",
                "threat_links__threat__targets__boundary",
            )
        )

        result = []
        for cm in countermeasures:
            linked_threats = [
                {
                    "threat_id": link.threat.id,
                    "display_number": link.threat.display_number,
                    "threat_name": threat_display_name(link.threat),
                    "targets": serialize_targets(link.threat),
                }
                for link in cm.threat_links.all()
            ]
            result.append(
                {
                    "id": cm.id,
                    "countermeasure_name": (
                        cm.countermeasure_library.name
                        if cm.countermeasure_library
                        else None
                    )
                    or cm.countermeasure_name,
                    "countermeasure_library_id": cm.countermeasure_library_id,
                    "status": cm.status,
                    "assigned_owner_email": cm.assigned_owner.email
                    if cm.assigned_owner
                    else None,
                    "linked_threats": linked_threats,
                }
            )

        return Response(
            {
                "threat_model_id": str(threat_model.id),
                "countermeasures": result,
                "total_count": len(result),
            }
        )

    @action(detail=True, methods=["get"])
    def review(self, request, pk=None):
        """The derived approval state and the review row (section 4.8)."""
        threat_model = self.get_object()
        return Response(review_state(threat_model))

    @action(detail=True, methods=["post"], url_path="mark-reviewed")
    def mark_reviewed(self, request, pk=None):
        threat_model = self.get_object()
        mark_reviewed(threat_model, request.user)
        return Response(review_state(threat_model))

    @action(
        detail=True,
        methods=["post"],
        permission_classes=[IsAuthenticated, IsSecurityTeam],
    )
    def approve(self, request, pk=None):
        """Approve the model as it is now (Security Team only, D4)."""
        threat_model = self.get_object()
        approve(threat_model, request.user)
        return Response(review_state(threat_model))

    @action(
        detail=True,
        methods=["post"],
        url_path="revoke-approval",
        permission_classes=[IsAuthenticated, IsSecurityTeam],
    )
    def revoke_approval(self, request, pk=None):
        threat_model = self.get_object()
        revoke_approval(threat_model)
        return Response(review_state(threat_model))

    @action(detail=True, methods=["get"])
    def threats(self, request, pk=None):
        """Every threat of this model with its countermeasures.

        Built by ``analysis_service.build_threat_analysis``, which the shared
        magic-link page reads too, in its allow-listed form.
        """
        from .analysis_service import build_threat_analysis

        threat_model = self.get_object()
        return Response(build_threat_analysis(threat_model))

    @action(detail=True, methods=["get"])
    def report(self, request, pk=None):
        """Get complete report data for this threat model."""
        from .report_service import build_report_data

        threat_model = self.get_object()
        data = build_report_data(threat_model)
        return Response(data)

    @action(detail=True, methods=["get"])
    def compliance_drift(self, request, pk=None):
        """Check for compliance drift between instance and library mappings."""
        from apps.threat_models.compliance_service import check_compliance_drift

        threat_model = self.get_object()
        result = check_compliance_drift(threat_model)
        return Response(result)

    @action(detail=True, methods=["post"])
    def refresh_compliance(self, request, pk=None):
        """Sync instance compliance mappings with library sources."""
        from apps.threat_models.compliance_service import refresh_compliance_standards

        threat_model = self.get_object()
        result = refresh_compliance_standards(threat_model)
        return Response(result)

    @action(
        detail=False,
        methods=["post"],
        url_path="import/cyclonedx",
        parser_classes=[MultiPartParser, JSONParser],
    )
    def import_cyclonedx(self, request):
        """Import a CycloneDX 2.0 TM-BOM JSON file as a new threat model."""
        from .tmbom import TmBomAdapter, TmBomImportError

        first_membership = request.user.organization_memberships.first()
        if not first_membership:
            return Response(
                {"detail": "User has no organization membership."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        organization = first_membership.organization

        if "file" in request.FILES:
            uploaded_file = request.FILES["file"]
            try:
                json_data = json.loads(uploaded_file.read().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return Response(
                    {
                        "detail": (
                            "Could not parse the uploaded file as JSON. "
                            "Check that it is a valid JSON file and try again."
                        ),
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        elif request.content_type and "json" in request.content_type:
            json_data = request.data
        else:
            return Response(
                {
                    "detail": "Provide a JSON file upload (field: 'file') or a JSON body."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        adapter = TmBomAdapter()
        try:
            threat_model, summary = adapter.import_data(
                json_data, organization, request.user
            )
        except (TmBomImportError, ValidationError) as e:
            detail = str(e)
            if hasattr(e, "detail"):
                detail = (
                    e.detail.get("detail", str(e.detail))
                    if isinstance(e.detail, dict)
                    else str(e.detail)
                )
            return Response(
                {"detail": detail},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception:
            logger.exception("Unexpected error during CycloneDX import")
            return Response(
                {
                    "detail": (
                        "An unexpected error occurred during import. "
                        "This is likely a bug. Please try again or contact support."
                    ),
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {
                "threat_model": {
                    "id": str(threat_model.id),
                    "name": threat_model.name,
                },
                "summary": summary,
            },
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["get"], url_path="export/cyclonedx")
    def export_cyclonedx(self, request, pk=None):
        """Export a threat model as CycloneDX 2.0 TM-BOM JSON."""
        from .tmbom import TmBomAdapter

        threat_model = self.get_object()
        adapter = TmBomAdapter()
        export_data = adapter.export_data(threat_model)

        import re

        response = JsonResponse(export_data, json_dumps_params={"indent": 2})
        safe_name = re.sub(r"[^a-z0-9\-]", "-", threat_model.name.lower())
        safe_name = re.sub(r"-{2,}", "-", safe_name).strip("-")
        filename = f"{safe_name}-cyclonedx-tm-bom.cdx.json"
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response


class ThreatModelReferenceImageViewSet(viewsets.ModelViewSet):
    """ViewSet for managing threat model reference images."""

    permission_classes = [IsAuthenticated, CanWrite]
    serializer_class = ThreatModelReferenceImageSerializer

    def get_queryset(self):
        """Filter by user's organization access and specific threat model."""
        user = self.request.user
        user_orgs = user.organization_memberships.values_list(
            "organization_id", flat=True
        )

        queryset = ThreatModelReferenceImage.objects.filter(
            threat_model__organization_id__in=user_orgs
        ).select_related("threat_model", "uploaded_by")

        # Filter by threat_model if accessed via nested route
        threat_model_id = self.kwargs.get("threat_model_pk")
        if threat_model_id:
            queryset = queryset.filter(threat_model_id=threat_model_id)

        return queryset

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action in ["create", "upload_for_threat_model"]:
            return ThreatModelReferenceImageUploadSerializer
        return ThreatModelReferenceImageSerializer

    def perform_create(self, serializer):
        """Set uploaded_by to current user."""
        serializer.save(uploaded_by=self.request.user)

    @action(detail=False, methods=["post"], url_path="upload")
    def upload_for_threat_model(self, request, threat_model_pk=None):
        """Upload a reference image for a specific threat model."""
        from django.shortcuts import get_object_or_404

        threat_model = get_object_or_404(ThreatModel, pk=threat_model_pk)

        # Verify user has access to this threat model's organization
        user_orgs = request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        if threat_model.organization_id not in user_orgs:
            return Response(
                {"detail": "Not authorized"}, status=status.HTTP_403_FORBIDDEN
            )

        serializer = ThreatModelReferenceImageUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        image = serializer.save(
            threat_model=threat_model,
            uploaded_by=request.user,
        )

        return Response(
            ThreatModelReferenceImageSerializer(
                image, context={"request": request}
            ).data,
            status=status.HTTP_201_CREATED,
        )


class OutOfScopeItemViewSet(viewsets.ModelViewSet):
    """ViewSet for OutOfScopeItem CRUD, nested under threat models."""

    serializer_class = OutOfScopeItemSerializer
    permission_classes = [IsAuthenticated, CanWrite]

    def get_queryset(self):
        """Filter by threat model and user's organization."""
        user = self.request.user
        org_ids = user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return OutOfScopeItem.objects.filter(
            blueprint__threat_model_id=self.kwargs["threat_model_pk"],
            blueprint__threat_model__organization_id__in=org_ids,
        ).select_related("blueprint")

    def perform_create(self, serializer):
        """Place the item in the given blueprint of this model, else the default."""
        threat_model_id = self.kwargs["threat_model_pk"]
        blueprint = serializer.validated_data.get("blueprint")
        if blueprint is None:
            blueprint = (
                Blueprint.objects.filter(threat_model_id=threat_model_id)
                .order_by("display_order", "created_at", "id")
                .first()
            )
        elif str(blueprint.threat_model_id) != str(threat_model_id):
            raise ValidationError(
                {"blueprint": "The blueprint must belong to this threat model."}
            )
        serializer.save(blueprint=blueprint)


class _ThreatModelNestedViewSet(viewsets.ModelViewSet):
    """Rows nested under ``/api/threat-models/{id}/``: scoped to the caller's
    organizations; the model is passed to the serializer as ``threat_model``."""

    permission_classes = [IsAuthenticated, CanWrite]

    def _threat_model(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        threat_model = ThreatModel.objects.filter(
            id=self.kwargs["threat_model_pk"], organization_id__in=org_ids
        ).first()
        if threat_model is None:
            from rest_framework.exceptions import NotFound

            raise NotFound("Threat model not found")
        return threat_model

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["threat_model"] = self._threat_model()
        return context


class AssumptionViewSet(_ThreatModelNestedViewSet):
    """``/api/threat-models/{id}/assumptions/``; filter ``blueprint``."""

    serializer_class = AssumptionSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["blueprint", "validity", "topic"]

    def get_queryset(self):
        return (
            Assumption.objects.filter(blueprint__threat_model=self._threat_model())
            .select_related("owner", "blueprint")
            .prefetch_related("component_links__component")
        )

    def perform_create(self, serializer):
        self.check_object_permissions(self.request, self._threat_model())
        serializer.save()


class BusinessObjectiveViewSet(_ThreatModelNestedViewSet):
    """``/api/threat-models/{id}/business-objectives/``."""

    serializer_class = BusinessObjectiveSerializer
    pagination_class = None

    def get_queryset(self):
        return BusinessObjective.objects.filter(
            threat_model=self._threat_model()
        ).select_related("owner")

    def perform_create(self, serializer):
        threat_model = self._threat_model()
        self.check_object_permissions(self.request, threat_model)
        serializer.save(threat_model=threat_model)


class UseCaseViewSet(_ThreatModelNestedViewSet):
    """``/api/threat-models/{id}/use-cases/``: list, retrieve and delete only.

    Use cases are import and export only (plan J14); the model page shows them
    read-only with a delete action.
    """

    serializer_class = UseCaseSerializer
    pagination_class = None
    http_method_names = ["get", "delete", "head", "options"]

    def get_queryset(self):
        return UseCase.objects.filter(threat_model=self._threat_model())


class BlueprintViewSet(viewsets.ModelViewSet):
    """Blueprint CRUD, nested under a threat model.

    A model always keeps at least one blueprint. `delete_preview` says what a
    delete would take with it, since every structural row of the blueprint
    cascades and the threats on those rows go too.
    """

    serializer_class = BlueprintSerializer
    permission_classes = [IsAuthenticated, CanWrite]
    pagination_class = None

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return Blueprint.objects.filter(
            threat_model_id=self.kwargs["threat_model_pk"],
            threat_model__organization_id__in=org_ids,
        ).select_related("threat_model")

    def _threat_model(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        threat_model = ThreatModel.objects.filter(
            id=self.kwargs["threat_model_pk"], organization_id__in=org_ids
        ).first()
        if threat_model is None:
            from rest_framework.exceptions import NotFound

            raise NotFound("Threat model not found")
        return threat_model

    def perform_create(self, serializer):
        threat_model = self._threat_model()
        self.check_object_permissions(self.request, threat_model)
        serializer.save(threat_model=threat_model)

    def perform_destroy(self, instance):
        if (
            not Blueprint.objects.filter(threat_model_id=instance.threat_model_id)
            .exclude(id=instance.id)
            .exists()
        ):
            raise ValidationError(
                {"detail": "A threat model keeps at least one blueprint."}
            )
        with transaction.atomic():
            instance.delete()

    @action(detail=True, methods=["get"])
    def delete_preview(self, request, threat_model_pk=None, pk=None):
        """Counts of what deleting this blueprint removes."""
        from apps.threats.models import InstanceThreat

        blueprint = self.get_object()
        return Response(
            {
                "blueprint": {"id": blueprint.id, "name": blueprint.name},
                "is_last": not Blueprint.objects.filter(
                    threat_model_id=blueprint.threat_model_id
                )
                .exclude(id=blueprint.id)
                .exists(),
                "components": blueprint.components.count(),
                "flows": blueprint.flows.count(),
                "zones": blueprint.zones.count(),
                "boundaries": blueprint.boundaries.count(),
                "diagrams": blueprint.dfds.count(),
                "data_assets": blueprint.data_assets.count(),
                "out_of_scope_items": blueprint.out_of_scope_items.count(),
                # Scenarios whose only targets sit in this blueprint go with it;
                # the rest only lose targets.
                "threats_deleted": InstanceThreat.objects.filter(
                    threat_model_id=blueprint.threat_model_id, whole_system=False
                )
                .exclude(
                    Q(targets__component__isnull=False)
                    & ~Q(targets__component__blueprint=blueprint)
                    | Q(targets__flow__isnull=False)
                    & ~Q(targets__flow__blueprint=blueprint)
                    | Q(targets__zone__isnull=False)
                    & ~Q(targets__zone__blueprint=blueprint)
                    | Q(targets__boundary__isnull=False)
                    & ~Q(targets__boundary__blueprint=blueprint)
                )
                .filter(
                    Q(targets__component__blueprint=blueprint)
                    | Q(targets__flow__blueprint=blueprint)
                    | Q(targets__zone__blueprint=blueprint)
                    | Q(targets__boundary__blueprint=blueprint)
                )
                .distinct()
                .count(),
            }
        )
