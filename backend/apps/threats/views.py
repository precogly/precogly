"""
Views for threats app.
"""

import contextlib

from django.db.models import Count, Prefetch, Q
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
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
    ComponentLibraryThreat,
    CountermeasureComment,
    CountermeasureLibrary,
    CountermeasureThreatLink,
    ExternalTaxonomy,
    InstanceCountermeasure,
    InstanceCountermeasureStandard,
    InstanceThreat,
    InstanceThreatTarget,
    InstanceThreatTaxonomyEntry,
    PentestFinding,
    Risk,
    RiskResponse,
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
    ComponentLibraryThreatSerializer,
    CountermeasureCommentSerializer,
    CountermeasureLibraryListSerializer,
    CountermeasureLibrarySerializer,
    ExternalTaxonomySerializer,
    InstanceCountermeasureSerializer,
    InstanceCountermeasureStandardSerializer,
    InstanceThreatSerializer,
    InstanceThreatTaxonomyEntrySerializer,
    PentestFindingSerializer,
    RiskDetailSerializer,
    RiskListSerializer,
    RiskResponseSerializer,
    TaxonomyEntryNestedSerializer,
    ThreatLibraryListSerializer,
    ThreatLibrarySerializer,
    ThreatPersonaSerializer,
    ThreatSourceSerializer,
    VerificationTestSerializer,
)
from .services import (
    check_platform_status,
    create_instance_countermeasure,
    link_countermeasure,
    note_user_edit,
    rating_level_rank,
    recalculate_all_threats_for_countermeasure,
    recalculate_residual,
    recalculate_risks_for_threat,
    recalculate_threat_status,
)


def _is_security_team(user):
    """Check if user has Security Team role in any organization."""
    return user.organization_memberships.filter(role="security_team").exists()


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
    search_fields = [
        "name",
        "description",
        "taxonomy_entries__taxonomy_entry__external_id",
        "taxonomy_entries__taxonomy_entry__title",
    ]
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


class InstanceThreatViewSet(viewsets.ModelViewSet):
    """One endpoint for every scenario, whatever it targets.

    Filters: ``threat_model``, ``blueprint``, ``component``, ``flow``, ``zone``,
    ``boundary`` (through the targets), ``threat_library``, ``status``,
    ``triage_status``, ``number``, ``whole_system``. ``search`` matches the name,
    and ``T7`` or ``7`` matches the number.
    """

    serializer_class = InstanceThreatSerializer
    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = [
        "threat_model",
        "threat_library",
        "status",
        "triage_status",
        "rating__level",
        "number",
        "whole_system",
    ]
    ordering_fields = [
        "number",
        "level_rank",
        "rating__score",
        "status",
        "created_at",
        "display_order",
    ]
    ordering = ["display_order", "number"]

    TARGET_FILTERS = ("component", "flow", "zone", "boundary")

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        queryset = (
            InstanceThreat.objects.filter(threat_model__organization_id__in=org_ids)
            .select_related("threat_library", "actor_persona", "rating")
            .annotate(level_rank=rating_level_rank("rating__level"))
            .prefetch_related(
                "instance_taxonomy_links__taxonomy_entry__taxonomy",
                "targets__component",
                "targets__flow__source_component",
                "targets__flow__dest_component",
                "targets__zone",
                "targets__boundary",
            )
        )
        params = self.request.query_params
        for kind in self.TARGET_FILTERS:
            value = params.get(kind)
            if value:
                queryset = queryset.filter(**{f"targets__{kind}_id": value})
        blueprint_id = params.get("blueprint")
        if blueprint_id:
            queryset = queryset.filter(
                Q(targets__component__blueprint_id=blueprint_id)
                | Q(targets__flow__blueprint_id=blueprint_id)
                | Q(targets__zone__blueprint_id=blueprint_id)
                | Q(targets__boundary__blueprint_id=blueprint_id)
            )
        search = (params.get("search") or "").strip()
        if search:
            number_text = search[1:] if search[:1].lower() == "t" else search
            condition = Q(threat_name__icontains=search) | Q(
                threat_library__name__icontains=search
            )
            if number_text.isdigit():
                condition |= Q(number=int(number_text))
            queryset = queryset.filter(condition)
        return queryset.distinct()

    @action(detail=True, methods=["get"])
    def suggested_countermeasures(self, request, pk=None):
        """Library countermeasures that can mitigate this scenario's threat.

        Returns:
            - suggested: countermeasures not yet applied
            - applied: countermeasures already applied to this scenario
        """
        threat = self.get_object()
        threat_library = threat.threat_library
        applicable_countermeasures = CountermeasureLibrary.objects.filter(
            applicable_threats=threat_library,
        )
        applied_ids = set(
            CountermeasureThreatLink.objects.filter(threat=threat).values_list(
                "countermeasure__countermeasure_library_id", flat=True
            )
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
                "threat_id": threat.id,
                "threat_name": threat_library.name
                if threat_library
                else threat.threat_name,
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
        Apply a countermeasure to this scenario.

        Request body:
            - countermeasure_library_id: ID of the library countermeasure to create+link
            - existing_countermeasure_id: ID of an existing countermeasure instance to link
            - status: optional, defaults to the library default (only used with countermeasure_library_id)
        """
        threat = self.get_object()
        threat_model = threat.threat_model

        existing_countermeasure_id = request.data.get("existing_countermeasure_id")
        if existing_countermeasure_id:
            existing_cm = InstanceCountermeasure.objects.filter(
                id=existing_countermeasure_id, threat_model=threat_model
            ).first()
            if existing_cm is None:
                return Response(
                    {"error": "Countermeasure instance not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )
            _link, link_created = link_countermeasure(existing_cm, threat)
            if not link_created:
                return Response(
                    {"error": "Countermeasure already linked to this threat"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            note_user_edit(threat)
            note_user_edit(existing_cm)
            recalculate_threat_status(threat)
            return Response(
                {
                    "countermeasure": InstanceCountermeasureSerializer(
                        existing_cm
                    ).data,
                    "message": "Linked existing countermeasure to threat",
                },
                status=status.HTTP_201_CREATED,
            )

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
        check_platform_status(request.user, threat_model, new_status=requested_status)

        instance_cm = create_instance_countermeasure(
            threat_model,
            countermeasure_library=countermeasure,
            status=requested_status,
        )
        link_countermeasure(instance_cm, threat)
        note_user_edit(threat)
        recalculate_threat_status(threat)

        return Response(
            {
                "countermeasure": InstanceCountermeasureSerializer(instance_cm).data,
                "message": f"Applied countermeasure '{countermeasure.name}' to threat",
            },
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["post"])
    def recalculate_status(self, request, pk=None):
        """Recalculate the threat status based on applied countermeasures."""
        threat = self.get_object()
        old_status = threat.status
        new_status = recalculate_threat_status(threat)
        return Response(
            {
                "threat_id": threat.id,
                "old_status": old_status,
                "new_status": new_status,
                "message": f"Status updated to {new_status}",
            }
        )

    @action(detail=True, methods=["post"])
    def set_targets(self, request, pk=None):
        """Replace the scenario's targets.

        Body: ``targets`` as ``[{type, id}]`` and optional ``whole_system``.
        An empty list is refused unless ``whole_system`` is true (I8).
        """
        threat = self.get_object()
        serializer = InstanceThreatSerializer(
            threat,
            data={
                "targets": request.data.get("targets", []),
                "whole_system": bool(request.data.get("whole_system", False)),
            },
            partial=True,
            context=self.get_serializer_context(),
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(InstanceThreatSerializer(threat).data)

    @action(detail=False, methods=["post"])
    def reorder(self, request):
        """Bulk-update display_order.

        With ``target_type`` and ``target_id`` the order is per target (what
        the tree shows under one node); otherwise it is the scenario's own
        order within the model.
        """
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
        target_type = request.data.get("target_type")
        target_id = request.data.get("target_id")
        if target_type in InstanceThreatTarget.TARGET_KINDS and target_id:
            rows = InstanceThreatTarget.objects.filter(
                threat_id__in=ordered_ids, **{f"{target_type}_id": target_id}
            )
            by_threat = {row.threat_id: row for row in rows}
            for position, threat_id in enumerate(ordered_ids):
                row = by_threat.get(threat_id)
                if row is not None and row.display_order != position:
                    row.display_order = position
                    row.save(update_fields=["display_order"])
            return Response({"status": "ok", "updated": len(by_threat)})
        InstanceThreat.objects.bulk_update(
            [
                InstanceThreat(id=threat_id, display_order=position)
                for position, threat_id in enumerate(ordered_ids)
            ],
            ["display_order"],
        )
        return Response({"status": "ok", "updated": len(ordered_ids)})

    def _scoped_component(self, request, component_id):
        org_ids = request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return (
            OrgsystemComponent.objects.filter(
                blueprint__threat_model__organization_id__in=org_ids,
                id=component_id,
            )
            .select_related("component_library")
            .first()
        )

    @action(detail=False, methods=["post"])
    def suggest(self, request):
        """Return AI-ranked, grounded threat candidates for a target.

        Component targets only in this version; other target types return an
        empty list. Persists nothing — the caller reviews the candidates and
        accepts them through the normal create path.
        """
        target_type = request.data.get("target_type", "component")
        target_id = request.data.get("target_id") or request.data.get("component_id")
        if not target_id:
            return Response(
                {"error": "target_id is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if target_type != "component":
            return Response(
                {"target_type": target_type, "target_id": target_id, "suggestions": []}
            )

        component = self._scoped_component(request, target_id)
        if component is None:
            return Response(
                {"error": "Component not found or not accessible"},
                status=status.HTTP_404_NOT_FOUND,
            )

        try:
            suggestions = suggest_component_threats(component, user=request.user)
        except AIDisabledError as err:
            return Response({"error": str(err)}, status=status.HTTP_400_BAD_REQUEST)
        except AIProviderError as err:
            # The model is enabled but unreachable/misbehaving; 503 signals a
            # transient/operational problem the user can act on (start the
            # model, fix the URL) rather than a bug in their request.
            return Response(
                {"error": str(err)}, status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        return Response(
            {
                "target_type": "component",
                "target_id": component.id,
                "suggestions": suggestions,
            }
        )

    @action(detail=False, methods=["get"])
    def ai_availability(self, request):
        """Report whether AI suggestions are available for a component's org.

        A cheap config lookup — it never builds a provider or probes the
        network; an enabled-but-unreachable model still surfaces later as a
        503 from ``suggest``.
        """
        target_id = request.query_params.get("target_id") or request.query_params.get(
            "component_id"
        )
        if not target_id:
            return Response(
                {"error": "target_id is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        component = self._scoped_component(request, target_id)
        if component is None:
            return Response(
                {"error": "Component not found or not accessible"},
                status=status.HTTP_404_NOT_FOUND,
            )
        try:
            resolve_config(organization_for_component(component))
        except AIDisabledError as err:
            return Response({"available": False, "reason": str(err)})
        return Response({"available": True, "reason": None})


class InstanceCountermeasureViewSet(viewsets.ModelViewSet):
    """Unified ViewSet for InstanceCountermeasure (component and flow)."""

    serializer_class = InstanceCountermeasureSerializer
    permission_classes = [IsAuthenticated, CanWrite]

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        queryset = (
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
                "threat_links__threat__threat_library",
                "threat_links__threat__targets__component",
                "threat_links__threat__targets__flow__source_component",
                "threat_links__threat__targets__flow__dest_component",
                "threat_links__threat__targets__zone",
                "threat_links__threat__targets__boundary",
                "targets__component",
                "targets__flow__source_component",
                "targets__flow__dest_component",
                "targets__zone",
                "targets__boundary",
                "provider_links",
            )
        )
        if self.request.query_params.get("overdue") in ("1", "true", "yes"):
            from datetime import date

            queryset = queryset.filter(due_date__lt=date.today()).exclude(
                status__in=[
                    InstanceCountermeasure.Status.IMPLEMENTED,
                    InstanceCountermeasure.Status.VERIFIED,
                    InstanceCountermeasure.Status.PLATFORM,
                ]
            )
        return queryset

    filter_backends = [DjangoFilterBackend]
    filterset_fields = [
        "threat_model",
        "countermeasure_library",
        "status",
        "required_for_release",
        "number",
    ]

    def perform_update(self, serializer):
        new_status = serializer.validated_data.get("status")
        if new_status is not None:
            check_platform_status(
                self.request.user,
                serializer.instance.threat_model,
                serializer.instance.status,
                new_status,
            )
        instance = serializer.save()
        note_user_edit(instance)
        recalculate_all_threats_for_countermeasure(instance)

    @action(detail=True, methods=["post"])
    def set_targets(self, request, pk=None):
        """Replace where the control applies: ``targets`` as ``[{type, id}]``.

        An empty list is allowed and means the whole system. Scope never
        changes a threat's status.
        """
        countermeasure = self.get_object()
        serializer = InstanceCountermeasureSerializer(
            countermeasure,
            data={"targets": request.data.get("targets", [])},
            partial=True,
            context=self.get_serializer_context(),
        )
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        note_user_edit(instance)
        return Response(InstanceCountermeasureSerializer(instance).data)

    @action(detail=True, methods=["post"])
    def link(self, request, pk=None):
        """Link this countermeasure to one more scenario of its model."""
        countermeasure = self.get_object()
        threat_id = request.data.get("threat_id")
        if not threat_id:
            return Response(
                {"error": "threat_id is required"}, status=status.HTTP_400_BAD_REQUEST
            )
        threat = InstanceThreat.objects.filter(
            id=threat_id, threat_model=countermeasure.threat_model
        ).first()
        if threat is None:
            return Response(
                {"error": "Threat not found"}, status=status.HTTP_404_NOT_FOUND
            )

        link, created = link_countermeasure(countermeasure, threat)
        if not created:
            return Response(
                {"error": "Already linked"}, status=status.HTTP_400_BAD_REQUEST
            )
        note_user_edit(countermeasure)
        note_user_edit(threat)
        recalculate_threat_status(threat)
        return Response(
            {"status": "linked", "link_id": link.id}, status=status.HTTP_201_CREATED
        )

    @action(detail=True, methods=["post"])
    def unlink(self, request, pk=None):
        """Unlink this countermeasure from a scenario.

        An untouched generated countermeasure that lost its last link is
        deleted (the orphan rule); anything a user edited, or that applies to
        the whole system, stays and is listed as unattached.
        """
        countermeasure = self.get_object()
        threat_id = request.data.get("threat_id")
        if not threat_id:
            return Response(
                {"error": "threat_id is required"}, status=status.HTTP_400_BAD_REQUEST
            )

        deleted_count, _ = CountermeasureThreatLink.objects.filter(
            countermeasure=countermeasure, threat_id=threat_id
        ).delete()
        if deleted_count == 0:
            return Response(
                {"error": "Link not found"}, status=status.HTTP_404_NOT_FOUND
            )

        threat = InstanceThreat.objects.filter(id=threat_id).first()
        if threat is not None:
            recalculate_threat_status(threat)
            recalculate_risks_for_threat(threat)

        if not InstanceCountermeasure.objects.filter(id=countermeasure.id).exists():
            # The post_delete rule already removed an orphaned generated row.
            return Response(
                {
                    "status": "deleted",
                    "message": "Last link removed, countermeasure deleted",
                }
            )
        countermeasure.refresh_from_db()
        remaining_links = countermeasure.threat_links.count()
        return Response({"status": "unlinked", "remaining_links": remaining_links})

    @action(detail=False, methods=["post"])
    def reorder(self, request):
        """Bulk-update display_order on junction table for countermeasures within a scenario."""
        threat_id = request.data.get("threat_id")
        ordered_ids = request.data.get("ordered_ids", [])
        if not ordered_ids or not isinstance(ordered_ids, list):
            return Response(
                {"error": "ordered_ids list is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        links = CountermeasureThreatLink.objects.filter(
            threat_id=threat_id, countermeasure_id__in=ordered_ids
        )
        by_countermeasure = {link.countermeasure_id: link for link in links}
        if len(by_countermeasure) != len(ordered_ids):
            return Response(
                {"error": "Some IDs not found or not accessible"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        for position, cm_id in enumerate(ordered_ids):
            by_countermeasure[cm_id].display_order = position
        CountermeasureThreatLink.objects.bulk_update(
            list(by_countermeasure.values()), ["display_order"]
        )
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
    """CRUD for instance-level taxonomy entries on threat scenarios."""

    serializer_class = InstanceThreatTaxonomyEntrySerializer
    permission_classes = [IsAuthenticated, CanWrite]

    def get_queryset(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return InstanceThreatTaxonomyEntry.objects.filter(
            threat__threat_model__organization_id__in=org_ids
        ).select_related("taxonomy_entry", "taxonomy_entry__taxonomy", "threat")

    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["threat", "taxonomy_entry"]


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
    filterset_fields = [
        "status",
        "inherent__level",
        "residual__level",
        "owner",
        "assigned_to",
    ]
    search_fields = ["name", "description"]
    ordering_fields = [
        "inherent_rank",
        "residual_rank",
        "inherent__score",
        "residual__score",
        "created_at",
        "name",
    ]
    ordering = ["-inherent_rank", "-inherent__score", "-created_at"]

    def get_queryset(self):
        from django.db.models import Count

        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return (
            Risk.objects.filter(
                threat_model_id=self.kwargs["threat_model_pk"],
                threat_model__organization_id__in=org_ids,
            )
            .select_related(
                "owner", "assigned_to", "threat_model", "inherent", "residual", "target"
            )
            .prefetch_related(
                "risk_threats__threat",
                "responses__owner",
                "responses__countermeasure_links__countermeasure",
            )
            .annotate(
                inherent_rank=rating_level_rank("inherent__level"),
                residual_rank=rating_level_rank("residual__level"),
                threat_count=Count("risk_threats", distinct=True),
            )
        )

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
        serializer.save(threat_model=self.get_serializer_context()["threat_model"])

    @action(detail=True, methods=["post"])
    def recalculate(self, request, threat_model_pk=None, pk=None):
        """Recompute residual score and level for this risk."""
        risk = self.get_object()
        recalculate_residual(risk)
        risk.refresh_from_db()
        serializer = RiskDetailSerializer(risk, context=self.get_serializer_context())
        return Response(serializer.data)

    @action(detail=True, methods=["post"], url_path="add-threats")
    def add_threats(self, request, threat_model_pk=None, pk=None):
        """Bulk link scenarios to this risk."""
        risk = self.get_object()
        threat_ids = list(request.data.get("threat_ids", []))

        valid_ids = set(
            InstanceThreat.objects.filter(
                id__in=threat_ids, threat_model_id=threat_model_pk
            ).values_list("id", flat=True)
        )
        rejected = set(threat_ids) - valid_ids
        if rejected:
            return Response(
                {
                    "error": "Some threat IDs do not belong to this threat model.",
                    "rejected_ids": sorted(rejected),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        existing = set(
            RiskThreat.objects.filter(risk=risk, threat_id__in=valid_ids).values_list(
                "threat_id", flat=True
            )
        )
        RiskThreat.objects.bulk_create(
            [
                RiskThreat(risk=risk, threat_id=threat_id)
                for threat_id in valid_ids - existing
            ]
        )
        for threat in InstanceThreat.objects.filter(id__in=valid_ids - existing):
            note_user_edit(threat)

        recalculate_residual(risk)
        risk.refresh_from_db()
        serializer = RiskDetailSerializer(risk, context=self.get_serializer_context())
        return Response(serializer.data)

    @action(detail=True, methods=["post"], url_path="remove-threats")
    def remove_threats(self, request, threat_model_pk=None, pk=None):
        """Bulk unlink scenarios from this risk."""
        risk = self.get_object()
        threat_ids = request.data.get("threat_ids", [])
        if threat_ids:
            RiskThreat.objects.filter(risk=risk, threat_id__in=threat_ids).delete()

        recalculate_residual(risk)
        risk.refresh_from_db()
        serializer = RiskDetailSerializer(risk, context=self.get_serializer_context())
        return Response(serializer.data)

    @action(detail=False, methods=["post"], url_path="bulk-update")
    def bulk_update(self, request, threat_model_pk=None):
        """
        Bulk update status or owner on multiple risks.

        Request body:
            risk_ids: list of risk IDs
            status: optional lifecycle status (identified, assessed, mitigated,
                accepted, transferred, retired)
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
        if "status" in request.data:
            new_status = request.data["status"]
            if new_status not in Risk.Status.values:
                return Response(
                    {"status": f"'{new_status}' is not a risk status."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            update_fields["status"] = new_status
        if "owner" in request.data:
            update_fields["owner_id"] = request.data["owner"]

        if not update_fields:
            return Response(
                {"error": "No fields to update"}, status=status.HTTP_400_BAD_REQUEST
            )

        updated = queryset.update(**update_fields)
        return Response({"updated": updated})


class RiskResponseViewSet(viewsets.ModelViewSet):
    """Responses of one risk: ``/api/threat-models/{id}/risks/{risk_id}/responses/``."""

    serializer_class = RiskResponseSerializer
    permission_classes = [IsAuthenticated, CanWrite]

    def _risk(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return get_object_or_404(
            Risk,
            pk=self.kwargs["risk_pk"],
            threat_model_id=self.kwargs["threat_model_pk"],
            threat_model__organization_id__in=org_ids,
        )

    def get_queryset(self):
        return (
            RiskResponse.objects.filter(risk=self._risk())
            .select_related("owner")
            .prefetch_related("countermeasure_links__countermeasure")
        )

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["risk"] = self._risk()
        return context

    def perform_create(self, serializer):
        serializer.save(risk=self._risk())


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

    def _threat_model(self):
        org_ids = self.request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return get_object_or_404(
            ThreatModel,
            pk=self.kwargs["threat_model_pk"],
            organization_id__in=org_ids,
        )

    def get_queryset(self):
        return ThreatPersona.objects.filter(threat_model=self._threat_model()).annotate(
            threat_count=Count("threats", distinct=True)
        )

    def perform_create(self, serializer):
        threat_model = self._threat_model()
        self.check_object_permissions(self.request, threat_model)
        serializer.save(threat_model=threat_model)


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
