"""
Views for organizations app.
"""

import secrets
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.utils import timezone
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, permissions, status, viewsets
from rest_framework.exceptions import ValidationError
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.core.permissions import IsSecurityTeam

from .models import (
    Organization,
    OrganizationMember,
    BusinessUnit,
    Team,
    TeamMembership,
    TeamInvitation,
    MagicLink,
    SharedWithMe,
)
from .serializers import (
    OrganizationListSerializer,
    OrganizationMemberListSerializer,
    OrganizationMemberSerializer,
    OrganizationSerializer,
    BusinessUnitSerializer,
    TeamSerializer,
    TeamListSerializer,
    TeamMembershipSerializer,
    TeamInvitationSerializer,
    MagicLinkSerializer,
    SharedWithMeSerializer,
)

User = get_user_model()


class OrganizationViewSet(viewsets.ModelViewSet):
    """ViewSet for Organization CRUD operations."""

    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["plan"]
    search_fields = ["name", "domain"]
    ordering_fields = ["name", "created_at"]
    ordering = ["name"]

    def get_permissions(self):
        """Apply IsSecurityTeam for write operations and member management."""
        if self.action in ["create", "update", "partial_update", "destroy", "add_member", "remove_member"]:
            return [IsAuthenticated(), IsSecurityTeam()]
        return [IsAuthenticated()]

    def get_queryset(self):
        """Return organizations the user belongs to."""
        user = self.request.user
        org_ids = user.organization_memberships.values_list("organization_id", flat=True)
        return Organization.objects.filter(id__in=org_ids).prefetch_related("members")

    def get_serializer_class(self):
        """Return appropriate serializer."""
        if self.action == "list":
            return OrganizationListSerializer
        return OrganizationSerializer

    def perform_create(self, serializer):
        """Create organization and add creator as admin."""
        org = serializer.save()
        OrganizationMember.objects.create(
            organization=org,
            user=self.request.user,
            role=OrganizationMember.Role.SECURITY_TEAM,
        )

    @action(detail=True, methods=["get"])
    def members(self, request, pk=None):
        """List members of an organization."""
        org = self.get_object()
        members = org.members.select_related("user").all()
        serializer = OrganizationMemberListSerializer(members, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=["post"], url_path="add-member")
    def add_member(self, request, pk=None):
        """Add a member to an organization."""
        org = self.get_object()
        serializer = OrganizationMemberSerializer(data={
            "organization": org.id,
            "user": request.data.get("user"),
            "role": request.data.get("role", OrganizationMember.Role.MEMBER),
        })
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"], url_path="remove-member")
    def remove_member(self, request, pk=None):
        """Remove a member from an organization."""
        org = self.get_object()
        user_id = request.data.get("user")
        try:
            member = org.members.get(user_id=user_id)
            if member.is_last_security_team_member():
                return Response(
                    {"detail": "At least one organization member must remain on the security team."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            TeamMembership.objects.filter(
                team__organization=org, user_id=user_id
            ).delete()
            member.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except OrganizationMember.DoesNotExist:
            return Response(
                {"detail": "Member not found"},
                status=status.HTTP_404_NOT_FOUND,
            )


class OrganizationMemberViewSet(viewsets.ModelViewSet):
    """ViewSet for OrganizationMember CRUD operations."""

    serializer_class = OrganizationMemberSerializer
    permission_classes = [IsAuthenticated, IsSecurityTeam]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["organization", "user", "role"]

    def get_queryset(self):
        """Return memberships for organizations the user belongs to."""
        user = self.request.user
        org_ids = user.organization_memberships.values_list("organization_id", flat=True)
        return OrganizationMember.objects.filter(
            organization_id__in=org_ids
        ).select_related("organization", "user")

    def destroy(self, request, *args, **kwargs):
        """Prevent deleting the final security-team member from an organization."""
        member = self.get_object()
        if member.is_last_security_team_member():
            return Response(
                {"detail": "At least one organization member must remain on the security team."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return super().destroy(request, *args, **kwargs)


class BusinessUnitViewSet(viewsets.ModelViewSet):
    """ViewSet for BusinessUnit CRUD operations."""

    serializer_class = BusinessUnitSerializer
    permission_classes = [IsAuthenticated, IsSecurityTeam]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["organization", "parent"]
    search_fields = ["name", "code"]
    ordering_fields = ["name", "created_at"]
    ordering = ["name"]

    def get_queryset(self):
        """Return business units for organizations the user belongs to."""
        user = self.request.user
        org_ids = user.organization_memberships.values_list("organization_id", flat=True)
        return BusinessUnit.objects.filter(
            organization_id__in=org_ids
        ).select_related("organization", "parent")


class IsTeamMember(permissions.BasePermission):
    """
    Permission check for team membership.
    - Org admins can LIST/RETRIEVE teams (read-only visibility)
    - Only explicit team members can perform write operations
    """

    def has_object_permission(self, request, view, obj):
        # Safe methods (GET, HEAD, OPTIONS) allowed for org members
        if request.method in permissions.SAFE_METHODS:
            return obj.organization.members.filter(user=request.user).exists()

        # Security Team gets unconditional write access
        if obj.organization.members.filter(
            user=request.user, role="security_team"
        ).exists():
            return True

        # Write operations require explicit team membership
        return obj.memberships.filter(
            user=request.user,
            role__in=["lead", "member"],  # Viewers can't write
        ).exists()


class TeamViewSet(viewsets.ModelViewSet):
    """ViewSet for Team CRUD operations."""

    permission_classes = [IsAuthenticated, IsTeamMember]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["organization", "business_unit", "is_default"]
    search_fields = ["name", "code"]
    ordering_fields = ["name", "created_at"]
    ordering = ["name"]

    def get_queryset(self):
        """
        Org admins can see all teams in their orgs (visibility).
        Filtering for 'my teams only' can be done via query param.
        """
        user = self.request.user
        org_ids = user.organization_memberships.values_list("organization_id", flat=True)
        queryset = Team.objects.filter(
            organization_id__in=org_ids
        ).select_related("organization", "business_unit")

        # Optional filter: only teams user is a member of
        # Security team members bypass this filter (they manage all teams)
        my_teams_only = self.request.query_params.get("my_teams", "false")
        if my_teams_only.lower() == "true":
            is_security_team = user.organization_memberships.filter(
                organization_id__in=org_ids,
                role=OrganizationMember.Role.SECURITY_TEAM,
            ).exists()
            if not is_security_team:
                queryset = queryset.filter(memberships__user=user)

        return queryset

    def get_serializer_class(self):
        """Return appropriate serializer."""
        if self.action == "list":
            return TeamListSerializer
        return TeamSerializer

    def get_permissions(self):
        """Skip IsTeamMember for list/create (handled differently)."""
        if self.action in ["list", "create"]:
            return [IsAuthenticated()]
        return super().get_permissions()

    def perform_create(self, serializer):
        """Create team and add creator as team lead."""
        team = serializer.save()
        TeamMembership.objects.create(
            team=team,
            user=self.request.user,
            role=TeamMembership.Role.LEAD,
        )

    @action(detail=True, methods=["post"], url_path="change-member-role")
    def change_member_role(self, request, pk=None):
        """Change a team member's role."""
        team = self.get_object()
        user_id = request.data.get("user_id")
        new_role = request.data.get("role")

        if not user_id or not new_role:
            return Response(
                {"error": "user_id and role are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            membership = team.memberships.get(user_id=user_id)
        except TeamMembership.DoesNotExist:
            return Response(
                {"error": "Member not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        membership.role = new_role
        membership.save(update_fields=["role", "updated_at"])
        return Response(TeamMembershipSerializer(membership).data)

    @action(detail=True, methods=["get"])
    def members(self, request, pk=None):
        """List members of a team."""
        team = self.get_object()
        memberships = team.memberships.select_related("user")
        serializer = TeamMembershipSerializer(memberships, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=["post"], url_path="add-member")
    def add_member(self, request, pk=None):
        """
        Add existing user to team by user_id.
        For non-existent users, use invite_member instead.
        """
        team = self.get_object()
        user_id = request.data.get("user_id")
        role = request.data.get("role", "member")

        if not user_id:
            return Response(
                {"error": "user_id is required. For new users, use invite_member."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Verify user exists
        if not User.objects.filter(id=user_id).exists():
            return Response(
                {"error": "User not found. Use invite_member for non-existent users."},
                status=status.HTTP_404_NOT_FOUND,
            )

        membership, created = TeamMembership.objects.get_or_create(
            team=team,
            user_id=user_id,
            defaults={"role": role},
        )
        return Response(TeamMembershipSerializer(membership).data)

    @action(detail=True, methods=["post"], url_path="invite-member")
    def invite_member(self, request, pk=None):
        """
        Invite user by email. Works for both existing and non-existent users.
        - If user exists: creates TeamMembership directly
        - If user doesn't exist: creates TeamInvitation (pending)
        """
        team = self.get_object()
        email = request.data.get("email")
        role = request.data.get("role", "member")

        if not email:
            return Response(
                {"error": "email is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check if user already exists
        try:
            existing_user = User.objects.get(email=email)
            # User exists - create membership directly
            membership, created = TeamMembership.objects.get_or_create(
                team=team,
                user=existing_user,
                defaults={"role": role},
            )
            return Response({
                "status": "added",
                "membership": TeamMembershipSerializer(membership).data,
            })
        except User.DoesNotExist:
            # User doesn't exist - create invitation
            invitation, created = TeamInvitation.objects.update_or_create(
                team=team,
                email=email,
                defaults={
                    "role": role,
                    "token": secrets.token_urlsafe(32),
                    "invited_by": request.user,
                    "status": TeamInvitation.Status.PENDING,
                    "expires_at": timezone.now() + timedelta(days=7),
                },
            )

            # Send invitation email (prints to console in development)
            frontend_base = settings.FRONTEND_URL if hasattr(settings, "FRONTEND_URL") else "http://localhost:5173"
            invite_url = f"{frontend_base}/invite/{invitation.token}"
            send_mail(
                subject=f"You've been invited to join {team.name} on Precogly",
                message=(
                    f"Hi,\n\n"
                    f"{request.user.email} has invited you to join the team "
                    f'"{team.name}" in the organization "{team.organization.name}".\n\n'
                    f"Click the link below to accept the invitation:\n"
                    f"{invite_url}\n\n"
                    f"This invitation expires in 7 days.\n\n"
                    f"— Precogly"
                ),
                from_email=None,  # uses DEFAULT_FROM_EMAIL
                recipient_list=[email],
            )

            return Response(
                {
                    "status": "invited",
                    "invitation": TeamInvitationSerializer(invitation).data,
                },
                status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
            )

    @action(detail=True, methods=["post"], url_path="remove-member")
    def remove_member(self, request, pk=None):
        """Remove a member from a team."""
        team = self.get_object()
        user_id = request.data.get("user_id")

        if not user_id:
            return Response(
                {"error": "user_id is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            membership = team.memberships.get(user_id=user_id)
            membership.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except TeamMembership.DoesNotExist:
            return Response(
                {"error": "Member not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

    @action(detail=True, methods=["post"])
    def join(self, request, pk=None):
        """
        Allow org member to explicitly join a team.
        Required for write access to team's threat models.
        """
        team = self.get_object()
        user = request.user

        # Verify user is org member
        if not team.organization.members.filter(user=user).exists():
            return Response(
                {"error": "Not a member of this organization"},
                status=status.HTTP_403_FORBIDDEN,
            )

        membership, created = TeamMembership.objects.get_or_create(
            team=team,
            user=user,
            defaults={"role": TeamMembership.Role.MEMBER},
        )

        return Response({
            "joined": created,
            "membership": TeamMembershipSerializer(membership).data,
        })


class MagicLinkViewSet(viewsets.ModelViewSet):
    """ViewSet for MagicLink CRUD operations."""

    serializer_class = MagicLinkSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["threat_model", "is_revoked"]

    def get_queryset(self):
        """Return magic links for threat models user has access to."""
        user = self.request.user
        return MagicLink.objects.filter(
            threat_model__organization__members__user=user
        ).select_related("threat_model")

    def get_permissions(self):
        """Require IsSecurityTeam for create and revoke."""
        if self.action in ["create", "revoke"]:
            return [IsAuthenticated(), IsSecurityTeam()]
        return [IsAuthenticated()]

    def perform_create(self, serializer):
        """Create magic link with token and expiration."""
        threat_model = serializer.validated_data.get("threat_model")
        user_org_ids = set(
            self.request.user.organization_memberships.values_list(
                "organization_id", flat=True
            )
        )
        if threat_model.organization_id not in user_org_ids:
            raise ValidationError(
                {"threat_model": "You do not have access to this threat model."}
            )
        serializer.save(
            token=secrets.token_urlsafe(32),
            created_by=self.request.user,
            expires_at=timezone.now() + timedelta(days=30),
        )

    @action(detail=True, methods=["post"])
    def revoke(self, request, pk=None):
        """Revoke a magic link."""
        magic_link = self.get_object()
        magic_link.is_revoked = True
        magic_link.save(update_fields=["is_revoked"])
        return Response({"status": "revoked"})


class MagicLinkAccessView(APIView):
    """Public view for accessing a magic link (no auth required)."""

    permission_classes = []  # No auth required

    def get(self, request, token):
        """Access a threat model via magic link."""
        try:
            link = MagicLink.objects.select_related(
                "threat_model", "threat_model__organization", "created_by"
            ).get(token=token)
        except MagicLink.DoesNotExist:
            return Response(
                {"error": "Invalid link"},
                status=status.HTTP_404_NOT_FOUND,
            )

        if not link.is_valid():
            return Response(
                {"error": "Link expired or revoked"},
                status=status.HTTP_410_GONE,
            )

        link.accessed_count += 1
        link.save(update_fields=["accessed_count"])

        # If user is logged in, add to their "Shared with Me" list
        is_authenticated = request.user.is_authenticated
        saved_to_account = False
        if is_authenticated:
            shared_record, created = SharedWithMe.objects.get_or_create(
                user=request.user,
                threat_model=link.threat_model,
                defaults={"magic_link": link},
            )
            if not created:
                # Update access count and last accessed time
                shared_record.access_count += 1
                shared_record.save(update_fields=["access_count", "last_accessed_at"])
            saved_to_account = True

        # Return read-only threat model data
        from apps.threat_models.serializers import ThreatModelSerializer

        serializer = ThreatModelSerializer(link.threat_model, context={'request': request})

        # Get threat analysis data first (stats depend on it)
        threat_analysis = self._get_threat_analysis_data(link.threat_model)

        # Compute summary stats from real DB data
        stats = self._compute_stats_from_threat_analysis(threat_analysis, link.threat_model)

        response_data = {
            "threat_model": serializer.data,
            "stats": stats,
            "threat_analysis": threat_analysis,
            "read_only": True,
            "expires_at": link.expires_at,
            "is_authenticated": is_authenticated,
            "saved_to_account": saved_to_account,
        }

        return Response(response_data)

    def _compute_stats_from_threat_analysis(self, threat_analysis, threat_model):
        """
        Compute summary statistics from real DB threat analysis data.
        Derives threat statuses using the same logic as the frontend deriveThreatStatus.
        """
        threats = threat_analysis.get("threats", [])

        # Filter out dismissed threats
        active_threats = [t for t in threats if not t.get("is_dismissed")]

        # Derive threat statuses (mirrors frontend deriveThreatStatus)
        exposed_count = 0
        mitigated_count = 0
        for threat in active_threats:
            countermeasures = threat.get("countermeasures", [])
            if not countermeasures:
                exposed_count += 1
                continue
            has_gaps = any(cm.get("status") == "gap" for cm in countermeasures)
            if has_gaps:
                exposed_count += 1
                continue
            has_planned = any(cm.get("status") == "planned" for cm in countermeasures)
            has_waived = any(cm.get("status") == "waived" for cm in countermeasures)
            if has_planned or has_waived:
                # addressable - not counted as exposed or mitigated
                continue
            # All countermeasures are verified/platform
            mitigated_count += 1

        # Count countermeasures by status
        all_countermeasures = []
        for threat in active_threats:
            all_countermeasures.extend(threat.get("countermeasures", []))
        total_countermeasures = len(all_countermeasures)
        verified_count = sum(
            1 for cm in all_countermeasures if cm.get("status") in ("platform", "verified")
        )
        gaps_count = sum(1 for cm in all_countermeasures if cm.get("status") == "gap")

        # Count components from DFD canvas nodes
        dfds = threat_model.dfds.all()
        processes = 0
        datastores = 0
        human_actors = 0
        system_actors = 0
        boundaries = 0
        has_data_flows = False

        for dfd in dfds:
            canvas_data = dfd.canvas_data or {}
            for node in canvas_data.get("nodes", []):
                node_type = node.get("type", "")
                if node_type == "process":
                    processes += 1
                elif node_type == "datastore":
                    datastores += 1
                elif node_type == "humanActor":
                    human_actors += 1
                elif node_type == "systemActor":
                    system_actors += 1
                elif node_type == "trustZone":
                    boundaries += 1
            if canvas_data.get("edges"):
                has_data_flows = True

        # Compute progress checklist
        workspace_data = threat_model.workspace_data or {}
        system_context = workspace_data.get("systemContext", {})
        assets = system_context.get("assets", [])
        progress_checklist = workspace_data.get("progressChecklist", [])
        manual_progress = {
            item.get("id"): item.get("checked", False)
            for item in progress_checklist
            if item.get("id")
        }

        total_threats = len(active_threats)
        progress = {
            "assets_defined": manual_progress.get("assets_defined", len(assets) > 0),
            "components_identified": (processes + datastores) > 0,
            "trust_boundaries_identified": boundaries > 0,
            "data_flows_defined": has_data_flows,
            "owners_assigned": manual_progress.get("owners_assigned", False),
            "threats_linked_components": total_threats > 0 and (processes + datastores) > 0,
            "threats_linked_flows": total_threats > 0 and has_data_flows,
            "countermeasures_assigned": total_countermeasures > 0,
        }

        return {
            "components": {
                "total": processes + datastores + human_actors + system_actors,
                "processes": processes,
                "datastores": datastores,
                "humanActors": human_actors,
                "systemActors": system_actors,
                "boundaries": boundaries,
            },
            "threats": {
                "total": total_threats,
                "exposed": exposed_count,
                "mitigated": mitigated_count,
            },
            "countermeasures": {
                "total": total_countermeasures,
                "verified": verified_count,
                "gaps": gaps_count,
            },
            "progress": progress,
        }

    def _serialize_taxonomy_entries(self, threat_library):
        """Serialize taxonomy entries for a threat library."""
        if not threat_library:
            return []
        entries = []
        for join in threat_library.taxonomy_entries.select_related(
            "taxonomy_entry__taxonomy"
        ).all():
            entry = join.taxonomy_entry
            entries.append({
                "taxonomy_slug": entry.taxonomy.slug,
                "taxonomy_name": entry.taxonomy.name,
                "external_id": entry.external_id,
                "title": entry.title,
            })
        return entries

    def _get_threat_analysis_data(self, threat_model):
        """
        Get threat analysis data for the threat model.
        Returns threats with their countermeasures and compliance mappings.
        Includes both component threats and data flow threats, including custom threats.
        """
        from apps.threats.models import (
            ComponentInstanceThreat,
            DataFlowInstanceThreat,
        )

        # Get all DFDs for this threat model
        dfds = threat_model.dfds.all()

        # Build node_id -> component_id mapping and edge_id -> flow_id mapping from all DFDs
        node_component_map = {}
        edge_flow_map = {}
        for dfd in dfds:
            canvas_data = dfd.canvas_data or {}
            # Map nodes to components
            for node in canvas_data.get("nodes", []):
                node_id = node.get("id")
                component_id = node.get("data", {}).get("component_id")
                if node_id and component_id:
                    node_component_map[node_id] = {
                        "component_id": component_id,
                        "dfd_id": str(dfd.id),
                        "dfd_name": dfd.name,
                    }
            # Map edges to data flows
            for edge in canvas_data.get("edges", []):
                edge_id = edge.get("id")
                dataflow_id = edge.get("data", {}).get("dataflow_id")
                if edge_id and dataflow_id:
                    edge_flow_map[edge_id] = {
                        "flow_id": dataflow_id,
                        "dfd_id": str(dfd.id),
                        "dfd_name": dfd.name,
                    }

        # Get component IDs from DFD canvas (DFD-based modeling)
        canvas_component_ids = [v["component_id"] for v in node_component_map.values()]
        canvas_flow_ids = [v["flow_id"] for v in edge_flow_map.values()]

        # Get analysis-only components (DFD-free modeling)
        # These are components directly linked to the threat model via threat_model FK
        analysis_only_components = threat_model.analysis_components.all()
        analysis_component_ids = [comp.id for comp in analysis_only_components]

        # Combine both sources
        component_ids = list(set(canvas_component_ids + analysis_component_ids))
        flow_ids = canvas_flow_ids  # Flows are currently only via DFD

        result = []

        from django.db.models import Prefetch
        from apps.threats.models import CountermeasureThreatLink

        # Fetch component threats
        if component_ids:
            component_threats = ComponentInstanceThreat.objects.filter(
                component_id__in=component_ids
            ).select_related(
                "component", "threat_library"
            ).prefetch_related(
                Prefetch(
                    "countermeasure_links",
                    queryset=CountermeasureThreatLink.objects.select_related(
                        "countermeasure",
                        "countermeasure__countermeasure_library",
                        "countermeasure__assigned_owner",
                        "countermeasure__verified_by",
                    ).prefetch_related(
                        "countermeasure__instance_standard_mappings__requirement__framework",
                    ).order_by("display_order"),
                ),
            )

            for threat in component_threats:
                # Find which node this component corresponds to (if it's in a DFD)
                node_info = None
                for node_id, info in node_component_map.items():
                    if info["component_id"] == threat.component_id:
                        node_info = {"node_id": node_id, **info}
                        break

                # If not in DFD, it's an analysis-only component (DFD-free modeling)
                # Use component ID directly without node mapping
                if not node_info and threat.component_id in analysis_component_ids:
                    # Analysis-only component - create a synthetic mapping
                    node_info = {
                        "node_id": f"analysis-{threat.component_id}",
                        "component_id": threat.component_id,
                        "dfd_id": None,
                        "dfd_name": None,
                    }

                # Support custom threats (threat_library can be null)
                threat_name = threat.threat_name or (
                    threat.threat_library.name if threat.threat_library else None
                )
                threat_description = (
                    threat.threat_library.description if threat.threat_library else None
                )
                taxonomy_entries = self._serialize_taxonomy_entries(threat.threat_library)

                threat_data = {
                    "id": threat.id,
                    "type": "component",
                    "component_id": threat.component_id,
                    "component_name": threat.component.name if threat.component else None,
                    "node_id": node_info["node_id"] if node_info else None,
                    "dfd_id": node_info["dfd_id"] if node_info else None,
                    "dfd_name": node_info["dfd_name"] if node_info else None,
                    "threat_library_id": threat.threat_library_id,
                    "threat_name": threat_name,
                    "threat_description": threat_description,
                    "taxonomy_entries": taxonomy_entries,
                    "inherent_severity": threat.inherent_severity,
                    "residual_severity": threat.residual_severity,
                    "status": threat.status,
                    "severity_scoring_metadata": threat.severity_scoring_metadata,
                    "is_dismissed": threat.is_dismissed,
                    "format_metadata": threat.format_metadata,
                    "countermeasures": [
                        {
                            "id": link.countermeasure.id,
                            "countermeasure_library_id": link.countermeasure.countermeasure_library_id,
                            "countermeasure_name": link.countermeasure.countermeasure_name or (
                                link.countermeasure.countermeasure_library.name if link.countermeasure.countermeasure_library else None
                            ),
                            "countermeasure_description": link.countermeasure.countermeasure_description or (
                                link.countermeasure.countermeasure_library.description if link.countermeasure.countermeasure_library else None
                            ),
                            "control_type": link.countermeasure.control_type or (
                                link.countermeasure.countermeasure_library.control_type if link.countermeasure.countermeasure_library else None
                            ),
                            "status": link.countermeasure.status,
                            "priority": link.countermeasure.priority,
                            "evidence_url": link.countermeasure.evidence_url,
                            "assigned_owner_email": link.countermeasure.assigned_owner.email if link.countermeasure.assigned_owner else None,
                            "verified_by_email": link.countermeasure.verified_by.email if link.countermeasure.verified_by else None,
                            "format_metadata": link.countermeasure.format_metadata,
                            "compliance_standards": [
                                {
                                    "id": std.id,
                                    "requirement_id": std.requirement_id,
                                    "framework_name": std.requirement.framework.name,
                                    "framework_slug": std.requirement.framework.slug,
                                    "section_code": std.requirement.section_code,
                                    "requirement_description": std.requirement.description,
                                    "sufficiency": std.sufficiency,
                                }
                                for std in link.countermeasure.instance_standard_mappings.all()
                            ],
                        }
                        for link in threat.countermeasure_links.all()
                    ],
                }
                result.append(threat_data)

        # Fetch data flow threats
        if flow_ids:
            flow_threats = DataFlowInstanceThreat.objects.filter(
                data_flow_id__in=flow_ids
            ).select_related(
                "data_flow", "threat_library"
            ).prefetch_related(
                Prefetch(
                    "countermeasure_links",
                    queryset=CountermeasureThreatLink.objects.select_related(
                        "countermeasure",
                        "countermeasure__countermeasure_library",
                        "countermeasure__assigned_owner",
                        "countermeasure__verified_by",
                    ).prefetch_related(
                        "countermeasure__instance_standard_mappings__requirement__framework",
                    ).order_by("display_order"),
                ),
            )

            for threat in flow_threats:
                # Find which edge this flow corresponds to
                edge_info = None
                for edge_id, info in edge_flow_map.items():
                    if info["flow_id"] == threat.data_flow_id:
                        edge_info = {"edge_id": edge_id, **info}
                        break

                # Support custom threats (threat_library can be null)
                threat_name = threat.threat_name or (
                    threat.threat_library.name if threat.threat_library else None
                )
                threat_description = (
                    threat.threat_library.description if threat.threat_library else None
                )
                taxonomy_entries = self._serialize_taxonomy_entries(threat.threat_library)

                threat_data = {
                    "id": threat.id,
                    "type": "flow",
                    "flow_id": threat.data_flow_id,
                    "flow_label": threat.data_flow.label if threat.data_flow else None,
                    "edge_id": edge_info["edge_id"] if edge_info else None,
                    "dfd_id": edge_info["dfd_id"] if edge_info else None,
                    "dfd_name": edge_info["dfd_name"] if edge_info else None,
                    "threat_library_id": threat.threat_library_id,
                    "threat_name": threat_name,
                    "threat_description": threat_description,
                    "taxonomy_entries": taxonomy_entries,
                    "inherent_severity": threat.inherent_severity,
                    "residual_severity": threat.residual_severity,
                    "status": threat.status,
                    "is_dismissed": threat.is_dismissed,
                    "format_metadata": threat.format_metadata,
                    "countermeasures": [
                        {
                            "id": link.countermeasure.id,
                            "countermeasure_library_id": link.countermeasure.countermeasure_library_id,
                            "countermeasure_name": link.countermeasure.countermeasure_name or (
                                link.countermeasure.countermeasure_library.name if link.countermeasure.countermeasure_library else None
                            ),
                            "countermeasure_description": link.countermeasure.countermeasure_description or (
                                link.countermeasure.countermeasure_library.description if link.countermeasure.countermeasure_library else None
                            ),
                            "control_type": link.countermeasure.control_type or (
                                link.countermeasure.countermeasure_library.control_type if link.countermeasure.countermeasure_library else None
                            ),
                            "status": link.countermeasure.status,
                            "priority": link.countermeasure.priority,
                            "evidence_url": link.countermeasure.evidence_url,
                            "assigned_owner_email": link.countermeasure.assigned_owner.email if link.countermeasure.assigned_owner else None,
                            "verified_by_email": link.countermeasure.verified_by.email if link.countermeasure.verified_by else None,
                            "format_metadata": link.countermeasure.format_metadata,
                            "compliance_standards": [
                                {
                                    "id": std.id,
                                    "requirement_id": std.requirement_id,
                                    "framework_name": std.requirement.framework.name,
                                    "framework_slug": std.requirement.framework.slug,
                                    "section_code": std.requirement.section_code,
                                    "requirement_description": std.requirement.description,
                                    "sufficiency": std.sufficiency,
                                }
                                for std in link.countermeasure.instance_standard_mappings.all()
                            ],
                        }
                        for link in threat.countermeasure_links.all()
                    ],
                }
                result.append(threat_data)

        # Add analysis-only components to the node_component_map
        # Use synthetic node IDs for frontend compatibility
        for comp_id in analysis_component_ids:
            if comp_id not in [v["component_id"] for v in node_component_map.values()]:
                node_component_map[f"analysis-{comp_id}"] = {
                    "component_id": comp_id,
                    "dfd_id": None,
                    "dfd_name": "Analysis-Only",
                }

        return {
            "threat_model_id": str(threat_model.id),
            "threats": result,
            "total_count": len(result),
            "node_component_map": node_component_map,
            "edge_flow_map": edge_flow_map,
        }


class TeamInvitationViewSet(viewsets.ModelViewSet):
    """Manage team invitations (for admins/leads)."""

    serializer_class = TeamInvitationSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["team", "status"]

    def get_queryset(self):
        """Show invitations for teams user can manage."""
        user = self.request.user
        return TeamInvitation.objects.filter(
            team__memberships__user=user,
            team__memberships__role="lead",
        ).select_related("team", "team__organization", "invited_by")

    @action(detail=True, methods=["post"])
    def revoke(self, request, pk=None):
        """Revoke a pending invitation."""
        invitation = self.get_object()
        if invitation.status != TeamInvitation.Status.PENDING:
            return Response(
                {"error": "Can only revoke pending invitations"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        invitation.status = TeamInvitation.Status.REVOKED
        invitation.save(update_fields=["status"])
        return Response({"status": "revoked"})


class TeamInvitationAcceptView(APIView):
    """
    Accept a team invitation.
    - GET: returns invitation details (no auth required)
    - POST: accepts the invitation (requires auth)
    """

    permission_classes = []  # No auth required for GET

    def get(self, request, token):
        """Get invitation details (for signup/login page)."""
        try:
            invitation = TeamInvitation.objects.select_related(
                "team", "team__organization"
            ).get(token=token)
        except TeamInvitation.DoesNotExist:
            return Response(
                {"error": "Invalid invitation"},
                status=status.HTTP_404_NOT_FOUND,
            )

        if not invitation.is_valid():
            return Response(
                {"error": "Invitation expired or already used"},
                status=status.HTTP_410_GONE,
            )

        return Response({
            "invitation": TeamInvitationSerializer(invitation).data,
            "requires_signup": not request.user.is_authenticated,
        })

    def post(self, request, token):
        """Accept the invitation (requires authentication)."""
        if not request.user.is_authenticated:
            return Response(
                {"error": "Must be logged in to accept invitation"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            invitation = TeamInvitation.objects.select_related("team").get(token=token)
        except TeamInvitation.DoesNotExist:
            return Response(
                {"error": "Invalid invitation"},
                status=status.HTTP_404_NOT_FOUND,
            )

        if not invitation.is_valid():
            return Response(
                {"error": "Invitation expired or already used"},
                status=status.HTTP_410_GONE,
            )

        # Verify email matches (optional security check)
        if invitation.email.lower() != request.user.email.lower():
            return Response(
                {"error": "Invitation was sent to a different email address"},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Accept invitation - creates TeamMembership
        membership = invitation.accept(request.user)

        # Also add to organization if not already a member
        OrganizationMember.objects.get_or_create(
            organization=invitation.team.organization,
            user=request.user,
            defaults={"role": OrganizationMember.Role.MEMBER},
        )

        return Response({
            "status": "accepted",
            "membership": TeamMembershipSerializer(membership).data,
        })


class SharedWithMeViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for listing threat models shared with the current user via magic links.
    Read-only - users cannot modify these records directly.
    """

    serializer_class = SharedWithMeSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ["last_accessed_at", "first_accessed_at", "access_count"]
    ordering = ["-last_accessed_at"]

    def get_queryset(self):
        """Return threat models shared with the current user."""
        return SharedWithMe.objects.filter(
            user=self.request.user
        ).select_related(
            "threat_model",
            "threat_model__organization",
            "magic_link",
            "magic_link__created_by",
        )

    @action(detail=True, methods=["delete"])
    def remove(self, request, pk=None):
        """Remove a model from the user's 'Shared with Me' list."""
        shared_item = self.get_object()
        shared_item.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
