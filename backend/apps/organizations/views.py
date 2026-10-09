"""
Views for organizations app.
"""

import secrets
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.db.models import Count
from django.utils import timezone
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.core.permissions import IsSecurityTeam
from apps.threat_models.analysis_service import SHARED, build_threat_analysis

from .models import (
    BusinessUnit,
    MagicLink,
    Organization,
    OrganizationMember,
    SharedWithMe,
    Team,
    TeamInvitation,
    TeamMembership,
)
from .serializers import (
    BusinessUnitSerializer,
    MagicLinkSerializer,
    OrganizationListSerializer,
    OrganizationMemberListSerializer,
    OrganizationMemberSerializer,
    OrganizationSerializer,
    SharedWithMeSerializer,
    TeamInvitationSerializer,
    TeamListSerializer,
    TeamMembershipSerializer,
    TeamSerializer,
)

User = get_user_model()


class OrganizationViewSet(viewsets.ModelViewSet):
    """ViewSet for Organization CRUD operations."""

    permission_classes = [IsAuthenticated]
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_fields = ["plan"]
    search_fields = ["name", "domain"]
    ordering_fields = ["name", "created_at"]
    ordering = ["name"]

    def get_permissions(self):
        """Apply IsSecurityTeam for write operations and member management."""
        if self.action in [
            "create",
            "update",
            "partial_update",
            "destroy",
            "add_member",
            "remove_member",
        ]:
            return [IsAuthenticated(), IsSecurityTeam()]
        return [IsAuthenticated()]

    def get_queryset(self):
        """Return organizations the user belongs to."""
        user = self.request.user
        org_ids = user.organization_memberships.values_list(
            "organization_id", flat=True
        )
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
        serializer = OrganizationMemberSerializer(
            data={
                "organization": org.id,
                "user": request.data.get("user"),
                "role": request.data.get("role", OrganizationMember.Role.MEMBER),
            }
        )
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
                    {
                        "detail": "At least one organization member must remain on the security team."
                    },
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
        org_ids = user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return OrganizationMember.objects.filter(
            organization_id__in=org_ids
        ).select_related("organization", "user")

    def destroy(self, request, *args, **kwargs):
        """Prevent deleting the final security-team member from an organization."""
        member = self.get_object()
        if member.is_last_security_team_member():
            return Response(
                {
                    "detail": "At least one organization member must remain on the security team."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        return super().destroy(request, *args, **kwargs)


class BusinessUnitViewSet(viewsets.ModelViewSet):
    """ViewSet for BusinessUnit CRUD operations."""

    serializer_class = BusinessUnitSerializer
    permission_classes = [IsAuthenticated, IsSecurityTeam]
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_fields = ["organization", "parent"]
    search_fields = ["name", "code"]
    ordering_fields = ["name", "created_at"]
    ordering = ["name"]

    def get_queryset(self):
        """Return business units for organizations the user belongs to."""
        user = self.request.user
        org_ids = user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return BusinessUnit.objects.filter(organization_id__in=org_ids).select_related(
            "organization", "parent"
        )


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
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
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
        org_ids = user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        queryset = Team.objects.filter(organization_id__in=org_ids).select_related(
            "organization", "business_unit"
        )

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

    def _can_manage_team(self, team, user):
        """Return True if user is team lead or org security_team."""
        if team.organization.members.filter(user=user, role="security_team").exists():
            return True
        return team.memberships.filter(user=user, role="lead").exists()

    @action(detail=True, methods=["post"], url_path="change-member-role")
    def change_member_role(self, request, pk=None):
        """Change a team member's role."""
        team = self.get_object()

        if not self._can_manage_team(team, request.user):
            return Response(
                {
                    "detail": "Only team leads and security team members can manage roles."
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        user_id = request.data.get("user_id")
        new_role = request.data.get("role")

        if not user_id or not new_role:
            return Response(
                {"error": "user_id and role are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        valid_roles = {r[0] for r in TeamMembership.Role.choices}
        if new_role not in valid_roles:
            return Response(
                {
                    "error": f"Invalid role. Must be one of: {', '.join(sorted(valid_roles))}"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            membership = team.memberships.get(user_id=user_id)
        except TeamMembership.DoesNotExist:
            return Response(
                {"error": "Member not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        if membership.role == "lead" and new_role != "lead":
            remaining_leads = (
                team.memberships.filter(role="lead").exclude(user_id=user_id).count()
            )
            if remaining_leads == 0:
                return Response(
                    {"error": "Cannot change role: this is the only team lead."},
                    status=status.HTTP_400_BAD_REQUEST,
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

        if not self._can_manage_team(team, request.user):
            return Response(
                {
                    "detail": "Only team leads and security team members can add members."
                },
                status=status.HTTP_403_FORBIDDEN,
            )

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

        membership, _created = TeamMembership.objects.get_or_create(
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

        if not self._can_manage_team(team, request.user):
            return Response(
                {
                    "detail": "Only team leads and security team members can invite members."
                },
                status=status.HTTP_403_FORBIDDEN,
            )

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
            return Response(
                {
                    "status": "added",
                    "membership": TeamMembershipSerializer(membership).data,
                }
            )
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
            frontend_base = (
                settings.FRONTEND_URL
                if hasattr(settings, "FRONTEND_URL")
                else "http://localhost:5173"
            )
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

        if not self._can_manage_team(team, request.user):
            return Response(
                {
                    "detail": "Only team leads and security team members can remove members."
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        user_id = request.data.get("user_id")

        if not user_id:
            return Response(
                {"error": "user_id is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            membership = team.memberships.get(user_id=user_id)
        except TeamMembership.DoesNotExist:
            return Response(
                {"error": "Member not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        if membership.role == "lead":
            remaining_leads = (
                team.memberships.filter(role="lead").exclude(user_id=user_id).count()
            )
            if remaining_leads == 0:
                return Response(
                    {"error": "Cannot remove the only team lead."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        membership.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

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

        return Response(
            {
                "joined": created,
                "membership": TeamMembershipSerializer(membership).data,
            }
        )


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

    def perform_create(self, serializer):
        """Create magic link with token and expiration."""
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

        serializer = ThreatModelSerializer(
            link.threat_model, context={"request": request}
        )

        # Get threat analysis data first (stats depend on it)
        threat_analysis = build_threat_analysis(link.threat_model, audience=SHARED)

        # Compute summary stats from real DB data
        stats = self._compute_stats_from_threat_analysis(
            threat_analysis, link.threat_model
        )

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

        # Filter out triaged threats
        active_threats = [
            t for t in threats if t.get("triage_status", "open") in ("open", "mitigate")
        ]

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
            1
            for cm in all_countermeasures
            if cm.get("status") in ("platform", "verified")
        )
        gaps_count = sum(1 for cm in all_countermeasures if cm.get("status") == "gap")

        # Counted from rows, across every blueprint of the model, so the shared
        # page agrees with the report and the analysis screen (F30).
        category_counts = dict(
            threat_model.components.values_list("category")
            .annotate(count=Count("id"))
            .values_list("category", "count")
        )
        processes = (
            category_counts.get("process", 0)
            + category_counts.get(None, 0)
            + category_counts.get("", 0)
        )
        datastores = category_counts.get("datastore", 0)
        human_actors = category_counts.get("external_human_actor", 0)
        system_actors = category_counts.get("external_system_actor", 0)
        boundaries = threat_model.zones.count()
        has_flows = threat_model.flows.exists()

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
            "boundaries_identified": boundaries > 0,
            "flows_defined": has_flows,
            "owners_assigned": manual_progress.get("owners_assigned", False),
            "threats_linked_components": total_threats > 0
            and (processes + datastores) > 0,
            "threats_linked_flows": total_threats > 0 and has_flows,
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

        return Response(
            {
                "invitation": TeamInvitationSerializer(invitation).data,
                "requires_signup": not request.user.is_authenticated,
            }
        )

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

        return Response(
            {
                "status": "accepted",
                "membership": TeamMembershipSerializer(membership).data,
            }
        )


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
        return SharedWithMe.objects.filter(user=self.request.user).select_related(
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
