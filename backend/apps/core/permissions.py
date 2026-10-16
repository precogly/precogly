"""
Core permission classes for RBAC.

Every model-scoped object reaches its threat model through ``threat_model``
or ``blueprint.threat_model`` (one hop further for rows that hang off a
component, flow, threat, countermeasure, risk, assumption or response), and
its organization and owning team through the model (plan section 4.9). An
inventory system reaches its organization directly. There is no "organization
is None, so allow" branch: an object with no organization is a shared library
row, and writing those is the Security Team's.
"""

from rest_framework import permissions

from apps.core.scope import threat_model_id_of


def _threat_model_of(obj):
    """The threat model an object belongs to, or None (a library row, an
    organization, an inventory system)."""
    from apps.threat_models.models import ThreatModel

    if getattr(obj, "threat_model_id", None):
        return obj.threat_model
    model_id = threat_model_id_of(obj)
    if model_id is None:
        return None
    return ThreatModel.objects.select_related("organization", "owning_team").get(
        pk=model_id
    )


def _get_organization(obj):
    """The organization an object belongs to, or None for shared rows."""
    if getattr(obj, "organization_id", None):
        return obj.organization
    threat_model = _threat_model_of(obj)
    if threat_model is not None:
        return threat_model.organization
    return None


def _is_security_team_anywhere(user) -> bool:
    return user.organization_memberships.filter(role="security_team").exists()


class IsSecurityTeam(permissions.BasePermission):
    """
    Restricts write operations to security team members.
    Read operations are allowed for all authenticated users.

    has_permission: gates on security_team role in any org (covers
    create/list where no object exists yet).
    has_object_permission: gates on security_team role in the
    *object's* org, preventing cross-org privilege escalation. A shared row
    (no organization) is written by anyone who passed has_permission.
    """

    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        if not request.user.is_authenticated:
            return False
        return _is_security_team_anywhere(request.user)

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        organization = _get_organization(obj)
        if organization is None:
            return _is_security_team_anywhere(request.user)
        return request.user.organization_memberships.filter(
            organization=organization,
            role="security_team",
        ).exists()


class CanWrite(permissions.BasePermission):
    """
    Allows read access to all authenticated users.
    Security team members get unconditional write access in their organization.
    Regular members must have a non-viewer team role for the object's owning team.
    A shared row (no organization) is written only by the Security Team.
    """

    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True

        return request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True

        organization = _get_organization(obj)
        if organization is None:
            return _is_security_team_anywhere(request.user)

        # Check org-level role
        org_membership = request.user.organization_memberships.filter(
            organization=organization
        ).first()
        if org_membership is None:
            return False

        # Security team gets unconditional write access
        if org_membership.role == "security_team":
            return True

        # Regular members: check team role for the object's owning team
        owning_team = self._get_owning_team(obj)
        if owning_team is None:
            return False

        from apps.organizations.models import TeamMembership

        team_membership = TeamMembership.objects.filter(
            user=request.user, team=owning_team
        ).first()
        if team_membership is None:
            return False

        return team_membership.role != "viewer"

    @staticmethod
    def _get_owning_team(obj):
        """The owning team: the model's, reached through the new keys."""
        if getattr(obj, "owning_team_id", None):
            return obj.owning_team
        threat_model = _threat_model_of(obj)
        if threat_model is not None:
            return threat_model.owning_team
        return None


def check_write_access(view, row):
    """Refuse a write that points at ``row`` unless the caller may write its model.

    Object permissions run only for rows that already exist, so an id sent in
    a request body (a threat model, a blueprint, a threat, a countermeasure,
    a component, a flow) is checked here instead. A row in an organization the
    caller is not a member of reads as missing (404); a row in the caller's
    organization goes through ``CanWrite`` on its threat model (403).
    """
    from rest_framework.exceptions import NotFound

    from apps.threat_models.models import ThreatModel

    threat_model = row if isinstance(row, ThreatModel) else _threat_model_of(row)
    if (
        threat_model is None
        or not view.request.user.organization_memberships.filter(
            organization_id=threat_model.organization_id
        ).exists()
    ):
        raise NotFound(f"{type(row).__name__} {row.pk} not found.")
    view.check_object_permissions(view.request, threat_model)


class WritableParentsMixin:
    """Run ``check_write_access`` on every parent a create or update names.

    ``writable_parent_fields`` lists the serializer fields that point at a
    model-scoped row. Each one present in ``validated_data`` is checked before
    the row is saved, so neither a create nor a PATCH can attach a row to
    another organization's model or to a model the caller cannot write.
    """

    writable_parent_fields = ()

    def check_writable_parents(self, serializer):
        for field_name in self.writable_parent_fields:
            row = serializer.validated_data.get(field_name)
            if row is not None:
                check_write_access(self, row)

    def perform_create(self, serializer):
        self.check_writable_parents(serializer)
        super().perform_create(serializer)

    def perform_update(self, serializer):
        self.check_writable_parents(serializer)
        super().perform_update(serializer)
