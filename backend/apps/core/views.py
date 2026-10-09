"""
Core views - dashboard stats and shared endpoints.
"""

from django.db.models import Count, Q
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.organizations.models import TeamMembership
from apps.threat_models.models import ThreatModel
from apps.threats.models import Risk
from apps.threats.services import derive_risk_status


class DashboardStatsView(APIView):
    """Dashboard statistics endpoint."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Get dashboard statistics scoped to user's team memberships."""
        user = request.user

        # Get organizations the user belongs to
        org_ids = user.organization_memberships.values_list(
            "organization_id", flat=True
        )

        # Security team sees all threat models in their orgs
        is_security_team = user.organization_memberships.filter(
            role="security_team"
        ).exists()

        if is_security_team:
            threat_models = ThreatModel.objects.filter(organization_id__in=org_ids)
            risks = (
                Risk.objects.filter(threat_model__organization_id__in=org_ids)
                .select_related("inherent")
                .prefetch_related("risk_threats__threat")
            )
        else:
            # Get teams the user belongs to
            user_team_ids = TeamMembership.objects.filter(user=user).values_list(
                "team_id", flat=True
            )

            threat_models = ThreatModel.objects.filter(
                organization_id__in=org_ids
            ).filter(Q(owning_team_id__in=user_team_ids) | Q(owning_team__isnull=True))
            risks = (
                Risk.objects.filter(threat_model__organization_id__in=org_ids)
                .filter(
                    Q(threat_model__owning_team_id__in=user_team_ids)
                    | Q(threat_model__owning_team__isnull=True)
                )
                .select_related("inherent")
                .prefetch_related("risk_threats__threat")
            )

        # Calculate threat model stats
        total_count = threat_models.count()

        risk_level_counts = risks.values("inherent__level").annotate(count=Count("id"))
        level_map = {
            entry["inherent__level"]: entry["count"] for entry in risk_level_counts
        }

        exposed_count = 0
        mitigated_count = 0
        for risk in risks:
            risk_status = derive_risk_status(risk)
            if risk_status == "exposed":
                exposed_count += 1
            elif risk_status in ["mitigated", "addressable"]:
                mitigated_count += 1

        return Response(
            {
                "total": total_count,
                "risks": {
                    "total": risks.count(),
                    "info": level_map.get("info", 0),
                    "critical": level_map.get("critical", 0),
                    "high": level_map.get("high", 0),
                    "medium": level_map.get("medium", 0),
                    "low": level_map.get("low", 0),
                    "exposed": exposed_count,
                    "mitigated": mitigated_count,
                },
            }
        )


class HealthCheckView(APIView):
    """Health check endpoint (no auth required)."""

    permission_classes = []

    def get(self, request):
        """Return health status."""
        return Response({"status": "healthy"})
