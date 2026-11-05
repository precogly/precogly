"""REST API for managing an organization's AI provider configs.

This is the settings-UI counterpart to the Django admin: organization members
manage their own "bring your own model" endpoints here, and probe them with a
server-side "test connection" action so the stored API key never travels back to
the browser.

Two invariants are enforced in the view rather than left to the database to
reject with a 500:

* **Tenancy** — a member can only see and touch configs for organizations they
  belong to. The FK to ``organization`` is otherwise unconstrained, so we check
  membership on every write.
* **One default per org** — the model has a DB constraint to that effect, but a
  naive "save with ``is_default=True``" would hit it as an IntegrityError. We
  instead clear any existing default in the same transaction before saving, so
  flipping the default is a clean, single API call.
"""

from datetime import timedelta

from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.db.models import Count, Sum
from django.db.models.functions import TruncMonth
from django.utils import timezone
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, serializers, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import AIProviderConfig, AIUsageRecord
from .providers.base import AIProviderError
from .providers.registry import build_provider
from .serializers import AIProviderConfigSerializer


class AIProviderConfigViewSet(viewsets.ModelViewSet):
    """CRUD for per-tenant AI provider configs, plus a connection probe."""

    # drf-spectacular reads the model from here; requests go through get_queryset().
    queryset = AIProviderConfig.objects.none()
    serializer_class = AIProviderConfigSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_fields = ["organization", "enabled", "is_default"]
    search_fields = ["name", "model", "base_url"]
    ordering_fields = ["name", "created_at"]
    ordering = ["name"]

    def get_queryset(self):
        """Only configs for organizations the requesting user belongs to."""
        return AIProviderConfig.objects.filter(
            organization_id__in=self._member_org_ids()
        ).select_related("organization")

    def _member_org_ids(self):
        return set(
            self.request.user.organization_memberships.values_list(
                "organization_id", flat=True
            )
        )

    def _require_member(self, organization) -> None:
        """Reject writes that target an org the user isn't a member of.

        Without this, the unconstrained ``organization`` FK would let a member
        create or move a config into an organization they have no relationship
        with. ``get_queryset`` already hides other orgs' configs on read; this is
        the matching guard on write.
        """
        if organization is None or organization.id not in self._member_org_ids():
            raise PermissionDenied(
                "You can only manage AI providers for organizations you belong to."
            )

    def perform_create(self, serializer):
        organization = serializer.validated_data.get("organization")
        self._require_member(organization)
        self._save_with_key_and_default(serializer, organization)

    def perform_update(self, serializer):
        # On PATCH the org may be absent from the payload; fall back to the
        # existing one so the membership check and default-clearing still target
        # the right tenant.
        organization = serializer.validated_data.get(
            "organization", serializer.instance.organization
        )
        self._require_member(organization)
        self._save_with_key_and_default(serializer, organization)

    def _save_with_key_and_default(self, serializer, organization) -> None:
        """Persist the config, honoring the write-only key and single-default rule.

        ``api_key`` is a write-only serializer field with no model setter, so it
        must be pulled out before the model is saved and applied through
        :meth:`AIProviderConfig.set_api_key`. A blank value means "keep the
        stored key", matching the UI's masked "leave blank to keep" affordance.
        """
        raw_key = serializer.validated_data.pop("api_key", "")
        making_default = serializer.validated_data.get("is_default", False)

        with transaction.atomic():
            if making_default:
                self._clear_other_defaults(
                    organization, exclude_pk=getattr(serializer.instance, "pk", None)
                )
            config = serializer.save()
            if raw_key:
                try:
                    config.set_api_key(raw_key)
                except ImproperlyConfigured as err:
                    # Storing a key needs AI_SECRET_KEY configured on the server.
                    # Surface that as a 400 the operator can act on rather than a
                    # 500; raising here also rolls back the half-saved row.
                    raise serializers.ValidationError({"api_key": str(err)}) from err
                config.save(update_fields=["api_key_encrypted"])

    @staticmethod
    def _clear_other_defaults(organization, *, exclude_pk=None) -> None:
        """Demote any current default in ``organization`` before promoting a new one."""
        others = AIProviderConfig.objects.filter(
            organization=organization, is_default=True
        )
        if exclude_pk is not None:
            others = others.exclude(pk=exclude_pk)
        others.update(is_default=False)

    @action(detail=True, methods=["post"], url_path="test-connection")
    def test_connection(self, request, pk=None):
        """Probe the saved endpoint server-side and report reachability.

        Returns HTTP 200 with ``{ok, detail}`` even when the provider is
        unreachable or misconfigured: a failed probe is an expected, inline-
        displayable outcome ("connection refused — is the server running?"), not
        a server error. The stored key stays on the server throughout.
        """
        config = self.get_object()
        try:
            health = build_provider(config.to_resolved_config()).test_connection()
        except AIProviderError as err:
            # Bad provider_type or an undecryptable key (AI_SECRET_KEY changed) —
            # report the actionable message rather than 500-ing.
            return Response({"ok": False, "detail": str(err)})
        return Response({"ok": health.ok, "detail": health.detail})


# The periods the usage report can be scoped to. Everything but the trend chart
# is filtered to the selected window; "this month" is the default.
USAGE_WINDOWS = ("this_month", "last_month", "last_30_days", "all_time")


class AIUsageSummaryView(APIView):
    """Aggregated AI token/cost usage for one organization.

    Backs the admin "your org spent $X on AI" report. Returns period totals plus
    the breakdowns the page shows (by feature, model, user) and a fixed 12-month
    trend. It is read-only aggregation over :class:`AIUsageRecord` — the heavy
    lifting is ``SUM``/``GROUP BY`` in Postgres, not application code.

    Scope is one organization the caller belongs to, named by an ``organization``
    query param (users can belong to several, so it can't be inferred). A
    ``window`` query param selects the period; it defaults to ``this_month``.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        org_id = self._required_org_id(request)
        window = request.query_params.get("window", "this_month")
        if window not in USAGE_WINDOWS:
            raise ValidationError(
                {"window": f"Must be one of: {', '.join(USAGE_WINDOWS)}."}
            )

        now = timezone.now()
        start, end = _window_range(window, now)
        scoped = AIUsageRecord.objects.filter(organization_id=org_id)
        if start is not None:
            scoped = scoped.filter(created_at__gte=start)
        if end is not None:
            scoped = scoped.filter(created_at__lt=end)

        totals = scoped.aggregate(
            tokens=Sum("total_tokens"), cost=Sum("cost_usd"), calls=Count("id")
        )
        tokens = totals["tokens"] or 0
        calls = totals["calls"] or 0

        return Response(
            {
                "window": window,
                "totals": {
                    "tokens": tokens,
                    "cost": _money(totals["cost"]),
                    "calls": calls,
                    # Integer division is fine — this is a display figure, and
                    # avoids implying false precision on a token count.
                    "avg_tokens_per_call": (tokens // calls) if calls else 0,
                },
                "by_feature": [
                    {
                        "feature": row["feature"],
                        "tokens": row["tokens"],
                        "cost": _money(row["cost"]),
                    }
                    for row in scoped.values("feature")
                    .annotate(tokens=Sum("total_tokens"), cost=Sum("cost_usd"))
                    .order_by("-tokens")
                ],
                "by_model": [
                    {
                        "model": row["model"],
                        "provider_type": row["provider_type"],
                        "tokens": row["tokens"],
                        "cost": _money(row["cost"]),
                    }
                    for row in scoped.values("model", "provider_type")
                    .annotate(tokens=Sum("total_tokens"), cost=Sum("cost_usd"))
                    .order_by("-tokens")
                ],
                "by_user": [
                    {
                        "user_id": row["user_id"],
                        "email": row["user__email"],
                        "tokens": row["tokens"],
                        "cost": _money(row["cost"]),
                    }
                    for row in scoped.values("user_id", "user__email")
                    .annotate(tokens=Sum("total_tokens"), cost=Sum("cost_usd"))
                    .order_by("-tokens")
                ],
                "trend": self._trend(org_id, now),
            }
        )

    def _required_org_id(self, request) -> int:
        """The requested org id, validated to one the caller belongs to."""
        raw = request.query_params.get("organization")
        if not raw:
            raise ValidationError({"organization": "This query parameter is required."})
        try:
            org_id = int(raw)
        except (TypeError, ValueError) as err:
            raise ValidationError({"organization": "Must be an integer id."}) from err
        member_org_ids = request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        if org_id not in set(member_org_ids):
            raise PermissionDenied(
                "You can only view AI usage for organizations you belong to."
            )
        return org_id

    @staticmethod
    def _trend(org_id: int, now) -> list[dict]:
        """Per-month tokens/cost for the last 12 months, ignoring the window.

        The trend is deliberately independent of the summary period so picking
        "this month" doesn't collapse the chart to a single bar.
        """
        # First day of the month 11 months back → 12 inclusive months.
        month = now.month - 11
        year = now.year
        while month <= 0:
            month += 12
            year -= 1
        trend_start = now.replace(
            year=year, month=month, day=1, hour=0, minute=0, second=0, microsecond=0
        )
        rows = (
            AIUsageRecord.objects.filter(
                organization_id=org_id, created_at__gte=trend_start
            )
            .annotate(month=TruncMonth("created_at"))
            .values("month")
            .annotate(tokens=Sum("total_tokens"), cost=Sum("cost_usd"))
            .order_by("month")
        )
        return [
            {
                "month": row["month"].date().isoformat(),
                "tokens": row["tokens"],
                "cost": _money(row["cost"]),
            }
            for row in rows
        ]


def _window_range(window: str, now):
    """Return ``(start, end)`` datetimes for ``window`` (``None`` = unbounded)."""
    if window == "all_time":
        return None, None
    if window == "last_30_days":
        return now - timedelta(days=30), None
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if window == "last_month":
        prev_month_end = month_start
        prev_month_start = (month_start - timedelta(days=1)).replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )
        return prev_month_start, prev_month_end
    # this_month
    return month_start, None


def _money(value):
    """Render an aggregated ``cost_usd`` for JSON: float, or ``None`` if unpriced.

    A ``NULL`` sum means every row in the group was self-hosted (unpriced), which
    the UI shows as "—" rather than ``$0`` — distinct from a real zero cost.
    """
    return float(value) if value is not None else None
