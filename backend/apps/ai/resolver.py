"""Decide *which* provider a request should use, and build it.

This is the one place that knows the precedence rule for "bring your own model":

1. the organization's own enabled default config, if it has one;
2. otherwise the operator-wide ``AI_*`` settings, if AI is enabled there;
3. otherwise nothing — AI is off for this context.

Keeping that rule here means callers (the suggest feature, future features) ask
for "a provider for this org" and stay ignorant of tenancy, settings, and
adapters. Switching a tenant onto its own model, or changing the fallback, never
touches them.
"""

from django.conf import settings

from .providers.base import AIDisabledError, ChatProvider, Completion, ResolvedConfig
from .providers.registry import build_provider


def settings_default_config() -> ResolvedConfig | None:
    """The operator-wide fallback provider from ``AI_*`` settings.

    Returns ``None`` when the operator hasn't enabled AI, so the resolver can
    treat "no fallback" and "no org config" uniformly. This is what keeps a
    zero-database dev setup working: set the env vars and every org inherits it.
    """
    if not settings.AI_SUGGESTIONS_ENABLED:
        return None
    return ResolvedConfig(
        provider_type="openai_compat",
        base_url=settings.AI_BASE_URL,
        model=settings.AI_MODEL,
        api_key=settings.AI_API_KEY,
        request_timeout=settings.AI_REQUEST_TIMEOUT,
    )


def resolve_config(organization) -> ResolvedConfig:
    """Return the :class:`ResolvedConfig` that should serve ``organization``.

    Raises :class:`AIDisabledError` when neither the org nor the operator
    fallback provides one — the API layer turns that into a clear "not enabled"
    response rather than an outage.
    """
    org_config = None
    if organization is not None:
        # Imported lazily so this module stays importable without the app
        # registry being ready (e.g. at settings-validation time).
        from .models import AIProviderConfig

        # The one-default-per-org constraint guarantees at most one match, so
        # .first() is unambiguous without an explicit ordering.
        org_config = AIProviderConfig.objects.filter(
            organization=organization, enabled=True, is_default=True
        ).first()

    if org_config is not None:
        return org_config.to_resolved_config()

    fallback = settings_default_config()
    if fallback is not None:
        return fallback

    raise AIDisabledError(
        "AI features are not configured for this organization. Add an AI "
        "provider, or set AI_SUGGESTIONS_ENABLED with AI_BASE_URL/AI_MODEL."
    )


class MeteringProvider(ChatProvider):
    """Wraps a real provider and records token usage for every completion.

    The wrapper is how usage tracking stays out of both the generic adapters
    (which must not know about orgs or features) and the feature code (which
    would otherwise have to remember to meter every call). A feature asks
    :func:`resolve_provider` for "a provider for this org, for *this* feature"
    and gets one of these; calling ``complete`` transparently appends an
    :class:`~apps.ai.models.AIUsageRecord`. Health probes pass straight through.
    """

    def __init__(self, inner: ChatProvider, *, organization, feature, user=None):
        super().__init__(inner.config)
        self._inner = inner
        self._organization = organization
        self._feature = feature
        self._user = user

    def complete(
        self, messages, *, temperature=0.2, force_json=True, max_tokens=4096
    ) -> Completion:
        completion = self._inner.complete(
            messages,
            temperature=temperature,
            force_json=force_json,
            max_tokens=max_tokens,
        )
        self._record(completion)
        return completion

    def test_connection(self):
        return self._inner.test_connection()

    def price_for(self, usage):
        return self._inner.price_for(usage)

    def _record(self, completion: Completion) -> None:
        # No usage block means the server didn't report counts — there's nothing
        # honest to record, so we skip rather than write a misleading zero row.
        usage = completion.usage
        if usage is None:
            return

        # Imported lazily so importing the resolver never requires the app
        # registry, matching resolve_config's handling of the same model module.
        from .models import AIUsageRecord

        config = self.config
        AIUsageRecord.objects.create(
            organization=self._organization,
            provider_config_id=config.config_id,
            feature=self._feature,
            model=config.model,
            provider_type=config.provider_type,
            user=self._user,
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            total_tokens=usage.total_tokens,
            cost_usd=self._inner.price_for(usage),
        )


def resolve_provider(organization, *, feature=None, user=None):
    """Build a ready-to-call :class:`~apps.ai.providers.base.ChatProvider`.

    Pass ``feature`` (and optionally the ``user`` who triggered it) to get a
    :class:`MeteringProvider` that records token usage per call. Without a
    ``feature`` — or for an org-less context, where a per-tenant usage row would
    be meaningless — the raw provider is returned unmetered.
    """
    provider = build_provider(resolve_config(organization))
    if feature is None or organization is None:
        return provider
    return MeteringProvider(
        provider, organization=organization, feature=feature, user=user
    )


def organization_for_component(component):
    """Find the organization that owns ``component``.

    A component reaches its org through its blueprint's threat model, mirroring
    ``apps.core.permissions._get_organization``. A user may belong to many
    orgs, but a component belongs to exactly one, so this (not the caller's
    membership list) is the correct tenant for resolving a provider.
    """
    if getattr(component, "blueprint_id", None):
        return component.blueprint.threat_model.organization
    return None


def resolve_provider_for_component(component, *, feature=None, user=None):
    """Convenience: resolve the provider for ``component``'s organization.

    Forwards ``feature``/``user`` so a feature call against a component is metered
    under the component's owning organization.
    """
    return resolve_provider(
        organization_for_component(component), feature=feature, user=user
    )
