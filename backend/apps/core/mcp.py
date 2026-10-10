"""Precogly's side of the mounted MCP endpoint.

The MCP server is a resource server: it accepts a bearer token a user granted in a
browser and acts as that user. It runs inside this process, so verification is a
database read rather than a network call to `/o/introspect/` — which is also why it
needs no credential of its own to perform it.

`precogly_mcp` knows nothing about any of this. It defines two seams and Precogly fills
both here, which is why they share a module:

```text
  precogly_mcp defines          this module supplies       and so the tool sees
  --------------------          --------------------       --------------------
  TokenVerifier                 DjangoAccessTokenVerifier  a resolved user
  PrecoglyReader (access.py)    ORMReader                  rows, as that user
```

Nothing else in Precogly knows that MCP tokens live in django-oauth-toolkit's tables, and
nothing in `precogly_mcp` imports Django.
"""

from __future__ import annotations

import hashlib
from typing import Any

from asgiref.sync import sync_to_async
from django.contrib.auth import get_user_model
from django.db.models import Prefetch
from mcp.server.auth.provider import AccessToken
from oauth2_provider.models import get_access_token_model
from precogly_mcp.access import Listing, PrecoglyReader

from apps.systems.models import ComponentLibrary
from apps.systems.serializers import ComponentLibrarySerializer
from apps.threat_models.models import ThreatModel
from apps.threat_models.serializers import ThreatModelListSerializer
from apps.threats.models import (
    CountermeasureLibrary,
    ThreatLibrary,
    ThreatLibraryTaxonomyEntry,
)
from apps.threats.serializers import (
    CountermeasureLibraryListSerializer,
    ThreatLibraryListSerializer,
)


class DjangoAccessTokenVerifier:
    """Resolve a bearer token against django-oauth-toolkit's access tokens.

    Returning `None` is how the SDK is told to answer 401, so every rejection path
    returns it rather than raising.
    """

    def __init__(self, resource_url: str) -> None:
        self.resource_url = resource_url

    async def verify_token(self, token: str) -> AccessToken | None:
        return await sync_to_async(self._verify, thread_sensitive=True)(token)

    def _verify(self, token: str) -> AccessToken | None:
        # Tokens are looked up by checksum, not by value: `token_checksum` is the
        # indexed column, and it is what django-oauth-toolkit's own introspection
        # endpoint matches on.
        checksum = hashlib.sha256(token.encode("utf-8")).hexdigest()
        try:
            stored = (
                get_access_token_model()
                .objects.select_related("user", "application")
                .get(token_checksum=checksum)
            )
        except get_access_token_model().DoesNotExist:
            return None

        if not stored.is_valid():
            return None

        # Every tool reads as a user and nothing here has an application-only meaning,
        # so a token naming no user — one issued by client credentials — is refused
        # rather than resolved to nobody. That also makes `subject` below always set.
        #
        # `is_active` is checked here rather than left to `is_valid()`, which is
        # django-oauth-toolkit's and covers expiry and scope. Disabling an account is
        # how access is taken away in practice, and django-oauth-toolkit does not
        # notice: measured against the dev stack, a disabled account's OAuth token
        # still returns 200 from `/api/threat-models/` while its JWT returns 401 "User
        # is inactive", because simplejwt checks and `validate_bearer_token` does not.
        # The REST API side of that is Precogly's to fix in its authentication classes;
        # this endpoint authenticates here, so this is where it belongs.
        if stored.user is None or not stored.user.is_active:
            return None

        # RFC 8707, which the MCP specification makes a MUST: a token is only
        # acceptable here if it was issued for this resource. The comparison is
        # deliberately not `stored.allows_audience()`, on two counts. That helper
        # returns True for a token carrying no resource indicator at all, which is
        # the case this check exists to refuse; and it matches by URL prefix, so a
        # token issued for the origin would satisfy it. Exact membership is what the
        # audience of this endpoint means.
        audiences = stored.resource or []
        if self.resource_url not in audiences:
            return None

        return AccessToken(
            token=token,
            client_id=stored.application.client_id if stored.application else "",
            scopes=stored.scope.split(),
            expires_at=int(stored.expires.timestamp()) if stored.expires else None,
            resource=self.resource_url,
            # This is the authorization boundary, not a log field. The token is
            # spent here and never again — `mcp_mount` hands this `AccessToken` to
            # the reader it supplies, and every row a tool sees is scoped to the
            # user named below. Unconditional: a token with no user was refused
            # above, so a resolved token always names one.
            subject=str(stored.user_id),
        )


class ORMReader:
    """Everything the tools read, as one user, without leaving the process.

    Forwarding the caller's token to Precogly's own REST API is the alternative, and it
    cannot work: the token is audience-bound to `/mcp` under RFC 8707, so
    django-oauth-toolkit refuses it at `/api/` by construction. What crosses into the
    data is the user, not the credential.

    Rows come from the same DRF serializers the REST API renders, so both transports
    produce the same shapes and the projection stays in one place. The serializers emit
    snake_case — `djangorestframework_camel_case` is a renderer, applied after this
    point — and the projection models set `populate_by_name`, so it validates either way.

    Holds a user id rather than a user, because `reader_for` runs inside the event loop
    where a query raises `SynchronousOnlyOperation`. The account is loaded in the same
    `sync_to_async` call that reads the rows, `thread_sensitive=True` as the verifier
    does, since Django's ORM is not async.
    """

    def __init__(self, user_id: int) -> None:
        self._user_id = user_id

    def _user(self):
        """The account this call acts as.

        `get` rather than `filter(...).first()`: the verifier accepted a token naming
        this user moments ago and `AccessToken.user` cascades on delete, so a missing row
        is a broken invariant rather than a caller error to answer politely.
        """
        return get_user_model().objects.get(pk=self._user_id)

    async def threat_models(self, organization_id: int | None = None) -> Listing:
        return await sync_to_async(self._threat_models, thread_sensitive=True)(
            organization_id
        )

    def _threat_models(self, organization_id: int | None) -> Listing:
        # `visible_to` is the read boundary, shared with `ThreatModelViewSet` so that
        # who-sees-what has one definition. `for_listing` is the viewset's list
        # queryset too: everything the list serializer reads, in a fixed number of
        # queries.
        queryset = ThreatModel.objects.visible_to(self._user()).for_listing()

        # Narrowing an already-scoped queryset, so an organization the caller cannot read
        # comes back empty. The REST filter answers differently — it validates against
        # every organization, which separates "not yours" from "no such id"
        # (precogly/precogly#259) — and empty is the better of the two answers.
        if organization_id is not None:
            queryset = queryset.filter(organization_id=organization_id)

        # Ordered explicitly though `ThreatModel.Meta.ordering` agrees: the tool's
        # description promises most-recently-updated first, and a default is not a
        # promise.
        rows = ThreatModelListSerializer(
            queryset.order_by("-updated_at"), many=True
        ).data

        # `total` equals the number of rows here and differs only over HTTP, where one
        # DRF page is all a reader can ask for. Nothing is truncated: there is no
        # measured budget to truncate to, and the twenty a page holds was DRF's default
        # rather than a decision.
        return Listing(rows=list(rows), total=len(rows))

    async def threat_library(self) -> list[dict[str, Any]]:
        return await sync_to_async(self._threat_library, thread_sensitive=True)()

    def _threat_library(self) -> list[dict[str, Any]]:
        # None of the three catalogs is scoped to the caller: the rows belong to no
        # organization, and every organization reads the same ones.
        #
        # The prefetch mirrors `ThreatLibraryViewSet.get_queryset` and is not an
        # optimisation to take or leave. `get_taxonomy_entries` walks the join rows and
        # then each entry and its taxonomy, which without it is queries per row across
        # the whole catalog.
        queryset = (
            ThreatLibrary.objects.select_related("source_pack")
            .prefetch_related(
                Prefetch(
                    "taxonomy_entries",
                    queryset=ThreatLibraryTaxonomyEntry.objects.select_related(
                        "taxonomy_entry__taxonomy"
                    ),
                )
            )
            .order_by("name")
        )
        return list(ThreatLibraryListSerializer(queryset, many=True).data)

    async def countermeasure_library(self) -> list[dict[str, Any]]:
        return await sync_to_async(
            self._countermeasure_library, thread_sensitive=True
        )()

    def _countermeasure_library(self) -> list[dict[str, Any]]:
        queryset = CountermeasureLibrary.objects.select_related("source_pack").order_by(
            "name"
        )
        return list(CountermeasureLibraryListSerializer(queryset, many=True).data)

    async def component_library(self) -> list[dict[str, Any]]:
        return await sync_to_async(self._component_library, thread_sensitive=True)()

    def _component_library(self) -> list[dict[str, Any]]:
        # This route has no list serializer — the viewset declares `serializer_class`
        # outright — so the rows carry timestamps the projection drops.
        queryset = ComponentLibrary.objects.select_related("source_pack").order_by(
            "name"
        )
        return list(ComponentLibrarySerializer(queryset, many=True).data)


def reader_for(access_token: AccessToken | None) -> PrecoglyReader:
    """Build the reader for whoever made this call.

    Called per request and inside the event loop, so it does no database work — see
    `ORMReader`. `access_token` is what `DjangoAccessTokenVerifier` returned, and its
    `subject` is always set, since a token naming no user is refused there.
    """
    if access_token is None or access_token.subject is None:
        # Unreachable through the endpoint, which authenticates before any tool runs.
        # Raising names the wiring mistake, where returning an empty reader would let it
        # surface as an empty listing that reads like an answer.
        raise RuntimeError("MCP tool call reached the reader without a resolved user")

    return ORMReader(int(access_token.subject))
