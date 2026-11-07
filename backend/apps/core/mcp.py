"""Precogly's side of the mounted MCP endpoint: the token verifier.

The endpoint runs inside this process, so verifying a bearer token is a database read
rather than a call to `/o/introspect/`, and needs no credential of its own.
"""

from __future__ import annotations

import hashlib

from asgiref.sync import sync_to_async
from mcp.server.auth.provider import AccessToken
from oauth2_provider.models import get_access_token_model


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
            # The authorization boundary, not a log field: tools act as this user.
            # Always set, since a token naming no user was refused above.
            subject=str(stored.user_id),
        )
