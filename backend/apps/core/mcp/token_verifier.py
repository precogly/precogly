"""Verify the bearer tokens `/mcp` receives.

The endpoint runs inside this process, so verifying a token is a database read rather
than a call to `/o/introspect/`, and needs no credential of its own.
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
        # By checksum, not value: `token_checksum` is the indexed column, and
        # django-oauth-toolkit's own introspection matches on it.
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

        # Tools always act as a user, so a token naming none (client credentials) is
        # refused.
        #
        # `is_valid()` covers expiry and scope but not `is_active`. Measured on the dev
        # stack: a disabled account's OAuth token still got 200 from
        # `/api/threat-models/` while its JWT got 401, because simplejwt checks
        # `is_active` and `validate_bearer_token` does not. The REST side needs its own
        # fix in the authentication classes.
        if stored.user is None or not stored.user.is_active:
            return None

        # RFC 8707, a MUST in the MCP specification: accept only tokens issued for
        # this resource. Not `stored.allows_audience()`: it returns True for a token
        # with no resource indicator, the case this check exists to refuse, and it
        # matches by URL prefix, so a token issued for the origin would pass.
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
