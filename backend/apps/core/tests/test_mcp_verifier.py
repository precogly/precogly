"""Which tokens `/mcp` accepts, and which it refuses.

`DjangoAccessTokenVerifier` is the endpoint's authorization boundary: it turns a
bearer string into a user id, and every row a tool later reads is scoped to that id.
Returning `None` is how the SDK is told to answer 401, so each refusal below is an
assertion that `verify_token` returned nothing.

The audience cases walk the real authorization flow rather than building an
`AccessToken` row directly. The check they exist for is that a `resource` parameter
sent at `/o/authorize/` survives into the column this verifier reads — a constructed
row would still satisfy the test if django-oauth-toolkit stopped persisting it. The
remaining refusals use built rows, since no flow produces a token naming no user.

The audience is a literal here rather than `settings.MCP_RESOURCE_URL`. What is
pinned is the verifier's behaviour for whatever audience it was constructed with;
that the advertised and enforced values agree is structural, since `config.mcp_mount`
passes one variable to both consumers.

`verify_token` is async and does its ORM work under
`sync_to_async(thread_sensitive=True)`, so `async_to_sync` keeps it on the calling
thread and inside this TestCase's transaction — the same arrangement
`test_mcp_reader` documents.
"""

import base64
import hashlib
import json
import secrets
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

from asgiref.sync import async_to_sync
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from oauth2_provider.models import (
    get_access_token_model,
    set_token_value,
)

from apps.core.mcp import DjangoAccessTokenVerifier

User = get_user_model()
AccessToken = get_access_token_model()

RESOURCE = "https://precogly.example/mcp"
ORIGIN = "https://precogly.example"
REGISTERED_REDIRECT = "http://localhost:33418/callback"


def verify(token, resource=RESOURCE):
    return async_to_sync(DjangoAccessTokenVerifier(resource).verify_token)(token)


class AnIssuedTokensAudience(TestCase):
    """`resource` at authorize, `resource` on the row, accepted here — or not."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            username="mcpclient", email="mcp-client@test.org", password="testpass123"
        )

    def setUp(self):
        self.client.force_login(self.user)
        self.client_id = self.client.post(
            reverse("oauth2_provider:dcr-register"),
            data=json.dumps(
                {
                    "client_name": "Claude Code",
                    "redirect_uris": [REGISTERED_REDIRECT],
                    "grant_types": ["authorization_code"],
                    "token_endpoint_auth_method": "none",
                }
            ),
            content_type="application/json",
        ).json()["client_id"]

        self.verifier = secrets.token_urlsafe(64)
        self.challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )

    def token_for(self, resource=None):
        """Walk login → consent → code → token, and return the raw access token.

        `resource` is sent at the authorization endpoint only. RFC 8707 lets the
        token request narrow the audience but never widen it, so omitting it there
        makes the grant's value carry through unchanged — which is what a client
        that asks for one resource actually does.
        """
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": REGISTERED_REDIRECT,
            "scope": "read",
            "state": "opaque-state",
            "code_challenge": self.challenge,
            "code_challenge_method": "S256",
        }
        if resource is not None:
            params["resource"] = resource

        self.client.get(reverse("oauth2_provider:authorize"), params)
        consent = self.client.post(
            reverse("oauth2_provider:authorize"), {**params, "allow": "Authorize"}
        )
        code = parse_qs(urlparse(consent.headers["Location"]).query)["code"][0]

        return self.client.post(
            reverse("oauth2_provider:token"),
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REGISTERED_REDIRECT,
                "client_id": self.client_id,
                "code_verifier": self.verifier,
            },
        ).json()["access_token"]

    def test_a_token_issued_for_this_resource_resolves_to_its_user(self):
        resolved = verify(self.token_for(RESOURCE))

        assert resolved is not None
        # `subject` is the authorization boundary rather than a log field: tools act
        # as this user.
        assert resolved.subject == str(self.user.pk)
        assert resolved.scopes == ["read"]

    def test_a_token_issued_without_a_resource_is_refused(self):
        # The case the check exists for, and the reason `apps.core.mcp` compares
        # audiences itself: `AccessToken.allows_audience()` returns True for an empty
        # `resource` list, treating an unbound token as valid for everything. RFC 8707
        # is a MUST in the MCP specification, so an audience nobody asked for is not
        # one this endpoint grants.
        assert verify(self.token_for()) is None

    def test_a_token_for_the_origin_does_not_reach_a_path_below_it(self):
        # The second reason for the hand-written comparison. django-oauth-toolkit's
        # default resource validator matches by URL prefix, so an audience of
        # `https://precogly.example` would admit a request to any path under it.
        # Exact membership is what the audience of this endpoint means.
        assert verify(self.token_for(ORIGIN)) is None


class TheOtherRefusals(TestCase):
    """Rejections no authorization flow produces, so the rows are built directly."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            username="mcpclient", email="mcp-client@test.org", password="testpass123"
        )

    def issue(self, raw, *, user, expires=None, resource=(RESOURCE,)):
        """An access token row as django-oauth-toolkit would store one.

        `set_token_value` rather than assigning `token`: the verifier looks rows up by
        `token_checksum`, which is derived here and is the only column populated when
        RFC 9700 token-storage redaction is on.
        """
        token = AccessToken(
            user=user,
            scope="read",
            expires=expires or (timezone.now() + timedelta(hours=1)),
            resource=list(resource),
        )
        set_token_value(token, raw)
        token.save()
        return raw

    def test_a_token_that_was_never_issued_is_refused(self):
        assert verify(secrets.token_urlsafe(30)) is None

    def test_an_expired_token_is_refused(self):
        raw = self.issue(
            secrets.token_urlsafe(30),
            user=self.user,
            expires=timezone.now() - timedelta(seconds=1),
        )

        assert verify(raw) is None

    def test_a_token_naming_no_user_is_refused(self):
        # A client-credentials token resolves to no one. Every tool reads as a user
        # and none has an application-only meaning, so this is refused rather than
        # resolved to nobody — which is also what makes `subject` unconditional.
        raw = self.issue(secrets.token_urlsafe(30), user=None)

        assert verify(raw) is None

    def test_a_disabled_account_is_refused(self):
        # `is_active` is checked here rather than left to `AccessToken.is_valid()`,
        # which covers expiry and scope and not this. Disabling an account is how
        # access is withdrawn in practice, and a token outliving the account it names
        # would keep working until it expired.
        raw = self.issue(secrets.token_urlsafe(30), user=self.user)
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        assert verify(raw) is None
