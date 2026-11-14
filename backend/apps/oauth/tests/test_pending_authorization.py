from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from oauth2_provider.models import get_application_model, get_grant_model
from oauth2_provider.oauth2_backends import get_oauthlib_core

from apps.oauth.models import PendingAuthorization

User = get_user_model()
Application = get_application_model()
Grant = get_grant_model()

REDIRECT = "http://localhost:33418/callback"
# A fixed S256 challenge. The tests never redeem the code, so its verifier is not needed.
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSW_bLlY"


class TestPendingAuthorization(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            username="consenter", email="consenter@test.org", password="testpass123"
        )
        cls.application = Application.objects.create(
            name="Claude Code",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris=REDIRECT,
        )

    def validate(self):
        """Runs django-oauth-toolkit's validation on an authorize GET, as the view would."""
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self.application.client_id,
                "redirect_uri": REDIRECT,
                "scope": "read",
                "state": "opaque-state",
                "code_challenge": CHALLENGE,
                "code_challenge_method": "S256",
                "resource": settings.MCP_RESOURCE_URL,
            }
        )
        request = RequestFactory().get(f"/o/authorize/?{query}")
        scopes, credentials = get_oauthlib_core().validate_authorization_request(
            request
        )
        return scopes, credentials, request.GET.getlist("resource")

    def test_the_stored_request_comes_back_as_it_was_validated(self):
        # Runs the real validation, so an oauthlib upgrade that adds a key fails here
        # before it fails an authorization.
        scopes, credentials, resource = self.validate()
        PendingAuthorization.from_validated(scopes, credentials, resource).save()

        stored = PendingAuthorization.objects.get()
        expected = {
            key: value for key, value in credentials.items() if key != "request"
        }
        assert stored.credentials() == {**expected, "resource": resource}

    def test_the_stored_request_issues_a_grant_with_its_resource(self):
        # The decision arrives in a separate request, so this drives the toolkit's two
        # calls apart, with nothing carried between them except the stored row.
        scopes, credentials, resource = self.validate()
        handle = PendingAuthorization.from_validated(scopes, credentials, resource)
        handle.save()

        stored = PendingAuthorization.objects.get(id=handle.id)
        decision = RequestFactory().post("/o/authorize/")
        decision.user = self.user
        uri, _, _, _ = get_oauthlib_core().create_authorization_response(
            decision,
            scopes=stored.scopes.split(),
            credentials=stored.credentials(),
            allow=True,
        )

        code = parse_qs(urlparse(uri).query)["code"][0]
        grant = Grant.objects.get(code=code)
        assert grant.user == self.user
        assert grant.code_challenge == CHALLENGE
        assert grant.resource == [settings.MCP_RESOURCE_URL]

    def test_an_unknown_key_is_refused(self):
        scopes, credentials, resource = self.validate()

        with pytest.raises(ValueError, match="unknown: \\['nonce'\\]"):
            PendingAuthorization.from_validated(
                scopes, {**credentials, "nonce": "n-0S6_WzA2Mj"}, resource
            )
