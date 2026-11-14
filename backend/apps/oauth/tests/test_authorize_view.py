from urllib.parse import parse_qs, urlencode, urlparse

from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory, TestCase
from oauth2_provider.models import get_application_model

from apps.oauth.models import PendingAuthorization
from apps.oauth.views import AuthorizeView

Application = get_application_model()

REDIRECT = "http://localhost:33418/callback"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSW_bLlY"


class TestAuthorizeView(TestCase):
    # The view is not routed until the consent page exists, so these call it directly.

    @classmethod
    def setUpTestData(cls):
        cls.application = Application.objects.create(
            name="Claude Code",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris=REDIRECT,
        )

    def authorize(self, **overrides):
        params = {
            "response_type": "code",
            "client_id": self.application.client_id,
            "redirect_uri": REDIRECT,
            "scope": "read",
            "state": "opaque-state",
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
            "resource": settings.MCP_RESOURCE_URL,
            **overrides,
        }
        request = RequestFactory().get(f"/o/authorize/?{urlencode(params)}")
        request.user = AnonymousUser()
        return AuthorizeView.as_view()(request)

    def test_a_signed_out_user_is_sent_to_the_consent_page_with_a_handle(self):
        response = self.authorize()

        assert response.status_code == 302
        location = urlparse(response["Location"])
        assert f"{location.scheme}://{location.netloc}" == settings.FRONTEND_URL
        assert location.path == "/oauth/consent"
        handle = parse_qs(location.query)["id"][0]
        stored = PendingAuthorization.objects.get(id=handle)
        assert stored.application == self.application
        assert stored.user is None
        assert stored.resource == [settings.MCP_RESOURCE_URL]

    def test_an_unknown_client_gets_an_error_page_and_no_redirect(self):
        # With no valid client there is no trusted redirect_uri, so redirecting would
        # send the browser wherever the request said.
        response = self.authorize(client_id="not-a-client")

        assert response.status_code == 400
        assert not PendingAuthorization.objects.exists()

    def test_a_malformed_resource_goes_back_to_the_client(self):
        response = self.authorize(resource="not-a-uri")

        assert response.status_code == 302
        query = parse_qs(urlparse(response["Location"]).query)
        assert response["Location"].startswith(REDIRECT)
        assert query["error"] == ["invalid_target"]
        assert query["state"] == ["opaque-state"]
        assert not PendingAuthorization.objects.exists()
