from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from oauth2_provider.models import get_access_token_model, get_application_model
from rest_framework_simplejwt.tokens import RefreshToken

from apps.core.mcp.api import dispatch
from apps.oauth.models import PendingAuthorization

User = get_user_model()
Application = get_application_model()
AccessToken = get_access_token_model()

REDIRECT = "http://127.0.0.1:33418/callback"


def jwt_header(user):
    return {"HTTP_AUTHORIZATION": f"Bearer {RefreshToken.for_user(user).access_token}"}


class TestReadingAPendingAuthorization(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            username="consenter", email="consenter@test.org", password="testpass123"
        )
        cls.other_user = User.objects.create_user(
            username="bystander", email="bystander@test.org", password="testpass123"
        )
        cls.application = Application.objects.create(
            name="Claude Code",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris=REDIRECT,
        )

    def setUp(self):
        self.pending = PendingAuthorization.objects.create(
            application=self.application,
            redirect_uri=REDIRECT,
            response_type="code",
            state="opaque-state",
            scopes="read write",
        )
        self.url = reverse("pending-authorization", args=[self.pending.id])

    def test_the_first_reader_gets_the_request_and_is_bound_to_it(self):
        response = self.client.get(self.url, **jwt_header(self.user))

        assert response.status_code == 200
        assert response.json() == {
            "clientName": "Claude Code",
            "scopes": [
                {
                    "name": "read",
                    "description": "Read your threat models, diagrams and installed "
                    "libraries",
                },
                {
                    "name": "write",
                    "description": "Create and change threat models on your behalf",
                },
            ],
            "redirectUri": REDIRECT,
            "loopbackRedirect": True,
        }
        self.pending.refresh_from_db()
        assert self.pending.user == self.user

    def test_the_bound_user_can_read_it_again(self):
        self.client.get(self.url, **jwt_header(self.user))

        assert self.client.get(self.url, **jwt_header(self.user)).status_code == 200

    def test_another_user_gets_a_404_once_it_is_bound(self):
        self.client.get(self.url, **jwt_header(self.user))

        assert (
            self.client.get(self.url, **jwt_header(self.other_user)).status_code == 404
        )

    def test_an_expired_request_is_a_404(self):
        self.pending.expires_at = timezone.now() - timedelta(seconds=1)
        self.pending.save()

        assert self.client.get(self.url, **jwt_header(self.user)).status_code == 404

    def test_a_used_request_is_a_404(self):
        self.pending.used = True
        self.pending.save()

        assert self.client.get(self.url, **jwt_header(self.user)).status_code == 404

    def test_an_unknown_handle_is_a_404(self):
        url = reverse("pending-authorization", args=["not-a-handle"])

        assert self.client.get(url, **jwt_header(self.user)).status_code == 404

    def test_an_mcp_access_token_is_refused(self):
        token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token="mcp-access-token",
            scope="read",
            expires=timezone.now() + timedelta(hours=1),
        )

        response = self.client.get(self.url, HTTP_AUTHORIZATION=f"Bearer {token.token}")

        assert response.status_code == 403
        self.pending.refresh_from_db()
        assert self.pending.user is None

    def test_code_mode_is_refused(self):
        # `dispatch` forces authentication past the view's own classes, so this is the
        # path a JWT-only `authentication_classes` would not have stopped.
        status, _ = dispatch(self.user, "GET", self.url)

        assert status == 403
        self.pending.refresh_from_db()
        assert self.pending.user is None
