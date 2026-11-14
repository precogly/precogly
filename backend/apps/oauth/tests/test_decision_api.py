from datetime import timedelta
from urllib.parse import parse_qs, urlparse

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_grant_model,
)
from rest_framework_simplejwt.tokens import RefreshToken

from apps.oauth.models import MAX_PASSWORD_ATTEMPTS, PendingAuthorization

User = get_user_model()
Application = get_application_model()
AccessToken = get_access_token_model()
Grant = get_grant_model()

REDIRECT = "http://127.0.0.1:33418/callback"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSW_bLlY"
PASSWORD = "testpass123"


def jwt_header(user):
    return {"HTTP_AUTHORIZATION": f"Bearer {RefreshToken.for_user(user).access_token}"}


class TestDecidingAPendingAuthorization(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            username="consenter", email="consenter@test.org", password=PASSWORD
        )
        cls.other_user = User.objects.create_user(
            username="bystander", email="bystander@test.org", password=PASSWORD
        )
        cls.application = Application.objects.create(
            name="Claude Code",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris=REDIRECT,
        )

    def setUp(self):
        # Bound to `user`, as reading the handle would leave it.
        self.pending = PendingAuthorization.objects.create(
            application=self.application,
            user=self.user,
            redirect_uri=REDIRECT,
            response_type="code",
            state="opaque-state",
            code_challenge=CHALLENGE,
            code_challenge_method="S256",
            scopes="read",
        )
        self.url = reverse("pending-authorization-decision", args=[self.pending.id])

    def decide(self, user=None, **body):
        return self.client.post(
            self.url,
            body,
            content_type="application/json",
            **jwt_header(user or self.user),
        )

    def redirect_query(self, response):
        url = response.json()["redirectUrl"]
        assert url.startswith(REDIRECT)
        return parse_qs(urlparse(url).query)

    def test_allowing_with_the_password_issues_a_code_to_the_user(self):
        response = self.decide(allow=True, password=PASSWORD)

        assert response.status_code == 200
        query = self.redirect_query(response)
        assert query["state"] == ["opaque-state"]
        grant = Grant.objects.get(code=query["code"][0])
        assert grant.user == self.user
        assert grant.code_challenge == CHALLENGE
        self.pending.refresh_from_db()
        assert self.pending.used

    def test_denying_sends_access_denied_without_asking_for_the_password(self):
        response = self.decide(allow=False)

        assert response.status_code == 200
        query = self.redirect_query(response)
        assert query["error"] == ["access_denied"]
        assert query["state"] == ["opaque-state"]
        assert not Grant.objects.exists()
        self.pending.refresh_from_db()
        assert self.pending.used

    def test_allowing_without_a_password_is_refused_and_not_counted(self):
        response = self.decide(allow=True)

        assert response.status_code == 400
        self.pending.refresh_from_db()
        assert self.pending.failed_password_attempts == 0
        assert not self.pending.used

    def test_a_wrong_password_is_counted_and_the_request_survives(self):
        response = self.decide(allow=True, password="wrong")

        assert response.status_code == 400
        self.pending.refresh_from_db()
        assert self.pending.failed_password_attempts == 1
        assert not self.pending.used
        assert self.decide(allow=True, password=PASSWORD).status_code == 200

    def test_the_last_allowed_wrong_password_uses_up_the_request(self):
        for _ in range(MAX_PASSWORD_ATTEMPTS):
            assert self.decide(allow=True, password="wrong").status_code == 400

        assert self.decide(allow=True, password=PASSWORD).status_code == 404
        assert not Grant.objects.exists()

    def test_a_request_takes_one_decision(self):
        self.decide(allow=False)

        assert self.decide(allow=True, password=PASSWORD).status_code == 404

    def test_another_user_cannot_decide(self):
        response = self.decide(user=self.other_user, allow=True, password=PASSWORD)

        assert response.status_code == 404

    def test_a_handle_nobody_has_read_cannot_be_decided(self):
        # Binding happens on read, so the page must show the request before the user
        # can approve it.
        self.pending.user = None
        self.pending.save()

        assert self.decide(allow=True, password=PASSWORD).status_code == 404

    def test_an_expired_request_cannot_be_decided(self):
        self.pending.expires_at = timezone.now() - timedelta(seconds=1)
        self.pending.save()

        assert self.decide(allow=True, password=PASSWORD).status_code == 404

    def test_an_mcp_access_token_cannot_decide(self):
        token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token="mcp-access-token",
            scope="read",
            expires=timezone.now() + timedelta(hours=1),
        )

        response = self.client.post(
            self.url,
            {"allow": True, "password": PASSWORD},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token.token}",
        )

        assert response.status_code == 403
        assert not Grant.objects.exists()
