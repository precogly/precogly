from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_refresh_token_model,
)
from rest_framework_simplejwt.tokens import RefreshToken as JWTRefreshToken

User = get_user_model()
Application = get_application_model()
AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()


def jwt_header(user):
    return {
        "HTTP_AUTHORIZATION": f"Bearer {JWTRefreshToken.for_user(user).access_token}"
    }


class TestAuthorizedApplications(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            username="owner", email="owner@test.org", password="testpass123"
        )
        cls.other_user = User.objects.create_user(
            username="bystander", email="bystander@test.org", password="testpass123"
        )
        cls.claude = Application.objects.create(
            name="Claude Code",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="http://127.0.0.1:33418/callback",
        )
        cls.opencode = Application.objects.create(
            name="opencode",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="http://127.0.0.1:53001/callback",
        )

    def issue(
        self, application, user=None, expires_in=timedelta(hours=1), refresh=True
    ):
        user = user or self.user
        access = AccessToken.objects.create(
            user=user,
            application=application,
            token=f"access-{application.pk}-{user.pk}-{AccessToken.objects.count()}",
            scope="read",
            expires=timezone.now() + expires_in,
        )
        if refresh:
            RefreshToken.objects.create(
                user=user,
                application=application,
                token=f"refresh-{access.token}",
                access_token=access,
            )
        return access

    def authorized(self, user=None):
        response = self.client.get(
            reverse("authorized-applications"), **jwt_header(user or self.user)
        )
        assert response.status_code == 200
        return response.json()

    def test_a_client_holding_a_token_is_listed_with_its_scopes(self):
        self.issue(self.claude)

        [entry] = self.authorized()

        assert entry["id"] == self.claude.pk
        assert entry["name"] == "Claude Code"
        assert [scope["name"] for scope in entry["scopes"]] == ["read"]
        assert entry["registeredAt"]
        assert entry["runsLocally"] is True
        assert entry["redirectHost"] == "127.0.0.1"

    def test_a_client_redirecting_elsewhere_shows_its_host(self):
        remote = Application.objects.create(
            name="Hosted agent",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="https://agent.example.com/oauth/callback",
        )
        self.issue(remote)

        [entry] = self.authorized()

        assert entry["runsLocally"] is False
        assert entry["redirectHost"] == "agent.example.com"

    def test_an_expired_token_with_a_live_refresh_token_still_counts(self):
        # MCP clients refresh: an expired access token is normal between uses.
        self.issue(self.claude, expires_in=timedelta(hours=-1))

        assert [entry["name"] for entry in self.authorized()] == ["Claude Code"]

    def test_an_expired_token_with_nothing_to_refresh_does_not(self):
        self.issue(self.claude, expires_in=timedelta(hours=-1), refresh=False)

        assert self.authorized() == []

    def test_another_users_clients_are_not_listed(self):
        self.issue(self.opencode, user=self.other_user)

        assert self.authorized() == []

    def test_revoking_removes_everything_the_client_holds(self):
        access = self.issue(self.claude)
        self.issue(self.opencode)

        response = self.client.delete(
            reverse("authorized-application", args=[self.claude.pk]),
            **jwt_header(self.user),
        )

        assert response.status_code == 204
        assert not AccessToken.objects.filter(application=self.claude).exists()
        refresh = RefreshToken.objects.get(token=f"refresh-{access.token}")
        assert refresh.revoked is not None
        assert [entry["name"] for entry in self.authorized()] == ["opencode"]

        # The client can no longer trade its refresh token for a new access token.
        exchange = self.client.post(
            reverse("oauth2_provider:token"),
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh.token,
                "client_id": self.claude.client_id,
            },
        )
        assert exchange.status_code == 400

    def test_revoking_a_client_the_user_has_not_authorized_is_a_404(self):
        self.issue(self.claude, user=self.other_user)

        response = self.client.delete(
            reverse("authorized-application", args=[self.claude.pk]),
            **jwt_header(self.user),
        )

        assert response.status_code == 404
        assert AccessToken.objects.filter(user=self.other_user).exists()

    def test_an_mcp_access_token_cannot_list_or_revoke(self):
        access = self.issue(self.claude)
        bearer = {"HTTP_AUTHORIZATION": f"Bearer {access.token}"}

        assert (
            self.client.get(reverse("authorized-applications"), **bearer).status_code
            == 403
        )
        assert (
            self.client.delete(
                reverse("authorized-application", args=[self.claude.pk]), **bearer
            ).status_code
            == 403
        )
