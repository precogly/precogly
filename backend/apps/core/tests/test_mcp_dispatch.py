"""`dispatch` runs an API request in-process, as a given user.

The settings are overridden to look like production. The test runner adds `testserver`
to `ALLOWED_HOSTS` and leaves `SECURE_SSL_REDIRECT` off, which would hide both ways
an in-process request addressed like `RequestFactory`'s default fails in production.
"""

import pytest
from asgiref.sync import async_to_sync
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from mcp.server.auth.provider import AccessToken

from apps.core.mcp import api as mcp
from apps.core.mcp.errors import APIError
from apps.organizations.models import Organization, OrganizationMember
from apps.threat_models.models import ThreatModel

User = get_user_model()


def member_of(organization, email, role="member"):
    """A user whose only membership is `organization`, whatever the signal granted."""
    user = User.objects.create_user(username=email, email=email, password="testpass123")
    user.organization_memberships.all().delete()
    user.team_memberships.all().delete()
    OrganizationMember.objects.create(organization=organization, user=user, role=role)
    return user


@override_settings(
    ALLOWED_HOSTS=["precogly.example"],
    MCP_RESOURCE_URL="https://precogly.example/mcp",
    SECURE_SSL_REDIRECT=True,
)
class DispatchTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        kestrel = Organization.objects.create(name="Kestrel", domain="kestrel.test")
        contoso = Organization.objects.create(name="Contoso", domain="contoso.test")
        ThreatModel.objects.create(organization=kestrel, name="Ingest pipeline")
        ThreatModel.objects.create(organization=contoso, name="Contoso ledger")
        cls.kestrel_user = member_of(kestrel, "ana@kestrel.test")
        cls.contoso_user = member_of(contoso, "raj@contoso.test")

    def setUp(self):
        # Middleware reads settings when it is built, so a handler cached by an
        # earlier test would not see the overrides above.
        mcp._handler.cache_clear()

    def test_a_user_reads_their_own_threat_models_and_no_one_elses(self):
        status, body = mcp.dispatch(self.kestrel_user, "GET", "/api/threat-models/")

        assert status == 200, body
        assert [row["name"] for row in body["results"]] == ["Ingest pipeline"]

    def test_an_unrouted_path_comes_back_as_a_status_not_an_exception(self):
        status, body = mcp.dispatch(self.kestrel_user, "GET", "/api/no-such-route/")

        assert status == 404
        assert isinstance(body, str)

    def test_params_become_the_query_string(self):
        ThreatModel.objects.create(
            organization=self.kestrel_user.organization_memberships.get().organization,
            name="Card vault",
        )

        status, body = mcp.dispatch(
            self.kestrel_user,
            "GET",
            "/api/threat-models/",
            params={"search": "vault"},
        )

        assert status == 200, body
        assert [row["name"] for row in body["results"]] == ["Card vault"]

    def test_body_is_sent_as_json(self):
        model = ThreatModel.objects.get(name="Ingest pipeline")
        # A plain member gets 403 here: editing a threat model is security team work.
        editor = member_of(model.organization, "lee@kestrel.test", role="security_team")

        status, body = mcp.dispatch(
            editor,
            "PATCH",
            f"/api/threat-models/{model.pk}/",
            body={"name": "Ingest pipeline v2"},
        )

        assert status == 200, body
        model.refresh_from_db()
        assert model.name == "Ingest pipeline v2"

    def test_request_refuses_a_query_in_both_the_path_and_params(self):
        access_token = AccessToken(
            token="t",
            client_id="c",
            scopes=["read"],
            subject=str(self.kestrel_user.pk),
        )

        with pytest.raises(APIError, match="not both"):
            async_to_sync(mcp.request)(
                access_token,
                "GET",
                "/api/threat-models/?search=a",
                params={"search": "b"},
            )

    def test_request_reads_as_the_user_the_token_names(self):
        # `async_to_sync` over `sync_to_async(thread_sensitive=True)` keeps the query
        # on this thread, inside this TestCase's transaction.
        access_token = AccessToken(
            token="t",
            client_id="c",
            scopes=["read"],
            subject=str(self.kestrel_user.pk),
        )

        body = async_to_sync(mcp.request)(access_token, "get", "/api/threat-models/")

        assert [row["name"] for row in body["results"]] == ["Ingest pipeline"]

    def test_request_raises_on_an_error_status_with_drfs_reason(self):
        # Kestrel's user cannot see Contoso's model, so the viewset answers 404.
        access_token = AccessToken(
            token="t",
            client_id="c",
            scopes=["read"],
            subject=str(self.kestrel_user.pk),
        )
        contoso_model = ThreatModel.objects.get(name="Contoso ledger")

        with pytest.raises(APIError) as raised:
            async_to_sync(mcp.request)(
                access_token, "GET", f"/api/threat-models/{contoso_model.pk}/"
            )

        assert str(raised.value) == (
            f"GET /api/threat-models/{contoso_model.pk}/ returned 404: "
            "No ThreatModel matches the given query."
        )
