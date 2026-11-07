"""`dispatch` runs an API request in-process, as a given user.

The settings are overridden to look like production. The test runner adds `testserver`
to `ALLOWED_HOSTS` and leaves `SECURE_SSL_REDIRECT` off, which would hide both ways
an in-process request addressed like `RequestFactory`'s default fails in production.
"""

from asgiref.sync import async_to_sync
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from mcp.server.auth.provider import AccessToken

from apps.core.mcp import api as mcp
from apps.organizations.models import Organization, OrganizationMember
from apps.threat_models.models import ThreatModel

User = get_user_model()


def member_of(organization, email):
    """A user whose only membership is `organization`, whatever the signal granted."""
    user = User.objects.create_user(username=email, email=email, password="testpass123")
    user.organization_memberships.all().delete()
    user.team_memberships.all().delete()
    OrganizationMember.objects.create(
        organization=organization, user=user, role="member"
    )
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

    def test_request_reads_as_the_user_the_token_names(self):
        # `async_to_sync` over `sync_to_async(thread_sensitive=True)` keeps the query
        # on this thread, inside this TestCase's transaction.
        access_token = AccessToken(
            token="t",
            client_id="c",
            scopes=["read"],
            subject=str(self.kestrel_user.pk),
        )

        status, body = async_to_sync(mcp.request)(
            access_token, "get", "/api/threat-models/"
        )

        assert status == 200, body
        assert [row["name"] for row in body["results"]] == ["Ingest pipeline"]
