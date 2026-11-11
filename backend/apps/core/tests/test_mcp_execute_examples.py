"""The examples in `execute`'s description run against the real API.

They call real endpoints with real parameters, so an API change can break one
silently, and a broken example in the description teaches the model the wrong call.
"""

from asgiref.sync import async_to_sync
from django.contrib.auth import get_user_model
from django.test import TestCase
from mcp.server.auth.provider import AccessToken
from precogly_mcp.tools import EXECUTE_EXAMPLES
from pydantic_monty import AsyncMonty

from apps.core.mcp import api
from apps.organizations.models import Organization, OrganizationMember
from apps.threat_models.models import ThreatModel

User = get_user_model()


async def run_examples(access_token: AccessToken) -> list[object]:
    async def request(method, path, params=None, body=None):
        return await api.request(access_token, method, path, params, body)

    results = []
    async with AsyncMonty() as sandbox:
        for code in EXECUTE_EXAMPLES:
            async with sandbox.checkout() as session:
                results.append(
                    await session.feed_run(code, external_lookup={"request": request})
                )
    return results


class ExecuteExampleTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        org = Organization.objects.create(name="Kestrel", domain="kestrel.test")
        # 25 models: more than one page of 20, so the paging example pages.
        ThreatModel.objects.create(organization=org, name="Payments gateway")
        for i in range(24):
            ThreatModel.objects.create(organization=org, name=f"Service {i}")
        # Security team, so the PATCH example is allowed.
        cls.user = User.objects.create_user(
            username="lee@kestrel.test", email="lee@kestrel.test", password="pw"
        )
        cls.user.organization_memberships.all().delete()
        OrganizationMember.objects.create(
            organization=org, user=cls.user, role="security_team"
        )

    def setUp(self):
        # Middleware reads settings when it is built; another test may have cached a
        # handler under overridden settings.
        api._handler.cache_clear()

    def test_every_example_runs_and_finds_something(self):
        access_token = AccessToken(
            token="t",
            client_id="c",
            scopes=["read", "write"],
            subject=str(self.user.pk),
        )

        results = async_to_sync(run_examples)(access_token)

        for code, result in zip(EXECUTE_EXAMPLES, results, strict=True):
            with self.subTest(code=code):
                assert result, f"example returned nothing: {result!r}"
        # The paging example read every model, not one page of them.
        assert results[1] == 25
        assert ThreatModel.objects.get(name="Payments gateway").criticality == "high"
