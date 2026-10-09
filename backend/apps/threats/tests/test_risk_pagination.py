"""Regression test for precogly/precogly#484.

The page-size tests fail without `ClientSizedPagination`. The rest pass against
stock `PageNumberPagination` too — they pin DRF behavior the frontend depends on
rather than anything this change introduced.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.core.pagination import ClientSizedPagination
from apps.organizations.models import Organization, OrganizationMember
from apps.threat_models.models import ThreatModel
from apps.threats.services import create_risk

User = get_user_model()

# The count from #484. Any number above PAGE_SIZE would do.
RISK_COUNT = 24


class RiskRegisterPaginationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Contoso")
        cls.user = User.objects.create_user(
            username="analyst", email="analyst@contoso.test", password="pw"
        )
        OrganizationMember.objects.create(
            organization=cls.org, user=cls.user, role="security_team"
        )
        cls.threat_model = ThreatModel.objects.create(
            organization=cls.org, created_by=cls.user, name="Contoso threat model"
        )
        for i in range(RISK_COUNT):
            create_risk(cls.threat_model, name=f"Risk {i:02d}", level="medium")

    def setUp(self):
        self.client = APIClient()
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(self.user).access_token}"
        )
        self.url = f"/api/threat-models/{self.threat_model.pk}/risks/"

    def test_first_page_reports_the_whole_register(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], RISK_COUNT)
        self.assertEqual(len(response.data["results"]), 20)
        self.assertIsNotNone(response.data["next"])

    def test_pages_together_cover_the_register_without_overlap(self):
        page_one = self.client.get(self.url, {"page": 1}).data["results"]
        page_two = self.client.get(self.url, {"page": 2}).data["results"]

        ids = [risk["id"] for risk in page_one + page_two]
        self.assertEqual(len(ids), RISK_COUNT)
        self.assertEqual(len(set(ids)), RISK_COUNT)

    def test_client_may_choose_the_page_size(self):
        """Without `page_size_query_param` this returns 20, so the register's
        board could never group more than a default page into its columns."""
        response = self.client.get(self.url, {"page_size": 100})

        self.assertEqual(len(response.data["results"]), RISK_COUNT)
        self.assertIsNone(response.data["next"])

    def test_page_size_is_capped(self):
        """An unbounded page size is a request to serialize the whole table."""
        response = self.client.get(self.url, {"page_size": 100000})

        self.assertEqual(
            len(response.data["results"]),
            min(RISK_COUNT, ClientSizedPagination.max_page_size),
        )

    def test_page_past_the_end_is_rejected(self):
        """Why the register steps back a page after deleting a page's last row:
        an out-of-range page is a 404, not an empty page."""
        response = self.client.get(self.url, {"page": 99})

        self.assertEqual(response.status_code, 404)
