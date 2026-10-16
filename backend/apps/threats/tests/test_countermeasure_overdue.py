"""Overdue countermeasures (from PR #559, JJediny): ``days_overdue`` and the
``?overdue=true`` filter on the countermeasures API.

A control is overdue when its due date has passed and it is not yet in
effect: implemented, verified and platform controls are never overdue.
"""

from datetime import date, timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import Organization, OrganizationMember
from apps.threat_models.models import ThreatModel
from apps.threats.services import create_instance_countermeasure

User = get_user_model()


class OverdueTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="sec", email="sec@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        cls.threat_model = ThreatModel.objects.create(
            name="TM", organization=cls.organization
        )
        today = date.today()
        cls.ten_days_ago = today - timedelta(days=10)

        def control(name, status, due_date):
            countermeasure = create_instance_countermeasure(
                cls.threat_model, countermeasure_name=name, status=status
            )
            countermeasure.due_date = due_date
            countermeasure.save(update_fields=["due_date"])
            return countermeasure

        cls.late_gap = control("Late gap", "gap", cls.ten_days_ago)
        cls.late_planned = control("Late planned", "planned", cls.ten_days_ago)
        cls.late_verified = control("Late but verified", "verified", cls.ten_days_ago)
        cls.late_platform = control("Late but platform", "platform", cls.ten_days_ago)
        cls.due_today = control("Due today", "gap", today)
        cls.due_later = control("Due later", "planned", today + timedelta(days=5))
        cls.no_date = control("No date", "gap", None)

    def test_days_overdue_counts_days_past_the_due_date_for_controls_not_in_effect(
        self,
    ):
        self.assertEqual(self.late_gap.days_overdue, 10)
        self.assertEqual(self.late_planned.days_overdue, 10)

    def test_controls_in_effect_or_not_yet_due_are_never_overdue(self):
        for countermeasure in (
            self.late_verified,
            self.late_platform,
            self.due_today,
            self.due_later,
            self.no_date,
        ):
            with self.subTest(countermeasure.countermeasure_name):
                self.assertIsNone(countermeasure.days_overdue)

    def test_the_overdue_filter_lists_only_overdue_controls_with_their_days(self):
        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(self.user).access_token}"
        )
        response = client.get(
            "/api/countermeasures/",
            {"threat_model": self.threat_model.pk, "overdue": "true"},
        )
        self.assertEqual(response.status_code, 200)
        rows = response.json()
        rows = rows["results"] if isinstance(rows, dict) else rows
        self.assertEqual(
            sorted(
                (row["countermeasureNameDisplay"], row["daysOverdue"]) for row in rows
            ),
            [("Late gap", 10), ("Late planned", 10)],
        )

        unfiltered = client.get(
            "/api/countermeasures/", {"threat_model": self.threat_model.pk}
        ).json()
        unfiltered = (
            unfiltered["results"] if isinstance(unfiltered, dict) else unfiltered
        )
        self.assertEqual(len(unfiltered), 7)
