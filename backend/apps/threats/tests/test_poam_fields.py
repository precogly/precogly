"""Tests for GSA-TTS/TTSE-petrified-forest-sspp#82/#81: POA&M model fields.

A POA&M item is an ``InstanceCountermeasure`` with ``poam_id`` and
``scheduled_completion`` set -- not a separate entity type. See the linked
issues for the full rationale.
"""

from datetime import date, timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.organizations.models import Organization, OrganizationMember
from apps.threat_models.models import ThreatModel
from apps.threats.models import InstanceCountermeasure

User = get_user_model()


class PoamFieldsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Poam Org", domain="poam.test")
        cls.user = User.objects.create_user(
            username="poam@test", email="poam@test", password="pw"
        )
        OrganizationMember.objects.create(
            organization=cls.org, user=cls.user, role="security_team"
        )
        cls.tm = ThreatModel.objects.create(name="Poam TM", organization=cls.org)

    def test_source_defaults_to_manual(self):
        cm = InstanceCountermeasure.objects.create(threat_model=self.tm)
        self.assertEqual(cm.source, InstanceCountermeasure.Source.MANUAL)

    def test_poam_id_and_scheduled_completion_are_queryable(self):
        InstanceCountermeasure.objects.create(
            threat_model=self.tm,
            poam_id="POAM-1",
            scheduled_completion=date(2026, 1, 1),
        )
        InstanceCountermeasure.objects.create(threat_model=self.tm)

        with_poam = InstanceCountermeasure.objects.exclude(poam_id="")
        self.assertEqual(with_poam.count(), 1)
        self.assertEqual(with_poam.first().poam_id, "POAM-1")

    def test_days_overdue_none_when_no_scheduled_completion(self):
        cm = InstanceCountermeasure.objects.create(threat_model=self.tm)
        self.assertIsNone(cm.days_overdue)

    def test_days_overdue_none_when_not_yet_due(self):
        cm = InstanceCountermeasure.objects.create(
            threat_model=self.tm,
            scheduled_completion=date.today() + timedelta(days=5),
        )
        self.assertIsNone(cm.days_overdue)

    def test_days_overdue_positive_when_overdue_and_open(self):
        cm = InstanceCountermeasure.objects.create(
            threat_model=self.tm,
            status=InstanceCountermeasure.Status.GAP,
            scheduled_completion=date.today() - timedelta(days=10),
        )
        self.assertEqual(cm.days_overdue, 10)

    def test_days_overdue_none_once_implemented(self):
        cm = InstanceCountermeasure.objects.create(
            threat_model=self.tm,
            status=InstanceCountermeasure.Status.IMPLEMENTED,
            scheduled_completion=date.today() - timedelta(days=10),
        )
        self.assertIsNone(cm.days_overdue)

    def test_days_overdue_none_once_verified(self):
        cm = InstanceCountermeasure.objects.create(
            threat_model=self.tm,
            status=InstanceCountermeasure.Status.VERIFIED,
            scheduled_completion=date.today() - timedelta(days=10),
        )
        self.assertIsNone(cm.days_overdue)
