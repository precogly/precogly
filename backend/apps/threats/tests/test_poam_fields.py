"""Tests for GSA-TTS/TTSE-petrified-forest-sspp#82/#81: POA&M model fields.

A POA&M item is an ``InstanceCountermeasure`` with ``source`` set to
``vault_import`` and a ``poam.id`` recorded in
``format_metadata.cyclonedx.poam`` -- not a separate entity type, and not a
first-class ``poam_id`` column (see maintainer review on #559: the "poam
identifier" need not be queryable as a dedicated field; it round-trips
through format_metadata the same way other CDX-origin properties do).
``days_overdue`` is computed from the pre-existing ``due_date`` field, which
is the same concept as OSCAL's "scheduled completion date" under different
(FedRAMP/general) vocabulary. See the linked issues for the full rationale.
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

    def test_poam_id_round_trips_through_format_metadata(self):
        InstanceCountermeasure.objects.create(
            threat_model=self.tm,
            source=InstanceCountermeasure.Source.VAULT_IMPORT,
            due_date=date(2026, 1, 1),
            format_metadata={"cyclonedx": {"poam": {"id": "POAM-1"}}},
        )
        InstanceCountermeasure.objects.create(threat_model=self.tm)

        with_poam = InstanceCountermeasure.objects.filter(
            format_metadata__cyclonedx__poam__id="POAM-1"
        )
        self.assertEqual(with_poam.count(), 1)
        self.assertEqual(
            with_poam.first().format_metadata["cyclonedx"]["poam"]["id"], "POAM-1"
        )

    def test_days_overdue_none_when_no_due_date(self):
        cm = InstanceCountermeasure.objects.create(threat_model=self.tm)
        self.assertIsNone(cm.days_overdue)

    def test_days_overdue_none_when_not_yet_due(self):
        cm = InstanceCountermeasure.objects.create(
            threat_model=self.tm,
            due_date=date.today() + timedelta(days=5),
        )
        self.assertIsNone(cm.days_overdue)

    def test_days_overdue_positive_when_overdue_and_open(self):
        cm = InstanceCountermeasure.objects.create(
            threat_model=self.tm,
            status=InstanceCountermeasure.Status.GAP,
            due_date=date.today() - timedelta(days=10),
        )
        self.assertEqual(cm.days_overdue, 10)

    def test_days_overdue_none_once_implemented(self):
        cm = InstanceCountermeasure.objects.create(
            threat_model=self.tm,
            status=InstanceCountermeasure.Status.IMPLEMENTED,
            due_date=date.today() - timedelta(days=10),
        )
        self.assertIsNone(cm.days_overdue)

    def test_days_overdue_none_once_verified(self):
        cm = InstanceCountermeasure.objects.create(
            threat_model=self.tm,
            status=InstanceCountermeasure.Status.VERIFIED,
            due_date=date.today() - timedelta(days=10),
        )
        self.assertIsNone(cm.days_overdue)

    def test_overdue_countermeasures_are_queryable(self):
        InstanceCountermeasure.objects.create(
            threat_model=self.tm,
            status=InstanceCountermeasure.Status.GAP,
            due_date=date.today() - timedelta(days=3),
        )
        InstanceCountermeasure.objects.create(
            threat_model=self.tm,
            status=InstanceCountermeasure.Status.GAP,
            due_date=date.today() + timedelta(days=3),
        )
        InstanceCountermeasure.objects.create(
            threat_model=self.tm,
            status=InstanceCountermeasure.Status.IMPLEMENTED,
            due_date=date.today() - timedelta(days=3),
        )

        overdue = InstanceCountermeasure.objects.filter(
            due_date__lt=date.today()
        ).exclude(
            status__in=[
                InstanceCountermeasure.Status.IMPLEMENTED,
                InstanceCountermeasure.Status.VERIFIED,
            ]
        )
        self.assertEqual(overdue.count(), 1)
