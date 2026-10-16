"""Tests for B-02: status/effectiveness mapping consistency."""

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import OrgsystemComponent
from apps.threat_models.models import ThreatModel
from apps.threats.models import CountermeasureThreatLink, InstanceCountermeasure
from apps.threats.services import (
    STATUS_EFFECTIVENESS_FALLBACK,
    create_instance_threat,
    recalculate_threat_status,
)

User = get_user_model()


class StatusEffectivenessTestCase(TestCase):
    """Base class that sets up a threat model with one component and one threat."""

    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Test Org", domain="test.org")
        cls.user = User.objects.create_user(
            username="testuser", email="test@test.org", password="testpass123"
        )
        OrganizationMember.objects.create(
            organization=cls.org, user=cls.user, role="security_team"
        )
        cls.tm = ThreatModel.objects.create(name="Test TM", organization=cls.org)
        cls.component = OrgsystemComponent.objects.create(
            blueprint=cls.tm.default_blueprint, name="Test Component"
        )
        cls.threat = create_instance_threat(
            cls.tm, targets=[cls.component], level="high"
        )

    def _add_countermeasure(self, status, effectiveness=None):
        cm = InstanceCountermeasure.objects.create(
            threat_model=self.tm,
            status=status,
            effectiveness=effectiveness,
        )
        CountermeasureThreatLink.objects.create(countermeasure=cm, threat=self.threat)
        return cm


class EffectivenessFallbackCoverageTests(StatusEffectivenessTestCase):
    """Every InstanceCountermeasure.Status must have a fallback effectiveness value."""

    def test_all_statuses_have_fallback_effectiveness(self):
        missing = [
            s.value
            for s in InstanceCountermeasure.Status
            if s.value not in STATUS_EFFECTIVENESS_FALLBACK
        ]
        self.assertEqual(
            missing,
            [],
            f"Statuses missing from STATUS_EFFECTIVENESS_FALLBACK: {missing}",
        )

    def test_in_progress_has_nonzero_effectiveness(self):
        self.assertGreater(STATUS_EFFECTIVENESS_FALLBACK["in_progress"], 0.0)

    def test_implemented_has_nonzero_effectiveness(self):
        self.assertGreater(STATUS_EFFECTIVENESS_FALLBACK["implemented"], 0.0)

    def test_implemented_greater_than_in_progress(self):
        self.assertGreater(
            STATUS_EFFECTIVENESS_FALLBACK["implemented"],
            STATUS_EFFECTIVENESS_FALLBACK["in_progress"],
        )


class ThreatStatusDerivationTests(StatusEffectivenessTestCase):
    """recalculate_threat_status must align with effectiveness values."""

    def test_in_progress_countermeasure_gives_addressable(self):
        self._add_countermeasure("in_progress")
        status = recalculate_threat_status(self.threat)
        self.assertEqual(status, "addressable")

    def test_implemented_countermeasure_gives_mitigated(self):
        self._add_countermeasure("implemented")
        status = recalculate_threat_status(self.threat)
        self.assertEqual(status, "mitigated")

    def test_verified_countermeasure_gives_mitigated(self):
        self._add_countermeasure("verified")
        status = recalculate_threat_status(self.threat)
        self.assertEqual(status, "mitigated")

    def test_decommissioned_countermeasure_gives_addressable(self):
        self._add_countermeasure("decommissioned")
        status = recalculate_threat_status(self.threat)
        self.assertEqual(status, "addressable")

    def test_gap_countermeasure_gives_exposed(self):
        self._add_countermeasure("gap")
        status = recalculate_threat_status(self.threat)
        self.assertEqual(status, "exposed")

    def test_gap_plus_verified_gives_exposed(self):
        self._add_countermeasure("gap")
        self._add_countermeasure("verified")
        status = recalculate_threat_status(self.threat)
        self.assertEqual(status, "exposed")

    def test_planned_plus_verified_gives_addressable(self):
        self._add_countermeasure("planned")
        self._add_countermeasure("verified")
        status = recalculate_threat_status(self.threat)
        self.assertEqual(status, "addressable")

    def test_in_progress_plus_implemented_gives_addressable(self):
        self._add_countermeasure("in_progress")
        self._add_countermeasure("implemented")
        status = recalculate_threat_status(self.threat)
        self.assertEqual(status, "addressable")
