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

    def test_fallbacks_do_not_decrease_along_the_lifecycle(self):
        """Moving a control forward must never make a residual worse."""
        lifecycle = ["gap", "planned", "in_progress", "implemented", "verified"]
        values = [STATUS_EFFECTIVENESS_FALLBACK[status] for status in lifecycle]
        self.assertEqual(
            values,
            sorted(values),
            f"not monotonic: {dict(zip(lifecycle, values, strict=True))}",
        )
        self.assertLess(
            STATUS_EFFECTIVENESS_FALLBACK["planned"],
            STATUS_EFFECTIVENESS_FALLBACK["in_progress"],
        )


class ResidualRecalculationTests(StatusEffectivenessTestCase):
    """What a recalculation may and may not overwrite."""

    def _level_only_risk_with_imported_residual(self):
        from apps.threats.models import Rating
        from apps.threats.services import apply_rating, create_risk, level_rating

        risk = create_risk(
            self.tm, name="Account takeover", level="high", threat_ids=[self.threat.id]
        )
        apply_rating(risk, "residual", level_rating("medium"))
        risk.refresh_from_db()
        self.assertEqual(risk.residual.methodology, "manual")
        self.assertEqual(risk.residual.level, Rating.Level.MEDIUM)
        return risk

    def test_level_only_risk_keeps_its_residual(self):
        from apps.threats.services import recalculate_residual

        risk = self._level_only_risk_with_imported_residual()
        residual_id_before = risk.residual_id
        self._add_countermeasure("verified")

        recalculate_residual(risk)

        risk.refresh_from_db()
        self.assertEqual(risk.residual_id, residual_id_before)
        self.assertEqual(risk.residual.level, "medium")

    def test_countermeasure_status_change_keeps_a_level_only_residual(self):
        from apps.threats.services import recalculate_all_threats_for_countermeasure

        risk = self._level_only_risk_with_imported_residual()
        control = self._add_countermeasure("planned")
        control.status = "in_progress"
        control.save()

        recalculate_all_threats_for_countermeasure(control)

        risk.refresh_from_db()
        self.assertEqual(risk.residual.level, "medium")

    def test_level_only_risk_without_a_residual_gets_a_copy_of_the_inherent(self):
        from apps.threats.models import Risk
        from apps.threats.services import level_rating, recalculate_residual

        inherent = level_rating("high")
        inherent.organization_id = self.org.id
        inherent.save()
        risk = Risk.objects.create(
            threat_model=self.tm, name="Fresh", inherent=inherent
        )
        self.assertIsNone(risk.residual_id)

        recalculate_residual(risk)

        risk.refresh_from_db()
        self.assertIsNotNone(risk.residual_id)
        self.assertEqual(risk.residual.level, "high")

    def test_matrix_risk_is_still_reduced(self):
        from apps.threats.services import create_risk, recalculate_residual

        risk = create_risk(
            self.tm,
            name="Exposure",
            rating_inputs={"likelihood": "certain", "impact": "severe"},
            threat_ids=[self.threat.id],
        )
        self.assertEqual(risk.residual.level, "critical")
        self._add_countermeasure("verified")

        recalculate_residual(risk)

        risk.refresh_from_db()
        self.assertEqual(risk.residual.likelihood_score, 1)
        self.assertEqual(risk.residual.level, "low")

    def test_in_progress_never_rates_worse_than_planned(self):
        from apps.threats.services import create_risk, recalculate_residual

        risk = create_risk(
            self.tm,
            name="Exposure",
            rating_inputs={"likelihood": "likely", "impact": "major"},
            threat_ids=[self.threat.id],
        )
        control = self._add_countermeasure("planned")
        recalculate_residual(risk)
        risk.refresh_from_db()
        planned_likelihood = risk.residual.likelihood_score

        control.status = "in_progress"
        control.save()
        recalculate_residual(risk)
        risk.refresh_from_db()

        self.assertLessEqual(risk.residual.likelihood_score, planned_likelihood)


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
