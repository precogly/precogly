"""`seed` connects packs only to the sample threat models it owns (regression for the
unscoped `_connect_packs_to_threat_models` that attached every pack to every threat
model in the database, including a real, pre-existing, non-sample one).

`seed` is designed to run on every container start so a fresh deploy's libraries are
never empty. On a database that already holds real threat models, that means this
command's own pack-connecting step runs against production data too, not only against
the sample organization it seeds. A pre-existing threat model that is not one of the
seeded samples must come out of a `seed` run with no pack connections at all.
"""

from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from apps.organizations.models import Organization, Team
from apps.threat_models.models import ThreatModel, ThreatModelLibraryPack


def run_seed() -> None:
    call_command("seed", stdout=StringIO(), stderr=StringIO())


class SeedPackScopeTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        # A real customer's own organization and threat model, created before `seed`
        # ever runs against this database -- standing in for a production deployment
        # whose container restarts re-run `seed` against already-live data.
        cls.real_org = Organization.objects.create(
            name="A Real Customer", plan=Organization.Plan.FREE, is_primary=False
        )
        cls.real_team = Team.objects.create(
            organization=cls.real_org, name="Security Team", is_default=True
        )
        cls.real_threat_model = ThreatModel.objects.create(
            organization=cls.real_org,
            owning_team=cls.real_team,
            name="A Real Customer's Own Device",
            description="Not a sample model. Must never gain pack connections from seed.",
            criticality=ThreatModel.Criticality.MEDIUM,
        )

        run_seed()

    def test_seed_does_not_connect_any_pack_to_a_pre_existing_non_sample_model(self):
        self.assertEqual(
            ThreatModelLibraryPack.objects.filter(
                threat_model=self.real_threat_model
            ).count(),
            0,
        )

    def test_seed_still_connects_packs_to_its_own_sample_models(self):
        sample = ThreatModel.objects.exclude(
            id=self.real_threat_model.id
        ).first()
        self.assertIsNotNone(sample, "seed should have created its own sample models")
        self.assertTrue(
            ThreatModelLibraryPack.objects.filter(threat_model=sample).exists(),
            "a sample threat model should still gain its pack connections",
        )

    def test_a_second_seed_run_still_does_not_touch_the_real_model(self):
        run_seed()
        self.assertEqual(
            ThreatModelLibraryPack.objects.filter(
                threat_model=self.real_threat_model
            ).count(),
            0,
        )
