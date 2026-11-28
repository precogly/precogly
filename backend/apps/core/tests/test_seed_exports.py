"""Every seeded model exports as a valid TM-BOM (plan 9.10 item 1).

The seed command runs once against the test database. Each sample model then
exports with zero schema and ref errors. A second seed run changes nothing,
which is the idempotency the seed promises.

The OT checks (network zones, signal and control flows, devices, a boundary)
moved to test_ot_model_export.py when the seed switched to the demo packs,
which carry no OT content.
"""

from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from apps.core.management.commands.seed import (
    SAMPLE_THREAT_MODELS,
    SECOND_ORG_THREAT_MODELS,
)
from apps.diagrams.models import DFD
from apps.systems.models import Boundary, Flow, Zone
from apps.threat_models.models import ThreatModel
from apps.threat_models.tmbom import TmBomAdapter
from apps.threat_models.tmbom.testing import assert_valid_tmbom


def run_seed() -> None:
    call_command("seed", stdout=StringIO(), stderr=StringIO())


class SeededModelsExportTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        run_seed()

    def test_seed_builds_every_sample_model(self):
        expected_names = {sample["name"] for sample in SAMPLE_THREAT_MODELS} | {
            sample["name"] for sample in SECOND_ORG_THREAT_MODELS
        }
        self.assertEqual(
            set(ThreatModel.objects.values_list("name", flat=True)), expected_names
        )

    def test_every_seeded_model_exports_with_zero_errors(self):
        for threat_model in ThreatModel.objects.order_by("id"):
            document = TmBomAdapter().export_data(threat_model)
            assert_valid_tmbom(document, context=threat_model.name)

    def test_second_seed_run_changes_nothing(self):
        before = (
            ThreatModel.objects.count(),
            DFD.objects.count(),
            Zone.objects.count(),
            Flow.objects.count(),
            Boundary.objects.count(),
        )
        run_seed()
        after = (
            ThreatModel.objects.count(),
            DFD.objects.count(),
            Zone.objects.count(),
            Flow.objects.count(),
            Boundary.objects.count(),
        )
        self.assertEqual(after, before)
