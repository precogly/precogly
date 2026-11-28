"""seed stops when a demo pack it lists is missing (risk R11).

Before, a missing pack folder was a one-line warning, and seed went on to create
the sample threat models with no diagram behind them.
"""

import shutil
import tempfile
from io import StringIO
from pathlib import Path

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings


class SeedMissingPackTests(TestCase):
    def test_a_missing_demo_pack_stops_seed_and_names_it(self):
        bundled_packs = Path(settings.LIBRARIES_PATH) / "packs"
        with tempfile.TemporaryDirectory() as temporary_root:
            packs_dir = Path(temporary_root) / "packs"
            shutil.copytree(
                bundled_packs / "demo-taxonomies", packs_dir / "demo-taxonomies"
            )
            shutil.copytree(
                bundled_packs / "demo-standards", packs_dir / "demo-standards"
            )
            # demo-threat-libraries/demo-aws is left out.

            with (
                override_settings(LIBRARIES_PATH=temporary_root),
                self.assertRaises(CommandError) as raised,
            ):
                call_command("seed", stdout=StringIO())

        self.assertIn("demo-threat-libraries/demo-aws", str(raised.exception))
