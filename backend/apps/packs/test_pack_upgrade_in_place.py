"""A forced pack import upgrades library rows in place (plan M1).

Instance threats and countermeasures keep their library links, nothing is
generated or deleted by the upgrade itself, and rows the new version no
longer ships are pruned.
"""

import tempfile
from pathlib import Path

import yaml
from django.test import TestCase

from apps.organizations.models import Organization
from apps.packs.models import LibraryPack
from apps.packs.services import import_pack_from_path
from apps.systems.models import ComponentLibrary, OrgsystemComponent
from apps.threat_models.models import ThreatModel, ThreatModelLibraryPack
from apps.threats.models import (
    ComponentLibraryThreat,
    CountermeasureLibrary,
    InstanceCountermeasure,
    InstanceThreat,
    ThreatLibrary,
)
from apps.threats.services import ensure_generated_threats

PACK_SLUG = "upgrade-test"


def _write_pack(root: Path, *, version: str, threats: dict, countermeasures: dict):
    """Write a minimal full pack.

    ``threats`` maps threat id to the countermeasure ids that mitigate it; every
    threat is mapped onto the one component. ``countermeasures`` maps id to name.
    """
    (root / "joins").mkdir(parents=True, exist_ok=True)
    (root / "pack.yaml").write_text(
        yaml.safe_dump(
            {
                "pack": {
                    "schema_version": 1,
                    "slug": PACK_SLUG,
                    "name": "Upgrade test",
                    "version": version,
                    "pack_type": "full",
                }
            }
        )
    )
    (root / "components.yaml").write_text(
        yaml.safe_dump(
            {
                "components": [
                    {"id": "web-app", "name": "Web App", "category": "process"}
                ]
            }
        )
    )
    (root / "threats.yaml").write_text(
        yaml.safe_dump(
            {
                "threats": [
                    {"id": threat_id, "name": threat_id.upper(), "description": "d"}
                    for threat_id in threats
                ]
            }
        )
    )
    (root / "countermeasures.yaml").write_text(
        yaml.safe_dump(
            {
                "countermeasures": [
                    {
                        "id": cm_id,
                        "name": name,
                        "description": "d",
                        "control_functions": ["preventive"],
                    }
                    for cm_id, name in countermeasures.items()
                ]
            }
        )
    )
    (root / "joins" / "components-threats.yaml").write_text(
        yaml.safe_dump(
            {
                "mappings": [
                    {
                        "component": "web-app",
                        "threats": [
                            {"threat": threat_id, "applies_to": "component"}
                            for threat_id in threats
                        ],
                    }
                ]
            }
        )
    )
    (root / "joins" / "threats-countermeasures.yaml").write_text(
        yaml.safe_dump(
            {
                "mappings": [
                    {"threat": threat_id, "countermeasures": cm_ids}
                    for threat_id, cm_ids in threats.items()
                ]
            }
        )
    )


class PackUpgradeInPlaceTests(TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.pack_path = Path(self.tempdir.name)
        self.addCleanup(self.tempdir.cleanup)

        _write_pack(
            self.pack_path,
            version="1.0.0",
            threats={"alpha": ["x"], "beta": ["y"]},
            countermeasures={"x": "X", "y": "Y"},
        )
        result = import_pack_from_path(self.pack_path, skip_validation=True)
        self.assertTrue(result.success, result.message)
        self.pack = LibraryPack.objects.get(slug=PACK_SLUG)

        organization = Organization.objects.create(name="Org", domain="org.test")
        self.threat_model = ThreatModel.objects.create(
            name="TM", organization=organization
        )
        ThreatModelLibraryPack.objects.create(
            threat_model=self.threat_model, library_pack=self.pack
        )
        self.component = OrgsystemComponent.objects.create(
            blueprint=self.threat_model.default_blueprint,
            name="Web",
            component_library=ComponentLibrary.objects.get(
                qualified_slug=f"{PACK_SLUG}/web-app"
            ),
        )
        self.assertEqual(ensure_generated_threats(self.component), 2)

    def _snapshot(self):
        threats = {
            t.threat_library.qualified_slug if t.threat_library else None: (
                t.id,
                t.threat_library_id,
            )
            for t in InstanceThreat.objects.filter(targets__component=self.component)
        }
        countermeasures = {
            c.countermeasure_library.qualified_slug
            if c.countermeasure_library
            else None: (
                c.id,
                c.countermeasure_library_id,
            )
            for c in InstanceCountermeasure.objects.filter(
                threat_model=self.threat_model
            )
        }
        return threats, countermeasures

    def test_same_content_reimport_changes_nothing(self):
        before = self._snapshot()
        library_ids_before = set(
            ThreatLibrary.objects.filter(source_pack=self.pack).values_list(
                "id", flat=True
            )
        )

        _write_pack(
            self.pack_path,
            version="1.0.1",
            threats={"alpha": ["x"], "beta": ["y"]},
            countermeasures={"x": "X", "y": "Y"},
        )
        result = import_pack_from_path(self.pack_path, force=True, skip_validation=True)
        self.assertTrue(result.success, result.message)

        self.pack.refresh_from_db()
        self.assertEqual(self.pack.version, "1.0.1")
        self.assertEqual(
            set(
                ThreatLibrary.objects.filter(source_pack=self.pack).values_list(
                    "id", flat=True
                )
            ),
            library_ids_before,
        )
        self.assertEqual(self._snapshot(), before)
        # The next generation run, what a DFD save does, adds nothing.
        self.assertEqual(ensure_generated_threats(self.component), 0)

    def test_removed_and_added_rows(self):
        threats_before, countermeasures_before = self._snapshot()
        alpha_instance_id, alpha_library_id = threats_before[f"{PACK_SLUG}/alpha"]
        beta_instance_id, _ = threats_before[f"{PACK_SLUG}/beta"]

        _write_pack(
            self.pack_path,
            version="2.0.0",
            threats={"alpha": ["x", "z"], "gamma": ["z"]},
            countermeasures={"x": "X renamed", "y": "Y", "z": "Z"},
        )
        result = import_pack_from_path(self.pack_path, force=True, skip_validation=True)
        self.assertTrue(result.success, result.message)

        # Kept rows keep their ids; the renamed one is updated in place.
        alpha = ThreatLibrary.objects.get(qualified_slug=f"{PACK_SLUG}/alpha")
        self.assertEqual(alpha.id, alpha_library_id)
        self.assertEqual(
            CountermeasureLibrary.objects.get(qualified_slug=f"{PACK_SLUG}/x").name,
            "X renamed",
        )
        self.assertEqual(
            CountermeasureLibrary.objects.get(qualified_slug=f"{PACK_SLUG}/x").id,
            countermeasures_before[f"{PACK_SLUG}/x"][1],
        )

        # Dropped rows are gone; the instance that pointed at one is orphaned, not deleted.
        self.assertFalse(
            ThreatLibrary.objects.filter(qualified_slug=f"{PACK_SLUG}/beta").exists()
        )
        beta_instance = InstanceThreat.objects.get(id=beta_instance_id)
        self.assertIsNone(beta_instance.threat_library_id)
        self.assertEqual(beta_instance.threat_name, "BETA")

        # The join from the dropped threat is gone, the kept ones are intact.
        self.assertEqual(
            set(
                ComponentLibraryThreat.objects.filter(
                    component_library__source_pack=self.pack
                ).values_list("threat_library__qualified_slug", flat=True)
            ),
            {f"{PACK_SLUG}/alpha", f"{PACK_SLUG}/gamma"},
        )
        self.assertEqual(
            set(
                alpha.applicable_countermeasures.values_list(
                    "qualified_slug", flat=True
                )
            ),
            {f"{PACK_SLUG}/x", f"{PACK_SLUG}/z"},
        )

        # The upgrade itself created and deleted no instance rows.
        self.assertEqual(
            InstanceThreat.objects.get(id=alpha_instance_id).threat_library_id,
            alpha_library_id,
        )
        self.assertEqual(
            InstanceThreat.objects.filter(targets__component=self.component).count(), 2
        )
        self.assertEqual(
            InstanceCountermeasure.objects.filter(
                threat_model=self.threat_model
            ).count(),
            2,
        )

        # Only a generation run brings in what the new version adds.
        self.assertEqual(ensure_generated_threats(self.component), 1)
        self.assertEqual(
            InstanceThreat.objects.filter(targets__component=self.component).count(), 3
        )
