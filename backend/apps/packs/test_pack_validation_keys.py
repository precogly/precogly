"""Pack validation for the step 6 and 7 keys (plan section 6.2)."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import yaml
from django.test import SimpleTestCase

from apps.packs.services import validate_pack


def _write(root: Path, name: str, data) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data))


def _pack(root: Path, *, components=None, joins=None, template=None) -> Path:
    _write(
        root,
        "pack.yaml",
        {
            "pack": {
                "slug": "keys",
                "name": "Keys",
                "version": "1.0.0",
                "pack_type": "technology",
                "schema_version": 1,
            }
        },
    )
    _write(
        root,
        "components.yaml",
        {
            "components": components
            or [{"id": "sensor", "name": "Sensor", "category": "process"}]
        },
    )
    _write(
        root,
        "threats.yaml",
        {"threats": [{"id": "spoof", "name": "Spoof", "description": "d"}]},
    )
    if joins is not None:
        _write(root, "joins/components-threats.yaml", {"mappings": joins})
    if template is not None:
        _write(
            root,
            "dfd-templates/t.yaml",
            {"slug": "t", "name": "T", "canvas_data": template},
        )
    return root


class KeyValidationTests(SimpleTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        for target in (
            "apps.packs.services._resolve_threat_reference_exists",
            "apps.packs.services._resolve_component_reference_exists",
        ):
            patcher = patch(target, return_value=False)
            patcher.start()
            self.addCleanup(patcher.stop)
        # The validator reads the installed taxonomies and packs; this is a
        # SimpleTestCase, so both are stubbed as empty.
        for target in (
            "apps.packs.services.ExternalTaxonomy",
            "apps.packs.services.LibraryPack",
        ):
            patcher = patch(target)
            mocked = patcher.start()
            mocked.objects.values_list.return_value = []
            mocked.objects.filter.return_value.exists.return_value = False
            mocked.objects.filter.return_value.first.return_value = None
            self.addCleanup(patcher.stop)

    def _messages(self, result):
        return "\n".join(error.message for error in result.errors)

    def test_valid_keys_pass(self):
        result = validate_pack(
            _pack(
                self.root,
                components=[
                    {
                        "id": "sensor",
                        "name": "S",
                        "category": "process",
                        "kind": "device",
                    }
                ],
                joins=[
                    {
                        "component": "sensor",
                        "threats": [
                            {
                                "threat": "spoof",
                                "applies_to": "flow",
                                "flow_types": ["signal"],
                                "severity": "high",
                            }
                        ],
                    }
                ],
                template={
                    "nodes": [
                        {
                            "id": "z",
                            "type": "trustZone",
                            "data": {"zoneType": "network", "trustLevel": 40},
                        }
                    ],
                    "edges": [
                        {
                            "id": "e",
                            "type": "dataFlow",
                            "data": {"flowType": "signal", "authentication": ["psk"]},
                        }
                    ],
                },
            )
        )
        self.assertEqual(self._messages(result), "")

    def test_bad_component_keys_are_errors(self):
        result = validate_pack(
            _pack(
                self.root,
                components=[
                    {"id": "x", "name": "X", "category": "external", "kind": "toaster"}
                ],
            )
        )
        messages = self._messages(result)
        self.assertIn("unknown category", messages)
        self.assertIn("unknown kind", messages)

    def test_bad_join_keys_are_errors(self):
        result = validate_pack(
            _pack(
                self.root,
                joins=[
                    {
                        "component": "sensor",
                        "threats": [
                            {"threat": "spoof", "applies_to": "sideways"},
                            {
                                "threat": "spoof",
                                "applies_to": "component",
                                "flow_types": ["signal"],
                            },
                            {
                                "threat": "spoof",
                                "applies_to": "flow",
                                "flow_types": ["laser"],
                                "severity": "huge",
                            },
                        ],
                    }
                ],
            )
        )
        messages = self._messages(result)
        self.assertIn("applies_to 'sideways'", messages)
        self.assertIn("applies_to: component", messages)
        self.assertIn("laser", messages)
        self.assertIn("severity 'huge'", messages)

    def test_old_template_keys_are_errors(self):
        result = validate_pack(
            _pack(
                self.root,
                template={
                    "nodes": [
                        {
                            "id": "z",
                            "type": "trustZone",
                            "data": {"zoneType": "zoneRestricted", "trustLevel": 140},
                        },
                        {"id": "n", "type": "process", "data": {"kind": "blender"}},
                    ],
                    "edges": [
                        {
                            "id": "e",
                            "type": "dataFlow",
                            "data": {"authenticated": True, "flowType": "beam"},
                        }
                    ],
                },
            )
        )
        messages = self._messages(result)
        self.assertIn("zoneRestricted", messages)
        self.assertIn("legacy value", messages)
        self.assertIn("trustLevel '140'", messages)
        self.assertIn("kind 'blender'", messages)
        self.assertIn("'authenticated' is retired", messages)
        self.assertIn("flowType 'beam'", messages)
        self.assertFalse(result.success)
