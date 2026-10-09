"""The TM-BOM example in the docs validates against the pinned schema.

``docs/guides/ai-threat-model-generation.md`` carries a complete hand-written
document that assistants copy; this test keeps it from drifting from the
schema (plan section 12). The importing guide has no full document, only
fragments, so only the authoring guide is checked.

The backend container mounts ``backend/`` and ``libraries/`` but not ``docs/``,
so the test skips when the guide is not on disk. Run it from a checkout that
has ``docs/`` (or mount ``./docs:/app/docs``) for it to count.
"""

import json
import re
from pathlib import Path
from unittest import skipUnless

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.organizations.models import Organization, OrganizationMember
from apps.threat_models.tmbom import TmBomAdapter
from apps.threat_models.tmbom.testing import assert_valid_tmbom

REPO_ROOT = Path(__file__).resolve().parents[4]
AUTHORING_GUIDE = REPO_ROOT / "docs" / "guides" / "ai-threat-model-generation.md"

JSON_BLOCK = re.compile(r"```json\n(.*?)\n```", re.DOTALL)


def complete_documents(markdown: str) -> list[dict]:
    """Every fenced JSON block that parses and declares a TM-BOM envelope.

    Fragments with placeholders such as ``<one blueprint object>`` do not
    parse and are skipped; the complete example does.
    """
    documents = []
    for block in JSON_BLOCK.findall(markdown):
        try:
            parsed = json.loads(block)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and parsed.get("specFormat") == "CycloneDX":
            documents.append(parsed)
    return documents


@skipUnless(AUTHORING_GUIDE.exists(), "docs/ is not available in this environment")
class DocsExampleTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.documents = complete_documents(AUTHORING_GUIDE.read_text(encoding="utf-8"))
        cls.organization = Organization.objects.create(
            name="Docs org", domain="docs.test"
        )
        cls.user = get_user_model().objects.create_user(
            username="docs", email="docs@docs.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )

    def test_authoring_guide_has_one_complete_example(self):
        self.assertEqual(len(self.documents), 1)

    def test_authoring_guide_example_is_a_valid_tmbom(self):
        for index, document in enumerate(self.documents):
            assert_valid_tmbom(document, context=f"example {index + 1} of the guide")

    def test_authoring_guide_example_imports_without_warnings(self):
        """The guide promises a clean import; hold it to that."""
        (document,) = self.documents
        threat_model, summary = TmBomAdapter().import_data(
            document, self.organization, self.user
        )
        self.assertEqual(summary.get("warnings", []), [])
        self.assertEqual(threat_model.threats.count(), 5)
        self.assertEqual(threat_model.countermeasures.count(), 4)
        self.assertEqual(threat_model.risks.count(), 2)
