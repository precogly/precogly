"""Which pack's component a node binds to when two packs share a short name.

demo-aws (bundled with the app) and the full aws pack both hold `s3`, named
"Amazon S3". A node must bind to the same row every time, whichever pack was
imported first:
  - a diagram made from a template binds to the template's own pack,
  - otherwise a full pack wins over a demo pack.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.diagrams.ai.generate import _validate_and_resolve
from apps.diagrams.models import DFD, DFDTemplatesLibrary
from apps.diagrams.services import sync_dfd_nodes_to_components
from apps.organizations.models import Organization
from apps.packs.models import LibraryPack
from apps.systems.models import ComponentLibrary, OrgsystemComponent
from apps.threat_models.models import ThreatModel, ThreatModelLibraryPack

User = get_user_model()


class ComponentLookupBetweenPacksTests(TestCase):
    def _make_pack(self, pack_slug: str) -> LibraryPack:
        library_pack = LibraryPack.objects.create(
            slug=pack_slug,
            name=pack_slug,
            pack_type=LibraryPack.PackType.FULL,
            version="1.0.0",
            author="Precogly",
        )
        ComponentLibrary.objects.create(
            source_pack=library_pack,
            slug="s3",
            qualified_slug=f"{pack_slug}/s3",
            name="Amazon S3",
            category="datastore",
            component_type="Object Storage",
            provider="aws",
        )
        DFDTemplatesLibrary.objects.create(
            source_pack=library_pack,
            slug="serverless",
            qualified_slug=f"{pack_slug}/serverless",
            name=f"{pack_slug} serverless",
            category="webApplication",
            diagram_type="level1",
            canvas_data={"nodes": [], "edges": []},
        )
        return library_pack

    def _import_packs(self, pack_slugs: list[str]) -> None:
        """Create the packs in this order and connect all of them, as import does."""
        for pack_slug in pack_slugs:
            library_pack = self._make_pack(pack_slug)
            ThreatModelLibraryPack.objects.create(
                threat_model=self.threat_model, library_pack=library_pack
            )

    def setUp(self):
        organization = Organization.objects.create(name="Org", domain="org.test")
        self.user = User.objects.create_user(
            username="u", email="u@org.test", password="x"
        )
        self.threat_model = ThreatModel.objects.create(
            name="TM", organization=organization
        )

    def _bound_pack_slug(self, node_data: dict, template_qualified_slug=None) -> str:
        """Sync one datastore node and return the pack its component came from."""
        template = (
            DFDTemplatesLibrary.objects.get(qualified_slug=template_qualified_slug)
            if template_qualified_slug
            else None
        )
        dfd = DFD.objects.create(
            name=f"DFD {DFD.objects.count()}",
            blueprint=self.threat_model.default_blueprint,
            is_primary=not DFD.objects.exists(),
            updated_by=self.user,
            template_library=template,
            canvas_data={
                "nodes": [
                    {
                        "id": "store",
                        "type": "datastore",
                        "position": {"x": 0, "y": 0},
                        "data": {"label": "Bucket", **node_data},
                    }
                ],
                "edges": [],
            },
        )
        OrgsystemComponent.objects.filter(
            blueprint=self.threat_model.default_blueprint
        ).delete()
        sync_dfd_nodes_to_components(dfd, self.threat_model.default_blueprint)
        component = OrgsystemComponent.objects.get(
            blueprint=self.threat_model.default_blueprint, name="Bucket"
        )
        return component.component_library.source_pack.slug

    def test_both_packs_imported_in_either_order(self):
        for import_order in (["demo-aws", "aws"], ["aws", "demo-aws"]):
            with self.subTest(import_order=import_order):
                self._import_packs(import_order)

                self.assertEqual(
                    self._bound_pack_slug(
                        {"component_ref": "s3"}, "demo-aws/serverless"
                    ),
                    "demo-aws",
                )
                self.assertEqual(
                    self._bound_pack_slug({"component_ref": "s3"}, "aws/serverless"),
                    "aws",
                )
                self.assertEqual(self._bound_pack_slug({"component_ref": "s3"}), "aws")
                self.assertEqual(
                    self._bound_pack_slug({"technology": "Amazon S3"}), "aws"
                )
                self.assertEqual(
                    self._bound_pack_slug({"component_ref": "demo-aws/s3"}),
                    "demo-aws",
                )

                DFD.objects.all().delete()
                ComponentLibrary.objects.all().delete()
                DFDTemplatesLibrary.objects.all().delete()
                ThreatModelLibraryPack.objects.all().delete()
                LibraryPack.objects.all().delete()

    def test_only_the_demo_pack_imported(self):
        self._import_packs(["demo-aws"])

        self.assertEqual(
            self._bound_pack_slug({"component_ref": "s3"}, "demo-aws/serverless"),
            "demo-aws",
        )
        self.assertEqual(self._bound_pack_slug({"component_ref": "s3"}), "demo-aws")
        self.assertEqual(self._bound_pack_slug({"technology": "Amazon S3"}), "demo-aws")

    def test_a_connected_pack_wins_over_an_unconnected_one(self):
        self._make_pack("aws")  # imported, but not connected to this model
        self._import_packs(["demo-aws"])

        self.assertEqual(self._bound_pack_slug({"component_ref": "s3"}), "demo-aws")

    def test_ai_generation_prefers_the_full_pack(self):
        for import_order in (["demo-aws", "aws"], ["aws", "demo-aws"]):
            with self.subTest(import_order=import_order):
                self._import_packs(import_order)
                nodes = [
                    {
                        "id": "store",
                        "type": "datastore",
                        "data": {"label": "Bucket", "component_ref": "s3"},
                    }
                ]

                resolved_nodes, _ = _validate_and_resolve(nodes, [], self.threat_model)

                bound_row = ComponentLibrary.objects.get(
                    id=resolved_nodes[0]["data"]["component_library_id"]
                )
                self.assertEqual(bound_row.qualified_slug, "aws/s3")

                ComponentLibrary.objects.all().delete()
                DFDTemplatesLibrary.objects.all().delete()
                ThreatModelLibraryPack.objects.all().delete()
                LibraryPack.objects.all().delete()
