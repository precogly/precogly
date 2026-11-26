"""The pack cross-check flags components no pack backs, never drawn boundaries."""

from django.test import TestCase

from apps.organizations.models import Organization
from apps.packs.models import LibraryPack
from apps.systems.models import ComponentLibrary, OrgsystemComponent
from apps.threat_models.models import ThreatModel, ThreatModelLibraryPack
from apps.threat_models.serializers import ThreatModelSerializer


class ComponentsNotInPackTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        organization = Organization.objects.create(name="Org", domain="org.test")
        cls.pack = LibraryPack.objects.create(
            slug="aws-overlay",
            name="AWS overlay",
            description="Test pack",
            pack_type="technology",
            version="1.0.0",
            author="Test",
        )
        cls.threat_model = ThreatModel.objects.create(
            name="TM", organization=organization
        )
        ThreatModelLibraryPack.objects.create(
            threat_model=cls.threat_model, library_pack=cls.pack
        )
        cls.blueprint = cls.threat_model.default_blueprint
        library = ComponentLibrary.objects.create(
            name="RDS",
            category=ComponentLibrary.Category.DATASTORE,
            slug="rds",
            source_pack=cls.pack,
        )
        cls.backed = OrgsystemComponent.objects.create(
            blueprint=cls.blueprint, name="Database", component_library=library
        )
        cls.unbacked = OrgsystemComponent.objects.create(
            blueprint=cls.blueprint, name="Custom job"
        )
        cls.system = OrgsystemComponent.objects.create(
            blueprint=cls.blueprint, name="Boundary", kind="system"
        )
        cls.subsystem = OrgsystemComponent.objects.create(
            blueprint=cls.blueprint, name="Inner boundary", kind="subsystem"
        )

    def _flagged_names(self):
        ids = [
            self.backed.id,
            self.unbacked.id,
            self.system.id,
            self.subsystem.id,
        ]
        signals = ThreatModelSerializer()._compute_quality_signals(
            self.threat_model, ids, []
        )
        signal = next(s for s in signals if s["id"] == "components_not_in_pack")
        return [item["name"] for item in signal["flagged_items"]]

    def test_flags_only_the_component_no_pack_backs(self):
        self.assertEqual(self._flagged_names(), ["Custom job"])

    def test_boundaries_alone_do_not_warn(self):
        signals = ThreatModelSerializer()._compute_quality_signals(
            self.threat_model, [self.system.id, self.subsystem.id], []
        )
        signal = next(s for s in signals if s["id"] == "components_not_in_pack")
        self.assertEqual(signal["status"], "ok")
