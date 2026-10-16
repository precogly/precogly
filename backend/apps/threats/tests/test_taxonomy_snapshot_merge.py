"""A threat's snapshot categories stay listed next to categories added by hand."""

from django.test import TestCase

from apps.organizations.models import Organization
from apps.systems.models import OrgsystemComponent
from apps.threat_models.models import ThreatModel
from apps.threats.models import (
    ExternalTaxonomy,
    InstanceThreatTaxonomyEntry,
    TaxonomyEntry,
)
from apps.threats.serializers import _merge_taxonomy_entries
from apps.threats.services import create_instance_threat


class SnapshotMergeTests(TestCase):
    def test_snapshot_survives_an_added_category(self):
        organization = Organization.objects.create(name="Org", domain="org.test")
        threat_model = ThreatModel.objects.create(name="M", organization=organization)
        api = OrgsystemComponent.objects.create(
            blueprint=threat_model.default_blueprint, name="API"
        )
        threat = create_instance_threat(threat_model, targets=[api], threat_name="X")
        threat.taxonomy_snapshot = [
            {"taxonomy_slug": "cwe", "external_id": "CWE-79", "title": "XSS"}
        ]
        threat.save(update_fields=["taxonomy_snapshot"])
        taxonomy = ExternalTaxonomy.objects.create(slug="capec", name="CAPEC")
        entry = TaxonomyEntry.objects.create(
            taxonomy=taxonomy, external_id="CAPEC-63", title="XSS"
        )
        InstanceThreatTaxonomyEntry.objects.create(threat=threat, taxonomy_entry=entry)

        merged = _merge_taxonomy_entries(threat)

        self.assertEqual(
            {(item["external_id"], item["source"]) for item in merged},
            {("CWE-79", "snapshot"), ("CAPEC-63", "instance")},
        )
