"""The step 3 adapter slice: scenarios, abstract threats and actors, out and back."""

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import Flow, OrgsystemComponent, Zone
from apps.threat_models.models import ThreatModel, ThreatModelState
from apps.threat_models.tmbom import TmBomAdapter
from apps.threat_models.tmbom.testing import assert_valid_tmbom
from apps.threats.models import (
    ExternalTaxonomy,
    InstanceThreatTaxonomyEntry,
    TaxonomyEntry,
    ThreatLibrary,
    ThreatLibraryTaxonomyEntry,
    ThreatPersona,
    ThreatSource,
    ThreatSourceLink,
)
from apps.threats.services import create_instance_threat

User = get_user_model()


def _next_number(threat_model) -> int:
    return ThreatModelState.objects.get(threat_model=threat_model).next_threat_number


def build_model(organization, user):
    threat_model = ThreatModel.objects.create(
        name="Payments", organization=organization, created_by=user
    )
    blueprint = threat_model.default_blueprint
    dmz = Zone.objects.create(blueprint=blueprint, name="DMZ")
    api = OrgsystemComponent.objects.create(
        blueprint=blueprint, name="API", category="process", zone=dmz
    )
    database = OrgsystemComponent.objects.create(
        blueprint=blueprint, name="Database", category="datastore"
    )
    flow = Flow.objects.create(
        blueprint=blueprint,
        source_component=api,
        dest_component=database,
        label="Query",
    )

    stride = ExternalTaxonomy.objects.create(slug="stride", name="STRIDE")
    tampering = TaxonomyEntry.objects.create(
        taxonomy=stride, external_id="tampering", title="Tampering"
    )
    capec = ExternalTaxonomy.objects.create(slug="capec", name="CAPEC")
    capec_66 = TaxonomyEntry.objects.create(
        taxonomy=capec, external_id="66", title="SQL Injection"
    )
    library = ThreatLibrary.objects.create(
        name="SQL injection",
        description="Injected SQL",
        slug="sql-injection",
        qualified_slug="demo/sql-injection",
    )
    ThreatLibraryTaxonomyEntry.objects.create(
        threat_library=library, taxonomy_entry=tampering
    )
    ThreatLibraryTaxonomyEntry.objects.create(
        threat_library=library, taxonomy_entry=capec_66
    )
    adversarial, _ = ThreatSource.objects.get_or_create(
        slug="adversarial", defaults={"name": "Adversarial"}
    )

    persona = ThreatPersona.objects.create(
        threat_model=threat_model,
        symbolic_name="malicious-insider",
        name="Malicious insider",
        description="Staff with database access",
        skill_level="high",
    )

    multi = create_instance_threat(
        threat_model,
        targets=[api, flow],
        threat_library=library,
        level="high",
        auto_generated=True,
        actor_persona=persona,
        intent="targeted",
        access_level="internal",
        decision_rationale="Accepted for now",
        triage_status="accept",
    )
    ThreatSourceLink.objects.create(source=adversarial, threat=multi)
    InstanceThreatTaxonomyEntry.objects.create(taxonomy_entry=capec_66, threat=multi)

    create_instance_threat(
        threat_model,
        whole_system=True,
        threat_name="Backup theft",
        threat_description="Backups leave the building",
        level="medium",
        threat_actor_text="Organized crime",
        taxonomy_snapshot=[
            {
                "taxonomy_slug": "stride",
                "external_id": "Information Disclosure",
                "title": "ID",
            },
            {"taxonomy_slug": "capec", "external_id": "150", "title": "Collect data"},
        ],
    )
    create_instance_threat(
        threat_model, targets=[dmz], threat_name="Zone hopping", level="low"
    )
    return threat_model


class ExportTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="u", email="u@org.test", password="x"
        )
        cls.threat_model = build_model(cls.organization, cls.user)
        cls.document = TmBomAdapter().export_data(cls.threat_model)

    def test_export_validates(self):
        assert_valid_tmbom(self.document, context="step 3 export")

    def test_abstract_threats_use_the_library_slug_and_spec_taxonomies(self):
        by_ref = {t["bom-ref"]: t for t in self.document["threats"]["threats"]}
        library = by_ref["threat-demo/sql-injection"]
        self.assertEqual(library["name"], "SQL injection")
        self.assertEqual(
            library["categories"], [{"taxonomy": "STRIDE", "category": "tampering"}]
        )
        self.assertEqual(library["properties"][0]["name"], "precogly:taxonomy")
        self.assertIn('"external_id":"66"', library["properties"][0]["value"])
        self.assertEqual(library["origin"], "adversarial")

        custom = next(t for t in by_ref.values() if t["name"] == "Backup theft")
        self.assertTrue(custom["bom-ref"].startswith("threat-custom-"))
        self.assertEqual(
            custom["categories"],
            [{"taxonomy": "STRIDE", "category": "information-disclosure"}],
        )
        self.assertNotIn("origin", custom)

    def test_scenarios_carry_targets_actor_and_number(self):
        scenarios = {s["name"]: s for s in self.document["threats"]["scenarios"]}
        first = self.document["blueprints"][0]
        api_ref = next(a["bom-ref"] for a in first["assets"] if a["name"] == "API")
        flow_ref = first["flows"][0]["bom-ref"]
        zone_ref = first["zones"][0]["bom-ref"]

        multi = scenarios["SQL injection"]
        self.assertEqual(multi["threats"], ["threat-demo/sql-injection"])
        self.assertEqual(multi["affectedAssets"], [api_ref, flow_ref])
        self.assertEqual(multi["intent"], "targeted")
        self.assertEqual(multi["accessLevel"], "internal")
        properties = {p["name"]: p["value"] for p in multi["properties"]}
        self.assertEqual(properties["precogly:number"], "1")
        self.assertEqual(properties["precogly:triage-status"], "accept")
        self.assertEqual(properties["precogly:decision-rationale"], "Accepted for now")
        self.assertEqual(properties["precogly:auto-generated"], "true")
        self.assertEqual(properties["precogly:threat-sources"], '["adversarial"]')
        self.assertIn('"external_id":"66"', properties["precogly:instance-categories"])

        whole = scenarios["Backup theft"]
        self.assertEqual(
            whole["affectedAssets"], [self.document["metadata"]["component"]["bom-ref"]]
        )
        self.assertEqual(scenarios["Zone hopping"]["affectedAssets"], [zone_ref])

        actors = {a["bom-ref"]: a for a in first["actors"]}
        self.assertEqual(
            multi["actor"],
            f"actor-persona-{self.threat_model.threat_personas.get().pk}",
        )
        persona_party = actors[multi["actor"]]["party"]
        self.assertEqual(persona_party["roles"], [{"role": "attacker"}])
        self.assertEqual(persona_party["persona"]["archetype"], "insider-threat")
        text_actor = actors[whole["actor"]]
        self.assertEqual(text_actor["properties"][0]["value"], "Organized crime")
        self.assertEqual(
            text_actor["party"]["persona"]["description"], "Organized crime"
        )

    def test_document_carries_the_next_threat_number(self):
        properties = {p["name"]: p["value"] for p in self.document["properties"]}
        self.assertEqual(properties["precogly:next-threat-number"], "4")


class RoundTripTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="u", email="u@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        cls.source_model = build_model(cls.organization, cls.user)

    def test_scenarios_survive_a_round_trip(self):
        adapter = TmBomAdapter()
        document = adapter.export_data(self.source_model)
        # Delete T2 first, so the counter test below means something.
        imported, summary = adapter.import_data(document, self.organization, self.user)
        self.assertEqual(summary["threats"], 3)
        self.assertEqual(summary["threat_personas"], 1)
        self.assertNotIn("warnings", summary)

        threats = {t.threat_name: t for t in imported.threats.all()}
        multi = threats["SQL injection"]
        self.assertEqual(multi.number, 1)
        self.assertEqual(multi.threat_library.qualified_slug, "demo/sql-injection")
        self.assertEqual(
            [
                (
                    row.target_kind,
                    row.target.name
                    if row.target_kind == "component"
                    else row.target.label,
                )
                for row in multi.targets.all()
            ],
            [("component", "API"), ("flow", "Query")],
        )
        self.assertTrue(multi.auto_generated)
        self.assertEqual(multi.triage_status, "accept")
        self.assertEqual(multi.intent, "targeted")
        self.assertEqual(multi.actor_persona.symbolic_name, "malicious-insider")
        self.assertEqual(multi.actor_persona.skill_level, "high")
        self.assertEqual(
            list(multi.source_links.values_list("source__slug", flat=True)),
            ["adversarial"],
        )
        self.assertEqual(
            list(
                multi.instance_taxonomy_links.values_list(
                    "taxonomy_entry__external_id", flat=True
                )
            ),
            ["66"],
        )

        whole = threats["Backup theft"]
        self.assertTrue(whole.whole_system)
        self.assertEqual(whole.targets.count(), 0)
        self.assertEqual(whole.threat_actor_text, "Organized crime")
        self.assertIsNone(whole.actor_persona)
        self.assertIsNone(whole.threat_library)
        self.assertEqual(
            whole.taxonomy_snapshot[0]["external_id"], "information-disclosure"
        )

        zone_threat = threats["Zone hopping"]
        self.assertEqual(zone_threat.targets.get().target_kind, "zone")
        self.assertEqual(_next_number(imported), 4)

        again = adapter.export_data(imported)
        assert_valid_tmbom(again)
        self.assertEqual(
            {s["bom-ref"] for s in again["threats"]["scenarios"]},
            {s["bom-ref"] for s in document["threats"]["scenarios"]},
        )
        self.assertEqual(
            {t["bom-ref"] for t in again["threats"]["threats"]},
            {t["bom-ref"] for t in document["threats"]["threats"]},
        )

    def test_the_counter_never_hands_out_a_deleted_number_again(self):
        adapter = TmBomAdapter()
        self.source_model.threats.get(number=3).delete()
        document = adapter.export_data(self.source_model)
        imported, _ = adapter.import_data(document, self.organization, self.user)
        self.assertEqual(_next_number(imported), 4)
        new_threat = create_instance_threat(
            imported, whole_system=True, threat_name="New", level="low"
        )
        self.assertEqual(new_threat.number, 4)

    def test_other_tools_scenarios_are_split_kept_and_warned(self):
        document = {
            "specFormat": "CycloneDX",
            "specVersion": "2.0",
            "metadata": {
                "component": {"type": "application", "bom-ref": "sys", "name": "X"}
            },
            "blueprints": [
                {
                    "name": "Other tool",
                    "modelTypes": ["data-flow"],
                    "assets": [{"bom-ref": "a1", "name": "Gateway", "type": "gateway"}],
                    "dataSets": [
                        {"bom-ref": "ds1", "name": "PII", "description": "PII"}
                    ],
                    "actors": [
                        {
                            "bom-ref": "user",
                            "description": "Customer",
                            "party": {"roles": [{"role": "end-user"}], "person": {}},
                        },
                        {
                            "bom-ref": "crime",
                            "party": {
                                "bom-ref": "crime-party",
                                "roles": [{"role": "attacker"}],
                                "persona": {
                                    "description": "Organized crime group",
                                    "archetype": "organized-crime",
                                },
                            },
                        },
                        {
                            "bom-ref": "bystander",
                            "party": {"roles": [{"role": "auditor"}], "person": {}},
                        },
                    ],
                    "flows": [
                        {
                            "bom-ref": "f1",
                            "name": "Browse",
                            "type": "data",
                            "source": "user",
                            "destination": "a1",
                        }
                    ],
                }
            ],
            "threats": {
                "threats": [
                    {
                        "bom-ref": "t-spoof",
                        "name": "Spoofing",
                        "categories": [{"taxonomy": "STRIDE", "category": "spoofing"}],
                        "origin": "adversarial",
                    },
                    {"bom-ref": "t-dos", "name": "Flooding"},
                ],
                "scenarios": [
                    {
                        "bom-ref": "s1",
                        "name": "Fake customer",
                        "threats": ["t-spoof", "t-dos"],
                        "affectedAssets": ["a1", "ds1"],
                        "actor": "crime",
                        "properties": [{"name": "precogly:number", "value": "7"}],
                    },
                    {
                        "bom-ref": "s2",
                        "name": "Everything burns",
                        "threats": ["t-dos"],
                        "affectedAssets": ["sys"],
                    },
                    {"bom-ref": "s3", "name": "Unplaced", "threats": ["t-dos"]},
                ],
            },
        }
        imported, summary = TmBomAdapter().import_data(
            document, self.organization, self.user
        )
        warnings = "\n".join(summary["warnings"])
        self.assertEqual(summary["threats"], 4)
        blueprint = imported.default_blueprint
        self.assertEqual(
            blueprint.components.get(name="Customer").category, "external_human_actor"
        )
        self.assertEqual(blueprint.flows.count(), 1)

        split = list(imported.threats.order_by("number"))
        self.assertEqual([t.number for t in split], [1, 2, 3, 7])
        first = imported.threats.get(number=7)
        self.assertEqual(first.threat_name, "Spoofing")
        self.assertEqual(first.format_metadata["cyclonedx"]["bom_ref"], "s1")
        self.assertEqual(
            first.format_metadata["cyclonedx"]["threat_bom_ref"], "t-spoof"
        )
        self.assertEqual(
            first.format_metadata["cyclonedx"]["extra_affected_assets"], ["ds1"]
        )
        self.assertEqual(first.targets.get().target.name, "Gateway")
        self.assertEqual(first.taxonomy_snapshot[0]["external_id"], "spoofing")
        self.assertEqual(first.actor_persona.name, "Organized crime group")
        self.assertEqual(
            first.actor_persona.format_metadata["cyclonedx"]["party_bom_ref"],
            "crime-party",
        )
        self.assertEqual(
            list(first.source_links.values_list("source__slug", flat=True)),
            ["adversarial"],
        )
        second = imported.threats.get(
            threat_name="Flooding", format_metadata__cyclonedx__split_from="s1"
        )
        self.assertEqual(second.targets.get().target.name, "Gateway")
        self.assertTrue(
            imported.threats.get(threat_name="Everything burns").whole_system
        )
        self.assertTrue(imported.threats.get(threat_name="Unplaced").whole_system)
        self.assertEqual(imported.threat_personas.count(), 1)
        self.assertIn("split", warnings)
        self.assertIn("ds1", warnings)
        self.assertEqual(_next_number(imported), 8)

        again = TmBomAdapter().export_data(imported)
        assert_valid_tmbom(again)
        refs = {s["bom-ref"] for s in again["threats"]["scenarios"]}
        self.assertIn("s1", refs)
        self.assertEqual(
            {t["bom-ref"] for t in again["threats"]["threats"]}, {"t-spoof", "t-dos"}
        )
