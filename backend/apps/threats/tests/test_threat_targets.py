"""One threat table: targets, whole-system threats, numbers, generation triggers."""

import threading

from django.contrib.auth import get_user_model
from django.db import connection, transaction
from django.test import TestCase, TransactionTestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.diagrams.models import DFD
from apps.diagrams.services import sync_dfd_nodes_to_components
from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import ComponentLibrary, Flow, OrgsystemComponent, Zone
from apps.threat_models.models import Blueprint, ThreatModel
from apps.threat_models.numbering import THREATS, allocate_numbers
from apps.threats.models import (
    ComponentLibraryThreat,
    CountermeasureLibrary,
    InstanceCountermeasure,
    InstanceThreat,
    ThreatLibrary,
)
from apps.threats.services import (
    TargetError,
    create_instance_threat,
    ensure_generated_threats,
    set_targets,
)

User = get_user_model()


class TargetFixture(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="u", email="u@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        cls.threat_model = ThreatModel.objects.create(
            name="TM", organization=cls.organization
        )
        cls.blueprint = cls.threat_model.default_blueprint
        cls.zone = Zone.objects.create(blueprint=cls.blueprint, name="DMZ")
        cls.api = OrgsystemComponent.objects.create(blueprint=cls.blueprint, name="API")
        cls.database = OrgsystemComponent.objects.create(
            blueprint=cls.blueprint, name="DB", category="datastore"
        )
        cls.flow = Flow.objects.create(
            blueprint=cls.blueprint,
            source_component=cls.api,
            dest_component=cls.database,
            label="Query",
        )

    def client_for(self, user):
        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(user).access_token}"
        )
        return client


class TargetServiceTests(TargetFixture):
    def test_a_scenario_can_target_several_rows_of_different_kinds(self):
        threat = create_instance_threat(
            self.threat_model,
            targets=[self.api, self.flow, self.zone],
            threat_name="Multi",
        )
        self.assertEqual(
            [row.target_kind for row in threat.targets.all()],
            ["component", "flow", "zone"],
        )
        self.assertEqual(threat.number, 1)
        self.assertEqual(threat.display_number, "T1")

    def test_targets_and_whole_system_are_exclusive(self):
        with self.assertRaises(TargetError):
            create_instance_threat(self.threat_model, threat_name="Nothing")
        with self.assertRaises(TargetError):
            create_instance_threat(
                self.threat_model,
                targets=[self.api],
                whole_system=True,
                threat_name="Both",
            )

    def test_a_target_from_another_model_is_refused(self):
        other = ThreatModel.objects.create(name="Other", organization=self.organization)
        foreign = OrgsystemComponent.objects.create(
            blueprint=other.default_blueprint, name="Foreign"
        )
        with self.assertRaises(TargetError):
            create_instance_threat(
                self.threat_model, targets=[foreign], threat_name="X"
            )

    def test_set_targets_diffs_and_keeps_order(self):
        threat = create_instance_threat(
            self.threat_model, targets=[self.api, self.flow], threat_name="Edit"
        )
        first_rows = {row.target_kind: row.id for row in threat.targets.all()}
        set_targets(threat, [self.flow, self.zone])
        rows = list(threat.targets.all())
        self.assertEqual([row.target_kind for row in rows], ["flow", "zone"])
        # The flow row survived the edit; only the component row went.
        self.assertEqual(rows[0].id, first_rows["flow"])
        self.assertTrue(InstanceThreat.objects.filter(pk=threat.pk).exists())

    def test_emptying_the_targets_needs_whole_system(self):
        threat = create_instance_threat(
            self.threat_model, targets=[self.api], threat_name="E"
        )
        with self.assertRaises(TargetError):
            set_targets(threat, [])
        set_targets(threat, [], whole_system=True)
        threat.refresh_from_db()
        self.assertTrue(threat.whole_system)
        self.assertEqual(threat.targets.count(), 0)
        self.assertTrue(InstanceThreat.objects.filter(pk=threat.pk).exists())

    def test_deleting_the_last_target_deletes_the_threat(self):
        threat = create_instance_threat(
            self.threat_model, targets=[self.api, self.database], threat_name="Two"
        )
        self.api.delete()
        self.assertTrue(InstanceThreat.objects.filter(pk=threat.pk).exists())
        self.database.delete()
        self.assertFalse(InstanceThreat.objects.filter(pk=threat.pk).exists())

    def test_a_whole_system_threat_survives_target_deletes(self):
        threat = create_instance_threat(
            self.threat_model, whole_system=True, threat_name="Whole"
        )
        self.api.delete()
        self.assertTrue(InstanceThreat.objects.filter(pk=threat.pk).exists())

    def test_a_blueprint_delete_applies_the_same_rule(self):
        second = Blueprint.objects.create(threat_model=self.threat_model, name="Second")
        only_there = OrgsystemComponent.objects.create(blueprint=second, name="Only")
        there_and_here = create_instance_threat(
            self.threat_model, targets=[only_there, self.api], threat_name="Shared"
        )
        gone_with_it = create_instance_threat(
            self.threat_model, targets=[only_there], threat_name="Lost"
        )
        second.delete()
        self.assertTrue(InstanceThreat.objects.filter(pk=there_and_here.pk).exists())
        self.assertEqual(there_and_here.targets.count(), 1)
        self.assertFalse(InstanceThreat.objects.filter(pk=gone_with_it.pk).exists())

    def test_numbers_are_never_reused(self):
        first = create_instance_threat(
            self.threat_model, targets=[self.api], threat_name="1"
        )
        second = create_instance_threat(
            self.threat_model, targets=[self.api], threat_name="2"
        )
        second.delete()
        third = create_instance_threat(
            self.threat_model, targets=[self.api], threat_name="3"
        )
        self.assertEqual((first.number, third.number), (1, 3))
        self.assertEqual(allocate_numbers(self.threat_model.id, THREATS, 3), [4, 5, 6])
        self.assertEqual(allocate_numbers(self.threat_model.id, THREATS, 0), [])

    def test_deleting_a_threat_leaves_countermeasures_users_touched(self):
        threat = create_instance_threat(
            self.threat_model, targets=[self.api], threat_name="T"
        )
        generated = InstanceCountermeasure.objects.create(
            threat_model=self.threat_model,
            countermeasure_name="Gen",
            auto_generated=True,
        )
        edited = InstanceCountermeasure.objects.create(
            threat_model=self.threat_model,
            countermeasure_name="Edited",
            auto_generated=False,
        )
        for countermeasure in (generated, edited):
            countermeasure.threat_links.create(threat=threat)
        threat.delete()
        self.assertFalse(
            InstanceCountermeasure.objects.filter(pk=generated.pk).exists()
        )
        self.assertTrue(InstanceCountermeasure.objects.filter(pk=edited.pk).exists())


class GenerationTests(TargetFixture):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.web_library = ComponentLibrary.objects.create(
            name="Web app", category=ComponentLibrary.Category.PROCESS
        )
        cls.queue_library = ComponentLibrary.objects.create(
            name="Queue", category=ComponentLibrary.Category.PROCESS
        )
        cls.xss = ThreatLibrary.objects.create(name="XSS", description="d")
        cls.sniff = ThreatLibrary.objects.create(name="Sniffing", description="d")
        cls.poison = ThreatLibrary.objects.create(name="Poisoning", description="d")
        ComponentLibraryThreat.objects.create(
            component_library=cls.web_library,
            threat_library=cls.xss,
            applies_to=ComponentLibraryThreat.AppliesTo.COMPONENT,
            default_level="high",
        )
        ComponentLibraryThreat.objects.create(
            component_library=cls.web_library,
            threat_library=cls.sniff,
            applies_to=ComponentLibraryThreat.AppliesTo.FLOW,
        )
        ComponentLibraryThreat.objects.create(
            component_library=cls.queue_library,
            threat_library=cls.poison,
            applies_to=ComponentLibraryThreat.AppliesTo.COMPONENT,
        )
        cls.waf = CountermeasureLibrary.objects.create(name="WAF", description="d")
        cls.waf.applicable_threats.add(cls.xss)

    def _dfd(self, library_id):
        return {
            "nodes": [
                {
                    "id": "n1",
                    "type": "process",
                    "position": {"x": 0, "y": 0},
                    "data": {"label": "Web", "component_library_id": library_id},
                },
                {
                    "id": "n2",
                    "type": "datastore",
                    "position": {"x": 0, "y": 0},
                    "data": {"label": "Store"},
                },
            ],
            "edges": [
                {
                    "id": "e1",
                    "type": "dataFlow",
                    "source": "n1",
                    "target": "n2",
                    "data": {},
                }
            ],
        }

    def test_generation_runs_on_creation_and_not_on_an_ordinary_save(self):
        dfd = DFD.objects.create(
            blueprint=self.blueprint,
            name="D",
            is_primary=True,
            canvas_data=self._dfd(self.web_library.id),
        )
        result = sync_dfd_nodes_to_components(dfd, self.blueprint)
        self.assertEqual(result["threats_generated"], 1)
        self.assertEqual(result["flow_threats_generated"], 1)
        web = self.blueprint.components.get(name="Web")
        xss = InstanceThreat.objects.get(
            targets__component=web, threat_library=self.xss
        )
        self.assertTrue(xss.auto_generated)
        self.assertEqual(xss.rating.level, "high")
        self.assertEqual(
            list(
                xss.countermeasure_links.values_list(
                    "countermeasure__countermeasure_name", flat=True
                )
            ),
            ["WAF"],
        )
        flow_threat = InstanceThreat.objects.get(threat_library=self.sniff)
        self.assertEqual(flow_threat.targets.get().target_kind, "flow")

        xss.delete()
        old = dfd.canvas_data
        result = sync_dfd_nodes_to_components(dfd, self.blueprint, old_canvas_data=old)
        self.assertEqual(result["threats_generated"], 0)
        self.assertFalse(
            InstanceThreat.objects.filter(threat_library=self.xss).exists()
        )

        # Asking for it brings it back, with a fresh number.
        self.assertEqual(ensure_generated_threats(web), 1)
        self.assertEqual(InstanceThreat.objects.get(threat_library=self.xss).number, 3)

    def test_regeneration_dedupes_including_merged_scenarios(self):
        web = OrgsystemComponent.objects.create(
            blueprint=self.blueprint, name="Web", component_library=self.web_library
        )
        self.assertEqual(ensure_generated_threats(web), 1)
        self.assertEqual(ensure_generated_threats(web), 0)
        merged = InstanceThreat.objects.get(threat_library=self.xss)
        set_targets(merged, [web, self.api])
        self.assertEqual(ensure_generated_threats(web), 0)
        self.assertEqual(
            InstanceThreat.objects.filter(threat_library=self.xss).count(), 1
        )

    def test_a_technology_change_keeps_the_row_and_its_numbers(self):
        dfd = DFD.objects.create(
            blueprint=self.blueprint,
            name="D",
            is_primary=True,
            canvas_data=self._dfd(self.web_library.id),
        )
        sync_dfd_nodes_to_components(dfd, self.blueprint)
        web = self.blueprint.components.get(name="Web")
        flow = self.blueprint.flows.get(source_component=web)
        custom = create_instance_threat(
            self.threat_model,
            targets=[web],
            threat_name="Custom",
            level="low",
        )
        edited_generated = InstanceThreat.objects.get(threat_library=self.sniff)
        edited_generated.auto_generated = False
        edited_generated.save()
        untouched = InstanceThreat.objects.get(threat_library=self.xss)

        old = dfd.canvas_data
        new = self._dfd(self.queue_library.id)
        new["nodes"][0]["data"]["component_id"] = web.id
        new["nodes"][1]["data"]["component_id"] = self.blueprint.components.get(
            name="Store"
        ).id
        new["edges"][0]["data"]["dataflow_id"] = flow.id
        dfd.canvas_data = new
        sync_dfd_nodes_to_components(dfd, self.blueprint, old_canvas_data=old)

        web.refresh_from_db()
        self.assertEqual(web.component_library, self.queue_library)
        self.assertEqual(self.blueprint.flows.get(pk=flow.pk).source_component, web)
        self.assertFalse(InstanceThreat.objects.filter(pk=untouched.pk).exists())
        self.assertEqual(InstanceThreat.objects.get(pk=custom.pk).number, custom.number)
        self.assertEqual(
            InstanceThreat.objects.get(pk=edited_generated.pk).number,
            edited_generated.number,
        )
        poison = InstanceThreat.objects.get(threat_library=self.poison)
        self.assertEqual(poison.targets.get().target, web)
        self.assertEqual(poison.number, 4)


class ThreatApiTests(TargetFixture):
    def setUp(self):
        self.client = self.client_for(self.user)

    def test_create_with_several_targets_and_edit_them(self):
        response = self.client.post(
            "/api/threats/",
            {
                "threat_model": self.threat_model.id,
                "threat_name": "Multi",
                "inherent_severity": "high",
                "targets": [
                    {"type": "component", "id": self.api.id},
                    {"type": "flow", "id": self.flow.id},
                ],
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.data["display_number"], "T1")
        self.assertEqual(
            [(t["type"], t["name"]) for t in response.data["targets"]],
            [("component", "API"), ("flow", "Query")],
        )
        threat_id = response.data["id"]

        edited = self.client.post(
            f"/api/threats/{threat_id}/set_targets/",
            {"targets": [{"type": "zone", "id": self.zone.id}]},
            format="json",
        )
        self.assertEqual(edited.status_code, 200, edited.content)
        self.assertEqual([t["type"] for t in edited.data["targets"]], ["zone"])

        emptied = self.client.post(
            f"/api/threats/{threat_id}/set_targets/", {"targets": []}, format="json"
        )
        self.assertEqual(emptied.status_code, 400)
        whole = self.client.post(
            f"/api/threats/{threat_id}/set_targets/",
            {"targets": [], "whole_system": True},
            format="json",
        )
        self.assertEqual(whole.status_code, 200, whole.content)
        self.assertTrue(whole.data["whole_system"])
        self.assertEqual(whole.data["targets"], [])

    def test_a_target_outside_the_model_is_refused(self):
        other = ThreatModel.objects.create(name="Other", organization=self.organization)
        foreign = OrgsystemComponent.objects.create(
            blueprint=other.default_blueprint, name="Foreign"
        )
        response = self.client.post(
            "/api/threats/",
            {
                "threat_model": self.threat_model.id,
                "threat_name": "X",
                "targets": [{"type": "component", "id": foreign.id}],
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("targets", response.data)

    def test_filters_and_search_by_number(self):
        create_instance_threat(
            self.threat_model, targets=[self.api], threat_name="Alpha"
        )
        flow_threat = create_instance_threat(
            self.threat_model, targets=[self.flow], threat_name="Beta"
        )
        for _ in range(5):
            create_instance_threat(
                self.threat_model, whole_system=True, threat_name="W"
            )

        by_flow = self.client.get(f"/api/threats/?flow={self.flow.id}")
        self.assertEqual([t["id"] for t in by_flow.data["results"]], [flow_threat.id])
        by_number = self.client.get("/api/threats/?search=T7")
        self.assertEqual(
            [t["display_number"] for t in by_number.data["results"]], ["T7"]
        )
        plain = self.client.get("/api/threats/?search=7")
        self.assertEqual(len(plain.data["results"]), 1)
        by_name = self.client.get("/api/threats/?search=alp")
        self.assertEqual(
            [t["threat_name_display"] for t in by_name.data["results"]], ["Alpha"]
        )
        whole = self.client.get("/api/threats/?whole_system=true")
        self.assertEqual(len(whole.data["results"]), 5)

    def test_a_user_edit_clears_auto_generated(self):
        threat = create_instance_threat(
            self.threat_model,
            targets=[self.api],
            threat_name="Gen",
            auto_generated=True,
        )
        response = self.client.patch(
            f"/api/threats/{threat.id}/", {"triage_status": "accept"}, format="json"
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertFalse(response.data["auto_generated"])


class NumberingConcurrencyTests(TransactionTestCase):
    """Two transactions allocating at once never get the same number."""

    def test_two_transactions_get_disjoint_numbers(self):
        organization = Organization.objects.create(name="Org", domain="org.test")
        threat_model = ThreatModel.objects.create(name="TM", organization=organization)
        first_locked = threading.Event()
        release_first = threading.Event()
        results = {}

        def first():
            try:
                with transaction.atomic():
                    results["first"] = allocate_numbers(threat_model.id, THREATS, 2)
                    first_locked.set()
                    release_first.wait(timeout=5)
            finally:
                connection.close()

        def second():
            try:
                first_locked.wait(timeout=5)
                with transaction.atomic():
                    results["second"] = allocate_numbers(threat_model.id, THREATS, 2)
            finally:
                connection.close()

        threads = [threading.Thread(target=first), threading.Thread(target=second)]
        for thread in threads:
            thread.start()
        first_locked.wait(timeout=5)
        # The second allocation is blocked on the row lock until the first commits.
        threads[1].join(timeout=0.5)
        self.assertTrue(threads[1].is_alive())
        self.assertNotIn("second", results)
        release_first.set()
        for thread in threads:
            thread.join(timeout=5)
        self.assertEqual(results["first"], [1, 2])
        self.assertEqual(results["second"], [3, 4])
