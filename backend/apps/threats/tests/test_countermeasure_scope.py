"""Control scope, providers, numbers, the orphan rule and the platform gate (step 4)."""

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.diagrams.models import DFD
from apps.diagrams.services import sync_dfd_nodes_to_components
from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import Flow, OrgsystemComponent, Zone
from apps.threat_models.models import ThreatModel
from apps.threat_models.report_service import build_report_data
from apps.threats.models import InstanceCountermeasure
from apps.threats.services import (
    TargetError,
    check_platform_status,
    create_instance_countermeasure,
    create_instance_threat,
    link_countermeasure,
    recalculate_threat_status,
    set_countermeasure_providers,
    set_countermeasure_targets,
)

User = get_user_model()


class ScopeFixture(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.security = User.objects.create_user(
            username="sec", email="sec@org.test", password="x"
        )
        cls.member = User.objects.create_user(
            username="dev", email="dev@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.security, role="security_team"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.member, role="member"
        )
        cls.threat_model = ThreatModel.objects.create(
            name="TM", organization=cls.organization
        )
        cls.blueprint = cls.threat_model.default_blueprint
        cls.zone = Zone.objects.create(blueprint=cls.blueprint, name="DMZ")
        cls.api = OrgsystemComponent.objects.create(blueprint=cls.blueprint, name="API")
        cls.waf = OrgsystemComponent.objects.create(blueprint=cls.blueprint, name="WAF")
        cls.flow = Flow.objects.create(
            blueprint=cls.blueprint,
            source_component=cls.api,
            dest_component=cls.waf,
            label="Query",
        )
        cls.threat = create_instance_threat(
            cls.threat_model,
            targets=[cls.api],
            threat_name="SQLi",
            level="high",
        )

    def client_for(self, user):
        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(user).access_token}"
        )
        return client


class ScopeServiceTests(ScopeFixture):
    def test_targets_are_stored_and_edited_as_a_diff(self):
        control = create_instance_countermeasure(
            self.threat_model, countermeasure_name="TLS", targets=[self.flow, self.zone]
        )
        self.assertEqual(control.display_number, "C1")
        self.assertEqual(
            [r.target_kind for r in control.targets.all()], ["flow", "zone"]
        )
        set_countermeasure_targets(control, [self.zone, self.api])
        self.assertEqual(
            [r.target_kind for r in control.targets.all()], ["zone", "component"]
        )
        set_countermeasure_targets(control, [])
        self.assertEqual(control.targets.count(), 0)
        self.assertTrue(InstanceCountermeasure.objects.filter(pk=control.pk).exists())

    def test_a_target_from_another_model_is_refused(self):
        other = ThreatModel.objects.create(name="Other", organization=self.organization)
        foreign = OrgsystemComponent.objects.create(
            blueprint=other.default_blueprint, name="Foreign"
        )
        control = create_instance_countermeasure(
            self.threat_model, countermeasure_name="X"
        )
        with self.assertRaises(TargetError):
            set_countermeasure_targets(control, [foreign])
        with self.assertRaises(TargetError):
            set_countermeasure_providers(control, [foreign])

    def test_scope_never_changes_a_threat_status(self):
        control = create_instance_countermeasure(
            self.threat_model,
            countermeasure_name="WAF rules",
            status="verified",
            targets=[self.api],
        )
        self.assertEqual(recalculate_threat_status(self.threat), "exposed")
        link_countermeasure(control, self.threat)
        self.assertEqual(recalculate_threat_status(self.threat), "mitigated")
        set_countermeasure_targets(control, [self.zone])
        self.assertEqual(recalculate_threat_status(self.threat), "mitigated")

    def test_providers_are_stored_in_order(self):
        control = create_instance_countermeasure(
            self.threat_model, countermeasure_name="Filter", implemented_by=[self.waf]
        )
        self.assertEqual(
            [link.component for link in control.provider_links.all()], [self.waf]
        )
        set_countermeasure_providers(control, [self.api, self.waf])
        self.assertEqual(
            [link.component for link in control.provider_links.all()],
            [self.api, self.waf],
        )

    def test_numbers_are_allocated_once_and_never_reused(self):
        first = create_instance_countermeasure(
            self.threat_model, countermeasure_name="1"
        )
        second = create_instance_countermeasure(
            self.threat_model, countermeasure_name="2"
        )
        second.delete()
        third = create_instance_countermeasure(
            self.threat_model, countermeasure_name="3"
        )
        self.assertEqual((first.number, third.number), (1, 3))

    def test_orphan_rule_spares_a_scoped_or_edited_control(self):
        scoped = create_instance_countermeasure(
            self.threat_model,
            countermeasure_name="Scoped",
            auto_generated=True,
            targets=[self.zone],
        )
        edited = create_instance_countermeasure(
            self.threat_model, countermeasure_name="Edited", auto_generated=False
        )
        untouched = create_instance_countermeasure(
            self.threat_model, countermeasure_name="Untouched", auto_generated=True
        )
        for control in (scoped, edited, untouched):
            link_countermeasure(control, self.threat)
        self.threat.delete()
        self.assertTrue(InstanceCountermeasure.objects.filter(pk=scoped.pk).exists())
        self.assertTrue(InstanceCountermeasure.objects.filter(pk=edited.pk).exists())
        self.assertFalse(
            InstanceCountermeasure.objects.filter(pk=untouched.pk).exists()
        )

    def test_platform_gate_lives_in_the_service(self):
        check_platform_status(self.security, self.threat_model, "gap", "platform")
        check_platform_status(self.member, self.threat_model, "gap", "implemented")
        check_platform_status(self.member, self.threat_model, "platform", "platform")
        with self.assertRaises(PermissionDenied):
            check_platform_status(self.member, self.threat_model, "gap", "platform")
        with self.assertRaises(PermissionDenied):
            check_platform_status(self.member, self.threat_model, "platform", "gap")

    def test_deleting_a_controls_last_target_warns_from_sync(self):
        dfd = DFD.objects.create(
            blueprint=self.blueprint,
            name="D",
            is_primary=True,
            canvas_data={
                "nodes": [
                    {
                        "id": "n1",
                        "type": "process",
                        "position": {"x": 0, "y": 0},
                        "data": {"label": "Gateway"},
                    }
                ],
                "edges": [],
            },
        )
        sync_dfd_nodes_to_components(dfd, self.blueprint)
        gateway = self.blueprint.components.get(name="Gateway")
        control = create_instance_countermeasure(
            self.threat_model, countermeasure_name="Rate limit", targets=[gateway]
        )
        old = dfd.canvas_data
        dfd.canvas_data = {"nodes": [], "edges": []}
        result = sync_dfd_nodes_to_components(dfd, self.blueprint, old_canvas_data=old)
        self.assertEqual(
            result["warnings"],
            [
                f"{control.display_number} no longer has a scope and now applies to the whole system"
            ],
        )
        control.refresh_from_db()
        self.assertEqual(control.targets.count(), 0)


class UnattachedCountsTests(ScopeFixture):
    def test_unattached_controls_are_listed_and_left_out_of_gap_metrics(self):
        linked = create_instance_countermeasure(
            self.threat_model, countermeasure_name="Linked gap", status="gap"
        )
        link_countermeasure(linked, self.threat)
        create_instance_countermeasure(
            self.threat_model,
            countermeasure_name="Whole system",
            status="gap",
            required_for_release=True,
        )
        report = build_report_data(self.threat_model)
        summary = report["countermeasure_summary"]
        self.assertEqual(
            [c["countermeasure_name"] for c in summary["unattached"]], ["Whole system"]
        )
        self.assertEqual(summary["unattached"][0]["control_number"], "C2")
        self.assertEqual(
            [g["countermeasure_name"] for g in summary["gaps"]], ["Linked gap"]
        )
        metrics = report["summary_metrics"]
        self.assertEqual(metrics["total_gaps"], 1)
        self.assertEqual(metrics["total_unattached"], 1)
        self.assertEqual(metrics["total_countermeasures"], 2)


class CountermeasureApiTests(ScopeFixture):
    def test_create_with_targets_providers_and_source(self):
        client = self.client_for(self.security)
        response = client.post(
            "/api/countermeasures/",
            {
                "threat_model": self.threat_model.id,
                "countermeasure_name": "Rate limiting",
                "status": "planned",
                "source": "Pentest 2026-09",
                "implemented_by_party": "Cloudflare",
                "targets": [{"type": "component", "id": self.api.id}],
                "implemented_by": [self.waf.id],
                "threat_id": self.threat.id,
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.data["display_number"], "C1")
        self.assertEqual(response.data["source"], "Pentest 2026-09")
        self.assertEqual([t["name"] for t in response.data["targets"]], ["API"])
        self.assertEqual(response.data["implemented_by"], [self.waf.id])
        self.assertEqual(response.data["threat_links"][0]["display_number"], "T1")

        edited = client.post(
            f"/api/countermeasures/{response.data['id']}/set_targets/",
            {"targets": [{"type": "zone", "id": self.zone.id}]},
            format="json",
        )
        self.assertEqual(edited.status_code, 200, edited.content)
        self.assertEqual([t["type"] for t in edited.data["targets"]], ["zone"])
        cleared = client.post(
            f"/api/countermeasures/{response.data['id']}/set_targets/",
            {"targets": []},
            format="json",
        )
        self.assertEqual(cleared.data["targets"], [])

    def test_ids_from_another_model_are_refused(self):
        other = ThreatModel.objects.create(name="Other", organization=self.organization)
        foreign = OrgsystemComponent.objects.create(
            blueprint=other.default_blueprint, name="Foreign"
        )
        client = self.client_for(self.security)
        for payload, field in (
            ({"targets": [{"type": "component", "id": foreign.id}]}, "targets"),
            ({"implemented_by": [foreign.id]}, "implemented_by"),
        ):
            response = client.post(
                "/api/countermeasures/",
                {
                    "threat_model": self.threat_model.id,
                    "countermeasure_name": "X",
                    **payload,
                },
                format="json",
            )
            self.assertEqual(response.status_code, 400, response.content)
            self.assertIn(field, response.data)

    def test_platform_status_needs_the_security_team_role(self):
        control = create_instance_countermeasure(
            self.threat_model, countermeasure_name="P"
        )
        denied = self.client_for(self.member).patch(
            f"/api/countermeasures/{control.id}/", {"status": "platform"}, format="json"
        )
        self.assertEqual(denied.status_code, 403)
        allowed = self.client_for(self.security).patch(
            f"/api/countermeasures/{control.id}/", {"status": "platform"}, format="json"
        )
        self.assertEqual(allowed.status_code, 200, allowed.content)


class ScopeLossWarningTests(ScopeFixture):
    """R12: every delete that takes a control's last target warns about it."""

    def scoped_control(self, *targets):
        control = create_instance_countermeasure(
            self.threat_model, countermeasure_name="Scoped"
        )
        set_countermeasure_targets(control, list(targets))
        return control

    def assert_warned(self, response, control):
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            response.json()["warnings"],
            [
                f"{control.display_number} no longer has a scope and now applies "
                "to the whole system"
            ],
        )
        self.assertTrue(InstanceCountermeasure.objects.filter(pk=control.pk).exists())

    def test_zone_delete_warns(self):
        control = self.scoped_control(self.zone)
        response = self.client_for(self.security).delete(f"/api/zones/{self.zone.id}/")
        self.assert_warned(response, control)

    def test_component_delete_warns_for_a_control_on_its_flow(self):
        control = self.scoped_control(self.flow)
        response = self.client_for(self.security).delete(
            f"/api/components/{self.waf.id}/"
        )
        self.assert_warned(response, control)

    def test_flow_delete_warns(self):
        control = self.scoped_control(self.flow)
        response = self.client_for(self.security).delete(f"/api/flows/{self.flow.id}/")
        self.assert_warned(response, control)

    def test_blueprint_delete_warns(self):
        from apps.threat_models.models import Blueprint

        second = Blueprint.objects.create(threat_model=self.threat_model, name="Second")
        only_there = OrgsystemComponent.objects.create(blueprint=second, name="Only")
        control = self.scoped_control(only_there)
        response = self.client_for(self.security).delete(
            f"/api/threat-models/{self.threat_model.id}/blueprints/{second.id}/"
        )
        self.assert_warned(response, control)

    def test_a_delete_that_leaves_a_target_is_quiet(self):
        self.scoped_control(self.zone, self.api)
        response = self.client_for(self.security).delete(f"/api/zones/{self.zone.id}/")
        self.assertEqual(response.status_code, 204, response.content)
