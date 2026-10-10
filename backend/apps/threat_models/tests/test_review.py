"""Review and approval with the content digest (step 12, section 4.8)."""

from datetime import timedelta

from django.apps import apps
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils.timezone import now
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.diagrams.models import DFD
from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import OrgsystemComponent
from apps.threat_models.digest import SNAPSHOT_FIELDS, model_digest
from apps.threat_models.models import ThreatModel, ThreatModelReview
from apps.threat_models.review import approve, review_state
from apps.threat_models.tmbom import TmBomAdapter
from apps.threat_models.tmbom.testing import assert_valid_tmbom
from apps.threats.models import CountermeasureComment
from apps.threats.services import create_instance_countermeasure, create_instance_threat

User = get_user_model()


class SnapshotCoverageTests(TestCase):
    def test_every_field_of_every_model_owned_table_is_decided(self):
        for label, (counted, left_out) in SNAPSHOT_FIELDS.items():
            app_label, model_name = label.split(".")
            model = apps.get_model(app_label, model_name)
            concrete = {
                field.name
                for field in model._meta.get_fields()
                if field.concrete and not field.many_to_many
            }
            decided = set(counted) | set(left_out)
            self.assertEqual(concrete - decided, set(), f"{label}: undecided fields")
            self.assertEqual(decided - concrete, set(), f"{label}: unknown fields")
            self.assertEqual(
                set(counted) & set(left_out), set(), f"{label}: listed twice"
            )

    def test_every_table_that_hangs_off_a_model_is_decided(self):
        """R30: a model-owned table is either in the snapshot or left out by name.

        Walks foreign keys out from the model and its blueprints. Tables that
        hold both shared and model-owned rows (``Tenancy.MIXED``) are not
        walked further: what points at them is library data.
        """
        from apps.core.tenancy import Tenancy
        from apps.threat_models.digest import LEFT_OUT_TABLES, ROW_SOURCES

        decided = set(SNAPSHOT_FIELDS) | set(LEFT_OUT_TABLES)
        self.assertEqual(set(SNAPSHOT_FIELDS) & set(LEFT_OUT_TABLES), set())
        self.assertEqual(set(ROW_SOURCES), set(SNAPSHOT_FIELDS) - {"threats.Rating"})
        owned = {"threat_models.ThreatModel", "threat_models.Blueprint"}
        frontier = set(owned)
        while frontier:
            reached = set()
            for model in apps.get_models():
                label = model._meta.label
                if label in owned:
                    continue
                for field in model._meta.concrete_fields:
                    if (field.many_to_one or field.one_to_one) and (
                        field.related_model._meta.label in frontier
                    ):
                        reached.add(label)
            owned |= reached
            frontier = {
                label
                for label in reached
                if getattr(apps.get_model(label), "tenancy", None) != Tenancy.MIXED
            }
        self.assertEqual(owned - decided, set(), "undecided model-owned tables")


class DigestTests(TestCase):
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
        OrganizationMember.objects.filter(user=cls.member).exclude(
            organization=cls.organization
        ).delete()
        cls.threat_model = ThreatModel.objects.create(
            name="TM", organization=cls.organization
        )
        cls.api = OrgsystemComponent.objects.create(
            blueprint=cls.threat_model.default_blueprint, name="API"
        )
        cls.threat = create_instance_threat(
            cls.threat_model, targets=[cls.api], threat_name="SQLi"
        )
        cls.dfd = DFD.objects.create(
            blueprint=cls.threat_model.default_blueprint,
            name="D",
            is_primary=True,
            canvas_data={
                "nodes": [
                    {
                        "id": "n1",
                        "type": "process",
                        "position": {"x": 0, "y": 0},
                        "data": {"label": "API", "component_id": cls.api.id},
                    }
                ],
                "edges": [],
            },
        )

    def api_client(self, user):
        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(user).access_token}"
        )
        return client

    def test_three_cases(self):
        approve(self.threat_model, self.security)
        self.assertEqual(review_state(self.threat_model)["approval_state"], "approved")

        # A content change makes the state "changed"; undoing it makes it "approved" again.
        self.threat.triage_status = "accept"
        self.threat.save()
        self.assertEqual(review_state(self.threat_model)["approval_state"], "changed")
        self.threat.triage_status = "open"
        self.threat.save()
        self.assertEqual(review_state(self.threat_model)["approval_state"], "approved")

        # Layout and comments are not content.
        self.dfd.canvas_data["nodes"][0]["position"] = {"x": 400, "y": 90}
        self.dfd.save()
        control = create_instance_countermeasure(
            self.threat_model, countermeasure_name="C"
        )
        before = model_digest(self.threat_model)
        CountermeasureComment.objects.create(
            countermeasure=control, author=self.security, body="Looks fine"
        )
        self.assertEqual(model_digest(self.threat_model), before)

    def test_layout_only_save_through_dfd_sync_keeps_the_approval(self):
        """R32: moving a node and saving through DFD sync is not a content change."""
        import copy

        from apps.diagrams.services import sync_dfd_nodes_to_components

        # The fixture component was made without a category, which the first
        # sync fills in (a content change). Sync once so the canvas and rows
        # agree, as they do for any model that has been saved from the editor.
        sync_dfd_nodes_to_components(self.dfd, self.dfd.blueprint)
        approve(self.threat_model, self.security)
        digest_before = model_digest(self.threat_model)
        dfd = DFD.objects.get(pk=self.dfd.pk)
        old_canvas = copy.deepcopy(dfd.canvas_data)
        new_canvas = copy.deepcopy(dfd.canvas_data)
        new_canvas["nodes"][0]["position"] = {"x": 400, "y": 90}

        dfd.canvas_data = new_canvas
        dfd.save()
        sync_dfd_nodes_to_components(dfd, dfd.blueprint, old_canvas_data=old_canvas)

        self.assertEqual(review_state(self.threat_model)["approval_state"], "approved")
        self.assertEqual(model_digest(self.threat_model), digest_before)

    def test_layout_only_dfd_patch_through_the_api_keeps_the_approval(self):
        """R32: the same layout-only save sent as PATCH /api/diagrams/{id}/."""
        import copy

        from apps.diagrams.services import sync_dfd_nodes_to_components

        # The fixture component was made without a category, which the first
        # sync fills in (a content change). Sync once so the canvas and rows
        # agree, as they do for any model that has been saved from the editor.
        sync_dfd_nodes_to_components(self.dfd, self.dfd.blueprint)
        approve(self.threat_model, self.security)
        digest_before = model_digest(self.threat_model)
        canvas = copy.deepcopy(DFD.objects.get(pk=self.dfd.pk).canvas_data)
        canvas["nodes"][0]["position"] = {"x": 400, "y": 90}

        response = self.api_client(self.security).patch(
            f"/api/diagrams/{self.dfd.id}/", {"canvas_data": canvas}, format="json"
        )

        self.assertEqual(response.status_code, 200, response.data)
        moved = DFD.objects.get(pk=self.dfd.pk).canvas_data["nodes"][0]["position"]
        self.assertEqual(moved, {"x": 400, "y": 90})
        self.assertEqual(review_state(self.threat_model)["approval_state"], "approved")
        self.assertEqual(model_digest(self.threat_model), digest_before)

    def test_replacing_a_rating_with_the_same_content_keeps_the_approval(self):
        """Rating rows are replaced on every rating and recalculation (R9)."""
        from apps.threats.services import (
            apply_rating,
            create_risk,
            rate_inputs,
            recalculate_residual,
        )

        apply_rating(
            self.threat, "rating", rate_inputs(self.threat_model, {"level": "low"})
        )
        risk = create_risk(self.threat_model, name="R", level="medium")
        approve(self.threat_model, self.security)

        recalculate_residual(risk)
        self.assertEqual(review_state(self.threat_model)["approval_state"], "approved")

        apply_rating(
            self.threat, "rating", rate_inputs(self.threat_model, {"level": "high"})
        )
        self.assertEqual(review_state(self.threat_model)["approval_state"], "changed")
        apply_rating(
            self.threat, "rating", rate_inputs(self.threat_model, {"level": "low"})
        )
        self.assertEqual(review_state(self.threat_model)["approval_state"], "approved")

    def test_a_stale_whole_row_save_does_not_bring_an_approval_back(self):
        stale = ThreatModel.objects.get(pk=self.threat_model.pk)
        approve(self.threat_model, self.security)
        ThreatModelReview.objects.filter(threat_model=self.threat_model).update(
            approval_digest="", approver=None, approved_at=None
        )
        stale.description = "edited from a stale copy"
        stale.save()
        self.assertEqual(review_state(self.threat_model)["approval_state"], "none")

    def test_endpoints_and_permission(self):
        url = f"/api/threat-models/{self.threat_model.id}/"
        member = self.api_client(self.member)
        security = self.api_client(self.security)
        self.assertEqual(member.get(f"{url}review/").data["approval_state"], "none")
        self.assertEqual(member.post(f"{url}approve/").status_code, 403)
        reviewed = security.post(f"{url}mark-reviewed/")
        self.assertEqual(reviewed.data["reviewer_email"], "sec@org.test")
        approved = security.post(f"{url}approve/")
        self.assertEqual(approved.status_code, 200, approved.content)
        self.assertEqual(approved.data["approval_state"], "approved")
        self.assertIsNotNone(security.get(url).data["approved_at"])
        listed = security.get("/api/threat-models/")
        row = next(r for r in listed.data["results"] if r["id"] == self.threat_model.id)
        self.assertIsNotNone(row["approved_at"])
        edited = security.patch(
            url,
            {
                "valid_until": (now() - timedelta(days=1)).isoformat(),
                "review_frequency": "P6M",
                "lifecycle_phase": "operations",
            },
            format="json",
        )
        self.assertEqual(edited.status_code, 200, edited.content)
        # An expired model keeps its approval state (here "changed": the PATCH
        # edited counted fields) and flags the review separately (R24).
        expired = security.get(f"{url}review/").data
        self.assertEqual(expired["approval_state"], "changed")
        self.assertTrue(expired["review_due"])
        bad = security.patch(url, {"review_frequency": "6 months"}, format="json")
        self.assertEqual(bad.status_code, 400)
        revoked = security.post(f"{url}revoke-approval/")
        self.assertIsNone(revoked.data["approved_at"])

    def test_review_block_exports_and_import_does_not_count_as_approval(self):
        approve(self.threat_model, self.security)
        self.threat_model.lifecycle_phase = "build"
        self.threat_model.review_frequency = "P1Y"
        self.threat_model.save()
        document = TmBomAdapter().export_data(self.threat_model)
        assert_valid_tmbom(document, context="step 12 export")
        block = document["blueprints"][0]["metadata"]
        self.assertEqual(block["approver"], f"party-user-{self.security.pk}")
        self.assertIn("approvalDate", block)
        self.assertEqual(block["lifecycles"], [{"phase": "build"}])
        self.assertEqual(block["validityPeriod"]["reviewFrequency"], "P1Y")
        self.assertEqual(document["metadata"]["lifecycles"], [{"phase": "build"}])
        parties = {
            p["bom-ref"]: p for p in document["metadata"]["component"]["parties"]
        }
        self.assertEqual(parties[block["approver"]]["roles"], [{"role": "signatory"}])

        imported, summary = TmBomAdapter().import_data(
            document, self.organization, self.security
        )
        state = review_state(imported)
        self.assertEqual(state["approval_state"], "none")
        self.assertEqual(
            state["source_document_review"]["approver"]["email"], "sec@org.test"
        )
        self.assertEqual(
            (imported.lifecycle_phase, imported.review_frequency), ("build", "P1Y")
        )
        self.assertIn("source document", "\n".join(summary["warnings"]))
