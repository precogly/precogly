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
        self.assertEqual(
            security.get(f"{url}review/").data["approval_state"], "review_due"
        )
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
