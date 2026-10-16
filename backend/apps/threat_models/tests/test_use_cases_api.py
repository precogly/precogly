"""Use cases and abuse cases: editable, with their links (editable-use-cases.md)."""

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import (
    Organization,
    OrganizationMember,
    Team,
    TeamMembership,
)
from apps.systems.models import Flow, OrgsystemComponent
from apps.threat_models.digest import model_digest
from apps.threat_models.models import (
    AbuseCase,
    AbuseCaseThreat,
    BusinessObjective,
    ThreatModel,
    UseCase,
)
from apps.threats.models import InstanceThreat, ThreatPersona
from apps.threats.services import create_instance_threat

User = get_user_model()


class _Base(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.other_organization = Organization.objects.create(
            name="Other", domain="other.test"
        )
        cls.team = Team.objects.create(organization=cls.organization, name="Shop")
        cls.user = User.objects.create_user(
            username="sec", email="sec@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        cls.viewer = User.objects.create_user(
            username="viewer", email="viewer@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.viewer, role="member"
        )
        TeamMembership.objects.create(team=cls.team, user=cls.viewer, role="viewer")
        cls.outsider = User.objects.create_user(
            username="out", email="out@other.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.other_organization, user=cls.outsider, role="security_team"
        )
        cls.threat_model = ThreatModel.objects.create(
            name="Shop", organization=cls.organization, owning_team=cls.team
        )
        blueprint = cls.threat_model.default_blueprint
        cls.web = OrgsystemComponent.objects.create(blueprint=blueprint, name="Web")
        cls.payment = OrgsystemComponent.objects.create(
            blueprint=blueprint, name="Payment API"
        )
        cls.orders = OrgsystemComponent.objects.create(
            blueprint=blueprint, name="Orders DB", category="datastore"
        )
        cls.flow = Flow.objects.create(
            blueprint=blueprint,
            source_component=cls.web,
            dest_component=cls.payment,
            label="Pay",
        )
        cls.objective = BusinessObjective.objects.create(
            threat_model=cls.threat_model, name="Revenue"
        )
        cls.fraudster = ThreatPersona.objects.create(
            threat_model=cls.threat_model, symbolic_name="fraudster", name="Fraudster"
        )
        cls.other_model = ThreatModel.objects.create(
            name="Other model", organization=cls.organization
        )
        cls.foreign_component = OrgsystemComponent.objects.create(
            blueprint=cls.other_model.default_blueprint, name="Elsewhere"
        )
        cls.foreign_persona = ThreatPersona.objects.create(
            threat_model=cls.other_model, symbolic_name="spy", name="Spy"
        )

    def _client(self, user):
        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(user).access_token}"
        )
        return client

    def setUp(self):
        self.client = self._client(self.user)
        self.use_cases_url = f"/api/threat-models/{self.threat_model.id}/use-cases/"
        self.abuse_cases_url = f"/api/threat-models/{self.threat_model.id}/abuse-cases/"


class UseCaseApiTests(_Base):
    def test_a_use_case_with_only_a_name_saves_and_lists(self):
        response = self.client.post(
            self.use_cases_url, {"name": "Refund"}, format="json"
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["components"], [])
        self.assertEqual(response.data["abuse_case_count"], 0)
        listed = self.client.get(self.use_cases_url)
        self.assertEqual([row["name"] for row in listed.data], ["Refund"])

    def test_links_set_replace_clear_and_stay_when_omitted(self):
        created = self.client.post(
            self.use_cases_url,
            {
                "name": "Place order",
                "componentIds": [self.web.id, self.orders.id],
                "flowIds": [self.flow.id],
                "businessObjectiveIds": [self.objective.id],
            },
            format="json",
        )
        self.assertEqual(created.status_code, 201, created.data)
        # A data store can be linked like any component.
        self.assertEqual(
            [c["name"] for c in created.data["components"]], ["Web", "Orders DB"]
        )
        self.assertEqual(
            created.data["flows"][0],
            {
                "id": self.flow.id,
                "name": "Pay",
                "source_name": "Web",
                "destination_name": "Payment API",
                "blueprint_id": self.threat_model.default_blueprint.id,
            },
        )
        self.assertEqual(created.data["business_objectives"][0]["name"], "Revenue")
        url = f"{self.use_cases_url}{created.data['id']}/"

        replaced = self.client.patch(
            url, {"componentIds": [self.payment.id]}, format="json"
        )
        self.assertEqual(
            [c["name"] for c in replaced.data["components"]], ["Payment API"]
        )
        self.assertEqual(len(replaced.data["flows"]), 1)  # omitted, so kept

        renamed = self.client.patch(url, {"name": "Order"}, format="json")
        self.assertEqual(len(renamed.data["components"]), 1)
        self.assertEqual(len(renamed.data["business_objectives"]), 1)

        cleared = self.client.patch(
            url,
            {"componentIds": [], "flowIds": [], "businessObjectiveIds": []},
            format="json",
        )
        self.assertEqual((cleared.data["components"], cleared.data["flows"]), ([], []))
        self.assertEqual(cleared.data["business_objectives"], [])

    def test_an_id_from_another_model_is_refused(self):
        response = self.client.post(
            self.use_cases_url,
            {"name": "X", "componentIds": [self.foreign_component.id]},
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            str(response.data["component_ids"][0]), "Not part of this threat model."
        )
        self.assertFalse(UseCase.objects.filter(name="X").exists())

    def test_flow_data_is_checked_and_normalized(self):
        missing_description = self.client.post(
            self.use_cases_url,
            {"name": "X", "flowData": {"main_flow": [{"number": 1}]}},
            format="json",
        )
        self.assertEqual(missing_description.status_code, 400)
        missing_condition = self.client.post(
            self.use_cases_url,
            {"name": "X", "flowData": {"exceptions": [{"name": "Down"}]}},
            format="json",
        )
        self.assertEqual(missing_condition.status_code, 400)
        not_text = self.client.post(
            self.use_cases_url,
            {
                "name": "X",
                "flowData": {
                    "exceptions": [
                        {"name": "Down", "condition": "Timeout", "handling": ["a"]}
                    ]
                },
            },
            format="json",
        )
        self.assertEqual(not_text.status_code, 400)

        saved = self.client.post(
            self.use_cases_url,
            {
                "name": "Refund",
                "flowData": {
                    "preconditions": ["Order exists", "Order exists"],
                    "main_flow": [
                        {"number": 5, "description": "Ask", "actor": "a-customer"},
                        {"number": 9, "description": "Pay back"},
                        {"number": 9, "description": "Pay back"},
                    ],
                    "exceptions": [
                        {"name": "Down", "condition": "Timeout", "handling": "Retry"}
                    ],
                },
            },
            format="json",
        )
        self.assertEqual(saved.status_code, 201, saved.data)
        flow_data = UseCase.objects.get(pk=saved.data["id"]).flow_data
        self.assertEqual(flow_data["preconditions"], ["Order exists"])
        self.assertEqual(
            flow_data["main_flow"],
            [
                {"number": 1, "description": "Ask", "actor": "a-customer"},
                {"number": 2, "description": "Pay back"},
            ],
        )
        self.assertEqual(flow_data["exceptions"][0]["handling"], "Retry")

    def test_viewer_cannot_write(self):
        use_case = UseCase.objects.create(threat_model=self.threat_model, name="Login")
        viewer = self._client(self.viewer)
        self.assertEqual(viewer.get(self.use_cases_url).status_code, 200)
        self.assertEqual(
            viewer.post(self.use_cases_url, {"name": "New"}, format="json").status_code,
            403,
        )
        url = f"{self.use_cases_url}{use_case.id}/"
        self.assertEqual(
            viewer.patch(url, {"name": "Renamed"}, format="json").status_code, 403
        )
        self.assertEqual(viewer.delete(url).status_code, 403)

    def test_outsider_gets_404(self):
        use_case = UseCase.objects.create(threat_model=self.threat_model, name="Login")
        outsider = self._client(self.outsider)
        self.assertEqual(outsider.get(self.use_cases_url).status_code, 404)
        self.assertEqual(
            outsider.delete(f"{self.use_cases_url}{use_case.id}/").status_code, 404
        )
        self.assertTrue(UseCase.objects.filter(id=use_case.id).exists())

    def test_list_counts_abuse_cases_with_flat_queries(self):
        def list_queries():
            with CaptureQueriesContext(connection) as captured:
                response = self.client.get(self.use_cases_url)
            self.assertEqual(response.status_code, 200)
            return len(captured), response

        UseCase.objects.create(threat_model=self.threat_model, name="One")
        baseline, _ = list_queries()
        for index in range(4):
            use_case = UseCase.objects.create(
                threat_model=self.threat_model, name=f"More {index}"
            )
            abuse_case = AbuseCase.objects.create(
                threat_model=self.threat_model, name=f"Abuse {index}"
            )
            abuse_case.use_case_links.create(use_case=use_case)
        count, response = list_queries()
        self.assertEqual(count, baseline)
        self.assertEqual(
            {row["name"]: row["abuse_case_count"] for row in response.data}["More 0"], 1
        )


class AbuseCaseApiTests(_Base):
    def test_an_abuse_case_with_only_a_name_saves(self):
        response = self.client.post(
            self.abuse_cases_url, {"name": "Card testing"}, format="json"
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIsNone(response.data["abuser"])
        self.assertEqual(response.data["threats"], [])
        self.assertEqual(response.data["unlinked_realizes"], [])

    def test_links_and_abuser(self):
        use_case = UseCase.objects.create(threat_model=self.threat_model, name="Order")
        threat = create_instance_threat(
            self.threat_model, targets=[self.payment], threat_name="Payment fraud"
        )
        response = self.client.post(
            self.abuse_cases_url,
            {
                "name": "Card testing",
                "abuserId": self.fraudster.id,
                "useCaseIds": [use_case.id],
                "componentIds": [self.payment.id],
                "flowIds": [self.flow.id],
                "threatIds": [threat.id],
                "flowData": {
                    "preconditions": ["Stolen cards"],
                    "main_flow": ["Try small payments"],
                    "detection_opportunities": ["Many declines"],
                },
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.data)
        data = response.data
        self.assertEqual(data["abuser"], {"id": self.fraudster.id, "name": "Fraudster"})
        self.assertEqual(data["use_cases"], [{"id": use_case.id, "name": "Order"}])
        self.assertEqual([c["name"] for c in data["components"]], ["Payment API"])
        self.assertEqual(data["flows"][0]["id"], self.flow.id)
        self.assertEqual(
            data["threats"],
            [
                {
                    "id": threat.id,
                    "number": threat.number,
                    "display_number": threat.display_number,
                    "name": "Payment fraud",
                }
            ],
        )
        self.assertEqual(
            data["flow_data"]["main_flow"],
            [{"number": 1, "description": "Try small payments"}],
        )

        url = f"{self.abuse_cases_url}{data['id']}/"
        cleared = self.client.patch(
            url, {"abuserId": None, "threatIds": []}, format="json"
        )
        self.assertIsNone(cleared.data["abuser"])
        self.assertEqual(cleared.data["threats"], [])
        self.assertEqual(len(cleared.data["use_cases"]), 1)

    def test_ids_from_another_model_are_refused(self):
        for payload in (
            {"abuserId": self.foreign_persona.id},
            {"componentIds": [self.foreign_component.id]},
            {"useCaseIds": [999999]},
        ):
            with self.subTest(payload=payload):
                response = self.client.post(
                    self.abuse_cases_url, {"name": "X", **payload}, format="json"
                )
                self.assertEqual(response.status_code, 400, response.data)
        self.assertFalse(AbuseCase.objects.exists())

    def test_viewer_cannot_create(self):
        viewer = self._client(self.viewer)
        response = viewer.post(self.abuse_cases_url, {"name": "X"}, format="json")
        self.assertEqual(response.status_code, 403)

    def test_deleting_a_persona_or_threat_keeps_the_abuse_case(self):
        threat = create_instance_threat(
            self.threat_model, targets=[self.payment], threat_name="Fraud"
        )
        abuse_case = AbuseCase.objects.create(
            threat_model=self.threat_model, name="Card testing", abuser=self.fraudster
        )
        AbuseCaseThreat.objects.create(abuse_case=abuse_case, threat=threat)
        threat.delete()
        self.fraudster.delete()
        abuse_case.refresh_from_db()
        self.assertIsNone(abuse_case.abuser)
        self.assertFalse(abuse_case.threat_links.exists())


class ReviewFollowUpTests(_Base):
    """Description, cleared abuser, new rows last, one-threat link actions."""

    def test_description_saves_and_round_trips(self):
        from apps.threat_models.tmbom import TmBomAdapter

        response = self.client.post(
            self.abuse_cases_url,
            {"name": "Card testing", "description": "Tests stolen cards."},
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["description"], "Tests stolen cards.")
        document = TmBomAdapter().export_data(self.threat_model)
        entry = document["threats"]["abuseCases"][0]
        self.assertEqual(entry["description"], "Tests stolen cards.")
        imported, _ = TmBomAdapter().import_data(document, self.organization, self.user)
        self.assertEqual(imported.abuse_cases.get().description, "Tests stolen cards.")

    def test_clearing_an_imported_abuser_drops_the_kept_ref(self):
        from apps.threat_models.tmbom import TmBomAdapter

        abuse_case = AbuseCase.objects.create(
            threat_model=self.threat_model,
            name="Card testing",
            format_metadata={"cyclonedx": {"abuser_ref": "actor-elsewhere"}},
        )
        response = self.client.patch(
            f"{self.abuse_cases_url}{abuse_case.id}/", {"abuserId": None}, format="json"
        )
        self.assertEqual(response.status_code, 200, response.data)
        abuse_case.refresh_from_db()
        self.assertNotIn("abuser_ref", abuse_case.format_metadata["cyclonedx"])
        document = TmBomAdapter().export_data(self.threat_model)
        self.assertNotIn("abuser", document["threats"]["abuseCases"][0])

    def test_new_rows_land_last(self):
        for position in range(3):
            UseCase.objects.create(
                threat_model=self.threat_model,
                name=f"U{position}",
                display_order=position,
            )
            AbuseCase.objects.create(
                threat_model=self.threat_model,
                name=f"A{position}",
                display_order=position,
            )
        self.client.post(self.use_cases_url, {"name": "New"}, format="json")
        self.client.post(self.abuse_cases_url, {"name": "New"}, format="json")
        self.assertEqual(
            list(self.threat_model.use_cases.values_list("name", flat=True))[-1], "New"
        )
        self.assertEqual(
            list(self.threat_model.abuse_cases.values_list("name", flat=True))[-1],
            "New",
        )

    def test_link_and_unlink_one_threat_keep_the_others(self):
        first = create_instance_threat(
            self.threat_model, targets=[self.payment], threat_name="First"
        )
        second = create_instance_threat(
            self.threat_model, targets=[self.payment], threat_name="Second"
        )
        abuse_case = AbuseCase.objects.create(
            threat_model=self.threat_model, name="Card testing"
        )
        url = f"{self.abuse_cases_url}{abuse_case.id}/"
        for threat in (first, second, first):
            response = self.client.post(
                f"{url}link-threat/", {"threatId": threat.id}, format="json"
            )
            self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(
            [t["id"] for t in response.data["threats"]], [first.id, second.id]
        )
        response = self.client.post(
            f"{url}unlink-threat/", {"threatId": first.id}, format="json"
        )
        self.assertEqual([t["id"] for t in response.data["threats"]], [second.id])

    def test_link_refuses_other_models_and_readers(self):
        abuse_case = AbuseCase.objects.create(
            threat_model=self.threat_model, name="Card testing"
        )
        foreign = create_instance_threat(
            self.other_model, targets=[self.foreign_component], threat_name="X"
        )
        url = f"{self.abuse_cases_url}{abuse_case.id}/link-threat/"
        self.assertEqual(
            self.client.post(url, {"threatId": foreign.id}, format="json").status_code,
            400,
        )
        self.assertEqual(self.client.post(url, {}, format="json").status_code, 400)
        own = create_instance_threat(
            self.threat_model, targets=[self.payment], threat_name="Own"
        )
        self.assertEqual(
            self._client(self.viewer)
            .post(url, {"threatId": own.id}, format="json")
            .status_code,
            403,
        )
        self.assertEqual(
            self._client(self.outsider)
            .post(url, {"threatId": own.id}, format="json")
            .status_code,
            404,
        )
        self.assertFalse(AbuseCaseThreat.objects.exists())


class ThreatAbuseCaseLinkTests(_Base):
    def test_create_with_abuse_case_ids_links_and_delete_unlinks(self):
        abuse_case = AbuseCase.objects.create(
            threat_model=self.threat_model, name="Card testing"
        )
        response = self.client.post(
            "/api/threats/",
            {
                "threatModel": self.threat_model.id,
                "threatName": "Payment fraud",
                "targets": [{"type": "component", "id": self.payment.id}],
                "abuseCaseIds": [abuse_case.id],
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(
            response.data["abuse_cases"],
            [{"id": abuse_case.id, "name": "Card testing"}],
        )
        threat = InstanceThreat.objects.get(pk=response.data["id"])
        self.assertTrue(abuse_case.threat_links.filter(threat=threat).exists())

        self.client.delete(f"/api/threats/{threat.id}/")
        self.assertFalse(abuse_case.threat_links.exists())

    def test_abuse_case_of_another_model_is_refused(self):
        foreign = AbuseCase.objects.create(threat_model=self.other_model, name="X")
        response = self.client.post(
            "/api/threats/",
            {
                "threatModel": self.threat_model.id,
                "threatName": "Payment fraud",
                "wholeSystem": True,
                "abuseCaseIds": [foreign.id],
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400)

    def test_update_replaces_the_abuse_cases(self):
        first = AbuseCase.objects.create(threat_model=self.threat_model, name="A")
        second = AbuseCase.objects.create(threat_model=self.threat_model, name="B")
        threat = create_instance_threat(
            self.threat_model, targets=[self.payment], threat_name="Fraud"
        )
        AbuseCaseThreat.objects.create(abuse_case=first, threat=threat)
        response = self.client.patch(
            f"/api/threats/{threat.id}/", {"abuseCaseIds": [second.id]}, format="json"
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual([a["name"] for a in response.data["abuse_cases"]], ["B"])


class ThreatListQueryTests(_Base):
    def test_threat_list_query_count_is_flat(self):
        """The threat serializer reads sources, objectives, abuse cases and the
        library taxonomy from the list's prefetch, not one query per threat."""
        url = f"/api/threats/?threat_model={self.threat_model.id}"
        create_instance_threat(self.threat_model, targets=[self.web], threat_name="A")
        with CaptureQueriesContext(connection) as one:
            self.client.get(url)
        for index in range(4):
            create_instance_threat(
                self.threat_model, targets=[self.web], threat_name=f"More {index}"
            )
        with CaptureQueriesContext(connection) as five:
            response = self.client.get(url)
        self.assertEqual(response.data["count"], 5)
        self.assertEqual(len(five), len(one))


class DigestTests(_Base):
    def test_abuse_cases_and_links_change_the_digest(self):
        use_case = UseCase.objects.create(threat_model=self.threat_model, name="Order")
        before = model_digest(self.threat_model)
        abuse_case = AbuseCase.objects.create(
            threat_model=self.threat_model, name="Card testing"
        )
        after_abuse_case = model_digest(self.threat_model)
        self.assertNotEqual(before, after_abuse_case)
        abuse_case.use_case_links.create(use_case=use_case)
        after_link = model_digest(self.threat_model)
        self.assertNotEqual(after_abuse_case, after_link)
        use_case.target_links.create(component=self.web)
        self.assertNotEqual(after_link, model_digest(self.threat_model))

    def test_display_order_does_not_change_the_digest(self):
        use_case = UseCase.objects.create(threat_model=self.threat_model, name="Order")
        before = model_digest(self.threat_model)
        use_case.display_order = 5
        use_case.save()
        self.assertEqual(before, model_digest(self.threat_model))
