"""Relationship types and their rules (plan J15, K4).

The two relationship actions take ``relation_type``; ``subsystem_of`` and
``superseded_by`` never form a loop, ``related_to`` is not stored in both
directions, ``depends_on`` may form a loop. The importer applies the same
rules and turns a refused relationship into a warning.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import Organization, OrganizationMember
from apps.threat_models.models import ThreatModel, ThreatModelRelationship
from apps.threat_models.relationships import RelationshipError, add_relationship
from apps.threat_models.tmbom.importer.document import ImportContext
from apps.threat_models.tmbom.importer.identity import import_relationships

User = get_user_model()


class RelationshipFixture(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="sec", email="sec@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        cls.model_a = ThreatModel.objects.create(
            name="Alpha", organization=cls.organization
        )
        cls.model_b = ThreatModel.objects.create(
            name="Beta", organization=cls.organization
        )
        cls.model_c = ThreatModel.objects.create(
            name="Gamma", organization=cls.organization
        )

    def setUp(self):
        self.client = APIClient()
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(self.user).access_token}"
        )

    def _add(self, source, target, relation_type=None):
        body = {"target_model_id": target.id}
        if relation_type is not None:
            body["relation_type"] = relation_type
        return self.client.post(
            f"/api/threat-models/{source.id}/add_referenced_model/",
            body,
            format="json",
        )

    def _remove(self, source, target, relation_type=None):
        body = {"target_model_id": target.id}
        if relation_type is not None:
            body["relation_type"] = relation_type
        return self.client.post(
            f"/api/threat-models/{source.id}/remove_referenced_model/",
            body,
            format="json",
        )

    def _rows(self):
        return set(
            ThreatModelRelationship.objects.values_list(
                "source_threat_model__name",
                "relation_type",
                "target_threat_model__name",
            )
        )


class RelationshipActionTests(RelationshipFixture):
    def test_default_type_is_related_to(self):
        response = self._add(self.model_a, self.model_b)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["created"])
        self.assertEqual(
            response.data["relationship"],
            {
                "id": ThreatModelRelationship.objects.get().id,
                "source_model_id": self.model_a.id,
                "target_model_id": self.model_b.id,
                "relation_type": "related_to",
                "direction": "outgoing",
                "model": {"id": self.model_b.id, "name": "Beta"},
            },
        )
        self.assertEqual(self._rows(), {("Alpha", "related_to", "Beta")})

    def test_each_explicit_type_is_stored(self):
        for relation_type in (
            "depends_on",
            "subsystem_of",
            "related_to",
            "superseded_by",
        ):
            response = self._add(self.model_a, self.model_b, relation_type)
            self.assertEqual(response.status_code, 200, response.data)
            self.assertEqual(
                response.data["relationship"]["relation_type"], relation_type
            )
        self.assertEqual(
            self._rows(),
            {
                ("Alpha", "depends_on", "Beta"),
                ("Alpha", "subsystem_of", "Beta"),
                ("Alpha", "related_to", "Beta"),
                ("Alpha", "superseded_by", "Beta"),
            },
        )

    def test_unknown_type_is_a_400(self):
        response = self._add(self.model_a, self.model_b, "owned_by")
        self.assertEqual(response.status_code, 400)
        self.assertIn("relation_type", response.data["error"])
        self.assertEqual(self._rows(), set())
        response = self._remove(self.model_a, self.model_b, "owned_by")
        self.assertEqual(response.status_code, 400)

    def test_self_link_is_refused(self):
        response = self._add(self.model_a, self.model_a, "depends_on")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self._rows(), set())

    def test_subsystem_loop_is_refused(self):
        self.assertEqual(
            self._add(self.model_a, self.model_b, "subsystem_of").status_code, 200
        )
        response = self._add(self.model_b, self.model_a, "subsystem_of")
        self.assertEqual(response.status_code, 400)
        self.assertIn("Beta", response.data["error"])
        self.assertIn("Alpha", response.data["error"])
        self.assertIn("loop", response.data["error"])
        self.assertEqual(self._rows(), {("Alpha", "subsystem_of", "Beta")})

    def test_longer_subsystem_loop_is_refused(self):
        self.assertEqual(
            self._add(self.model_a, self.model_b, "subsystem_of").status_code, 200
        )
        self.assertEqual(
            self._add(self.model_b, self.model_c, "subsystem_of").status_code, 200
        )
        response = self._add(self.model_c, self.model_a, "subsystem_of")
        self.assertEqual(response.status_code, 400)
        self.assertIn("Gamma -> Alpha -> Beta -> Gamma", response.data["error"])
        self.assertEqual(len(self._rows()), 2)

    def test_superseded_loop_is_refused(self):
        self.assertEqual(
            self._add(self.model_a, self.model_b, "superseded_by").status_code, 200
        )
        response = self._add(self.model_b, self.model_a, "superseded_by")
        self.assertEqual(response.status_code, 400)
        self.assertIn("is superseded by", response.data["error"])
        # Another type between the same models is not part of the loop check.
        self.assertEqual(
            self._add(self.model_b, self.model_a, "subsystem_of").status_code, 200
        )

    def test_depends_on_may_form_a_loop(self):
        self.assertEqual(
            self._add(self.model_a, self.model_b, "depends_on").status_code, 200
        )
        self.assertEqual(
            self._add(self.model_b, self.model_a, "depends_on").status_code, 200
        )
        self.assertEqual(
            self._rows(),
            {("Alpha", "depends_on", "Beta"), ("Beta", "depends_on", "Alpha")},
        )

    def test_related_to_reverse_is_not_stored_twice(self):
        first = self._add(self.model_a, self.model_b, "related_to")
        self.assertEqual(first.status_code, 200)
        reverse = self._add(self.model_b, self.model_a, "related_to")
        self.assertEqual(reverse.status_code, 200)
        self.assertFalse(reverse.data["created"])
        self.assertEqual(
            reverse.data["relationship"]["id"], first.data["relationship"]["id"]
        )
        # Seen from Beta the existing row is incoming.
        self.assertEqual(reverse.data["relationship"]["direction"], "incoming")
        self.assertEqual(reverse.data["relationship"]["model"]["name"], "Alpha")
        self.assertEqual(self._rows(), {("Alpha", "related_to", "Beta")})

    def test_remove_deletes_exactly_that_type(self):
        self._add(self.model_a, self.model_b, "depends_on")
        self._add(self.model_a, self.model_b, "related_to")
        response = self._remove(self.model_a, self.model_b, "depends_on")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self._rows(), {("Alpha", "related_to", "Beta")})
        # The default type is related_to.
        response = self._remove(self.model_a, self.model_b)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self._rows(), set())
        response = self._remove(self.model_a, self.model_b)
        self.assertEqual(response.status_code, 404)

    def test_detail_lists_related_models_with_type_and_direction(self):
        self._add(self.model_a, self.model_b, "depends_on")
        self._add(self.model_c, self.model_a, "subsystem_of")
        response = self.client.get(f"/api/threat-models/{self.model_a.id}/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [
                (row["model"]["name"], row["relation_type"], row["direction"])
                for row in response.data["related_models"]
            ],
            [("Beta", "depends_on", "outgoing"), ("Gamma", "subsystem_of", "incoming")],
        )
        self.assertEqual(response.data["referenced_model_ids"], [str(self.model_b.id)])


class RelationshipImportTests(RelationshipFixture):
    def _document_linking(self, target, relation_type):
        return {
            "blueprints": [
                {
                    "assets": [
                        {
                            "bom-ref": "sys-target",
                            "name": target.name,
                            "type": "system",
                            "externalReferences": [
                                {
                                    "type": "threat-model",
                                    "url": f"urn:cdx:{target.serial_number}/1",
                                }
                            ],
                            "properties": [
                                {
                                    "name": "precogly:relationship",
                                    "value": relation_type,
                                }
                            ],
                        }
                    ]
                }
            ]
        }

    def test_a_loop_becomes_a_warning_instead_of_a_row(self):
        add_relationship(self.model_b, self.model_a, "subsystem_of")
        document = self._document_linking(self.model_b, "subsystem_of")
        context = ImportContext(
            document=document, organization=self.organization, user=self.user
        )
        import_relationships(document, self.model_a, context)
        self.assertEqual(self._rows(), {("Beta", "subsystem_of", "Alpha")})
        self.assertEqual(len(context.warnings), 1)
        self.assertIn("loop", context.warnings[0])
        self.assertIn("Alpha", context.warnings[0])
        self.assertIn("Beta", context.warnings[0])
        self.assertNotIn("relationships", context.summary)

    def test_an_allowed_relationship_is_imported(self):
        document = self._document_linking(self.model_b, "depends_on")
        context = ImportContext(
            document=document, organization=self.organization, user=self.user
        )
        import_relationships(document, self.model_a, context)
        self.assertEqual(self._rows(), {("Alpha", "depends_on", "Beta")})
        self.assertEqual(context.warnings, [])
        self.assertEqual(context.summary["relationships"], 1)


class RelationshipServiceTests(RelationshipFixture):
    def test_other_organization_is_refused(self):
        foreign = ThreatModel.objects.create(
            name="Foreign",
            organization=Organization.objects.create(name="X", domain="x.test"),
        )
        with self.assertRaises(RelationshipError):
            add_relationship(self.model_a, foreign, "related_to")
