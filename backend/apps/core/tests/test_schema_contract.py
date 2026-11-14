"""Responses match the OpenAPI schema, as checked by django-contract-tester.

`OpenAPIClient` validates every response it receives against the schema drf-spectacular
generates, so a request through it is the assertion: a response the schema does not
describe raises `DocumentationError`.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from openapi_tester.clients import OpenAPIClient


class SchemaContractTests(TestCase):
    client_class = OpenAPIClient

    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user(
            username="ana@kestrel.test",
            email="ana@kestrel.test",
            password="correct-horse-battery",
            first_name="Ana",
            last_name="Reyes",
        )

    def test_field_names_are_documented_as_the_api_renders_them(self):
        # The API renders camelCase (`firstName`); a schema naming the field
        # `first_name` describes a response nobody receives.
        self.client.force_authenticate(self.user)
        self.client.get("/api/auth/user/")
