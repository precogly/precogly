"""`schema` generates the OpenAPI schema once per process. No database: generation
only imports the project."""

from asgiref.sync import async_to_sync
from django.test import SimpleTestCase

from apps.core.mcp.schema import schema


class SchemaTests(SimpleTestCase):
    def test_the_schema_describes_the_api(self):
        assert "/api/threat-models/" in async_to_sync(schema)()["paths"]

    def test_it_is_generated_once_and_shared(self):
        assert async_to_sync(schema)() is async_to_sync(schema)()
