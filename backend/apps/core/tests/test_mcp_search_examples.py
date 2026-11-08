"""The examples in `search`'s description run against the real schema.

They name real paths and fields, so an API change can break one silently, and a
broken example in the description teaches the model the wrong call. No database:
generating the schema only imports the project.
"""

from asgiref.sync import async_to_sync
from django.test import SimpleTestCase
from precogly_mcp.spec import process_spec
from precogly_mcp.tools import SEARCH_EXAMPLES
from pydantic_monty import AsyncMonty

from apps.core.mcp.schema import schema


async def run_examples() -> list[object]:
    spec = process_spec(await schema())
    results = []
    async with AsyncMonty() as sandbox:
        for code in SEARCH_EXAMPLES:
            async with sandbox.checkout() as session:
                results.append(await session.feed_run(code, inputs={"spec": spec}))
    return results


class SearchExampleTests(SimpleTestCase):
    def test_every_example_runs_and_finds_something(self):
        for code, result in zip(
            SEARCH_EXAMPLES, async_to_sync(run_examples)(), strict=True
        ):
            with self.subTest(code=code):
                assert result, f"example returned nothing: {result!r}"
