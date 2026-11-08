"""The OpenAPI schema reduced to what a `search` needs, with every `$ref` inlined.

The model's search code reads `spec["paths"][path][method]` and finds parameters and
bodies in place, without following references itself.
"""

from __future__ import annotations

from typing import Any

HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")

# Everything else on an operation (`operationId`, `security`, `x-*`) is noise to a
# search and costs context when a result is returned.
KEPT = ("summary", "description", "tags", "parameters", "requestBody", "responses")


def resolve_refs(
    node: Any, spec: dict[str, Any], ancestors: frozenset[str] = frozenset()
) -> Any:
    """A copy of `node` with every `$ref` replaced by what it points to.

    Returns new containers and never modifies `node` or `spec`: the schema is shared
    by every caller in the process.

    A reference already being expanded on the current path becomes
    `{"$circular": ref}`. Only ancestors count, not every reference seen so far, so a
    component used twice in one operation is inlined both times.
    """
    if isinstance(node, list):
        return [resolve_refs(item, spec, ancestors) for item in node]
    if not isinstance(node, dict):
        return node

    ref = node.get("$ref")
    if isinstance(ref, str):
        if ref in ancestors:
            return {"$circular": ref}
        target: Any = spec
        for part in ref.removeprefix("#/").split("/"):
            target = target[part]
        return resolve_refs(target, spec, ancestors | {ref})

    return {key: resolve_refs(value, spec, ancestors) for key, value in node.items()}


def process_spec(raw: dict[str, Any]) -> dict[str, Any]:
    """`{"paths": {path: {method: operation}}}`, each operation reduced to `KEPT`."""
    paths: dict[str, Any] = {}
    for path, item in raw.get("paths", {}).items():
        operations = {
            method: {
                field: resolve_refs(item[method][field], raw)
                for field in KEPT
                if field in item[method]
            }
            for method in HTTP_METHODS
            if method in item
        }
        if operations:
            paths[path] = operations
    return {"paths": paths}
