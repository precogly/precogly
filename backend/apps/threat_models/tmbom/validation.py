"""Validate a TM-BOM document against the pinned schema.

Two checks, both reported as plain data so callers can turn them into test
failures or import warnings:

- ``validate_document``: JSON Schema validation. Zero errors is the export gate
  (plan section 9.2), and on import every error becomes a warning.
- ``check_ref_integrity``: what JSON Schema cannot say. Every ``bom-ref`` must be
  unique and every reference must resolve to one (H18). Added with the first
  adapter slice; the function is declared here so the gate has one entry point.
"""

from dataclasses import dataclass
from functools import cache

from jsonschema import Draft202012Validator

from .schema import load_schema


@dataclass(frozen=True)
class SchemaError:
    """One validation finding, located by its JSON path."""

    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path or '<document>'}: {self.message}"


@cache
def _validator() -> Draft202012Validator:
    schema = load_schema()
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _json_path(error) -> str:
    return "/".join(str(part) for part in error.absolute_path)


def validate_document(document: dict) -> list[SchemaError]:
    """Return every schema error in ``document``, ordered by path.

    The message of a nested error (``anyOf``/``oneOf``) is the top-level one;
    the path still says which element failed.
    """
    errors = sorted(
        _validator().iter_errors(document), key=lambda error: list(error.absolute_path)
    )
    return [
        SchemaError(path=_json_path(error), message=error.message) for error in errors
    ]


# Keys whose values are refs to elements of the same document (refLinkType).
# A value may also be a BOM-Link into another document, which is not checked.
REF_KEYS = frozenset(
    {
        "source",
        "destination",
        "zone",
        "parent",
        "threats",
        "affectedAssets",
        "actor",
        "threatProfile",
        "appliesTo",
        "implementedBy",
        "satisfies",
        "mitigations",
        "relatedThreats",
        "relatedBusinessObjectives",
        "controls",
        "boundary",
        "threatsAtBoundary",
        "controlsAtBoundary",
        "zones",
        "relatedAssets",
        "dataSets",
        "dataStore",
        "excludedComponents",
        "ref",
        "dependsOn",
        "contains",
        "aggregates",
        "associates",
        "composes",
        "generalizes",
        "realizes",
        "serves",
        "owner",
        "reviewer",
        "approver",
        "party",
        "affects",
        "addresses",
        "targets",
    }
)


def check_ref_integrity(document: dict) -> list[SchemaError]:
    """Return duplicate ``bom-ref`` values and references that resolve to nothing (H18)."""
    findings = _duplicate_bom_refs(document)
    refs = _collect_refs(document)
    findings.extend(_dangling_refs(document, refs))
    return findings


def _collect_refs(node, found=None) -> set:
    if found is None:
        found = set()
    if isinstance(node, dict):
        value = node.get("bom-ref")
        if isinstance(value, str):
            found.add(value)
        for item in node.values():
            _collect_refs(item, found)
    elif isinstance(node, list):
        for item in node:
            _collect_refs(item, found)
    return found


def _is_bom_link(value: str) -> bool:
    return value.startswith("urn:cdx:")


def _dangling_refs(document: dict, refs: set) -> list[SchemaError]:
    findings: list[SchemaError] = []

    def check(value, path):
        if isinstance(value, str):
            if value and not _is_bom_link(value) and value not in refs:
                findings.append(
                    SchemaError(
                        path=path, message=f"reference {value!r} resolves to nothing"
                    )
                )
        elif isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, str):
                    check(item, f"{path}/{index}")

    def walk(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                child = f"{path}/{key}" if path else key
                if key in REF_KEYS and isinstance(value, (str, list)):
                    check(value, child)
                walk(value, child)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}/{index}")

    walk(document, "")
    return findings


def _duplicate_bom_refs(document: dict) -> list[SchemaError]:
    seen: dict[str, str] = {}
    findings: list[SchemaError] = []

    def walk(node, path: str) -> None:
        if isinstance(node, dict):
            bom_ref = node.get("bom-ref")
            if isinstance(bom_ref, str):
                if bom_ref in seen:
                    findings.append(
                        SchemaError(
                            path=f"{path}/bom-ref",
                            message=f"duplicate bom-ref {bom_ref!r}, first seen at {seen[bom_ref]}",
                        )
                    )
                else:
                    seen[bom_ref] = path
            for key, value in node.items():
                walk(value, f"{path}/{key}" if path else key)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}/{index}")

    walk(document, "")
    return findings
