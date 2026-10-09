"""Test helpers for the TM-BOM adapter.

Importable from any app's tests. ``assert_valid_tmbom`` is the export gate:
zero schema errors and zero ref errors, each printed with its path when it
fails so the offending element is findable.
"""

from .validation import check_ref_integrity, validate_document


def assert_valid_tmbom(document: dict, *, context: str = "") -> None:
    """Fail with every schema and ref-integrity error listed, one per line."""
    findings = [*validate_document(document), *check_ref_integrity(document)]
    if not findings:
        return
    heading = f"TM-BOM document {context} ".strip() if context else "TM-BOM document"
    lines = [f"{heading} has {len(findings)} error(s):"]
    lines.extend(f"  - {finding}" for finding in findings)
    raise AssertionError("\n".join(lines))
