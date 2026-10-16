"""How to fix a document, appended to import warnings (any tool's output).

Teams arrive from spreadsheets, draw.io, IriusRisk, ThreatModeler and
in-house compliance tools, and their exporters often write a shape close to
CycloneDX 2.0 but not quite it. A warning that only says what Precogly did
leaves them guessing, so the common cases get one sentence on what to write
instead. Nothing here reads a non-spec shape: the importer stays strict and
the export stays valid 2.0; only the wording changes.
"""

import re
from collections import Counter

from .properties import PROPERTY_PREFIX
from .validation import SchemaError

STANDARD_REQUIREMENTS = "definitions.standards[].requirements"

DATE_HINT = "Write the date as YYYY-MM-DD, for example 2026-12-31."
DATE_TIME_HINT = "Write an ISO 8601 date-time, for example 2026-12-31T00:00:00Z."
OWNER_HINT = (
    "Invite the person to the organization with that email address, then assign "
    "them in Precogly; the next import of the file matches them."
)

_REQUIRED = re.compile(r"^'(?P<name>[^']+)' is a required property$")
_UNEXPECTED = re.compile(
    r"^Additional properties are not allowed \((?P<names>.+) (?:was|were) unexpected\)$"
)
_NOT_STRING = re.compile(r"is not of type 'string'$")
_DATE_FORMAT = re.compile(r"is not a '(?P<format>date|date-time)'$")

# Required fields whose bare name does not tell a newcomer what to write.
_REQUIRED_EXAMPLES = {
    "modelTypes": 'Add "modelTypes" listing the kinds of model the blueprint holds, for example ["data-flow"].',
    "bom-ref": 'Add a "bom-ref" that is unique in the document, so other elements can point at this one.',
    "specVersion": 'Add "specVersion": "2.0".',
    "specFormat": 'Add "specFormat": "CycloneDX".',
}


def schema_hint(error: SchemaError) -> str | None:
    """One sentence on how to fix a schema finding, or None when the message says enough."""
    path, message = error.path, error.message

    required = _REQUIRED.match(message)
    if required:
        name = required.group("name")
        return _REQUIRED_EXAMPLES.get(name, f'Add "{name}" to this object.')

    unexpected = _UNEXPECTED.match(message)
    if unexpected:
        names = set(re.findall(r"'([^']+)'", unexpected.group("names")))
        if path.startswith("definitions/requirements/") and names & {
            "identifier",
            "source",
            "text",
            "title",
        }:
            return (
                "A requirement from a standard (NIST 800-53, ISO 27001, IEC 62443, ...) belongs under "
                f"{STANDARD_REQUIREMENTS}, with an identifier such as AC-2 and the standard's name on "
                "the standard; definitions.requirements holds engineering requirements."
            )
        return (
            'Remove these fields, or carry them as name/value pairs under "properties".'
        )

    if _NOT_STRING.search(message) and re.fullmatch(
        r"controls/\d+/satisfies/\d+", path
    ):
        return (
            "satisfies lists references: define each requirement under "
            f"{STANDARD_REQUIREMENTS} with a bom-ref and put that bom-ref here."
        )

    date_format = _DATE_FORMAT.search(message)
    if date_format:
        return (
            DATE_TIME_HINT if date_format.group("format") == "date-time" else DATE_HINT
        )

    return None


def with_hint(error: SchemaError) -> str:
    """The schema warning with its fix, when there is one."""
    hint = schema_hint(error)
    return f"Schema: {error}" + (f" {hint}" if hint else "")


def _is_precogly_property(name: str) -> bool:
    """Precogly's own namespaces: ``precogly:`` and its tools' (``precogly-guest:``)."""
    return name.startswith(PROPERTY_PREFIX) or name.startswith("precogly-")


def custom_properties_warning(document: dict, limit: int = 8) -> str | None:
    """One warning naming the custom properties Precogly does not read.

    Precogly reads the spec's own fields and its ``precogly:`` properties.
    Nothing in the model uses any other property (a tool's own ``vendor:due``,
    say), so a value the team relies on would otherwise disappear from view
    without a word. Most are written back on export (``passthrough.keep_unknown``),
    but not those on objects rebuilt from Precogly's own fields, such as the
    metadata component, the scope, threat actors and visualizations.
    """
    counts: Counter = Counter()

    def visit(node) -> None:
        if isinstance(node, dict):
            for item in node.get("properties") or []:
                if isinstance(item, dict):
                    name = item.get("name")
                    if isinstance(name, str) and not _is_precogly_property(name):
                        counts[name] += 1
            for value in node.values():
                visit(value)
        elif isinstance(node, list):
            for value in node:
                visit(value)

    visit(document)
    if not counts:
        return None
    listed = ", ".join(f"{name} ({count})" for name, count in counts.most_common(limit))
    more = f", and {len(counts) - limit} more" if len(counts) > limit else ""
    return (
        f"Custom properties Precogly does not read: {listed}{more}. "
        "Most are written back on export, but not those on objects Precogly rebuilds from its own fields "
        "(such as threat actors and visualizations). "
        "To have Precogly use a value, write it in the spec's own field or as a precogly: property "
        "(for a control's due date: a risk response's targetDate, or precogly:due-date); see "
        "Importing and Exporting in the docs."
    )
