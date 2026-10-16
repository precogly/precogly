"""The compliance matrix of a threat model: requirement by control, per framework.

An assessor reviews one requirement at a time: which controls cover it, are
they in place, which threats do they address, and which requirements have
nothing. The idea comes from PR #561 by JJediny (GSA-TTS), rebuilt here on
the #583 model for every framework (no default framework).

Per framework the model's controls map to:

- Rows are the pack's requirements for an installed framework (so "not
  covered" ones show), or only the mapped requirements for one that is not
  installed (a snapshot mapping keeps its section code and framework name).
- A row's state: ``not_covered`` (no mapping), ``partial_only`` (every
  mapping is partial), ``satisfied`` (a full mapping whose control is
  verified or platform, the report's existing "in effect" rule), else
  ``covered``.
- Gaps are measured against the pack, which often holds only part of a
  standard, so the framework carries ``pack_requirement_count`` and the
  wording on screen says "of the requirements in this pack".
- Rows are grouped by the requirement's parent when the pack has a
  hierarchy, else by the part of the code before the first dot ("V1" for
  ASVS V1.2.3, "SR 1" for IEC 62443 SR 1.1, "6" for PCI DSS 6.5.1), else by
  the part before the first dash ("SC" for SC-8). When that gives every row
  its own group the list stays flat. A family (a requirement other
  requirements name as parent) is the group heading, and a row only when a
  control maps to it directly.

A fixed number of queries, whatever the number of requirements.
"""

import re
from collections import defaultdict

from apps.compliance.models import StandardRequirement
from apps.threats.models import CountermeasureThreatLink, InstanceCountermeasureStandard

IN_EFFECT_STATUSES = {"verified", "platform"}

STATE_ORDER = ("satisfied", "covered", "partial_only", "not_covered")


def natural_key(code: str) -> list:
    """Sort key that puts V1.2 before V1.10 and 6 before 10."""
    return [
        int(part) if part.isdigit() else part.lower()
        for part in re.split(r"(\d+)", code or "")
    ]


def group_key(code: str) -> str:
    """The group a requirement code falls in when the pack has no hierarchy."""
    code = (code or "").strip()
    if "." in code:
        return code.split(".", 1)[0].strip()
    if "-" in code:
        return code.split("-", 1)[0].strip()
    return code


def row_state(mappings: list[dict]) -> str:
    if not mappings:
        return "not_covered"
    if all(mapping["sufficiency"] == "partial" for mapping in mappings):
        return "partial_only"
    if any(
        mapping["sufficiency"] == "full" and mapping["status"] in IN_EFFECT_STATUSES
        for mapping in mappings
    ):
        return "satisfied"
    return "covered"


def _group_rows(rows: list[dict], parent_names: dict) -> list[dict]:
    """Rows in groups: by parent when there is one, else by code prefix."""
    by_group: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        parent_id = row.pop("_parent_id", None)
        name = (
            parent_names.get(parent_id) if parent_id else group_key(row["section_code"])
        )
        by_group[name or ""].append(row)
    if (
        all(len(group_rows) == 1 for group_rows in by_group.values())
        and len(by_group) > 1
    ):
        by_group = {"": [row for group_rows in by_group.values() for row in group_rows]}
    groups = []
    for name in sorted(by_group, key=natural_key):
        group_rows = sorted(
            by_group[name], key=lambda row: natural_key(row["section_code"])
        )
        groups.append({"name": name, "rows": group_rows})
    return groups


def build_compliance_matrix(threat_model) -> list[dict]:
    """One entry per framework the model's controls map to, installed or not."""
    mappings = list(
        InstanceCountermeasureStandard.objects.filter(
            countermeasure__threat_model=threat_model
        )
        .select_related(
            "requirement__framework", "countermeasure__countermeasure_library"
        )
        .order_by("countermeasure__number")
    )
    if not mappings:
        return []

    countermeasure_ids = {mapping.countermeasure_id for mapping in mappings}
    threat_numbers: dict[int, list[str]] = defaultdict(list)
    for link in (
        CountermeasureThreatLink.objects.filter(
            countermeasure_id__in=countermeasure_ids
        )
        .select_related("threat")
        .order_by("threat__number")
    ):
        threat_numbers[link.countermeasure_id].append(f"T{link.threat.number}")

    def mapped_control(mapping) -> dict:
        countermeasure = mapping.countermeasure
        library = countermeasure.countermeasure_library
        return {
            "id": countermeasure.id,
            "display_number": countermeasure.display_number,
            "name": (library.name if library else None)
            or countermeasure.countermeasure_name,
            "status": countermeasure.status,
            "sufficiency": mapping.sufficiency,
            "days_overdue": countermeasure.days_overdue,
            "threats": threat_numbers.get(countermeasure.id, []),
        }

    # Installed frameworks: every requirement of the pack is a row.
    installed_mappings: dict[int, dict[int, list[dict]]] = defaultdict(
        lambda: defaultdict(list)
    )
    frameworks = {}
    # Not installed: the mapped section codes are the rows.
    snapshot_mappings: dict[str, dict[str, dict]] = defaultdict(dict)
    for mapping in mappings:
        if mapping.requirement_id is not None:
            framework = mapping.requirement.framework
            frameworks[framework.id] = framework
            installed_mappings[framework.id][mapping.requirement_id].append(
                mapped_control(mapping)
            )
        else:
            name = mapping.framework_name or "Unnamed framework"
            row = snapshot_mappings[name].setdefault(
                mapping.section_code,
                {"description": mapping.requirement_description, "controls": []},
            )
            row["controls"].append(mapped_control(mapping))

    requirements_by_framework: dict[int, list] = defaultdict(list)
    parent_names = {}
    for requirement in StandardRequirement.objects.filter(
        framework_id__in=frameworks.keys()
    ).select_related("parent"):
        requirements_by_framework[requirement.framework_id].append(requirement)
        if requirement.parent_id:
            parent = requirement.parent
            parent_names[parent.id] = f"{parent.section_code} {parent.name}".strip()

    result = []
    for framework_id, framework in frameworks.items():
        mapped = installed_mappings[framework_id]
        rows = []
        family_ids = {
            requirement.parent_id
            for requirement in requirements_by_framework[framework_id]
            if requirement.parent_id
        }
        for requirement in requirements_by_framework[framework_id]:
            controls = mapped.get(requirement.id, [])
            is_family = requirement.id in family_ids
            # A family (a parent of other requirements) is the group heading;
            # it is a row only when a control maps to it directly.
            if is_family and not controls:
                continue
            rows.append(
                {
                    "requirement_id": requirement.id,
                    "section_code": requirement.section_code,
                    "name": requirement.name,
                    "description": requirement.description,
                    "state": row_state(controls),
                    "controls": controls,
                    "overdue": any(control["days_overdue"] for control in controls),
                    "_parent_id": requirement.id
                    if is_family
                    else requirement.parent_id,
                }
            )
        result.append(
            _framework_entry(
                framework.name, framework.version, True, rows, parent_names
            )
        )

    for name, rows_by_code in snapshot_mappings.items():
        rows = [
            {
                "requirement_id": None,
                "section_code": code,
                "name": "",
                "description": row["description"],
                "state": row_state(row["controls"]),
                "controls": row["controls"],
                "overdue": any(control["days_overdue"] for control in row["controls"]),
            }
            for code, row in rows_by_code.items()
        ]
        result.append(_framework_entry(name, "", False, rows, parent_names))

    return sorted(
        result, key=lambda entry: (not entry["installed"], entry["name"].lower())
    )


def _framework_entry(
    name: str, version: str, installed: bool, rows: list[dict], parent_names: dict
) -> dict:
    counts = dict.fromkeys(STATE_ORDER, 0)
    for row in rows:
        counts[row["state"]] += 1
    return {
        "name": name,
        "version": version,
        "installed": installed,
        # The pack's requirements (installed), or None: without the pack there is no total.
        "pack_requirement_count": len(rows) if installed else None,
        "mapped_requirement_count": len(
            [row for row in rows if row["state"] != "not_covered"]
        ),
        # A list, not a dict: the API camel-cases dict keys (partial_only would
        # arrive as partialOnly), while state values stay as they are.
        "state_counts": [
            {"state": state, "count": counts[state]} for state in STATE_ORDER
        ],
        "groups": _group_rows(rows, parent_names),
    }
