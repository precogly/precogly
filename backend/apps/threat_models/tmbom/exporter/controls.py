"""Controls (step 4 slice, plan section 9.3).

One ``controls[]`` entry per ``InstanceCountermeasure``: ``appliesTo`` from
its target rows (none means the whole system and the field is left out),
``implementedBy`` from its provider components and its provider party (G10),
``satisfies`` as refs into ``definitions.standards[].requirements[]``, the
status with custom objects for gap, waived and platform, external references
for the ticket and the evidence, and ``precogly:mitigates`` naming the
scenarios it is explicitly linked to (G2). Parties (owners, providers) are
declared once on ``metadata.component.parties`` and referenced.
"""

from django.utils.text import slugify

from ..properties import PropertyOwner, make_property
from ..refs import RefRegistry
from ..spec_values import (
    CONTROL_CATEGORIES,
    COUNTERMEASURE_STATUS_TO_SPEC,
    SPEC_STATUS_TO_COUNTERMEASURE,
    custom_type,
    type_name,
)
from .blueprint import component_ref


def _cyclonedx_metadata(row) -> dict:
    return (getattr(row, "format_metadata", None) or {}).get("cyclonedx") or {}


# Roles the exporter assigns that the CycloneDX role taxonomy predefines. Any
# other role (``assignee``) is written as a custom role, ``{"name": role}``.
PREDEFINED_PARTY_ROLES = frozenset(
    {"attacker", "auditor", "owner", "provider", "reviewer", "signatory"}
)


def role_entry(role: str) -> dict:
    return {"role": role} if role in PREDEFINED_PARTY_ROLES else {"name": role}


class PartyIndex:
    """Parties declared once on the system component: owners and providers."""

    def __init__(self, refs: RefRegistry):
        self.refs = refs
        self.entries: list[dict] = []
        self._user_refs: dict[int, str] = {}
        self._provider_refs: dict[str, str] = {}

    def user_ref(self, user, role: str) -> str:
        ref = self._user_refs.get(user.pk)
        if ref is None:
            ref = self.refs.fixed(f"party-user-{user.pk}")
            person = {}
            full_name = user.get_full_name()
            if full_name:
                person["name"] = full_name
            if user.email:
                person["email"] = [{"address": user.email}]
            if not person:
                person["name"] = user.get_username()
            self.entries.append(
                {"bom-ref": ref, "roles": [role_entry(role)], "person": person}
            )
            self._user_refs[user.pk] = ref
            return ref
        entry = next(e for e in self.entries if e["bom-ref"] == ref)
        if role_entry(role) not in entry["roles"]:
            entry["roles"].append(role_entry(role))
        return ref

    def provider_ref(self, name: str) -> str:
        ref = self._provider_refs.get(name)
        if ref is None:
            ref = self.refs.fixed(f"party-provider-{slugify(name)[:60] or 'provider'}")
            self.entries.append(
                {
                    "bom-ref": ref,
                    "roles": [{"role": "provider"}],
                    "organization": {"name": name},
                }
            )
            self._provider_refs[name] = ref
        return ref


class StandardsIndex:
    """``definitions.standards[]`` built from the requirements controls satisfy.

    A requirement with a library row goes under its framework's standard
    (``standard-<framework id>``, ``requirement-<id>``). A snapshot mapping,
    whose framework is not installed here, goes under a standard named from
    the snapshot (``requirement-snapshot-<mapping id>``), so the mapping
    still travels (PR #559).
    """

    def __init__(self, refs: RefRegistry):
        self.refs = refs
        self.standards: dict[str, dict] = {}
        self._requirement_refs: dict[tuple, str] = {}

    def _standard(self, key: str, bom_ref: str, name: str, version: str = "") -> dict:
        standard = self.standards.get(key)
        if standard is None:
            standard = {
                "bom-ref": self.refs.fixed(bom_ref),
                "name": name,
                "requirements": [],
            }
            if version:
                standard["version"] = version
            self.standards[key] = standard
        return standard

    def requirement_ref(self, requirement) -> str:
        key = ("row", requirement.pk)
        ref = self._requirement_refs.get(key)
        if ref is not None:
            return ref
        framework = requirement.framework
        standard = self._standard(
            f"framework-{framework.pk}",
            f"standard-{framework.pk}",
            framework.name,
            framework.version,
        )
        ref = self.refs.fixed(f"requirement-{requirement.pk}")
        entry = {
            "bom-ref": ref,
            "identifier": requirement.section_code,
            "title": requirement.name or requirement.section_code,
        }
        if requirement.description:
            entry["text"] = requirement.description
        standard["requirements"].append(entry)
        self._requirement_refs[key] = ref
        return ref

    def snapshot_ref(self, mapping) -> str:
        key = ("snapshot", mapping.framework_name, mapping.section_code)
        ref = self._requirement_refs.get(key)
        if ref is not None:
            return ref
        name = mapping.framework_name or "Unknown standard"
        standard = self._standard(
            f"name-{name}", f"standard-{slugify(name)[:60] or 'unknown'}", name
        )
        ref = self.refs.fixed(f"requirement-snapshot-{mapping.pk}")
        entry = {
            "bom-ref": ref,
            "identifier": mapping.section_code,
            "title": mapping.section_code,
        }
        if mapping.requirement_description:
            entry["text"] = mapping.requirement_description
        standard["requirements"].append(entry)
        self._requirement_refs[key] = ref
        return ref

    def finish(self) -> list[dict]:
        return list(self.standards.values())


def control_name(countermeasure) -> str:
    if countermeasure.countermeasure_name:
        return countermeasure.countermeasure_name
    library = countermeasure.countermeasure_library
    if library is not None and library.name:
        return library.name
    return countermeasure.display_number


def _status(countermeasure):
    # A spec status that mapped onto ours at import is written back while the
    # row still carries what it mapped to (L9), so "proposed" stays "proposed".
    cyclonedx = (countermeasure.format_metadata or {}).get("cyclonedx") or {}
    original = cyclonedx.get("original_status")
    if original is not None:
        mapped = SPEC_STATUS_TO_COUNTERMEASURE.get(type_name(original))
        if mapped == countermeasure.status:
            return original
    spec = COUNTERMEASURE_STATUS_TO_SPEC.get(countermeasure.status)
    if spec is not None:
        return spec
    return custom_type(countermeasure.status)


def _satisfies(countermeasure, standards: StandardsIndex):
    """``(refs, sufficiency entries)``; instance mappings override library ones."""
    by_requirement: dict = {}
    library = countermeasure.countermeasure_library
    if library is not None:
        for mapping in library.standard_mappings.all():
            if mapping.requirement_id and mapping.requirement.framework_id:
                by_requirement[mapping.requirement_id] = (
                    standards.requirement_ref(mapping.requirement),
                    mapping.sufficiency,
                )
    for mapping in countermeasure.instance_standard_mappings.all():
        if mapping.requirement_id and mapping.requirement.framework_id:
            by_requirement[mapping.requirement_id] = (
                standards.requirement_ref(mapping.requirement),
                mapping.sufficiency,
            )
        elif mapping.section_code:
            by_requirement[("snapshot", mapping.pk)] = (
                standards.snapshot_ref(mapping),
                mapping.sufficiency,
            )
    refs = []
    sufficiency = []
    for ref, value in by_requirement.values():
        if ref in refs:
            continue
        refs.append(ref)
        sufficiency.append({"requirement": ref, "sufficiency": value})
    return refs, sufficiency


def _properties(countermeasure, scenario_refs: list[str], sufficiency: list[dict]):
    owner = PropertyOwner.CONTROL
    properties = [make_property("precogly:number", owner, countermeasure.number)]
    if countermeasure.control_functions:
        properties.append(
            make_property(
                "precogly:control-functions",
                owner,
                list(countermeasure.control_functions),
            )
        )
    if countermeasure.control_nature:
        properties.append(
            make_property(
                "precogly:control-nature", owner, countermeasure.control_nature
            )
        )
    if countermeasure.priority and countermeasure.priority != "none":
        properties.append(
            make_property("precogly:priority", owner, countermeasure.priority)
        )
    if countermeasure.due_date:
        properties.append(
            make_property(
                "precogly:due-date", owner, countermeasure.due_date.isoformat()
            )
        )
    if countermeasure.required_for_release:
        properties.append(make_property("precogly:required-for-release", owner, True))
    if countermeasure.auto_generated:
        properties.append(make_property("precogly:auto-generated", owner, True))
    if countermeasure.source:
        properties.append(
            make_property("precogly:source", owner, countermeasure.source)
        )
    if countermeasure.verified_by_id and countermeasure.verified_by.email:
        properties.append(
            make_property(
                "precogly:verified-by", owner, countermeasure.verified_by.email
            )
        )
    library = countermeasure.countermeasure_library
    if library is not None and library.qualified_slug:
        properties.append(
            make_property("precogly:library", owner, library.qualified_slug)
        )
    if scenario_refs:
        properties.append(make_property("precogly:mitigates", owner, scenario_refs))
    if sufficiency:
        properties.append(make_property("precogly:sufficiency", owner, sufficiency))
    return properties


def _external_references(countermeasure) -> list[dict]:
    references = []
    if countermeasure.external_ticket_url:
        references.append(
            {"type": "issue-tracker", "url": countermeasure.external_ticket_url}
        )
    if countermeasure.evidence_url:
        references.append({"type": "evidence", "url": countermeasure.evidence_url})
    return references


def _control(
    countermeasure, refs: RefRegistry, parties: PartyIndex, standards: StandardsIndex
) -> dict:
    entry = {
        "bom-ref": refs.ref("control", countermeasure),
        "name": control_name(countermeasure),
    }
    description = countermeasure.countermeasure_description or (
        countermeasure.countermeasure_library.description
        if countermeasure.countermeasure_library_id
        else ""
    )
    if description:
        entry["description"] = description
    category = next(
        (f for f in countermeasure.control_functions or [] if f in CONTROL_CATEGORIES),
        None,
    )
    if category:
        entry["category"] = category
    entry["status"] = _status(countermeasure)

    applies_to = []
    for row in countermeasure.targets.all():
        target = row.target
        if target is None:
            continue
        if row.target_kind == "component":
            applies_to.append(component_ref(target, refs))
        else:
            applies_to.append(refs.ref(row.target_kind, target))
    for extra in _cyclonedx_metadata(countermeasure).get("extra_applies_to") or []:
        if (
            isinstance(extra, str)
            and refs.will_resolve(extra)
            and extra not in applies_to
        ):
            applies_to.append(extra)
    if applies_to:
        entry["appliesTo"] = applies_to

    implemented_by = [
        component_ref(link.component, refs)
        for link in countermeasure.provider_links.all()
    ]
    if countermeasure.implemented_by_party:
        implemented_by.append(parties.provider_ref(countermeasure.implemented_by_party))
    for extra in _cyclonedx_metadata(countermeasure).get("extra_implemented_by") or []:
        if (
            isinstance(extra, str)
            and refs.will_resolve(extra)
            and extra not in implemented_by
        ):
            implemented_by.append(extra)
    if implemented_by:
        entry["implementedBy"] = implemented_by

    satisfies, sufficiency = _satisfies(countermeasure, standards)
    if satisfies:
        entry["satisfies"] = satisfies
    if countermeasure.effectiveness is not None:
        entry["effectiveness"] = {"percentage": countermeasure.effectiveness}
    if countermeasure.assigned_owner_id:
        entry["owner"] = parties.user_ref(countermeasure.assigned_owner, "owner")
    references = _external_references(countermeasure)
    if references:
        entry["externalReferences"] = references
    scenario_refs = [
        refs.ref("scenario", link.threat) for link in countermeasure.threat_links.all()
    ]
    entry["properties"] = _properties(countermeasure, scenario_refs, sufficiency)
    return entry


def countermeasures_queryset(threat_model):
    return (
        threat_model.countermeasures.select_related(
            "countermeasure_library", "assigned_owner", "verified_by"
        )
        .prefetch_related(
            "countermeasure_library__standard_mappings__requirement__framework",
            "instance_standard_mappings__requirement__framework",
            "targets__component__component_library",
            "targets__flow",
            "targets__zone",
            "targets__boundary",
            "provider_links__component__component_library",
            "threat_links__threat",
        )
        .order_by("number")
    )


def reserve_control_refs(threat_model, refs: RefRegistry) -> None:
    refs.reserve_stored(threat_model.countermeasures.all())


def export_controls(threat_model, refs: RefRegistry, *, parties=None):
    """``(controls, parties, standards)`` for the document.

    ``parties`` is shared with the risks exporter, so an owner of a control
    and of a risk is declared once.
    """
    parties = parties if parties is not None else PartyIndex(refs)
    standards = StandardsIndex(refs)
    controls = [
        _control(countermeasure, refs, parties, standards)
        for countermeasure in countermeasures_queryset(threat_model)
    ]
    return controls, parties.entries, standards.finish()
