"""Controls into ``InstanceCountermeasure`` rows (step 4 slice).

Rules (plan sections 4.3, 9.2, 9.4 and PR #559, D20):

- ``appliesTo`` becomes target rows; the system component or no list means
  the whole system; a ref we cannot target is kept and warned about.
- ``implementedBy`` becomes provider components, or the provider party's
  name as text.
- ``satisfies`` resolves each requirement through ``definitions.standards``
  (and the older ``definitions.requirements`` shape) to an installed
  ``StandardRequirement`` when its framework is here, else to a snapshot
  mapping that still displays; object-form entries ``{reference, framework}``
  are accepted too. Dangling refs warn and are skipped.
- Status: spec values map to ours; the custom names gap, waived and platform
  are ours; ``platform`` needs the Security Team role in the organization,
  otherwise ``gap`` is stored and the import warns (H6). Decision-process
  statuses (recommended, proposed, approved, rejected) are stored as planned
  or waived with the original kept in ``format_metadata``.
- Threat links come from ``precogly:mitigates`` when present, else from
  ``threat.mitigations`` (every scenario of that threat).
"""

from datetime import date

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied

from apps.compliance.models import StandardRequirement
from apps.threat_models.numbering import COUNTERMEASURES, raise_counter_to
from apps.threats.models import (
    CountermeasureLibrary,
    InstanceCountermeasureStandard,
)
from apps.threats.services import (
    check_platform_status,
    create_instance_countermeasure,
    link_countermeasure,
    recalculate_threat_status,
)

from ..passthrough import keep_unknown
from ..properties import PropertyOwner, read_properties
from ..refs import remember_ref
from ..spec_values import (
    CONTROL_CATEGORIES,
    CUSTOM_COUNTERMEASURE_STATUSES,
    SPEC_STATUS_TO_COUNTERMEASURE,
    type_name,
)

User = get_user_model()


def _label(data: dict, fallback: str) -> str:
    return str(data.get("name") or data.get("bom-ref") or fallback)[:255]


def _flatten(values) -> list:
    result = []
    for value in values:
        if isinstance(value, list):
            result.extend(value)
        else:
            result.append(value)
    return result


class ControlImporter:
    def __init__(self, document: dict, threat_model, context, *, system_ref):
        self.document = document
        self.threat_model = threat_model
        self.context = context
        self.system_ref = system_ref
        self.used_numbers: set[int] = set()
        self.highest_number = 0
        self.requirements = self._index_requirements()
        self.parties = self._index_parties()
        self.linked_threats = {}

    # -- indexes ----------------------------------------------------------

    def _index_requirements(self) -> dict:
        """ref -> {framework_name, section_code, description}"""
        index = {}
        definitions = self.document.get("definitions") or {}
        for standard in definitions.get("standards") or []:
            if not isinstance(standard, dict):
                continue
            framework_name = str(standard.get("name") or "")
            for requirement in standard.get("requirements") or []:
                if not isinstance(requirement, dict) or not requirement.get("bom-ref"):
                    continue
                index[requirement["bom-ref"]] = {
                    "framework_name": framework_name,
                    "section_code": str(requirement.get("identifier") or ""),
                    "description": str(
                        requirement.get("text") or requirement.get("title") or ""
                    ),
                }
        # The shape PR #559 handled: requirements with a `source.name`.
        for requirement in definitions.get("requirements") or []:
            if not isinstance(requirement, dict) or not requirement.get("bom-ref"):
                continue
            if requirement["bom-ref"] in index or not requirement.get("identifier"):
                continue
            index[requirement["bom-ref"]] = {
                "framework_name": str(
                    (requirement.get("source") or {}).get("name") or ""
                ),
                "section_code": str(requirement.get("identifier") or ""),
                "description": str(requirement.get("description") or ""),
            }
        return index

    def _index_parties(self) -> dict:
        component = (self.document.get("metadata") or {}).get("component") or {}
        parties = component.get("parties") if isinstance(component, dict) else None
        return {
            party["bom-ref"]: party
            for party in parties or []
            if isinstance(party, dict) and isinstance(party.get("bom-ref"), str)
        }

    # -- pieces -----------------------------------------------------------

    def _status(self, control: dict, label: str):
        """``(status, original)``; ``original`` is kept when it is not ours."""
        raw = control.get("status")
        name = type_name(raw)
        if isinstance(raw, dict) or name in CUSTOM_COUNTERMEASURE_STATUSES:
            if name in CUSTOM_COUNTERMEASURE_STATUSES:
                if name == "platform":
                    try:
                        check_platform_status(
                            self.context.user, self.threat_model, None, "platform"
                        )
                    except PermissionDenied:
                        self.context.warn(
                            f"Control '{label}': platform status needs the Security "
                            "Team role; stored as gap."
                        )
                        return "gap", raw
                return name, None
            if name:
                self.context.warn(
                    f"Control '{label}': status '{name}' is not one Precogly has; "
                    "stored as gap and kept for export."
                )
            return "gap", raw
        if not name:
            return "gap", None
        mapped = SPEC_STATUS_TO_COUNTERMEASURE.get(name)
        if mapped is None:
            self.context.warn(
                f"Control '{label}': unknown status '{name}'; stored as gap."
            )
            return "gap", raw
        original = raw if mapped != name.replace("-", "_") else None
        return mapped, original

    def _targets(self, control: dict, label: str):
        targets = []
        extras = []
        for ref in control.get("appliesTo") or []:
            if not isinstance(ref, str) or ref == self.system_ref:
                continue
            row = self.context.resolve(
                ref, "asset", "datastore", "flow", "zone", "boundary"
            )
            if row is None:
                extras.append(ref)
            elif row not in targets:
                targets.append(row)
        if extras:
            self.context.warn(
                f"Control '{label}': {len(extras)} appliesTo ref(s) cannot be a target "
                "in Precogly and were kept for export: " + ", ".join(extras)
            )
        return targets, extras

    def _party_name(self, party: dict) -> str:
        for key in ("organization", "person"):
            value = party.get(key)
            if isinstance(value, dict) and value.get("name"):
                return str(value["name"])
        persona = party.get("persona")
        if isinstance(persona, dict) and persona.get("description"):
            return str(persona["description"])
        return str(party.get("bom-ref") or "")

    def _implemented_by(self, control: dict, label: str):
        """Provider components, provider party text, and refs kept for export.

        A ref that is neither a component nor a declared party (another
        tool's element, kept in passthrough content) is kept on the control
        and written back on export while it still resolves (S5, R31).
        """
        components = []
        party_names = []
        extras = []
        for ref in control.get("implementedBy") or []:
            if not isinstance(ref, str):
                continue
            component = self.context.resolve(ref, "asset", "datastore")
            if component is not None:
                if component not in components:
                    components.append(component)
                continue
            party = self.parties.get(ref)
            if party is not None:
                party_names.append(self._party_name(party))
                continue
            extras.append(ref)
        if extras:
            self.context.warn(
                f"Control '{label}': {len(extras)} implementedBy ref(s) are neither a "
                "component nor a declared party and were kept for export: "
                + ", ".join(extras)
            )
        return components, ", ".join(party_names)[:255], extras

    def _owner(self, control: dict, label: str):
        """The assigned owner as a user of the organization, else None."""
        raw = control.get("owner")
        party = self.parties.get(raw) if isinstance(raw, str) else raw
        if not isinstance(party, dict):
            return None, raw if raw else None
        emails = []
        person = party.get("person")
        if isinstance(person, dict):
            for item in person.get("email") or []:
                if isinstance(item, dict) and item.get("address"):
                    emails.append(str(item["address"]).lower())
        for email in emails:
            user = User.objects.filter(
                email__iexact=email,
                organization_memberships__organization_id=self.threat_model.organization_id,
            ).first()
            if user is not None:
                return user, None
        self.context.warn(
            f"Control '{label}': owner matches no member of the organization; kept "
            "for export, not assigned."
        )
        return None, raw

    def _user_by_email(self, email: str):
        if not email:
            return None
        return User.objects.filter(
            email__iexact=email,
            organization_memberships__organization_id=self.threat_model.organization_id,
        ).first()

    def _external_references(self, control: dict):
        ticket = ""
        evidence = ""
        others = []
        for reference in control.get("externalReferences") or []:
            if not isinstance(reference, dict) or not reference.get("url"):
                continue
            kind = reference.get("type")
            if kind == "issue-tracker" and not ticket:
                ticket = str(reference["url"])[:200]
            elif kind == "evidence" and not evidence:
                evidence = str(reference["url"])[:200]
            else:
                others.append(reference)
        return ticket, evidence, others

    def _satisfies(self, countermeasure, control: dict, properties: dict, label: str):
        sufficiency_by_ref = {}
        for item in _flatten(properties.get("precogly:sufficiency", [])):
            if isinstance(item, dict) and item.get("requirement"):
                sufficiency_by_ref[item["requirement"]] = item.get("sufficiency")
        for entry in control.get("satisfies") or []:
            if isinstance(entry, dict):
                info = {
                    "section_code": str(
                        entry.get("reference") or entry.get("control-id") or ""
                    ),
                    "framework_name": str(
                        entry.get("framework") or entry.get("framework_name") or ""
                    ),
                    "description": str(entry.get("description") or ""),
                }
                ref = None
            else:
                ref = entry
                info = self.requirements.get(entry) if isinstance(entry, str) else None
            if not info or not info.get("section_code"):
                self.context.warn(
                    f"Control '{label}': satisfies reference '{entry}' matches no "
                    "requirement definition; skipped."
                )
                continue
            sufficiency = sufficiency_by_ref.get(ref) or "partial"
            if sufficiency not in {"full", "partial"}:
                sufficiency = "partial"
            self._store_requirement(countermeasure, info, sufficiency)

    def _store_requirement(self, countermeasure, info: dict, sufficiency: str) -> None:
        section_code = info["section_code"][:50]
        framework_name = info["framework_name"][:255]
        requirement = None
        if section_code and framework_name:
            requirement = (
                StandardRequirement.objects.filter(
                    framework__name=framework_name, section_code=section_code
                ).first()
                or StandardRequirement.objects.filter(
                    framework__slug=framework_name, section_code=section_code
                ).first()
            )
        if requirement is not None:
            InstanceCountermeasureStandard.objects.get_or_create(
                countermeasure=countermeasure,
                requirement=requirement,
                defaults={
                    "sufficiency": sufficiency,
                    "section_code": section_code,
                    "framework_name": requirement.framework.name,
                    "requirement_description": info.get("description")
                    or requirement.description,
                },
            )
            return
        InstanceCountermeasureStandard.objects.get_or_create(
            countermeasure=countermeasure,
            requirement=None,
            section_code=section_code,
            framework_name=framework_name,
            defaults={
                "sufficiency": sufficiency,
                "requirement_description": info.get("description") or "",
            },
        )

    def _number(self, properties: dict, label: str):
        number = properties.get("precogly:number")
        if number is None:
            return None
        if number < 1 or number in self.used_numbers:
            self.context.warn(
                f"Control '{label}': number {number} is taken or invalid; a new one "
                "was allocated."
            )
            return None
        return number

    def _due_date(self, properties: dict, label: str):
        raw = properties.get("precogly:due-date")
        if not raw:
            return None
        try:
            return date.fromisoformat(str(raw))
        except ValueError:
            self.context.warn(
                f"Control '{label}': due date '{raw}' is not a date; ignored."
            )
            return None

    def _mitigated_scenarios(self, control: dict, properties: dict, label: str):
        explicit = [
            ref
            for ref in _flatten(properties.get("precogly:mitigates", []))
            if isinstance(ref, str)
        ]
        if explicit:
            threats = []
            for ref in explicit:
                threat = self.context.resolve(ref, "scenario")
                if threat is None:
                    self.context.warn(
                        f"Control '{label}': mitigates '{ref}' is not a scenario; skipped."
                    )
                elif threat not in threats:
                    threats.append(threat)
            return threats
        control_ref = control.get("bom-ref")
        threats = []
        for threat_ref, mitigations in self.context.mitigations_by_threat_ref.items():
            if control_ref in mitigations:
                for threat in self.context.scenarios_by_threat_ref.get(threat_ref, []):
                    if threat not in threats:
                        threats.append(threat)
        return threats

    # -- one control --------------------------------------------------------

    def _import_control(self, control: dict, index: int) -> None:
        label = _label(control, f"control {index}")
        properties = read_properties(control.get("properties"), PropertyOwner.CONTROL)
        status, original_status = self._status(control, label)
        targets, extra_targets = self._targets(control, label)
        components, party_text, extra_providers = self._implemented_by(control, label)
        owner, kept_owner = self._owner(control, label)
        ticket, evidence, other_references = self._external_references(control)

        functions = [
            str(f) for f in _flatten(properties.get("precogly:control-functions", []))
        ]
        category = type_name(control.get("category"))
        if not functions and category in CONTROL_CATEGORIES:
            functions = [category]

        library = None
        library_slug = properties.get("precogly:library")
        if library_slug:
            library = CountermeasureLibrary.objects.filter(
                qualified_slug=library_slug
            ).first()

        effectiveness = None
        effectiveness_data = control.get("effectiveness")
        if isinstance(effectiveness_data, dict) and isinstance(
            effectiveness_data.get("percentage"), (int, float)
        ):
            effectiveness = max(0.0, min(1.0, float(effectiveness_data["percentage"])))

        countermeasure = create_instance_countermeasure(
            self.threat_model,
            countermeasure_library=library,
            status=status,
            auto_generated=bool(properties.get("precogly:auto-generated", False)),
            number=self._number(properties, label),
            targets=targets,
            implemented_by=components,
            countermeasure_name=str(control.get("name") or label)[:255],
            countermeasure_description=str(control.get("description") or ""),
            control_functions=functions,
            control_nature=str(properties.get("precogly:control-nature") or "")[:20],
            implemented_by_party=party_text,
            source=str(properties.get("precogly:source") or "")[:255],
            priority=str(properties.get("precogly:priority") or "none")[:10],
            due_date=self._due_date(properties, label),
            required_for_release=bool(
                properties.get("precogly:required-for-release", False)
            ),
            effectiveness=effectiveness,
            assigned_owner=owner,
            verified_by=self._user_by_email(
                str(properties.get("precogly:verified-by") or "")
            ),
            external_ticket_url=ticket,
            evidence_url=evidence,
        )
        self.used_numbers.add(countermeasure.number)
        self.highest_number = max(self.highest_number, countermeasure.number)

        bom_ref = (
            control.get("bom-ref") if isinstance(control.get("bom-ref"), str) else ""
        )
        remember_ref(countermeasure, bom_ref)
        keep_unknown(countermeasure, control, "control")
        cyclonedx = dict((countermeasure.format_metadata or {}).get("cyclonedx") or {})
        if original_status is not None:
            cyclonedx["original_status"] = original_status
        if extra_targets:
            cyclonedx["extra_applies_to"] = extra_targets
        if extra_providers:
            cyclonedx["extra_implemented_by"] = extra_providers
        if kept_owner is not None:
            cyclonedx["owner"] = kept_owner
        if other_references:
            cyclonedx["external_references"] = other_references
        if cyclonedx:
            metadata = dict(countermeasure.format_metadata or {})
            metadata["cyclonedx"] = cyclonedx
            countermeasure.format_metadata = metadata
            countermeasure.save(update_fields=["format_metadata"])
        self.context.register(bom_ref, "control", countermeasure)

        self._satisfies(countermeasure, control, properties, label)
        for threat in self._mitigated_scenarios(control, properties, label):
            link_countermeasure(countermeasure, threat)
            self.linked_threats[threat.pk] = threat
        self.context.count("controls")

    def _apply_trust_boundaries(self) -> None:
        """``threatsAtBoundary`` and ``controlsAtBoundary`` from other tools add
        the boundary as a target; our own documents carry the targets already,
        so this only ever adds what is missing (section 9.4)."""
        from apps.threats.services import add_target, set_countermeasure_targets

        section = self.document.get("threats")
        entries = section.get("trustBoundaries") if isinstance(section, dict) else None
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            boundary = self.context.resolve(entry.get("boundary"), "boundary")
            if boundary is None:
                self.context.warn(
                    f"Trust boundary '{entry.get('bom-ref')}': boundary "
                    f"'{entry.get('boundary')}' was not found; skipped."
                )
                continue
            for ref in entry.get("threatsAtBoundary") or []:
                threat = self.context.resolve(ref, "scenario")
                if threat is None:
                    self.context.warn(
                        f"Trust boundary '{entry.get('bom-ref')}': '{ref}' is not a "
                        "scenario; skipped."
                    )
                    continue
                if threat.whole_system:
                    continue
                add_target(threat, boundary)
            for ref in entry.get("controlsAtBoundary") or []:
                countermeasure = self.context.resolve(ref, "control")
                if countermeasure is None:
                    self.context.warn(
                        f"Trust boundary '{entry.get('bom-ref')}': '{ref}' is not a "
                        "control; skipped."
                    )
                    continue
                targets = [row.target for row in countermeasure.targets.all()]
                if boundary not in targets:
                    set_countermeasure_targets(countermeasure, [*targets, boundary])

    def run(self) -> None:
        controls = self.document.get("controls")
        if controls is not None and not isinstance(controls, list):
            self.context.warn("The 'controls' section is not a list and was skipped.")
            controls = []
        for index, control in enumerate(controls or []):
            if not isinstance(control, dict):
                self.context.warn(f"Control {index} is not an object and was skipped.")
                continue
            self._import_control(control, index)
        self._apply_trust_boundaries()
        for threat in self.linked_threats.values():
            recalculate_threat_status(threat)

        document_properties = read_properties(
            self.document.get("properties"), PropertyOwner.DOCUMENT
        )
        minimum_next = max(
            self.highest_number + 1,
            int(document_properties.get("precogly:next-countermeasure-number") or 1),
        )
        raise_counter_to(self.threat_model.id, COUNTERMEASURES, minimum_next)


def import_controls(document: dict, threat_model, context, *, system_ref) -> None:
    ControlImporter(document, threat_model, context, system_ref=system_ref).run()
