"""Scenarios, abstract threats and actors into ``InstanceThreat`` rows (step 3).

Rules (plan sections 9.3 and 9.4):

- Several ``affectedAssets`` become one scenario with several targets (fixes
  #533); none, or only the system component, becomes a whole-system threat.
  A ref we cannot target is kept in ``format_metadata`` and warned about
  (H11); the scenario is never silently widened.
- A scenario that realizes several threats is split into one row per threat.
  Only the first keeps the document's ref and number (H10).
- An abstract threat whose ref is ``threat-<qualified slug>`` of an installed
  library row links to it; any other becomes a custom threat that remembers
  the abstract ref, so export re-emits it.
- The actor is a persona (created from its party, matched by symbolic name)
  or, for an actor carrying ``precogly:actor-text``, free text (K3). Actors
  with the ``attacker`` role or archetype become personas even when no
  scenario cites them (M10).
- Numbers come from ``precogly:number`` when free, else are allocated; the
  counter is raised to the document's ``precogly:next-threat-number`` (M12).
"""

from django.utils.text import slugify

from apps.threat_models.numbering import THREATS, raise_counter_to
from apps.threats.models import (
    InstanceThreat,
    InstanceThreatTaxonomyEntry,
    TaxonomyEntry,
    ThreatLibrary,
    ThreatPersona,
    ThreatSource,
    ThreatSourceLink,
)
from apps.threats.services import create_instance_threat

from ..passthrough import OBJECT_KNOWN, keep_unknown
from ..properties import PropertyOwner, read_properties
from ..ratings import rating_from_spec
from ..refs import remember_ref
from ..spec_values import ATTACKER_ARCHETYPES, THREAT_ORIGINS, type_name

LIBRARY_REF_PREFIX = "threat-"
TARGET_KINDS = {"asset": "component", "datastore": "component"}


def _choice(field_name: str, value, default: str) -> str:
    allowed = {
        choice for choice, _ in InstanceThreat._meta.get_field(field_name).choices
    }
    return value if value in allowed else default


def _label(data: dict, fallback: str) -> str:
    return str(data.get("name") or data.get("bom-ref") or fallback)[:255]


def _library_for(threat_ref) -> ThreatLibrary | None:
    if not isinstance(threat_ref, str) or not threat_ref.startswith(LIBRARY_REF_PREFIX):
        return None
    return ThreatLibrary.objects.filter(
        qualified_slug=threat_ref[len(LIBRARY_REF_PREFIX) :]
    ).first()


def _snapshot_from_abstract(abstract_data: dict) -> list[dict]:
    entries = []
    for category in abstract_data.get("categories") or []:
        if not isinstance(category, dict):
            continue
        taxonomy = str(category.get("taxonomy") or "").lower()
        value = str(category.get("category") or "")
        if taxonomy and value:
            entries.append(
                {"taxonomy_slug": taxonomy, "external_id": value, "title": value}
            )
    properties = read_properties(abstract_data.get("properties"), PropertyOwner.THREAT)
    for item in _flatten(properties.get("precogly:taxonomy", [])):
        if (
            isinstance(item, dict)
            and item.get("taxonomy_slug")
            and item.get("external_id")
        ):
            entries.append(
                {
                    "taxonomy_slug": str(item["taxonomy_slug"]),
                    "external_id": str(item["external_id"]),
                    "title": str(item.get("title") or item["external_id"]),
                }
            )
    return entries


def _flatten(values) -> list:
    """JSON properties arrive as a list of decoded values; lists are merged."""
    result = []
    for value in values:
        if isinstance(value, list):
            result.extend(value)
        else:
            result.append(value)
    return result


def _is_attacker(actor_data: dict) -> bool:
    party = actor_data.get("party")
    if not isinstance(party, dict):
        return False
    for role in party.get("roles") or []:
        if isinstance(role, dict) and role.get("role") == "attacker":
            return True
    persona = party.get("persona")
    if isinstance(persona, dict):
        archetype = type_name(persona.get("archetype"))
        if archetype in ATTACKER_ARCHETYPES:
            return True
    return False


class ThreatImporter:
    def __init__(self, document: dict, threat_model, context, *, system_ref):
        self.document = document
        self.threat_model = threat_model
        self.context = context
        self.system_ref = system_ref
        self.used_numbers: set[int] = set()
        self.highest_number = 0
        self.personas_by_actor_ref: dict[str, ThreatPersona] = {}
        self.persona_counter = 0
        section = document.get("threats")
        self.section = section if isinstance(section, dict) else {}
        self.abstract = {
            item["bom-ref"]: item
            for item in self.section.get("threats") or []
            if isinstance(item, dict) and isinstance(item.get("bom-ref"), str)
        }

    # -- actors ---------------------------------------------------------

    def _actor_text(self, actor_data: dict) -> str:
        properties = read_properties(actor_data.get("properties"), PropertyOwner.ACTOR)
        return str(properties.get("precogly:actor-text") or "")[:100]

    def _persona_for(self, actor_ref: str, actor_data: dict) -> ThreatPersona:
        existing = self.personas_by_actor_ref.get(actor_ref)
        if existing is not None:
            return existing
        party = (
            actor_data.get("party") if isinstance(actor_data.get("party"), dict) else {}
        )
        persona_data = (
            party.get("persona") if isinstance(party.get("persona"), dict) else {}
        )
        properties = read_properties(
            party.get("properties"), PropertyOwner.PERSONA_PARTY
        )
        self.persona_counter += 1
        name = (
            str(properties.get("precogly:persona-name") or "")
            or str(persona_data.get("description") or "")[:255]
            or f"Persona {self.persona_counter}"
        )
        symbolic = (
            str(properties.get("precogly:persona-symbolic-name") or "")
            or slugify(name)[:100]
            or f"persona-{self.persona_counter}"
        )[:100]
        base = symbolic
        suffix = 2
        while ThreatPersona.objects.filter(
            threat_model=self.threat_model, symbolic_name=symbolic
        ).exists():
            symbolic = f"{base}-{suffix}"[:100]
            suffix += 1
        if symbolic != base:
            self.context.warn(
                f"Persona '{name}': symbolic name '{base}' is taken; stored as "
                f"'{symbolic}'."
            )
        persona = ThreatPersona.objects.create(
            threat_model=self.threat_model,
            symbolic_name=symbolic,
            name=name[:255],
            description=str(persona_data.get("description") or ""),
            is_person=bool(properties.get("precogly:persona-is-person", True)),
            malicious_intent=bool(
                properties.get("precogly:persona-malicious-intent", True)
            ),
            skill_level=str(properties.get("precogly:persona-skill-level") or "")[:100],
            motivation=str(properties.get("precogly:persona-motivation") or ""),
            resources=str(properties.get("precogly:persona-resources") or ""),
            objectives=str(properties.get("precogly:persona-objectives") or ""),
        )
        remember_ref(persona, actor_ref)
        cyclonedx = persona.format_metadata["cyclonedx"]
        if isinstance(party.get("bom-ref"), str):
            cyclonedx["party_bom_ref"] = party["bom-ref"]
        if persona_data.get("archetype") is not None:
            cyclonedx["archetype"] = persona_data["archetype"]
        if symbolic != base:
            cyclonedx["original_symbolic_name"] = base
        persona.save(update_fields=["format_metadata"])
        self.context.register(party.get("bom-ref"), "party", persona)
        self.context.count("threat_personas")
        self.personas_by_actor_ref[actor_ref] = persona
        return persona

    def _actor(self, scenario: dict, label: str):
        """``(persona, text)`` for the scenario's actor; at most one is set."""
        actor_ref = scenario.get("actor")
        if not isinstance(actor_ref, str) or not actor_ref:
            return None, ""
        entry = self.context.actors.get(actor_ref)
        if entry is None:
            persona = self.context.resolve(actor_ref, "party")
            if persona is not None:
                return persona, ""
            self.context.warn(
                f"Scenario '{label}': actor '{actor_ref}' is not an actor of any "
                "blueprint; the scenario has no actor."
            )
            return None, ""
        text = self._actor_text(entry["data"])
        if text:
            return None, text
        return self._persona_for(actor_ref, entry["data"]), ""

    def _personas_for_uncited_attackers(self) -> None:
        for actor_ref, entry in self.context.actors.items():
            if actor_ref in self.personas_by_actor_ref:
                continue
            if self._actor_text(entry["data"]):
                continue
            if _is_attacker(entry["data"]):
                self._persona_for(actor_ref, entry["data"])

    # -- targets ---------------------------------------------------------

    def _targets(self, scenario: dict, label: str):
        """``(targets, whole_system, extra refs)`` from ``affectedAssets``."""
        refs = scenario.get("affectedAssets")
        if not refs:
            return [], True, []
        targets = []
        extras = []
        names_system = False
        for ref in refs:
            if not isinstance(ref, str):
                continue
            if ref == self.system_ref:
                names_system = True
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
                f"Scenario '{label}': {len(extras)} affected asset(s) cannot be a "
                "target in Precogly and were kept for export: " + ", ".join(extras)
            )
        if targets:
            return targets, False, extras
        if not names_system and extras:
            self.context.warn(
                f"Scenario '{label}' names only elements Precogly cannot show; "
                "stored as a whole-system threat."
            )
        return [], True, extras

    # -- scenarios -------------------------------------------------------

    def _number(self, properties: dict, label: str):
        number = properties.get("precogly:number")
        if number is None:
            return None
        if number < 1 or number in self.used_numbers:
            self.context.warn(
                f"Scenario '{label}': number {number} is taken or invalid; a new one "
                "was allocated."
            )
            return None
        return number

    def _link_instance_categories(self, threat, properties: dict, label: str) -> None:
        for item in _flatten(properties.get("precogly:instance-categories", [])):
            if not isinstance(item, dict):
                continue
            entry = TaxonomyEntry.objects.filter(
                taxonomy__slug=item.get("taxonomy_slug"),
                external_id=item.get("external_id"),
            ).first()
            if entry is None:
                self.context.warn(
                    f"Scenario '{label}': taxonomy entry "
                    f"{item.get('taxonomy_slug')}/{item.get('external_id')} is not "
                    "installed and was left out."
                )
                continue
            InstanceThreatTaxonomyEntry.objects.get_or_create(
                taxonomy_entry=entry, threat=threat
            )

    def _link_sources(self, threat, properties: dict, abstract_data: dict, label: str):
        slugs = [
            str(slug)
            for slug in _flatten(properties.get("precogly:threat-sources", []))
        ]
        if not slugs:
            origin = type_name(abstract_data.get("origin"))
            if origin in THREAT_ORIGINS:
                slugs = [origin]
        for slug in slugs:
            source = ThreatSource.objects.filter(slug=slug).first()
            if source is None:
                self.context.warn(
                    f"Scenario '{label}': threat source '{slug}' is unknown and was "
                    "left out."
                )
                continue
            ThreatSourceLink.objects.get_or_create(source=source, threat=threat)

    def _link_objectives(
        self, threat, properties: dict, abstract_data: dict, label: str
    ):
        """``precogly:business-objectives`` on the scenario, else the abstract
        threat's ``relatedBusinessObjectives`` (every scenario of the threat)."""
        from apps.threats.services import set_threat_business_objectives

        refs = [
            ref
            for ref in _flatten(properties.get("precogly:business-objectives", []))
            if isinstance(ref, str)
        ]
        if not refs:
            refs = [
                r
                for r in abstract_data.get("relatedBusinessObjectives") or []
                if isinstance(r, str)
            ]
        objectives = []
        for ref in refs:
            objective = self.context.resolve(ref, "objective")
            if objective is None:
                self.context.warn(
                    f"Scenario '{label}': business objective '{ref}' was not found; skipped."
                )
            elif objective not in objectives:
                objectives.append(objective)
        if objectives:
            set_threat_business_objectives(threat, objectives)

    def _import_scenario(self, scenario: dict, index: int) -> None:
        label = _label(scenario, f"scenario {index}")
        threat_refs = [r for r in scenario.get("threats") or [] if isinstance(r, str)]
        if not threat_refs:
            self.context.warn(
                f"Scenario '{label}' realizes no threat; stored as custom."
            )
            threat_refs = [None]
        targets, whole_system, extras = self._targets(scenario, label)
        persona, actor_text = self._actor(scenario, label)
        properties = read_properties(scenario.get("properties"), PropertyOwner.SCENARIO)
        scenario_ref = (
            scenario.get("bom-ref") if isinstance(scenario.get("bom-ref"), str) else ""
        )

        if len(threat_refs) > 1:
            self.context.warn(
                f"Scenario '{label}' realizes {len(threat_refs)} threats and was split "
                "into one scenario per threat; only the first keeps its ref and number."
            )

        for position, threat_ref in enumerate(threat_refs):
            abstract_data = self.abstract.get(threat_ref) or {}
            if threat_ref is not None and not abstract_data:
                self.context.warn(
                    f"Scenario '{label}': threat '{threat_ref}' is not declared in the "
                    "document; stored as a custom threat."
                )
            library = _library_for(threat_ref)
            threat_name = str(
                scenario.get("name") or abstract_data.get("name") or label
            )
            if len(threat_refs) > 1 and abstract_data.get("name"):
                threat_name = str(abstract_data["name"])
            description = str(scenario.get("description") or "")
            if not description and library is None:
                description = str(abstract_data.get("description") or "")

            rating = rating_from_spec(
                scenario.get("riskScore"),
                scenario.get("likelihood"),
                scenario.get("impact"),
                rationale=(scenario.get("riskScore") or {}).get("rationale", "")
                if isinstance(scenario.get("riskScore"), dict)
                else "",
            )
            impact_data = (
                scenario.get("impact")
                if isinstance(scenario.get("impact"), dict)
                else {}
            )
            impact_description = str(
                properties.get("precogly:impact-description")
                or impact_data.get("description")
                or ""
            )
            threat = create_instance_threat(
                self.threat_model,
                targets=targets,
                whole_system=whole_system,
                threat_library=library,
                rating=rating,
                level="medium",
                auto_generated=bool(properties.get("precogly:auto-generated", False)),
                number=self._number(properties, label) if position == 0 else None,
                threat_name=threat_name[:255],
                threat_description=description,
                taxonomy_snapshot=(
                    _snapshot_from_abstract(abstract_data) if library is None else None
                ),
                status=_choice(
                    "status", properties.get("precogly:threat-status"), "exposed"
                ),
                triage_status=_choice(
                    "triage_status", properties.get("precogly:triage-status"), "open"
                ),
                decision_rationale=str(
                    properties.get("precogly:decision-rationale") or ""
                ),
                impact_description=impact_description,
                intent=_choice("intent", scenario.get("intent"), ""),
                access_level=_choice("access_level", scenario.get("accessLevel"), ""),
                actor_persona=persona,
                threat_actor_text=actor_text,
            )
            self.used_numbers.add(threat.number)
            self.highest_number = max(self.highest_number, threat.number)

            if position == 0:
                remember_ref(threat, scenario_ref)
                keep_unknown(threat, scenario, "scenario")
                self.context.register(scenario_ref, "scenario", threat)
            if library is None and abstract_data:
                unknown = {
                    k: v
                    for k, v in abstract_data.items()
                    if k not in OBJECT_KNOWN["threat"]
                }
                if unknown:
                    threat.format_metadata.setdefault("cyclonedx", {})[
                        "threat_passthrough"
                    ] = unknown
            if threat_ref is not None:
                self.context.scenarios_by_threat_ref.setdefault(threat_ref, []).append(
                    threat
                )
                self.context.mitigations_by_threat_ref[threat_ref] = [
                    ref
                    for ref in abstract_data.get("mitigations") or []
                    if isinstance(ref, str)
                ]
            cyclonedx = dict((threat.format_metadata or {}).get("cyclonedx") or {})
            if position > 0 and scenario_ref:
                cyclonedx["split_from"] = scenario_ref
            if library is None and threat_ref:
                cyclonedx["threat_bom_ref"] = threat_ref
            if extras:
                cyclonedx["extra_affected_assets"] = extras
            if cyclonedx:
                metadata = dict(threat.format_metadata or {})
                metadata["cyclonedx"] = cyclonedx
                threat.format_metadata = metadata
                threat.save(update_fields=["format_metadata"])

            self._link_instance_categories(threat, properties, label)
            self._link_sources(threat, properties, abstract_data, label)
            self._link_objectives(threat, properties, abstract_data, label)
            self.context.count("threats")

    def run(self) -> None:
        if self.document.get("threats") is not None and not self.section:
            self.context.warn("The 'threats' section is not an object and was skipped.")
        for index, scenario in enumerate(self.section.get("scenarios") or []):
            if not isinstance(scenario, dict):
                self.context.warn(f"Scenario {index} is not an object and was skipped.")
                continue
            self._import_scenario(scenario, index)
        self._personas_for_uncited_attackers()

        document_properties = read_properties(
            self.document.get("properties"), PropertyOwner.DOCUMENT
        )
        minimum_next = max(
            self.highest_number + 1,
            int(document_properties.get("precogly:next-threat-number") or 1),
        )
        raise_counter_to(self.threat_model.id, THREATS, minimum_next)


def import_threats(document: dict, threat_model, context, *, system_ref) -> None:
    ThreatImporter(document, threat_model, context, system_ref=system_ref).run()
