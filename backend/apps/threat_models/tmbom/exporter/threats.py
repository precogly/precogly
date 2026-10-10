"""Scenarios, abstract threats and actors (step 3 slice, plan section 9.3).

- One ``threats.scenarios[]`` entry per ``InstanceThreat``, with ``threats``
  (the abstract threat it realizes), ``affectedAssets`` from its targets (the
  system component for a whole-system threat), its actor, intent and access
  level, and the ``precogly:`` properties that hold what the spec has no field
  for yet (number, status, triage, severities until step 5).
- One ``threats.threats[]`` entry per library threat in use, with the ref
  ``threat-<qualified slug>`` so it is the same on every installation (M1), or
  one synthesized entry per custom threat (``threat-custom-<id>``). Categories
  use the four spec taxonomies; anything else is ``precogly:taxonomy``.
  ``origin`` is written only when every scenario of that threat cites the
  same single source (H17).
- One ``actors[]`` entry on the first blueprint per persona and per distinct
  actor text, each with an inline persona party carrying the ``attacker``
  role and an archetype (G4, G7, K3).
"""

from django.utils.text import slugify

from ..properties import PropertyOwner, make_property
from ..ratings import scenario_rating
from ..refs import RefRegistry
from ..spec_values import (
    ATTACKER_ARCHETYPES,
    PERSONA_ARCHETYPES,
    TAXONOMY_SLUG_TO_SPEC,
    THREAT_CATEGORIES,
    THREAT_ORIGINS,
    custom_type,
)
from .blueprint import component_ref


def _cyclonedx_metadata(row) -> dict:
    return (getattr(row, "format_metadata", None) or {}).get("cyclonedx") or {}


def _normalized(value: str) -> str:
    return slugify(str(value or "").replace("_", "-"))


def spec_category(taxonomy_slug: str, external_id: str, title: str):
    """``(taxonomy, category)`` when the entry is one of the spec's, else None."""
    taxonomy = TAXONOMY_SLUG_TO_SPEC.get(str(taxonomy_slug or "").lower())
    if taxonomy is None:
        return None
    allowed = THREAT_CATEGORIES[taxonomy]
    for candidate in (_normalized(external_id), _normalized(title)):
        if candidate in allowed:
            return taxonomy, candidate
    return None


def _categories_and_properties(entries) -> tuple[list[dict], list[dict]]:
    """Split taxonomy entries into spec ``categories`` and ``precogly:taxonomy``."""
    categories: list[dict] = []
    properties: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        match = spec_category(
            entry["taxonomy_slug"], entry["external_id"], entry["title"]
        )
        if match is not None:
            if match not in seen:
                seen.add(match)
                categories.append({"taxonomy": match[0], "category": match[1]})
            continue
        properties.append(
            make_property(
                "precogly:taxonomy",
                PropertyOwner.THREAT,
                {
                    "taxonomy_slug": entry["taxonomy_slug"],
                    "external_id": entry["external_id"],
                    "title": entry["title"],
                },
            )
        )
    return categories, properties


def _library_entries(threat_library) -> list[dict]:
    return [
        {
            "taxonomy_slug": link.taxonomy_entry.taxonomy.slug,
            "external_id": link.taxonomy_entry.external_id,
            "title": link.taxonomy_entry.title,
        }
        for link in threat_library.taxonomy_entries.all()
    ]


def _snapshot_entries(threat) -> list[dict]:
    entries = []
    for item in threat.taxonomy_snapshot or []:
        if (
            isinstance(item, dict)
            and item.get("taxonomy_slug")
            and item.get("external_id")
        ):
            entries.append(
                {
                    "taxonomy_slug": item["taxonomy_slug"],
                    "external_id": item["external_id"],
                    "title": item.get("title") or item["external_id"],
                }
            )
    return entries


def _instance_entries(threat) -> list[dict]:
    return [
        {
            "taxonomy_slug": link.taxonomy_entry.taxonomy.slug,
            "external_id": link.taxonomy_entry.external_id,
            "title": link.taxonomy_entry.title,
        }
        for link in threat.instance_taxonomy_links.all()
    ]


def threat_display_name(threat) -> str:
    if threat.threat_name:
        return threat.threat_name
    if threat.threat_library_id and threat.threat_library.name:
        return threat.threat_library.name
    return threat.display_number


class AbstractThreatIndex:
    """One abstract threat per library row or custom threat, built on demand."""

    def __init__(self, refs: RefRegistry):
        self.refs = refs
        self.entries: dict[str, dict] = {}
        self.source_sets: dict[str, list[frozenset]] = {}
        self.source_names: dict[str, str] = {}
        self.mitigations: dict[str, list[str]] = {}
        self.objectives: dict[str, list[str]] = {}

    @staticmethod
    def key_for(threat) -> str:
        library = threat.threat_library if threat.threat_library_id else None
        if library is not None and library.qualified_slug:
            return f"threat-{library.qualified_slug}"
        stored = _cyclonedx_metadata(threat).get("threat_bom_ref")
        if isinstance(stored, str) and stored:
            return stored
        if library is not None:
            return f"threat-library-{library.pk}"
        return f"threat-custom-{threat.pk}"

    def ref_for(self, threat) -> str:
        key = self.key_for(threat)
        entry = self.entries.get(key)
        if entry is None:
            entry = self._build(key, threat)
            self.entries[key] = entry
        sources = {
            link.source.slug: link.source.name for link in threat.source_links.all()
        }
        self.source_sets.setdefault(key, []).append(frozenset(sources))
        self.source_names.update(sources)
        objectives = self.objectives.setdefault(key, [])
        for link in threat.business_objective_links.all():
            objective_ref = self.refs.ref("objective", link.business_objective)
            if objective_ref not in objectives:
                objectives.append(objective_ref)
        # ``threat.mitigations`` is the union over the threat's scenarios (G2).
        mitigations = self.mitigations.setdefault(key, [])
        for link in threat.countermeasure_links.all():
            control_ref = self.refs.ref("control", link.countermeasure)
            if control_ref not in mitigations:
                mitigations.append(control_ref)
        return entry["bom-ref"]

    def _build(self, key: str, threat) -> dict:
        library = threat.threat_library if threat.threat_library_id else None
        if library is not None:
            name = library.name
            description = library.description
            taxonomy_entries = _library_entries(library)
        else:
            name = threat_display_name(threat)
            description = threat.threat_description
            taxonomy_entries = _snapshot_entries(threat)
        entry = {"bom-ref": self.refs.fixed(key), "name": name}
        if description:
            entry["description"] = description
        categories, properties = _categories_and_properties(taxonomy_entries)
        if categories:
            entry["categories"] = categories
        if properties:
            entry["properties"] = properties
        return entry

    def finish(self) -> list[dict]:
        """The abstract threats, with ``origin`` where every scenario agrees."""
        result = []
        for key, entry in self.entries.items():
            sets = self.source_sets.get(key, [])
            if sets and all(s == sets[0] for s in sets) and len(sets[0]) == 1:
                slug = next(iter(sets[0]))
                entry["origin"] = (
                    slug
                    if slug in THREAT_ORIGINS
                    else custom_type(self.source_names[slug])
                )
            if self.mitigations.get(key):
                entry["mitigations"] = list(self.mitigations[key])
            if self.objectives.get(key):
                entry["relatedBusinessObjectives"] = list(self.objectives[key])
            result.append(entry)
        return result


def _archetype(persona) -> str:
    symbolic = (persona.symbolic_name or "").lower()
    for candidate in PERSONA_ARCHETYPES:
        if candidate in symbolic:
            return candidate
    if "insider" in symbolic:
        return "insider-threat"
    if persona.malicious_intent:
        return ATTACKER_ARCHETYPES[0]
    return "end-user"


class ActorIndex:
    """The ``actors[]`` entries of the first blueprint, one per actor in use."""

    def __init__(self, refs: RefRegistry):
        self.refs = refs
        self.entries: list[dict] = []
        self._persona_refs: dict[int, str] = {}
        self._text_refs: dict[str, str] = {}

    def persona_ref(self, persona) -> str:
        ref = self._persona_refs.get(persona.pk)
        if ref is not None:
            return ref
        ref = self.refs.ref("actor-persona", persona)
        stored_party = _cyclonedx_metadata(persona).get("party_bom_ref")
        party_ref = self.refs.fixed(
            stored_party
            if isinstance(stored_party, str) and stored_party
            else f"party-persona-{persona.pk}"
        )
        party = {
            "bom-ref": party_ref,
            "roles": [{"role": "attacker"}],
            "persona": {"archetype": _archetype(persona)},
            "properties": self._persona_properties(persona),
        }
        if persona.description:
            party["persona"]["description"] = persona.description
        self.entries.append({"bom-ref": ref, "party": party})
        self._persona_refs[persona.pk] = ref
        return ref

    @staticmethod
    def _persona_properties(persona) -> list[dict]:
        owner = PropertyOwner.PERSONA_PARTY
        properties = [
            make_property("precogly:persona-name", owner, persona.name),
            make_property(
                "precogly:persona-symbolic-name", owner, persona.symbolic_name
            ),
            make_property("precogly:persona-is-person", owner, persona.is_person),
            make_property(
                "precogly:persona-malicious-intent", owner, persona.malicious_intent
            ),
        ]
        for field, name in (
            ("skill_level", "precogly:persona-skill-level"),
            ("motivation", "precogly:persona-motivation"),
            ("resources", "precogly:persona-resources"),
            ("objectives", "precogly:persona-objectives"),
        ):
            value = getattr(persona, field)
            if value:
                properties.append(make_property(name, owner, value))
        return properties

    def text_ref(self, text: str) -> str:
        ref = self._text_refs.get(text)
        if ref is not None:
            return ref
        slug = slugify(text)[:60] or "actor"
        ref = self.refs.fixed(f"actor-text-{slug}")
        party_ref = self.refs.fixed(f"party-text-{slug}")
        self.entries.append(
            {
                "bom-ref": ref,
                "party": {
                    "bom-ref": party_ref,
                    "roles": [{"role": "attacker"}],
                    "persona": {"description": text, "archetype": "attacker"},
                },
                "properties": [
                    make_property("precogly:actor-text", PropertyOwner.ACTOR, text)
                ],
            }
        )
        self._text_refs[text] = ref
        return ref


def _target_refs(threat, refs: RefRegistry) -> list[str]:
    result = []
    for row in threat.targets.all():
        kind = row.target_kind
        target = row.target
        if target is None:
            continue
        if kind == "component":
            result.append(component_ref(target, refs))
        else:
            result.append(refs.ref(kind, target))
    return result


def _scenario_properties(threat) -> list[dict]:
    owner = PropertyOwner.SCENARIO
    properties = [
        make_property("precogly:number", owner, threat.number),
        make_property("precogly:threat-status", owner, threat.status),
        make_property("precogly:triage-status", owner, threat.triage_status),
    ]
    if threat.decision_rationale:
        properties.append(
            make_property(
                "precogly:decision-rationale", owner, threat.decision_rationale
            )
        )
    if threat.impact_description and not threat.rating.impact_level:
        # With an impact level the description rides on ``impact.description``.
        properties.append(
            make_property(
                "precogly:impact-description", owner, threat.impact_description
            )
        )
    if threat.auto_generated:
        properties.append(make_property("precogly:auto-generated", owner, True))
    instance_entries = _instance_entries(threat)
    if instance_entries:
        properties.append(
            make_property("precogly:instance-categories", owner, instance_entries)
        )
    sources = [link.source.slug for link in threat.source_links.all()]
    if sources:
        properties.append(make_property("precogly:threat-sources", owner, sources))
    split_from = _cyclonedx_metadata(threat).get("split_from")
    if isinstance(split_from, str) and split_from:
        properties.append(make_property("precogly:split-from", owner, split_from))
    return properties


def _objective_property(threat, refs):
    objective_refs = [
        refs.ref("objective", link.business_objective)
        for link in threat.business_objective_links.all()
    ]
    if not objective_refs:
        return None
    return make_property(
        "precogly:business-objectives", PropertyOwner.SCENARIO, objective_refs
    )


def _scenario(
    threat,
    refs: RefRegistry,
    abstract: AbstractThreatIndex,
    actors: ActorIndex,
    system_ref: str,
) -> dict:
    entry = {
        "bom-ref": refs.ref("scenario", threat),
        "name": threat_display_name(threat),
        "threats": [abstract.ref_for(threat)],
    }
    description = threat.threat_description or (
        threat.threat_library.description if threat.threat_library_id else ""
    )
    if description:
        entry["description"] = description

    affected = [system_ref] if threat.whole_system else _target_refs(threat, refs)
    # Refs that arrived on import and point at things we could not target
    # (H11). They are re-emitted only while they resolve in this document;
    # passthrough sections, where most of them live, land at step 14.
    for extra in _cyclonedx_metadata(threat).get("extra_affected_assets") or []:
        if (
            isinstance(extra, str)
            and refs.will_resolve(extra)
            and extra not in affected
        ):
            affected.append(extra)
    if affected:
        entry["affectedAssets"] = affected

    if threat.actor_persona_id:
        entry["actor"] = actors.persona_ref(threat.actor_persona)
    elif threat.threat_actor_text:
        entry["actor"] = actors.text_ref(threat.threat_actor_text)
    if threat.intent:
        entry["intent"] = threat.intent
    if threat.access_level:
        entry["accessLevel"] = threat.access_level
    rated = scenario_rating(threat.rating)
    if threat.impact_description and "impact" in rated:
        rated["impact"]["description"] = threat.impact_description
    entry.update(rated)
    entry["properties"] = _scenario_properties(threat)
    objective_property = _objective_property(threat, refs)
    if objective_property is not None:
        entry["properties"].append(objective_property)
    return entry


def threats_queryset(threat_model):
    return (
        threat_model.threats.select_related("threat_library", "actor_persona", "rating")
        .prefetch_related(
            "threat_library__taxonomy_entries__taxonomy_entry__taxonomy",
            "instance_taxonomy_links__taxonomy_entry__taxonomy",
            "source_links__source",
            "targets__component__component_library",
            "targets__flow",
            "targets__zone",
            "targets__boundary",
            "countermeasure_links__countermeasure",
            "business_objective_links__business_objective",
        )
        .order_by("number")
    )


def reserve_threat_refs(threat_model, refs: RefRegistry) -> None:
    refs.reserve_stored(threat_model.threats.all())
    refs.reserve_stored(threat_model.threat_personas.all())


def export_threats(threat_model, refs: RefRegistry, *, system_ref: str):
    """``(threats section or None, actors for the first blueprint)``."""
    abstract = AbstractThreatIndex(refs)
    actors = ActorIndex(refs)
    scenarios = [
        _scenario(threat, refs, abstract, actors, system_ref)
        for threat in threats_queryset(threat_model)
    ]
    # Personas nobody cites still travel: they are part of the model.
    for persona in threat_model.threat_personas.order_by("id"):
        actors.persona_ref(persona)
    if not scenarios and not actors.entries:
        return None, []
    section = {}
    threats = abstract.finish()
    if threats:
        section["threats"] = threats
    if scenarios:
        section["scenarios"] = scenarios
    return (section or None), actors.entries
