"""Grounded threat suggestions for a component instance.

The design goal is trust. A security tool that confidently invents a fake
threat is worse than one with no AI at all, so we never let the model produce
free-form findings. Instead we:

1. Gather the *real* library threats already associated with the component's
   type (the same candidate pool the deterministic ``generate_threats`` action
   draws from), minus any the component already has.
2. Ask the model only to *select* the most relevant of those and explain why
   each applies to this component — a ranking-and-rationale task, not invention.
3. Discard any suggestion whose id is not in the candidate pool.

Step 3 is the guarantee: even a hallucinating or adversarial local model cannot
introduce a threat that isn't grounded in an installed pack. The output is a
list of *candidates* — nothing is persisted. The user reviews and accepts each
one through the normal create path.
"""

from __future__ import annotations

from django.db.models import Q

from apps.ai import resolve_provider_for_component
from apps.ai.utils import extract_json_object
from apps.threat_models.models import ThreatModelLibraryPack
from apps.threats.models import ComponentLibraryThreat, InstanceThreat, Rating

# Keep the prompt and the validation honest about which severities exist.
VALID_SEVERITIES = {choice.value for choice in Rating.Level}

# A single model call is bounded by how many candidates we hand it. Real packs
# rarely associate more than a few dozen threats with one component type, but we
# cap the set so an unusually large pack can't blow the context window or stall
# a small local model.
# TODO: Is there a smarter way to do this? Or is a hard-coded hard limit enough?
MAX_CANDIDATES = 40


def candidate_library_threats(component):
    """Library threats applicable to ``component`` that it doesn't already have.

    Mirrors the candidate selection in
    ``apps.threats.services.generate_threats_for_component`` (component- or
    both-scoped threats, filtered to the threat model's connected packs) so the
    AI suggests from exactly the pool the deterministic generator would use.
    Threats already present on the component are excluded — we suggest gaps, not
    duplicates.
    """
    if not component.component_library_id:
        return ComponentLibraryThreat.objects.none()

    library_threats = ComponentLibraryThreat.objects.filter(
        component_library_id=component.component_library_id,
        applies_to__in=[
            ComponentLibraryThreat.AppliesTo.COMPONENT,
            ComponentLibraryThreat.AppliesTo.BOTH,
        ],
    ).select_related("threat_library", "threat_library__source_pack")

    # Restrict to packs connected to this threat model; always allow custom or
    # legacy threats (no source pack) through, matching the generator.
    if component.blueprint_id:
        connected_pack_ids = ThreatModelLibraryPack.objects.filter(
            threat_model_id=component.blueprint.threat_model_id
        ).values_list("library_pack_id", flat=True)
        library_threats = library_threats.filter(
            Q(threat_library__source_pack_id__in=connected_pack_ids)
            | Q(threat_library__source_pack__isnull=True)
        )

    already_present = InstanceThreat.objects.filter(
        targets__component=component
    ).values_list("threat_library_id", flat=True)

    return library_threats.exclude(threat_library_id__in=already_present)[
        :MAX_CANDIDATES
    ]


def suggest_component_threats(component, *, user=None) -> list[dict]:
    """Return ranked, grounded threat candidates for ``component``.

    Returns an empty list when there is nothing to ground on (no library type,
    or every applicable threat is already present). Raises ``AIProviderError``
    subclasses (``AIDisabledError`` when no model is configured for the
    component's organization, ``AIProviderError`` when the model is unreachable).

    ``user`` (the requester) is recorded on the usage row this call meters, so
    the org admin's report can attribute spend per person.
    """
    candidates = list(candidate_library_threats(component))
    if not candidates:
        return []

    # Index by the threat-library id we hand to the model; this is also the id
    # the create endpoint needs, so a validated suggestion maps straight to a
    # create payload with no extra lookups.
    by_id = {clt.threat_library_id: clt for clt in candidates}

    # Resolve the model for this component's organization (its own config if it
    # brought one, else the operator-wide fallback). We do this only after
    # confirming there are candidates, so a component with nothing to suggest
    # never requires AI to be configured at all.
    provider = resolve_provider_for_component(
        component, feature="suggest_threats", user=user
    )
    messages = _build_messages(component, candidates)
    completion = provider.complete(messages)
    selections = _parse_selections(completion.content)

    suggestions = []
    for selection in selections:
        threat_library_id = selection.get("id")
        # The trust boundary: silently drop anything the model invented or that
        # isn't in the candidate pool we offered.
        clt = by_id.get(threat_library_id)
        if clt is None:
            continue

        threat = clt.threat_library
        suggestions.append(
            {
                "threat_library": threat_library_id,
                "threat_name": threat.name,
                "threat_description": threat.description,
                "default_level": clt.default_level,
                # Trust the model's severity only if it's a real choice;
                # otherwise fall back to the pack's default.
                "suggested_severity": _coerce_severity(
                    selection.get("severity"), clt.default_level
                ),
                "rationale": _clean_rationale(selection.get("rationale")),
                "taxonomy": _taxonomy_tags(threat),
                # Citation back to the grounding source builds reviewer trust:
                # "suggested from <pack>" beats an unattributed assertion.
                "source": {
                    "qualified_slug": threat.qualified_slug,
                    "pack_name": (
                        threat.source_pack.name if threat.source_pack else None
                    ),
                },
            }
        )

    return suggestions


def _build_messages(component, candidates) -> list[dict[str, str]]:
    """Construct the system+user prompt grounding the model in real pack data."""
    system = (
        "You are a threat-modeling assistant for the Precogly platform. You "
        "help a security architect decide which known threats are most relevant "
        "to a specific system component. You MUST only choose from the numbered "
        "candidate threats provided — never invent new threats. Respond with a "
        "single JSON object of the form "
        '{"suggestions": [{"id": <candidate id>, "severity": '
        '"low|medium|high|critical", "rationale": "<one or two sentences on why '
        'this threat applies to THIS component>"}]}. Order suggestions from most '
        "to least relevant. Omit candidates that are not relevant rather than "
        "padding the list."
    )

    component_block = _describe_component(component)
    candidate_lines = "\n".join(_describe_candidate(clt) for clt in candidates)
    user = (
        f"Component under review:\n{component_block}\n\n"
        f"Candidate threats (choose by id):\n{candidate_lines}\n\n"
        "Return the JSON object now."
    )

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def _describe_component(component) -> str:
    """A compact, model-readable summary of the component."""
    parts = [f"name: {component.name}"]
    component_type = getattr(component, "component_type", "") or ""
    if component_type:
        parts.append(f"type: {component_type}")
    description = getattr(component, "description", "") or ""
    if description:
        parts.append(f"description: {description}")
    return "\n".join(parts)


def _describe_candidate(clt) -> str:
    """One line per candidate: id, name, default severity, taxonomy, description."""
    threat = clt.threat_library
    tags = ", ".join(_taxonomy_tags(threat))
    tag_suffix = f" [{tags}]" if tags else ""
    # Trim long descriptions so a big candidate set stays within a small model's
    # context window; the name and taxonomy carry most of the signal.
    description = (threat.description or "").strip().replace("\n", " ")
    if len(description) > 240:
        description = description[:237] + "..."
    return (
        f"- id={clt.threat_library_id} | {threat.name} "
        f"(default severity: {clt.default_level}){tag_suffix}: {description}"
    )


def _taxonomy_tags(threat) -> list[str]:
    """Compact taxonomy labels like 'STRIDE:tampering' or 'CWE-89'."""
    tags = []
    for join in threat.taxonomy_entries.select_related(
        "taxonomy_entry__taxonomy"
    ).all():
        entry = join.taxonomy_entry
        tags.append(f"{entry.taxonomy.slug}:{entry.external_id}")
    return tags


def _parse_selections(raw: str) -> list[dict]:
    """Extract the ``suggestions`` list from the model's JSON reply.

    Tolerates models that wrap JSON in markdown fences or add prose around it by
    locating the outermost JSON object. Returns an empty list on anything we
    can't parse — a malformed reply should yield no suggestions, never an error
    that blocks the user.
    """
    payload = extract_json_object(raw)
    if payload is None:
        return []
    suggestions = payload.get("suggestions")
    if not isinstance(suggestions, list):
        return []
    return [item for item in suggestions if isinstance(item, dict)]


def _coerce_severity(value, fallback: str) -> str:
    """Accept the model's severity only if it's a valid choice."""
    if isinstance(value, str) and value.lower() in VALID_SEVERITIES:
        return value.lower()
    return fallback


def _clean_rationale(value) -> str:
    """Normalize the model's rationale to a bounded plain string."""
    if not isinstance(value, str):
        return ""
    rationale = value.strip()
    # Keep rationales short; they're decision aids, not essays.
    if len(rationale) > 500:
        rationale = rationale[:497] + "..."
    return rationale
