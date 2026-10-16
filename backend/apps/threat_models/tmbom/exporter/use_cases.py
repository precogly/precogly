"""Use cases: ``definitions.useCases[]`` from ``UseCase`` rows.

``flow_data`` is JSON written by import, so every entry is checked against
what the schema requires before it is emitted; steps use ``number``, never
``ordinal`` (#584 section 1). The use case's own lists are ``uniqueItems``,
so repeated entries are written once (an alternative flow's ``steps`` is not).
"""

from ..passthrough import collect_refs
from ..properties import PropertyOwner, make_property
from ..refs import RefRegistry
from .blueprint import component_ref

LIST_KEYS = (
    ("preconditions", "preconditions"),
    ("postconditions", "postconditions"),
    ("success_criteria", "successCriteria"),
    ("notes", "notes"),
)


def _unique(items: list) -> list:
    """``items`` with repeats removed, first occurrence kept."""
    unique_items = []
    for item in items:
        if item not in unique_items:
            unique_items.append(item)
    return unique_items


def _steps(raw) -> list[dict]:
    if not isinstance(raw, list):
        return []
    steps = []
    for index, step in enumerate(raw, start=1):
        if isinstance(step, str):
            if step:
                steps.append({"number": index, "description": step})
            continue
        if not isinstance(step, dict):
            continue
        description = step.get("description")
        if not isinstance(description, str) or not description:
            continue
        number = step.get("number", step.get("ordinal", index))
        try:
            number = int(number)
        except (TypeError, ValueError):
            number = index
        if number < 1:
            number = index
        entry = {"number": number, "description": description}
        if isinstance(step.get("actor"), str) and step["actor"]:
            entry["actor"] = step["actor"]
        steps.append(entry)
    return steps


def _named_entry(item) -> dict | None:
    """``name``, ``condition`` and ``description`` of a flow or an exception."""
    if not isinstance(item, dict):
        return None
    name = item.get("name")
    condition = item.get("condition")
    if not isinstance(name, str) or not name:
        return None
    if not isinstance(condition, str) or not condition:
        return None
    entry = {"name": name, "condition": condition}
    if isinstance(item.get("description"), str) and item["description"]:
        entry["description"] = item["description"]
    return entry


def _alternative_flows(raw) -> list[dict]:
    flows = []
    for item in raw if isinstance(raw, list) else []:
        entry = _named_entry(item)
        if entry is None:
            continue
        steps = _steps(item.get("steps"))
        if steps:
            entry["steps"] = steps
        flows.append(entry)
    return _unique(flows)


def _exceptions(raw) -> list[dict]:
    """Exceptions; ``handling`` is a single string in the schema, not steps."""
    exceptions = []
    for item in raw if isinstance(raw, list) else []:
        entry = _named_entry(item)
        if entry is None:
            continue
        handling = item.get("handling")
        if isinstance(handling, str) and handling:
            entry["handling"] = handling
        exceptions.append(entry)
    return _unique(exceptions)


def export_use_case(use_case, refs: RefRegistry) -> dict:
    entry = {"bom-ref": refs.ref("usecase", use_case), "name": use_case.name}
    if use_case.description:
        entry["description"] = use_case.description
    flow_data = use_case.flow_data or {}
    for ours, theirs in LIST_KEYS:
        raw = flow_data.get(ours)
        values = _unique(
            [v for v in raw if isinstance(v, str) and v]
            if isinstance(raw, list)
            else []
        )
        if values:
            entry[theirs] = values
    main_flow = _unique(_steps(flow_data.get("main_flow")))
    if main_flow:
        entry["mainFlow"] = main_flow
    alternative = _alternative_flows(flow_data.get("alternative_flows"))
    if alternative:
        entry["alternativeFlows"] = alternative
    exceptions = _exceptions(flow_data.get("exceptions"))
    if exceptions:
        entry["exceptions"] = exceptions

    objectives = [
        refs.ref("objective", link.business_objective)
        for link in use_case.business_objective_links.all()
    ]
    # Refs that arrived on import and point at nothing we store; written
    # back while they resolve (``drop_unresolved_refs``).
    kept = ((use_case.format_metadata or {}).get("cyclonedx") or {}).get(
        "extra_business_objectives"
    )
    objectives = _unique(
        objectives + [ref for ref in kept or [] if isinstance(ref, str)]
    )
    if objectives:
        entry["businessObjectives"] = objectives
    abuse_case_refs = [
        refs.ref("abusecase", link.abuse_case)
        for link in use_case.abuse_case_links.all()
    ]
    if abuse_case_refs:
        entry["properties"] = [
            make_property(
                "precogly:abuse-cases", PropertyOwner.USE_CASE, abuse_case_refs
            )
        ]
    return entry


def use_cases_queryset(threat_model):
    return threat_model.use_cases.order_by("display_order", "id").prefetch_related(
        "business_objective_links__business_objective",
        "abuse_case_links__abuse_case",
        "target_links__component",
        "target_links__flow",
    )


def reserve_use_case_refs(threat_model, refs: RefRegistry) -> None:
    refs.reserve_stored(threat_model.use_cases.all())
    refs.reserve_stored(threat_model.abuse_cases.all())


def export_use_cases(threat_model, refs: RefRegistry) -> list[dict]:
    return [
        export_use_case(use_case, refs) for use_case in use_cases_queryset(threat_model)
    ]


def add_use_case_links(document: dict, blueprints, threat_model, refs) -> None:
    """Each blueprint's ``useCases[]`` and each asset's ``useCases``.

    One ``{ref, assets, flows}`` entry per use case with a link in that
    blueprint. ``assets`` holds data store refs too (the schema accepts any
    ref there); only process and actor assets carry ``useCases``, since a
    ``dataStores`` entry has no such field.
    """
    by_blueprint: dict[int, dict] = {}
    for use_case in use_cases_queryset(threat_model):
        use_case_ref = refs.ref("usecase", use_case)
        for link in use_case.target_links.all():
            row = link.component or link.flow
            per_use_case = by_blueprint.setdefault(row.blueprint_id, {})
            entry = per_use_case.setdefault(
                use_case_ref, {"ref": use_case_ref, "assets": [], "flows": []}
            )
            if link.component_id:
                entry["assets"].append(component_ref(link.component, refs))
            else:
                entry["flows"].append(refs.ref("flow", link.flow))
    for blueprint, blueprint_entry in zip(
        blueprints, document.get("blueprints") or [], strict=False
    ):
        entries = []
        for entry in by_blueprint.get(blueprint.pk, {}).values():
            entries.append({key: value for key, value in entry.items() if value})
        if not entries:
            continue
        blueprint_entry["useCases"] = entries
        asset_use_cases: dict[str, list[str]] = {}
        for entry in entries:
            for asset_ref in entry.get("assets", []):
                asset_use_cases.setdefault(asset_ref, []).append(entry["ref"])
        for asset in blueprint_entry.get("assets") or []:
            use_case_refs = asset_use_cases.get(asset.get("bom-ref"))
            if use_case_refs:
                asset["useCases"] = use_case_refs


def _steps_of(entry: dict) -> list[list]:
    flows = [entry.get("mainFlow") or []]
    for alternative in entry.get("alternativeFlows") or []:
        flows.append(alternative.get("steps") or [])
    return flows


def _resolves(ref, known_refs: set) -> bool:
    return isinstance(ref, str) and (ref in known_refs or ref.startswith("urn:cdx:"))


def drop_unresolved_refs(document: dict, warnings: list) -> None:
    """Leave out kept refs that no longer resolve in ``document``.

    Use case and abuse case content written back as imported (step actors,
    an abuse case's abuser, targets, realizes and mitigations, a use case's
    business objectives) can name things deleted since, or things another
    tool's file declared and we do not keep. Run once the whole document is
    built, so every ref it holds is known.
    """
    known_refs = collect_refs(document)
    entries = [
        ("Use case", entry)
        for entry in (document.get("definitions") or {}).get("useCases") or []
    ] + [
        ("Abuse case", entry)
        for entry in (document.get("threats") or {}).get("abuseCases") or []
    ]
    for kind, entry in entries:
        for steps in _steps_of(entry):
            for step in steps:
                actor = step.get("actor")
                if actor is None or _resolves(actor, known_refs):
                    continue
                del step["actor"]
                warnings.append(
                    f"{kind} '{entry['name']}', step {step['number']}: "
                    f"dropped actor '{actor}'; it no longer resolves."
                )
        if "abuser" in entry and not _resolves(entry["abuser"], known_refs):
            warnings.append(
                f"{kind} '{entry['name']}': dropped abuser '{entry['abuser']}'; "
                "it no longer resolves."
            )
            del entry["abuser"]
        for key in ("businessObjectives", "targets", "realizes", "mitigations"):
            if key not in entry:
                continue
            kept = [ref for ref in entry[key] if _resolves(ref, known_refs)]
            for ref in entry[key]:
                if ref not in kept:
                    warnings.append(
                        f"{kind} '{entry['name']}': removed '{ref}' from {key}; "
                        "it no longer resolves."
                    )
            if kept:
                entry[key] = kept
            else:
                del entry[key]
        # A step that lost its actor can now equal another step.
        if entry.get("mainFlow"):
            entry["mainFlow"] = _unique(entry["mainFlow"])
