"""Use cases: ``definitions.useCases[]`` from ``UseCase`` rows.

``flow_data`` is JSON written by import, so every entry is checked against
what the schema requires before it is emitted; steps use ``number``, never
``ordinal`` (#584 section 1).
"""

from ..refs import RefRegistry

LIST_KEYS = (
    ("preconditions", "preconditions"),
    ("postconditions", "postconditions"),
    ("success_criteria", "successCriteria"),
    ("notes", "notes"),
)


def _steps(raw) -> list[dict]:
    steps = []
    for index, step in enumerate(raw or [], start=1):
        if isinstance(step, str):
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
        entry = {"number": number, "description": description}
        if isinstance(step.get("actor"), str) and step["actor"]:
            entry["actor"] = step["actor"]
        steps.append(entry)
    return steps


def _named_flows(raw, steps_key: str) -> list[dict]:
    flows = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        condition = item.get("condition")
        if not isinstance(name, str) or not name or not isinstance(condition, str):
            continue
        entry = {"name": name, "condition": condition}
        if isinstance(item.get("description"), str) and item["description"]:
            entry["description"] = item["description"]
        steps = _steps(item.get(steps_key) or item.get("steps"))
        if steps:
            entry[steps_key] = steps
        flows.append(entry)
    return flows


def export_use_case(use_case, refs: RefRegistry) -> dict:
    entry = {"bom-ref": refs.ref("usecase", use_case), "name": use_case.name}
    if use_case.description:
        entry["description"] = use_case.description
    flow_data = use_case.flow_data or {}
    for ours, theirs in LIST_KEYS:
        values = [v for v in (flow_data.get(ours) or []) if isinstance(v, str)]
        if values:
            entry[theirs] = values
    main_flow = _steps(flow_data.get("main_flow"))
    if main_flow:
        entry["mainFlow"] = main_flow
    alternative = _named_flows(flow_data.get("alternative_flows"), "steps")
    if alternative:
        entry["alternativeFlows"] = alternative
    exceptions = _named_flows(flow_data.get("exceptions"), "handling")
    if exceptions:
        entry["exceptions"] = exceptions
    return entry


def export_use_cases(threat_model, refs: RefRegistry) -> list[dict]:
    use_cases = list(threat_model.use_cases.order_by("id"))
    refs.reserve_stored(use_cases)
    return [export_use_case(use_case, refs) for use_case in use_cases]
