"""``flow_data`` of use cases and abuse cases, checked against the schema.

One helper for the serializers and the importer. It follows the spec's
use case module: every list is ``uniqueItems``, a step needs a description
and a number from 1, a flow or an exception needs a name and a condition, and
an exception's ``handling`` is a single string. Unknown keys are kept, so an
imported step ``actor`` survives an edit.

The serializers refuse input with problems (400); the importer drops the
offending entries and turns each problem into a warning, so a stored row is
always valid and an imported one can always be edited and saved.
"""

STRING_LISTS = {
    "use_case": ("preconditions", "postconditions", "success_criteria", "notes"),
    "abuse_case": ("preconditions", "detection_opportunities"),
}
HAS_BRANCHES = {"use_case": True, "abuse_case": False}


def _text(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _unique(items: list) -> list:
    result = []
    for item in items:
        if item not in result:
            result.append(item)
    return result


def _string_list(key: str, raw, problems: list) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        problems.append(f"{key} must be a list of text.")
        return []
    values = []
    for item in raw:
        text = _text(item)
        if not text:
            problems.append(f"{key}: an entry is empty or not text.")
            continue
        values.append(text)
    return _unique(values)


def _steps(where: str, raw, problems: list) -> list[dict]:
    """Steps renumbered 1..n; a step without a description is dropped."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        problems.append(f"{where} must be a list of steps.")
        return []
    steps = []
    for position, item in enumerate(raw, start=1):
        if isinstance(item, str):
            item = {"description": item}
        if not isinstance(item, dict):
            problems.append(f"{where}, step {position}: not a step.")
            continue
        description = _text(item.get("description"))
        if not description:
            problems.append(f"{where}, step {position}: a description is required.")
            continue
        step = {key: value for key, value in item.items() if key != "number"}
        step["description"] = description
        if step not in steps:
            steps.append(step)
    return [{"number": index, **step} for index, step in enumerate(steps, start=1)]


def _named(where: str, raw, problems: list, *, is_exception: bool) -> list[dict]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        problems.append(f"{where} must be a list.")
        return []
    entries = []
    for position, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            problems.append(f"{where} {position}: not an object.")
            continue
        name = _text(item.get("name"))
        condition = _text(item.get("condition"))
        label = f"{where} {position}" + (f" '{name}'" if name else "")
        if not name:
            problems.append(f"{label}: a name is required.")
            continue
        if not condition:
            problems.append(f"{label}: a condition is required.")
            continue
        entry = dict(item)
        entry["name"] = name
        entry["condition"] = condition
        if "description" in entry and not _text(entry["description"]):
            entry.pop("description")
        if is_exception:
            handling = entry.get("handling")
            if handling is not None and not isinstance(handling, str):
                problems.append(f"{label}: handling must be text.")
                entry.pop("handling")
            elif isinstance(handling, str) and not handling.strip():
                entry.pop("handling")
        else:
            steps = _steps(f"{label}, steps", item.get("steps"), problems)
            if steps:
                entry["steps"] = steps
            else:
                entry.pop("steps", None)
        if entry not in entries:
            entries.append(entry)
    return entries


def normalize_flow_data(data, kind: str = "use_case") -> tuple[dict, list[str]]:
    """``(normalized flow_data, problems)`` for a use case or an abuse case."""
    problems: list[str] = []
    if data is None:
        return {}, problems
    if not isinstance(data, dict):
        return {}, ["flow_data must be an object."]
    result = {}
    handled = set(STRING_LISTS[kind]) | {"main_flow"}
    for key in STRING_LISTS[kind]:
        values = _string_list(key, data.get(key), problems)
        if values:
            result[key] = values
    main_flow = _steps("main_flow", data.get("main_flow"), problems)
    if main_flow:
        result["main_flow"] = main_flow
    if HAS_BRANCHES[kind]:
        handled |= {"alternative_flows", "exceptions"}
        alternatives = _named(
            "alternative_flows",
            data.get("alternative_flows"),
            problems,
            is_exception=False,
        )
        if alternatives:
            result["alternative_flows"] = alternatives
        exceptions = _named(
            "exceptions", data.get("exceptions"), problems, is_exception=True
        )
        if exceptions:
            result["exceptions"] = exceptions
    for key, value in data.items():
        if key not in handled:
            result[key] = value
    return result, problems
