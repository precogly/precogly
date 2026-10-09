"""Canvas JSON normalisation.

React Flow canvas JSON reaches the backend by two paths that disagree about
key casing. The API path arrives in snake_case, because the camelCase parser
converts request bodies. The pack path copies template YAML straight into
``DFDTemplatesLibrary.canvas_data`` and from there into ``DFD.canvas_data`` in
the seed command, and template YAML is written in camelCase (``parentId``,
``actorType``, ``zoneType``). DFD sync reads snake_case only, so a seeded
canvas silently lost its zone membership and actor types.

``normalize_canvas`` makes one shape of the two. It runs at the start of DFD
sync, when templates are loaded, when a template is served resolved, and in
the seed, so every reader sees snake_case keys. It is idempotent on canvases
that are already snake_case.

It also fills the defaults for missing type keys (``zone_type``,
``boundary_type``, ``flow_type``), so every canvas, template and AI output
loads without a rewrite. A component's ``kind`` has no canvas default: blank
derives from the category on the row.
"""

import re

_CAMEL_BOUNDARY = re.compile(r"(?<!^)(?<![A-Z_])(?=[A-Z])")

# Keys whose values are free-form JSON written by the user, where keys inside
# the value are data, not field names. Left untouched.
_OPAQUE_VALUE_KEYS = frozenset({"style", "position", "measured"})


def to_snake_case(name: str) -> str:
    """``parentId`` to ``parent_id``; ``zoneType`` to ``zone_type``.

    Already snake_case names come back unchanged. Consecutive capitals stay
    together (``dataURL`` to ``data_url`` is not attempted; no canvas key has
    them).
    """
    if "_" in name or name.islower():
        return name
    return _CAMEL_BOUNDARY.sub("_", name).lower()


def _normalize_mapping(mapping: dict) -> dict:
    normalized = {}
    for key, value in mapping.items():
        new_key = to_snake_case(key) if isinstance(key, str) else key
        if new_key in _OPAQUE_VALUE_KEYS:
            normalized[new_key] = value
        else:
            normalized[new_key] = _normalize_value(value)
    return normalized


def _normalize_value(value):
    if isinstance(value, dict):
        return _normalize_mapping(value)
    if isinstance(value, list):
        return [_normalize_value(item) for item in value]
    return value


def normalize_canvas(canvas_data: dict | None) -> dict:
    """Return a copy of ``canvas_data`` with every key in snake_case.

    Node and edge ``type`` values (``trustZone``, ``dataFlow``) are values,
    not keys, and are not touched: they are renderer keys the frontend owns.
    ``None`` or an empty canvas gives an empty dict with ``nodes`` and ``edges``
    lists, which is what every reader expects.
    """
    if not canvas_data:
        return {"nodes": [], "edges": []}
    normalized = _normalize_mapping(canvas_data)
    normalized.setdefault("nodes", [])
    normalized.setdefault("edges", [])
    _fill_type_defaults(normalized)
    return normalized


# Type keys every canvas, template and AI output gets when missing, so
# readers never see an absent type (plan sections 4.5 and 5.6).
NODE_TYPE_DEFAULTS = {"trustZone": {"zone_type": "trust"}}
EDGE_TYPE_DEFAULTS = {
    "trustBoundary": {"boundary_type": "trust"},
    "dataFlow": {"flow_type": "data"},
}


def _fill_type_defaults(canvas: dict) -> None:
    for node in canvas.get("nodes", []):
        defaults = (
            NODE_TYPE_DEFAULTS.get(node.get("type")) if isinstance(node, dict) else None
        )
        if defaults:
            data = node.setdefault("data", {})
            for key, value in defaults.items():
                if not data.get(key):
                    data[key] = value
    for edge in canvas.get("edges", []):
        defaults = (
            EDGE_TYPE_DEFAULTS.get(edge.get("type")) if isinstance(edge, dict) else None
        )
        if defaults:
            data = edge.setdefault("data", {})
            for key, value in defaults.items():
                if not data.get(key):
                    data[key] = value
