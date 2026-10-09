"""A primary DFD for an imported blueprint that has no canvas (section 9.8).

Zones are laid out as nested containers sized by their children, components
in a grid per zone (and a grid outside any zone), flows as ``dataFlow`` edges
and boundaries as ``trustBoundary`` edges. Every node and edge carries its
row id and every field on sync's list, so the first save updates rows and
clears nothing (M5, N1). Fields with no control are not on the canvas.
Mirrors the guest editor's ``deserializeFromStructure``. Fixes #288.
"""

from apps.systems.crossing import CANVAS_SESSION_KEYS

NODE_WIDTH = 180
NODE_HEIGHT = 80
GAP = 40
PADDING = 60
COLUMNS = 3

NODE_TYPE_BY_CATEGORY = {
    "process": "process",
    "datastore": "datastore",
    "external_human_actor": "humanActor",
    "external_system_actor": "systemActor",
}


def _component_node(component, parent_id=None) -> dict:
    data = {
        "label": component.name,
        "component_id": component.id,
        "description": component.description,
        "kind": component.kind,
    }
    if component.component_library_id:
        data["component_library_id"] = component.component_library_id
    node_type = (
        "systemScope"
        if component.kind in ("system", "subsystem")
        else NODE_TYPE_BY_CATEGORY.get(component.category or "", "process")
    )
    # The same keys the editor writes, so a sync of this canvas changes nothing.
    if component.actor_type:
        key = "system_type" if node_type == "systemActor" else "actor_type"
        data[key] = component.actor_type
    if component.data_store_type:
        data["data_store_type"] = component.data_store_type
    if component.data_sensitivity_level:
        data["data_sensitivity"] = component.data_sensitivity_level
    node = {
        "id": f"n-{component.id}",
        "type": node_type,
        "position": {"x": 0, "y": 0},
        "data": data,
    }
    if parent_id:
        node["parent_id"] = parent_id
    return node


def _grid(count: int) -> tuple[int, int]:
    columns = min(COLUMNS, max(count, 1))
    rows = -(-count // columns) if count else 0
    return columns, rows


def _place(nodes: list[dict], origin_x: int, origin_y: int) -> tuple[int, int]:
    """Lay ``nodes`` in a grid from the origin; returns the box size used."""
    columns, rows = _grid(len(nodes))
    for index, node in enumerate(nodes):
        column, row = index % columns, index // columns
        node["position"] = {
            "x": origin_x + column * (NODE_WIDTH + GAP),
            "y": origin_y + row * (NODE_HEIGHT + GAP),
        }
    width = columns * NODE_WIDTH + max(columns - 1, 0) * GAP
    height = rows * NODE_HEIGHT + max(rows - 1, 0) * GAP
    return width, height


def build_canvas(blueprint) -> dict:
    components = list(
        blueprint.components.select_related("component_library").order_by("id")
    )
    zones = list(blueprint.zones.order_by("id"))
    flows = list(blueprint.flows.order_by("id"))
    boundaries = list(blueprint.boundaries.order_by("id"))

    zone_node_id = {zone.id: f"z-{zone.id}" for zone in zones}
    nodes: list[dict] = []
    zone_nodes: dict[int, dict] = {}
    for zone in zones:
        data = {
            "label": zone.name,
            "trust_zone_id": zone.id,
            "zone_type": zone.zone_type,
            "description": zone.description,
        }
        if zone.trust_level is not None:
            data["trust_level"] = zone.trust_level
        node = {
            "id": zone_node_id[zone.id],
            "type": "trustZone",
            "position": {"x": 0, "y": 0},
            "data": data,
        }
        if zone.parent_id and zone.parent_id in zone_node_id:
            node["parent_id"] = zone_node_id[zone.parent_id]
        zone_nodes[zone.id] = node
        nodes.append(node)

    by_zone: dict[int | None, list[dict]] = {}
    for component in components:
        parent = zone_node_id.get(component.zone_id) if component.zone_id else None
        node = _component_node(component, parent)
        by_zone.setdefault(component.zone_id if parent else None, []).append(node)
        nodes.append(node)

    # Size each zone from the bottom of the tree up: children first.
    def depth(zone):
        level, current = 0, zone
        while current.parent_id:
            level += 1
            current = next(z for z in zones if z.id == current.parent_id)
        return level

    sizes: dict[int, tuple[int, int]] = {}
    for zone in sorted(zones, key=depth, reverse=True):
        inner = by_zone.get(zone.id, [])
        width, height = _place(inner, PADDING, PADDING)
        child_zones = [z for z in zones if z.parent_id == zone.id]
        cursor_y = PADDING + height + (GAP if inner else 0)
        for child in child_zones:
            child_width, child_height = sizes[child.id]
            zone_nodes[child.id]["position"] = {"x": PADDING, "y": cursor_y}
            width = max(width, child_width)
            cursor_y += child_height + GAP
        total_height = max(
            cursor_y - (GAP if child_zones else 0), PADDING + NODE_HEIGHT
        )
        sizes[zone.id] = (width + 2 * PADDING, total_height + PADDING)
        zone_nodes[zone.id]["style"] = {
            "width": sizes[zone.id][0],
            "height": sizes[zone.id][1],
        }

    # Top-level zones side by side, then the loose components below them.
    cursor_x = 0
    tallest = 0
    for zone in zones:
        if zone.parent_id:
            continue
        zone_nodes[zone.id]["position"] = {"x": cursor_x, "y": 0}
        width, height = sizes[zone.id]
        cursor_x += width + GAP
        tallest = max(tallest, height)
    _place(by_zone.get(None, []), 0, tallest + GAP if zones else 0)

    component_node_id = {component.id: f"n-{component.id}" for component in components}
    edges = []
    for flow in flows:
        data = {
            "label": flow.label,
            "dataflow_id": flow.id,
            "flow_type": flow.flow_type,
            "description": flow.description,
            "has_sensitive_data": flow.has_sensitive_data,
            "data_classification": list(flow.data_classification or []),
            "authentication": list(flow.authentication or []),
        }
        if flow.is_data_like:
            data["protocol"] = flow.protocol
            data["encrypted"] = flow.encrypted
            if flow.port is not None:
                data["port"] = flow.port
        edges.append(
            {
                "id": f"e-{flow.id}",
                "type": "dataFlow",
                "source": component_node_id[flow.source_component_id],
                "target": component_node_id[flow.dest_component_id],
                "data": data,
            }
        )
    for boundary in boundaries:
        data = {
            "label": boundary.label,
            "trust_boundary_id": boundary.id,
            "boundary_type": boundary.boundary_type,
            "authentication_methods": list(boundary.authentication or []),
            "access_control_methods": list(boundary.authorization or []),
            "data_validation": boundary.data_validation,
            "logging": boundary.logging,
            "monitoring": boundary.monitoring,
            "rate_limit": boundary.rate_limit,
        }
        for canvas_key, spec_key in CANVAS_SESSION_KEYS.items():
            if spec_key in (boundary.session_management or {}):
                data[canvas_key] = boundary.session_management[spec_key]
        edges.append(
            {
                "id": f"b-{boundary.id}",
                "type": "trustBoundary",
                "source": zone_node_id[boundary.zone_a_id],
                "target": zone_node_id[boundary.zone_b_id],
                "data": data,
            }
        )
    return {"nodes": nodes, "edges": edges}
