"""Step 2: Generate DFD canvas_data from a structured analysis."""

from __future__ import annotations

import json
import logging
import math

from apps.ai.providers.base import AIProviderError
from apps.ai.resolver import resolve_provider
from apps.ai.utils import extract_json_object

from .prompts import (
    DEFAULT_NODE_SIZES,
    GENERATE_SYSTEM_PROMPT,
    MAX_COMPONENT_LIBRARY_ENTRIES,
    NODE_TYPE_TO_CATEGORY,
    VALID_NODE_TYPES,
)

logger = logging.getLogger(__name__)

# Node types that act as containers (can have children).
_CONTAINER_TYPES = frozenset({"trustZone", "systemScope"})

# Node types that are external actors and belong outside the system scope.
_ACTOR_TYPES = frozenset({"humanActor", "systemActor"})

# Padding inside containers around the bounding box of their children.
_CONTAINER_PADDING = 40

# Gap between children when re-laid out inside a container.
_CHILD_GAP = 30

# Gap between actors placed outside the system scope.
_ACTOR_GAP = 30


def generate_dfd_from_analysis(
    *,
    analysis: dict,
    answers: list[dict],
    threat_model,
    organization,
    user=None,
) -> dict:
    """Generate ``canvas_data`` (nodes + edges) from an architecture analysis.

    Fetches the component library scoped to the threat model's connected packs,
    asks the model to produce positioned canvas data, then validates and
    resolves component references.

    Returns ``{"nodes": [...], "edges": [...]}``.
    """
    provider = resolve_provider(organization, feature="generate_dfd", user=user)

    library_lines = _build_component_library_prompt(threat_model)

    user_content = f"Architecture analysis:\n{json.dumps(analysis, indent=2)}\n\n"

    if answers:
        user_content += "User's answers to clarifying questions:\n"
        for qa in answers:
            question = qa.get("question", "")
            answer = qa.get("answer", "")
            if answer:
                user_content += f"Q: {question}\nA: {answer}\n\n"

    if library_lines:
        user_content += f"Available component library entries (use component_ref when matching):\n{library_lines}\n\n"

    user_content += "Generate the DFD canvas data JSON now."

    messages = [
        {"role": "system", "content": GENERATE_SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]

    completion = provider.complete(messages, temperature=0.2, max_tokens=16384)
    result = extract_json_object(completion.content)

    if result is None:
        logger.error(
            "[generate_dfd] Model response could not be parsed as JSON. "
            "Raw content (%d chars):\n%s",
            len(completion.content),
            completion.content[:2000],
        )
        raise AIProviderError(
            "The AI model returned a response that could not be parsed as JSON. "
            "Try again or use a different model."
        )

    nodes = result.get("nodes", [])
    edges = result.get("edges", [])

    if not isinstance(nodes, list):
        nodes = []
    if not isinstance(edges, list):
        edges = []

    nodes, edges = _validate_and_resolve(nodes, edges, threat_model)
    nodes, edges = _fix_layout(nodes, edges, analysis)

    return {"nodes": nodes, "edges": edges}


def _build_component_library_prompt(threat_model) -> str:
    """Build a compact listing of available component library entries."""
    from apps.systems.models import ComponentLibrary
    from apps.threat_models.models import ThreatModelLibraryPack

    connected_pack_ids = ThreatModelLibraryPack.objects.filter(
        threat_model=threat_model
    ).values_list("library_pack_id", flat=True)

    entries = (
        ComponentLibrary.objects.filter(source_pack_id__in=connected_pack_ids)
        .select_related("source_pack")
        .order_by("name")[:MAX_COMPONENT_LIBRARY_ENTRIES]
    )

    lines = []
    for entry in entries:
        slug = entry.qualified_slug or entry.slug
        line = f"slug={slug} | {entry.name} ({entry.category}, {entry.component_type}, {entry.provider})"
        lines.append(line)

    return "\n".join(lines)


def _validate_and_resolve(
    nodes: list[dict], edges: list[dict], threat_model
) -> tuple[list[dict], list[dict]]:
    """Post-process model output: validate types, resolve refs, drop invalid items."""
    from apps.systems.models import ComponentLibrary
    from apps.threat_models.models import ThreatModelLibraryPack

    # Build a lookup of available component library entries.
    connected_pack_ids = list(
        ThreatModelLibraryPack.objects.filter(threat_model=threat_model).values_list(
            "library_pack_id", flat=True
        )
    )

    library_by_qualified_slug: dict[str, ComponentLibrary] = {}
    library_by_slug: dict[str, ComponentLibrary] = {}

    if connected_pack_ids:
        for entry in ComponentLibrary.objects.filter(
            source_pack_id__in=connected_pack_ids
        ):
            if entry.qualified_slug:
                library_by_qualified_slug[entry.qualified_slug] = entry
            if entry.slug:
                library_by_slug[entry.slug] = entry

    valid_nodes = []
    valid_node_ids: set[str] = set()

    for node in nodes:
        if not isinstance(node, dict):
            continue

        node_type = node.get("type")
        node_id = node.get("id")

        if not node_id or not isinstance(node_id, str):
            continue

        # Drop nodes with invalid types.
        if node_type not in VALID_NODE_TYPES:
            continue

        # Ensure position exists.
        if "position" not in node or not isinstance(node.get("position"), dict):
            node["position"] = {"x": 0, "y": 0}

        # Ensure style with dimensions exists.
        if "style" not in node or not isinstance(node.get("style"), dict):
            defaults = DEFAULT_NODE_SIZES.get(node_type, {"width": 150, "height": 70})
            node["style"] = {**defaults}

        # Ensure data dict with label.
        if "data" not in node or not isinstance(node.get("data"), dict):
            node["data"] = {"label": node_id}
        elif not node["data"].get("label"):
            node["data"]["label"] = node_id

        # Resolve component_ref against the component library.
        data = node["data"]
        component_ref = data.get("component_ref")
        if component_ref and node_type in NODE_TYPE_TO_CATEGORY:
            resolved = library_by_qualified_slug.get(
                component_ref
            ) or library_by_slug.get(component_ref)
            if resolved:
                data["component_library_id"] = resolved.id
                data["component_library_name"] = resolved.name
            # Strip component_ref regardless — it served its purpose.
            data.pop("component_ref", None)

        valid_nodes.append(node)
        valid_node_ids.add(node_id)

    # Second pass: validate parentId references.
    for node in valid_nodes:
        parent_id = node.get("parentId")
        if parent_id and parent_id not in valid_node_ids:
            node.pop("parentId", None)

    # Validate edges: both source and target must reference valid nodes.
    valid_edges = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue

        edge_id = edge.get("id")
        source = edge.get("source")
        target = edge.get("target")

        if not edge_id or not source or not target:
            continue

        if source not in valid_node_ids or target not in valid_node_ids:
            continue

        # Ensure edge has type.
        if "type" not in edge:
            edge["type"] = "dataFlow"

        # Ensure edge has data dict.
        if "data" not in edge or not isinstance(edge.get("data"), dict):
            edge["data"] = {}

        valid_edges.append(edge)

    return valid_nodes, valid_edges


# ---------------------------------------------------------------------------
# Layout correction
# ---------------------------------------------------------------------------


def _fix_layout(
    nodes: list[dict], edges: list[dict], analysis: dict
) -> tuple[list[dict], list[dict]]:
    """Deterministic layout correction for LLM-generated canvas data.

    The model gets the *semantics* right (what belongs where) but struggles
    with precise coordinates. This function:

    1. Recovers orphaned nodes by matching them to trust zones via the
       analysis's component→trustZone mapping.
    2. Re-lays out children inside each container in a compact grid.
    3. Auto-sizes containers (bottom-up) to fit their children with padding.
    4. Places external actors outside the system scope.
    5. Recomputes edge handles from actual node positions.
    """
    by_id: dict[str, dict] = {n["id"]: n for n in nodes}

    # Find the system scope and trust zone nodes.
    system_scope_id = _find_system_scope(nodes)
    zone_ids = {n["id"] for n in nodes if n["type"] == "trustZone"}

    # Step 1: Orphan recovery — assign parentId to nodes that should be inside
    # a container but aren't.
    _recover_orphans(nodes, by_id, analysis, system_scope_id, zone_ids)

    # Step 2: Re-layout children inside each container (bottom-up: trust zones
    # first, then system scope).
    for zone_id in zone_ids:
        _layout_children(nodes, by_id, zone_id)

    if system_scope_id:
        # Layout trust zones inside the system scope.
        _layout_children(nodes, by_id, system_scope_id)

    # Step 3: Place actors outside the system scope (to the left).
    _place_actors_outside(nodes, by_id, system_scope_id)

    # Step 4: Recompute edge handles from actual absolute positions.
    _recompute_handles(edges, nodes, by_id)

    return nodes, edges


def _find_system_scope(nodes: list[dict]) -> str | None:
    """Return the id of the first systemScope node, or None."""
    for node in nodes:
        if node["type"] == "systemScope":
            return node["id"]
    return None


def _recover_orphans(
    nodes: list[dict],
    by_id: dict[str, dict],
    analysis: dict,
    system_scope_id: str | None,
    zone_ids: set[str],
) -> None:
    """Assign parentId to leaf nodes that lost their container reference.

    Uses the analysis's component→trustZone name mapping to match nodes to
    the trust zone node whose label best matches.
    """
    # Build component name → trustZone name from the analysis.
    component_zone_map: dict[str, str] = {}
    for comp in analysis.get("components", []):
        name = comp.get("name", "")
        zone = comp.get("trustZone", "")
        if name and zone:
            component_zone_map[name.lower()] = zone.lower()

    # Build zone label → zone id lookup.
    zone_label_to_id: dict[str, str] = {}
    for zone_id in zone_ids:
        zone_node = by_id.get(zone_id)
        if zone_node:
            label = zone_node.get("data", {}).get("label", "").lower()
            if label:
                zone_label_to_id[label] = zone_id

    for node in nodes:
        node_type = node["type"]

        # Skip containers and nodes that already have a valid parent.
        if node_type in _CONTAINER_TYPES:
            continue
        if node_type in _ACTOR_TYPES:
            # Actors should be outside — clear any parentId.
            node.pop("parentId", None)
            continue

        parent_id = node.get("parentId")
        if parent_id and parent_id in by_id:
            continue  # Already parented correctly.

        # Try to match via analysis trustZone.
        node_label = node.get("data", {}).get("label", "").lower()
        target_zone_name = component_zone_map.get(node_label, "")

        matched_zone_id = None
        if target_zone_name:
            # Exact match first, then substring.
            matched_zone_id = zone_label_to_id.get(target_zone_name)
            if not matched_zone_id:
                for zone_label, zone_id in zone_label_to_id.items():
                    if target_zone_name in zone_label or zone_label in target_zone_name:
                        matched_zone_id = zone_id
                        break

        if matched_zone_id:
            node["parentId"] = matched_zone_id
        elif zone_ids:
            # Fall back to the first trust zone.
            node["parentId"] = next(iter(zone_ids))
        elif system_scope_id:
            node["parentId"] = system_scope_id

    # Ensure trust zones are parented to the system scope.
    if system_scope_id:
        for zone_id in zone_ids:
            zone_node = by_id.get(zone_id)
            if zone_node:
                zone_node["parentId"] = system_scope_id


def _layout_children(
    nodes: list[dict], by_id: dict[str, dict], container_id: str
) -> None:
    """Re-lay out children of ``container_id`` in a compact grid and resize
    the container to fit."""
    children = [n for n in nodes if n.get("parentId") == container_id]
    if not children:
        # No children — use default size.
        container = by_id.get(container_id)
        if container:
            defaults = DEFAULT_NODE_SIZES.get(
                container["type"], {"width": 500, "height": 350}
            )
            container["style"] = {**defaults}
        return

    # Sort children: containers first (so trust zones are placed before leaf
    # nodes when inside a system scope), then by original position.
    children.sort(
        key=lambda n: (
            0 if n["type"] in _CONTAINER_TYPES else 1,
            n.get("position", {}).get("y", 0),
            n.get("position", {}).get("x", 0),
        )
    )

    # Compute child sizes.
    child_sizes = []
    for child in children:
        style = child.get("style", {})
        child_sizes.append(
            {
                "w": style.get(
                    "width", DEFAULT_NODE_SIZES.get(child["type"], {}).get("width", 150)
                ),
                "h": style.get(
                    "height",
                    DEFAULT_NODE_SIZES.get(child["type"], {}).get("height", 70),
                ),
            }
        )

    # Determine grid columns based on number of children.
    num_children = len(children)
    if num_children <= 3:
        cols = num_children
    elif num_children <= 8:
        cols = 3
    else:
        cols = math.ceil(math.sqrt(num_children))

    # Place children in grid rows, each row packed by actual child widths.
    cursor_x = _CONTAINER_PADDING
    cursor_y = _CONTAINER_PADDING + 30  # Extra 30px for the container label.
    row_max_height = 0
    max_row_right = 0

    for i, (child, size) in enumerate(zip(children, child_sizes, strict=True)):
        col_index = i % cols
        if col_index == 0 and i > 0:
            # New row.
            cursor_x = _CONTAINER_PADDING
            cursor_y += row_max_height + _CHILD_GAP
            row_max_height = 0

        child["position"] = {"x": cursor_x, "y": cursor_y}
        right_edge = cursor_x + size["w"]
        if right_edge > max_row_right:
            max_row_right = right_edge

        cursor_x += size["w"] + _CHILD_GAP
        if size["h"] > row_max_height:
            row_max_height = size["h"]

    # Size the container to enclose all children.
    total_width = max_row_right + _CONTAINER_PADDING
    total_height = cursor_y + row_max_height + _CONTAINER_PADDING

    # Enforce minimums.
    container = by_id.get(container_id)
    if container:
        min_sizes = DEFAULT_NODE_SIZES.get(
            container["type"], {"width": 400, "height": 300}
        )
        container["style"] = {
            "width": max(total_width, min_sizes["width"]),
            "height": max(total_height, min_sizes["height"]),
        }


def _place_actors_outside(
    nodes: list[dict], by_id: dict[str, dict], system_scope_id: str | None
) -> None:
    """Position external actors to the left of the system scope."""
    actors = [n for n in nodes if n["type"] in _ACTOR_TYPES]
    if not actors:
        return

    # Determine the left edge of the system scope for reference.
    scope_x = 0
    if system_scope_id:
        scope_node = by_id.get(system_scope_id)
        if scope_node:
            scope_x = scope_node.get("position", {}).get("x", 0)

    # Stack actors vertically to the left of the system scope.
    actor_x = scope_x - 180
    actor_y = 20

    for actor in actors:
        actor.pop("parentId", None)
        size = DEFAULT_NODE_SIZES.get(actor["type"], {"width": 100, "height": 100})
        actor["position"] = {"x": actor_x, "y": actor_y}
        actor["style"] = {**size}
        actor_y += size["height"] + _ACTOR_GAP


def _get_absolute_position(node: dict, by_id: dict[str, dict]) -> tuple[float, float]:
    """Compute a node's absolute position by walking the parent chain."""
    abs_x = node.get("position", {}).get("x", 0)
    abs_y = node.get("position", {}).get("y", 0)

    parent_id = node.get("parentId")
    visited: set[str] = set()
    while parent_id and parent_id not in visited:
        visited.add(parent_id)
        parent = by_id.get(parent_id)
        if not parent:
            break
        abs_x += parent.get("position", {}).get("x", 0)
        abs_y += parent.get("position", {}).get("y", 0)
        parent_id = parent.get("parentId")

    return abs_x, abs_y


def _get_node_center(node: dict, by_id: dict[str, dict]) -> tuple[float, float]:
    """Compute the absolute center point of a node."""
    abs_x, abs_y = _get_absolute_position(node, by_id)
    style = node.get("style", {})
    default_size = DEFAULT_NODE_SIZES.get(node["type"], {"width": 150, "height": 70})
    w = style.get("width", default_size["width"])
    h = style.get("height", default_size["height"])
    return abs_x + w / 2, abs_y + h / 2


def _recompute_handles(
    edges: list[dict], nodes: list[dict], by_id: dict[str, dict]
) -> None:
    """Set sourceHandle/targetHandle based on actual relative positions."""
    for edge in edges:
        source_node = by_id.get(edge.get("source", ""))
        target_node = by_id.get(edge.get("target", ""))
        if not source_node or not target_node:
            continue

        src_cx, src_cy = _get_node_center(source_node, by_id)
        tgt_cx, tgt_cy = _get_node_center(target_node, by_id)

        dx = tgt_cx - src_cx
        dy = tgt_cy - src_cy

        # Choose primary axis based on which delta is larger.
        if abs(dx) >= abs(dy):
            if dx >= 0:
                edge["sourceHandle"] = "right-source"
                edge["targetHandle"] = "left-target"
            else:
                edge["sourceHandle"] = "left-source"
                edge["targetHandle"] = "right-target"
        else:
            if dy >= 0:
                edge["sourceHandle"] = "bottom-source"
                edge["targetHandle"] = "top-target"
            else:
                edge["sourceHandle"] = "top-source"
                edge["targetHandle"] = "bottom-target"
