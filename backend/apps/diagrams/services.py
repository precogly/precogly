"""
Services for diagrams app - DFD node synchronization and threat generation.
"""

import copy

from django.db import transaction

from apps.systems.crossing import (
    ASSET_TYPES,
    BOUNDARY_TYPES,
    FLOW_TYPES,
    UNSPECIFIED,
    ZONE_TYPES,
    clean_type_list,
    is_data_like,
    session_management_from_canvas,
)
from apps.systems.models import (
    Boundary,
    ComponentLibrary,
    Flow,
    Orgsystem,
    OrgsystemComponent,
    Zone,
)
from apps.threats.models import Risk
from apps.threats.services import (
    ensure_generated_threats,
    recalculate_residual,
    remove_threats_that_stopped_applying,
    risk_ids_citing_targets,
    scope_loss_warnings,
)

from .canvas import normalize_canvas

ANALYZABLE_NODE_TYPES = ("process", "datastore", "humanActor", "systemActor")


def _row_values(row) -> dict:
    """A row's field values, to tell whether a sync changed it (R41)."""
    return {
        field.attname: copy.deepcopy(getattr(row, field.attname))
        for field in row._meta.concrete_fields
        if field.attname != "updated_at"
    }


def _save_if_changed(row, before: dict) -> None:
    """Save only when sync changed a field, so ``updated_at`` means an edit.

    Section 15: saving a DFD unchanged changes no row field.
    """
    if _row_values(row) != before:
        row.save()


def _extract_backend_ids_from_canvas(canvas_data):
    """
    Extract all backend record IDs stored in canvas_data nodes and edges.

    Returns a dict of sets:
        component_ids, dataflow_ids, zone_ids, boundary_ids
    """
    nodes = canvas_data.get("nodes", [])
    edges = canvas_data.get("edges", [])

    component_ids = set()
    zone_ids = set()
    dataflow_ids = set()
    boundary_ids = set()

    for node in nodes:
        node_data = node.get("data", {})
        node_type = node.get("type")

        if node_type in ANALYZABLE_NODE_TYPES:
            cid = node_data.get("component_id")
            if cid is not None:
                component_ids.add(cid)
        elif node_type == "trustZone":
            zid = node_data.get("trust_zone_id")
            if zid is not None:
                zone_ids.add(zid)
        elif node_type == "systemScope":
            # A scope node is a system asset: a component row (F20).
            cid = node_data.get("component_id")
            if cid is not None:
                component_ids.add(cid)

    for edge in edges:
        edge_data = edge.get("data", {})
        edge_type = edge.get("type")

        if edge_type == "dataFlow":
            did = edge_data.get("dataflow_id")
            if did is not None:
                dataflow_ids.add(did)
        elif edge_type == "trustBoundary":
            bid = edge_data.get("trust_boundary_id")
            if bid is not None:
                boundary_ids.add(bid)

    return {
        "component_ids": component_ids,
        "dataflow_ids": dataflow_ids,
        "zone_ids": zone_ids,
        "boundary_ids": boundary_ids,
    }


def _cleanup_orphaned_records(old_canvas_data, new_canvas_data, blueprint):
    """
    Delete backend records whose canvas nodes/edges were removed between saves.

    Compares old_canvas_data (before save) with new_canvas_data (after save) to
    find backend IDs that disappeared, then deletes those records. Deletion order
    respects FK constraints: boundaries -> flows -> components -> zones -> systems.
    Every delete is scoped to the blueprint: the ids come from caller-supplied
    canvas data, and an id from another blueprint must not reach its row.

    Analysis-only components (created via Threat Analysis UI, not from canvas) are
    never in canvas_data and are therefore never affected.
    """
    old_ids = _extract_backend_ids_from_canvas(old_canvas_data)
    new_ids = _extract_backend_ids_from_canvas(new_canvas_data)

    orphaned_boundary_ids = old_ids["boundary_ids"] - new_ids["boundary_ids"]
    orphaned_flow_ids = old_ids["dataflow_ids"] - new_ids["dataflow_ids"]
    orphaned_component_ids = old_ids["component_ids"] - new_ids["component_ids"]
    orphaned_zone_ids = old_ids["zone_ids"] - new_ids["zone_ids"]

    has_orphans = (
        orphaned_boundary_ids
        or orphaned_flow_ids
        or orphaned_component_ids
        or orphaned_zone_ids
    )
    if not has_orphans:
        return None

    # Controls scoped only to rows about to go keep their status and links
    # but read as "applies to the whole system" afterwards; the editor is
    # told (plan section 4.3).
    warnings = scope_loss_warnings(
        component_ids=orphaned_component_ids,
        flow_ids=orphaned_flow_ids,
        zone_ids=orphaned_zone_ids,
        boundary_ids=orphaned_boundary_ids,
    )
    deleted_counts = {"warnings": warnings}

    # 1. Boundaries (FK zone_a/zone_b -> CASCADE, delete before zones)
    if orphaned_boundary_ids:
        count, _ = Boundary.objects.filter(
            id__in=orphaned_boundary_ids, blueprint=blueprint
        ).delete()
        deleted_counts["boundaries"] = count

    # The risks citing threats on the rows about to go lose those links with the
    # cascade, so their ids are captured first and recalculated after.
    affected_risk_ids = set()
    if orphaned_flow_ids or orphaned_component_ids:
        affected_risk_ids = risk_ids_citing_targets(
            component_ids=orphaned_component_ids, flow_ids=orphaned_flow_ids
        )

    # 2. Flows (FK source/dest component -> CASCADE, delete before components)
    if orphaned_flow_ids:
        count, _ = Flow.objects.filter(
            id__in=orphaned_flow_ids, blueprint=blueprint
        ).delete()
        deleted_counts["flows"] = count

    # 3. Components (CASCADE -> targets -> the deletion rule removes scenarios
    #    that lost their only target)
    if orphaned_component_ids:
        count, _ = OrgsystemComponent.objects.filter(
            id__in=orphaned_component_ids,
            blueprint=blueprint,
        ).delete()
        deleted_counts["components"] = count

    for risk in Risk.objects.filter(id__in=affected_risk_ids).select_related(
        "inherent"
    ):
        recalculate_residual(risk)

    # 4. Zones
    if orphaned_zone_ids:
        count, _ = Zone.objects.filter(
            id__in=orphaned_zone_ids, blueprint=blueprint
        ).delete()
        deleted_counts["zones"] = count

    return deleted_counts


def _component_fields_from_node(node_type, node_data):
    """The editor-owned component fields a canvas node carries."""
    return {
        "description": node_data.get("description", ""),
        "actor_type": (
            node_data.get("actor_type", "")
            if node_type == "humanActor"
            else node_data.get("system_type", "")
            if node_type == "systemActor"
            else ""
        ),
        "data_store_type": node_data.get("data_store_type", "")
        if node_type == "datastore"
        else "",
        "data_sensitivity_level": node_data.get("data_sensitivity", "")
        if node_type in ("process", "datastore")
        else "",
    }


def _library_copy_fields(component_library):
    """Fields a component copies from its library row (M16)."""
    if component_library is None:
        return {}
    return {
        "component_type": component_library.component_type,
        "provider": component_library.provider,
        "kind": component_library.kind,
    }


def _kind_from_node(node_data, component_library):
    """The component's kind after a save (M16, N1).

    The canvas holds the user's choice: a ``kind`` on the node wins. No
    ``kind`` means the panel's "Default", which is the library's kind (none
    without a library), so clearing the choice clears it in the row (R14) and
    a technology change copies the new library's kind (R15). Generated
    canvases write ``kind`` only when it differs from the library's
    (``tmbom/dfd_layout.py``).
    """
    named = node_data.get("kind")
    if named in ASSET_TYPES:
        return named
    return component_library.kind if component_library else ""


def crosses_a_boundary(flow, boundaries, zone_parents) -> bool:
    """True when the flow's ends sit on opposite sides of a boundary (H19).

    Each end's side of a boundary between zones A and B is whichever of the
    two is nearest among the zones that enclose it. The flow crosses when one
    end is on A's side and the other on B's. With B nested in A, a flow with
    both ends inside B stays on B's side and does not cross; a flow from B to
    a component placed directly in A does (R16).
    """

    def enclosing(zone_id):
        chain = []
        while zone_id is not None and zone_id not in chain:
            chain.append(zone_id)
            zone_id = zone_parents.get(zone_id)
        return chain

    def side(chain, zone_a_id, zone_b_id):
        return next(
            (zone_id for zone_id in chain if zone_id in (zone_a_id, zone_b_id)), None
        )

    source_chain = enclosing(flow.source_component.zone_id)
    dest_chain = enclosing(flow.dest_component.zone_id)
    if not source_chain or not dest_chain:
        return False
    for zone_a_id, zone_b_id in boundaries:
        source_side = side(source_chain, zone_a_id, zone_b_id)
        dest_side = side(dest_chain, zone_a_id, zone_b_id)
        if source_side and dest_side and source_side != dest_side:
            return True
    return False


def update_crosses_boundary(blueprint) -> None:
    """Recompute ``crosses_boundary`` for every flow of the blueprint."""
    boundaries = list(blueprint.boundaries.values_list("zone_a_id", "zone_b_id"))
    zone_parents = dict(blueprint.zones.values_list("id", "parent_id"))
    for flow in blueprint.flows.select_related("source_component", "dest_component"):
        crosses = crosses_a_boundary(flow, boundaries, zone_parents)
        if flow.crosses_boundary != crosses:
            Flow.objects.filter(pk=flow.pk).update(crosses_boundary=crosses)


NODE_TYPE_TO_CATEGORY = {
    "process": "process",
    "datastore": "datastore",
    "humanActor": "external_human_actor",
    "systemActor": "external_system_actor",
}


def sync_dfd_nodes_to_components(dfd, blueprint, old_canvas_data=None):
    """
    Sync DFD canvas nodes and edges to backend records.

    When a DFD is saved, this function:
    1. Cleans up orphaned records (nodes/edges removed since last save)
    2. Extracts analyzable nodes (process, datastore, humanActor, systemActor) from canvas_data
    3. Creates or updates OrgsystemComponent records for each
    4. Links to ComponentLibrary based on technology if available
    5. Stores the component_id back in the node data
    6. Generates library threats for new components and for components whose
       library changed (never on an ordinary save, plan section 4.1)
    7. Syncs edges to Flow records, generating threats for new flows and for
       flows whose ends changed (M7)

    A technology change updates the component in place (L6): it keeps its row,
    its flows, its data asset links and its edited threats, gets the new
    library's fields, and the generation rules add what now applies and drop
    the untouched generated threats that no longer do.

    Every row this creates belongs to ``blueprint``, and every canvas id it
    looks up is scoped to that blueprint, so a canvas that names another
    blueprint's row cannot read or write it.

    Args:
        dfd: The DFD instance being saved
        blueprint: The Blueprint the DFD visualises
        old_canvas_data: Canvas data from before this save (used to detect
            deleted nodes/edges and clean up orphaned backend records)
    """
    # Every reader below expects snake_case keys. A canvas copied from a pack
    # template (seed, template insert) arrives in camelCase; normalising here,
    # and writing the result back onto the DFD, means the id writers further
    # down and the next save all see one shape.
    canvas_data = normalize_canvas(dfd.canvas_data)
    dfd.canvas_data = canvas_data
    old_canvas_data = normalize_canvas(old_canvas_data) if old_canvas_data else None
    nodes = canvas_data.get("nodes", [])
    edges = canvas_data.get("edges", [])

    empty_result = {
        "synced_count": 0,
        "created_count": 0,
        "threats_generated": 0,
        "node_component_map": {},
        "flows_synced": 0,
        "flows_created": 0,
        "flow_threats_generated": 0,
        "zones_synced": 0,
        "zones_created": 0,
        "boundaries_synced": 0,
        "boundaries_created": 0,
        "warnings": [],
    }

    if not nodes:
        # Even with no nodes, we must clean up records from the old canvas
        if old_canvas_data:
            with transaction.atomic():
                cleanup = _cleanup_orphaned_records(
                    old_canvas_data, canvas_data, blueprint
                )
                empty_result["warnings"] = (cleanup or {}).get("warnings", [])
        return empty_result

    analyzable_nodes = [
        node for node in nodes if node.get("type") in ANALYZABLE_NODE_TYPES
    ]

    synced_count = 0
    created_count = 0
    threats_generated = 0
    node_component_map = {}
    # (component, library_changed): what the generation rules run on
    components_to_generate = []

    with transaction.atomic():
        # Sync trust zone nodes first (zones must exist before component assignment)
        zone_result = _sync_nodes_to_zones(dfd, nodes, blueprint)
        node_zone_map = zone_result["node_zone_map"]

        # Sync system scope nodes to system assets (components of kind system)
        node_lookup = {node.get("id"): node for node in nodes}
        system_result = _sync_scope_nodes_to_system_components(
            dfd, nodes, blueprint, node_lookup
        )
        node_system_map = system_result["node_system_map"]
        # Scope nodes nested in scope nodes: the inner one's parent is the outer.
        for node in nodes:
            if node.get("type") != "systemScope":
                continue
            parent = node_lookup.get(node.get("parent_id"))
            parent_system_id = (
                node_system_map.get(parent.get("id")) if parent is not None else None
            )
            OrgsystemComponent.objects.filter(id=node_system_map[node["id"]]).update(
                parent_component_id=parent_system_id
            )

        for node in analyzable_nodes:
            node_id = node.get("id")
            node_data = node.get("data", {})
            node_type = node.get("type")
            label = node_data.get("label", f"Unnamed {node_type}")
            category = NODE_TYPE_TO_CATEGORY.get(node_type, "process")
            fields = _component_fields_from_node(node_type, node_data)

            # Find matching ComponentLibrary - try multiple sources
            component_library = None
            component_library_id = node_data.get("component_library_id")
            if component_library_id:
                component_library = ComponentLibrary.objects.filter(
                    id=component_library_id
                ).first()
            if not component_library:
                component_ref = node_data.get("component_ref")
                if component_ref:
                    component_library = ComponentLibrary.objects.filter(
                        slug=component_ref
                    ).first()
            if not component_library:
                technology = node_data.get("technology", "")
                component_library = _find_component_library(technology, node_type)
            new_library_id = component_library.id if component_library else None

            component = None
            existing_component_id = node_data.get("component_id")
            if existing_component_id:
                component = OrgsystemComponent.objects.filter(
                    id=existing_component_id, blueprint=blueprint
                ).first()

            if component is None:
                copied = _library_copy_fields(component_library)
                copied["kind"] = _kind_from_node(node_data, component_library)
                component = OrgsystemComponent.objects.create(
                    name=label,
                    blueprint=blueprint,
                    component_library=component_library,
                    category=category,
                    **fields,
                    **copied,
                )
                created_count += 1
                synced_count += 1
                components_to_generate.append((component, False))
            else:
                before = _row_values(component)
                library_changed = component.component_library_id != new_library_id
                kind = _kind_from_node(node_data, component_library)
                component.name = label
                component.component_library = component_library
                component.category = category
                for key, value in fields.items():
                    setattr(component, key, value)
                if library_changed:
                    for key, value in _library_copy_fields(component_library).items():
                        setattr(component, key, value)
                component.kind = kind
                _save_if_changed(component, before)
                synced_count += 1
                if library_changed:
                    components_to_generate.append((component, True))

            node_component_map[node_id] = component.id

        # Update canvas_data with component_ids
        _update_canvas_with_component_ids(dfd, node_component_map)

        # Assign trust zones, system scopes, and parent components
        # by walking each node's parentId ancestry chain.
        # With process container hierarchy (D1), a node's direct parentId
        # may point to a process (not a trust zone), so we must walk up.

        for node in analyzable_nodes:
            node_id = node.get("id")
            component_id = node_component_map.get(node_id)
            if not component_id:
                continue

            parent_id = node.get("parent_id")  # React Flow parentId → snake_case

            # Walk up parentId chain to resolve trust zone, system scope,
            # and parent component in a single traversal
            zone_id = None
            system_id = None
            parent_component_db_id = None
            walk_id = parent_id
            visited = set()

            while walk_id and walk_id not in visited:
                visited.add(walk_id)

                # Check for parent component (nearest process ancestor)
                if (
                    not parent_component_db_id
                    and node.get("type") == "process"
                    and walk_id in node_component_map
                ):
                    ancestor_node = node_lookup.get(walk_id)
                    if ancestor_node and ancestor_node.get("type") == "process":
                        parent_component_db_id = node_component_map[walk_id]

                # Check for trust zone
                if not zone_id and walk_id in node_zone_map:
                    zone_id = node_zone_map[walk_id]

                # Check for system scope
                if not system_id and walk_id in node_system_map:
                    system_id = node_system_map[walk_id]

                # Stop early if all resolved
                if (
                    zone_id
                    and system_id
                    and (parent_component_db_id or node.get("type") != "process")
                ):
                    break

                ancestor_node = node_lookup.get(walk_id)
                walk_id = ancestor_node.get("parent_id") if ancestor_node else None

            # A component drawn inside a scope node gets that system asset as
            # its parent when it has no process parent (section 4.9).
            OrgsystemComponent.objects.filter(id=component_id).update(
                zone_id=zone_id,
                parent_component_id=parent_component_db_id or system_id,
            )

        # Generation runs only on its triggers: a new component, or one whose
        # library changed. An ordinary save generates nothing, so a generated
        # threat the user deleted stays deleted.
        for component, library_changed in components_to_generate:
            component.refresh_from_db()
            if library_changed:
                remove_threats_that_stopped_applying(component)
            if component.component_library_id:
                threats_generated += ensure_generated_threats(component)

        # Sync edges to Flow records and generate flow threats
        flow_result = _sync_edges_to_flows(dfd, edges, node_component_map, blueprint)

        # Sync trust boundary edges to Boundary DB records
        boundary_result = _sync_edges_to_boundaries(
            dfd, edges, node_zone_map, blueprint
        )
        update_crosses_boundary(blueprint)

        # Clean up orphaned records (nodes/edges removed since last save)
        warnings = []
        if old_canvas_data:
            cleanup = _cleanup_orphaned_records(
                old_canvas_data, dfd.canvas_data or {}, blueprint
            )
            warnings = (cleanup or {}).get("warnings", [])

    return {
        "warnings": warnings,
        "synced_count": synced_count,
        "created_count": created_count,
        "threats_generated": threats_generated,
        "node_component_map": node_component_map,
        "flows_synced": flow_result["synced_count"],
        "flows_created": flow_result["created_count"],
        "flow_threats_generated": flow_result["threats_generated"],
        "zones_synced": zone_result["synced_count"],
        "zones_created": zone_result["created_count"],
        "boundaries_synced": boundary_result["synced_count"],
        "boundaries_created": boundary_result["created_count"],
    }


def _find_component_library(technology: str, node_type: str):
    """
    Find a ComponentLibrary entry matching the technology.

    Args:
        technology: Technology string from node data (e.g., "aws-s3", "PostgreSQL")
        node_type: The node type ("process", "datastore", "humanActor", or "systemActor")

    Returns:
        ComponentLibrary instance or None
    """
    if not technology:
        return None

    node_type_to_category = {
        "process": "process",
        "datastore": "datastore",
        "humanActor": "external_human_actor",
        "systemActor": "external_system_actor",
    }
    category = node_type_to_category.get(node_type)

    base_qs = ComponentLibrary.objects.all()
    if category:
        base_qs = base_qs.filter(category=category)

    # Try exact match on slug first
    component = base_qs.filter(slug=technology).first()
    if component:
        return component

    # Try name match (case-insensitive)
    component = base_qs.filter(name__iexact=technology).first()
    if component:
        return component

    # Try partial name match
    component = base_qs.filter(name__icontains=technology).first()
    return component


def _update_canvas_with_component_ids(dfd, node_component_map):
    """Update DFD canvas_data with component_ids for synced nodes."""
    canvas_data = dfd.canvas_data or {}
    nodes = canvas_data.get("nodes", [])

    updated = False
    for node in nodes:
        node_id = node.get("id")
        if node_id in node_component_map:
            if "data" not in node:
                node["data"] = {}
            if node["data"].get("component_id") != node_component_map[node_id]:
                node["data"]["component_id"] = node_component_map[node_id]
                updated = True

    if updated:
        dfd.canvas_data = canvas_data
        dfd.save(update_fields=["canvas_data"])


def _authentication_from_edge(edge_data) -> list:
    """The flow's authentication list from the canvas.

    ``authentication`` is the list; the retired boolean ``authenticated``
    (the editor still sends it until step 15) maps to ``[unspecified]`` or an
    empty list (I9).
    """
    if "authentication" in edge_data:
        try:
            return clean_type_list(
                edge_data.get("authentication"), field="authentication"
            )
        except ValueError:
            return []
    if edge_data.get("authenticated"):
        return [UNSPECIFIED]
    return []


def _flow_fields_from_edge(edge_data) -> dict:
    flow_type = edge_data.get("flow_type") or "data"
    if flow_type not in FLOW_TYPES:
        flow_type = "data"
    data_like = is_data_like(flow_type)
    port = edge_data.get("port")
    try:
        port = int(port) if port not in (None, "") else None
    except (TypeError, ValueError):
        port = None
    return {
        "label": edge_data.get("label", ""),
        "flow_type": flow_type,
        # Protocol, port and encryption mean nothing on a signal or energy flow.
        "protocol": edge_data.get("protocol", "") if data_like else "",
        "port": port if data_like else None,
        "encrypted": bool(edge_data.get("encrypted", False)) if data_like else False,
        "authentication": _authentication_from_edge(edge_data),
        "description": edge_data.get("description", ""),
        "has_sensitive_data": edge_data.get("has_sensitive_data", False),
        "data_classification": edge_data.get("data_classification", []),
    }


def _sync_edges_to_flows(dfd, edges, node_component_map, blueprint):
    """
    Sync DFD edges to Flow records and generate threats.

    Only creates Flow records for edges where BOTH source and dest nodes have
    been synced to components. Threats are generated for new flows and for
    flows whose ends changed (M7); an ordinary save generates nothing.

    Returns:
        dict with synced_count, created_count, threats_generated
    """
    synced_count = 0
    created_count = 0
    threats_generated = 0
    flows_to_generate = []  # (flow, ends_changed)
    edge_flow_map = {}

    for edge in edges:
        # Only sync dataFlow edges — skip trust boundaries and other edge types
        if edge.get("type") != "dataFlow":
            continue

        edge_id = edge.get("id")
        source_node_id = edge.get("source")
        target_node_id = edge.get("target")
        edge_data = edge.get("data", {})

        # Skip edges where either endpoint doesn't have a component
        source_component_id = node_component_map.get(source_node_id)
        target_component_id = node_component_map.get(target_node_id)
        if not source_component_id or not target_component_id:
            continue

        fields = _flow_fields_from_edge(edge_data)

        flow = None
        existing_flow_id = edge_data.get("dataflow_id")
        if existing_flow_id:
            flow = Flow.objects.filter(id=existing_flow_id, blueprint=blueprint).first()

        if flow is None:
            flow = Flow.objects.create(
                blueprint=blueprint,
                source_component_id=source_component_id,
                dest_component_id=target_component_id,
                edge_id=edge_id,
                **fields,
            )
            created_count += 1
            synced_count += 1
            flows_to_generate.append((flow, False))
        else:
            before = _row_values(flow)
            ends_changed = (
                flow.source_component_id != source_component_id
                or flow.dest_component_id != target_component_id
                or flow.flow_type != fields["flow_type"]
            )
            for key, value in fields.items():
                setattr(flow, key, value)
            flow.source_component_id = source_component_id
            flow.dest_component_id = target_component_id
            flow.edge_id = edge_id
            _save_if_changed(flow, before)
            synced_count += 1
            if ends_changed:
                flows_to_generate.append((flow, True))

        edge_flow_map[edge_id] = flow.id

    # Update canvas_data with dataflow_ids
    _update_canvas_with_dataflow_ids(dfd, edge_flow_map)

    for flow, ends_changed in flows_to_generate:
        flow.refresh_from_db()
        if ends_changed:
            remove_threats_that_stopped_applying(flow)
        threats_generated += ensure_generated_threats(flow)

    return {
        "synced_count": synced_count,
        "created_count": created_count,
        "threats_generated": threats_generated,
    }


def _update_canvas_with_dataflow_ids(dfd, edge_dataflow_map):
    """Update DFD canvas_data with dataflow_ids for synced edges."""
    if not edge_dataflow_map:
        return

    canvas_data = dfd.canvas_data or {}
    edges = canvas_data.get("edges", [])

    updated = False
    for edge in edges:
        edge_id = edge.get("id")
        if edge_id in edge_dataflow_map:
            if "data" not in edge:
                edge["data"] = {}
            if edge["data"].get("dataflow_id") != edge_dataflow_map[edge_id]:
                edge["data"]["dataflow_id"] = edge_dataflow_map[edge_id]
                updated = True

    if updated:
        dfd.canvas_data = canvas_data
        dfd.save(update_fields=["canvas_data"])


def _sync_nodes_to_zones(dfd, nodes, blueprint):
    """Sync trust zone canvas nodes to Zone DB records."""
    zone_nodes = [node for node in nodes if node.get("type") == "trustZone"]

    synced_count = 0
    created_count = 0
    node_zone_map = {}  # canvas node_id -> Zone DB id

    # `zone_id` below is caller-supplied canvas data, so the lookup is scoped
    # to the diagram's own blueprint. Unscoped it renamed and reclassified another
    # tenant's zone — precogly/precogly#406.
    for node in zone_nodes:
        node_id = node.get("id")
        node_data = node.get("data", {})

        # snake_case — parser already converted from frontend camelCase
        label = node_data.get("label", "Unnamed Zone")
        # No value means not set (F13); no fallback level.
        trust_level = _trust_level_from_canvas(node_data.get("trust_level"))
        description = node_data.get("description", "")
        zone_type = node_data.get("zone_type") or "trust"
        if zone_type not in ZONE_TYPES:
            zone_type = "trust"
        fields = {
            "name": label,
            "zone_type": zone_type,
            "trust_level": trust_level,
            "description": description,
        }

        existing_zone_id = node_data.get("trust_zone_id")

        if existing_zone_id:
            try:
                zone = Zone.objects.get(id=existing_zone_id, blueprint=blueprint)
                before = _row_values(zone)
                for key, value in fields.items():
                    setattr(zone, key, value)
                _save_if_changed(zone, before)
                synced_count += 1
            except Zone.DoesNotExist:
                zone = Zone.objects.create(blueprint=blueprint, **fields)
                created_count += 1
        else:
            zone = Zone.objects.create(blueprint=blueprint, **fields)
            created_count += 1
            synced_count += 1

        node_zone_map[node_id] = zone.id

    # Second pass: set parent relationships for nested zones
    for node in zone_nodes:
        node_id = node.get("id")
        parent_node_id = node.get("parent_id")  # React Flow parentId → snake_case
        if parent_node_id and parent_node_id in node_zone_map:
            Zone.objects.filter(id=node_zone_map[node_id]).update(
                parent_id=node_zone_map[parent_node_id]
            )
        elif node_id in node_zone_map:
            # Clear parent if zone was un-nested on canvas
            Zone.objects.filter(id=node_zone_map[node_id]).exclude(
                parent__isnull=True
            ).update(parent=None)

    _update_canvas_with_zone_ids(dfd, node_zone_map)

    return {
        "synced_count": synced_count,
        "created_count": created_count,
        "node_zone_map": node_zone_map,
    }


def _update_canvas_with_zone_ids(dfd, node_zone_map):
    """Update DFD canvas_data with zone_ids for synced zone nodes."""
    if not node_zone_map:
        return

    canvas_data = dfd.canvas_data or {}
    nodes = canvas_data.get("nodes", [])

    updated = False
    for node in nodes:
        node_id = node.get("id")
        if node_id in node_zone_map:
            if "data" not in node:
                node["data"] = {}
            if node["data"].get("trust_zone_id") != node_zone_map[node_id]:
                node["data"]["trust_zone_id"] = node_zone_map[node_id]
                updated = True

    if updated:
        dfd.canvas_data = canvas_data
        dfd.save(update_fields=["canvas_data"])


def _sync_scope_nodes_to_system_components(dfd, nodes, blueprint, node_lookup):
    """A ``systemScope`` node is a system asset: an ``OrgsystemComponent`` with
    ``kind`` system, or subsystem when drawn inside another scope (F20). The
    panel's own choice (``kind`` of system or subsystem on the node) wins over
    the nesting rule when it is set.

    Its optional ``orgsystem_id`` links the asset to an inventory row of the
    same organization that the user picked; sync never creates or deletes
    ``Orgsystem`` rows. Returns ``{node id: component id}``.
    """
    scope_nodes = [node for node in nodes if node.get("type") == "systemScope"]
    organization_id = blueprint.threat_model.organization_id
    node_system_map = {}
    created_count = 0
    synced_count = 0
    for node in scope_nodes:
        node_id = node.get("id")
        node_data = node.get("data", {})
        parent = node_lookup.get(node.get("parent_id"))
        chosen_kind = node_data.get("kind")
        if chosen_kind in ("system", "subsystem"):
            kind = chosen_kind
        else:
            kind = (
                "subsystem"
                if parent is not None and parent.get("type") == "systemScope"
                else "system"
            )
        orgsystem = None
        orgsystem_id = node_data.get("orgsystem_id")
        if orgsystem_id:
            orgsystem = Orgsystem.objects.filter(
                id=orgsystem_id, organization_id=organization_id
            ).first()
        fields = {
            "name": node_data.get("label", "Unnamed System"),
            "description": node_data.get("description", ""),
            "category": "process",
            "kind": kind,
            "orgsystem": orgsystem,
        }
        component = None
        existing_id = node_data.get("component_id")
        if existing_id:
            component = OrgsystemComponent.objects.filter(
                id=existing_id, blueprint=blueprint
            ).first()
        if component is None:
            component = OrgsystemComponent.objects.create(blueprint=blueprint, **fields)
            created_count += 1
        else:
            before = _row_values(component)
            for key, value in fields.items():
                setattr(component, key, value)
            _save_if_changed(component, before)
        synced_count += 1
        node_system_map[node_id] = component.id
    _update_canvas_with_component_ids(dfd, node_system_map)
    return {
        "synced_count": synced_count,
        "created_count": created_count,
        "node_system_map": node_system_map,
    }


# The boundary panel's controls, stored in `format_metadata` until step 6 gives
# them real fields. Sync owns exactly these keys: it writes every one on each
# save (a key missing from the canvas means the user cleared it) and touches no
# other key, so what an import kept beside them survives (M5, N1).
def _trust_level_from_canvas(raw):
    if raw is None or raw == "":
        return None
    try:
        level = int(raw)
    except (TypeError, ValueError):
        return None
    return max(0, min(100, level))


def _boundary_fields_from_edge(edge_data, existing_session):
    """The boundary fields sync owns, read from the canvas (M5, N1).

    A missing key means cleared, which is how the editor clears a value. The
    two session timeouts, protocols and data transformation have no control
    and are left alone.
    """
    boundary_type = edge_data.get("boundary_type") or "trust"
    if boundary_type not in BOUNDARY_TYPES:
        boundary_type = "trust"
    try:
        authentication = clean_type_list(
            edge_data.get("authentication_methods"), field="authentication"
        )
    except ValueError:
        authentication = []
    try:
        authorization = clean_type_list(
            edge_data.get("access_control_methods"), field="authorization"
        )
    except ValueError:
        authorization = []
    return {
        "label": edge_data.get("label", ""),
        "boundary_type": boundary_type,
        "authentication": authentication,
        "authorization": authorization,
        "data_validation": bool(edge_data.get("data_validation", False)),
        "logging": bool(edge_data.get("logging", False)),
        "monitoring": bool(edge_data.get("monitoring", False)),
        "rate_limit": str(edge_data.get("rate_limit") or "")[:255],
        "session_management": session_management_from_canvas(
            existing_session, edge_data
        ),
    }


def _sync_edges_to_boundaries(dfd, edges, node_zone_map, blueprint):
    """Sync trust boundary edges to Boundary DB records."""
    synced_count = 0
    created_count = 0
    edge_boundary_map = {}

    # Same reason as `_sync_nodes_to_zones`: `boundary_id` arrives in the
    # canvas payload, so the lookup is scoped rather than taken on trust.
    for edge in edges:
        if edge.get("type") != "trustBoundary":
            continue

        edge_id = edge.get("id")
        source_node_id = edge.get("source")
        target_node_id = edge.get("target")
        edge_data = edge.get("data", {})

        zone_a_id = node_zone_map.get(source_node_id)
        zone_b_id = node_zone_map.get(target_node_id)
        if not zone_a_id or not zone_b_id:
            continue

        existing_boundary_id = edge_data.get("trust_boundary_id")
        boundary = None
        if existing_boundary_id:
            boundary = Boundary.objects.filter(
                id=existing_boundary_id, blueprint=blueprint
            ).first()

        if boundary is not None:
            before = _row_values(boundary)
            fields = _boundary_fields_from_edge(edge_data, boundary.session_management)
            boundary.zone_a_id = zone_a_id
            boundary.zone_b_id = zone_b_id
            boundary.edge_id = edge_id
            for key, value in fields.items():
                setattr(boundary, key, value)
            _save_if_changed(boundary, before)
            synced_count += 1
        else:
            boundary = Boundary.objects.create(
                blueprint=blueprint,
                zone_a_id=zone_a_id,
                zone_b_id=zone_b_id,
                edge_id=edge_id,
                **_boundary_fields_from_edge(edge_data, {}),
            )
            created_count += 1
            if not existing_boundary_id:
                synced_count += 1

        edge_boundary_map[edge_id] = boundary.id

    _update_canvas_with_boundary_ids(dfd, edge_boundary_map)

    return {"synced_count": synced_count, "created_count": created_count}


def _update_canvas_with_boundary_ids(dfd, edge_boundary_map):
    """Update DFD canvas_data with boundary_ids for synced boundary edges."""
    if not edge_boundary_map:
        return

    canvas_data = dfd.canvas_data or {}
    edges = canvas_data.get("edges", [])

    updated = False
    for edge in edges:
        edge_id = edge.get("id")
        if edge_id in edge_boundary_map:
            if "data" not in edge:
                edge["data"] = {}
            if edge["data"].get("trust_boundary_id") != edge_boundary_map[edge_id]:
                edge["data"]["trust_boundary_id"] = edge_boundary_map[edge_id]
                updated = True

    if updated:
        dfd.canvas_data = canvas_data
        dfd.save(update_fields=["canvas_data"])
