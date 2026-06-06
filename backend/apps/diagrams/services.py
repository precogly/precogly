"""
Services for diagrams app - DFD node synchronization and threat generation.
"""

from django.db import transaction
from django.db.models import Q

from apps.systems.models import (
    ComponentLibrary,
    DataFlow,
    Orgsystem,
    OrgsystemComponent,
    TrustBoundary,
    TrustZone,
)
from apps.threat_models.models import ThreatModelOrgsystem
from apps.threats.models import (
    ComponentInstanceThreat,
    ComponentLibraryThreat,
    DataFlowInstanceThreat,
    FlowInstanceCountermeasure,
    Risk,
    RiskThreat,
    ThreatLibrary,
    build_taxonomy_snapshot,
)
from apps.threats.services import recalculate_risk

ANALYZABLE_NODE_TYPES = ("process", "datastore", "humanActor", "systemActor")


def _extract_backend_ids_from_canvas(canvas_data):
    """
    Extract all backend record IDs stored in canvas_data nodes and edges.

    Returns a dict of sets:
        component_ids, dataflow_ids, trust_zone_ids, orgsystem_ids, trust_boundary_ids
    """
    nodes = canvas_data.get("nodes", [])
    edges = canvas_data.get("edges", [])

    component_ids = set()
    trust_zone_ids = set()
    orgsystem_ids = set()
    dataflow_ids = set()
    trust_boundary_ids = set()

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
                trust_zone_ids.add(zid)
        elif node_type == "systemScope":
            sid = node_data.get("orgsystem_id")
            if sid is not None:
                orgsystem_ids.add(sid)

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
                trust_boundary_ids.add(bid)

    return {
        "component_ids": component_ids,
        "dataflow_ids": dataflow_ids,
        "trust_zone_ids": trust_zone_ids,
        "orgsystem_ids": orgsystem_ids,
        "trust_boundary_ids": trust_boundary_ids,
    }


def _cleanup_orphaned_records(old_canvas_data, new_canvas_data, threat_model):
    """
    Delete backend records whose canvas nodes/edges were removed between saves.

    Compares old_canvas_data (before save) with new_canvas_data (after save) to
    find backend IDs that disappeared, then deletes those records. Deletion order
    respects FK constraints: boundaries -> dataflows -> components -> zones -> systems.

    Analysis-only components (created via Threat Analysis UI, not from canvas) are
    never in canvas_data and are therefore never affected.
    """
    old_ids = _extract_backend_ids_from_canvas(old_canvas_data)
    new_ids = _extract_backend_ids_from_canvas(new_canvas_data)

    orphaned_boundary_ids = old_ids["trust_boundary_ids"] - new_ids["trust_boundary_ids"]
    orphaned_dataflow_ids = old_ids["dataflow_ids"] - new_ids["dataflow_ids"]
    orphaned_component_ids = old_ids["component_ids"] - new_ids["component_ids"]
    orphaned_zone_ids = old_ids["trust_zone_ids"] - new_ids["trust_zone_ids"]
    orphaned_system_ids = old_ids["orgsystem_ids"] - new_ids["orgsystem_ids"]

    has_orphans = (
        orphaned_boundary_ids or orphaned_dataflow_ids or orphaned_component_ids
        or orphaned_zone_ids or orphaned_system_ids
    )
    if not has_orphans:
        return

    deleted_counts = {}

    # 1. Trust boundaries (FK zone_a/zone_b -> CASCADE, delete before zones)
    if orphaned_boundary_ids:
        count, _ = TrustBoundary.objects.filter(id__in=orphaned_boundary_ids).delete()
        deleted_counts["trust_boundaries"] = count

    # 2. DataFlows (FK source/dest component -> CASCADE, delete before components)
    if orphaned_dataflow_ids:
        # Capture affected risk IDs before CASCADE wipes RiskThreat links
        affected_risk_ids = list(
            RiskThreat.objects.filter(
                flow_threat__data_flow_id__in=orphaned_dataflow_ids
            ).values_list("risk_id", flat=True).distinct()
        )

        count, _ = DataFlow.objects.filter(id__in=orphaned_dataflow_ids).delete()
        deleted_counts["dataflows"] = count

        # Recalculate risks that lost threat links
        for risk in Risk.objects.filter(id__in=affected_risk_ids):
            recalculate_risk(risk)

    # 3. Components (CASCADE -> ComponentInstanceThreat -> ComponentInstanceCountermeasure)
    # Scope to this threat model to prevent cross-model deletion from corrupted canvas data
    if orphaned_component_ids:
        # Capture affected risk IDs before CASCADE wipes RiskThreat links
        affected_risk_ids = list(
            RiskThreat.objects.filter(
                Q(component_threat__component_id__in=orphaned_component_ids)
                | Q(flow_threat__data_flow__source_component_id__in=orphaned_component_ids)
                | Q(flow_threat__data_flow__dest_component_id__in=orphaned_component_ids)
            ).values_list("risk_id", flat=True).distinct()
        )

        count, _ = OrgsystemComponent.objects.filter(
            id__in=orphaned_component_ids,
            threat_model=threat_model,
        ).delete()
        deleted_counts["components"] = count

        # Recalculate risks that lost threat links
        for risk in Risk.objects.filter(id__in=affected_risk_ids):
            recalculate_risk(risk)

    # 4. Trust zones
    if orphaned_zone_ids:
        count, _ = TrustZone.objects.filter(id__in=orphaned_zone_ids).delete()
        deleted_counts["trust_zones"] = count

    # 5. Orgsystems and their ThreatModelOrgsystem links
    if orphaned_system_ids:
        ThreatModelOrgsystem.objects.filter(
            threat_model=threat_model,
            orgsystem_id__in=orphaned_system_ids,
        ).delete()
        count, _ = Orgsystem.objects.filter(id__in=orphaned_system_ids).delete()
        deleted_counts["orgsystems"] = count

    return deleted_counts


def sync_dfd_nodes_to_components(dfd, threat_model, old_canvas_data=None):
    """
    Sync DFD canvas nodes and edges to backend records.

    When a DFD is saved, this function:
    1. Cleans up orphaned records (nodes/edges removed since last save)
    2. Extracts analyzable nodes (process, datastore, humanActor, systemActor) from canvas_data
    3. Creates or updates OrgsystemComponent records for each
    4. Links to ComponentLibrary based on technology if available
    5. Stores the component_id back in the node data
    6. Auto-generates threats for new components
    7. Syncs edges to DataFlow records
    8. Auto-generates threats for new data flows

    Note: Components are created with orgsystem=None. Users can optionally
    assign components to systems via the node edit panel if the threat model
    has linked systems.

    Args:
        dfd: The DFD instance being saved
        threat_model: The associated ThreatModel instance
        old_canvas_data: Canvas data from before this save (used to detect
            deleted nodes/edges and clean up orphaned backend records)
    """
    canvas_data = dfd.canvas_data or {}
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
    }

    if not nodes:
        # Even with no nodes, we must clean up records from the old canvas
        if old_canvas_data:
            with transaction.atomic():
                _cleanup_orphaned_records(old_canvas_data, canvas_data, threat_model)
        return empty_result

    # Filter to analyzable nodes (process, datastore, humanActor, systemActor)
    # All of these can have associated threats and participate in data flows
    analyzable_nodes = [
        node for node in nodes
        if node.get("type") in ANALYZABLE_NODE_TYPES
    ]

    synced_count = 0
    created_count = 0
    threats_generated = 0
    node_component_map = {}
    all_synced_components = []

    with transaction.atomic():
        # Sync trust zone nodes first (zones must exist before component assignment)
        zone_result = _sync_nodes_to_trust_zones(dfd, nodes)
        node_zone_map = zone_result["node_zone_map"]

        # Sync system scope nodes to Orgsystem records
        system_result = _sync_nodes_to_orgsystems(dfd, nodes, threat_model)
        node_system_map = system_result["node_system_map"]

        for node in analyzable_nodes:
            node_id = node.get("id")
            node_data = node.get("data", {})
            node_type = node.get("type")

            # Get component name from node
            label = node_data.get("label", f"Unnamed {node_type}")

            # Check if this node already has a component_id stored
            existing_component_id = node_data.get("component_id")

            # Find matching ComponentLibrary - try multiple sources
            component_library = None

            # 1. Try component_library_id first (already resolved reference)
            component_library_id = node_data.get("component_library_id")
            if component_library_id:
                component_library = ComponentLibrary.objects.filter(id=component_library_id).first()

            # 2. Try component_ref (slug reference from template)
            if not component_library:
                component_ref = node_data.get("component_ref")
                if component_ref:
                    component_library = ComponentLibrary.objects.filter(slug=component_ref).first()

            # 3. Try technology field (legacy/manual assignment)
            if not component_library:
                technology = node_data.get("technology", "")
                component_library = _find_component_library(technology, node_type)

            # For actors without component_library, still create component records
            # so they can participate in data flows and have threats generated
            # Map node types to ComponentLibrary.Category choices
            node_type_to_category = {
                "process": "process",
                "datastore": "datastore",
                "humanActor": "external_human_actor",
                "systemActor": "external_system_actor",
            }

            # Get category for the component
            category = node_type_to_category.get(node_type, "process")

            if existing_component_id:
                # Update existing component
                try:
                    component = OrgsystemComponent.objects.get(id=existing_component_id)

                    # Detect library change BEFORE any mutation to the component
                    old_library_id = component.component_library_id
                    new_library_id = component_library.id if component_library else None
                    library_changed = old_library_id != new_library_id

                    if library_changed and old_library_id is not None:
                        # Technology changed (or cleared). Delete the old component
                        # and create a fresh one. CASCADE handles cleanup of:
                        #   - ComponentInstanceThreat (+ countermeasures, tests,
                        #     compliance mappings, risk links)
                        #   - DataFlow records (+ flow threats, flow countermeasures,
                        #     flow tests, flow compliance mappings, flow risk links)
                        #   - ComponentDataAsset records
                        #   - PentestFinding matches (SET_NULL)

                        # Capture affected risk IDs before CASCADE wipes RiskThreat links
                        affected_risk_ids = list(
                            RiskThreat.objects.filter(
                                Q(component_threat__component=component)
                                | Q(flow_threat__data_flow__source_component=component)
                                | Q(flow_threat__data_flow__dest_component=component)
                            ).values_list("risk_id", flat=True).distinct()
                        )

                        component.delete()

                        # Recalculate risks that lost threat links
                        for risk in Risk.objects.filter(id__in=affected_risk_ids):
                            recalculate_risk(risk)

                        # Create replacement component with new library
                        component = OrgsystemComponent.objects.create(
                            name=label,
                            orgsystem=None,
                            threat_model=threat_model,
                            component_library=component_library,
                            category=category,
                            description=node_data.get("description", ""),
                            actor_type=(
                                node_data.get("actor_type", "") if node_type == "humanActor"
                                else node_data.get("system_type", "") if node_type == "systemActor"
                                else ""
                            ),
                            data_store_type=node_data.get("data_store_type", "") if node_type == "datastore" else "",
                            data_sensitivity_level=node_data.get("data_sensitivity", "") if node_type in ("process", "datastore") else "",
                        )
                        created_count += 1
                        all_synced_components.append(component)
                    else:
                        # No library change (or first assignment): update in place
                        component.name = label
                        component.component_library = component_library
                        component.category = category
                        component.description = node_data.get("description", "")
                        if node_type == "humanActor":
                            component.actor_type = node_data.get("actor_type", "")
                        elif node_type == "systemActor":
                            component.actor_type = node_data.get("system_type", "")
                        if node_type == "datastore":
                            component.data_store_type = node_data.get("data_store_type", "")
                        if node_type in ("process", "datastore"):
                            component.data_sensitivity_level = node_data.get("data_sensitivity", "")
                        # NOTE: Don't overwrite orgsystem - preserve user's system assignment
                        # Backfill threat_model if not set (for components created before this link existed)
                        if component.threat_model_id is None:
                            component.threat_model = threat_model
                        component.save()
                        synced_count += 1
                        all_synced_components.append(component)

                except OrgsystemComponent.DoesNotExist:
                    # Component was deleted, create new one
                    component = OrgsystemComponent.objects.create(
                        name=label,
                        orgsystem=None,  # No automatic system assignment
                        threat_model=threat_model,
                        component_library=component_library,
                        category=category,
                        description=node_data.get("description", ""),
                        actor_type=(
                            node_data.get("actor_type", "") if node_type == "humanActor"
                            else node_data.get("system_type", "") if node_type == "systemActor"
                            else ""
                        ),
                        data_store_type=node_data.get("data_store_type", "") if node_type == "datastore" else "",
                        data_sensitivity_level=node_data.get("data_sensitivity", "") if node_type in ("process", "datastore") else "",
                    )
                    created_count += 1
                    all_synced_components.append(component)
            else:
                # Create new component with no system assigned
                # component_library may be None for actors without technology
                component = OrgsystemComponent.objects.create(
                    name=label,
                    orgsystem=None,  # No automatic system assignment
                    threat_model=threat_model,
                    component_library=component_library,
                    category=category,
                    description=node_data.get("description", ""),
                    actor_type=(
                        node_data.get("actor_type", "") if node_type == "humanActor"
                        else node_data.get("system_type", "") if node_type == "systemActor"
                        else ""
                    ),
                    data_store_type=node_data.get("data_store_type", "") if node_type == "datastore" else "",
                    data_sensitivity_level=node_data.get("data_sensitivity", "") if node_type in ("process", "datastore") else "",
                )
                created_count += 1
                all_synced_components.append(component)
                synced_count += 1

            node_component_map[node_id] = component.id

        # Update canvas_data with component_ids
        _update_canvas_with_component_ids(dfd, node_component_map)

        # Assign trust zones, system scopes, and parent components
        # by walking each node's parentId ancestry chain.
        # With process container hierarchy (D1), a node's direct parentId
        # may point to a process (not a trust zone), so we must walk up.
        node_lookup = {node.get("id"): node for node in nodes}

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
                if zone_id and system_id and (parent_component_db_id or node.get("type") != "process"):
                    break

                ancestor_node = node_lookup.get(walk_id)
                walk_id = ancestor_node.get("parent_id") if ancestor_node else None

            OrgsystemComponent.objects.filter(id=component_id).update(
                trust_zone_id=zone_id,
                orgsystem_id=system_id,
                parent_component_id=parent_component_db_id,
            )

        # Auto-generate threats for all synced components (idempotent via get_or_create)
        for component in all_synced_components:
            if component.component_library:
                generated = _generate_threats_for_component(component)
                threats_generated += generated

        # Sync trust boundary edges to TrustBoundary DB records (must sync before flows to enable detection)
        boundary_result = _sync_edges_to_trust_boundaries(
            dfd, edges, node_zone_map
        )

        # Sync edges to DataFlow records and generate flow threats
        # Pass node_zone_map and boundary edge map for automatic boundary crossing detection
        boundary_edge_map = {
            edge.get("id"): (node_zone_map.get(edge.get("source")), node_zone_map.get(edge.get("target")))
            for edge in edges
            if edge.get("type") == "trustBoundary"
        }

        # Clean up orphaned records BEFORE syncing flows, so boundary deletions
        # are visible when _update_canvas_with_boundary_crossings runs
        if old_canvas_data:
            _cleanup_orphaned_records(old_canvas_data, dfd.canvas_data or {}, threat_model)

        flow_result = _sync_edges_to_dataflows(dfd, edges, node_component_map, node_zone_map, boundary_edge_map)

    return {
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


def _generate_countermeasures_for_threat(threat_instance):
    """
    Generate countermeasures for a threat based on applicable countermeasures.

    Args:
        threat_instance: ComponentInstanceThreat instance

    Returns:
        Number of countermeasures created
    """
    from apps.threats.models import ComponentInstanceCountermeasure, ComponentInstanceCountermeasureStandard, CountermeasureLibrary
    from apps.compliance.models import CountermeasureLibraryStandard

    # Find countermeasures that apply to this threat's library
    applicable_countermeasures = CountermeasureLibrary.objects.filter(
        applicable_threats=threat_instance.threat_library,
    )

    # Filter by connected packs if the threat's component has a threat model.
    # Allow countermeasures with no source_pack (custom/legacy) to always pass through.
    if hasattr(threat_instance, 'component') and threat_instance.component and threat_instance.component.threat_model_id:
        from apps.threat_models.models import ThreatModelLibraryPack

        connected_pack_ids = ThreatModelLibraryPack.objects.filter(
            threat_model_id=threat_instance.component.threat_model_id
        ).values_list("library_pack_id", flat=True)
        applicable_countermeasures = applicable_countermeasures.filter(
            Q(source_pack_id__in=connected_pack_ids)
            | Q(source_pack__isnull=True)
        )

    created_count = 0
    has_platform_countermeasure = False
    for countermeasure_library in applicable_countermeasures:
        countermeasure_status = countermeasure_library.default_status
        cm_instance, created = ComponentInstanceCountermeasure.objects.get_or_create(
            instance_threat=threat_instance,
            countermeasure_library=countermeasure_library,
            defaults={
                "status": countermeasure_status,
                # Copy metadata for self-sufficiency if library is later removed
                "countermeasure_name": countermeasure_library.name if countermeasure_library else "",
                "countermeasure_description": countermeasure_library.description if countermeasure_library else "",
                "control_type": countermeasure_library.control_type if countermeasure_library else "",
            },
        )
        if created:
            created_count += 1
            if countermeasure_status == "platform":
                has_platform_countermeasure = True
            # Propagate library-level compliance mappings to instance level (#29)
            library_standards = CountermeasureLibraryStandard.objects.filter(
                countermeasure_library=countermeasure_library,
            ).select_related("requirement", "requirement__framework")
            if library_standards.exists():
                ComponentInstanceCountermeasureStandard.objects.bulk_create(
                    [
                        ComponentInstanceCountermeasureStandard(
                            component_countermeasure=cm_instance,
                            requirement=ls.requirement,
                            sufficiency=ls.sufficiency,
                            section_code=ls.requirement.section_code,
                            framework_name=ls.requirement.framework.name,
                            requirement_description=ls.requirement.description,
                        )
                        for ls in library_standards
                    ],
                    ignore_conflicts=True,
                )

    # Recalculate threat status if any platform countermeasures were created
    if has_platform_countermeasure:
        from apps.threats.services import recalculate_threat_status
        recalculate_threat_status(threat_instance)

    return created_count


def _generate_threats_for_component(component):
    """
    Generate threats for a component based on its library type.

    Returns the number of threats created.
    """
    if not component.component_library:
        return 0

    # Get threats linked to this component's library type
    # Only include threats that apply to components (not flow-only threats)
    library_threats = ComponentLibraryThreat.objects.filter(
        component_library=component.component_library,
        applies_to__in=[
            ComponentLibraryThreat.AppliesTo.COMPONENT,
            ComponentLibraryThreat.AppliesTo.BOTH,
        ],
    ).select_related("threat_library")

    # Filter by connected packs if component has a threat model.
    # Allow threats with no source_pack (custom/legacy) to always pass through.
    if component.threat_model_id:
        from apps.threat_models.models import ThreatModelLibraryPack

        connected_pack_ids = ThreatModelLibraryPack.objects.filter(
            threat_model_id=component.threat_model_id
        ).values_list("library_pack_id", flat=True)
        library_threats = library_threats.filter(
            Q(threat_library__source_pack_id__in=connected_pack_ids)
            | Q(threat_library__source_pack__isnull=True)
        )

    created_count = 0

    for lib_threat in library_threats:
        threat_lib = lib_threat.threat_library
        threat_instance, created = ComponentInstanceThreat.objects.get_or_create(
            component=component,
            threat_library=threat_lib,
            defaults={
                "inherent_severity": lib_threat.default_severity,
                "status": ComponentInstanceThreat.Status.EXPOSED,
                # Copy metadata for self-sufficiency if library is later removed
                "threat_name": threat_lib.name if threat_lib else "",
                "threat_description": threat_lib.description if threat_lib else "",
                "taxonomy_snapshot": build_taxonomy_snapshot(threat_lib),
            },
        )
        if created:
            created_count += 1
            # Auto-generate countermeasures for this new threat
            _generate_countermeasures_for_threat(threat_instance)

    return created_count


def _get_zone_ancestor_ids(zone_id):
    """
    Get all ancestor zone IDs for a given zone, including itself.
    Walks up the parent chain to find all ancestors.

    Args:
        zone_id: ID of the starting zone

    Returns:
        Set of zone IDs (including the input zone)
    """
    from apps.systems.models import TrustZone

    if not zone_id:
        return set()

    ancestor_ids = {zone_id}
    current_zone_id = zone_id

    # Walk up the parent chain
    while True:
        try:
            zone = TrustZone.objects.get(id=current_zone_id)
            if zone.parent_id:
                ancestor_ids.add(zone.parent_id)
                current_zone_id = zone.parent_id
            else:
                break
        except TrustZone.DoesNotExist:
            break

    return ancestor_ids


def _detect_boundary_crossings(source_component_id, target_component_id):
    """
    Detect which trust boundaries a data flow crosses based on its source and target components.

    A data flow crosses a trust boundary when:
    1. Source component is in zone A (or any ancestor of A)
    2. Target component is in zone B (or any ancestor of B)
    3. There's a TrustBoundary connecting any ancestor of A to any ancestor of B

    Handles nested zones by walking up the zone hierarchy.

    Args:
        source_component_id: ID of the source OrgsystemComponent
        target_component_id: ID of the target OrgsystemComponent

    Returns:
        List of trust boundary IDs that this data flow crosses
    """
    from apps.systems.models import OrgsystemComponent, TrustBoundary

    try:
        source_component = OrgsystemComponent.objects.select_related('trust_zone').get(id=source_component_id)
        target_component = OrgsystemComponent.objects.select_related('trust_zone').get(id=target_component_id)
    except OrgsystemComponent.DoesNotExist:
        return []

    source_zone_id = source_component.trust_zone_id
    target_zone_id = target_component.trust_zone_id

    if not source_zone_id or not target_zone_id:
        return []

    # Get all ancestor zones for both source and target
    source_ancestors = _get_zone_ancestor_ids(source_zone_id)
    target_ancestors = _get_zone_ancestor_ids(target_zone_id)

    # Same zone family - no boundary crossing (they share a common ancestor)
    if source_ancestors & target_ancestors:
        return []

    # Find trust boundaries between any ancestor of source and any ancestor of target
    boundary_ids = list(
        TrustBoundary.objects.filter(
            zone_a_id__in=source_ancestors,
            zone_b_id__in=target_ancestors
        ).union(
            TrustBoundary.objects.filter(
                zone_a_id__in=target_ancestors,
                zone_b_id__in=source_ancestors
            )
        ).values_list('id', flat=True).distinct()
    )

    return boundary_ids


def _build_zone_ancestor_map(zone_ids):
    """
    Build a map of zone_id -> set of ancestor zone IDs (including itself).
    Pre-fetches all ancestor relationships in one query.

    Args:
        zone_ids: Set of zone IDs to get ancestors for

    Returns:
        Dict mapping zone_id -> set of ancestor zone IDs
    """
    from apps.systems.models import TrustZone

    if not zone_ids:
        return {}

    # Get all zones in one query
    zones = TrustZone.objects.filter(id__in=zone_ids).select_related('parent')
    zone_map = {z.id: z for z in zones}

    result = {}
    for zone_id in zone_ids:
        ancestors = set()
        current_id = zone_id
        while current_id:
            ancestors.add(current_id)
            zone = zone_map.get(current_id)
            if zone and zone.parent_id:
                current_id = zone.parent_id
            else:
                current_id = None
        result[zone_id] = ancestors

    return result


def _detect_boundary_crossings_batch(source_component_id, target_component_id, component_zone_map, zone_ancestor_map, boundary_zone_pairs, all_boundaries):
    """
    Batch version of boundary detection using pre-fetched data.

    Args:
        source_component_id: ID of source component
        target_component_id: ID of target component
        component_zone_map: Dict mapping component_id -> zone_id
        zone_ancestor_map: Dict mapping zone_id -> set of ancestor zone IDs
        boundary_zone_pairs: Set of (zone_a_id, zone_b_id) tuples for all boundaries
        all_boundaries: QuerySet of TrustBoundary objects

    Returns:
        List of boundary IDs crossed
    """
    src_zone = component_zone_map.get(source_component_id)
    tgt_zone = component_zone_map.get(target_component_id)

    if not src_zone or not tgt_zone:
        return []

    src_ancestors = zone_ancestor_map.get(src_zone, {src_zone})
    tgt_ancestors = zone_ancestor_map.get(tgt_zone, {tgt_zone})

    # Same zone family - no boundary crossing
    if src_ancestors & tgt_ancestors:
        return []

    # Find boundaries where one endpoint is in source ancestors and other in target ancestors
    boundary_ids = []
    for boundary in all_boundaries:
        zone_a_in_src = boundary.zone_a_id in src_ancestors
        zone_b_in_src = boundary.zone_b_id in src_ancestors
        zone_a_in_tgt = boundary.zone_a_id in tgt_ancestors
        zone_b_in_tgt = boundary.zone_b_id in tgt_ancestors

        # Boundary crosses if one endpoint is in source family and other in target family
        if (zone_a_in_src and zone_b_in_tgt) or (zone_b_in_src and zone_a_in_tgt):
            boundary_ids.append(boundary.id)

    return boundary_ids


def _get_all_boundaries_for_zones(source_ancestors, target_ancestors):
    """
    Find all trust boundaries between any ancestor of source zone and any ancestor of target zone.

    Args:
        source_ancestors: Set of ancestor zone IDs for source
        target_ancestors: Set of ancestor zone IDs for target

    Returns:
        List of boundary IDs
    """
    from apps.systems.models import TrustBoundary

    if not source_ancestors or not target_ancestors:
        return []

    # Single query to find all boundaries between the two zone families
    return list(
        TrustBoundary.objects.filter(
            Q(zone_a_id__in=source_ancestors, zone_b_id__in=target_ancestors) |
            Q(zone_a_id__in=target_ancestors, zone_b_id__in=source_ancestors)
        ).values_list('id', flat=True).distinct()
    )


def _sync_edges_to_dataflows(dfd, edges, node_component_map, node_zone_map=None, boundary_edge_map=None):
    """
    Sync DFD edges to DataFlow records and generate threats.

    Only creates DataFlow records for edges where BOTH source and dest
    nodes have been synced to components (i.e., have technologies assigned).

    Args:
        dfd: The DFD instance
        edges: List of edges from canvas_data
        node_component_map: Mapping of node_id -> component_id
        node_zone_map: Mapping of node_id -> zone_id (for boundary detection)
        boundary_edge_map: Mapping of edge_id -> (zone_a_id, zone_b_id) for trust boundaries

    Returns:
        dict with synced_count, created_count, threats_generated
    """
    from apps.systems.models import OrgsystemComponent, TrustBoundary

    # Collect all component IDs that appear in data flows
    dataflow_edges = [
        edge for edge in edges
        if edge.get("type") == "dataFlow" and node_component_map.get(edge.get("source")) and node_component_map.get(edge.get("target"))
    ]

    if not dataflow_edges:
        return {"synced_count": 0, "created_count": 0, "threats_generated": 0}

    # Batch fetch all components with their zones
    all_component_ids = set()
    for edge in dataflow_edges:
        src_id = node_component_map.get(edge.get("source"))
        tgt_id = node_component_map.get(edge.get("target"))
        if src_id:
            all_component_ids.add(src_id)
        if tgt_id:
            all_component_ids.add(tgt_id)

    components = OrgsystemComponent.objects.filter(id__in=all_component_ids).select_related('trust_zone')
    component_zone_map = {c.id: c.trust_zone_id for c in components}

    # Build zone ancestor map for all relevant zones
    all_zone_ids = {z for z in component_zone_map.values() if z}
    zone_ancestor_map = _build_zone_ancestor_map(all_zone_ids)

    # Batch fetch all relevant boundaries at once
    # Get all unique zone sets to check for boundaries
    all_boundary_ids = set()
    for edge in dataflow_edges:
        src_zone = component_zone_map.get(node_component_map.get(edge.get("source")))
        tgt_zone = component_zone_map.get(node_component_map.get(edge.get("target")))
        if src_zone and tgt_zone:
            src_ancestors = zone_ancestor_map.get(src_zone, {src_zone})
            tgt_ancestors = zone_ancestor_map.get(tgt_zone, {tgt_zone})
            # Skip if same zone family
            if src_ancestors & tgt_ancestors:
                continue
            boundaries = _get_all_boundaries_for_zones(src_ancestors, tgt_ancestors)
            all_boundary_ids.update(boundaries)

    # Build boundary map for quick lookup
    # Fetch ALL existing boundaries in DB (not just those crossed by flows)
    all_existing_boundaries = list(TrustBoundary.objects.all().only('id'))
    all_boundary_ids = {b.id for b in all_existing_boundaries}

    all_boundaries = list(TrustBoundary.objects.filter(id__in=all_boundary_ids))
    boundary_zone_pairs = set()
    boundary_ids_set = set()
    for b in all_boundaries:
        boundary_zone_pairs.add((b.zone_a_id, b.zone_b_id))
        boundary_zone_pairs.add((b.zone_b_id, b.zone_a_id))
        boundary_ids_set.add(b.id)

    from apps.threats.models import CountermeasureLibrary

    synced_count = 0
    created_count = 0
    threats_generated = 0
    all_synced_flows = []
    edge_dataflow_map = {}
    edge_boundary_crossings = {}

    for edge in dataflow_edges:
        edge_id = edge.get("id")
        source_node_id = edge.get("source")
        target_node_id = edge.get("target")
        edge_data = edge.get("data", {})

        source_component_id = node_component_map.get(source_node_id)
        target_component_id = node_component_map.get(target_node_id)

        if not source_component_id or not target_component_id:
            continue

        # Get edge properties
        label = edge_data.get("label", "")
        protocol = edge_data.get("protocol", "")
        encrypted = edge_data.get("encrypted", False)
        authenticated = edge_data.get("authenticated", False)
        description = edge_data.get("description", "")
        has_sensitive_data = edge_data.get("has_sensitive_data", False)
        data_classification = edge_data.get("data_classification", [])

        existing_dataflow_id = edge_data.get("dataflow_id")

        # Compute boundary crossings from pre-fetched data
        trust_boundary_ids = _detect_boundary_crossings_batch(
            source_component_id, target_component_id,
            component_zone_map, zone_ancestor_map, boundary_zone_pairs, all_boundaries
        )

        if existing_dataflow_id:
            # Update existing DataFlow
            try:
                dataflow = DataFlow.objects.get(id=existing_dataflow_id)
                dataflow.label = label
                dataflow.protocol = protocol
                dataflow.encrypted = encrypted
                dataflow.authenticated = authenticated
                dataflow.description = description
                dataflow.has_sensitive_data = has_sensitive_data
                dataflow.data_classification = data_classification
                dataflow.source_component_id = source_component_id
                dataflow.dest_component_id = target_component_id
                dataflow.trust_boundary_ids = trust_boundary_ids
                dataflow.save()
                synced_count += 1
                all_synced_flows.append(dataflow)
            except DataFlow.DoesNotExist:
                # DataFlow was deleted, create new one
                dataflow = DataFlow.objects.create(
                    source_component_id=source_component_id,
                    dest_component_id=target_component_id,
                    label=label,
                    edge_id=edge_id,
                    protocol=protocol,
                    encrypted=encrypted,
                    authenticated=authenticated,
                    description=description,
                    has_sensitive_data=has_sensitive_data,
                    data_classification=data_classification,
                    trust_boundary_ids=trust_boundary_ids,
                )
                created_count += 1
                synced_count += 1
                all_synced_flows.append(dataflow)
        else:
            # Create new DataFlow
            dataflow = DataFlow.objects.create(
                source_component_id=source_component_id,
                dest_component_id=target_component_id,
                label=label,
                edge_id=edge_id,
                protocol=protocol,
                encrypted=encrypted,
                authenticated=authenticated,
                description=description,
                has_sensitive_data=has_sensitive_data,
                data_classification=data_classification,
                trust_boundary_ids=trust_boundary_ids,
            )
            created_count += 1
            all_synced_flows.append(dataflow)
            synced_count += 1

        edge_dataflow_map[edge_id] = dataflow.id

        # Track boundary crossings for canvas update
        if trust_boundary_ids:
            edge_boundary_crossings[edge_id] = trust_boundary_ids

    # Update canvas_data with dataflow_ids
    _update_canvas_with_dataflow_ids(dfd, edge_dataflow_map)

    # Update canvas_data with boundary crossings
    _update_canvas_with_boundary_crossings(dfd, edge_boundary_crossings, boundary_ids_set)

    # Generate threats for all synced data flows (idempotent via get_or_create)
    for dataflow in all_synced_flows:
        generated = _generate_threats_for_dataflow(dataflow)
        threats_generated += generated

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


def _update_canvas_with_boundary_crossings(dfd, edge_boundary_crossings, all_current_boundary_ids=None):
    """
    Update DFD canvas_data with trust boundary IDs for data flow edges.

    Args:
        dfd: The DFD instance
        edge_boundary_crossings: Dict mapping edge_id -> list of boundary IDs crossed
        all_current_boundary_ids: Set of boundary IDs that still exist (to clear stale refs)
    """
    if not edge_boundary_crossings and not all_current_boundary_ids:
        return

    canvas_data = dfd.canvas_data or {}
    edges = canvas_data.get("edges", [])
    current_boundary_ids_set = set(all_current_boundary_ids) if all_current_boundary_ids else None

    updated = False
    for edge in edges:
        edge_id = edge.get("id")
        edge_data = edge.get("data", {})

        if edge.get("type") == "dataFlow":
            current_ids = edge_data.get("crossesBoundaryIds", [])
            new_ids = edge_boundary_crossings.get(edge_id, [])

            if current_boundary_ids_set is not None:
                # Filter detected IDs to only include boundaries that still exist
                new_ids_filtered = [bid for bid in new_ids if bid in current_boundary_ids_set]
                # If no boundaries detected this save, clear the field entirely
                # (don't preserve stale IDs from a prior save)
                filtered_ids = new_ids_filtered
            else:
                filtered_ids = new_ids if new_ids else current_ids

            if edge_data.get("crossesBoundaryIds") != filtered_ids:
                edge_data["crossesBoundaryIds"] = filtered_ids
                updated = True

    if updated:
        dfd.canvas_data = canvas_data
        dfd.save(update_fields=["canvas_data"])


def _generate_threats_for_dataflow(dataflow):
    """
    Generate threats for a data flow based on connected components.

    For data flows, we look at threats associated with EITHER endpoint's
    component library where applies_to is "flow" or "both".

    Returns the number of threats created.
    """
    source_component = dataflow.source_component
    dest_component = dataflow.dest_component

    # Collect component libraries from both endpoints
    component_libraries = []
    if source_component and source_component.component_library:
        component_libraries.append(source_component.component_library)
    if dest_component and dest_component.component_library:
        component_libraries.append(dest_component.component_library)

    created_count = 0
    seen_threat_ids = set()

    # If we have component libraries, get threats specific to those components
    if component_libraries:
        # Get threats that apply to data flows for these component types
        library_threats = ComponentLibraryThreat.objects.filter(
            component_library__in=component_libraries,
            applies_to__in=[
                ComponentLibraryThreat.AppliesTo.FLOW,
                ComponentLibraryThreat.AppliesTo.BOTH,
            ],
        ).select_related("threat_library").distinct()

        # Filter by connected packs if dataflow has a threat model.
        # Allow threats with no source_pack (custom/legacy) to always pass through.
        threat_model_id = getattr(source_component, "threat_model_id", None) or getattr(dest_component, "threat_model_id", None)
        if threat_model_id:
            from apps.threat_models.models import ThreatModelLibraryPack

            connected_pack_ids = ThreatModelLibraryPack.objects.filter(
                threat_model_id=threat_model_id
            ).values_list("library_pack_id", flat=True)
            library_threats = library_threats.filter(
                Q(threat_library__source_pack_id__in=connected_pack_ids)
                | Q(threat_library__source_pack__isnull=True)
            )

        for lib_threat in library_threats:
            # Avoid duplicate threats if both endpoints have the same threat
            if lib_threat.threat_library_id in seen_threat_ids:
                continue
            seen_threat_ids.add(lib_threat.threat_library_id)

            threat_lib = lib_threat.threat_library
            threat_instance, created = DataFlowInstanceThreat.objects.get_or_create(
                data_flow=dataflow,
                threat_library=threat_lib,
                defaults={
                    "inherent_severity": lib_threat.default_severity,
                    "status": DataFlowInstanceThreat.Status.EXPOSED,
                    # Copy metadata for self-sufficiency if library is later removed
                    "threat_name": threat_lib.name if threat_lib else "",
                    "threat_description": threat_lib.description if threat_lib else "",
                    "taxonomy_snapshot": build_taxonomy_snapshot(threat_lib),
                },
            )
            if created:
                created_count += 1
                # Auto-generate countermeasures for this new threat
                _generate_countermeasures_for_flow_threat(threat_instance)

    return created_count


def _generate_countermeasures_for_flow_threat(threat_instance):
    """
    Generate countermeasures for a data flow threat.

    Args:
        threat_instance: DataFlowInstanceThreat instance

    Returns:
        Number of countermeasures created
    """
    from apps.threats.models import CountermeasureLibrary, FlowInstanceCountermeasureStandard
    from apps.compliance.models import CountermeasureLibraryStandard

    # Find countermeasures that apply to this threat's library
    applicable_countermeasures = CountermeasureLibrary.objects.filter(
        applicable_threats=threat_instance.threat_library,
    )

    # Filter by connected packs if the flow's component has a threat model.
    # Allow countermeasures with no source_pack (custom/legacy) to always pass through.
    data_flow = threat_instance.data_flow
    threat_model_id = None
    if hasattr(data_flow, "source_component") and data_flow.source_component:
        threat_model_id = data_flow.source_component.threat_model_id
    if not threat_model_id and hasattr(data_flow, "dest_component") and data_flow.dest_component:
        threat_model_id = data_flow.dest_component.threat_model_id
    if threat_model_id:
        from apps.threat_models.models import ThreatModelLibraryPack

        connected_pack_ids = ThreatModelLibraryPack.objects.filter(
            threat_model_id=threat_model_id
        ).values_list("library_pack_id", flat=True)
        applicable_countermeasures = applicable_countermeasures.filter(
            Q(source_pack_id__in=connected_pack_ids)
            | Q(source_pack__isnull=True)
        )

    created_count = 0
    has_platform_countermeasure = False
    for countermeasure_library in applicable_countermeasures:
        countermeasure_status = countermeasure_library.default_status
        cm_instance, created = FlowInstanceCountermeasure.objects.get_or_create(
            flow_threat=threat_instance,
            countermeasure_library=countermeasure_library,
            defaults={
                "status": countermeasure_status,
                # Copy metadata for self-sufficiency if library is later removed
                "countermeasure_name": countermeasure_library.name if countermeasure_library else "",
                "countermeasure_description": countermeasure_library.description if countermeasure_library else "",
                "control_type": countermeasure_library.control_type if countermeasure_library else "",
            },
        )
        if created:
            created_count += 1
            if countermeasure_status == "platform":
                has_platform_countermeasure = True
            # Propagate library-level compliance mappings to instance level (#29)
            library_standards = CountermeasureLibraryStandard.objects.filter(
                countermeasure_library=countermeasure_library,
            ).select_related("requirement", "requirement__framework")
            if library_standards.exists():
                FlowInstanceCountermeasureStandard.objects.bulk_create(
                    [
                        FlowInstanceCountermeasureStandard(
                            flow_countermeasure=cm_instance,
                            requirement=ls.requirement,
                            sufficiency=ls.sufficiency,
                            section_code=ls.requirement.section_code,
                            framework_name=ls.requirement.framework.name,
                            requirement_description=ls.requirement.description,
                        )
                        for ls in library_standards
                    ],
                    ignore_conflicts=True,
                )

    # Recalculate threat status if any platform countermeasures were created
    if has_platform_countermeasure:
        from apps.threats.services import recalculate_threat_status
        recalculate_threat_status(threat_instance)

    return created_count


def _sync_nodes_to_trust_zones(dfd, nodes):
    """Sync trust zone canvas nodes to TrustZone DB records."""
    trust_zone_nodes = [
        node for node in nodes if node.get("type") == "trustZone"
    ]

    synced_count = 0
    created_count = 0
    node_zone_map = {}  # canvas node_id -> TrustZone DB id

    for node in trust_zone_nodes:
        node_id = node.get("id")
        node_data = node.get("data", {})

        # snake_case — parser already converted from frontend camelCase
        label = node_data.get("label", "Unnamed Zone")
        trust_level = node_data.get("trust_level", 75)
        description = node_data.get("description", "")

        existing_trust_zone_id = node_data.get("trust_zone_id")

        if existing_trust_zone_id:
            try:
                trust_zone = TrustZone.objects.get(id=existing_trust_zone_id)
                trust_zone.name = label
                trust_zone.trust_level = trust_level
                trust_zone.description = description
                trust_zone.save()
                synced_count += 1
            except TrustZone.DoesNotExist:
                trust_zone = TrustZone.objects.create(
                    name=label,
                    trust_level=trust_level,
                    description=description,
                )
                created_count += 1
        else:
            trust_zone = TrustZone.objects.create(
                name=label,
                trust_level=trust_level,
                description=description,
            )
            created_count += 1
            synced_count += 1

        node_zone_map[node_id] = trust_zone.id

    # Second pass: set parent relationships for nested zones
    for node in trust_zone_nodes:
        node_id = node.get("id")
        parent_node_id = node.get("parent_id")  # React Flow parentId → snake_case
        if parent_node_id and parent_node_id in node_zone_map:
            TrustZone.objects.filter(id=node_zone_map[node_id]).update(
                parent_id=node_zone_map[parent_node_id]
            )
        elif node_id in node_zone_map:
            # Clear parent if zone was un-nested on canvas
            TrustZone.objects.filter(id=node_zone_map[node_id]).exclude(
                parent__isnull=True
            ).update(parent=None)

    _update_canvas_with_trust_zone_ids(dfd, node_zone_map)

    return {
        "synced_count": synced_count,
        "created_count": created_count,
        "node_zone_map": node_zone_map,
    }


def _update_canvas_with_trust_zone_ids(dfd, node_zone_map):
    """Update DFD canvas_data with trust_zone_ids for synced zone nodes."""
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


def _sync_nodes_to_orgsystems(dfd, nodes, threat_model):
    """Sync system scope canvas nodes to Orgsystem DB records."""
    system_scope_nodes = [
        node for node in nodes if node.get("type") == "systemScope"
    ]

    synced_count = 0
    created_count = 0
    node_system_map = {}  # canvas node_id -> Orgsystem DB id

    # Derive organization from the threat model
    organization = threat_model.organization if threat_model else None

    for node in system_scope_nodes:
        node_id = node.get("id")
        node_data = node.get("data", {})

        label = node_data.get("label", "Unnamed System")
        owner = node_data.get("owner", "")
        description = node_data.get("description", "")

        existing_orgsystem_id = node_data.get("orgsystem_id")

        if existing_orgsystem_id:
            try:
                orgsystem = Orgsystem.objects.get(id=existing_orgsystem_id)
                orgsystem.name = label
                orgsystem.owner = owner
                orgsystem.description = description
                orgsystem.save()
                synced_count += 1
            except Orgsystem.DoesNotExist:
                orgsystem = Orgsystem.objects.create(
                    name=label,
                    owner=owner,
                    description=description,
                    organization=organization,
                )
                created_count += 1
        else:
            orgsystem = Orgsystem.objects.create(
                name=label,
                owner=owner,
                description=description,
                organization=organization,
            )
            created_count += 1
            synced_count += 1

        node_system_map[node_id] = orgsystem.id

        # Auto-connect the system to the threat model
        if threat_model:
            ThreatModelOrgsystem.objects.get_or_create(
                threat_model=threat_model, orgsystem=orgsystem
            )

    _update_canvas_with_orgsystem_ids(dfd, node_system_map)

    return {
        "synced_count": synced_count,
        "created_count": created_count,
        "node_system_map": node_system_map,
    }


def _update_canvas_with_orgsystem_ids(dfd, node_system_map):
    """Update DFD canvas_data with orgsystem_ids for synced system scope nodes."""
    if not node_system_map:
        return

    canvas_data = dfd.canvas_data or {}
    nodes = canvas_data.get("nodes", [])

    updated = False
    for node in nodes:
        node_id = node.get("id")
        if node_id in node_system_map:
            if "data" not in node:
                node["data"] = {}
            if node["data"].get("orgsystem_id") != node_system_map[node_id]:
                node["data"]["orgsystem_id"] = node_system_map[node_id]
                updated = True

    if updated:
        dfd.canvas_data = canvas_data
        dfd.save(update_fields=["canvas_data"])


def _sync_edges_to_trust_boundaries(dfd, edges, node_zone_map):
    """Sync trust boundary edges to TrustBoundary DB records."""
    synced_count = 0
    created_count = 0
    edge_boundary_map = {}

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

        label = edge_data.get("label", "")

        # Extract security metadata into format_metadata dict
        # Keys are already snake_case (parser converted from frontend camelCase)
        metadata_keys = [
            "access_control_methods", "authentication_methods",
            "access_token_expires", "access_token_ttl",
            "has_refresh_token", "refresh_token_expires", "refresh_token_ttl",
            "can_user_logout", "can_system_logout",
        ]
        format_metadata = {
            key: edge_data[key] for key in metadata_keys if key in edge_data
        }

        existing_boundary_id = edge_data.get("trust_boundary_id")
        boundary = None

        if existing_boundary_id:
            try:
                boundary = TrustBoundary.objects.get(id=existing_boundary_id)
                boundary.zone_a_id = zone_a_id
                boundary.zone_b_id = zone_b_id
                boundary.label = label
                boundary.edge_id = edge_id
                boundary.format_metadata = format_metadata
                boundary.save()
                synced_count += 1
            except TrustBoundary.DoesNotExist:
                # Check if boundary with these zones already exists (different edge_id)
                existing = TrustBoundary.objects.filter(zone_a_id=zone_a_id, zone_b_id=zone_b_id).first()
                if existing:
                    boundary = existing
                    boundary.label = label
                    boundary.edge_id = edge_id
                    boundary.format_metadata = format_metadata
                    boundary.save()
                    synced_count += 1
                else:
                    boundary = TrustBoundary.objects.create(
                        zone_a_id=zone_a_id,
                        zone_b_id=zone_b_id,
                        label=label,
                        edge_id=edge_id,
                        format_metadata=format_metadata,
                    )
                    created_count += 1
                    synced_count += 1
        else:
            # Check if boundary with these zones already exists
            existing = TrustBoundary.objects.filter(
                Q(zone_a_id=zone_a_id, zone_b_id=zone_b_id) |
                Q(zone_a_id=zone_b_id, zone_b_id=zone_a_id)
            ).first()
            if existing:
                boundary = existing
                boundary.label = label
                boundary.edge_id = edge_id
                boundary.format_metadata = format_metadata
                boundary.save()
                synced_count += 1
            else:
                boundary = TrustBoundary.objects.create(
                    zone_a_id=zone_a_id,
                    zone_b_id=zone_b_id,
                    label=label,
                    edge_id=edge_id,
                    format_metadata=format_metadata,
                )
                created_count += 1
                synced_count += 1

        # Always write back trust_boundary_id so frontend has it for subsequent saves
        edge_data["trust_boundary_id"] = boundary.id
        edge_boundary_map[edge_id] = boundary.id

    _update_canvas_with_trust_boundary_ids(dfd, edge_boundary_map)

    return {"synced_count": synced_count, "created_count": created_count}


def _update_canvas_with_trust_boundary_ids(dfd, edge_boundary_map):
    """Update DFD canvas_data with trust_boundary_ids for synced boundary edges."""
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
