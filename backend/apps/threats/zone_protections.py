"""
Zone-based countermeasure inheritance analysis and application.

Analyzes trust zone topology to suggest inheriting platform countermeasures
from outer (lower trust_level) zones to inner (higher trust_level) zones.
"""

from django.db.models import Q

from apps.systems.models import Boundary
from apps.threats.models import (
    CountermeasureThreatLink,
    InstanceCountermeasure,
)
from apps.threats.services import recalculate_all_threats_for_countermeasure


def _get_all_outer_zones(zone, visited=None):
    """
    Walk the trust boundary chain outward, collecting all zones with
    lower trust_level. Traverses multiple boundary layers for nested zones.
    """
    if visited is None:
        visited = set()
    visited.add(zone.id)

    outer_zones = []
    boundaries = Boundary.objects.filter(
        Q(zone_a=zone) | Q(zone_b=zone)
    ).select_related("zone_a", "zone_b")

    for boundary in boundaries:
        adjacent = boundary.zone_a if boundary.zone_b_id == zone.id else boundary.zone_b
        if adjacent.id in visited or adjacent.trust_level >= zone.trust_level:
            continue
        outer_zones.append(adjacent)
        outer_zones.extend(_get_all_outer_zones(adjacent, visited))

    return outer_zones


def analyze_zone_protections(threat_model):
    """
    Analyze zone topology for a threat model and return inheritance suggestions.

    For each gap countermeasure on a component in a trust zone, checks if the
    same countermeasure_library has a platform instance on any component in an
    outer (lower trust_level) zone.

    Returns a list of suggestion dicts.
    """
    from apps.systems.models import OrgsystemComponent

    # Replicate component scoping from ThreatModelViewSet.threats
    dfds = threat_model.dfds.all()
    component_ids = set()
    for dfd in dfds:
        canvas_data = dfd.canvas_data or {}
        for node in canvas_data.get("nodes", []):
            component_id = node.get("data", {}).get("component_id")
            if component_id:
                component_ids.add(component_id)

    # Also include analysis-only components
    analysis_only_ids = (
        OrgsystemComponent.objects.filter(threat_model=threat_model)
        .exclude(id__in=component_ids)
        .values_list("id", flat=True)
    )
    component_ids.update(analysis_only_ids)

    if not component_ids:
        return []

    # Get all gap countermeasures that have a library link and whose
    # linked threats' components have a trust zone
    gap_links = CountermeasureThreatLink.objects.filter(
        component_threat__component_id__in=component_ids,
        component_threat__component__zone__isnull=False,
        countermeasure__countermeasure_library__isnull=False,
        countermeasure__status="gap",
        component_threat__isnull=False,
    ).select_related(
        "component_threat__component__zone",
        "countermeasure__countermeasure_library",
    )

    if not gap_links:
        return []

    # Cache outer zones per zone_id
    outer_zones_cache = {}
    suggestions = []

    for gap_link in gap_links:
        gap_cm = gap_link.countermeasure
        component = gap_link.component_threat.component
        zone = component.zone
        zone_id = zone.id

        if zone_id not in outer_zones_cache:
            outer_zones_cache[zone_id] = _get_all_outer_zones(zone)

        outer_zones = outer_zones_cache[zone_id]
        if not outer_zones:
            continue

        # Find a matching platform countermeasure in outer zones (also in scope)
        source_link = (
            CountermeasureThreatLink.objects.filter(
                component_threat__component_id__in=component_ids,
                component_threat__component__zone__in=outer_zones,
                countermeasure__countermeasure_library=gap_cm.countermeasure_library,
                countermeasure__status="platform",
                component_threat__isnull=False,
            )
            .select_related(
                "component_threat__component__zone",
                "countermeasure__countermeasure_library",
            )
            .first()
        )

        if source_link:
            suggestions.append(
                {
                    "target_countermeasure_id": gap_cm.id,
                    "target_component_name": component.name,
                    "target_zone_name": zone.name,
                    "source_component_name": source_link.component_threat.component.name,
                    "source_zone_name": source_link.component_threat.component.zone.name,
                    "countermeasure_name": gap_cm.countermeasure_library.name,
                    "control_functions": gap_cm.countermeasure_library.control_functions,
                }
            )

    return suggestions


def apply_zone_protections(items):
    """
    Apply zone inheritance to selected countermeasures.

    items: list of dicts with countermeasure_id, source_component_name, source_zone_name

    Updates matching gap countermeasures to platform with inheritance metadata,
    then recalculates threat statuses for affected threats.
    """
    if not items:
        return {"updated_count": 0}

    updated_count = 0
    affected_countermeasures = set()

    for item in items:
        countermeasure_id = item.get("countermeasure_id")
        source_component_name = item.get("source_component_name", "")
        source_zone_name = item.get("source_zone_name", "")

        count = InstanceCountermeasure.objects.filter(
            id=countermeasure_id,
            status="gap",
        ).update(
            status="platform",
            is_inherited=True,
            inherited_from_component_name=source_component_name,
            inherited_from_zone_name=source_zone_name,
        )
        updated_count += count

        if count > 0:
            try:
                cm = InstanceCountermeasure.objects.get(id=countermeasure_id)
                affected_countermeasures.add(cm.id)
            except InstanceCountermeasure.DoesNotExist:
                pass

    # Recalculate threat statuses for all affected countermeasures (and their linked threats)
    for cm_id in affected_countermeasures:
        try:
            cm = InstanceCountermeasure.objects.get(id=cm_id)
            recalculate_all_threats_for_countermeasure(cm)
        except InstanceCountermeasure.DoesNotExist:
            pass

    return {"updated_count": updated_count}
