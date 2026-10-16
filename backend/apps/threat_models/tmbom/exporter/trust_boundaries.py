"""``threats.trustBoundaries[]`` (step 6 slice, plan section 9.4).

One entry per boundary of type ``trust``, with its own ref. ``trustLevel`` is
written only when both zones have a level, and is then the lower of the two
mapped by fixed ranges (H12). ``threatsAtBoundary`` and
``controlsAtBoundary`` are derived from the scenarios and controls that
target the boundary.
"""

from ..refs import RefRegistry
from ..spec_values import trust_level_name


def export_trust_boundaries(threat_model, refs: RefRegistry) -> list[dict]:
    from apps.threats.models import InstanceCountermeasureTarget, InstanceThreatTarget

    entries = []
    boundaries = (
        threat_model.boundaries.filter(boundary_type="trust")
        .select_related("zone_a", "zone_b")
        .order_by("id")
    )
    for boundary in boundaries:
        entry = {
            "bom-ref": refs.fixed(f"trustboundary-{boundary.pk}"),
            "boundary": refs.ref("boundary", boundary),
        }
        if boundary.label:
            entry["name"] = boundary.label
        if boundary.description:
            entry["description"] = boundary.description
        levels = [boundary.zone_a.trust_level, boundary.zone_b.trust_level]
        if all(level is not None for level in levels):
            entry["trustLevel"] = trust_level_name(min(levels))
        threats = [
            refs.ref("scenario", row.threat)
            for row in InstanceThreatTarget.objects.filter(boundary=boundary)
            .select_related("threat")
            .order_by("threat__number")
        ]
        if threats:
            entry["threatsAtBoundary"] = threats
        controls = [
            refs.ref("control", row.countermeasure)
            for row in InstanceCountermeasureTarget.objects.filter(boundary=boundary)
            .select_related("countermeasure")
            .order_by("countermeasure__number")
        ]
        if controls:
            entry["controlsAtBoundary"] = controls
        entries.append(entry)
    return entries
