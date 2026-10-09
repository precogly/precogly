"""The threat analysis payload: one builder for every reader.

``build_threat_analysis`` is what the signed-in editor reads through
``ThreatModelViewSet.threats`` and what the shared magic-link page reads through
``MagicLinkAccessView``. Before this module the two views built the payload
separately and drifted (different key names, different field sets, F29).

Every scenario is one entry with a ``targets`` list (plan section 5.3); a
scenario on several targets appears once and the editor shows it under each.
``library_mismatch`` marks an edited generated scenario the library no longer
lists on its targets (section 4.1).

The shared page is an audience with an explicit allow-list: it sees the same
shape, minus every key that is not listed in ``SHARED_THREAT_KEYS`` and
``SHARED_COUNTERMEASURE_KEYS``. Adding a field to the signed-in payload never
exposes it on a public link by accident (M6).
"""

from django.db.models import Prefetch

from apps.systems.models import Flow, OrgsystemComponent
from apps.threats.models import CountermeasureThreatLink, InstanceThreat
from apps.threats.services import applicable_library_threats

SIGNED_IN = "signed_in"
SHARED = "shared"

# What a magic-link viewer may see of a threat. Everything else on the
# signed-in payload (decision rationale, impact description, threat actor,
# display order, the generated flag) stays off the public page.
SHARED_THREAT_KEYS = frozenset(
    {
        "id",
        "number",
        "display_number",
        "whole_system",
        "targets",
        "threat_library_id",
        "threat_name",
        "threat_description",
        "taxonomy_entries",
        "rating",
        "status",
        "triage_status",
        "countermeasures",
    }
)

SHARED_TARGET_KEYS = frozenset(
    {"type", "id", "name", "blueprint_id", "node_id", "edge_id", "dfd_id", "dfd_name"}
)

SHARED_COUNTERMEASURE_KEYS = frozenset(
    {
        "id",
        "number",
        "display_number",
        "targets",
        "countermeasure_library_id",
        "countermeasure_name",
        "countermeasure_description",
        "control_functions",
        "control_nature",
        "status",
        "priority",
        "evidence_url",
        "assigned_owner_email",
        "verified_by_email",
        "standard_mappings",
    }
)


def serialize_taxonomy_entries(threat):
    """Library and instance taxonomy entries, deduplicated, else the snapshot."""
    seen = {}

    if threat.threat_library:
        for join in threat.threat_library.taxonomy_entries.all():
            entry = join.taxonomy_entry
            key = (entry.taxonomy.slug, entry.external_id)
            seen[key] = {
                "taxonomy_slug": entry.taxonomy.slug,
                "taxonomy_name": entry.taxonomy.name,
                "external_id": entry.external_id,
                "title": entry.title,
                "reference_url": entry.reference_url,
                "source": "library",
            }

    for link in threat.instance_taxonomy_links.all():
        entry = link.taxonomy_entry
        key = (entry.taxonomy.slug, entry.external_id)
        if key not in seen:
            seen[key] = {
                "taxonomy_slug": entry.taxonomy.slug,
                "taxonomy_name": entry.taxonomy.name,
                "external_id": entry.external_id,
                "title": entry.title,
                "reference_url": entry.reference_url,
                "source": "instance",
            }

    if not seen:
        return threat.taxonomy_snapshot or []
    return list(seen.values())


def serialize_standard_mappings(countermeasure):
    """Library and instance compliance mappings; instance wins per requirement."""
    seen = {}

    if countermeasure.countermeasure_library:
        for mapping in countermeasure.countermeasure_library.standard_mappings.all():
            if mapping.requirement and mapping.requirement.framework:
                seen[mapping.requirement_id] = {
                    "id": mapping.id,
                    "framework_name": mapping.requirement.framework.name,
                    "framework_slug": mapping.requirement.framework.slug,
                    "section_code": mapping.requirement.section_code,
                    "requirement_description": mapping.requirement.description,
                    "sufficiency": mapping.sufficiency,
                }

    for mapping in countermeasure.instance_standard_mappings.all():
        if mapping.requirement and mapping.requirement.framework:
            seen[mapping.requirement_id] = {
                "id": mapping.id,
                "framework_name": mapping.requirement.framework.name,
                "framework_slug": mapping.requirement.framework.slug,
                "section_code": mapping.requirement.section_code,
                "requirement_description": mapping.requirement.description,
                "sufficiency": mapping.sufficiency,
            }
        else:
            seen[f"snapshot_{mapping.id}"] = {
                "id": mapping.id,
                "framework_name": mapping.framework_name,
                "framework_slug": "",
                "section_code": mapping.section_code,
                "requirement_description": mapping.requirement_description,
                "sufficiency": mapping.sufficiency,
            }

    return list(seen.values())


def threat_display_name(threat):
    return threat.threat_name or (
        threat.threat_library.name if threat.threat_library else None
    )


def flow_display_label(flow):
    if flow is None:
        return None
    if flow.label:
        return flow.label
    if flow.source_component and flow.dest_component:
        return f"{flow.source_component.name} → {flow.dest_component.name}"
    return None


def target_name(row):
    """The name a target is shown under: the row's name, or a flow's label."""
    if isinstance(row, Flow):
        return flow_display_label(row)
    return getattr(row, "name", None) or getattr(row, "label", None)


class CanvasIndex:
    """Where each row sits on the model's diagrams.

    Analysis-only rows (on no canvas) get synthetic ids, as the editor expects.
    """

    def __init__(self, threat_model):
        self.node_component_map = {}
        self.edge_flow_map = {}
        self.component_nodes = {}
        self.flow_edges = {}
        self.zone_nodes = {}
        self.boundary_edges = {}
        for dfd in threat_model.dfds.all():
            canvas_data = dfd.canvas_data or {}
            placement = {"dfd_id": str(dfd.id), "dfd_name": dfd.name}
            for node in canvas_data.get("nodes", []):
                node_id = node.get("id")
                data = node.get("data", {})
                if not node_id:
                    continue
                if data.get("component_id"):
                    self.node_component_map[node_id] = {
                        "component_id": data["component_id"],
                        **placement,
                    }
                    self.component_nodes.setdefault(
                        data["component_id"], {"node_id": node_id, **placement}
                    )
                if data.get("trust_zone_id"):
                    self.zone_nodes.setdefault(
                        data["trust_zone_id"], {"node_id": node_id, **placement}
                    )
            for edge in canvas_data.get("edges", []):
                edge_id = edge.get("id")
                data = edge.get("data", {})
                if not edge_id:
                    continue
                if data.get("dataflow_id"):
                    self.edge_flow_map[edge_id] = {
                        "flow_id": data["dataflow_id"],
                        **placement,
                    }
                    self.flow_edges.setdefault(
                        data["dataflow_id"], {"edge_id": edge_id, **placement}
                    )
                if data.get("trust_boundary_id"):
                    self.boundary_edges.setdefault(
                        data["trust_boundary_id"], {"edge_id": edge_id, **placement}
                    )

    def place(self, kind, row):
        """node_id or edge_id plus the diagram for a target row."""
        empty = {"dfd_id": None, "dfd_name": None}
        if kind == "component":
            found = self.component_nodes.get(row.id)
            if found is None:
                node_id = f"analysis-{row.id}"
                self.node_component_map.setdefault(
                    node_id, {"component_id": row.id, **empty, "is_analysis_only": True}
                )
                return {"node_id": node_id, "edge_id": None, **empty}
            return {"node_id": found["node_id"], "edge_id": None, **_placement(found)}
        if kind == "flow":
            found = self.flow_edges.get(row.id)
            if found is None:
                edge_id = f"analysis-flow-{row.id}"
                self.edge_flow_map.setdefault(
                    edge_id, {"flow_id": row.id, **empty, "is_analysis_only": True}
                )
                return {"node_id": None, "edge_id": edge_id, **empty}
            return {"node_id": None, "edge_id": found["edge_id"], **_placement(found)}
        if kind == "zone":
            found = self.zone_nodes.get(row.id)
            if found is None:
                return {"node_id": None, "edge_id": None, **empty}
            return {"node_id": found["node_id"], "edge_id": None, **_placement(found)}
        found = self.boundary_edges.get(row.id)
        if found is None:
            return {"node_id": None, "edge_id": None, **empty}
        return {"node_id": None, "edge_id": found["edge_id"], **_placement(found)}


def _placement(found):
    return {"dfd_id": found["dfd_id"], "dfd_name": found["dfd_name"]}


def serialize_targets(owner, index: CanvasIndex | None = None):
    """The ``targets`` list of a scenario or control: type, id, name, blueprint, canvas spot."""
    result = []
    for target_row in owner.targets.all():
        kind = target_row.target_kind
        row = target_row.target
        if row is None:
            continue
        entry = {
            "type": kind,
            "id": row.id,
            "name": target_name(row),
            "blueprint_id": row.blueprint_id,
        }
        if index is not None:
            entry.update(index.place(kind, row))
        result.append(entry)
    return result


def _also_mitigates(countermeasure, current_link_id, index):
    """The other scenarios a countermeasure is linked to, for the editor's hint."""
    other_links = (
        CountermeasureThreatLink.objects.filter(countermeasure=countermeasure)
        .exclude(id=current_link_id)
        .select_related("threat", "threat__threat_library")
        .prefetch_related(
            "threat__targets__component",
            "threat__targets__flow__source_component",
            "threat__targets__flow__dest_component",
            "threat__targets__zone",
            "threat__targets__boundary",
        )
    )
    return [
        {
            "threat_id": link.threat.id,
            "display_number": link.threat.display_number,
            "threat_name": threat_display_name(link.threat),
            "targets": serialize_targets(link.threat),
        }
        for link in other_links
    ]


def serialize_countermeasures_from_links(
    links, *, index=None, with_also_mitigates=True
):
    """Countermeasures attached to one scenario, through its links."""
    result = []
    for link in links:
        countermeasure = link.countermeasure
        library = countermeasure.countermeasure_library
        result.append(
            {
                "id": countermeasure.id,
                "countermeasure_library_id": countermeasure.countermeasure_library_id,
                "countermeasure_name": (library.name if library else None)
                or countermeasure.countermeasure_name,
                "countermeasure_description": countermeasure.countermeasure_description
                or (library.description if library else None),
                "control_functions": (library.control_functions if library else None)
                or countermeasure.control_functions,
                "control_nature": (library.control_nature if library else None)
                or countermeasure.control_nature,
                "status": countermeasure.status,
                "priority": countermeasure.priority,
                "due_date": countermeasure.due_date,
                "external_ticket_url": countermeasure.external_ticket_url,
                "evidence_url": countermeasure.evidence_url,
                "assigned_owner_email": countermeasure.assigned_owner.email
                if countermeasure.assigned_owner
                else None,
                "verified_by_email": countermeasure.verified_by.email
                if countermeasure.verified_by
                else None,
                "standard_mappings": serialize_standard_mappings(countermeasure),
                "display_order": link.display_order,
                "auto_generated": countermeasure.auto_generated,
                "number": countermeasure.number,
                "display_number": countermeasure.display_number,
                "targets": serialize_targets(countermeasure, index),
                "implemented_by": [
                    link.component_id for link in countermeasure.provider_links.all()
                ],
                "implemented_by_party": countermeasure.implemented_by_party,
                "source": countermeasure.source,
                "also_mitigates": _also_mitigates(countermeasure, link.id, index)
                if with_also_mitigates
                else [],
            }
        )
    return result


def _countermeasure_links_prefetch():
    return Prefetch(
        "countermeasure_links",
        queryset=CountermeasureThreatLink.objects.select_related(
            "countermeasure",
            "countermeasure__countermeasure_library",
            "countermeasure__assigned_owner",
            "countermeasure__verified_by",
        )
        .prefetch_related(
            "countermeasure__countermeasure_library__standard_mappings__requirement__framework",
            "countermeasure__instance_standard_mappings__requirement__framework",
            "countermeasure__targets__component",
            "countermeasure__targets__flow__source_component",
            "countermeasure__targets__flow__dest_component",
            "countermeasure__targets__zone",
            "countermeasure__targets__boundary",
            "countermeasure__provider_links",
        )
        .order_by("display_order"),
    )


def rating_to_dict(rating):
    from apps.threats.serializers import rating_to_dict as _rating_to_dict

    return _rating_to_dict(rating)


def threats_queryset(threat_model):
    """Every scenario of the model with what the payload needs prefetched."""
    return (
        InstanceThreat.objects.filter(threat_model=threat_model)
        .select_related("threat_library", "actor_persona")
        .prefetch_related(
            "threat_library__taxonomy_entries__taxonomy_entry__taxonomy",
            "instance_taxonomy_links__taxonomy_entry__taxonomy",
            "targets__component",
            "targets__flow__source_component",
            "targets__flow__dest_component",
            "targets__zone",
            "targets__boundary",
            _countermeasure_links_prefetch(),
        )
        .order_by("display_order", "number")
    )


class LibraryMismatchIndex:
    """Which library threats the libraries list for each component and flow."""

    def __init__(self):
        self._applicable = {}

    def applicable_ids(self, kind, row):
        key = (kind, row.id)
        if key not in self._applicable:
            self._applicable[key] = set(applicable_library_threats(row))
        return self._applicable[key]

    def mismatch(self, threat) -> bool:
        """True when an edited generated scenario is listed on none of its targets."""
        if threat.threat_library_id is None:
            return False
        checked = False
        for target_row in threat.targets.all():
            kind = target_row.target_kind
            if kind not in ("component", "flow"):
                continue
            checked = True
            if threat.threat_library_id in self.applicable_ids(kind, target_row.target):
                return False
        return checked


def _restrict(mapping, allowed_keys):
    return {key: value for key, value in mapping.items() if key in allowed_keys}


def build_threat_analysis(threat_model, *, audience=SIGNED_IN):
    """Every scenario of a model with its countermeasures and canvas positions.

    ``audience`` is ``SIGNED_IN`` (the full payload) or ``SHARED`` (the
    allow-listed subset for magic-link viewers).
    """
    if audience not in (SIGNED_IN, SHARED):
        raise ValueError(f"unknown audience {audience!r}")
    shared = audience == SHARED

    index = CanvasIndex(threat_model)
    mismatches = LibraryMismatchIndex()

    # Every component and flow appears in the maps, canvas or not, so the
    # editor can list targets that carry no threat yet.
    for component in OrgsystemComponent.objects.filter(
        blueprint__threat_model=threat_model
    ):
        index.place("component", component)
    for flow in Flow.objects.filter(
        blueprint__threat_model=threat_model
    ).select_related("source_component", "dest_component"):
        index.place("flow", flow)

    threats = []
    for threat in threats_queryset(threat_model):
        entry = {
            "id": threat.id,
            "number": threat.number,
            "display_number": threat.display_number,
            "whole_system": threat.whole_system,
            "auto_generated": threat.auto_generated,
            "library_mismatch": mismatches.mismatch(threat),
            "targets": serialize_targets(threat, index),
            "threat_library_id": threat.threat_library_id,
            "threat_name": threat_display_name(threat),
            "threat_description": threat.threat_description
            or (threat.threat_library.description if threat.threat_library else None),
            "taxonomy_entries": serialize_taxonomy_entries(threat),
            "rating": rating_to_dict(threat.rating),
            "status": threat.status,
            "triage_status": threat.triage_status,
            "decision_rationale": threat.decision_rationale,
            "display_order": threat.display_order,
            "impact_description": threat.impact_description,
            "threat_actor_text": threat.threat_actor_text,
            "actor_persona_id": threat.actor_persona_id,
            "actor_persona_name": threat.actor_persona.name
            if threat.actor_persona
            else None,
            "intent": threat.intent,
            "access_level": threat.access_level,
            "countermeasures": serialize_countermeasures_from_links(
                threat.countermeasure_links.all(),
                index=index,
                with_also_mitigates=not shared,
            ),
        }
        threats.append(entry)

    if shared:
        threats = [
            {
                **_restrict(threat, SHARED_THREAT_KEYS),
                "targets": [
                    _restrict(t, SHARED_TARGET_KEYS) for t in threat["targets"]
                ],
                "countermeasures": [
                    {
                        **_restrict(countermeasure, SHARED_COUNTERMEASURE_KEYS),
                        "targets": [
                            _restrict(target, SHARED_TARGET_KEYS)
                            for target in countermeasure["targets"]
                        ],
                    }
                    for countermeasure in threat["countermeasures"]
                ],
            }
            for threat in threats
        ]

    return {
        "threat_model_id": str(threat_model.id),
        "threats": threats,
        "total_count": len(threats),
        "node_component_map": index.node_component_map,
        "edge_flow_map": index.edge_flow_map,
    }
