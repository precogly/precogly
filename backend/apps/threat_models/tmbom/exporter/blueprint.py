"""One spec blueprint per Precogly blueprint (step 1 slice).

Assets (processes and external actors), data stores, data sets, zones,
boundaries, flows, visualizations and scope. The fields later steps add (zone
and boundary types, crossing requirements, flow types, authentication lists)
plug into the builders here.
"""

import base64
import json

from apps.systems.crossing import AUTHENTICATION_TYPES, AUTHORIZATION_TYPES
from apps.systems.models import (
    ComponentDataAsset,
    DataAsset,
    Flow,
    FlowAsset,
    OrgsystemComponent,
)

from ..properties import PropertyOwner, make_property
from ..refs import RefRegistry
from ..spec_values import (
    DATA_CLASSIFICATIONS,
    DATA_STORE_TYPE_TO_SPEC,
    DIAGRAM_TYPE_TO_VISUALIZATION_TYPE,
    PRECOGLY_DFD_MEDIA_TYPE,
    custom_type,
)

DATASTORE = "datastore"


def _is_datastore(component) -> bool:
    return component.category == DATASTORE


def asset_kind(component) -> str:
    """The ref kind of a component: ``datastore`` or ``asset``."""
    return "datastore" if _is_datastore(component) else "asset"


def component_ref(component, refs: RefRegistry) -> str:
    return refs.ref(asset_kind(component), component)


def reserve_blueprint_refs(blueprints, refs: RefRegistry) -> None:
    """Note every imported ref before issuing any, so clashes are seen."""
    for blueprint in blueprints:
        refs.reserve_stored([blueprint])
        refs.reserve_stored(blueprint.components.all())
        refs.reserve_stored(blueprint.zones.all())
        refs.reserve_stored(blueprint.boundaries.all())
        refs.reserve_stored(blueprint.flows.all())
        refs.reserve_stored(blueprint.data_assets.all())
        refs.reserve_stored(blueprint.dfds.all())


def _library_properties(component, refs: RefRegistry) -> list[dict]:
    """The library link, its copies and the parent, shared by assets and stores."""
    properties = []
    library = component.component_library
    if library is not None and library.qualified_slug:
        properties.append(
            make_property(
                "precogly:library", PropertyOwner.ASSET, library.qualified_slug
            )
        )
    if component.component_type:
        properties.append(
            make_property(
                "precogly:component-type", PropertyOwner.ASSET, component.component_type
            )
        )
    if component.parent_component_id:
        properties.append(
            make_property(
                "precogly:parent",
                PropertyOwner.ASSET,
                component_ref(component.parent_component, refs),
            )
        )
    return properties


def _asset(component, refs: RefRegistry) -> dict:
    asset = {
        "bom-ref": component_ref(component, refs),
        "name": component.name,
        "type": (_kept_type(component, "") if not component.kind else None)
        or component.effective_kind,
    }
    if component.description:
        asset["description"] = component.description
    if component.zone_id:
        asset["zone"] = refs.ref("zone", component.zone)
    properties = []
    if component.category:
        properties.append(
            make_property("precogly:category", PropertyOwner.ASSET, component.category)
        )
    if component.actor_type:
        properties.append(
            make_property(
                "precogly:actor-type", PropertyOwner.ASSET, component.actor_type
            )
        )
    if component.data_sensitivity_level:
        properties.append(
            make_property(
                "precogly:data-sensitivity",
                PropertyOwner.ASSET,
                component.data_sensitivity_level,
            )
        )
    if component.orgsystem_id and component.orgsystem.lifecycle_state:
        properties.append(
            make_property(
                "precogly:lifecycle-state",
                PropertyOwner.ASSET,
                component.orgsystem.lifecycle_state,
            )
        )
    properties.extend(_library_properties(component, refs))
    if component.provider:
        properties.append(
            make_property("precogly:provider", PropertyOwner.ASSET, component.provider)
        )
    if properties:
        asset["properties"] = properties
    return asset


def _data_store_type(component) -> str | dict:
    value = (component.data_store_type or "").strip()
    if not value:
        return custom_type("unspecified")
    return DATA_STORE_TYPE_TO_SPEC.get(value.lower(), custom_type(value))


def _data_store(component, refs: RefRegistry, datasets_by_component: dict) -> dict:
    store = {
        "bom-ref": component_ref(component, refs),
        "name": component.name,
        "type": _data_store_type(component),
    }
    if component.description:
        store["description"] = component.description
    vendor = component.provider or (
        component.component_library.provider if component.component_library else ""
    )
    if vendor:
        store["vendor"] = vendor
    if component.zone_id:
        store["zone"] = refs.ref("zone", component.zone)
    linked = datasets_by_component.get(component.id, [])
    if linked:
        store["dataSets"] = [refs.ref("dataset", data_asset) for data_asset in linked]
    properties = []
    if component.data_store_type and not isinstance(store["type"], dict):
        properties.append(
            make_property(
                "precogly:data-store-type",
                PropertyOwner.DATA_STORE,
                component.data_store_type,
            )
        )
    if component.data_sensitivity_level:
        properties.append(
            make_property(
                "precogly:data-sensitivity",
                PropertyOwner.ASSET,
                component.data_sensitivity_level,
            )
        )
    properties.extend(_library_properties(component, refs))
    if properties:
        store["properties"] = properties
    return store


def profile_ref(data_asset, refs: RefRegistry) -> str:
    """The ref of the data set's one profile, which flows point at."""
    return f"{refs.ref('dataset', data_asset)}-profile"


def _data_set(
    data_asset,
    refs: RefRegistry,
    placements: list,
    placement_details: list,
    *,
    carried: bool,
) -> dict:
    entry = {
        "bom-ref": refs.ref("dataset", data_asset),
        "name": data_asset.name,
        # Required by the schema; the name is the fallback (section 9.4).
        "description": data_asset.description or data_asset.name,
    }
    classification = (data_asset.classification or "").strip().lower()
    if classification or carried:
        profile = {
            "bom-ref": profile_ref(data_asset, refs),
            "name": f"{data_asset.name} profile",
        }
        if classification:
            profile["classification"] = (
                classification
                if classification in DATA_CLASSIFICATIONS
                else custom_type(data_asset.classification)
            )
        if data_asset.compliance_tags:
            profile["regulations"] = [str(tag) for tag in data_asset.compliance_tags]
        entry["dataProfiles"] = [profile]
    if placements:
        entry["placements"] = placements
    properties = []
    for name, value in (
        ("precogly:confidentiality", data_asset.confidentiality),
        ("precogly:integrity", data_asset.integrity),
        ("precogly:availability", data_asset.availability),
    ):
        if value and value != DataAsset.Sensitivity.MEDIUM:
            properties.append(make_property(name, PropertyOwner.DATA_SET, value))
    if data_asset.data_sensitivity:
        properties.append(
            make_property(
                "precogly:data-sensitivity-tags",
                PropertyOwner.DATA_SET,
                list(data_asset.data_sensitivity),
            )
        )
    if placement_details:
        properties.append(
            make_property(
                "precogly:placements", PropertyOwner.DATA_SET, placement_details
            )
        )
    if properties:
        entry["properties"] = properties
    return entry


def _flow_data(flow, refs: RefRegistry, links: list) -> tuple[list[str], list[dict]]:
    """``(profile refs, per data set protection details)`` for a flow's links."""
    profiles = []
    details = []
    for link in links:
        profiles.append(profile_ref(link.data_asset, refs))
        fields = {
            "protectionMethod": link.protection_method,
            "encryptionType": link.encryption_type,
            "format": link.format,
            "sensitivityOverride": link.sensitivity_override,
        }
        if any(fields.values()):
            details.append(
                {"dataSet": refs.ref("dataset", link.data_asset)}
                | {key: value for key, value in fields.items() if value}
            )
    return profiles, details


def _kept_type(row, default: str):
    """A custom type object an import kept, as long as the row still has the default (L9)."""
    kept = ((row.format_metadata or {}).get("cyclonedx") or {}).get("custom_type")
    if isinstance(kept, dict) and kept.get("name"):
        return kept
    return None


def _zone(zone, refs: RefRegistry) -> dict:
    entry = {
        "bom-ref": refs.ref("zone", zone),
        "name": zone.name,
        "type": (_kept_type(zone, "trust") if zone.zone_type == "trust" else None)
        or zone.zone_type,
    }
    if zone.description:
        entry["description"] = zone.description
    if zone.parent_id:
        entry["parent"] = refs.ref("zone", zone.parent)
    if zone.trust_level is not None:
        entry["properties"] = [
            make_property("precogly:trust-level", PropertyOwner.ZONE, zone.trust_level)
        ]
    return entry


def _crossing_requirements(boundary) -> dict:
    """The spec object; the booleans are written only when true (M14, S4)."""
    requirements = {}
    if boundary.authentication:
        requirements["authentication"] = [
            value if value in AUTHENTICATION_TYPES else custom_type(value)
            for value in boundary.authentication
        ]
    if boundary.authorization:
        requirements["authorization"] = [
            value if value in AUTHORIZATION_TYPES else custom_type(value)
            for value in boundary.authorization
        ]
    for field, key in (
        ("data_validation", "dataValidation"),
        ("data_transformation", "dataTransformation"),
        ("logging", "logging"),
        ("monitoring", "monitoring"),
    ):
        if getattr(boundary, field):
            requirements[key] = True
    if boundary.rate_limit:
        requirements["rateLimit"] = boundary.rate_limit
    if boundary.protocols:
        requirements["protocols"] = [str(p) for p in boundary.protocols]
    return requirements


def _boundary(boundary, refs: RefRegistry) -> dict:
    entry = {
        "bom-ref": refs.ref("boundary", boundary),
        "zones": [refs.ref("zone", boundary.zone_a), refs.ref("zone", boundary.zone_b)],
        "type": (
            _kept_type(boundary, "trust") if boundary.boundary_type == "trust" else None
        )
        or boundary.boundary_type,
    }
    if boundary.label:
        entry["name"] = boundary.label
    # Zones an import carried beyond the first two (M11) stay with the row.
    extra_zones = ((boundary.format_metadata or {}).get("cyclonedx") or {}).get(
        "extra_zones"
    )
    for ref in extra_zones or []:
        if (
            isinstance(ref, str)
            and refs.will_resolve(ref)
            and ref not in entry["zones"]
        ):
            entry["zones"].append(ref)
    requirements = _crossing_requirements(boundary)
    if requirements:
        entry["crossingRequirements"] = requirements
    if boundary.session_management:
        entry["sessionManagement"] = dict(boundary.session_management)
    return entry


def flow_name(flow) -> str:
    """The label, else "source to destination" (required by the schema)."""
    if flow.label:
        return flow.label
    return f"{flow.source_component.name} to {flow.dest_component.name}"


def _flow(flow, refs: RefRegistry, links: list = ()) -> dict:
    entry = {
        "bom-ref": refs.ref("flow", flow),
        "name": flow_name(flow),
        "type": (_kept_type(flow, "data") if flow.flow_type == "data" else None)
        or flow.flow_type,
        "source": component_ref(flow.source_component, refs),
        "destination": component_ref(flow.dest_component, refs),
    }
    if flow.description:
        entry["description"] = flow.description
    if flow.encrypted:
        entry["encrypted"] = True
    if flow.protocol:
        entry["protocols"] = [flow.protocol]
    if flow.authentication:
        entry["authentication"] = [
            value if value in AUTHENTICATION_TYPES else custom_type(value)
            for value in flow.authentication
        ]
    if flow.authorization:
        entry["authorization"] = [
            value if value in AUTHORIZATION_TYPES else custom_type(value)
            for value in flow.authorization
        ]
    properties = []
    if flow.port is not None:
        properties.append(make_property("precogly:port", PropertyOwner.FLOW, flow.port))
    if flow.has_sensitive_data:
        properties.append(
            make_property("precogly:has-sensitive-data", PropertyOwner.FLOW, True)
        )
    if flow.data_classification:
        properties.append(
            make_property(
                "precogly:data-classification",
                PropertyOwner.FLOW,
                list(flow.data_classification),
            )
        )
    profiles, details = _flow_data(flow, refs, list(links))
    kept_inline = ((flow.format_metadata or {}).get("cyclonedx") or {}).get(
        "inline_data_profiles"
    )
    profiles.extend(p for p in kept_inline or [] if isinstance(p, dict))
    if profiles:
        entry["dataProfiles"] = profiles
    if details:
        properties.append(
            make_property("precogly:flow-data", PropertyOwner.FLOW, details)
        )
    if properties:
        entry["properties"] = properties
    return entry


def _canvas_with_refs(dfd, refs: RefRegistry, blueprint) -> dict:
    """The canvas with each synced node and edge annotated by its bom-ref.

    Import maps the refs back to the new rows' ids, so a canvas survives a
    move between installations without name matching.
    """
    canvas = json.loads(json.dumps(dfd.canvas_data or {}))
    components = {c.id: c for c in blueprint.components.all()}
    zones = {z.id: z for z in blueprint.zones.all()}
    flows = {f.id: f for f in blueprint.flows.all()}
    boundaries = {b.id: b for b in blueprint.boundaries.all()}
    for node in canvas.get("nodes", []):
        data = node.setdefault("data", {})
        component = components.get(data.get("component_id"))
        zone = zones.get(data.get("trust_zone_id"))
        if component is not None:
            data["bom_ref"] = component_ref(component, refs)
        elif zone is not None:
            data["bom_ref"] = refs.ref("zone", zone)
    for edge in canvas.get("edges", []):
        data = edge.setdefault("data", {})
        flow = flows.get(data.get("dataflow_id"))
        boundary = boundaries.get(data.get("trust_boundary_id"))
        if flow is not None:
            data["bom_ref"] = refs.ref("flow", flow)
        elif boundary is not None:
            data["bom_ref"] = refs.ref("boundary", boundary)
    return canvas


def _visualization(dfd, refs: RefRegistry, blueprint) -> dict:
    canvas = _canvas_with_refs(dfd, refs, blueprint)
    content = base64.b64encode(
        json.dumps(canvas, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    return {
        "bom-ref": refs.ref("visualization", dfd),
        "name": dfd.name,
        "type": {
            "type": DIAGRAM_TYPE_TO_VISUALIZATION_TYPE.get(
                dfd.diagram_type, "data-flow"
            )
        },
        "attachment": {
            "mediaType": PRECOGLY_DFD_MEDIA_TYPE,
            "encoding": "base64",
            "content": content,
        },
        "properties": [
            make_property(
                "precogly:diagram-type", PropertyOwner.VISUALIZATION, dfd.diagram_type
            ),
            make_property(
                "precogly:primary", PropertyOwner.VISUALIZATION, dfd.is_primary
            ),
        ],
    }


def _scope(blueprint, components, refs: RefRegistry) -> dict | None:
    items = list(blueprint.out_of_scope_items.all())
    if not items and not blueprint.scope_description:
        return None
    scope = {"name": f"{blueprint.name} scope"}
    if blueprint.scope_description:
        scope["description"] = blueprint.scope_description
    by_name = {}
    for component in components:
        by_name.setdefault(component.name, component)
    excluded = []
    properties = []
    for item in items:
        component = by_name.get(item.name)
        if component is not None:
            excluded.append(component_ref(component, refs))
        else:
            properties.append(
                make_property(
                    "precogly:out-of-scope",
                    PropertyOwner.SCOPE,
                    {"name": item.name, "reason": item.reason},
                )
            )
    if excluded:
        scope["excludedComponents"] = excluded
    if properties:
        scope["properties"] = properties
    return scope


def export_blueprint(blueprint, refs: RefRegistry) -> dict:
    components = list(
        OrgsystemComponent.objects.filter(blueprint=blueprint)
        .select_related("component_library", "zone", "orgsystem")
        .order_by("id")
    )
    zones = list(blueprint.zones.select_related("parent").order_by("id"))
    boundaries = list(
        blueprint.boundaries.select_related("zone_a", "zone_b").order_by("id")
    )
    flows = list(
        Flow.objects.filter(blueprint=blueprint)
        .select_related("source_component", "dest_component")
        .order_by("id")
    )
    data_assets = list(blueprint.data_assets.order_by("id"))
    dfds = list(blueprint.dfds.order_by("-is_primary", "id"))

    datasets_by_component: dict = {}
    placements_by_dataset: dict = {}
    placement_details_by_dataset: dict = {}
    for link in (
        ComponentDataAsset.objects.filter(component__blueprint=blueprint)
        .select_related("component", "data_asset")
        .order_by("id")
    ):
        if _is_datastore(link.component):
            datasets_by_component.setdefault(link.component_id, []).append(
                link.data_asset
            )
            store_ref = component_ref(link.component, refs)
            placements_by_dataset.setdefault(link.data_asset_id, []).append(
                {"dataStore": store_ref, "encrypted": bool(link.encrypted)}
            )
            if link.volume or link.data_state != ComponentDataAsset.DataState.AT_REST:
                detail = {"dataStore": store_ref, "dataState": link.data_state}
                if link.volume:
                    detail["volume"] = link.volume
                placement_details_by_dataset.setdefault(link.data_asset_id, []).append(
                    detail
                )
    flow_links_by_flow: dict = {}
    for link in (
        FlowAsset.objects.filter(flow__blueprint=blueprint)
        .select_related("data_asset")
        .order_by("id")
    ):
        flow_links_by_flow.setdefault(link.flow_id, []).append(link)
    carried_dataset_ids = {
        link.data_asset_id for links in flow_links_by_flow.values() for link in links
    }

    entry = {
        "bom-ref": refs.ref("blueprint", blueprint),
        "name": blueprint.name,
        "modelTypes": list(blueprint.model_types or ["data-flow"]),
    }
    if blueprint.description:
        entry["description"] = blueprint.description

    scope = _scope(blueprint, components, refs)
    if scope:
        entry["scope"] = scope

    assets = [_asset(c, refs) for c in components if not _is_datastore(c)]
    if assets:
        entry["assets"] = assets
    stores = [
        _data_store(c, refs, datasets_by_component)
        for c in components
        if _is_datastore(c)
    ]
    if stores:
        entry["dataStores"] = stores
    if data_assets:
        entry["dataSets"] = [
            _data_set(
                d,
                refs,
                placements_by_dataset.get(d.id, []),
                placement_details_by_dataset.get(d.id, []),
                carried=d.id in carried_dataset_ids,
            )
            for d in data_assets
        ]
    if zones:
        entry["zones"] = [_zone(z, refs) for z in zones]
    if boundaries:
        entry["boundaries"] = [_boundary(b, refs) for b in boundaries]
    if flows:
        entry["flows"] = [
            _flow(f, refs, flow_links_by_flow.get(f.id, [])) for f in flows
        ]
    if dfds:
        entry["visualizations"] = [_visualization(d, refs, blueprint) for d in dfds]
    return entry
