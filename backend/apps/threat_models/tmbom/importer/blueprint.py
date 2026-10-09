"""Import one spec blueprint into one Precogly blueprint (step 1 slice).

The first blueprint of the document reuses the model's default blueprint; the
rest are created. Zones come first (parents second pass), then boundaries,
assets, data stores, data sets, flows, scope and visualizations.
"""

import base64
import json

from apps.diagrams.canvas import normalize_canvas
from apps.diagrams.models import DFD
from apps.diagrams.services import update_crosses_boundary
from apps.systems.crossing import (
    ASSET_TYPES,
    BOUNDARY_TYPES,
    FLOW_TYPES,
    ZONE_TYPES,
    clean_session_management,
    clean_type_list,
)
from apps.systems.models import (
    Boundary,
    ComponentDataAsset,
    ComponentLibrary,
    DataAsset,
    Flow,
    FlowAsset,
    OrgsystemComponent,
    Zone,
)
from apps.threat_models.models import MODEL_TYPES, Blueprint, OutOfScopeItem

from ..dfd_layout import build_canvas
from ..passthrough import keep_unknown
from ..properties import PropertyOwner, read_properties
from ..refs import remember_ref, stored_ref
from ..spec_values import (
    ASSET_TYPE_TO_CATEGORY,
    DEFAULT_CATEGORY,
    PRECOGLY_DFD_MEDIA_TYPE,
    SPEC_TO_DATA_STORE_TYPE,
    type_name,
)
from .context import import_assumptions

VALID_CATEGORIES = {
    "process",
    "datastore",
    "external_human_actor",
    "external_system_actor",
}


def _label(data: dict, fallback: str = "unnamed") -> str:
    return str(data.get("name") or data.get("bom-ref") or fallback)[:255]


def _keep_ref(row, data: dict, kind: str | None = None) -> None:
    remember_ref(row, data.get("bom-ref", ""))
    if kind is not None:
        keep_unknown(row, data, kind)
    row.save(update_fields=["format_metadata"])


def _model_types(data: dict, context) -> list[str]:
    raw = data.get("modelTypes") or []
    kept = [value for value in raw if isinstance(value, str) and value in MODEL_TYPES]
    dropped = [value for value in raw if value not in kept]
    if dropped:
        context.warn(
            f"Blueprint '{_label(data)}': model type(s) {dropped} are not spec "
            "values and were left out."
        )
    return kept or ["data-flow"]


def _blueprint_row(data: dict, threat_model, context, is_first: bool) -> Blueprint:
    values = {
        "name": _label(data, threat_model.name),
        "description": str(data.get("description") or ""),
        "model_types": _model_types(data, context),
        "scope_description": str((data.get("scope") or {}).get("description") or ""),
    }
    if is_first:
        blueprint = threat_model.default_blueprint
        for key, value in values.items():
            setattr(blueprint, key, value)
        blueprint.save()
    else:
        blueprint = Blueprint.objects.create(
            threat_model=threat_model,
            display_order=threat_model.blueprints.count(),
            **values,
        )
    _keep_ref(blueprint, data, "blueprint")
    context.register(data.get("bom-ref"), "blueprint", blueprint)
    context.count("blueprints")
    return blueprint


def _spec_type(raw, allowed, default: str, context, label: str, what: str):
    """``(value, kept custom object)`` for a type field (L9).

    A spec value is stored as is. A custom object, or a value outside the
    enum, gives the default with the original kept for export and a warning.
    """
    name = type_name(raw)
    if isinstance(raw, dict):
        if name in allowed:
            return name, None
        context.warn(
            f"{what} '{label}': type '{name}' is a custom type; stored as "
            f"'{default}' and kept for export."
        )
        return default, raw
    if not name:
        return default, None
    if name in allowed:
        return name, None
    context.warn(
        f"{what} '{label}': type '{name}' is not a spec value; stored as "
        f"'{default}' and kept for export."
    )
    return default, {"name": name}


def _keep_custom_type(row, kept) -> None:
    if kept is None:
        return
    metadata = dict(row.format_metadata or {})
    cyclonedx = dict(metadata.get("cyclonedx") or {})
    cyclonedx["custom_type"] = kept
    metadata["cyclonedx"] = cyclonedx
    row.format_metadata = metadata
    row.save(update_fields=["format_metadata"])


def _import_zones(data: dict, blueprint, context) -> None:
    zones = [z for z in data.get("zones") or [] if isinstance(z, dict)]
    created = []
    for zone_data in zones:
        label = _label(zone_data, "zone")
        zone_type, kept = _spec_type(
            zone_data.get("type"), ZONE_TYPES, "trust", context, label, "Zone"
        )
        properties = read_properties(zone_data.get("properties"), PropertyOwner.ZONE)
        trust_level = properties.get("precogly:trust-level")
        if isinstance(trust_level, int) and not 0 <= trust_level <= 100:
            trust_level = None
        zone = Zone.objects.create(
            blueprint=blueprint,
            name=label,
            description=str(zone_data.get("description") or ""),
            zone_type=zone_type,
            trust_level=trust_level if isinstance(trust_level, int) else None,
        )
        _keep_ref(zone, zone_data, "zone")
        _keep_custom_type(zone, kept)
        context.register(zone_data.get("bom-ref"), "zone", zone)
        created.append((zone, zone_data))
        context.count("zones")
    for zone, zone_data in created:
        parent_ref = zone_data.get("parent")
        if not parent_ref:
            continue
        parent = context.resolve(parent_ref, "zone")
        if parent is None or parent.blueprint_id != blueprint.id:
            context.warn(
                f"Zone '{zone.name}': parent '{parent_ref}' is not a zone of this "
                "blueprint; the zone was imported without a parent."
            )
            continue
        zone.parent = parent
        zone.save(update_fields=["parent"])


def _crossing_fields(boundary_data: dict, context, label: str) -> dict:
    """The crossing requirement and session management fields of a boundary.

    A list that mixes ``none`` with other values, or a malformed object, is
    stored empty and warned about (M15); the original is not kept because the
    row has nothing to attach it to that export would read.
    """
    requirements = boundary_data.get("crossingRequirements")
    requirements = requirements if isinstance(requirements, dict) else {}
    fields = {}
    for key, field in (
        ("authentication", "authentication"),
        ("authorization", "authorization"),
    ):
        try:
            fields[field] = clean_type_list(requirements.get(key), field=field)
        except ValueError as error:
            context.warn(f"Boundary '{label}': {error} Stored empty.")
            fields[field] = []
    for key, field in (
        ("dataValidation", "data_validation"),
        ("dataTransformation", "data_transformation"),
        ("logging", "logging"),
        ("monitoring", "monitoring"),
    ):
        fields[field] = bool(requirements.get(key, False))
    fields["rate_limit"] = str(requirements.get("rateLimit") or "")[:255]
    try:
        fields["protocols"] = clean_type_list(
            requirements.get("protocols"), field="protocols"
        )
    except ValueError as error:
        context.warn(f"Boundary '{label}': {error} Stored empty.")
        fields["protocols"] = []
    try:
        fields["session_management"] = clean_session_management(
            boundary_data.get("sessionManagement")
        )
    except ValueError as error:
        context.warn(f"Boundary '{label}': {error} Session management stored empty.")
        fields["session_management"] = {}
    return fields


def _import_boundaries(data: dict, blueprint, context) -> None:
    for boundary_data in data.get("boundaries") or []:
        if not isinstance(boundary_data, dict):
            continue
        zone_refs = boundary_data.get("zones") or []
        zones = [context.resolve(ref, "zone") for ref in zone_refs]
        zones = [z for z in zones if z is not None and z.blueprint_id == blueprint.id]
        label = _label(boundary_data, "boundary")
        if len(zones) < 2:
            context.warn(
                f"Boundary '{label}' does not join two zones of this blueprint "
                "and was skipped."
            )
            continue
        if len(zone_refs) > 2:
            context.warn(
                f"Boundary '{label}' joins {len(zone_refs)} zones; Precogly keeps "
                "the first two and writes the rest back on export."
            )
        boundary_type, kept = _spec_type(
            boundary_data.get("type"),
            BOUNDARY_TYPES,
            "trust",
            context,
            label,
            "Boundary",
        )
        boundary = Boundary.objects.create(
            blueprint=blueprint,
            zone_a=zones[0],
            zone_b=zones[1],
            label=str(boundary_data.get("name") or ""),
            boundary_type=boundary_type,
            **_crossing_fields(boundary_data, context, label),
        )
        _keep_ref(boundary, boundary_data, "boundary")
        _keep_custom_type(boundary, kept)
        if len(zone_refs) > 2:
            metadata = dict(boundary.format_metadata or {})
            cyclonedx = dict(metadata.get("cyclonedx") or {})
            cyclonedx["extra_zones"] = [
                ref for ref in zone_refs[2:] if isinstance(ref, str)
            ]
            metadata["cyclonedx"] = cyclonedx
            boundary.format_metadata = metadata
            boundary.save(update_fields=["format_metadata"])
        context.register(boundary_data.get("bom-ref"), "boundary", boundary)
        context.count("boundaries")


def _zone_for(data: dict, blueprint, context, label: str):
    zone_ref = data.get("zone")
    if not zone_ref:
        return None
    zone = context.resolve(zone_ref, "zone")
    if zone is None or zone.blueprint_id != blueprint.id:
        context.warn(
            f"'{label}': zone '{zone_ref}' was not found; left without a zone."
        )
        return None
    return zone


def _json_items(properties: dict, name: str) -> list:
    """The items of a JSON list property; repeated properties are concatenated."""
    items = []
    for value in properties.get(name) or []:
        items.extend(value if isinstance(value, list) else [value])
    return items


def _library_fields(properties: dict, context, label: str) -> dict:
    """The library link and the copies a component carries (M16).

    The document's copies win over the library's current values: they are
    what the exporting model had. A library that is not installed here is
    warned and the copies are kept as they are.
    """
    fields = {
        "component_type": str(properties.get("precogly:component-type") or "")[:100],
        "provider": str(properties.get("precogly:provider") or "")[:100],
    }
    slug = properties.get("precogly:library")
    if not slug:
        return fields
    library = ComponentLibrary.objects.filter(qualified_slug=str(slug)).first()
    if library is None:
        context.warn(
            f"'{label}': component library '{slug}' is not installed; the component "
            "keeps its copied fields without a library link."
        )
        return fields
    fields["component_library"] = library
    for key in ("component_type", "provider"):
        if not fields[key]:
            fields[key] = getattr(library, key) or ""
    return fields


def _link_parents(data: dict, blueprint, context) -> None:
    """``precogly:parent`` refs, applied once every component of the blueprint exists."""
    for key, owner in (
        ("assets", PropertyOwner.ASSET),
        ("dataStores", PropertyOwner.ASSET),
    ):
        for entry in data.get(key) or []:
            if not isinstance(entry, dict):
                continue
            parent_ref = read_properties(entry.get("properties"), owner).get(
                "precogly:parent"
            )
            if not parent_ref:
                continue
            component = context.resolve(entry.get("bom-ref"), "asset", "datastore")
            parent = context.resolve(parent_ref, "asset", "datastore")
            if component is None:
                continue
            if (
                parent is None
                or parent.blueprint_id != blueprint.id
                or parent == component
            ):
                context.warn(
                    f"'{component.name}': parent '{parent_ref}' is not a component of "
                    "this blueprint; imported without a parent."
                )
                continue
            component.parent_component = parent
            component.save(update_fields=["parent_component"])


def _import_assets(data: dict, blueprint, context) -> None:
    for asset_data in data.get("assets") or []:
        if not isinstance(asset_data, dict):
            continue
        label = _label(asset_data, "asset")
        properties = read_properties(asset_data.get("properties"), PropertyOwner.ASSET)
        category = properties.get("precogly:category")
        if category not in VALID_CATEGORIES:
            category = ASSET_TYPE_TO_CATEGORY.get(
                type_name(asset_data.get("type")), DEFAULT_CATEGORY
            )
        kind_name = type_name(asset_data.get("type"))
        kind, kept = (kind_name, None) if kind_name in ASSET_TYPES else ("", None)
        if kind_name and kind_name not in ASSET_TYPES:
            kept = (
                asset_data.get("type")
                if isinstance(asset_data.get("type"), dict)
                else {"name": kind_name}
            )
            context.warn(
                f"Asset '{label}': type '{kind_name}' is not a CycloneDX asset type; "
                "the kind derives from the category and the type is kept for export."
            )
        component = OrgsystemComponent.objects.create(
            blueprint=blueprint,
            name=label,
            description=str(asset_data.get("description") or ""),
            category=category,
            kind=kind,
            actor_type=str(properties.get("precogly:actor-type") or "")[:20],
            data_sensitivity_level=str(
                properties.get("precogly:data-sensitivity") or ""
            )[:20],
            zone=_zone_for(asset_data, blueprint, context, label),
            **_library_fields(properties, context, label),
        )
        _keep_ref(component, asset_data, "asset")
        _keep_custom_type(component, kept)
        ref_kind = "datastore" if category == "datastore" else "asset"
        context.register(asset_data.get("bom-ref"), ref_kind, component)
        context.count("components")


def _data_store_type(store_data: dict, properties: dict) -> str:
    own = properties.get("precogly:data-store-type")
    if own:
        return str(own)[:20]
    raw = store_data.get("type")
    name = type_name(raw)
    if isinstance(raw, dict):
        return "" if name == "unspecified" else name[:20]
    return SPEC_TO_DATA_STORE_TYPE.get(name, name)[:20]


def _import_data_stores(data: dict, blueprint, context) -> None:
    for store_data in data.get("dataStores") or []:
        if not isinstance(store_data, dict):
            continue
        label = _label(store_data, "data store")
        properties = read_properties(
            store_data.get("properties"), PropertyOwner.DATA_STORE
        )
        properties.update(
            read_properties(store_data.get("properties"), PropertyOwner.ASSET)
        )
        component = OrgsystemComponent.objects.create(
            blueprint=blueprint,
            name=label,
            description=str(store_data.get("description") or ""),
            category="datastore",
            data_store_type=_data_store_type(store_data, properties),
            data_sensitivity_level=str(
                properties.get("precogly:data-sensitivity") or ""
            )[:20],
            zone=_zone_for(store_data, blueprint, context, label),
            **_library_fields(
                {**properties, "precogly:provider": store_data.get("vendor")},
                context,
                label,
            ),
        )
        _keep_ref(component, store_data, "data-store")
        context.register(store_data.get("bom-ref"), "datastore", component)
        context.count("components")


def _classification(dataset_data: dict) -> str:
    for profile in dataset_data.get("dataProfiles") or []:
        if isinstance(profile, dict) and profile.get("classification"):
            return type_name(profile["classification"])[:100]
    return ""


def _import_data_sets(data: dict, blueprint, context) -> None:
    for dataset_data in data.get("dataSets") or []:
        if not isinstance(dataset_data, dict):
            continue
        label = _label(dataset_data, "data set")
        regulations = []
        for profile in dataset_data.get("dataProfiles") or []:
            if isinstance(profile, dict):
                regulations.extend(str(r) for r in profile.get("regulations") or [])
        properties = read_properties(
            dataset_data.get("properties"), PropertyOwner.DATA_SET
        )
        needs = {}
        for key in ("confidentiality", "integrity", "availability"):
            value = properties.get(f"precogly:{key}")
            if value in DataAsset.Sensitivity.values:
                needs[key] = value
            elif value:
                context.warn(
                    f"Data set '{label}': {key} '{value}' is not low, medium or high."
                )
        tags = _json_items(properties, "precogly:data-sensitivity-tags")
        data_asset = DataAsset.objects.create(
            blueprint=blueprint,
            name=label,
            description=str(dataset_data.get("description") or ""),
            classification=_classification(dataset_data),
            compliance_tags=regulations,
            data_sensitivity=[str(t) for t in tags],
            **needs,
        )
        _keep_ref(data_asset, dataset_data, "data-set")
        context.register(dataset_data.get("bom-ref"), "dataset", data_asset)
        for profile in dataset_data.get("dataProfiles") or []:
            if isinstance(profile, dict) and profile.get("bom-ref"):
                context.register(profile["bom-ref"], "profile", data_asset)
        context.count("data_assets")
        details = {
            detail.get("dataStore"): detail
            for detail in _json_items(properties, "precogly:placements")
            if isinstance(detail, dict)
        }
        for placement in dataset_data.get("placements") or []:
            if not isinstance(placement, dict):
                continue
            store = context.resolve(placement.get("dataStore"), "datastore")
            if store is None or store.blueprint_id != blueprint.id:
                context.warn(
                    f"Data set '{label}': placement on '{placement.get('dataStore')}' "
                    "points at no data store of this blueprint and was skipped."
                )
                continue
            detail = details.get(placement.get("dataStore"), {})
            data_state = detail.get("dataState")
            if data_state not in ComponentDataAsset.DataState.values:
                data_state = ComponentDataAsset.DataState.AT_REST
            ComponentDataAsset.objects.get_or_create(
                component=store,
                data_asset=data_asset,
                defaults={
                    "data_state": data_state,
                    "volume": str(detail.get("volume") or "")[:100],
                    "encrypted": bool(placement.get("encrypted", False)),
                },
            )

    # A data store may also list its data sets directly.
    for store_data in data.get("dataStores") or []:
        if not isinstance(store_data, dict):
            continue
        store = context.resolve(store_data.get("bom-ref"), "datastore")
        if store is None:
            continue
        for dataset_ref in store_data.get("dataSets") or []:
            data_asset = context.resolve(dataset_ref, "dataset")
            if data_asset is None:
                context.warn(
                    f"Data store '{store.name}': data set '{dataset_ref}' was not found."
                )
                continue
            ComponentDataAsset.objects.get_or_create(
                component=store,
                data_asset=data_asset,
                defaults={"data_state": ComponentDataAsset.DataState.AT_REST},
            )


def _import_actors(data: dict, blueprint, context) -> None:
    """Note the blueprint's actors; what each becomes is decided later (M10).

    An actor that is an end of a flow becomes an external actor component
    (``_component_for_actor``); one a scenario cites, or whose party is an
    attacker, becomes a persona (the threats importer); the rest are kept on
    the blueprint for re-emission.
    """
    kept = []
    for actor_data in data.get("actors") or []:
        if not isinstance(actor_data, dict) or not isinstance(
            actor_data.get("bom-ref"), str
        ):
            continue
        entry = {"blueprint": blueprint, "data": actor_data}
        context.actors[actor_data["bom-ref"]] = entry
        context.register(actor_data["bom-ref"], "actor", entry)
        kept.append(actor_data)
    if kept:
        metadata = dict(blueprint.format_metadata or {})
        cyclonedx = dict(metadata.get("cyclonedx") or {})
        cyclonedx["actors"] = kept
        metadata["cyclonedx"] = cyclonedx
        blueprint.format_metadata = metadata
        blueprint.save(update_fields=["format_metadata"])


def _component_for_actor(ref, blueprint, context):
    """An actor used as a flow end becomes an external actor component (M10)."""
    entry = context.resolve(ref, "actor")
    if entry is None:
        return None
    actor_data = entry["data"]
    party = actor_data.get("party") if isinstance(actor_data.get("party"), dict) else {}
    is_system = "system" in party or "organization" in party
    category = "external_system_actor" if is_system else "external_human_actor"
    label = str(
        actor_data.get("description")
        or (party.get("person") or {}).get("name")
        or (party.get("organization") or {}).get("name")
        or ref
    )[:255]
    component = OrgsystemComponent.objects.create(
        blueprint=entry["blueprint"],
        name=label,
        category=category,
        zone=_zone_for(actor_data, entry["blueprint"], context, label),
    )
    _keep_ref(component, actor_data)
    context.register(ref, "asset", component)
    context.count("components")
    return component


def _flow_end(ref, blueprint, context):
    end = context.resolve(ref, "asset", "datastore")
    if end is None:
        end = _component_for_actor(ref, blueprint, context)
    return end


def _import_flows(data: dict, blueprint, context) -> None:
    for flow_data in data.get("flows") or []:
        if not isinstance(flow_data, dict):
            continue
        label = _label(flow_data, "flow")
        source = _flow_end(flow_data.get("source"), blueprint, context)
        destination = _flow_end(flow_data.get("destination"), blueprint, context)
        ends = [end for end in (source, destination) if end is not None]
        if len(ends) < 2 or any(end.blueprint_id != blueprint.id for end in ends):
            context.warn(
                f"Flow '{label}' was skipped: its source or destination is not a "
                "component of this blueprint."
            )
            continue
        protocols = [p for p in flow_data.get("protocols") or [] if isinstance(p, str)]
        flow_type, kept = _spec_type(
            flow_data.get("type"), FLOW_TYPES, "data", context, label, "Flow"
        )
        lists = {}
        for key in ("authentication", "authorization"):
            try:
                lists[key] = clean_type_list(flow_data.get(key), field=key)
            except ValueError as error:
                context.warn(f"Flow '{label}': {error} Stored empty.")
                lists[key] = []
        properties = read_properties(flow_data.get("properties"), PropertyOwner.FLOW)
        port = properties.get("precogly:port")
        classification = [
            str(tag)
            for value in properties.get("precogly:data-classification", [])
            for tag in (value if isinstance(value, list) else [value])
        ]
        flow = Flow.objects.create(
            blueprint=blueprint,
            source_component=source,
            dest_component=destination,
            label=str(flow_data.get("name") or "")[:255],
            description=str(flow_data.get("description") or ""),
            flow_type=flow_type,
            protocol=protocols[0][:50] if protocols else "",
            port=port if isinstance(port, int) and not isinstance(port, bool) else None,
            encrypted=bool(flow_data.get("encrypted", False)),
            authentication=lists["authentication"],
            authorization=lists["authorization"],
            has_sensitive_data=bool(
                properties.get("precogly:has-sensitive-data", False)
            ),
            data_classification=classification,
        )
        _keep_ref(flow, flow_data, "flow")
        _keep_custom_type(flow, kept)
        context.register(flow_data.get("bom-ref"), "flow", flow)
        context.count("flows")
        _link_flow_data(flow, flow_data, properties, blueprint, context, label)


_FLOW_DATA_FIELDS = {
    "protectionMethod": "protection_method",
    "encryptionType": "encryption_type",
    "format": "format",
    "sensitivityOverride": "sensitivity_override",
}


def _link_flow_data(flow, flow_data: dict, properties: dict, blueprint, context, label):
    """The data sets a flow carries: profile refs, with ``precogly:flow-data`` details."""
    details = {
        detail.get("dataSet"): detail
        for detail in _json_items(properties, "precogly:flow-data")
        if isinstance(detail, dict)
    }
    inline = []
    for entry in flow_data.get("dataProfiles") or []:
        if not isinstance(entry, str):
            inline.append(entry)
            continue
        data_asset = context.resolve(entry, "profile")
        if data_asset is None or data_asset.blueprint_id != blueprint.id:
            context.warn(
                f"Flow '{label}': data profile '{entry}' is not a data set of this "
                "blueprint; the link was skipped."
            )
            continue
        detail = details.get(stored_ref(data_asset) or "", {})
        fields = {
            field: str(detail.get(key) or "")[:50]
            for key, field in _FLOW_DATA_FIELDS.items()
        }
        if fields["protection_method"] not in FlowAsset.ProtectionMethod.values:
            if fields["protection_method"]:
                context.warn(
                    f"Flow '{label}': protection method "
                    f"'{fields['protection_method']}' is not one of ours; left empty."
                )
            fields["protection_method"] = ""
        fields["sensitivity_override"] = fields["sensitivity_override"][:20]
        FlowAsset.objects.get_or_create(
            flow=flow, data_asset=data_asset, defaults=fields
        )
    if inline:
        metadata = dict(flow.format_metadata or {})
        cyclonedx = dict(metadata.get("cyclonedx") or {})
        cyclonedx["inline_data_profiles"] = inline
        metadata["cyclonedx"] = cyclonedx
        flow.format_metadata = metadata
        flow.save(update_fields=["format_metadata"])
        context.warn(
            f"Flow '{label}': {len(inline)} inline data profile(s) are kept for export "
            "but not linked to a data set."
        )


def _import_scope(data: dict, blueprint, context) -> None:
    scope = data.get("scope") or {}
    if not isinstance(scope, dict):
        return
    for ref in scope.get("excludedComponents") or []:
        component = context.resolve(ref, "asset", "datastore")
        if component is None:
            context.warn(f"Scope: excluded component '{ref}' was not found; skipped.")
            continue
        OutOfScopeItem.objects.create(blueprint=blueprint, name=component.name)
        context.count("out_of_scope_items")
    unknown_scope = {
        k: v
        for k, v in scope.items()
        if k not in ("name", "description", "excludedComponents", "properties")
    }
    if unknown_scope:
        metadata = dict(blueprint.format_metadata or {})
        cyclonedx = dict(metadata.get("cyclonedx") or {})
        cyclonedx["scope_passthrough"] = unknown_scope
        metadata["cyclonedx"] = cyclonedx
        blueprint.format_metadata = metadata
        blueprint.save(update_fields=["format_metadata"])
    properties = read_properties(scope.get("properties"), PropertyOwner.SCOPE)
    for item in properties.get("precogly:out-of-scope", []):
        if not isinstance(item, dict) or not item.get("name"):
            continue
        OutOfScopeItem.objects.create(
            blueprint=blueprint,
            name=str(item["name"])[:255],
            reason=str(item.get("reason") or ""),
        )
        context.count("out_of_scope_items")


def _decode_canvas(attachment: dict):
    content = attachment.get("content")
    if not isinstance(content, str):
        return None
    try:
        if attachment.get("encoding") == "base64":
            content = base64.b64decode(content).decode("utf-8")
        return json.loads(content)
    except (ValueError, TypeError):
        return None


def _remap_canvas(canvas: dict, blueprint, context) -> dict:
    """Point node and edge ids at the rows this import created, by bom-ref.

    When the canvas and the blueprint disagree on a name, the blueprint wins
    and the correction is warned (section 9.8).
    """
    for node in canvas.get("nodes", []):
        data = node.setdefault("data", {})
        ref = data.pop("bom_ref", None)
        row = context.resolve(ref) if ref else None
        if isinstance(row, OrgsystemComponent) and row.blueprint_id == blueprint.id:
            data["component_id"] = row.id
            if data.get("label") not in (None, row.name):
                context.warn(
                    f"Canvas node '{data.get('label')}' renamed to '{row.name}' to "
                    "match the blueprint."
                )
                data["label"] = row.name
        elif isinstance(row, Zone) and row.blueprint_id == blueprint.id:
            data["trust_zone_id"] = row.id
            if data.get("label") not in (None, row.name):
                context.warn(
                    f"Canvas zone '{data.get('label')}' renamed to '{row.name}' to "
                    "match the blueprint."
                )
                data["label"] = row.name
        else:
            data.pop("component_id", None)
            data.pop("trust_zone_id", None)
        data.pop("orgsystem_id", None)
    for edge in canvas.get("edges", []):
        data = edge.setdefault("data", {})
        ref = data.pop("bom_ref", None)
        row = context.resolve(ref) if ref else None
        if isinstance(row, Flow) and row.blueprint_id == blueprint.id:
            data["dataflow_id"] = row.id
        elif isinstance(row, Boundary) and row.blueprint_id == blueprint.id:
            data["trust_boundary_id"] = row.id
        else:
            data.pop("dataflow_id", None)
            data.pop("trust_boundary_id", None)
    return canvas


def _import_visualizations(data: dict, blueprint, context) -> None:
    passthrough = []
    for visualization in data.get("visualizations") or []:
        if not isinstance(visualization, dict):
            continue
        attachment = visualization.get("attachment") or {}
        if attachment.get("mediaType") != PRECOGLY_DFD_MEDIA_TYPE:
            passthrough.append(visualization)
            continue
        canvas = _decode_canvas(attachment)
        if not isinstance(canvas, dict):
            context.warn(
                f"Visualization '{_label(visualization, 'diagram')}' carries a "
                "Precogly canvas that could not be decoded; skipped."
            )
            continue
        properties = read_properties(
            visualization.get("properties"), PropertyOwner.VISUALIZATION
        )
        diagram_type = properties.get("precogly:diagram-type") or "level1"
        if diagram_type not in DFD.DiagramType.values:
            diagram_type = "level1"
        is_primary = bool(properties.get("precogly:primary", False))
        if is_primary and blueprint.dfds.filter(is_primary=True).exists():
            is_primary = False
        dfd = DFD.objects.create(
            blueprint=blueprint,
            name=_label(visualization, "Diagram"),
            diagram_type=diagram_type,
            is_primary=is_primary,
            canvas_data=_remap_canvas(normalize_canvas(canvas), blueprint, context),
        )
        remember_ref(dfd, visualization.get("bom-ref", ""))
        context.register(visualization.get("bom-ref"), "visualization", dfd)
        context.count("diagrams")
    if blueprint.dfds.exists() and not blueprint.dfds.filter(is_primary=True).exists():
        first = blueprint.dfds.order_by("id").first()
        first.is_primary = True
        first.save(update_fields=["is_primary"])
    if passthrough:
        # Kept whole for re-emission; the general passthrough lands at step 14.
        metadata = dict(blueprint.format_metadata or {})
        cyclonedx = dict(metadata.get("cyclonedx") or {})
        cyclonedx["visualizations"] = passthrough
        metadata["cyclonedx"] = cyclonedx
        blueprint.format_metadata = metadata
        blueprint.save(update_fields=["format_metadata"])
        context.warn(
            f"{len(passthrough)} visualization(s) are not Precogly canvases; "
            "kept for export, not shown."
        )


def generate_missing_canvases(threat_model, context) -> None:
    """A blueprint with no Precogly canvas gets one drawn from its rows (9.8).

    Runs after the whole document is in, so assets that stood for other models
    (and were turned into relationships) are not drawn.
    """
    for blueprint in threat_model.blueprints.order_by("id"):
        if blueprint.dfds.exists():
            continue
        DFD.objects.create(
            blueprint=blueprint,
            name=blueprint.name,
            diagram_type="level1",
            is_primary=True,
            canvas_data=build_canvas(blueprint),
        )
        context.count("diagrams_generated")


def import_blueprint(data: dict, threat_model, context, *, is_first: bool) -> Blueprint:
    blueprint = _blueprint_row(data, threat_model, context, is_first)
    _import_zones(data, blueprint, context)
    _import_boundaries(data, blueprint, context)
    _import_assets(data, blueprint, context)
    _import_data_stores(data, blueprint, context)
    _link_parents(data, blueprint, context)
    _import_data_sets(data, blueprint, context)
    _import_actors(data, blueprint, context)
    _import_flows(data, blueprint, context)
    _import_scope(data, blueprint, context)
    _import_visualizations(data, blueprint, context)
    import_assumptions(data, blueprint, context)
    update_crosses_boundary(blueprint)
    return blueprint
