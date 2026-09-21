"""CycloneDX 2.0 TM-BOM format adapter — import and export."""

import logging
from collections import defaultdict
from uuid import uuid4

from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.utils.text import slugify
from django.utils.timezone import now

from .base import BaseAdapter
from .cyclonedx_bom_ref import BomRefResolver
from .cyclonedx_enum_maps import (
    ASSET_TYPE_TO_CATEGORY,
    CATEGORY_TO_ASSET_TYPE,
    CDX_STATUS_TO_CONTROL,
    CDX_TO_LEVEL,
    CDX_TO_RESPONSE,
    CONTROL_STATUS_TO_CDX,
    LEVEL_TO_CDX,
    RESPONSE_TO_CDX,
    SEVERITY_TO_CDX_RISK_LEVEL,
)

logger = logging.getLogger(__name__)

PRECOGLY_VERSION = getattr(settings, "PRECOGLY_VERSION", "0.1.0")


class TmBomImportError(Exception):
    """User-facing import error with actionable detail."""

    pass


class CycloneDxAdapter(BaseAdapter):
    """CycloneDX 2.0 TM-BOM import/export adapter."""

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self, json_data):
        """Validate CycloneDX 2.0 input. Returns list of warnings."""
        warnings = []

        if not isinstance(json_data, dict):
            raise TmBomImportError(
                "The uploaded file does not contain a JSON object. "
                "CycloneDX TM-BOM files must be a JSON object at the top level."
            )

        spec_format = json_data.get("specFormat")
        if spec_format != "CycloneDX":
            if spec_format:
                raise TmBomImportError(
                    f"This file has specFormat '{spec_format}' but expected "
                    f"'CycloneDX'. Make sure you are uploading a CycloneDX "
                    f"TM-BOM file."
                )
            raise TmBomImportError(
                "This file is missing the 'specFormat' field. "
                "CycloneDX TM-BOM files must have specFormat set to 'CycloneDX'."
            )
        spec_version = json_data.get("specVersion", "")
        if not spec_version.startswith("2."):
            raise TmBomImportError(
                f"Unsupported CycloneDX version '{spec_version}'. "
                f"Only version 2.x files are supported."
            )

        blueprints = json_data.get("blueprints", [])
        if not blueprints:
            warnings.append(
                "No blueprints found. Only threats/risks/controls will be imported."
            )
        elif len(blueprints) > 1:
            warnings.append(
                f"Document contains {len(blueprints)} blueprints. "
                f"Only the first blueprint "
                f"('{blueprints[0].get('name', 'unnamed')}') will be imported."
            )

        return warnings

    # ==================================================================
    # EXPORT
    # ==================================================================

    def export_data(self, threat_model):
        """Export a ThreatModel as CycloneDX 2.0 TM-BOM JSON dict."""
        resolver = BomRefResolver()

        # Prefetch related data
        prefetch = self._prefetch_for_export(threat_model)

        document = {
            "specFormat": "CycloneDX",
            "specVersion": "2.0",
            "serialNumber": f"urn:uuid:{uuid4()}",
            "version": 1,
            "metadata": self._build_metadata(threat_model),
        }

        # Definitions (use cases, requirements)
        definitions = self._build_definitions(threat_model, resolver, prefetch)
        if definitions:
            document["definitions"] = definitions

        # Blueprint
        blueprint = self._build_blueprint(threat_model, resolver, prefetch)
        document["blueprints"] = [blueprint]

        # Controls (build before threats so mitigations can reference them)
        controls = self._build_controls(threat_model, resolver, prefetch)
        if controls:
            document["controls"] = controls

        # Threats
        threats_block = self._build_threats_block(threat_model, resolver, prefetch)
        if threats_block:
            document["threats"] = threats_block

        # Risks
        risks_block = self._build_risks_block(threat_model, resolver, prefetch)
        if risks_block:
            document["risks"] = risks_block

        # Re-emit Tier 3 passthrough data from format_metadata
        cyclonedx_meta = threat_model.format_metadata.get("cyclonedx", {})
        if cyclonedx_meta.get("components"):
            document["components"] = cyclonedx_meta["components"]

        return document

    # --- Export helpers ---

    def _prefetch_for_export(self, threat_model):
        """Prefetch all related objects for export efficiency."""
        from apps.systems.models import (
            ComponentDataAsset,
            DataAsset,
            DataFlow,
            OrgsystemComponent,
            TrustBoundary,
            TrustZone,
        )
        from apps.threats.models import (
            ComponentInstanceThreat,
            DataFlowInstanceThreat,
            InstanceCountermeasure,
            Risk,
        )

        components = OrgsystemComponent.objects.filter(
            threat_model=threat_model,
        ).select_related("trust_zone", "component_library")

        data_flows = DataFlow.objects.filter(
            source_component__threat_model=threat_model,
        ).select_related("source_component", "dest_component")

        zone_ids = set(
            components.exclude(trust_zone=None).values_list("trust_zone_id", flat=True)
        )
        trust_zones = TrustZone.objects.filter(id__in=zone_ids).select_related("parent")

        trust_boundaries = TrustBoundary.objects.filter(
            Q(zone_a_id__in=zone_ids) | Q(zone_b_id__in=zone_ids)
        ).select_related("zone_a", "zone_b")

        data_assets = DataAsset.objects.filter(threat_model=threat_model)

        component_threats = (
            ComponentInstanceThreat.objects.filter(
                component__threat_model=threat_model,
            )
            .select_related("threat_library", "component")
            .prefetch_related(
                "countermeasure_links__countermeasure",
                "persona_links__persona",
                "threat_library__taxonomy_entries__taxonomy_entry__taxonomy",
                "instance_taxonomy_links__taxonomy_entry__taxonomy",
            )
        )

        flow_threats = (
            DataFlowInstanceThreat.objects.filter(
                data_flow__source_component__threat_model=threat_model,
            )
            .select_related("threat_library", "data_flow")
            .prefetch_related(
                "countermeasure_links__countermeasure",
                "persona_links__persona",
                "threat_library__taxonomy_entries__taxonomy_entry__taxonomy",
                "instance_taxonomy_links__taxonomy_entry__taxonomy",
            )
        )

        risks = Risk.objects.filter(threat_model=threat_model).prefetch_related(
            "risk_threats__component_threat",
            "risk_threats__flow_threat",
            "responses__owner",
        )

        countermeasures = (
            InstanceCountermeasure.objects.filter(
                threat_model=threat_model,
            )
            .select_related("countermeasure_library")
            .prefetch_related(
                "threat_links__component_threat__component",
                "threat_links__flow_threat__data_flow",
                "instance_standard_mappings__requirement__framework",
                "countermeasure_library__standard_mappings__requirement__framework",
            )
        )

        component_data_assets = ComponentDataAsset.objects.filter(
            component__threat_model=threat_model,
        ).select_related("data_asset")

        from apps.diagrams.models import DFD

        primary_dfd = DFD.objects.filter(
            threat_model=threat_model, is_primary=True
        ).first()

        return {
            "components": list(components),
            "data_flows": list(data_flows),
            "trust_zones": list(trust_zones),
            "trust_boundaries": list(trust_boundaries),
            "data_assets": list(data_assets),
            "component_threats": list(component_threats),
            "flow_threats": list(flow_threats),
            "risks": list(risks),
            "countermeasures": list(countermeasures),
            "component_data_assets": list(component_data_assets),
            "primary_dfd": primary_dfd,
        }

    def _build_metadata(self, threat_model):
        metadata = {
            "timestamp": now().isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "Precogly",
                        "version": PRECOGLY_VERSION,
                    }
                ]
            },
        }
        if threat_model.created_by:
            full_name = threat_model.created_by.get_full_name()
            email = threat_model.created_by.email
            author = {}
            if full_name:
                author["name"] = full_name
            if email:
                author["email"] = email
            if author:
                metadata["authors"] = [author]
        return metadata

    def _requirement_snapshot_from_requirement(self, requirement):
        """Return the CDX requirement fields shared by real and snapshot mappings."""
        return {
            "identifier": requirement.section_code,
            "title": requirement.name or requirement.section_code,
            "description": requirement.description,
            "source": {"name": requirement.framework.name},
        }

    def _requirement_snapshot_from_mapping(self, mapping):
        """Return CDX requirement fields from an unresolved instance mapping."""
        return {
            "identifier": mapping.section_code,
            "title": mapping.section_code,
            "description": mapping.requirement_description or "",
            "source": {"name": mapping.framework_name},
        }

    def _requirement_snapshot_from_definition(self, requirement_data):
        """Normalize a CDX requirement definition for deferred control resolution."""
        return {
            "section_code": requirement_data.get("identifier", ""),
            "framework_name": (requirement_data.get("source") or {}).get("name", ""),
            "description": requirement_data.get("description", ""),
        }

    def _build_requirement_definition(self, bom_ref, snapshot):
        """Build a CDX requirement entry from normalized snapshot fields."""
        return {"bom-ref": bom_ref, **snapshot}

    def _build_definitions(self, threat_model, resolver, prefetch):
        definitions = {}

        # Use cases
        use_cases = list(threat_model.use_cases.all())
        if use_cases:
            cdx_use_cases = []
            for use_case in use_cases:
                entry = {
                    "bom-ref": resolver.register("usecase", use_case),
                    "name": use_case.name,
                }
                if use_case.description:
                    entry["description"] = use_case.description
                flow_data = use_case.flow_data or {}
                for src_key, cdx_key in (
                    ("preconditions", "preconditions"),
                    ("postconditions", "postconditions"),
                    ("success_criteria", "successCriteria"),
                    ("main_flow", "mainFlow"),
                    ("alternative_flows", "alternativeFlows"),
                    ("exceptions", "exceptions"),
                ):
                    if flow_data.get(src_key):
                        entry[cdx_key] = flow_data[src_key]
                cdx_use_cases.append(entry)
            definitions["useCases"] = cdx_use_cases

        # Requirements: collect all unique requirements from countermeasure
        # compliance mappings (library + instance) and register them so
        # _build_controls can reference them in satisfies. Instance mappings
        # whose FK is unresolved still carry section_code/framework_name
        # snapshots, so emit those too (GSA-TTS/TTSE-petrified-forest-sspp#31).
        requirements_by_id = {}
        snapshot_requirements = {}
        for cm in prefetch["countermeasures"]:
            if cm.countermeasure_library:
                for mapping in cm.countermeasure_library.standard_mappings.all():
                    if mapping.requirement and mapping.requirement.framework:
                        requirements_by_id[mapping.requirement_id] = mapping.requirement
            for mapping in cm.instance_standard_mappings.all():
                if mapping.requirement and mapping.requirement.framework:
                    requirements_by_id[mapping.requirement_id] = mapping.requirement
                elif mapping.section_code and mapping.framework_name:
                    key = (mapping.framework_name, mapping.section_code)
                    snapshot_requirements[key] = mapping

        if requirements_by_id or snapshot_requirements:
            cdx_requirements = []
            for req in requirements_by_id.values():
                cdx_requirements.append(
                    self._build_requirement_definition(
                        resolver.register("requirement", req),
                        self._requirement_snapshot_from_requirement(req),
                    )
                )
            for mapping in snapshot_requirements.values():
                cdx_requirements.append(
                    self._build_requirement_definition(
                        resolver.register("requirement", mapping),
                        self._requirement_snapshot_from_mapping(mapping),
                    )
                )
            definitions["requirements"] = cdx_requirements

        return definitions

    def _build_blueprint(self, threat_model, resolver, prefetch):
        components = prefetch["components"]
        data_flows = prefetch["data_flows"]
        trust_zones = prefetch["trust_zones"]
        trust_boundaries = prefetch["trust_boundaries"]
        data_assets = prefetch["data_assets"]
        component_data_assets = prefetch["component_data_assets"]

        # Register zones first (assets reference them)
        for zone in trust_zones:
            resolver.register("zone", zone)

        blueprint = {
            "bom-ref": resolver.register("blueprint", threat_model),
            "name": threat_model.name,
            "modelTypes": ["data-flow"],
        }
        if threat_model.description:
            blueprint["description"] = threat_model.description

        # Assets
        assets = []
        datastore_components = []
        for component in components:
            category = component.category or (
                component.component_library.category
                if component.component_library
                else ""
            )
            assets.append(self._build_asset(component, category, resolver))
            if category == "datastore":
                datastore_components.append(component)
        if assets:
            blueprint["assets"] = assets

        # Data stores
        if datastore_components:
            data_asset_map = defaultdict(list)
            for cda in component_data_assets:
                data_asset_map[cda.component_id].append(cda.data_asset)
            data_stores = []
            for component in datastore_components:
                data_stores.append(
                    self._build_data_store(component, data_asset_map, resolver)
                )
            blueprint["dataStores"] = data_stores

        # Data sets
        if data_assets:
            data_sets = []
            for data_asset in data_assets:
                data_sets.append(self._build_data_set(data_asset, resolver))
            blueprint["dataSets"] = data_sets

        # Zones
        if trust_zones:
            blueprint["zones"] = [
                self._build_zone(zone, resolver) for zone in trust_zones
            ]

        # Boundaries
        if trust_boundaries:
            blueprint["boundaries"] = [
                self._build_boundary(boundary, resolver)
                for boundary in trust_boundaries
            ]

        # Flows
        if data_flows:
            flows = []
            for flow in data_flows:
                flows.append(self._build_flow(flow, resolver))
            blueprint["flows"] = flows

        # Assumptions
        assumptions = self._build_assumptions(threat_model)
        if assumptions:
            blueprint["assumptions"] = assumptions

        # Visualizations — include DFD canvas if present
        visualizations = []
        primary_dfd = prefetch.get("primary_dfd")
        if primary_dfd and primary_dfd.canvas_data:
            visualizations.append(
                {
                    "type": "precogly-dfd",
                    "name": primary_dfd.name,
                    "diagramType": primary_dfd.diagram_type,
                    "data": primary_dfd.canvas_data,
                }
            )

        # Re-emit Tier 3 blueprint-level passthrough data
        cyclonedx_meta = threat_model.format_metadata.get("cyclonedx", {})
        if cyclonedx_meta.get("behaviors"):
            blueprint["behaviors"] = cyclonedx_meta["behaviors"]
        if cyclonedx_meta.get("relationships"):
            blueprint["relationships"] = cyclonedx_meta["relationships"]

        # Merge any passthrough visualizations (non-DFD)
        passthrough_visualizations = cyclonedx_meta.get("visualizations", [])
        for vis in passthrough_visualizations:
            if vis.get("type") != "precogly-dfd":
                visualizations.append(vis)

        if visualizations:
            blueprint["visualizations"] = visualizations

        return blueprint

    def _build_asset(self, component, category, resolver):
        bom_ref = resolver.register("asset", component)
        asset = {
            "bom-ref": bom_ref,
            "name": component.name,
            "type": CATEGORY_TO_ASSET_TYPE.get(category, "component"),
        }
        if component.description:
            asset["description"] = component.description
        if component.trust_zone:
            zone_ref = resolver.get_ref("zone", component.trust_zone)
            if zone_ref:
                asset["zone"] = zone_ref

        # Re-emit Tier 3 asset data
        cdx_meta = component.format_metadata.get("cyclonedx", {})
        if cdx_meta.get("interfaces"):
            asset["interfaces"] = cdx_meta["interfaces"]
        if cdx_meta.get("classification"):
            asset["classification"] = cdx_meta["classification"]
        if cdx_meta.get("authentication"):
            asset["authentication"] = cdx_meta["authentication"]
        if cdx_meta.get("authorization"):
            asset["authorization"] = cdx_meta["authorization"]

        return asset

    def _build_data_store(self, component, data_asset_map, resolver):
        store = {
            "bom-ref": resolver.register("datastore", component),
            "name": component.name,
        }
        if component.component_library and component.component_library.provider:
            store["vendor"] = component.component_library.provider
        if component.trust_zone:
            zone_ref = resolver.get_ref("zone", component.trust_zone)
            if zone_ref:
                store["zone"] = zone_ref

        # Link to data sets
        linked_assets = data_asset_map.get(component.id, [])
        if linked_assets:
            store["dataSets"] = [
                resolver.get_ref("dataset", da)
                for da in linked_assets
                if resolver.get_ref("dataset", da)
            ]
        return store

    def _build_data_set(self, data_asset, resolver):
        entry = {
            "bom-ref": resolver.register("dataset", data_asset),
            "name": data_asset.name,
        }
        if data_asset.description:
            entry["description"] = data_asset.description
        if data_asset.classification:
            entry["classification"] = data_asset.classification
        return entry

    def _build_zone(self, zone, resolver):
        zone_data = {
            "bom-ref": resolver.get_ref("zone", zone),
            "name": zone.name,
            "type": "trust",
        }
        if zone.description:
            zone_data["description"] = zone.description
        if zone.trust_level is not None:
            zone_data["trustLevel"] = zone.trust_level
        if zone.parent:
            parent_ref = resolver.get_ref("zone", zone.parent)
            if parent_ref:
                zone_data["parent"] = parent_ref
        return zone_data

    def _build_boundary(self, boundary, resolver):
        boundary_data = {
            "zones": [
                resolver.get_ref("zone", boundary.zone_a),
                resolver.get_ref("zone", boundary.zone_b),
            ],
        }
        if boundary.label:
            boundary_data["name"] = boundary.label
        if boundary.description:
            boundary_data["description"] = boundary.description

        # Crossing requirements from boolean fields
        crossing = {}
        if boundary.authentication:
            crossing["authentication"] = True
        if boundary.authorization:
            crossing["authorization"] = True
        if boundary.data_validation:
            crossing["dataValidation"] = True
        if boundary.logging:
            crossing["logging"] = True
        if boundary.monitoring:
            crossing["monitoring"] = True
        if boundary.rate_limiting:
            crossing["rateLimit"] = True

        # Re-emit Tier 3 crossing data
        cdx_meta = boundary.format_metadata.get("cyclonedx", {})
        crossing_details = cdx_meta.get("crossing_details", {})
        if crossing_details.get("dataTransformation"):
            crossing["dataTransformation"] = crossing_details["dataTransformation"]
        if crossing_details.get("protocols"):
            crossing["protocols"] = crossing_details["protocols"]

        if crossing:
            boundary_data["crossingRequirements"] = crossing

        # Re-emit session management
        if cdx_meta.get("session_management"):
            boundary_data["sessionManagement"] = cdx_meta["session_management"]

        return boundary_data

    def _build_flow(self, flow, resolver):
        flow_data = {
            "bom-ref": resolver.register("flow", flow),
            "source": resolver.get_ref("asset", flow.source_component),
            "destination": resolver.get_ref("asset", flow.dest_component),
            "type": "data",
        }
        if flow.label:
            flow_data["name"] = flow.label
        if flow.description:
            flow_data["description"] = flow.description
        if flow.protocol:
            flow_data["protocols"] = [flow.protocol]
        if flow.encrypted:
            flow_data["encrypted"] = True
        if flow.authenticated:
            flow_data["authenticated"] = True
        return flow_data

    def _build_assumptions(self, threat_model):
        assumptions = threat_model.assumptions or []
        result = []
        for i, assumption in enumerate(assumptions):
            if isinstance(assumption, str):
                result.append({"bom-ref": f"assumption-{i}", "description": assumption})
            elif isinstance(assumption, dict):
                entry = {"bom-ref": assumption.get("id", f"assumption-{i}")}
                if "description" in assumption:
                    entry["description"] = assumption["description"]
                if "validity" in assumption:
                    entry["validity"] = assumption["validity"]
                if "topics" in assumption:
                    topics = assumption["topics"]
                    if topics:
                        entry["topic"] = topics[0]
                result.append(entry)
        return result

    def _build_threats_block(self, threat_model, resolver, prefetch):
        component_threats = prefetch["component_threats"]
        flow_threats = prefetch["flow_threats"]

        # Group by threat_library to emit one abstract threat per library entry
        threats_by_library = defaultdict(list)
        for ct in component_threats:
            key = ct.threat_library_id or f"orphan-ct-{ct.id}"
            threats_by_library[key].append(("component", ct))
        for ft in flow_threats:
            key = ft.threat_library_id or f"orphan-ft-{ft.id}"
            threats_by_library[key].append(("flow", ft))

        if not threats_by_library:
            return {}

        abstract_threats = []
        scenarios = []

        for _library_id, instances in threats_by_library.items():
            _first_type, first_instance = instances[0]
            threat_lib = first_instance.threat_library

            # Abstract threat
            abstract_ref = resolver.register("threat", threat_lib or first_instance)
            abstract_threat = {
                "bom-ref": abstract_ref,
                "name": (threat_lib.name if threat_lib else first_instance.threat_name),
                "description": (
                    threat_lib.description
                    if threat_lib
                    else first_instance.threat_description
                ),
            }

            # Taxonomy categories
            categories = self._build_threat_categories(first_instance)
            if categories:
                abstract_threat["categories"] = categories

            # Affected assets
            affected = []
            for inst_type, inst in instances:
                if inst_type == "component":
                    ref = resolver.get_ref("asset", inst.component)
                else:
                    ref = resolver.get_ref("flow", inst.data_flow)
                if ref:
                    affected.append(ref)
            if affected:
                abstract_threat["affectedAssets"] = affected

            # Mitigation refs
            mitigation_refs = set()
            for _, inst in instances:
                for link in inst.countermeasure_links.all():
                    ctrl_ref = resolver.get_ref("control", link.countermeasure)
                    if ctrl_ref:
                        mitigation_refs.add(ctrl_ref)
            if mitigation_refs:
                abstract_threat["mitigations"] = list(mitigation_refs)

            abstract_threats.append(abstract_threat)

            # Scenarios
            for inst_type, inst in instances:
                scenario = {
                    "bom-ref": resolver.register("scenario", inst),
                    "threat": abstract_ref,
                }

                if inst_type == "component":
                    asset_ref = resolver.get_ref("asset", inst.component)
                else:
                    asset_ref = resolver.get_ref("flow", inst.data_flow)
                if asset_ref:
                    scenario["affectedAssets"] = [asset_ref]

                if inst.inherent_severity:
                    scenario["riskScore"] = {
                        "level": SEVERITY_TO_CDX_RISK_LEVEL.get(
                            inst.inherent_severity, inst.inherent_severity
                        ),
                    }

                # Actor
                persona_links = list(inst.persona_links.all())
                if persona_links:
                    persona_ref = resolver.get_ref("persona", persona_links[0].persona)
                    if persona_ref:
                        scenario["actor"] = persona_ref

                # Intent and access level
                if inst.intent:
                    scenario["intent"] = inst.intent
                if inst.access_level:
                    scenario["accessLevel"] = inst.access_level

                # Triage status
                scenario_props = []
                if inst.triage_status != "open":
                    scenario_props.append(
                        {
                            "name": "precogly:threat-status",
                            "value": inst.triage_status,
                        }
                    )
                if inst.decision_rationale:
                    scenario_props.append(
                        {
                            "name": "precogly:decision-rationale",
                            "value": inst.decision_rationale,
                        }
                    )
                if scenario_props:
                    scenario["properties"] = scenario_props

                # Re-emit Tier 3 scenario data
                cdx_meta = inst.format_metadata.get("cyclonedx", {})
                scenario_meta = cdx_meta.get("scenario", {})
                for key in ("motivation", "attackVector", "exploitability"):
                    if scenario_meta.get(key):
                        scenario[key] = scenario_meta[key]

                scenarios.append(scenario)

        result = {}
        if abstract_threats:
            result["threats"] = abstract_threats
        if scenarios:
            result["scenarios"] = scenarios

        # Methodologies (derived from categories already computed per threat)
        taxonomies_used = set()
        for t in abstract_threats:
            for cat in t.get("categories", []):
                if cat.get("taxonomy"):
                    taxonomies_used.add(cat["taxonomy"])
        methodologies = []
        if "stride" in taxonomies_used:
            methodologies.append({"type": "stride"})
        if methodologies:
            result["methodologies"] = methodologies

        # Re-emit Tier 3 threat-level passthrough
        cyclonedx_meta = threat_model.format_metadata.get("cyclonedx", {})
        if cyclonedx_meta.get("attack_trees"):
            result["attackTrees"] = cyclonedx_meta["attack_trees"]
        if cyclonedx_meta.get("attack_paths"):
            result["attackPaths"] = cyclonedx_meta["attack_paths"]
        if cyclonedx_meta.get("abuse_cases"):
            result["abuseCases"] = cyclonedx_meta["abuse_cases"]

        return result

    def _build_threat_categories(self, instance):
        """Build CycloneDX threat categories from live taxonomy entries."""
        seen = {}

        if instance.threat_library:
            for join in instance.threat_library.taxonomy_entries.all():
                entry = join.taxonomy_entry
                if entry.taxonomy:
                    key = (entry.taxonomy.slug, entry.external_id)
                    seen[key] = {
                        "taxonomy": entry.taxonomy.slug,
                        "id": entry.external_id,
                        "name": entry.title,
                    }

        for link in instance.instance_taxonomy_links.all():
            entry = link.taxonomy_entry
            if entry.taxonomy:
                key = (entry.taxonomy.slug, entry.external_id)
                if key not in seen:
                    seen[key] = {
                        "taxonomy": entry.taxonomy.slug,
                        "id": entry.external_id,
                        "name": entry.title,
                    }

        if seen:
            return list(seen.values())

        categories = []
        for snap in instance.taxonomy_snapshot or []:
            if not isinstance(snap, dict):
                continue
            category = {}
            taxonomy_slug = snap.get("taxonomy_slug", "")
            if taxonomy_slug:
                category["taxonomy"] = taxonomy_slug
            if snap.get("external_id"):
                category["id"] = snap["external_id"]
            if snap.get("title"):
                category["name"] = snap["title"]
            if category:
                categories.append(category)
        return categories

    def _build_risks_block(self, threat_model, resolver, prefetch):
        risks = prefetch["risks"]
        if not risks:
            return {}

        risk_entries = []
        for risk in risks:
            entry = {
                "bom-ref": resolver.register("risk", risk),
                "name": risk.name,
                "statement": risk.description,
            }

            # Domains
            if risk.domains:
                entry["domains"] = [{"type": d} for d in risk.domains]

            # Related threats
            related_threats = set()
            for risk_threat in risk.risk_threats.all():
                threat_inst = risk_threat.component_threat or risk_threat.flow_threat
                if threat_inst and threat_inst.threat_library:
                    ref = resolver.get_ref("threat", threat_inst.threat_library)
                    if ref:
                        related_threats.add(ref)
            if related_threats:
                entry["relatedThreats"] = list(related_threats)

            # Inherent risk
            entry["inherentRisk"] = self._build_risk_rating(
                risk.inherent_score,
                risk.inherent_level,
                risk.scoring_metadata,
            )

            # Residual risk
            if risk.residual_score is not None:
                entry["residualRisk"] = self._build_risk_rating(
                    risk.residual_score, risk.residual_level, {}
                )

            # Target risk
            if risk.target_score is not None:
                entry["targetRisk"] = self._build_risk_rating(
                    risk.target_score, risk.target_level, {}
                )

            # Risk responses
            risk_responses = list(risk.responses.all())
            if risk_responses:
                responses = []
                for resp in risk_responses:
                    response_entry = {
                        "strategy": RESPONSE_TO_CDX.get(resp.strategy, resp.strategy),
                    }
                    if resp.description:
                        response_entry["description"] = resp.description
                    if resp.status:
                        response_entry["status"] = resp.status
                    if resp.effectiveness is not None:
                        response_entry["effectiveness"] = {
                            "percentage": resp.effectiveness,
                        }
                    if resp.cost:
                        response_entry["cost"] = resp.cost
                    if resp.priority:
                        response_entry["priority"] = resp.priority
                    if resp.owner:
                        response_entry["owner"] = resp.owner.email
                    if resp.target_date:
                        response_entry["targetDate"] = resp.target_date.isoformat()
                    responses.append(response_entry)
                entry["responses"] = responses

            # Owner
            if risk.owner:
                entry["owner"] = risk.owner.email

            risk_entries.append(entry)

        result = {}
        if risk_entries:
            result["risks"] = risk_entries

        # Re-emit Tier 3 risk-level passthrough
        cyclonedx_meta = threat_model.format_metadata.get("cyclonedx", {})
        if cyclonedx_meta.get("risk_assessments"):
            result["assessments"] = cyclonedx_meta["risk_assessments"]
        if cyclonedx_meta.get("risk_appetites"):
            result["riskAppetites"] = cyclonedx_meta["risk_appetites"]

        return result

    def _build_risk_rating(self, score, level, scoring_metadata):
        rating = {
            "riskScore": {
                "score": score,
                "level": LEVEL_TO_CDX.get(level, level),
            }
        }
        return rating

    def _build_controls(self, threat_model, resolver, prefetch):
        countermeasures = prefetch["countermeasures"]
        if not countermeasures:
            return []

        controls = []
        for cm in countermeasures:
            ref = resolver.register("control", cm)
            control = {
                "bom-ref": ref,
                "name": cm.countermeasure_name
                or (
                    cm.countermeasure_library.name if cm.countermeasure_library else ""
                ),
                "status": CONTROL_STATUS_TO_CDX.get(cm.status, cm.status),
            }

            description = cm.countermeasure_description or (
                cm.countermeasure_library.description
                if cm.countermeasure_library
                else ""
            )
            if description:
                control["description"] = description

            control_functions = cm.control_functions or (
                cm.countermeasure_library.control_functions
                if cm.countermeasure_library
                else []
            )
            control_nature = cm.control_nature or (
                cm.countermeasure_library.control_nature
                if cm.countermeasure_library
                else ""
            )
            if control_functions:
                control["category"] = control_functions[0]
            props = []
            if control_functions:
                props.append(
                    {
                        "name": "precogly:control-functions",
                        "value": ",".join(control_functions),
                    }
                )
            if control_nature:
                props.append(
                    {"name": "precogly:control-nature", "value": control_nature}
                )
            if props:
                control["properties"] = props

            if cm.effectiveness is not None:
                control["effectiveness"] = {
                    "percentage": cm.effectiveness,
                }

            # appliesTo
            applies_to = set()
            for link in cm.threat_links.all():
                if link.component_threat:
                    asset_ref = resolver.get_ref(
                        "asset", link.component_threat.component
                    )
                    if asset_ref:
                        applies_to.add(asset_ref)
                elif link.flow_threat:
                    flow_ref = resolver.get_ref("flow", link.flow_threat.data_flow)
                    if flow_ref:
                        applies_to.add(flow_ref)
            if applies_to:
                control["appliesTo"] = list(applies_to)

            # satisfies (compliance): merge library + instance mappings
            satisfies_by_req = {}
            if cm.countermeasure_library:
                for mapping in cm.countermeasure_library.standard_mappings.all():
                    if mapping.requirement:
                        req_ref = resolver.get_ref("requirement", mapping.requirement)
                        if req_ref:
                            satisfies_by_req[mapping.requirement_id] = req_ref
            for mapping in cm.instance_standard_mappings.all():
                if mapping.requirement:
                    req_ref = resolver.get_ref("requirement", mapping.requirement)
                    if req_ref:
                        satisfies_by_req[mapping.requirement_id] = req_ref
                elif mapping.section_code and mapping.framework_name:
                    req_ref = resolver.get_ref("requirement", mapping)
                    if req_ref:
                        satisfies_by_req[mapping.id] = req_ref
            if satisfies_by_req:
                control["satisfies"] = list(satisfies_by_req.values())

            controls.append(control)

        return controls

    # ==================================================================
    # IMPORT
    # ==================================================================

    @transaction.atomic()
    def import_data(self, json_data, organization, created_by):
        """Import CycloneDX 2.0 TM-BOM into a new ThreatModel."""
        warnings = self.validate(json_data)
        resolver = BomRefResolver()
        summary = defaultdict(int)

        blueprint = (json_data.get("blueprints") or [{}])[0]
        definitions = json_data.get("definitions", {})

        # 1. ThreatModel
        try:
            threat_model = self._import_threat_model(
                blueprint, json_data, organization, created_by
            )
        except Exception as e:
            raise TmBomImportError(f"Failed to create threat model: {e}") from e
        summary["threat_model"] = 1

        # 2. Orgsystem
        try:
            orgsystem = self._import_orgsystem(blueprint, threat_model, organization)
        except Exception as e:
            raise TmBomImportError(f"Failed to create system: {e}") from e
        summary["orgsystems"] = 1

        # 3. Zones
        for zone_data in blueprint.get("zones", []):
            zone_name = zone_data.get("name", zone_data.get("bom-ref", "unknown"))
            try:
                self._import_zone(zone_data, resolver, organization)
            except Exception as e:
                raise TmBomImportError(
                    f"Failed to import trust zone '{zone_name}': {e}. "
                    f"Check that the zone definition is complete."
                ) from e
            summary["zones"] += 1

        # 4. Boundaries (depends on zones)
        for boundary_data in blueprint.get("boundaries", []):
            result = self._import_boundary(
                boundary_data, resolver, organization, warnings
            )
            if result:
                summary["boundaries"] += 1

        # 5. Assets -> OrgsystemComponent
        for asset_data in blueprint.get("assets", []):
            asset_name = asset_data.get("name", asset_data.get("bom-ref", "unknown"))
            try:
                self._import_asset(asset_data, orgsystem, threat_model, resolver)
            except Exception as e:
                raise TmBomImportError(
                    f"Failed to import asset '{asset_name}': {e}. "
                    f"Check the asset type and zone reference."
                ) from e
            summary["components"] += 1

        # 6. DataStores -> merge into components
        for store_data in blueprint.get("dataStores", []):
            self._import_data_store(store_data, orgsystem, threat_model, resolver)

        # 7. DataSets -> DataAsset
        for dataset_data in blueprint.get("dataSets", []):
            self._import_data_set(dataset_data, threat_model, resolver)
            summary["data_assets"] += 1

        # 7.5 Assumptions
        assumptions_data = blueprint.get("assumptions", [])
        if assumptions_data:
            imported_assumptions = []
            for assumption in assumptions_data:
                imported_assumptions.append(
                    {
                        "id": assumption.get("bom-ref", ""),
                        "description": assumption.get("description", ""),
                        "validity": assumption.get("validity", "unconfirmed"),
                        "topics": (
                            [assumption["topic"]] if assumption.get("topic") else []
                        ),
                    }
                )
            threat_model.assumptions = imported_assumptions
            threat_model.save(update_fields=["assumptions"])

        # 8. Flows -> DataFlow
        for flow_data in blueprint.get("flows", []):
            result = self._import_flow(flow_data, threat_model, resolver, warnings)
            if result:
                summary["flows"] += 1

        # 9. Use cases from definitions
        for uc_data in definitions.get("useCases", []):
            self._import_use_case(uc_data, threat_model, resolver)
            summary["use_cases"] += 1

        # 9.5 Requirements from definitions (so control satisfies[] can resolve)
        for req_data in definitions.get("requirements", []):
            self._import_requirement(req_data, resolver)

        # 10. Controls -> InstanceCountermeasure
        control_objs = []
        for control_data in json_data.get("controls", []):
            control_name = control_data.get(
                "name", control_data.get("bom-ref", "unknown")
            )
            try:
                cm = self._import_control(
                    control_data, threat_model, resolver, warnings
                )
                if cm is not None:
                    control_objs.append(cm)
            except TmBomImportError:
                raise
            except Exception as e:
                raise TmBomImportError(
                    f"Failed to import control '{control_name}': {e}"
                ) from e
            summary["controls"] += 1

        # 10.5 Resolve control satisfies[] -> InstanceCountermeasureStandard
        for cm in control_objs:
            self._resolve_control_satisfies(cm, resolver, warnings)

        # 11. Threats -> ThreatLibrary
        threats_block = json_data.get("threats", {})
        scenario_threat_refs = {
            s.get("threat")
            for s in threats_block.get("scenarios", [])
            if s.get("threat")
        }
        for threat_data in threats_block.get("threats", []):
            self._import_threat(
                threat_data,
                threat_model,
                resolver,
                scenario_threat_refs,
                warnings,
            )
            summary["threats"] += 1

        # 12. Scenarios -> instance threats
        for scenario_data in threats_block.get("scenarios", []):
            self._import_scenario(scenario_data, threat_model, resolver, warnings)
            summary["scenarios"] += 1

        # 13. Risks
        risks_block = json_data.get("risks", {})
        for risk_data in risks_block.get("risks", []):
            self._import_risk(risk_data, threat_model, resolver)
            summary["risks"] += 1

        # 14. Resolve control -> threat links from mitigations
        self._resolve_control_threat_links(threats_block, threat_model, resolver)

        # 15. Tier 3 passthrough
        self._store_tier3_data(threat_model, json_data, blueprint, resolver, warnings)

        if warnings:
            summary["warnings"] = warnings

        return threat_model, dict(summary)

    # --- Import helpers ---

    def _import_threat_model(self, blueprint, json_data, organization, created_by):
        from apps.threat_models.models import ThreatModel

        name = blueprint.get("name", "Imported CycloneDX Model")

        threat_model = ThreatModel.objects.create(
            organization=organization,
            created_by=created_by,
            name=name,
            description=blueprint.get("description", ""),
            format_metadata={
                "cyclonedx": {"spec_version": json_data.get("specVersion", "2.0")}
            },
        )
        return threat_model

    def _import_orgsystem(self, blueprint, threat_model, organization):
        from apps.systems.models import Orgsystem
        from apps.threat_models.models import ThreatModelOrgsystem

        orgsystem = Orgsystem.objects.create(
            organization=organization,
            name=blueprint.get("name", threat_model.name),
            description=blueprint.get("description", ""),
        )
        ThreatModelOrgsystem.objects.create(
            threat_model=threat_model,
            orgsystem=orgsystem,
        )
        return orgsystem

    def _import_zone(self, zone_data, resolver, organization):
        from apps.systems.models import TrustZone

        bom_ref = zone_data.get("bom-ref", "")
        name = zone_data.get("name", bom_ref)

        parent = None
        parent_ref = zone_data.get("parent")
        if parent_ref:
            parent = resolver.resolve("zone", parent_ref)

        zone = TrustZone.objects.create(
            organization=organization,
            name=name,
            description=zone_data.get("description", ""),
            trust_level=zone_data.get("trustLevel") or 50,
            parent=parent,
        )
        resolver.register("zone", bom_ref, zone)
        return zone

    def _import_boundary(self, boundary_data, resolver, organization, warnings):
        from apps.systems.models import TrustBoundary

        bom_ref = boundary_data.get("bom-ref", "")
        zone_refs = boundary_data.get("zones", [])
        zone_a = resolver.resolve("zone", zone_refs[0]) if len(zone_refs) > 0 else None
        zone_b = resolver.resolve("zone", zone_refs[1]) if len(zone_refs) > 1 else None

        if not zone_a or not zone_b:
            msg = (
                f"Boundary '{boundary_data.get('name', bom_ref)}' references "
                f"unknown zones and was skipped. "
                f"Check that the zones it connects are defined earlier in the file."
            )
            logger.warning(msg)
            warnings.append(msg)
            return None

        crossing = boundary_data.get("crossingRequirements", {})

        boundary = TrustBoundary.objects.create(
            organization=organization,
            zone_a=zone_a,
            zone_b=zone_b,
            label=boundary_data.get("name", ""),
            description=boundary_data.get("description", ""),
            authentication=bool(crossing.get("authentication")),
            authorization=bool(crossing.get("authorization")),
            data_validation=bool(crossing.get("dataValidation")),
            logging=bool(crossing.get("logging")),
            monitoring=bool(crossing.get("monitoring")),
            rate_limiting=bool(crossing.get("rateLimit")),
            format_metadata={
                "cyclonedx": {
                    "bom_ref": bom_ref,
                    "session_management": boundary_data.get("sessionManagement"),
                    "crossing_details": {
                        k: v
                        for k, v in {
                            "dataTransformation": crossing.get("dataTransformation"),
                            "protocols": crossing.get("protocols"),
                        }.items()
                        if v is not None
                    },
                }
            },
        )
        if bom_ref:
            resolver.register("boundary", bom_ref, boundary)
        return boundary

    def _import_asset(self, asset_data, orgsystem, threat_model, resolver):
        from apps.systems.models import OrgsystemComponent

        bom_ref = asset_data.get("bom-ref", "")
        name = asset_data.get("name", bom_ref)
        asset_type = asset_data.get("type", "component")

        if isinstance(asset_type, dict):
            type_name = asset_type.get("name", "component")
            category = ASSET_TYPE_TO_CATEGORY.get(type_name, "process")
        else:
            category = ASSET_TYPE_TO_CATEGORY.get(asset_type, "process")

        zone = None
        zone_ref = asset_data.get("zone")
        if zone_ref:
            zone = resolver.resolve("zone", zone_ref)

        # Build Tier 3 metadata
        cdx_meta = {"bom_ref": bom_ref}
        if (
            isinstance(asset_type, str)
            and asset_type
            not in (
                "component",
                "data-store",
                "actor",
            )
        ) or isinstance(asset_type, dict):
            cdx_meta["asset_type"] = asset_type
        for key in ("interfaces", "classification", "authentication", "authorization"):
            if asset_data.get(key):
                cdx_meta[key] = asset_data[key]

        component = OrgsystemComponent.objects.create(
            orgsystem=orgsystem,
            threat_model=threat_model,
            name=name,
            description=asset_data.get("description", ""),
            category=category,
            trust_zone=zone,
            format_metadata={"cyclonedx": cdx_meta},
        )
        resolver.register("asset", bom_ref, component)
        return component

    def _import_data_store(self, store_data, orgsystem, threat_model, resolver):
        """Import a dataStore — merge into existing asset or create new component."""
        from apps.systems.models import OrgsystemComponent

        bom_ref = store_data.get("bom-ref", "")
        name = store_data.get("name", bom_ref)

        # Try to merge with existing component of same name
        existing = None
        for entity_type, obj in resolver._ref_to_obj.values():
            if (
                entity_type == "asset"
                and isinstance(obj, OrgsystemComponent)
                and obj.name == name
            ):
                existing = obj
                break

        if existing:
            # Merge: update store type if available
            store_type = store_data.get("type")
            if store_type:
                cdx_meta = existing.format_metadata.get("cyclonedx", {})
                cdx_meta["data_store_type"] = store_type
                existing.format_metadata["cyclonedx"] = cdx_meta
                existing.save(update_fields=["format_metadata"])
            resolver.register("datastore", bom_ref, existing)
        else:
            component = OrgsystemComponent.objects.create(
                orgsystem=orgsystem,
                threat_model=threat_model,
                name=name,
                description=store_data.get("description", ""),
                category="datastore",
                format_metadata={
                    "cyclonedx": {
                        "bom_ref": bom_ref,
                        "data_store_type": store_data.get("type"),
                    }
                },
            )
            resolver.register("datastore", bom_ref, component)
            resolver.register("asset", f"ds-{bom_ref}", component)

    def _import_data_set(self, dataset_data, threat_model, resolver):
        from apps.systems.models import DataAsset

        bom_ref = dataset_data.get("bom-ref", "")
        name = dataset_data.get("name", bom_ref)

        data_asset = DataAsset.objects.create(
            threat_model=threat_model,
            name=name,
            description=dataset_data.get("description", ""),
            classification=dataset_data.get("classification", "internal"),
            format_metadata={"cyclonedx": {"bom_ref": bom_ref}},
        )
        resolver.register("dataset", bom_ref, data_asset)
        return data_asset

    def _import_flow(self, flow_data, threat_model, resolver, warnings):
        from apps.systems.models import DataFlow

        bom_ref = flow_data.get("bom-ref", "")
        source_ref = flow_data.get("source")
        dest_ref = flow_data.get("destination")

        source = resolver.resolve("asset", source_ref) if source_ref else None
        dest = resolver.resolve("asset", dest_ref) if dest_ref else None

        if not source or not dest:
            missing = []
            if not source:
                missing.append(f"source '{source_ref}'")
            if not dest:
                missing.append(f"destination '{dest_ref}'")
            msg = (
                f"Data flow '{flow_data.get('name', bom_ref)}' was skipped "
                f"because {' and '.join(missing)} could not be resolved. "
                f"Check that the referenced assets are defined in the file."
            )
            logger.warning(msg)
            warnings.append(msg)
            return None

        protocols = flow_data.get("protocols", [])

        crosses_trust_zone = getattr(source, "trust_zone_id", None) != getattr(
            dest, "trust_zone_id", None
        )

        flow = DataFlow.objects.create(
            source_component=source,
            dest_component=dest,
            label=flow_data.get("name", ""),
            description=flow_data.get("description", ""),
            protocol=protocols[0] if protocols else "",
            encrypted=flow_data.get("encrypted", False),
            authenticated=flow_data.get("authenticated", False),
            crosses_trust_zone=crosses_trust_zone,
            format_metadata={"cyclonedx": {"bom_ref": bom_ref}},
        )
        resolver.register("flow", bom_ref, flow)
        return flow

    def _import_use_case(self, uc_data, threat_model, resolver):
        from apps.threat_models.models import UseCase

        bom_ref = uc_data.get("bom-ref", "")
        name = uc_data.get("name", bom_ref)

        flow_data = {}
        for cdx_key, precogly_key in (
            ("preconditions", "preconditions"),
            ("postconditions", "postconditions"),
            ("successCriteria", "success_criteria"),
            ("mainFlow", "main_flow"),
            ("alternativeFlows", "alternative_flows"),
            ("exceptions", "exceptions"),
        ):
            if uc_data.get(cdx_key):
                flow_data[precogly_key] = uc_data[cdx_key]

        use_case = UseCase.objects.create(
            threat_model=threat_model,
            name=name,
            description=uc_data.get("description", ""),
            flow_data=flow_data,
            format_metadata={"cyclonedx": {"bom_ref": bom_ref}},
        )
        resolver.register("usecase", bom_ref, use_case)
        return use_case

    def _import_requirement(self, req_data, resolver):
        """Register a CDX requirement bom-ref -> (framework_name, section_code).

        The referenced StandardRequirement may not be installed locally, so we
        register the raw identifiers here and resolve the FK lazily in
        _resolve_control_satisfies (GSA-TTS/TTSE-petrified-forest-sspp#31 item 1).
        """
        bom_ref = req_data.get("bom-ref", "")
        if not bom_ref:
            return
        resolver.register(
            "requirement",
            bom_ref,
            self._requirement_snapshot_from_definition(req_data),
        )

    def _resolve_control_satisfies(self, cm, resolver, warnings):
        """Create InstanceCountermeasureStandard rows from a control's satisfies[].

        Resolves the StandardRequirement FK when its framework is installed;
        otherwise stores section_code/framework_name snapshots so the mapping
        still displays (GSA-TTS/TTSE-petrified-forest-sspp#31 item 1).
        """
        from apps.compliance.models import StandardRequirement
        from apps.threats.models import InstanceCountermeasureStandard

        satisfies = getattr(cm, "_deferred_satisfies", None)
        if not satisfies:
            return

        for req_ref in satisfies:
            req_info = resolver.resolve("requirement", req_ref)
            if not isinstance(req_info, dict):
                msg = (
                    f"Control '{cm.countermeasure_name}': satisfies reference "
                    f"'{req_ref}' does not match any requirement definition; skipped."
                )
                logger.warning(msg)
                warnings.append(msg)
                continue

            section_code = req_info.get("section_code", "")
            framework_name = req_info.get("framework_name", "")
            requirement = None
            if section_code and framework_name:
                requirement = StandardRequirement.objects.filter(
                    framework__name=framework_name,
                    section_code=section_code,
                ).first()

            if requirement:
                InstanceCountermeasureStandard.objects.get_or_create(
                    countermeasure=cm,
                    requirement=requirement,
                    defaults={
                        "section_code": section_code,
                        "framework_name": framework_name,
                        "requirement_description": req_info.get("description", ""),
                    },
                )
            else:
                InstanceCountermeasureStandard.objects.get_or_create(
                    countermeasure=cm,
                    requirement=None,
                    section_code=section_code,
                    framework_name=framework_name,
                    defaults={
                        "requirement_description": req_info.get("description", ""),
                    },
                )

    def _import_control(self, control_data, threat_model, resolver, warnings):
        from apps.threats.models import InstanceCountermeasure

        bom_ref = control_data.get("bom-ref", "")
        name = control_data.get("name", bom_ref)
        cdx_status = control_data.get("status", "recommended")
        valid_statuses = {c[0] for c in InstanceCountermeasure.Status.choices}
        status = CDX_STATUS_TO_CONTROL.get(cdx_status, "gap")
        if status not in valid_statuses:
            msg = (
                f"Control '{name}': unrecognized status '{cdx_status}', "
                f"defaulting to 'gap'."
            )
            logger.warning(msg)
            warnings.append(msg)
            status = "gap"

        effectiveness = None
        eff_data = control_data.get("effectiveness", {})
        if isinstance(eff_data, dict) and "percentage" in eff_data:
            effectiveness = eff_data["percentage"]

        # Extract control_functions and control_nature from properties
        control_functions = []
        control_nature = ""
        for prop in control_data.get("properties", []):
            prop_name = prop.get("name", "")
            if prop_name == "precogly:control-functions":
                control_functions = [
                    v.strip() for v in prop.get("value", "").split(",") if v.strip()
                ]
            elif prop_name == "precogly:control-nature":
                control_nature = prop.get("value", "")
        if not control_functions:
            category = control_data.get("category", "")
            if category:
                control_functions = [category]

        # Store original status in format_metadata if it maps lossy
        cdx_meta = {"bom_ref": bom_ref}
        if cdx_status in ("proposed", "approved"):
            cdx_meta["original_status"] = cdx_status

        # Extract vault:* properties for inheritance metadata
        props = {
            p["name"]: p["value"]
            for p in control_data.get("properties", [])
            if isinstance(p, dict) and "name" in p and "value" in p
        }
        nist_id = props.get("nist:control-id") or props.get("crm:control-id", "")
        origination = props.get("vault:origination", "")
        provider_system = props.get("vault:providing-system", "")
        if nist_id:
            cdx_meta["nist_control_id"] = nist_id
        is_inherited = origination in ("inherited", "shared")

        # poam:* properties annotate an existing control as a POA&M item
        # rather than creating a separate entity (GSA-TTS/TTSE-petrified-forest-sspp#81).
        poam_props = {
            k[len("poam:") :]: v for k, v in props.items() if k.startswith("poam:")
        }
        poam_id = poam_props.get("id", "")
        scheduled_completion = None
        if poam_props.get("scheduled-completion"):
            from datetime import date

            try:
                scheduled_completion = date.fromisoformat(
                    poam_props["scheduled-completion"]
                )
            except ValueError:
                msg = (
                    f"Control '{name}': invalid poam:scheduled-completion date "
                    f"'{poam_props['scheduled-completion']}', ignored."
                )
                logger.warning(msg)
                warnings.append(msg)
        if poam_props:
            cdx_meta["poam"] = poam_props

        # externalReferences: an entry typed "evidence" populates evidence_url
        # (GSA-TTS/TTSE-petrified-forest-sspp#31 item 3).
        evidence_url = ""
        for ref in control_data.get("externalReferences", []):
            if (
                isinstance(ref, dict)
                and ref.get("type") == "evidence"
                and ref.get("url")
            ):
                evidence_url = ref["url"]
                break

        cm = InstanceCountermeasure.objects.create(
            threat_model=threat_model,
            countermeasure_name=name,
            countermeasure_description=control_data.get("description", ""),
            control_functions=control_functions,
            control_nature=control_nature,
            status=status,
            effectiveness=effectiveness,
            is_inherited=is_inherited,
            inherited_from_component_name=provider_system or "",
            evidence_url=evidence_url,
            source=(
                InstanceCountermeasure.Source.VAULT_IMPORT
                if is_inherited or poam_props
                else InstanceCountermeasure.Source.MANUAL
            ),
            poam_id=poam_id,
            scheduled_completion=scheduled_completion,
            format_metadata={"cyclonedx": cdx_meta},
        )
        resolver.register("control", bom_ref, cm)

        # Deferred: satisfies resolved by _resolve_control_satisfies after all
        # requirements are imported. appliesTo import is not currently implemented.
        if control_data.get("satisfies"):
            cm._deferred_satisfies = control_data["satisfies"]

        return cm

    def _import_threat(
        self,
        threat_data,
        threat_model,
        resolver,
        scenario_threat_refs,
        warnings,
    ):
        from apps.threats.models import ThreatLibrary

        bom_ref = threat_data.get("bom-ref", "")
        name = threat_data.get("name", bom_ref)

        threat_lib, _ = ThreatLibrary.objects.get_or_create(
            name=name,
            defaults={
                "description": threat_data.get("description", ""),
                "slug": slugify(name)[:100],
                "customization_status": "detached",
            },
        )
        resolver.register("threat", bom_ref, threat_lib)

        self._import_threat_categories(threat_data, threat_lib)

        # Store triage properties for scenario import to pick up
        triage_status = "open"
        decision_rationale = ""
        for prop in threat_data.get("properties", []):
            prop_name = prop.get("name", "")
            if prop_name == "precogly:threat-status":
                triage_status = prop.get("value", "open")
            elif prop_name == "precogly:decision-rationale":
                decision_rationale = prop.get("value", "")
        if triage_status != "open" or decision_rationale:
            threat_lib._triage_status = triage_status
            threat_lib._decision_rationale = decision_rationale

        # If no scenarios reference this threat, create instance threats
        # directly from affectedAssets
        if bom_ref not in scenario_threat_refs:
            for asset_ref in threat_data.get("affectedAssets", []):
                self._create_instance_threat_from_abstract(
                    threat_lib,
                    asset_ref,
                    threat_data,
                    threat_model,
                    resolver,
                    warnings,
                )

    def _import_threat_categories(self, threat_data, threat_lib):
        """Parse CycloneDX categories and create taxonomy entries via get_or_create."""
        from apps.threats.models import (
            ExternalTaxonomy,
            TaxonomyEntry,
            ThreatLibraryTaxonomyEntry,
        )

        for category in threat_data.get("categories", []):
            taxonomy_slug = category.get("taxonomy", "")
            external_id = category.get("id", "")
            entry_name = category.get("name", external_id)
            if not taxonomy_slug or not external_id:
                continue

            taxonomy, _ = ExternalTaxonomy.objects.get_or_create(
                slug=taxonomy_slug,
                defaults={"name": taxonomy_slug.upper()},
            )
            entry, _ = TaxonomyEntry.objects.get_or_create(
                taxonomy=taxonomy,
                external_id=external_id,
                defaults={"title": entry_name},
            )
            ThreatLibraryTaxonomyEntry.objects.get_or_create(
                threat_library=threat_lib,
                taxonomy_entry=entry,
            )

    def _create_instance_threat_from_abstract(
        self,
        threat_lib,
        asset_ref,
        threat_data,
        threat_model,
        resolver,
        warnings,
    ):
        from apps.systems.models import DataFlow, OrgsystemComponent
        from apps.threats.models import (
            ComponentInstanceThreat,
            DataFlowInstanceThreat,
        )

        target = resolver.resolve("asset", asset_ref) or resolver.resolve(
            "flow", asset_ref
        )
        if not target:
            msg = (
                f"Threat '{threat_lib.name}' references unknown asset '{asset_ref}' "
                f"and the link was skipped."
            )
            logger.warning(msg)
            warnings.append(msg)
            return

        defaults = {
            "threat_name": threat_lib.name,
            "threat_description": threat_lib.description,
            "inherent_severity": "medium",
        }
        if hasattr(threat_lib, "_triage_status"):
            defaults["triage_status"] = threat_lib._triage_status
        if hasattr(threat_lib, "_decision_rationale"):
            defaults["decision_rationale"] = threat_lib._decision_rationale

        created = False
        if isinstance(target, OrgsystemComponent):
            _, created = ComponentInstanceThreat.objects.get_or_create(
                component=target,
                threat_library=threat_lib,
                defaults=defaults,
            )
        elif isinstance(target, DataFlow):
            _, created = DataFlowInstanceThreat.objects.get_or_create(
                data_flow=target,
                threat_library=threat_lib,
                defaults=defaults,
            )

        if not created and target:
            msg = (
                f"Duplicate threat-asset link skipped: "
                f"threat '{threat_lib.name}' x asset '{target.name}'."
            )
            logger.warning(msg)
            warnings.append(msg)

    def _import_scenario(self, scenario_data, threat_model, resolver, warnings):
        from apps.systems.models import DataFlow, OrgsystemComponent
        from apps.threats.models import (
            ComponentInstanceThreat,
            DataFlowInstanceThreat,
        )

        bom_ref = scenario_data.get("bom-ref", "")
        threat_ref = scenario_data.get("threat")
        threat_lib = resolver.resolve("threat", threat_ref) if threat_ref else None

        severity = "medium"
        risk_score = scenario_data.get("riskScore", {})
        if risk_score.get("level"):
            severity = CDX_TO_LEVEL.get(risk_score["level"], "medium")

        intent = scenario_data.get("intent", "")
        access_level = scenario_data.get("accessLevel", "")

        # Triage status from scenario properties or abstract threat
        triage_status = "open"
        decision_rationale = ""
        for prop in scenario_data.get("properties", []):
            prop_name = prop.get("name", "")
            if prop_name == "precogly:threat-status":
                triage_status = prop.get("value", "open")
            elif prop_name == "precogly:decision-rationale":
                decision_rationale = prop.get("value", "")
        if triage_status == "open" and threat_lib:
            triage_status = getattr(threat_lib, "_triage_status", "open")
            decision_rationale = decision_rationale or getattr(
                threat_lib, "_decision_rationale", ""
            )

        # Tier 3 scenario metadata
        scenario_meta = {}
        for key in ("motivation", "attackVector", "exploitability"):
            if scenario_data.get(key):
                scenario_meta[key] = scenario_data[key]

        for asset_ref in scenario_data.get("affectedAssets", []):
            target = resolver.resolve("asset", asset_ref) or resolver.resolve(
                "flow", asset_ref
            )
            if not target:
                msg = (
                    f"Scenario '{bom_ref}' references unknown asset '{asset_ref}' "
                    f"and the link was skipped."
                )
                logger.warning(msg)
                warnings.append(msg)
                continue

            cdx_meta = {"scenario_bom_ref": bom_ref}
            if scenario_meta:
                cdx_meta["scenario"] = scenario_meta

            instance_kwargs = {
                "threat_library": threat_lib,
                "threat_name": threat_lib.name if threat_lib else "",
                "threat_description": (threat_lib.description if threat_lib else ""),
                "inherent_severity": severity,
                "intent": intent,
                "access_level": access_level,
                "format_metadata": {"cyclonedx": cdx_meta},
            }
            if triage_status != "open":
                instance_kwargs["triage_status"] = triage_status
            if decision_rationale:
                instance_kwargs["decision_rationale"] = decision_rationale

            if isinstance(target, OrgsystemComponent):
                instance = ComponentInstanceThreat.objects.create(
                    component=target,
                    **instance_kwargs,
                )
                resolver.register("scenario", bom_ref, instance)
            elif isinstance(target, DataFlow):
                instance = DataFlowInstanceThreat.objects.create(
                    data_flow=target,
                    **instance_kwargs,
                )
                resolver.register("scenario", bom_ref, instance)

    def _import_risk(self, risk_data, threat_model, resolver):
        from apps.threats.models import (
            ComponentInstanceThreat,
            DataFlowInstanceThreat,
            Risk,
            RiskResponse,
            RiskThreat,
        )

        bom_ref = risk_data.get("bom-ref", "")
        name = risk_data.get("name", bom_ref)

        inherent = risk_data.get("inherentRisk", {})
        inherent_score, inherent_level = self._extract_risk_score(inherent)

        residual = risk_data.get("residualRisk", {})
        residual_score, residual_level = self._extract_risk_score(residual)

        target = risk_data.get("targetRisk", {})
        target_score, target_level = self._extract_risk_score(target)

        domains = [
            d.get("type", d) if isinstance(d, dict) else d
            for d in risk_data.get("domains", [])
        ]

        risk = Risk.objects.create(
            threat_model=threat_model,
            name=name,
            description=risk_data.get("statement", risk_data.get("description", "")),
            inherent_score=inherent_score,
            inherent_level=inherent_level,
            residual_score=residual_score if residual_score else None,
            residual_level=residual_level if residual_level else "",
            target_score=target_score if target_score else None,
            target_level=target_level if target_level else "",
            domains=domains,
            scoring_metadata={
                "cyclonedx": {
                    "inherent_rating": inherent,
                    "residual_rating": residual,
                }
            },
            format_metadata={"cyclonedx": {"bom_ref": bom_ref}},
        )
        resolver.register("risk", bom_ref, risk)

        # Risk responses
        for resp_data in risk_data.get("responses", []):
            strategy = resp_data.get("strategy", "")
            target_date = None
            if resp_data.get("targetDate"):
                from django.utils.dateparse import parse_datetime

                target_date = parse_datetime(resp_data["targetDate"])

            # Collect remaining fields as format_metadata
            known_keys = {
                "strategy",
                "description",
                "status",
                "effectiveness",
                "cost",
                "priority",
                "targetDate",
            }
            extra_meta = {k: v for k, v in resp_data.items() if k not in known_keys}

            eff_data = resp_data.get("effectiveness", {})
            effectiveness = (
                eff_data.get("percentage") if isinstance(eff_data, dict) else None
            )

            RiskResponse.objects.create(
                risk=risk,
                strategy=CDX_TO_RESPONSE.get(strategy, strategy),
                description=resp_data.get("description", ""),
                status=resp_data.get("status", "planned"),
                effectiveness=effectiveness,
                cost=resp_data.get("cost", ""),
                priority=resp_data.get("priority", ""),
                target_date=target_date,
                format_metadata=({"cyclonedx": extra_meta} if extra_meta else {}),
            )

        # Link to threats via relatedThreats
        for threat_ref in risk_data.get("relatedThreats", []):
            threat_lib = resolver.resolve("threat", threat_ref)
            if threat_lib:
                for ct in ComponentInstanceThreat.objects.filter(
                    threat_library=threat_lib,
                    component__threat_model=threat_model,
                ):
                    RiskThreat.objects.get_or_create(risk=risk, component_threat=ct)
                for ft in DataFlowInstanceThreat.objects.filter(
                    threat_library=threat_lib,
                    data_flow__source_component__threat_model=threat_model,
                ):
                    RiskThreat.objects.get_or_create(risk=risk, flow_threat=ft)

    def _extract_risk_score(self, rating):
        """Extract (score, level) from a CycloneDX risk rating."""
        if not rating:
            return 45, "medium"

        score_data = rating.get("riskScore", {})
        level = score_data.get("level", "medium")

        score = score_data.get("score")
        if score is not None:
            score = min(100, max(0, int(score)))
        else:
            score = {"low": 20, "medium": 45, "high": 70, "critical": 90}.get(level, 45)

        precogly_level = CDX_TO_LEVEL.get(level, "medium")
        return score, precogly_level

    def _resolve_control_threat_links(self, threats_block, threat_model, resolver):
        """Create CountermeasureThreatLink records from threat mitigations."""
        from apps.threats.models import (
            ComponentInstanceThreat,
            CountermeasureThreatLink,
            DataFlowInstanceThreat,
        )

        for threat_data in threats_block.get("threats", []):
            mitigation_refs = threat_data.get("mitigations", [])
            if not mitigation_refs:
                continue

            threat_ref = threat_data.get("bom-ref", "")
            threat_lib = resolver.resolve("threat", threat_ref)
            if not threat_lib:
                continue

            component_threats = list(
                ComponentInstanceThreat.objects.filter(
                    threat_library=threat_lib,
                    component__threat_model=threat_model,
                )
            )
            flow_threats = list(
                DataFlowInstanceThreat.objects.filter(
                    threat_library=threat_lib,
                    data_flow__source_component__threat_model=threat_model,
                )
            )

            for mitigation_ref in mitigation_refs:
                control = resolver.resolve("control", mitigation_ref)
                if not control:
                    continue
                for ct in component_threats:
                    CountermeasureThreatLink.objects.get_or_create(
                        countermeasure=control,
                        component_threat=ct,
                    )
                for ft in flow_threats:
                    CountermeasureThreatLink.objects.get_or_create(
                        countermeasure=control,
                        flow_threat=ft,
                    )

    def _store_tier3_data(self, threat_model, json_data, blueprint, resolver, warnings):
        """Store ThreatModel-level Tier 3 data for round-trip fidelity."""
        tier3 = {}

        if blueprint.get("behaviors"):
            tier3["behaviors"] = blueprint["behaviors"]

        threats_block = json_data.get("threats", {})
        if threats_block.get("attackTrees"):
            tier3["attack_trees"] = threats_block["attackTrees"]
        if threats_block.get("attackPaths"):
            tier3["attack_paths"] = threats_block["attackPaths"]
        if threats_block.get("abuseCases"):
            tier3["abuse_cases"] = threats_block["abuseCases"]

        risks_block = json_data.get("risks", {})
        if risks_block.get("assessments"):
            tier3["risk_assessments"] = risks_block["assessments"]
        if risks_block.get("riskAppetites"):
            tier3["risk_appetites"] = risks_block["riskAppetites"]

        if blueprint.get("relationships"):
            tier3["relationships"] = blueprint["relationships"]

        if json_data.get("metadata"):
            tier3["document_metadata"] = json_data["metadata"]

        if blueprint.get("modelTypes"):
            tier3["model_types"] = blueprint["modelTypes"]

        if json_data.get("components"):
            tier3["components"] = json_data["components"]

        # Visualizations — extract Precogly DFD, pass through the rest
        visualizations = blueprint.get("visualizations", [])
        passthrough_visualizations = []
        for vis in visualizations:
            if vis.get("type") == "precogly-dfd" and vis.get("data"):
                self._import_dfd(vis, threat_model, resolver, warnings)
            else:
                passthrough_visualizations.append(vis)
        if passthrough_visualizations:
            tier3["visualizations"] = passthrough_visualizations

        if tier3:
            threat_model.format_metadata.setdefault("cyclonedx", {}).update(tier3)
            threat_model.save(update_fields=["format_metadata"])

    def _import_dfd(self, vis_data, threat_model, resolver, warnings):
        """Recreate a DFD record from an exported Precogly DFD visualization."""
        import copy

        from apps.diagrams.models import DFD

        name = vis_data.get("name", f"{threat_model.name} DFD")
        diagram_type = vis_data.get("diagramType", "level1")
        canvas_data = copy.deepcopy(vis_data.get("data", {}))

        # Normalize camelCase keys from guest editor to snake_case
        for node in canvas_data.get("nodes", []):
            if "parentId" in node and "parent_id" not in node:
                node["parent_id"] = node.pop("parentId")
            data = node.get("data", {})
            if "trustZoneId" in data and "trust_zone_id" not in data:
                data["trust_zone_id"] = data.pop("trustZoneId")
        for edge in canvas_data.get("edges", []):
            data = edge.get("data", {})
            if "dataflowId" in data and "dataflow_id" not in data:
                data["dataflow_id"] = data.pop("dataflowId")
            if "trustBoundaryId" in data and "trust_boundary_id" not in data:
                data["trust_boundary_id"] = data.pop("trustBoundaryId")

        # Build resolver lookups
        asset_name_to_component = {}
        zone_name_to_zone = {}
        boundary_name_to_boundary = {}
        flow_label_to_flow = {}
        for _ref_key, (entity_type, obj) in resolver._ref_to_obj.items():
            if entity_type == "asset" and hasattr(obj, "name"):
                asset_name_to_component[obj.name] = obj
            elif entity_type == "zone" and hasattr(obj, "name"):
                zone_name_to_zone[obj.name] = obj
            elif entity_type == "boundary" and hasattr(obj, "id"):
                if hasattr(obj, "name"):
                    boundary_name_to_boundary[obj.name] = obj
            elif entity_type == "flow" and hasattr(obj, "label"):
                flow_label_to_flow[obj.label] = obj

        # Assign/remap foreign keys in nodes
        for node in canvas_data.get("nodes", []):
            data = node.get("data", {})
            label = data.get("label", "")
            node_type = node.get("type", "")

            if node_type == "trustZone":
                zone = zone_name_to_zone.get(label)
                if zone:
                    data["trust_zone_id"] = zone.id
                continue

            new_component = asset_name_to_component.get(label)
            if new_component:
                data["component_id"] = new_component.id
            elif data.get("component_id") is not None:
                msg = (
                    f"DFD node '{label}' has no matching imported asset. "
                    f"It may appear unlinked on the canvas."
                )
                logger.warning(msg)
                warnings.append(msg)

        # Assign/remap foreign keys in edges
        for edge in canvas_data.get("edges", []):
            data = edge.get("data", {})
            label = data.get("label", "")
            edge_type = edge.get("type", "")

            if edge_type == "trustBoundary":
                boundary = boundary_name_to_boundary.get(label)
                if boundary:
                    data["trust_boundary_id"] = boundary.id
                continue

            new_flow = flow_label_to_flow.get(label)
            if new_flow:
                data["dataflow_id"] = new_flow.id

        DFD.objects.create(
            name=name,
            diagram_type=diagram_type,
            threat_model=threat_model,
            is_primary=True,
            canvas_data=canvas_data,
        )
