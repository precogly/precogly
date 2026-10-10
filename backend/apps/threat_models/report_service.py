"""
Report data assembly service.

Builds a comprehensive dataset for threat model reporting by gathering data
from all related models in optimized query batches.
"""

from collections import defaultdict

from apps.compliance.models import StandardFramework, StandardRequirementMapping
from apps.systems.models import (
    Boundary,
    ComponentDataAsset,
    Flow,
    FlowAsset,
    OrgsystemComponent,
    Zone,
)
from apps.threats.models import (
    ACTIVE_TRIAGE_STATUSES,
    CountermeasureThreatLink,
    InstanceCountermeasure,
    InstanceCountermeasureStandard,
    InstanceThreat,
    Risk,
)
from apps.threats.services import derive_risk_status

from .models import Assumption


def _get_scoped_ids(threat_model):
    """The component and flow ids of every blueprint of the model.

    Read from the rows' blueprint keys, not from canvas JSON, so the report
    agrees with the analysis screen and completion status (F30).
    """
    component_ids = list(
        OrgsystemComponent.objects.filter(
            blueprint__threat_model=threat_model
        ).values_list("id", flat=True)
    )
    dataflow_ids = list(
        Flow.objects.filter(blueprint__threat_model=threat_model).values_list(
            "id", flat=True
        )
    )
    return component_ids, dataflow_ids


def _build_metadata(threat_model):
    """Build metadata section."""
    frameworks = []
    for assoc in threat_model.framework_associations.select_related("framework").all():
        frameworks.append(
            {
                "name": assoc.framework.name,
                "slug": assoc.framework.slug,
                "version": assoc.framework.version,
            }
        )

    return {
        "name": threat_model.name,
        "description": threat_model.description,
        "criticality": threat_model.criticality,
        "risk_scoring_method": threat_model.risk_scoring_method,
        "methodologies": list(threat_model.methodologies or []),
        "owning_team": threat_model.owning_team.name
        if threat_model.owning_team
        else None,
        "created_by": threat_model.created_by.email
        if threat_model.created_by
        else None,
        "created_at": threat_model.created_at.isoformat()
        if threat_model.created_at
        else None,
        "updated_at": threat_model.updated_at.isoformat()
        if threat_model.updated_at
        else None,
        "frameworks": frameworks,
        "lifecycle_phase": threat_model.lifecycle_phase,
        "valid_from": threat_model.valid_from.isoformat()
        if threat_model.valid_from
        else None,
        "valid_until": threat_model.valid_until.isoformat()
        if threat_model.valid_until
        else None,
        "review_frequency": threat_model.review_frequency,
        "review": _review(threat_model),
    }


def _review(threat_model):
    from .review import review_state

    state = review_state(threat_model)
    return {
        "approval_state": state["approval_state"],
        "review_due": state["review_due"],
        "reviewer": state["reviewer_email"],
        "reviewed_at": state["reviewed_at"].isoformat()
        if state["reviewed_at"]
        else None,
        "approver": state["approver_email"],
        "approved_at": state["approved_at"].isoformat()
        if state["approved_at"]
        else None,
        "source_document_review": state["source_document_review"],
    }


def _build_scope(threat_model):
    """Build scope section."""
    out_of_scope = list(threat_model.out_of_scope_items.values("id", "name", "reason"))

    referenced_models = []
    for rel in threat_model.outgoing_relationships.select_related(
        "target_threat_model"
    ).all():
        referenced_models.append(
            {
                "id": str(rel.target_threat_model.id),
                "name": rel.target_threat_model.name,
                "relation_type": rel.relation_type,
            }
        )

    assumptions = [
        {
            "id": assumption.id,
            "blueprint": assumption.blueprint.name,
            "description": assumption.description,
            "topic": assumption.topic,
            "validity": assumption.validity,
            "impact": assumption.impact,
            "owner": assumption.owner.email
            if assumption.owner
            else assumption.owner_name,
            "validation_method": assumption.validation_method,
            "validation_date": assumption.validation_date.isoformat()
            if assumption.validation_date
            else None,
            "components": [
                link.component.name for link in assumption.component_links.all()
            ],
        }
        for assumption in Assumption.objects.filter(
            blueprint__threat_model=threat_model
        )
        .select_related("owner", "blueprint")
        .prefetch_related("component_links__component")
    ]
    objectives = [
        {
            "id": objective.id,
            "name": objective.name,
            "description": objective.description,
            "criticality": objective.criticality,
            "owner": objective.owner.email if objective.owner else objective.owner_name,
            "threat_count": objective.threat_links.count(),
            "risk_count": objective.risk_links.count(),
        }
        for objective in threat_model.business_objectives.select_related("owner")
    ]

    return {
        "description": threat_model.description,
        "assumptions": assumptions,
        "business_objectives": objectives,
        "out_of_scope_items": out_of_scope,
        "referenced_models": referenced_models,
    }


def _build_architecture(threat_model, component_ids):
    """Build architecture section."""
    dfds = []
    for dfd in threat_model.dfds.all():
        canvas_data = dfd.canvas_data or {}
        dfds.append(
            {
                "id": str(dfd.id),
                "name": dfd.name,
                "diagram_type": dfd.diagram_type,
                "is_primary": dfd.is_primary,
                "node_count": len(canvas_data.get("nodes", [])),
                "edge_count": len(canvas_data.get("edges", [])),
                "canvas_data": canvas_data,
            }
        )

    reference_images = []
    for img in threat_model.reference_images.all():
        reference_images.append(
            {
                "id": img.id,
                "filename": img.filename,
                "description": img.description,
            }
        )

    zones = []
    for zone in Zone.objects.filter(blueprint__threat_model=threat_model):
        zones.append(
            {
                "id": zone.id,
                "name": zone.name,
                "zone_type": zone.zone_type,
                "trust_level": zone.trust_level,
                "description": zone.description,
            }
        )

    boundaries = []
    for boundary in Boundary.objects.filter(
        blueprint__threat_model=threat_model
    ).select_related("zone_a", "zone_b"):
        boundaries.append(
            {
                "id": boundary.id,
                "label": boundary.label,
                "boundary_type": boundary.boundary_type,
                "zone_a": boundary.zone_a.name,
                "zone_b": boundary.zone_b.name,
                "description": boundary.description,
                "authentication": list(boundary.authentication or []),
                "authorization": list(boundary.authorization or []),
                "requires_authentication": boundary.requires_authentication,
                "requires_authorization": boundary.requires_authorization,
                "data_validation": boundary.data_validation,
                "logging": boundary.logging,
                "monitoring": boundary.monitoring,
                "rate_limit": boundary.rate_limit,
            }
        )

    return {
        "dfds": dfds,
        "reference_images": reference_images,
        "zones": zones,
        "boundaries": boundaries,
    }


def _build_data_assets(threat_model, component_ids, dataflow_ids):
    """Build data assets section."""
    assets = []
    for asset in threat_model.data_assets.all():
        placements = list(
            ComponentDataAsset.objects.filter(
                data_asset=asset,
                component_id__in=component_ids,
            )
            .select_related("component")
            .values("component__name", "data_state", "volume", "encrypted")
        )
        in_transit = list(
            FlowAsset.objects.filter(
                data_asset=asset,
                flow_id__in=dataflow_ids,
            )
            .select_related("flow")
            .values("flow__label", "protection_method", "encryption_type")
        )
        assets.append(
            {
                "id": asset.id,
                "name": asset.name,
                "description": asset.description,
                "classification": asset.classification,
                "confidentiality": asset.confidentiality,
                "integrity": asset.integrity,
                "availability": asset.availability,
                "placements": [
                    {
                        "component_name": p["component__name"],
                        "data_state": p["data_state"],
                        "volume": p["volume"],
                        "encrypted": p["encrypted"],
                    }
                    for p in placements
                ],
                "in_transit": [
                    {
                        "flow_label": t["flow__label"],
                        "protection_method": t["protection_method"],
                        "encryption_type": t["encryption_type"],
                    }
                    for t in in_transit
                ],
            }
        )

    return assets


def _build_components(component_ids):
    """Build components section grouped by category."""
    components = OrgsystemComponent.objects.filter(id__in=component_ids).select_related(
        "zone"
    )

    grouped = {
        "processes": [],
        "data_stores": [],
        "human_actors": [],
        "system_actors": [],
    }

    for comp in components:
        entry = {
            "id": comp.id,
            "name": comp.name,
            "category": comp.category,
            "component_type": comp.component_type,
            "kind": comp.effective_kind,
            "actor_type": comp.actor_type,
            "provider": comp.provider,
            "zone": comp.zone.name if comp.zone else None,
            "description": comp.description,
        }
        category = comp.category or ""
        if category == "process":
            grouped["processes"].append(entry)
        elif category == "datastore":
            grouped["data_stores"].append(entry)
        elif category == "external_human_actor":
            grouped["human_actors"].append(entry)
        elif category == "external_system_actor":
            grouped["system_actors"].append(entry)
        else:
            grouped["processes"].append(entry)

    return grouped


def _build_flows(dataflow_ids):
    """Build data flows section."""
    flows = Flow.objects.filter(id__in=dataflow_ids).select_related(
        "source_component", "dest_component"
    )

    result = []
    for flow in flows:
        result.append(
            {
                "id": flow.id,
                "label": flow.label,
                "source": flow.source_component.name if flow.source_component else None,
                "destination": flow.dest_component.name
                if flow.dest_component
                else None,
                "protocol": flow.protocol,
                "encrypted": flow.encrypted,
                "flow_type": flow.flow_type,
                "authentication": list(flow.authentication or []),
                "authorization": list(flow.authorization or []),
                "requires_authentication": flow.requires_authentication,
                "crosses_boundary": flow.crosses_boundary,
                "has_sensitive_data": flow.has_sensitive_data,
            }
        )

    return result


def _get_stride_category(threat_instance):
    """Extract STRIDE category from library or instance taxonomy entries."""
    if threat_instance.threat_library:
        for join in threat_instance.threat_library.taxonomy_entries.all():
            entry = join.taxonomy_entry
            if entry.taxonomy and entry.taxonomy.slug == "stride":
                return entry.external_id

    for link in threat_instance.instance_taxonomy_links.all():
        entry = link.taxonomy_entry
        if entry.taxonomy and entry.taxonomy.slug == "stride":
            return entry.external_id

    return "unknown"


def _get_taxonomy_entries(threat_instance):
    """Return merged taxonomy entries (library + instance), falling back to snapshot."""
    seen = {}

    if threat_instance.threat_library:
        for join in threat_instance.threat_library.taxonomy_entries.all():
            entry = join.taxonomy_entry
            if entry.taxonomy:
                key = (entry.taxonomy.slug, entry.external_id)
                seen[key] = {
                    "taxonomy_slug": entry.taxonomy.slug,
                    "external_id": entry.external_id,
                    "title": entry.title,
                    "reference_url": entry.reference_url or "",
                    "source": "library",
                }

    for link in threat_instance.instance_taxonomy_links.all():
        entry = link.taxonomy_entry
        if entry.taxonomy:
            key = (entry.taxonomy.slug, entry.external_id)
            if key not in seen:
                seen[key] = {
                    "taxonomy_slug": entry.taxonomy.slug,
                    "external_id": entry.external_id,
                    "title": entry.title,
                    "reference_url": entry.reference_url or "",
                    "source": "instance",
                }

    if not seen:
        return threat_instance.taxonomy_snapshot or []

    return list(seen.values())


def _serialize_compliance_standards(cm):
    """Serialize compliance standard mappings for a countermeasure.

    Merges library-level and instance-level mappings, with instance
    entries overriding library entries for the same requirement.
    """
    seen = {}

    if cm.countermeasure_library:
        for mapping in cm.countermeasure_library.standard_mappings.all():
            if mapping.requirement and mapping.requirement.framework:
                seen[mapping.requirement_id] = {
                    "framework_name": mapping.requirement.framework.name,
                    "section_code": mapping.requirement.section_code,
                    "sufficiency": mapping.sufficiency,
                }

    for mapping in cm.instance_standard_mappings.all():
        if mapping.requirement and mapping.requirement.framework:
            seen[mapping.requirement_id] = {
                "framework_name": mapping.requirement.framework.name,
                "section_code": mapping.requirement.section_code,
                "sufficiency": mapping.sufficiency,
            }
        elif not mapping.requirement:
            seen[f"snapshot-{mapping.id}"] = {
                "framework_name": mapping.framework_name,
                "section_code": mapping.section_code,
                "sufficiency": mapping.sufficiency,
            }

    return list(seen.values())


def _serialize_countermeasure(cm):
    """Serialize a countermeasure instance to dict."""
    return {
        "id": cm.id,
        "countermeasure_name": (
            cm.countermeasure_library.name if cm.countermeasure_library else None
        )
        or cm.countermeasure_name,
        "control_functions": (
            cm.countermeasure_library.control_functions
            if cm.countermeasure_library
            else None
        )
        or cm.control_functions,
        "control_nature": (
            cm.countermeasure_library.control_nature
            if cm.countermeasure_library
            else None
        )
        or cm.control_nature,
        "status": cm.status,
        "priority": cm.priority,
        "assigned_owner_email": cm.assigned_owner.email if cm.assigned_owner else None,
        "verified_by_email": cm.verified_by.email if cm.verified_by else None,
        "evidence_url": cm.evidence_url,
        "number": cm.number,
        "display_number": cm.display_number,
        "scope": _target_names(cm),
        "implemented_by_party": cm.implemented_by_party,
        "source": cm.source,
        "compliance_standards": _serialize_compliance_standards(cm),
    }


def _rating(rating):
    """A rating for the report: level, score, methodology, likelihood, impact."""
    if rating is None:
        return None
    return {
        "level": rating.level,
        "score": rating.score,
        "methodology": rating.methodology,
        "likelihood_level": rating.likelihood_level or None,
        "likelihood_score": rating.likelihood_score,
        "impact_level": rating.impact_level or None,
        "impact_score": rating.impact_score,
        "rationale": rating.rationale,
    }


def _target_names(threat):
    """The names a scenario's targets are shown under, in target order."""
    from .analysis_service import target_name

    names = []
    for target_row in threat.targets.all():
        row = target_row.target
        if row is not None:
            names.append(target_name(row))
    return names


def _build_threat_analysis(threat_model):
    """Build threat analysis section: STRIDE summary and every scenario once.

    One list keyed by scenario, each carrying its targets (plan section 5.3),
    in place of two dicts keyed by component name and flow label, which
    collided on equal names.
    """
    from django.db.models import Prefetch

    countermeasure_links_prefetch = Prefetch(
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
        )
        .order_by("display_order"),
    )

    threats = (
        InstanceThreat.objects.filter(threat_model=threat_model)
        .select_related("threat_library", "rating")
        .prefetch_related(
            "threat_library__taxonomy_entries__taxonomy_entry__taxonomy",
            "instance_taxonomy_links__taxonomy_entry__taxonomy",
            "targets__component",
            "targets__flow__source_component",
            "targets__flow__dest_component",
            "targets__zone",
            "targets__boundary",
            "business_objective_links__business_objective",
            countermeasure_links_prefetch,
        )
        .order_by("number")
    )

    stride_counts = defaultdict(int)
    active = []
    triaged = []

    for threat in threats:
        name = threat.threat_name or (
            threat.threat_library.name if threat.threat_library else None
        )
        targets = _target_names(threat)
        if threat.triage_status in ACTIVE_TRIAGE_STATUSES:
            category = _get_stride_category(threat)
            stride_counts[category] += 1
            active.append(
                {
                    "id": threat.id,
                    "number": threat.number,
                    "display_number": threat.display_number,
                    "whole_system": threat.whole_system,
                    "targets": targets,
                    "threat_name": name,
                    "threat_description": threat.threat_description
                    or (
                        threat.threat_library.description
                        if threat.threat_library
                        else None
                    ),
                    "stride_category": category,
                    "business_objectives": [
                        link.business_objective.name
                        for link in threat.business_objective_links.all()
                    ],
                    "taxonomy_entries": _get_taxonomy_entries(threat),
                    "rating": _rating(threat.rating),
                    "status": threat.status,
                    "impact_description": threat.impact_description,
                    "threat_actor_text": threat.threat_actor_text,
                    "countermeasures": [
                        _serialize_countermeasure(link.countermeasure)
                        for link in threat.countermeasure_links.all()
                    ],
                }
            )
        else:
            triaged.append(
                {
                    "id": threat.id,
                    "number": threat.number,
                    "display_number": threat.display_number,
                    "threat_name": name,
                    "targets": targets,
                    "triage_status": threat.triage_status,
                    "decision_rationale": threat.decision_rationale,
                }
            )

    return {
        "stride_summary": dict(stride_counts),
        "threats": active,
        "triaged_threats": triaged,
    }


def _build_countermeasure_summary(threat_model):
    """Build countermeasure summary with status breakdown.

    Uses direct threat_model FK — each countermeasure counted once even if shared.
    Controls with no threat link are listed on their own (I3): they are left
    out of gap and coverage figures by the readers, not hidden.
    """
    all_countermeasures = (
        InstanceCountermeasure.objects.filter(threat_model=threat_model)
        .select_related("countermeasure_library", "assigned_owner")
        .prefetch_related(
            "threat_links__threat__targets__component",
            "threat_links__threat__targets__flow__source_component",
            "threat_links__threat__targets__flow__dest_component",
            "threat_links__threat__targets__zone",
            "threat_links__threat__targets__boundary",
            "targets__component",
            "targets__flow__source_component",
            "targets__flow__dest_component",
            "targets__zone",
            "targets__boundary",
        )
    )

    status_counts = defaultdict(int)
    gaps = []
    waived = []
    unattached = []

    for cm in all_countermeasures:
        status_counts[cm.status] += 1
        cm_name = (
            cm.countermeasure_library.name if cm.countermeasure_library else None
        ) or cm.countermeasure_name

        links = list(cm.threat_links.all())
        first_threat = links[0].threat if links else None
        targets = _target_names(first_threat) if first_threat else []
        entry_id = str(cm.id)

        if not links:
            unattached.append(
                {
                    "id": entry_id,
                    "countermeasure_name": cm_name,
                    "control_number": cm.display_number,
                    "status": cm.status,
                    "auto_generated": cm.auto_generated,
                    "scope": _target_names(cm),
                }
            )

        # Unattached controls are listed on their own and stay out of the gap
        # and waived lists, which are about threats (I3).
        if not links:
            continue
        if cm.status == "gap":
            gaps.append(
                {
                    "id": entry_id,
                    "countermeasure_name": cm_name,
                    "control_number": cm.display_number,
                    "priority": cm.priority,
                    "assigned_owner_email": cm.assigned_owner.email
                    if cm.assigned_owner
                    else None,
                    "targets": targets,
                    "display_number": first_threat.display_number
                    if first_threat
                    else None,
                }
            )
        elif cm.status == "waived":
            waived.append(
                {
                    "id": entry_id,
                    "countermeasure_name": cm_name,
                    "control_number": cm.display_number,
                    "targets": targets,
                    "display_number": first_threat.display_number
                    if first_threat
                    else None,
                }
            )

    return {
        "status_breakdown": dict(status_counts),
        "gaps": gaps,
        "waived": waived,
        "unattached": unattached,
    }


def _build_risks(threat_model):
    """Build risk register section."""
    risks = (
        Risk.objects.filter(threat_model=threat_model)
        .select_related("inherent", "residual", "target", "owner")
        .prefetch_related(
            "risk_threats__threat__threat_library",
            "risk_threats__threat__targets__component",
            "risk_threats__threat__targets__flow__source_component",
            "risk_threats__threat__targets__flow__dest_component",
            "risk_threats__threat__targets__zone",
            "risk_threats__threat__targets__boundary",
        )
    )

    result = []
    for risk in risks:
        contributing_threats = []
        for risk_threat in risk.risk_threats.all():
            threat = risk_threat.threat
            contributing_threats.append(
                {
                    "threat_id": threat.id,
                    "display_number": threat.display_number,
                    "threat_name": threat.threat_name
                    or (threat.threat_library.name if threat.threat_library else None),
                    "status": threat.status,
                    "targets": _target_names(threat),
                }
            )

        result.append(
            {
                "id": risk.id,
                "name": risk.name,
                "description": risk.description,
                "status": risk.status,
                "statement": risk.statement,
                "exposure": derive_risk_status(risk),
                "business_objectives": [
                    link.business_objective.name
                    for link in risk.business_objective_links.all()
                ],
                "domains": list(risk.domains or []),
                "inherent": _rating(risk.inherent),
                "residual": _rating(risk.residual),
                "target": _rating(risk.target),
                "responses": [
                    {
                        "id": response.id,
                        "strategy": response.strategy,
                        "status": response.status,
                        "description": response.description,
                        "priority": response.priority,
                        "cost": response.cost,
                        "owner_email": response.owner.email if response.owner else None,
                        "target_date": response.target_date,
                        "countermeasures": [
                            link.countermeasure.display_number
                            for link in response.countermeasure_links.all()
                        ],
                    }
                    for response in risk.responses.all()
                ],
                "owner_email": risk.owner.email if risk.owner else None,
                "contributing_threats": contributing_threats,
            }
        )

    return result


def _build_compliance(threat_model, component_ids, dataflow_ids):
    """Build compliance section with framework coverage and satisfaction.

    Derives frameworks from instance-level compliance mappings rather than
    requiring explicit ThreatModelFramework associations.

    Coverage: requirement has at least one countermeasure mapped to it.
    Satisfaction: requirement has at least one countermeasure with status
    "verified" or "platform".
    """
    satisfied_statuses = {"verified", "platform"}

    # Collect all covered and satisfied (framework_id, requirement_id) pairs
    framework_coverage = defaultdict(set)
    framework_satisfied = defaultdict(set)

    # From unified countermeasure instance mappings (using threat_model FK)
    instance_standards = InstanceCountermeasureStandard.objects.filter(
        countermeasure__threat_model=threat_model,
        requirement__isnull=False,
    ).select_related("requirement__framework", "countermeasure")

    for mapping in instance_standards:
        fw_id = mapping.requirement.framework_id
        req_id = mapping.requirement_id
        framework_coverage[fw_id].add(req_id)
        if mapping.countermeasure.status in satisfied_statuses:
            framework_satisfied[fw_id].add(req_id)

    # Build framework summaries
    frameworks = []
    if framework_coverage:
        for framework in StandardFramework.objects.filter(
            id__in=framework_coverage.keys()
        ):
            covered_ids = framework_coverage[framework.id]
            satisfied_ids = framework_satisfied.get(framework.id, set())
            total_requirements = framework.requirements.count()
            frameworks.append(
                {
                    "name": framework.name,
                    "slug": framework.slug,
                    "total_requirements": total_requirements,
                    "covered_requirements": len(covered_ids),
                    "coverage_percentage": (
                        round(len(covered_ids) / total_requirements * 100, 1)
                        if total_requirements > 0
                        else 0
                    ),
                    "satisfied_requirements": len(satisfied_ids),
                    "satisfaction_percentage": (
                        round(len(satisfied_ids) / total_requirements * 100, 1)
                        if total_requirements > 0
                        else 0
                    ),
                }
            )

    # Build cross-framework requirement mappings
    cross_framework_mappings = []
    framework_slugs = {fw["slug"] for fw in frameworks}

    if len(framework_slugs) >= 2:
        relevant_mappings = StandardRequirementMapping.objects.filter(
            from_requirement__framework__slug__in=framework_slugs,
            to_requirement__framework__slug__in=framework_slugs,
        ).select_related(
            "from_requirement__framework",
            "to_requirement__framework",
        )

        # Group by (source_framework_slug, target_framework_slug)
        groups = defaultdict(list)
        for mapping in relevant_mappings:
            key = (
                mapping.from_requirement.framework.slug,
                mapping.to_requirement.framework.slug,
            )
            groups[key].append(
                {
                    "from_section_code": mapping.from_requirement.section_code,
                    "from_description": mapping.from_requirement.description,
                    "to_section_code": mapping.to_requirement.section_code,
                    "to_description": mapping.to_requirement.description,
                    "sufficiency": mapping.sufficiency,
                }
            )

        # Build display names from frameworks already computed above
        framework_name_by_slug = {fw["slug"]: fw["name"] for fw in frameworks}

        for (source_slug, target_slug), mappings_list in groups.items():
            cross_framework_mappings.append(
                {
                    "source_framework": framework_name_by_slug.get(
                        source_slug, source_slug
                    ),
                    "target_framework": framework_name_by_slug.get(
                        target_slug, target_slug
                    ),
                    "mappings": mappings_list,
                }
            )

    return {
        "frameworks": frameworks,
        "cross_framework_mappings": cross_framework_mappings,
    }


def _build_summary_metrics(threat_analysis, countermeasure_summary, risks):
    """Build summary metrics for dashboard."""
    active_threats = threat_analysis["threats"]
    total_active_threats = len(active_threats)
    total_triaged = len(threat_analysis["triaged_threats"])

    threat_status_counts = defaultdict(int)
    for threat in active_threats:
        threat_status_counts[threat["status"]] += 1

    cm_breakdown = countermeasure_summary["status_breakdown"]
    total_cms = sum(cm_breakdown.values())

    risk_level_counts = defaultdict(int)
    for risk in risks:
        rating = risk["residual"] or risk["inherent"]
        risk_level_counts[rating["level"]] += 1

    return {
        "total_active_threats": total_active_threats,
        "total_triaged_threats": total_triaged,
        "threats_by_status": dict(threat_status_counts),
        "total_countermeasures": total_cms,
        "countermeasures_by_status": cm_breakdown,
        "total_gaps": len(countermeasure_summary["gaps"]),
        "total_waived": len(countermeasure_summary["waived"]),
        "total_unattached": len(countermeasure_summary["unattached"]),
        "total_risks": len(risks),
        "risks_by_level": dict(risk_level_counts),
    }


def build_report_data(threat_model):
    """
    Assemble complete report dataset for a threat model.

    Returns a dict with all sections needed for any report type.
    """
    component_ids, dataflow_ids = _get_scoped_ids(threat_model)

    metadata = _build_metadata(threat_model)
    scope = _build_scope(threat_model)
    architecture = _build_architecture(threat_model, component_ids)
    data_assets = _build_data_assets(threat_model, component_ids, dataflow_ids)
    components = _build_components(component_ids)
    flows = _build_flows(dataflow_ids)
    threat_analysis = _build_threat_analysis(threat_model)
    countermeasure_summary = _build_countermeasure_summary(threat_model)
    risks = _build_risks(threat_model)
    compliance = _build_compliance(threat_model, component_ids, dataflow_ids)
    summary_metrics = _build_summary_metrics(
        threat_analysis, countermeasure_summary, risks
    )

    # Reuse completion status from serializer
    from apps.threat_models.serializers import ThreatModelSerializer

    serializer = ThreatModelSerializer()
    completion_status = serializer._compute_completion_status(threat_model)
    progress_checklist = serializer._flatten_to_legacy_checklist(completion_status)

    return {
        "metadata": metadata,
        "scope": scope,
        "architecture": architecture,
        "data_assets": data_assets,
        "components": components,
        "flows": flows,
        "threat_analysis": threat_analysis,
        "countermeasure_summary": countermeasure_summary,
        "risks": risks,
        "compliance": compliance,
        "summary_metrics": summary_metrics,
        "progress_checklist": progress_checklist,
        "completion_status": completion_status,
    }
