"""Service functions for risk computation and recalculation."""

from .models import (
    ACTIVE_TRIAGE_STATUSES,
    ComponentInstanceThreat,
    CountermeasureThreatLink,
    InstanceCountermeasure,
    Risk,
    RiskThreat,
)
from .scoring.registry import get_scoring_methods, score_to_level

STATUS_EFFECTIVENESS_FALLBACK = {
    "verified": 1.0,
    "platform": 1.0,
    "implemented": 0.7,
    "in_progress": 0.3,
    "planned": 0.5,
    "gap": 0.0,
    "waived": 0.0,
    "decommissioned": 0.0,
}

NON_CREDIT_STATUSES = {"gap", "waived", "decommissioned"}


def get_countermeasures_for_threat(threat):
    """Return countermeasures linked to a threat via the junction table."""
    if isinstance(threat, ComponentInstanceThreat):
        return InstanceCountermeasure.objects.filter(
            threat_links__component_threat=threat
        )
    else:
        return InstanceCountermeasure.objects.filter(threat_links__flow_threat=threat)


def recalculate_threat_status(instance_threat):
    """Derive threat status from countermeasures via junction table.

    Works for both ComponentInstanceThreat and DataFlowInstanceThreat.

    Status logic:
        - EXPOSED: No countermeasures applied OR any countermeasure is a gap
        - ADDRESSABLE: Some countermeasures are planned/waived/in_progress/decommissioned
        - MITIGATED: All countermeasures are implemented/verified/platform
    """
    countermeasures = get_countermeasures_for_threat(instance_threat)

    if not countermeasures.exists():
        new_status = "exposed"
    else:
        statuses = list(countermeasures.values_list("status", flat=True))
        has_gaps = any(s == "gap" for s in statuses)

        if has_gaps:
            new_status = "exposed"
        elif any(
            s in ("planned", "waived", "in_progress", "decommissioned")
            for s in statuses
        ):
            new_status = "addressable"
        else:
            new_status = "mitigated"

    if instance_threat.status != new_status:
        instance_threat.status = new_status
        instance_threat.save(update_fields=["status", "updated_at"])

    return new_status


def derive_risk_status(risk):
    """Aggregate status from all linked threats' statuses.

    Returns: "exposed" / "addressable" / "mitigated"
    """
    risk_threats = risk.risk_threats.select_related(
        "component_threat", "flow_threat"
    ).all()

    if not risk_threats.exists():
        return "exposed"

    all_threat_statuses = []
    for risk_threat in risk_threats:
        threat = risk_threat.component_threat or risk_threat.flow_threat
        if threat and threat.triage_status in ACTIVE_TRIAGE_STATUSES:
            all_threat_statuses.append(threat.status)

    if not all_threat_statuses:
        return "exposed"

    if all(s == "mitigated" for s in all_threat_statuses):
        return "mitigated"
    if all(s in ["mitigated", "addressable"] for s in all_threat_statuses):
        return "addressable"
    return "exposed"


def compute_residual_score(risk):
    """Compute residual score from inherent score and countermeasure effectiveness.

    Deduplicates shared countermeasures — each countermeasure instance is counted
    only once even if it mitigates multiple threats within the same risk.

    Gap, waived, and decommissioned countermeasures always receive zero credit.
    For other statuses, effectiveness comes from:
      1. User-entered value on the countermeasure (if set)
      2. Status-derived fallback from STATUS_EFFECTIVENESS_FALLBACK
    """
    all_effectiveness = []
    seen_countermeasure_ids = set()

    for risk_threat in risk.risk_threats.all():
        threat = risk_threat.component_threat or risk_threat.flow_threat
        if not threat or threat.triage_status not in ACTIVE_TRIAGE_STATUSES:
            continue
        for countermeasure in get_countermeasures_for_threat(threat):
            if countermeasure.id in seen_countermeasure_ids:
                continue
            seen_countermeasure_ids.add(countermeasure.id)

            if countermeasure.status in NON_CREDIT_STATUSES:
                all_effectiveness.append(0.0)
            elif countermeasure.effectiveness is not None:
                all_effectiveness.append(countermeasure.effectiveness)
            else:
                all_effectiveness.append(
                    STATUS_EFFECTIVENESS_FALLBACK.get(countermeasure.status, 0.0)
                )

    if not all_effectiveness:
        return risk.inherent_score

    avg_effectiveness = sum(all_effectiveness) / len(all_effectiveness)
    return max(1, round(risk.inherent_score * (1 - avg_effectiveness)))


def calculate_inherent_score(scoring_method, scoring_metadata):
    """Delegate to the scoring engine registry to compute inherent score.

    Returns (score: int, level: str) or raises ValidationError.
    """
    methods = get_scoring_methods()
    method_config = methods.get(scoring_method)

    if not method_config:
        raise ValueError(f"Unknown scoring method: {scoring_method}")

    engine_class = method_config["engine"]
    if engine_class is None:
        # Custom method or not-yet-implemented — caller must provide score directly
        return None, None

    engine = engine_class()
    engine.validate_inputs(scoring_metadata)
    return engine.calculate(scoring_metadata)


def recalculate_risk(risk):
    """Recompute residual_score and residual_level, save to DB."""
    residual_score = compute_residual_score(risk)
    residual_level = (
        score_to_level(residual_score) if residual_score is not None else ""
    )

    Risk.objects.filter(pk=risk.pk).update(
        residual_score=residual_score,
        residual_level=residual_level,
    )


def recalculate_risks_for_threat(threat_instance, threat_type="component"):
    """Find all Risks linked to this threat and recalculate each."""
    if threat_type == "component":
        risk_ids = RiskThreat.objects.filter(
            component_threat=threat_instance
        ).values_list("risk_id", flat=True)
    else:
        risk_ids = RiskThreat.objects.filter(flow_threat=threat_instance).values_list(
            "risk_id", flat=True
        )

    for risk in Risk.objects.filter(id__in=risk_ids):
        recalculate_risk(risk)


def recalculate_all_threats_for_countermeasure(countermeasure):
    """Recalculate status for all threats linked to this countermeasure.

    Used when a shared countermeasure's status or effectiveness changes.
    Handles both component and flow threats via the polymorphic junction table.
    """
    for link in CountermeasureThreatLink.objects.filter(countermeasure=countermeasure):
        threat = link.component_threat or link.flow_threat
        threat_type = "component" if link.component_threat else "flow"
        recalculate_threat_status(threat)
        recalculate_risks_for_threat(threat, threat_type=threat_type)
