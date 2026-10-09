"""Service functions for threats and countermeasures.

Two halves:

- The creation seam: every threat scenario, countermeasure, target and link
  is created through the functions in the first half. DFD sync, the API, pack
  connection, the AI accept path and the importer all call these, so a change
  to how a row is created happens in one place.
- Status and risk computation, which read the rows the seam writes.

Vocabulary (plan section 4.1): a *target* is a component, flow, zone or
boundary row; a scenario has one or many targets, or none when it is a
whole-system threat.
"""

from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import Q

from apps.core.scope import belongs_to_threat_model, organization_id_of
from apps.systems.crossing import link_applies_to_flow_type
from apps.systems.models import Boundary, Flow, OrgsystemComponent, Zone
from apps.threat_models.numbering import COUNTERMEASURES, THREATS, allocate_numbers

from .models import (
    ACTIVE_TRIAGE_STATUSES,
    ComponentLibraryThreat,
    CountermeasureLibrary,
    CountermeasureThreatLink,
    InstanceCountermeasure,
    InstanceCountermeasureProvider,
    InstanceCountermeasureTarget,
    InstanceThreat,
    InstanceThreatBusinessObjective,
    InstanceThreatTarget,
    Rating,
    Risk,
    RiskBusinessObjective,
    RiskResponse,
    RiskResponseCountermeasure,
    RiskThreat,
    build_taxonomy_snapshot,
)
from .scoring.registry import get_engine

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

TARGET_MODELS = {
    "component": OrgsystemComponent,
    "flow": Flow,
    "zone": Zone,
    "boundary": Boundary,
}


class TargetError(ValueError):
    """A target list that would leave a scenario in an invalid state."""


def target_kind_of(row) -> str:
    for kind, model in TARGET_MODELS.items():
        if isinstance(row, model):
            return kind
    raise TypeError(f"not a target: {row!r}")


def resolve_target(kind: str, target_id, threat_model):
    """The target row of ``kind`` with ``target_id`` inside ``threat_model``, or None."""
    model = TARGET_MODELS.get(kind)
    if model is None:
        return None
    return model.objects.filter(
        id=target_id, blueprint__threat_model=threat_model
    ).first()


def _threat_model_id_for_target(target):
    """The threat model a target belongs to, through its blueprint."""
    return target.blueprint.threat_model_id


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------


def _check_targets_belong(owner, targets):
    """Every target must sit in the owner's threat model (M13)."""
    for target in targets:
        if not belongs_to_threat_model(target, owner.threat_model_id):
            raise TargetError(
                f"{target_kind_of(target)} {target.pk} does not belong to the "
                "threat model"
            )


def _sync_target_rows(target_model, owner_field, owner, targets):
    """Make ``owner``'s target rows equal ``targets``, in that order, as a diff.

    New rows are added before stale ones are removed, so an owner never passes
    through zero rows on an edit.
    """
    wanted = {(target_kind_of(t), t.pk) for t in targets}
    rows = target_model.objects.filter(**{owner_field: owner})
    existing = {(row.target_kind, row.target_id): row for row in rows}
    for position, target in enumerate(targets):
        key = (target_kind_of(target), target.pk)
        row = existing.get(key)
        if row is None:
            target_model.objects.create(
                **{owner_field: owner}, display_order=position, **{key[0]: target}
            )
        elif row.display_order != position:
            row.display_order = position
            row.save(update_fields=["display_order"])
    for key, row in existing.items():
        if key not in wanted:
            row.delete()


def set_targets(threat, targets, *, whole_system=False):
    """Replace a scenario's targets.

    Adds the new rows before removing the old ones, so an edit never passes
    through zero targets, which the deletion rule would read as "delete me".
    An empty list is accepted only together with ``whole_system=True``; in
    that path the flag is saved first and the rows removed second (M22).
    """
    targets = list(targets)
    if targets and whole_system:
        raise TargetError("a whole-system scenario has no targets")
    if not targets and not whole_system:
        raise TargetError("a scenario needs at least one target, or whole_system set")
    _check_targets_belong(threat, targets)

    with transaction.atomic():
        if whole_system:
            if not threat.whole_system:
                threat.whole_system = True
                threat.save(update_fields=["whole_system", "updated_at"])
            threat.targets.all().delete()
            return

        if threat.whole_system:
            threat.whole_system = False
            threat.save(update_fields=["whole_system", "updated_at"])
        _sync_target_rows(InstanceThreatTarget, "threat", threat, targets)


def add_target(threat, target) -> bool:
    """Attach one more target. Returns True when it was new."""
    _check_targets_belong(threat, [target])
    kind = target_kind_of(target)
    _, created = InstanceThreatTarget.objects.get_or_create(
        threat=threat,
        **{kind: target},
        defaults={"display_order": threat.targets.count()},
    )
    if created and threat.whole_system:
        threat.whole_system = False
        threat.save(update_fields=["whole_system", "updated_at"])
    return created


def set_countermeasure_targets(countermeasure, targets):
    """Replace where a control applies. An empty list means the whole system.

    Scope never changes a threat's status (section 4.3, L4), so nothing is
    recalculated here.
    """
    targets = list(targets)
    _check_targets_belong(countermeasure, targets)
    with transaction.atomic():
        _sync_target_rows(
            InstanceCountermeasureTarget, "countermeasure", countermeasure, targets
        )


def set_countermeasure_providers(countermeasure, components):
    """Replace the components that implement a control (``implementedBy``)."""
    components = list(components)
    for component in components:
        if not belongs_to_threat_model(component, countermeasure.threat_model_id):
            raise TargetError(
                f"component {component.pk} does not belong to the threat model"
            )
    wanted = {component.pk for component in components}
    with transaction.atomic():
        existing = {
            link.component_id: link for link in countermeasure.provider_links.all()
        }
        for position, component in enumerate(components):
            link = existing.get(component.pk)
            if link is None:
                InstanceCountermeasureProvider.objects.create(
                    countermeasure=countermeasure,
                    component=component,
                    display_order=position,
                )
            elif link.display_order != position:
                link.display_order = position
                link.save(update_fields=["display_order"])
        for component_id, link in existing.items():
            if component_id not in wanted:
                link.delete()


def countermeasures_losing_scope(
    *, component_ids=(), flow_ids=(), zone_ids=(), boundary_ids=()
):
    """Controls whose every target is among the rows about to be deleted.

    Called before the delete. Each one keeps its status and links but reads
    as "applies to the whole system" afterwards, so the caller warns
    (section 4.3).
    """
    going = (
        Q(component_id__in=list(component_ids))
        | Q(flow_id__in=list(flow_ids))
        | Q(flow__source_component_id__in=list(component_ids))
        | Q(flow__dest_component_id__in=list(component_ids))
        | Q(zone_id__in=list(zone_ids))
        | Q(boundary_id__in=list(boundary_ids))
        | Q(boundary__zone_a_id__in=list(zone_ids))
        | Q(boundary__zone_b_id__in=list(zone_ids))
    )
    candidate_ids = set(
        InstanceCountermeasureTarget.objects.filter(going).values_list(
            "countermeasure_id", flat=True
        )
    )
    if not candidate_ids:
        return []
    staying_ids = set(
        InstanceCountermeasureTarget.objects.filter(countermeasure_id__in=candidate_ids)
        .exclude(going)
        .values_list("countermeasure_id", flat=True)
    )
    return list(
        InstanceCountermeasure.objects.filter(
            id__in=candidate_ids - staying_ids
        ).order_by("number")
    )


def user_is_security_team(user, organization_id) -> bool:
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    return user.organization_memberships.filter(
        organization_id=organization_id, role="security_team"
    ).exists()


def check_platform_status(user, threat_model, current_status=None, new_status=None):
    """The one gate on ``platform`` status (H6): Security Team only.

    Raises ``PermissionDenied`` when a user without the role in the model's
    organization sets or removes platform status. Every write path, import
    included, goes through here.
    """
    if new_status != "platform" and current_status != "platform":
        return
    if new_status == current_status:
        return
    if not user_is_security_team(user, threat_model.organization_id):
        raise PermissionDenied(
            "Only Security Team members can assign or remove platform status."
        )


# ---------------------------------------------------------------------------
# Ratings (#31 comment, section 2.4)
# ---------------------------------------------------------------------------

LEVEL_ONLY_KEYS = {"level", "rationale"}


def engine_for(threat_model):
    """The engine of a threat model's risk methodology, or None when not available."""
    return get_engine(threat_model.risk_scoring_method)


def rate_inputs(threat_model, inputs: dict, *, for_threat: bool = False):
    """An unsaved rating from a form's ``rating_inputs``.

    A level on its own is a level-only (manual) rating for threats and risks
    alike. Otherwise a threat is rated with the 5x5 matrix and a risk with
    the model's methodology; a methodology without an engine is refused.
    """
    from rest_framework.exceptions import ValidationError

    if not isinstance(inputs, dict) or not inputs:
        raise ValidationError(
            {"rating_inputs": "Give a level, or the method's inputs."}
        )
    if "level" in inputs and set(inputs) <= LEVEL_ONLY_KEYS:
        engine = get_engine("manual")
    elif for_threat:
        engine = get_engine("qualitative-matrix")
    else:
        engine = engine_for(threat_model)
        if engine is None:
            raise ValidationError(
                {
                    "rating_inputs": f"The {threat_model.risk_scoring_method} method has "
                    "no engine yet; give a level instead."
                }
            )
    engine.validate(inputs)
    return engine.rate(inputs)


def level_rating(level: str, rationale: str = ""):
    return get_engine("manual").rate({"level": level, "rationale": rationale})


def apply_rating(owner, field_name: str, rating) -> None:
    """Persist a rating on ``owner.<field_name>``; the only path that does.

    The organization comes from the owner's threat model, never from the
    request. A rating the owner pointed at before is deleted after the owner
    has moved on, which RESTRICT then allows.
    """
    with transaction.atomic():
        rating.organization_id = organization_id_of(owner)
        rating.save()
        previous_id = getattr(owner, f"{field_name}_id")
        setattr(owner, field_name, rating)
        owner.save(update_fields=[field_name, "updated_at"])
        if previous_id and previous_id != rating.pk:
            Rating.objects.filter(pk=previous_id).delete()


def rating_level_rank(field: str = "rating__level"):
    """A Case expression that orders levels as info < low < ... < critical."""
    from django.db.models import Case, IntegerField, Value, When

    return Case(
        *[
            When(**{field: level}, then=Value(rank))
            for level, rank in Rating.LEVEL_RANK.items()
        ],
        default=Value(-1),
        output_field=IntegerField(),
    )


# ---------------------------------------------------------------------------
# Creation seam
# ---------------------------------------------------------------------------


def _connected_pack_filter(threat_model_id, field_prefix):
    """Q limiting library rows to the model's connected packs or no pack at all."""
    from apps.threat_models.models import ThreatModelLibraryPack

    connected_pack_ids = ThreatModelLibraryPack.objects.filter(
        threat_model_id=threat_model_id
    ).values_list("library_pack_id", flat=True)
    return Q(**{f"{field_prefix}source_pack_id__in": connected_pack_ids}) | Q(
        **{f"{field_prefix}source_pack__isnull": True}
    )


def _library_copy_fields(threat_library):
    return {
        "threat_name": threat_library.name if threat_library else "",
        "threat_description": threat_library.description if threat_library else "",
        "taxonomy_snapshot": build_taxonomy_snapshot(threat_library),
    }


def create_instance_threat(
    threat_model,
    *,
    targets=(),
    whole_system=False,
    threat_library=None,
    level="medium",
    rating=None,
    rating_inputs=None,
    auto_generated=False,
    number=None,
    **fields,
):
    """Create one scenario with its targets, its number and its rating.

    Name, description and taxonomy snapshot are copied from the library row
    unless the caller gives them, so a threat stays self-sufficient if the
    library row is later removed. ``number`` is allocated unless the caller
    carries one in (import keeps the document's numbers). The rating is the
    unsaved ``rating`` when given, else rated from ``rating_inputs``, else a
    level-only rating at ``level``.
    """
    targets = list(targets)
    if not targets and not whole_system:
        raise TargetError("a scenario needs at least one target, or whole_system set")
    if targets and whole_system:
        raise TargetError("a whole-system scenario has no targets")

    values = {**_library_copy_fields(threat_library)}
    for key in ("threat_name", "threat_description", "taxonomy_snapshot"):
        if fields.get(key):
            values[key] = fields.pop(key)
        else:
            fields.pop(key, None)
    values.update(fields)

    with transaction.atomic():
        if rating is None:
            rating = (
                rate_inputs(threat_model, rating_inputs, for_threat=True)
                if rating_inputs
                else level_rating(level)
            )
        rating.organization_id = threat_model.organization_id
        rating.save()
        if number is None:
            number = allocate_numbers(threat_model.id, THREATS, 1)[0]
        threat = InstanceThreat.objects.create(
            threat_model=threat_model,
            number=number,
            whole_system=whole_system,
            auto_generated=auto_generated,
            threat_library=threat_library,
            rating=rating,
            **values,
        )
        if targets:
            set_targets(threat, targets)
    return threat


def find_generated_threat(target, threat_library):
    """A scenario in the target's model with this library threat on this target.

    The dedupe rule for generation. It also respects a user who merged two
    generated threats into one multi-target scenario: the merged scenario
    still has the target, so nothing is generated again.
    """
    kind = target_kind_of(target)
    return InstanceThreat.objects.filter(
        threat_model_id=_threat_model_id_for_target(target),
        threat_library=threat_library,
        **{f"targets__{kind}": target},
    ).first()


def ensure_instance_threat(target, threat_library, *, level="medium"):
    """Return ``(threat, created)`` for a library threat on a target."""
    existing = find_generated_threat(target, threat_library)
    if existing is not None:
        return existing, False
    threat = create_instance_threat(
        target.blueprint.threat_model,
        targets=[target],
        threat_library=threat_library,
        level=level,
        auto_generated=True,
        status=InstanceThreat.Status.EXPOSED,
    )
    return threat, True


def create_instance_countermeasure(
    threat_model,
    *,
    countermeasure_library=None,
    status=None,
    auto_generated=False,
    number=None,
    targets=(),
    implemented_by=(),
    **fields,
):
    """Create one countermeasure scoped to a threat model, with its number.

    Name, description, control functions and nature are copied from the
    library row unless given. Status falls back to the library default, then
    to ``gap``. ``targets`` (where it applies) and ``implemented_by`` (which
    components implement it) are optional; no targets means the whole system.
    """
    library = countermeasure_library
    values = {
        "countermeasure_name": library.name if library else "",
        "countermeasure_description": library.description if library else "",
        "control_functions": list(library.control_functions) if library else [],
        "control_nature": library.control_nature if library else "",
    }
    for key in list(values):
        if key in fields:
            values[key] = fields.pop(key)
    values.update(fields)
    effective_status = status or (library.default_status if library else None) or "gap"
    with transaction.atomic():
        if number is None:
            number = allocate_numbers(threat_model.id, COUNTERMEASURES, 1)[0]
        countermeasure = InstanceCountermeasure.objects.create(
            threat_model=threat_model,
            countermeasure_library=library,
            status=effective_status,
            auto_generated=auto_generated,
            number=number,
            **values,
        )
        if targets:
            set_countermeasure_targets(countermeasure, targets)
        if implemented_by:
            set_countermeasure_providers(countermeasure, implemented_by)
    return countermeasure


def ensure_instance_countermeasure(threat_model, countermeasure_library):
    """Return ``(countermeasure, created)`` for a library countermeasure in a model.

    Generation reuses one countermeasure row per library row per model, which
    is what lets one control cover threats on many components.
    """
    existing = InstanceCountermeasure.objects.filter(
        threat_model=threat_model, countermeasure_library=countermeasure_library
    ).first()
    if existing is not None:
        return existing, False
    return (
        create_instance_countermeasure(
            threat_model,
            countermeasure_library=countermeasure_library,
            auto_generated=True,
        ),
        True,
    )


def link_countermeasure(countermeasure, threat):
    """Link a countermeasure to a scenario. Returns ``(link, created)``."""
    return CountermeasureThreatLink.objects.get_or_create(
        countermeasure=countermeasure, threat=threat
    )


def countermeasure_is_orphan(countermeasure) -> bool:
    """The orphan rule (section 4.3, H1): generated, untouched, nothing attached:
    no threat link, no target, no risk response relying on it."""
    if not countermeasure.auto_generated:
        return False
    if countermeasure.threat_links.exists():
        return False
    if countermeasure.risk_response_links.exists():
        return False
    return not countermeasure.targets.exists()


def delete_if_orphaned(countermeasure) -> bool:
    if countermeasure_is_orphan(countermeasure):
        countermeasure.delete()
        return True
    return False


def note_user_edit(row) -> None:
    """A user-facing write touched ``row`` (or something hanging off it): it is
    no longer an untouched generated row (M8). System writes never call this."""
    if getattr(row, "auto_generated", False):
        row.auto_generated = False
        row.save(update_fields=["auto_generated", "updated_at"])


def generate_countermeasures_for_threat(threat):
    """Create and link the library countermeasures that apply to a scenario.

    Returns the number of new countermeasures or links. Propagates the
    library's compliance mappings onto a newly created instance (#29).
    """
    from apps.compliance.models import CountermeasureLibraryStandard

    from .models import InstanceCountermeasureStandard

    if threat.threat_library_id is None:
        return 0

    threat_model = threat.threat_model
    applicable_countermeasures = CountermeasureLibrary.objects.filter(
        applicable_threats=threat.threat_library
    ).filter(_connected_pack_filter(threat_model.id, ""))

    created_count = 0
    has_platform_countermeasure = False
    for countermeasure_library in applicable_countermeasures:
        countermeasure, created = ensure_instance_countermeasure(
            threat_model, countermeasure_library
        )
        _, link_created = link_countermeasure(countermeasure, threat)
        if not (created or link_created):
            continue
        created_count += 1
        if countermeasure_library.default_status == "platform":
            has_platform_countermeasure = True

        # Orphaned library mappings (requirement=None, precogly/precogly#338)
        # have nothing to propagate and would raise on ``requirement.section_code``.
        library_standards = (
            CountermeasureLibraryStandard.objects.filter(
                countermeasure_library=countermeasure_library,
            )
            .exclude(requirement__isnull=True)
            .select_related("requirement", "requirement__framework")
        )
        if library_standards.exists():
            InstanceCountermeasureStandard.objects.bulk_create(
                [
                    InstanceCountermeasureStandard(
                        countermeasure=countermeasure,
                        requirement=mapping.requirement,
                        sufficiency=mapping.sufficiency,
                        section_code=mapping.requirement.section_code,
                        framework_name=mapping.requirement.framework.name,
                        requirement_description=mapping.requirement.description,
                    )
                    for mapping in library_standards
                ],
                ignore_conflicts=True,
            )

    if has_platform_countermeasure:
        recalculate_threat_status(threat)

    return created_count


def library_threats_for_component(component):
    """The library links that say which threats a component should carry."""
    if not component.component_library_id:
        return ComponentLibraryThreat.objects.none()
    return (
        ComponentLibraryThreat.objects.filter(
            component_library=component.component_library,
            applies_to__in=[
                ComponentLibraryThreat.AppliesTo.COMPONENT,
                ComponentLibraryThreat.AppliesTo.BOTH,
            ],
        )
        .filter(
            _connected_pack_filter(
                _threat_model_id_for_target(component), "threat_library__"
            )
        )
        .select_related("threat_library")
    )


def library_threats_for_flow(flow):
    """The library links at both ends that apply to flows.

    Both ends may carry the same threat; callers dedupe by threat library.
    """
    component_libraries = [
        end.component_library_id
        for end in (flow.source_component, flow.dest_component)
        if end is not None and end.component_library_id
    ]
    if not component_libraries:
        return ComponentLibraryThreat.objects.none()
    return (
        ComponentLibraryThreat.objects.filter(
            component_library_id__in=component_libraries,
            applies_to__in=[
                ComponentLibraryThreat.AppliesTo.FLOW,
                ComponentLibraryThreat.AppliesTo.BOTH,
            ],
        )
        .filter(
            _connected_pack_filter(
                _threat_model_id_for_target(flow), "threat_library__"
            )
        )
        .select_related("threat_library")
    )


def applicable_library_threats(target):
    """``{threat_library_id: link}`` for a component or flow.

    A flow link applies when the flow's type is admitted by the link's
    ``flow_types`` (empty means data-like flows only, H2).
    """
    kind = target_kind_of(target)
    if kind == "component":
        links = library_threats_for_component(target)
    elif kind == "flow":
        links = [
            link
            for link in library_threats_for_flow(target)
            if link_applies_to_flow_type(link.flow_types, target.flow_type)
        ]
    else:
        return {}
    applicable = {}
    for link in links:
        applicable.setdefault(link.threat_library_id, link)
    return applicable


def ensure_generated_threats(target):
    """Generate the library threats a component or flow is missing.

    The one entry point for generation. Runs only on the triggers in plan
    section 4.1 (creation, a library change, a flow type or ends change, a
    pack connection, the user's "Add missing library threats"), never on an
    ordinary save, so a deleted generated threat stays deleted. Returns the
    number created.
    """
    created_count = 0
    for link in applicable_library_threats(target).values():
        _, created = ensure_instance_threat(
            target, link.threat_library, level=link.default_level
        )
        if created:
            created_count += 1
            generate_countermeasures_for_threat(
                find_generated_threat(target, link.threat_library)
            )
    return created_count


def remove_threats_that_stopped_applying(target) -> int:
    """After a library, type or ends change: drop the untouched generated
    threats the library no longer lists for this target (I1, L6).

    Only the target row is removed; the deletion rule deletes the scenario
    when that was its only target. Edited scenarios stay, and the analysis
    payload marks them ``library_mismatch``. Returns the number of targets
    removed.
    """
    kind = target_kind_of(target)
    applicable_ids = set(applicable_library_threats(target))
    stale = InstanceThreatTarget.objects.filter(
        **{kind: target},
        threat__auto_generated=True,
        threat__threat_library__isnull=False,
    ).exclude(threat__threat_library_id__in=applicable_ids)
    removed = 0
    for row in list(stale):
        row.delete()
        removed += 1
    return removed


# ---------------------------------------------------------------------------
# Status and risk computation
# ---------------------------------------------------------------------------


def get_countermeasures_for_threat(threat):
    """Return countermeasures linked to a scenario via the junction table."""
    return InstanceCountermeasure.objects.filter(threat_links__threat=threat)


def recalculate_threat_status(threat):
    """Derive threat status from its explicitly linked countermeasures.

    Status logic:
        - EXPOSED: No countermeasures applied OR any countermeasure is a gap
        - ADDRESSABLE: Some countermeasures are planned/waived/in_progress/decommissioned
        - MITIGATED: All countermeasures are implemented/verified/platform
    """
    countermeasures = get_countermeasures_for_threat(threat)

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

    if threat.status != new_status:
        threat.status = new_status
        threat.save(update_fields=["status", "updated_at"])

    return new_status


def derive_risk_status(risk):
    """The risk's exposure from its linked threats' statuses.

    Returns "exposed", "addressable" or "mitigated". Reads the prefetched
    ``risk_threats__threat`` when the caller loaded it, so a list runs no
    query per risk (section 4.7).
    """
    risk_threats = list(risk.risk_threats.all())

    if not risk_threats:
        return "exposed"

    all_threat_statuses = [
        risk_threat.threat.status
        for risk_threat in risk_threats
        if risk_threat.threat.triage_status in ACTIVE_TRIAGE_STATUSES
    ]

    if not all_threat_statuses:
        return "exposed"

    if all(s == "mitigated" for s in all_threat_statuses):
        return "mitigated"
    if all(s in ["mitigated", "addressable"] for s in all_threat_statuses):
        return "addressable"
    return "exposed"


def create_risk(
    threat_model,
    *,
    rating_inputs=None,
    level=None,
    rating=None,
    threat_ids=(),
    **fields,
):
    """Create a risk with its inherent rating and its residual computed."""
    with transaction.atomic():
        if rating is None:
            rating = (
                rate_inputs(threat_model, rating_inputs)
                if rating_inputs
                else level_rating(level or "medium")
            )
        rating.organization_id = threat_model.organization_id
        rating.save()
        risk = Risk.objects.create(threat_model=threat_model, inherent=rating, **fields)
        if threat_ids:
            RiskThreat.objects.bulk_create(
                [
                    RiskThreat(risk=risk, threat_id=threat_id)
                    for threat_id in dict.fromkeys(threat_ids)
                ]
            )
        recalculate_residual(risk)
    return risk


def countermeasure_effectiveness_for_risk(risk):
    """Average effectiveness of the controls on the risk's active threats.

    Deduplicates shared countermeasures. Each control contributes its
    user-assessed effectiveness, else the fallback for its status. None when
    nothing contributes.
    """
    all_effectiveness = []
    seen_countermeasure_ids = set()

    for risk_threat in risk.risk_threats.select_related("threat").all():
        threat = risk_threat.threat
        if threat.triage_status not in ACTIVE_TRIAGE_STATUSES:
            continue
        for countermeasure in get_countermeasures_for_threat(threat):
            if countermeasure.id in seen_countermeasure_ids:
                continue
            seen_countermeasure_ids.add(countermeasure.id)
            if countermeasure.effectiveness is not None:
                all_effectiveness.append(countermeasure.effectiveness)
            else:
                all_effectiveness.append(
                    STATUS_EFFECTIVENESS_FALLBACK.get(countermeasure.status, 0.0)
                )

    if not all_effectiveness:
        return None
    return sum(all_effectiveness) / len(all_effectiveness)


def recalculate_residual(risk) -> None:
    """Rate the residual from the inherent rating and the controls' effectiveness.

    The inherent rating's own engine reduces likelihood and re-bands; with
    nothing contributing, the residual is a copy of the inherent rating.
    """
    from .scoring.base import copy_rating

    effectiveness = countermeasure_effectiveness_for_risk(risk)
    engine = get_engine(risk.inherent.methodology)
    if effectiveness is None or engine is None:
        residual = copy_rating(risk.inherent)
    else:
        residual = engine.rate_residual(risk.inherent, effectiveness)
    apply_rating(risk, "residual", residual)


def recalculate_risks_for_threat(threat):
    """Find all Risks linked to this scenario and recalculate each."""
    risk_ids = RiskThreat.objects.filter(threat=threat).values_list(
        "risk_id", flat=True
    )
    for risk in Risk.objects.filter(id__in=risk_ids):
        recalculate_residual(risk)


def risk_ids_citing_targets(component_ids=(), flow_ids=()):
    """Ids of every risk that cites a scenario on these targets.

    Captured before the targets are deleted (the links go with them) so the
    caller can recalculate those risks afterwards.
    """
    risk_ids = set(
        RiskThreat.objects.filter(
            Q(threat__targets__component_id__in=list(component_ids))
            | Q(threat__targets__flow_id__in=list(flow_ids))
            | Q(threat__targets__flow__source_component_id__in=list(component_ids))
            | Q(threat__targets__flow__dest_component_id__in=list(component_ids))
        ).values_list("risk_id", flat=True)
    )
    return risk_ids


def recalculate_all_threats_for_countermeasure(countermeasure):
    """Recalculate status for all scenarios linked to this countermeasure.

    Used when a shared countermeasure's status or effectiveness changes.
    """
    for link in CountermeasureThreatLink.objects.filter(
        countermeasure=countermeasure
    ).select_related("threat"):
        recalculate_threat_status(link.threat)
        recalculate_risks_for_threat(link.threat)


def set_response_countermeasures(response, countermeasures) -> None:
    """Replace the controls a risk response relies on (same model only, M13)."""
    countermeasures = list(countermeasures)
    for countermeasure in countermeasures:
        if countermeasure.threat_model_id != response.risk.threat_model_id:
            raise TargetError(
                f"countermeasure {countermeasure.pk} does not belong to the threat model"
            )
    wanted = {c.pk for c in countermeasures}
    with transaction.atomic():
        existing = {
            link.countermeasure_id: link for link in response.countermeasure_links.all()
        }
        for position, countermeasure in enumerate(countermeasures):
            link = existing.get(countermeasure.pk)
            if link is None:
                RiskResponseCountermeasure.objects.create(
                    response=response,
                    countermeasure=countermeasure,
                    display_order=position,
                )
            elif link.display_order != position:
                link.display_order = position
                link.save(update_fields=["display_order"])
        for countermeasure_id, link in existing.items():
            if countermeasure_id not in wanted:
                link.delete()
                countermeasure = InstanceCountermeasure.objects.filter(
                    pk=countermeasure_id
                ).first()
                if countermeasure is not None:
                    delete_if_orphaned(countermeasure)


def create_risk_response(risk, *, countermeasures=(), **fields):
    response = RiskResponse.objects.create(risk=risk, **fields)
    if countermeasures:
        set_response_countermeasures(response, countermeasures)
    return response


def _sync_objective_links(link_model, owner_field, owner, objectives):
    for objective in objectives:
        if objective.threat_model_id != owner.threat_model_id:
            raise TargetError(
                f"business objective {objective.pk} does not belong to the threat model"
            )
    wanted = {o.pk for o in objectives}
    with transaction.atomic():
        existing = {
            link.business_objective_id: link
            for link in link_model.objects.filter(**{owner_field: owner})
        }
        for position, objective in enumerate(objectives):
            link = existing.get(objective.pk)
            if link is None:
                link_model.objects.create(
                    **{owner_field: owner},
                    business_objective=objective,
                    display_order=position,
                )
            elif link.display_order != position:
                link.display_order = position
                link.save(update_fields=["display_order"])
        for objective_id, link in existing.items():
            if objective_id not in wanted:
                link.delete()


def set_threat_business_objectives(threat, objectives) -> None:
    """Replace the objectives a scenario puts at risk (same model only, M13)."""
    _sync_objective_links(
        InstanceThreatBusinessObjective, "threat", threat, list(objectives)
    )


def set_risk_business_objectives(risk, objectives) -> None:
    _sync_objective_links(RiskBusinessObjective, "risk", risk, list(objectives))
