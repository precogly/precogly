"""Use case and abuse case links (``major-changes/editable-use-cases.md``).

Each ``set_*`` call replaces only the lists it is given, in one transaction;
a list left as ``None`` keeps its links. Callers check scope first: every
row must belong to the owner's threat model.
"""

from django.db import transaction

from .models import (
    AbuseCaseTarget,
    AbuseCaseThreat,
    AbuseCaseUseCase,
    UseCaseBusinessObjective,
    UseCaseTarget,
)


def _sync(link_model, owner_field: str, owner, field: str, rows) -> None:
    """Make ``owner``'s links on ``field`` equal ``rows``, in that order.

    Only links whose ``field`` is set are touched, so the component and flow
    links of a target table are synced independently.
    """
    rows = list(dict.fromkeys(rows))
    wanted = {row.pk for row in rows}
    existing = {
        getattr(link, f"{field}_id"): link
        for link in link_model.objects.filter(
            **{owner_field: owner, f"{field}__isnull": False}
        )
    }
    for position, row in enumerate(rows):
        link = existing.get(row.pk)
        if link is None:
            link_model.objects.create(
                **{owner_field: owner, field: row, "display_order": position}
            )
        elif link.display_order != position:
            link.display_order = position
            link.save(update_fields=["display_order"])
    for row_id, link in existing.items():
        if row_id not in wanted:
            link.delete()


@transaction.atomic
def set_use_case_links(
    use_case, *, components=None, flows=None, business_objectives=None
) -> None:
    if components is not None:
        _sync(UseCaseTarget, "use_case", use_case, "component", components)
    if flows is not None:
        _sync(UseCaseTarget, "use_case", use_case, "flow", flows)
    if business_objectives is not None:
        _sync(
            UseCaseBusinessObjective,
            "use_case",
            use_case,
            "business_objective",
            business_objectives,
        )


@transaction.atomic
def set_abuse_case_links(
    abuse_case, *, use_cases=None, components=None, flows=None, threats=None
) -> None:
    if use_cases is not None:
        _sync(AbuseCaseUseCase, "abuse_case", abuse_case, "use_case", use_cases)
    if components is not None:
        _sync(AbuseCaseTarget, "abuse_case", abuse_case, "component", components)
    if flows is not None:
        _sync(AbuseCaseTarget, "abuse_case", abuse_case, "flow", flows)
    if threats is not None:
        _sync(AbuseCaseThreat, "abuse_case", abuse_case, "threat", threats)


def link_threat_to_abuse_cases(threat, abuse_cases) -> None:
    """Add ``threat`` to each abuse case, keeping their other threats."""
    for abuse_case in abuse_cases:
        position = abuse_case.threat_links.count()
        AbuseCaseThreat.objects.get_or_create(
            abuse_case=abuse_case,
            threat=threat,
            defaults={"display_order": position},
        )


def set_threat_abuse_cases(threat, abuse_cases) -> None:
    """Make the abuse cases ``threat`` comes from equal ``abuse_cases``."""
    wanted = {abuse_case.pk for abuse_case in abuse_cases}
    with transaction.atomic():
        threat.abuse_case_links.exclude(abuse_case_id__in=wanted).delete()
        link_threat_to_abuse_cases(threat, abuse_cases)
