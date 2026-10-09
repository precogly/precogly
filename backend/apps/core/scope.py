"""Scope checks for ids a client can send (plan section 4.3, M13).

Two questions, answered in one place so every serializer and service that
accepts an id asks them the same way: does this row belong to this threat
model, and does this row belong to this organization. Model-scoped rows
reach their model through ``threat_model`` or ``blueprint.threat_model``;
rows that hang off a component, flow or countermeasure go one hop further.
"""


def threat_model_id_of(row):
    """The id of the threat model ``row`` belongs to, or None."""
    if row is None:
        return None
    if getattr(row, "threat_model_id", None):
        return row.threat_model_id
    if getattr(row, "blueprint_id", None):
        return row.blueprint.threat_model_id
    for attribute in (
        "component",
        "flow",
        "countermeasure",
        "threat",
        "risk",
        "response",
        "assumption",
        "source_component",
        "source_threat_model",
        "dfd",
    ):
        if getattr(row, f"{attribute}_id", None):
            return threat_model_id_of(getattr(row, attribute))
    return None


def belongs_to_threat_model(row, threat_model) -> bool:
    """True when ``row`` is part of ``threat_model`` (an instance or an id)."""
    wanted = getattr(threat_model, "pk", threat_model)
    found = threat_model_id_of(row)
    return found is not None and wanted is not None and found == wanted


def organization_id_of(row):
    """The id of the organization ``row`` belongs to, directly or through its model."""
    if row is None:
        return None
    if getattr(row, "organization_id", None):
        return row.organization_id
    model_id = threat_model_id_of(row)
    if model_id is None:
        return None
    from apps.threat_models.models import ThreatModel

    return (
        ThreatModel.objects.filter(pk=model_id)
        .values_list("organization_id", flat=True)
        .first()
    )


def belongs_to_organization(row, organization) -> bool:
    wanted = getattr(organization, "pk", organization)
    found = organization_id_of(row)
    return found is not None and wanted is not None and found == wanted
