"""Relationships between threat models (plan J15, K4).

One place for the rules the relationship actions and the TM-BOM importer
share:

- a model is never linked to itself;
- ``subsystem_of`` and ``superseded_by`` never form a loop: following that
  relation type from the target must not lead back to the source;
- ``related_to`` is symmetric, so the reverse row between the same two models
  stands for the requested one and nothing is stored twice;
- ``depends_on`` may form a loop, because two systems can depend on each
  other and the schema accepts it.
"""

from .models import ThreatModelRelationship

RELATION_TYPES = tuple(ThreatModelRelationship.RelationType.values)

# Types where a loop is refused.
ACYCLIC_RELATION_TYPES = (
    ThreatModelRelationship.RelationType.SUBSYSTEM_OF,
    ThreatModelRelationship.RelationType.SUPERSEDED_BY,
)

# Types where the reverse row stands for the requested one.
SYMMETRIC_RELATION_TYPES = (ThreatModelRelationship.RelationType.RELATED_TO,)

RELATION_PHRASES = {
    ThreatModelRelationship.RelationType.DEPENDS_ON: "depends on",
    ThreatModelRelationship.RelationType.SUBSYSTEM_OF: "is a subsystem of",
    ThreatModelRelationship.RelationType.RELATED_TO: "is related to",
    ThreatModelRelationship.RelationType.SUPERSEDED_BY: "is superseded by",
}


class RelationshipError(ValueError):
    """A relationship the rules refuse. The message names the models."""


def relationship_payload(relationship, viewpoint=None):
    """The API shape of one relationship row.

    With ``viewpoint`` (a threat model), ``model`` is the other end and
    ``direction`` says whether the viewpoint is the source (``outgoing``) or
    the target (``incoming``).
    """
    payload = {
        "id": relationship.id,
        "source_model_id": relationship.source_threat_model_id,
        "target_model_id": relationship.target_threat_model_id,
        "relation_type": relationship.relation_type,
    }
    if viewpoint is not None:
        if relationship.source_threat_model_id == viewpoint.id:
            other = relationship.target_threat_model
            payload["direction"] = "outgoing"
        else:
            other = relationship.source_threat_model
            payload["direction"] = "incoming"
        payload["model"] = {"id": other.id, "name": other.name}
    return payload


def _path_to(relation_type, start, destination_id):
    """The chain of models reached from ``start`` by following ``relation_type``
    that ends at ``destination_id``, or ``None`` when it is not reachable."""
    parents = {start.id: None}
    names = {start.id: start.name}
    frontier = [start.id]
    while frontier:
        rows = ThreatModelRelationship.objects.filter(
            relation_type=relation_type, source_threat_model_id__in=frontier
        ).values_list(
            "source_threat_model_id",
            "target_threat_model_id",
            "target_threat_model__name",
        )
        next_frontier = []
        for source_id, target_id, target_name in rows:
            if target_id in parents:
                continue
            parents[target_id] = source_id
            names[target_id] = target_name
            if target_id == destination_id:
                path = []
                cursor = target_id
                while cursor is not None:
                    path.append(names[cursor])
                    cursor = parents[cursor]
                return list(reversed(path))
            next_frontier.append(target_id)
        frontier = next_frontier
    return None


def add_relationship(source, target, relation_type):
    """Store ``source relation_type target`` after the checks above.

    Returns ``(relationship, created)``. ``created`` is False when the row, or
    for a symmetric type its reverse, already existed. Raises
    ``RelationshipError`` for a refused relationship.
    """
    if relation_type not in RELATION_TYPES:
        raise RelationshipError(
            f"'{relation_type}' is not a relationship type; choose one of "
            + ", ".join(RELATION_TYPES)
            + "."
        )
    if source.id == target.id:
        raise RelationshipError("A threat model cannot reference itself.")
    if source.organization_id != target.organization_id:
        raise RelationshipError(
            "Related threat models must belong to the same organization."
        )
    phrase = RELATION_PHRASES[relation_type]

    if relation_type in SYMMETRIC_RELATION_TYPES:
        reverse = ThreatModelRelationship.objects.filter(
            source_threat_model=target,
            target_threat_model=source,
            relation_type=relation_type,
        ).first()
        if reverse is not None:
            return reverse, False

    if relation_type in ACYCLIC_RELATION_TYPES:
        loop = _path_to(relation_type, target, source.id)
        if loop is not None:
            chain = " -> ".join([source.name, *loop])
            raise RelationshipError(
                f"'{source.name}' {phrase} '{target.name}' would form a loop: {chain}."
            )

    return ThreatModelRelationship.objects.get_or_create(
        source_threat_model=source,
        target_threat_model=target,
        relation_type=relation_type,
    )


def remove_relationship(source, target_id, relation_type):
    """Delete exactly the row ``source relation_type target``; the number deleted."""
    deleted, _ = ThreatModelRelationship.objects.filter(
        source_threat_model=source,
        target_threat_model_id=target_id,
        relation_type=relation_type,
    ).delete()
    return deleted


def relationships_of(threat_model):
    """Every relationship the model takes part in, outgoing rows first, each
    as ``relationship_payload`` seen from the model."""
    outgoing = threat_model.outgoing_relationships.select_related(
        "target_threat_model"
    ).order_by("id")
    incoming = threat_model.incoming_relationships.select_related(
        "source_threat_model"
    ).order_by("id")
    return [relationship_payload(row, threat_model) for row in outgoing] + [
        relationship_payload(row, threat_model) for row in incoming
    ]
