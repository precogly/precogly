"""Row-lifecycle rules for threats and countermeasures.

Two rules, both written as ``post_delete`` handlers so they hold whichever
path deletes the row (the API, DFD sync, a blueprint delete, a cascade):

- A countermeasure that library generation created and nobody edited is
  removed when its last threat link goes (section 4.3, H1). Anything a user
  touched, or that has no link because it applies to the whole system, stays.
- A threat whose last target goes, and that is not a whole-system threat, is
  deleted (section 4.1, H9). The check runs after each target row, so it gives
  the same answer for one deleted node, several in one save, or a whole
  blueprint. It does nothing when the delete started from the threat itself,
  its model or its organization, where the threat is already going.
"""

from django.db.models.signals import post_delete
from django.dispatch import receiver


def _origin_model(origin):
    """The model class of a delete's origin (an instance or a queryset)."""
    if origin is None:
        return None
    return getattr(origin, "model", None) or type(origin)


@receiver(post_delete, sender="threats.CountermeasureThreatLink")
def cleanup_orphaned_countermeasure(sender, instance, **kwargs):
    """Delete an untouched generated countermeasure that lost its last link."""
    from apps.threats.models import InstanceCountermeasure
    from apps.threats.services import delete_if_orphaned

    try:
        countermeasure = InstanceCountermeasure.objects.get(
            pk=instance.countermeasure_id
        )
    except InstanceCountermeasure.DoesNotExist:
        return  # Already deleted (e.g., during threat model cascade)

    delete_if_orphaned(countermeasure)


@receiver(post_delete, sender="threats.InstanceThreatTarget")
def delete_threat_that_lost_its_last_target(sender, instance, origin=None, **kwargs):
    """Apply the target rule once the target row is gone."""
    from apps.organizations.models import Organization
    from apps.threat_models.models import ThreatModel
    from apps.threats.models import InstanceThreat

    if _origin_model(origin) in (InstanceThreat, ThreatModel, Organization):
        return

    threat = InstanceThreat.objects.filter(pk=instance.threat_id).first()
    if threat is None or threat.whole_system:
        return
    if threat.targets.exists():
        return
    threat.delete()


@receiver(post_delete, sender="threats.InstanceThreat")
def delete_threat_rating(sender, instance, **kwargs):
    """A scenario's rating goes with it (RESTRICT does not fire on owner deletion)."""
    from apps.threats.models import Rating

    # Read the id off the instance; a deferred field would query a row that
    # is already gone.
    rating_id = instance.__dict__.get("rating_id")
    if rating_id:
        Rating.objects.filter(pk=rating_id).delete()


@receiver(post_delete, sender="threats.Risk")
def delete_risk_ratings(sender, instance, **kwargs):
    from apps.threats.models import Rating

    ids = [
        rating_id
        for rating_id in (
            instance.inherent_id,
            instance.residual_id,
            instance.target_id,
        )
        if rating_id
    ]
    if ids:
        Rating.objects.filter(pk__in=ids).delete()
