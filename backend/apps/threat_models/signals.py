"""Rows every threat model carries from the moment it exists.

A threat model always has at least one blueprint, one state row (the
number counters) and one review row. The API, the seed command, the importers and a dozen tests
create models with ``ThreatModel.objects.create`` directly, so both are created
here, on save, rather than in one serializer (H15, I7).

The default blueprint takes the model's name. When the model is renamed, a
blueprint still carrying the old name follows it, so the first name does not
outlive the model (S6).
"""

from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from .models import Blueprint, ThreatModel, ThreatModelReview, ThreatModelState


@receiver(pre_save, sender=ThreatModel)
def remember_previous_name(sender, instance, **kwargs):
    if instance.pk is None:
        instance._previous_name = None
        return
    instance._previous_name = (
        ThreatModel.objects.filter(pk=instance.pk)
        .values_list("name", flat=True)
        .first()
    )


@receiver(post_save, sender=ThreatModel)
def ensure_default_rows(sender, instance, created, **kwargs):
    if created:
        if not Blueprint.objects.filter(threat_model=instance).exists():
            Blueprint.objects.create(threat_model=instance, name=instance.name)
        ThreatModelState.objects.get_or_create(threat_model=instance)
        ThreatModelReview.objects.get_or_create(threat_model=instance)
        return

    previous_name = getattr(instance, "_previous_name", None)
    if previous_name and previous_name != instance.name:
        Blueprint.objects.filter(threat_model=instance, name=previous_name).update(
            name=instance.name
        )
