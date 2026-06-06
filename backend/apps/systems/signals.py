"""
Signals for systems app - cascade cleanup of boundary references.
"""

from django.db.models.signals import post_delete
from django.dispatch import receiver

from .models import TrustBoundary, DataFlow


@receiver(post_delete, sender=TrustBoundary)
def cleanup_boundary_references_on_delete(sender, instance, **kwargs):
    """
    When a TrustBoundary is deleted, remove its ID from all data flows
    that cross it (trust_boundary_ids JSON field).
    """
    # Get all DataFlows that reference this boundary in their trust_boundary_ids
    flows_with_boundary = DataFlow.objects.filter(
        trust_boundary_ids__contains=[instance.id]
    )

    for flow in flows_with_boundary:
        # Remove the boundary ID from the list
        updated_ids = [bid for bid in flow.trust_boundary_ids if bid != instance.id]
        flow.trust_boundary_ids = updated_ids
        flow.save(update_fields=['trust_boundary_ids'])