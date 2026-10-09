"""Review and approval of a threat model (plan section 4.8, F21, L5).

The review row is written only here, under a row lock. ``approve`` stores
the content digest; ``review_state`` compares it with the current digest.
There are no hooks elsewhere: whatever is in the snapshot counts.
"""

from django.db import transaction
from django.utils.timezone import now

from .digest import model_digest
from .models import ThreatModelReview

APPROVAL_NONE = "none"
APPROVAL_APPROVED = "approved"
APPROVAL_CHANGED = "changed"
APPROVAL_REVIEW_DUE = "review_due"


def _locked_review(threat_model):
    review, _ = ThreatModelReview.objects.select_for_update().get_or_create(
        threat_model=threat_model
    )
    return review


def mark_reviewed(threat_model, user):
    with transaction.atomic():
        review = _locked_review(threat_model)
        review.reviewer = user
        review.reviewed_at = now()
        review.save(update_fields=["reviewer", "reviewed_at", "updated_at"])
    return review


def approve(threat_model, user):
    """Approve the model as it is now: the digest of its content is stored."""
    digest = model_digest(threat_model)
    with transaction.atomic():
        review = _locked_review(threat_model)
        review.approver = user
        review.approved_at = now()
        review.approval_digest = digest
        review.save(
            update_fields=["approver", "approved_at", "approval_digest", "updated_at"]
        )
    return review


def revoke_approval(threat_model):
    with transaction.atomic():
        review = _locked_review(threat_model)
        review.approver = None
        review.approved_at = None
        review.approval_digest = ""
        review.save(
            update_fields=["approver", "approved_at", "approval_digest", "updated_at"]
        )
    return review


def review_state(threat_model) -> dict:
    """The derived approval state plus the review row's fields.

    ``approval_state`` is ``none``, ``approved`` or ``changed``, or
    ``review_due`` when ``valid_until`` has passed.
    """
    review, _ = ThreatModelReview.objects.get_or_create(threat_model=threat_model)
    current = model_digest(threat_model)
    if review.approval_digest:
        state = (
            APPROVAL_APPROVED if review.approval_digest == current else APPROVAL_CHANGED
        )
    else:
        state = APPROVAL_NONE
    if threat_model.valid_until is not None and threat_model.valid_until < now():
        state = APPROVAL_REVIEW_DUE
    return {
        "approval_state": state,
        "reviewer": review.reviewer_id,
        "reviewer_email": review.reviewer.email if review.reviewer else None,
        "reviewed_at": review.reviewed_at,
        "approver": review.approver_id,
        "approver_email": review.approver.email if review.approver else None,
        "approved_at": review.approved_at,
        "current_digest": current,
        "approval_digest": review.approval_digest or None,
        "valid_from": threat_model.valid_from,
        "valid_until": threat_model.valid_until,
        "review_frequency": threat_model.review_frequency,
        "lifecycle_phase": threat_model.lifecycle_phase,
        "source_document_review": (
            (threat_model.format_metadata or {}).get("cyclonedx") or {}
        ).get("review"),
    }
