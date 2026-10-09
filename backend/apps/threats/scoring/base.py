"""The engine contract (#31 comment, section 2.2).

An engine takes the user's inputs and returns an unsaved ``Rating``. It owns
its own bands and its own native scale; nothing outside an engine turns a
score into a level. Registering happens on subclassing: any engine with a
``key`` is in the registry.
"""

from abc import ABC, abstractmethod


class BaseScoringEngine(ABC):
    key: str = ""  # CycloneDX methodology value, or a custom name
    label: str = ""
    description: str = ""
    input_schema: dict = {}
    score_scale: str = ""  # shown next to the score, e.g. "25" or "9"

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if cls.key:
            from . import registry

            registry.register(cls)

    @abstractmethod
    def validate(self, inputs: dict) -> None:
        """Raise ``rest_framework.exceptions.ValidationError`` on bad input."""

    @abstractmethod
    def rate(self, inputs: dict):
        """Return an unsaved ``Rating`` with methodology, level, score and the
        likelihood and impact fields set."""

    def rate_residual(self, inherent, effectiveness: float):
        """The residual rating after controls of ``effectiveness`` (0 to 1).

        Default: a copy of the inherent rating, which is right for engines
        with no likelihood axis. Engines with one scale their likelihood by
        ``1 - effectiveness`` and re-band.
        """
        return copy_rating(inherent)


def copy_rating(rating):
    """An unsaved copy of a rating's assessment fields."""
    from apps.threats.models import Rating

    return Rating(
        methodology=rating.methodology,
        level=rating.level,
        score=rating.score,
        likelihood_level=rating.likelihood_level,
        likelihood_score=rating.likelihood_score,
        likelihood_factors=list(rating.likelihood_factors or []),
        likelihood_extra=dict(rating.likelihood_extra or {}),
        impact_level=rating.impact_level,
        impact_score=rating.impact_score,
        impact_factors=list(rating.impact_factors or []),
        impact_extra=dict(rating.impact_extra or {}),
        rationale=rating.rationale,
    )


def require_enum(inputs: dict, field: str, values, *, label: str) -> str:
    from rest_framework.exceptions import ValidationError

    value = inputs.get(field)
    if value is None or value == "":
        raise ValidationError({"rating_inputs": f"{field} is required for {label}."})
    if value not in values:
        raise ValidationError(
            {
                "rating_inputs": f"Invalid {field} '{value}'. Must be one of: "
                + ", ".join(values)
            }
        )
    return value
