"""The 5x5 likelihood by impact matrix (#31 comment, section 2.2).

Native scale 1 to 25: the product of likelihood (1 to 5) and impact (1 to 5).
Bands on the product: 1-2 info, 3-6 low, 7-12 medium, 13-19 high, 20-25
critical. The input vocabulary is the one the form has always shown; the
stored levels are the CycloneDX ones.
"""

from .base import BaseScoringEngine, copy_rating, require_enum

LIKELIHOOD_VALUES = {"rare": 1, "unlikely": 2, "possible": 3, "likely": 4, "certain": 5}
IMPACT_VALUES = {"negligible": 1, "minor": 2, "moderate": 3, "major": 4, "severe": 5}

LIKELIHOOD_TO_SPEC = {
    "rare": "very-low",
    "unlikely": "low",
    "possible": "medium",
    "likely": "high",
    "certain": "certain",
}
IMPACT_TO_SPEC = {
    "negligible": "negligible",
    "minor": "low",
    "moderate": "moderate",
    "major": "major",
    "severe": "catastrophic",
}
SPEC_TO_LIKELIHOOD = {spec: ours for ours, spec in LIKELIHOOD_TO_SPEC.items()}
SPEC_TO_IMPACT = {spec: ours for ours, spec in IMPACT_TO_SPEC.items()}
LIKELIHOOD_BY_SCORE = {score: name for name, score in LIKELIHOOD_VALUES.items()}
IMPACT_BY_SCORE = {score: name for name, score in IMPACT_VALUES.items()}


def _on_scale(score) -> bool:
    """True for a whole number from 1 to 5, the matrix's own scores."""
    return score is not None and float(score).is_integer() and 1 <= score <= 5


def band(product: float) -> str:
    if product <= 2:
        return "info"
    if product <= 6:
        return "low"
    if product <= 12:
        return "medium"
    if product <= 19:
        return "high"
    return "critical"


class QualitativeMatrixEngine(BaseScoringEngine):
    key = "qualitative-matrix"
    label = "Likelihood x Impact (5x5 Matrix)"
    description = "Score = likelihood (1 to 5) x impact (1 to 5), 1 to 25."
    score_scale = "25"
    input_schema = {
        "likelihood": {
            "type": "enum",
            "values": list(LIKELIHOOD_VALUES),
            "labels": ["Rare", "Unlikely", "Possible", "Likely", "Certain"],
            "required": True,
        },
        "impact": {
            "type": "enum",
            "values": list(IMPACT_VALUES),
            "labels": ["Negligible", "Minor", "Moderate", "Major", "Severe"],
            "required": True,
        },
        "rationale": {"type": "text", "required": False},
    }

    def validate(self, inputs: dict) -> None:
        require_enum(inputs, "likelihood", list(LIKELIHOOD_VALUES), label="the matrix")
        require_enum(inputs, "impact", list(IMPACT_VALUES), label="the matrix")

    def _build(self, likelihood_score: int, impact_score: int, rationale: str = ""):
        from apps.threats.models import Rating

        product = likelihood_score * impact_score
        return Rating(
            methodology=self.key,
            level=band(product),
            score=float(product),
            likelihood_level=LIKELIHOOD_TO_SPEC[LIKELIHOOD_BY_SCORE[likelihood_score]],
            likelihood_score=float(likelihood_score),
            impact_level=IMPACT_TO_SPEC[IMPACT_BY_SCORE[impact_score]],
            impact_score=float(impact_score),
            rationale=rationale,
        )

    def rate(self, inputs: dict):
        self.validate(inputs)
        return self._build(
            LIKELIHOOD_VALUES[inputs["likelihood"]],
            IMPACT_VALUES[inputs["impact"]],
            str(inputs.get("rationale") or ""),
        )

    def rate_residual(self, inherent, effectiveness: float):
        # An imported rating keeps whatever scores the file had (#31 comment
        # 2.7). Off the 1 to 5 scale there is no matrix cell to reduce from,
        # so the residual is a copy, as with no contributing controls (R13).
        if not (
            _on_scale(inherent.likelihood_score) and _on_scale(inherent.impact_score)
        ):
            return copy_rating(inherent)
        reduced = max(1, round(inherent.likelihood_score * (1 - effectiveness)))
        residual = self._build(
            int(reduced), int(inherent.impact_score), inherent.rationale
        )
        residual.likelihood_factors = list(inherent.likelihood_factors or [])
        residual.impact_factors = list(inherent.impact_factors or [])
        residual.impact_extra = dict(inherent.impact_extra or {})
        return residual

    def inputs_from_rating(self, rating) -> dict | None:
        """The form inputs that reproduce ``rating``, for pre-filling (#31, 2.10)."""
        likelihood = SPEC_TO_LIKELIHOOD.get(rating.likelihood_level)
        impact = SPEC_TO_IMPACT.get(rating.impact_level)
        if likelihood is None or impact is None:
            return None
        return {"likelihood": likelihood, "impact": impact}
