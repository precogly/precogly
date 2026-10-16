"""A ``Rating`` row is the spec's ``rating`` object (#31 comment, 2.7).

Export: ``score`` always, as ``{level, score?, methodology}``; ``likelihood``
and ``impact`` only when their level is set, since the spec requires it.
Import is the inverse; an unknown methodology string is kept as a custom name.
"""

from .spec_values import type_name

SPEC_METHODOLOGIES = (
    "dread",
    "fair",
    "fmea",
    "nist-sp-800-30",
    "octave",
    "owasp-risk-rating",
    "qualitative-matrix",
)
LEVELS = ("info", "low", "medium", "high", "critical")
LIKELIHOOD_LEVELS = ("very-low", "low", "medium", "high", "very-high", "certain")
IMPACT_LEVELS = ("negligible", "low", "moderate", "major", "catastrophic")
LIKELIHOOD_EXTRA_KEYS = ("probability", "frequency", "timeframe", "range", "rationale")
IMPACT_EXTRA_KEYS = (
    "categories",
    "quantification",
    "range",
    "polarity",
    "riskAttributes",
    "description",
)


def rating_to_spec(rating) -> dict:
    """``{score, likelihood?, impact?, rationale?}`` for a rating row."""
    score = {"level": rating.level}
    if rating.score is not None:
        score["score"] = rating.score
    score["methodology"] = (
        rating.methodology
        if rating.methodology in SPEC_METHODOLOGIES
        else {"name": rating.methodology or "manual"}
    )
    result = {"score": score}
    if rating.likelihood_level:
        likelihood = {"level": rating.likelihood_level}
        if rating.likelihood_score is not None:
            likelihood["score"] = rating.likelihood_score
        if rating.likelihood_factors:
            likelihood["factors"] = list(rating.likelihood_factors)
        for key in LIKELIHOOD_EXTRA_KEYS:
            if key in (rating.likelihood_extra or {}):
                likelihood[key] = rating.likelihood_extra[key]
        result["likelihood"] = likelihood
    if rating.impact_level:
        impact = {"level": rating.impact_level}
        if rating.impact_score is not None:
            impact["score"] = rating.impact_score
        if rating.impact_factors:
            impact["factors"] = list(rating.impact_factors)
        for key in IMPACT_EXTRA_KEYS:
            if key in (rating.impact_extra or {}):
                impact[key] = rating.impact_extra[key]
        result["impact"] = impact
    if rating.rationale:
        result["rationale"] = rating.rationale
    return result


def scenario_rating(rating) -> dict:
    """The three scenario keys: ``likelihood``, ``impact``, ``riskScore``."""
    spec = rating_to_spec(rating)
    entry = {"riskScore": spec["score"]}
    if "likelihood" in spec:
        entry["likelihood"] = spec["likelihood"]
    if "impact" in spec:
        entry["impact"] = spec["impact"]
    return entry


def rating_from_spec(score_data, likelihood_data=None, impact_data=None, rationale=""):
    """An unsaved ``Rating`` from the spec objects; None when there is no level."""
    from apps.threats.models import Rating

    score_data = score_data if isinstance(score_data, dict) else {}
    level = score_data.get("level")
    if level not in LEVELS:
        return None
    methodology = type_name(score_data.get("methodology")) or "manual"
    rating = Rating(
        methodology=methodology[:40],
        level=level,
        score=_number(score_data.get("score")),
        rationale=str(rationale or "")[:10000],
    )
    if (
        isinstance(likelihood_data, dict)
        and likelihood_data.get("level") in LIKELIHOOD_LEVELS
    ):
        rating.likelihood_level = likelihood_data["level"]
        rating.likelihood_score = _number(likelihood_data.get("score"))
        factors = likelihood_data.get("factors")
        rating.likelihood_factors = list(factors) if isinstance(factors, list) else []
        rating.likelihood_extra = {
            key: likelihood_data[key]
            for key in LIKELIHOOD_EXTRA_KEYS
            if key in likelihood_data
        }
    if isinstance(impact_data, dict) and impact_data.get("level") in IMPACT_LEVELS:
        rating.impact_level = impact_data["level"]
        rating.impact_score = _number(impact_data.get("score"))
        factors = impact_data.get("factors")
        rating.impact_factors = list(factors) if isinstance(factors, list) else []
        rating.impact_extra = {
            key: impact_data[key] for key in IMPACT_EXTRA_KEYS if key in impact_data
        }
    return rating


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)
