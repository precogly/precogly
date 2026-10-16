"""OWASP Risk Rating (#31 comment, section 2.2 and Part 1).

Sixteen factors, each 0 to 9, in four groups. Likelihood is the mean of the
eight threat agent and vulnerability factors; impact the mean of the eight
technical and business impact factors; both rounded to one decimal. OWASP's
bands on each: below 3 low, below 6 medium, else high. The overall level
comes from the OWASP matrix; ``score`` is the mean of the two, 0 to 9.
"""

from rest_framework.exceptions import ValidationError

from .base import BaseScoringEngine, copy_rating

GROUPS = {
    "threat_agent": ("skill_level", "motive", "opportunity", "size"),
    "vulnerability": (
        "ease_of_discovery",
        "ease_of_exploit",
        "awareness",
        "intrusion_detection",
    ),
    "technical_impact": (
        "loss_of_confidentiality",
        "loss_of_integrity",
        "loss_of_availability",
        "loss_of_accountability",
    ),
    "business_impact": (
        "financial_damage",
        "reputation_damage",
        "non_compliance",
        "privacy_violation",
    ),
}
LIKELIHOOD_GROUPS = ("threat_agent", "vulnerability")
IMPACT_GROUPS = ("technical_impact", "business_impact")

GROUP_LABELS = {
    "threat_agent": "Threat agent factors",
    "vulnerability": "Vulnerability factors",
    "technical_impact": "Technical impact factors",
    "business_impact": "Business impact factors",
}

# OWASP's option labels at the values the methodology names; other values are
# in between.
FIELD_LABELS = {
    "skill_level": {
        1: "No technical skills",
        3: "Some technical skills",
        5: "Advanced computer user",
        6: "Network and programming skills",
        9: "Security penetration skills",
    },
    "motive": {1: "Low or no reward", 4: "Possible reward", 9: "High reward"},
    "opportunity": {
        0: "Full access or expensive resources required",
        4: "Special access or resources required",
        7: "Some access or resources required",
        9: "No access or resources required",
    },
    "size": {
        2: "Developers or system administrators",
        4: "Intranet users",
        5: "Partners",
        6: "Authenticated users",
        9: "Anonymous Internet users",
    },
    "ease_of_discovery": {
        1: "Practically impossible",
        3: "Difficult",
        7: "Easy",
        9: "Automated tools available",
    },
    "ease_of_exploit": {
        1: "Theoretical",
        3: "Difficult",
        5: "Easy",
        9: "Automated tools available",
    },
    "awareness": {1: "Unknown", 4: "Hidden", 6: "Obvious", 9: "Public knowledge"},
    "intrusion_detection": {
        1: "Active detection in application",
        3: "Logged and reviewed",
        8: "Logged without review",
        9: "Not logged",
    },
    "loss_of_confidentiality": {
        2: "Minimal non-sensitive data disclosed",
        6: "Minimal critical data disclosed",
        7: "Extensive non-sensitive data disclosed",
        9: "All data disclosed",
    },
    "loss_of_integrity": {
        1: "Minimal slightly corrupt data",
        3: "Minimal seriously corrupt data",
        5: "Extensive slightly corrupt data",
        7: "Extensive seriously corrupt data",
        9: "All data totally corrupt",
    },
    "loss_of_availability": {
        1: "Minimal secondary services interrupted",
        5: "Minimal primary services interrupted",
        7: "Extensive primary services interrupted",
        9: "All services completely lost",
    },
    "loss_of_accountability": {
        1: "Fully traceable",
        7: "Possibly traceable",
        9: "Completely anonymous",
    },
    "financial_damage": {
        1: "Less than the cost to fix",
        3: "Minor effect on annual profit",
        7: "Significant effect on annual profit",
        9: "Bankruptcy",
    },
    "reputation_damage": {
        1: "Minimal damage",
        4: "Loss of major accounts",
        5: "Loss of goodwill",
        9: "Brand damage",
    },
    "non_compliance": {
        2: "Minor violation",
        5: "Clear violation",
        7: "High profile violation",
    },
    "privacy_violation": {
        3: "One individual",
        5: "Hundreds of people",
        7: "Thousands of people",
        9: "Millions of people",
    },
}

LIKELIHOOD_FACTOR_TYPES = {
    "skill_level": "threat-capability",
    "motive": "motivation",
    "opportunity": "opportunity",
    "size": {"name": "Threat agent size"},
    "ease_of_discovery": "discoverability",
    "ease_of_exploit": "exploit-maturity",
    "awareness": {"name": "Awareness"},
    "intrusion_detection": "detectability",
}
IMPACT_FACTOR_CATEGORIES = {
    "loss_of_confidentiality": "confidentiality",
    "loss_of_integrity": "integrity",
    "loss_of_availability": "availability",
    "loss_of_accountability": {"name": "Accountability"},
    "financial_damage": "financial",
    "reputation_damage": "reputation",
    "non_compliance": "regulatory",
    "privacy_violation": "privacy",
}

LIKELIHOOD_LEVELS = {"low": "low", "medium": "medium", "high": "high"}
IMPACT_LEVELS = {"low": "low", "medium": "moderate", "high": "major"}
MATRIX = {
    ("low", "low"): "info",
    ("low", "medium"): "low",
    ("low", "high"): "medium",
    ("medium", "low"): "low",
    ("medium", "medium"): "medium",
    ("medium", "high"): "high",
    ("high", "low"): "medium",
    ("high", "medium"): "high",
    ("high", "high"): "critical",
}


def owasp_band(score: float) -> str:
    if score < 3:
        return "low"
    if score < 6:
        return "medium"
    return "high"


def _labels(field: str) -> list:
    known = FIELD_LABELS[field]
    return [known.get(value) for value in range(10)]


def _factor_name(field: str) -> str:
    return field.replace("_", " ").capitalize()


class OwaspRiskRatingEngine(BaseScoringEngine):
    key = "owasp-risk-rating"
    label = "OWASP Risk Rating"
    description = "Sixteen factors, 0 to 9, in OWASP's likelihood and impact groups."
    score_scale = "9"
    input_schema = {
        group: {
            "type": "group",
            "label": GROUP_LABELS[group],
            "required": True,
            "fields": {
                field: {
                    "type": "integer",
                    "min": 0,
                    "max": 9,
                    "labels": _labels(field),
                    "required": True,
                }
                for field in fields
            },
        }
        for group, fields in GROUPS.items()
    }
    input_schema["rationale"] = {"type": "text", "required": False}

    def validate(self, inputs: dict) -> None:
        problems = []
        for group, fields in GROUPS.items():
            values = inputs.get(group)
            if not isinstance(values, dict):
                problems.append(f"{group} is required")
                continue
            for field in fields:
                value = values.get(field)
                if (
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or not 0 <= value <= 9
                ):
                    problems.append(f"{group}.{field} must be an integer from 0 to 9")
        if problems:
            raise ValidationError({"rating_inputs": problems})

    @staticmethod
    def _mean(inputs: dict, groups) -> float:
        values = [inputs[group][field] for group in groups for field in GROUPS[group]]
        return round(sum(values) / len(values), 1)

    def _build(self, likelihood_score: float, impact_score: float, inputs: dict):
        from apps.threats.models import Rating

        likelihood_band = owasp_band(likelihood_score)
        impact_band = owasp_band(impact_score)
        return Rating(
            methodology=self.key,
            level=MATRIX[(likelihood_band, impact_band)],
            score=round((likelihood_score + impact_score) / 2, 3),
            likelihood_level=LIKELIHOOD_LEVELS[likelihood_band],
            likelihood_score=likelihood_score,
            likelihood_factors=[
                {
                    "name": _factor_name(field),
                    "type": LIKELIHOOD_FACTOR_TYPES[field],
                    "score": inputs[group][field],
                }
                for group in LIKELIHOOD_GROUPS
                for field in GROUPS[group]
            ],
            impact_level=IMPACT_LEVELS[impact_band],
            impact_score=impact_score,
            impact_factors=[
                {
                    "name": _factor_name(field),
                    "category": IMPACT_FACTOR_CATEGORIES[field],
                    "score": inputs[group][field],
                }
                for group in IMPACT_GROUPS
                for field in GROUPS[group]
            ],
            rationale=str(inputs.get("rationale") or ""),
        )

    def rate(self, inputs: dict):
        self.validate(inputs)
        return self._build(
            self._mean(inputs, LIKELIHOOD_GROUPS),
            self._mean(inputs, IMPACT_GROUPS),
            inputs,
        )

    def rate_residual(self, inherent, effectiveness: float):
        if inherent.likelihood_score is None or inherent.impact_score is None:
            return copy_rating(inherent)
        residual = copy_rating(inherent)
        likelihood_score = round(inherent.likelihood_score * (1 - effectiveness), 1)
        likelihood_band = owasp_band(likelihood_score)
        impact_band = owasp_band(inherent.impact_score)
        residual.likelihood_score = likelihood_score
        residual.likelihood_level = LIKELIHOOD_LEVELS[likelihood_band]
        residual.level = MATRIX[(likelihood_band, impact_band)]
        residual.score = round((likelihood_score + inherent.impact_score) / 2, 3)
        return residual
