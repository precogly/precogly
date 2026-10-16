"""Level-only rating: the user picks a level (#31 comment, section 2.2)."""

from .base import BaseScoringEngine, require_enum


class ManualEngine(BaseScoringEngine):
    key = "manual"
    label = "Level only"
    description = "Pick a level directly. No likelihood or impact."
    input_schema = {
        "level": {
            "type": "enum",
            "values": ["info", "low", "medium", "high", "critical"],
            "labels": ["Info", "Low", "Medium", "High", "Critical"],
            "required": True,
        },
        "rationale": {"type": "text", "required": False},
    }

    def validate(self, inputs: dict) -> None:
        require_enum(
            inputs,
            "level",
            self.input_schema["level"]["values"],
            label="a level-only rating",
        )

    def rate(self, inputs: dict):
        from apps.threats.models import Rating

        self.validate(inputs)
        return Rating(
            methodology=self.key,
            level=inputs["level"],
            score=None,
            rationale=str(inputs.get("rationale") or ""),
        )
