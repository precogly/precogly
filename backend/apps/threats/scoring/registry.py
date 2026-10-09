"""Scoring method registry: engines by their CycloneDX methodology key.

Populated by ``BaseScoringEngine.__init_subclass__``. Methods without an
engine yet (FAIR, Mozilla RRA) are listed with ``available: false`` so the
chooser can show them.
"""

from importlib import import_module

_ENGINES: dict[str, type] = {}
_ENGINE_MODULES = ("qualitative_matrix", "owasp_risk_rating", "manual")

# Methods a threat model may pick that have no engine yet.
PLANNED_METHODS = {
    "fair": {
        "label": "FAIR",
        "description": "Factor Analysis of Information Risk. Quantitative. Engine not yet available.",
    },
    "mozilla-rra": {
        "label": "Mozilla Rapid Risk Assessment",
        "description": "Qualitative risk assessment with data classification. Engine not yet available.",
    },
}


def register(engine_class) -> None:
    _ENGINES[engine_class.key] = engine_class


def _ensure_loaded() -> None:
    for name in _ENGINE_MODULES:
        import_module(f"{__package__}.{name}")


def get_engine(key: str):
    """An engine instance for ``key``, or None when none is registered."""
    _ensure_loaded()
    engine_class = _ENGINES.get(key)
    return engine_class() if engine_class is not None else None


def get_engines() -> dict:
    _ensure_loaded()
    return dict(_ENGINES)


def get_scoring_methods_list() -> list[dict]:
    """The chooser's list: registered engines first, then planned methods."""
    _ensure_loaded()
    methods = [
        {
            "key": engine_class.key,
            "label": engine_class.label,
            "description": engine_class.description,
            "input_schema": engine_class.input_schema,
            "score_scale": engine_class.score_scale,
            "available": True,
        }
        for engine_class in _ENGINES.values()
        if engine_class.key != "manual"
    ]
    for key, planned in PLANNED_METHODS.items():
        if key not in _ENGINES:
            methods.append(
                {
                    "key": key,
                    "label": planned["label"],
                    "description": planned["description"],
                    "input_schema": {},
                    "score_scale": "",
                    "available": False,
                }
            )
    return methods
