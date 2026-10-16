"""Use cases: ``definitions.useCases[]`` into ``UseCase`` rows."""

from apps.threat_models.flow_data import normalize_flow_data
from apps.threat_models.models import UseCase

from ..passthrough import keep_unknown
from ..refs import remember_ref

KEYS = (
    ("preconditions", "preconditions"),
    ("postconditions", "postconditions"),
    ("successCriteria", "success_criteria"),
    ("mainFlow", "main_flow"),
    ("alternativeFlows", "alternative_flows"),
    ("exceptions", "exceptions"),
    ("notes", "notes"),
)


def import_use_cases(document: dict, threat_model, context) -> None:
    definitions = document.get("definitions") or {}
    for position, use_case_data in enumerate(definitions.get("useCases") or []):
        if not isinstance(use_case_data, dict):
            continue
        name = str(
            use_case_data.get("name") or use_case_data.get("bom-ref") or "Use case"
        )[:255]
        # Invalid entries are dropped with a warning, so the stored row is
        # always valid and the use case can be edited and saved.
        flow_data, problems = normalize_flow_data(
            {
                ours: use_case_data[theirs]
                for theirs, ours in KEYS
                if use_case_data.get(theirs)
            },
            "use_case",
        )
        for problem in problems:
            context.warn(f"Use case '{name}': {problem} Left out.")
        use_case = UseCase.objects.create(
            threat_model=threat_model,
            name=name,
            description=str(use_case_data.get("description") or ""),
            flow_data=flow_data,
            display_order=position,
        )
        remember_ref(use_case, use_case_data.get("bom-ref", ""))
        keep_unknown(use_case, use_case_data, "usecase")
        use_case.save(update_fields=["format_metadata"])
        context.register(use_case_data.get("bom-ref"), "usecase", use_case)
        context.count("use_cases")
