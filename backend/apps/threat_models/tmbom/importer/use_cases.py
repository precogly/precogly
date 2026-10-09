"""Use cases: ``definitions.useCases[]`` into ``UseCase`` rows."""

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
    for use_case_data in definitions.get("useCases") or []:
        if not isinstance(use_case_data, dict):
            continue
        flow_data = {
            ours: use_case_data[theirs]
            for theirs, ours in KEYS
            if use_case_data.get(theirs)
        }
        use_case = UseCase.objects.create(
            threat_model=threat_model,
            name=str(
                use_case_data.get("name") or use_case_data.get("bom-ref") or "Use case"
            )[:255],
            description=str(use_case_data.get("description") or ""),
            flow_data=flow_data,
        )
        remember_ref(use_case, use_case_data.get("bom-ref", ""))
        keep_unknown(use_case, use_case_data, "usecase")
        use_case.save(update_fields=["format_metadata"])
        context.register(use_case_data.get("bom-ref"), "usecase", use_case)
        context.count("use_cases")
