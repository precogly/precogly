"""``risks.risks[]`` into ``Risk`` and ``RiskResponse`` rows (step 8 slice).

- ``relatedThreats`` refs that are scenarios become links; a ref to an
  abstract threat or anything else is kept on the risk and warned (M15).
- ``responses[]`` with the four strategies we hold become rows (controls
  resolved to this model's); ``exploit`` and ``enhance`` are kept on the
  risk and warned.
- A response's ``targetDate`` becomes the due date of each control it names
  that has none of its own (``precogly:due-date`` wins); with several
  responses the earliest date is kept. This is the spec-native place for a
  planned control's date in 2.0 (a POA&M milestone, say), so overdue
  controls show from a file that carries no Precogly properties (PR #559).
- A custom status is kept and the row gets ``identified`` with a warning.
- A statement marked ``precogly:statement-generated`` is not stored, so the
  model keeps an empty statement rather than a synthesized one.
- Ratings come from ``inherentRisk`` (else a level-only medium rating),
  ``residualRisk`` and ``targetRisk``.
- Kept for export (``kept_values``): an owner that is no member of the
  organization, a response's spec status that maps onto one of ours
  (``proposed`` stored as planned), the effectiveness ``rating``, a
  domain's ``priority`` and ``description``, and custom domains.
"""

from datetime import datetime

from django.contrib.auth import get_user_model

from apps.threats.models import Risk, RiskResponse
from apps.threats.services import (
    apply_rating,
    create_risk,
    create_risk_response,
    level_rating,
    set_risk_business_objectives,
)

from ..import_hints import DATE_TIME_HINT, OWNER_HINT
from ..kept_values import (
    domain_details_to_keep,
    effectiveness_to_keep,
    owner_to_keep,
)
from ..passthrough import keep_unknown
from ..properties import PropertyOwner, read_properties
from ..ratings import rating_from_spec
from ..refs import remember_ref
from ..spec_values import (
    RESPONSE_STATUS_TO_SPEC,
    SPEC_STATUS_TO_RESPONSE,
    type_name,
)

User = get_user_model()

HELD_STRATEGIES = {choice for choice, _ in RiskResponse.Strategy.choices}
RISK_DOMAINS = (
    "security",
    "privacy",
    "operational",
    "financial",
    "compliance",
    "strategic",
    "reputational",
    "safety",
    "environmental",
    "supply-chain",
    "technical",
    "project",
    "ethical",
    "societal",
    "human-rights",
    "health",
    "legal",
)


def _label(data: dict, fallback: str) -> str:
    return str(data.get("name") or data.get("bom-ref") or fallback)[:255]


class RiskImporter:
    def __init__(self, document: dict, threat_model, context):
        self.document = document
        self.threat_model = threat_model
        self.context = context
        # Controls whose due date came from a response here: id -> date, so a
        # later, earlier response can move it, but a date of their own stays.
        self.due_dates_from_responses: dict[int, object] = {}
        component = (document.get("metadata") or {}).get("component") or {}
        parties = component.get("parties") if isinstance(component, dict) else None
        self.parties = {
            party["bom-ref"]: party
            for party in parties or []
            if isinstance(party, dict) and isinstance(party.get("bom-ref"), str)
        }

    def _user_for_party(self, raw):
        party = self.parties.get(raw) if isinstance(raw, str) else raw
        if not isinstance(party, dict):
            return None
        person = party.get("person")
        if not isinstance(person, dict):
            return None
        for item in person.get("email") or []:
            if isinstance(item, dict) and item.get("address"):
                user = User.objects.filter(
                    email__iexact=str(item["address"]),
                    organization_memberships__organization_id=self.threat_model.organization_id,
                ).first()
                if user is not None:
                    return user
        return None

    def _owner(self, raw, label: str):
        """``(user, kept)``: the member the party names, else the party to keep."""
        if not raw:
            return None, None
        user = self._user_for_party(raw)
        if user is not None:
            return user, None
        self.context.warn(
            f"{label}: owner matches no member of the organization; kept for "
            f"export, not assigned. {OWNER_HINT}"
        )
        return None, owner_to_keep(raw, self.parties)

    def _name_for(self, base: str) -> str:
        """A unique risk name in the model (H14): a suffix and a warning."""
        name = base
        suffix = 2
        while Risk.objects.filter(threat_model=self.threat_model, name=name).exists():
            name = f"{base} ({suffix})"[:255]
            suffix += 1
        if name != base:
            self.context.warn(f"Risk '{base}': the name is taken; stored as '{name}'.")
        return name

    def _date_controls(self, controls: list, due_date) -> None:
        """Give each control without its own due date the response's target date."""
        for countermeasure in controls:
            earlier = self.due_dates_from_responses.get(countermeasure.pk)
            if earlier is None and countermeasure.due_date is not None:
                continue  # its own date, from precogly:due-date
            if earlier is not None and earlier <= due_date:
                continue
            countermeasure.due_date = due_date
            countermeasure.save(update_fields=["due_date"])
            self.due_dates_from_responses[countermeasure.pk] = due_date

    def _responses(self, risk, risk_data: dict, label: str) -> list:
        kept = []
        for response_data in risk_data.get("responses") or []:
            if not isinstance(response_data, dict):
                continue
            strategy = response_data.get("strategy")
            if strategy not in HELD_STRATEGIES:
                kept.append(response_data)
                self.context.warn(
                    f"Risk '{label}': response strategy '{strategy}' has no row in "
                    "Precogly; kept for export."
                )
                continue
            status_name = type_name(response_data.get("status"))
            status = SPEC_STATUS_TO_RESPONSE.get(status_name, "planned")
            controls = []
            for ref in response_data.get("controls") or []:
                countermeasure = self.context.resolve(ref, "control")
                if countermeasure is None:
                    self.context.warn(
                        f"Risk '{label}': response control '{ref}' was not found; skipped."
                    )
                elif countermeasure not in controls:
                    controls.append(countermeasure)
            effectiveness = response_data.get("effectiveness")
            percentage = (
                effectiveness.get("percentage")
                if isinstance(effectiveness, dict)
                else None
            )
            target_date = None
            raw_date = response_data.get("targetDate")
            if isinstance(raw_date, str):
                try:
                    target_date = datetime.fromisoformat(
                        raw_date.replace("Z", "+00:00")
                    )
                except ValueError:
                    self.context.warn(
                        f"Risk '{label}': targetDate '{raw_date}' ignored. {DATE_TIME_HINT}"
                    )
            if target_date is not None:
                self._date_controls(controls, target_date.date())
            cost = response_data.get("cost")
            priority = response_data.get("priority")
            owner, kept_owner = self._owner(
                response_data.get("owner"), f"Risk '{label}', response"
            )
            response = create_risk_response(
                risk,
                countermeasures=controls,
                strategy=strategy,
                description=str(response_data.get("description") or ""),
                status=status,
                effectiveness=float(percentage)
                if isinstance(percentage, (int, float))
                and not isinstance(percentage, bool)
                else None,
                cost=cost if cost in {c for c, _ in RiskResponse.Cost.choices} else "",
                priority=priority
                if priority in {p for p, _ in RiskResponse.Priority.choices}
                else "",
                owner=owner,
                target_date=target_date,
            )
            remember_ref(response, response_data.get("bom-ref", ""))
            keep_unknown(response, response_data, "response")
            cyclonedx = {}
            # Kept unless the spec value is ours as is, so "proposed" (stored
            # as planned) and custom statuses are written back.
            if response_data.get("status") is not None and not (
                isinstance(response_data["status"], str)
                and RESPONSE_STATUS_TO_SPEC.get(status) == status_name
            ):
                cyclonedx["original_status"] = response_data["status"]
            kept_effectiveness = effectiveness_to_keep(effectiveness)
            if kept_effectiveness is not None:
                cyclonedx["effectiveness"] = kept_effectiveness
            if kept_owner is not None:
                cyclonedx["owner"] = kept_owner
            if cyclonedx:
                response.format_metadata = {
                    **(response.format_metadata or {}),
                    "cyclonedx": {
                        **((response.format_metadata or {}).get("cyclonedx") or {}),
                        **cyclonedx,
                    },
                }
            response.save(update_fields=["format_metadata"])
            self.context.register(response_data.get("bom-ref"), "response", response)
            self.context.count("risk_responses")
        return kept

    def _import_risk(self, risk_data: dict, index: int) -> None:
        label = _label(risk_data, f"risk {index}")
        properties = read_properties(risk_data.get("properties"), PropertyOwner.RISK)
        statement = str(risk_data.get("statement") or "")
        if properties.get("precogly:statement-generated"):
            statement = ""

        raw_status = risk_data.get("status")
        status_name = type_name(raw_status)
        kept_status = None
        if status_name in {s for s, _ in Risk.Status.choices}:
            status = status_name
        else:
            status = Risk.Status.IDENTIFIED
            if raw_status is not None:
                kept_status = (
                    raw_status
                    if isinstance(raw_status, dict)
                    else {"name": status_name}
                )
                self.context.warn(
                    f"Risk '{label}': status '{status_name}' is not one Precogly has; "
                    "stored as identified and kept for export."
                )

        domains = []
        extra_domains = []
        for domain in risk_data.get("domains") or []:
            name = domain.get("type") if isinstance(domain, dict) else domain
            name = type_name(name)
            if name in RISK_DOMAINS and name not in domains:
                domains.append(name)
            elif name and name not in RISK_DOMAINS and isinstance(domain, dict):
                extra_domains.append(domain)
                self.context.warn(
                    f"Risk '{label}': domain '{name}' is a custom domain; kept for "
                    "export, not shown."
                )

        threats = []
        extra_related = []
        for ref in risk_data.get("relatedThreats") or []:
            threat = (
                self.context.resolve(ref, "scenario") if isinstance(ref, str) else None
            )
            if threat is None:
                extra_related.append(ref)
            elif threat not in threats:
                threats.append(threat)
        if extra_related:
            self.context.warn(
                f"Risk '{label}': relatedThreats {extra_related} are not scenarios; kept "
                "for export, not linked."
            )

        inherent = (
            rating_from_spec(
                (risk_data.get("inherentRisk") or {}).get("score"),
                (risk_data.get("inherentRisk") or {}).get("likelihood"),
                (risk_data.get("inherentRisk") or {}).get("impact"),
                rationale=(risk_data.get("inherentRisk") or {}).get("rationale", ""),
            )
            if isinstance(risk_data.get("inherentRisk"), dict)
            else None
        )
        if inherent is None:
            inherent = level_rating("medium")
            self.context.warn(f"Risk '{label}' has no inherent rating; rated medium.")

        owner, kept_owner = self._owner(risk_data.get("owner"), f"Risk '{label}'")
        risk = create_risk(
            self.threat_model,
            rating=inherent,
            threat_ids=[t.id for t in threats],
            name=self._name_for(label),
            description=str(risk_data.get("description") or ""),
            status=status,
            statement=statement,
            domains=domains,
            owner=owner,
            assigned_to=self._user_for_party(properties.get("precogly:assigned-to")),
        )
        for key, field in (("residualRisk", "residual"), ("targetRisk", "target")):
            data = risk_data.get(key)
            if not isinstance(data, dict):
                continue
            rating = rating_from_spec(
                data.get("score"),
                data.get("likelihood"),
                data.get("impact"),
                rationale=data.get("rationale", ""),
            )
            if rating is not None:
                apply_rating(risk, field, rating)

        objectives = []
        for ref in risk_data.get("relatedBusinessObjectives") or []:
            objective = (
                self.context.resolve(ref, "objective") if isinstance(ref, str) else None
            )
            if objective is None:
                self.context.warn(
                    f"Risk '{label}': business objective '{ref}' was not found; skipped."
                )
            elif objective not in objectives:
                objectives.append(objective)
        if objectives:
            set_risk_business_objectives(risk, objectives)

        remember_ref(risk, risk_data.get("bom-ref", ""))

        keep_unknown(risk, risk_data, "risk")
        cyclonedx = dict((risk.format_metadata or {}).get("cyclonedx") or {})
        if kept_status is not None:
            cyclonedx["custom_status"] = kept_status
        if extra_related:
            cyclonedx["extra_related_threats"] = [
                r for r in extra_related if isinstance(r, str)
            ]
        if label != risk.name:
            cyclonedx["original_name"] = label
        if kept_owner is not None:
            cyclonedx["owner"] = kept_owner
        domain_details = domain_details_to_keep(risk_data.get("domains"), type_name)
        if domain_details:
            cyclonedx["domain_details"] = domain_details
        if extra_domains:
            cyclonedx["extra_domains"] = extra_domains
        kept_responses = self._responses(risk, risk_data, label)
        if kept_responses:
            cyclonedx["extra_responses"] = kept_responses
        if cyclonedx:
            risk.format_metadata = {
                **(risk.format_metadata or {}),
                "cyclonedx": cyclonedx,
            }
            risk.save(update_fields=["format_metadata"])
        self.context.register(risk_data.get("bom-ref"), "risk", risk)
        self.context.count("risks")

    def run(self) -> None:
        section = self.document.get("risks")
        if section is None:
            return
        if not isinstance(section, dict):
            self.context.warn("The 'risks' section is not an object and was skipped.")
            return
        for index, risk_data in enumerate(section.get("risks") or []):
            if not isinstance(risk_data, dict):
                self.context.warn(f"Risk {index} is not an object and was skipped.")
                continue
            self._import_risk(risk_data, index)


def import_risks(document: dict, threat_model, context) -> None:
    RiskImporter(document, threat_model, context).run()
