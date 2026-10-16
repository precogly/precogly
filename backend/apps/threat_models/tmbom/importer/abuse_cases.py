"""Use case links and abuse cases into rows (``editable-use-cases.md``).

Runs after threats and controls, since an abuse case links to scenarios,
personas and controls.

- ``useCase.businessObjectives``, each blueprint's ``useCases[]`` (assets and
  flows) and each asset's ``useCases`` become use case links; data store refs
  resolve too. A blueprint entry for a use case that is not in the document
  is kept on the blueprint and written back.
- ``threats.abuseCases[]`` become ``AbuseCase`` rows. ``abuser`` resolves to
  the persona the actor became; any other abuser is kept as a ref.
  ``targets`` resolve to components and flows.
- ``realizes`` names abstract threats, but our threat rows are scenarios and
  one library threat can have several. Per realized threat: the scenarios
  whose ``precogly:abuse-cases`` name this abuse case (our own exports); else
  the scenarios of that threat whose targets overlap the abuse case's; else
  no link, and the threat is kept as unlinked (by library row when it is
  one, so export writes our ref for it) and shown in the UI with a link
  action. Linking every scenario would turn one generic library threat used
  twenty times into twenty links.
- Refs that resolve to nothing we store are kept on the row and written back
  while they resolve; only a ref that points nowhere in the document is
  warned about.
- ``precogly:abuse-cases`` on a use case links abuse cases to it.
"""

from apps.threat_models.flow_data import normalize_flow_data
from apps.threat_models.models import AbuseCase
from apps.threat_models.use_cases import set_abuse_case_links, set_use_case_links

from ..passthrough import collect_refs
from ..properties import PropertyOwner, read_properties
from ..refs import remember_ref
from .threats import _flatten, _library_for

COMPONENT_KINDS = ("asset", "datastore")


def _refs(raw) -> list[str]:
    if not isinstance(raw, list):
        return []
    return list(dict.fromkeys(ref for ref in raw if isinstance(ref, str) and ref))


def _set_cyclonedx(row, key: str, value) -> None:
    metadata = dict(row.format_metadata or {})
    cyclonedx = dict(metadata.get("cyclonedx") or {})
    if value:
        cyclonedx[key] = value
    else:
        cyclonedx.pop(key, None)
    metadata["cyclonedx"] = cyclonedx
    row.format_metadata = metadata


class AbuseCaseImporter:
    def __init__(self, document: dict, threat_model, context):
        self.document = document
        self.threat_model = threat_model
        self.context = context
        self.document_refs = collect_refs(document)
        section = document.get("threats")
        self.section = section if isinstance(section, dict) else {}
        # use case row id -> {"components": [...], "flows": [...]}
        self.use_case_targets: dict[int, dict[str, list]] = {}
        self.use_cases_by_id: dict = {}

    def _points_nowhere(self, ref: str) -> bool:
        return not ref.startswith("urn:cdx:") and ref not in self.document_refs

    def _warn_nowhere(self, label: str, field: str, refs) -> None:
        nowhere = [ref for ref in refs if self._points_nowhere(ref)]
        if nowhere:
            self.context.warn(
                f"{label}: {field} {', '.join(nowhere)} point(s) at nothing in the "
                "document; kept as they came."
            )

    def _component_or_flow(self, ref):
        component = self.context.resolve(ref, *COMPONENT_KINDS)
        if component is not None:
            return "components", component
        flow = self.context.resolve(ref, "flow")
        if flow is not None:
            return "flows", flow
        return None, None

    # -- use cases -------------------------------------------------------

    def _use_case(self, ref):
        return self.context.resolve(ref, "usecase")

    def _add_use_case_target(self, use_case, ref) -> bool:
        kind, row = self._component_or_flow(ref)
        if row is None:
            return False
        targets = self.use_case_targets.setdefault(
            use_case.pk, {"components": [], "flows": []}
        )
        if row not in targets[kind]:
            targets[kind].append(row)
        self.use_cases_by_id[use_case.pk] = use_case
        return True

    def _blueprint_use_case_entries(self) -> None:
        from apps.threat_models.models import Blueprint

        for blueprint_data in self.document.get("blueprints") or []:
            if not isinstance(blueprint_data, dict):
                continue
            blueprint = self.context.resolve(blueprint_data.get("bom-ref"), "blueprint")
            kept_entries = []
            for entry in blueprint_data.get("useCases") or []:
                if not isinstance(entry, dict):
                    continue
                use_case = self._use_case(entry.get("ref"))
                if use_case is None:
                    kept_entries.append(entry)
                    continue
                unresolved = {"assets": [], "flows": []}
                for key in ("assets", "flows"):
                    for ref in _refs(entry.get(key)):
                        if not self._add_use_case_target(use_case, ref):
                            unresolved[key].append(ref)
                kept = {key: refs for key, refs in unresolved.items() if refs}
                if entry.get("requirements"):
                    kept["requirements"] = entry["requirements"]
                if kept:
                    kept["ref"] = entry["ref"]
                    kept_entries.append(kept)
                    self._warn_nowhere(
                        f"Use case '{use_case.name}'",
                        "linked elements",
                        unresolved["assets"] + unresolved["flows"],
                    )
            if kept_entries and isinstance(blueprint, Blueprint):
                # Re-read: earlier import steps saved the row from other copies.
                blueprint = Blueprint.objects.get(pk=blueprint.pk)
                metadata = dict(blueprint.format_metadata or {})
                cyclonedx = dict(metadata.get("cyclonedx") or {})
                passthrough = dict(cyclonedx.get("passthrough") or {})
                passthrough["useCases"] = kept_entries
                cyclonedx["passthrough"] = passthrough
                metadata["cyclonedx"] = cyclonedx
                blueprint.format_metadata = metadata
                blueprint.save(update_fields=["format_metadata"])

    def _asset_use_cases(self) -> None:
        for blueprint_data in self.document.get("blueprints") or []:
            if not isinstance(blueprint_data, dict):
                continue
            for asset in blueprint_data.get("assets") or []:
                if not isinstance(asset, dict):
                    continue
                for ref in _refs(asset.get("useCases")):
                    use_case = self._use_case(ref)
                    if use_case is None:
                        self._warn_nowhere(
                            f"Asset '{asset.get('name') or asset.get('bom-ref')}'",
                            "use case",
                            [ref],
                        )
                        continue
                    self._add_use_case_target(use_case, asset.get("bom-ref"))

    def _use_case_objectives(self) -> None:
        definitions = self.document.get("definitions") or {}
        for data in definitions.get("useCases") or []:
            if not isinstance(data, dict):
                continue
            use_case = self._use_case(data.get("bom-ref"))
            if use_case is None:
                continue
            objectives, extra = [], []
            for ref in _refs(data.get("businessObjectives")):
                objective = self.context.resolve(ref, "objective")
                if objective is None:
                    extra.append(ref)
                elif objective not in objectives:
                    objectives.append(objective)
            if objectives:
                set_use_case_links(use_case, business_objectives=objectives)
            if extra:
                self._warn_nowhere(
                    f"Use case '{use_case.name}'", "business objectives", extra
                )
                _set_cyclonedx(use_case, "extra_business_objectives", extra)
                use_case.save(update_fields=["format_metadata"])

    def _save_use_case_targets(self) -> None:
        for use_case_id, targets in self.use_case_targets.items():
            set_use_case_links(
                self.use_cases_by_id[use_case_id],
                components=targets["components"],
                flows=targets["flows"],
            )

    # -- abuse cases -----------------------------------------------------

    def _scenarios_by_abuse_ref(self) -> dict[str, list]:
        """Scenario rows per abuse case ref, from ``precogly:abuse-cases``."""
        found: dict[str, list] = {}
        for scenario in self.section.get("scenarios") or []:
            if not isinstance(scenario, dict):
                continue
            threat = self.context.resolve(scenario.get("bom-ref"), "scenario")
            if threat is None:
                continue
            properties = read_properties(
                scenario.get("properties"), PropertyOwner.SCENARIO
            )
            for ref in _flatten(properties.get("precogly:abuse-cases", [])):
                if isinstance(ref, str):
                    found.setdefault(ref, []).append(threat)
        return found

    def _realized_by_abstract(self) -> dict[str, list[str]]:
        """Abstract threat refs per abuse case ref, from ``threat.abuseCases``."""
        found: dict[str, list[str]] = {}
        for abstract in self.section.get("threats") or []:
            if not isinstance(abstract, dict) or not isinstance(
                abstract.get("bom-ref"), str
            ):
                continue
            for ref in _refs(abstract.get("abuseCases")):
                found.setdefault(ref, []).append(abstract["bom-ref"])
        return found

    def _abstract_name(self, threat_ref: str) -> str:
        for abstract in self.section.get("threats") or []:
            if isinstance(abstract, dict) and abstract.get("bom-ref") == threat_ref:
                return str(abstract.get("name") or threat_ref)
        return threat_ref

    def _abuser(self, ref, label: str):
        """``(persona or None, kept ref or "")``."""
        if not isinstance(ref, str) or not ref:
            return None, ""
        persona = self.context.personas_by_actor_ref.get(ref) or self.context.resolve(
            ref, "party"
        )
        if persona is not None:
            return persona, ""
        self._warn_nowhere(f"Abuse case '{label}'", "abuser", [ref])
        return None, ref

    def _threat_links(self, data, abuse_ref, components, flows, exact, label):
        """``(scenario rows, unlinked realizes entries)``."""
        realizes = _refs(data.get("realizes"))
        for threat_ref in self.abstract_by_abuse.get(abuse_ref, []):
            if threat_ref not in realizes:
                realizes.append(threat_ref)
        component_ids = {row.pk for row in components}
        flow_ids = {row.pk for row in flows}
        linked, unlinked = [], []
        for threat_ref in realizes:
            scenarios = self.context.scenarios_by_threat_ref.get(threat_ref, [])
            chosen = [threat for threat in exact if threat in scenarios]
            if not chosen and (component_ids or flow_ids):
                chosen = [
                    threat
                    for threat in scenarios
                    if any(
                        target.component_id in component_ids
                        or target.flow_id in flow_ids
                        for target in threat.targets.all()
                    )
                ]
            if chosen:
                linked.extend(threat for threat in chosen if threat not in linked)
                continue
            library = _library_for(threat_ref)
            if library is not None:
                unlinked.append({"library_threat": library.pk, "name": library.name})
            else:
                unlinked.append(
                    {"ref": threat_ref, "name": self._abstract_name(threat_ref)}
                )
                self._warn_nowhere(f"Abuse case '{label}'", "realizes", [threat_ref])
        # Exact links whose threat the abuse case does not name still count.
        linked.extend(threat for threat in exact if threat not in linked)
        return linked, unlinked

    def _mitigations(self, data, label: str) -> list[dict]:
        kept = []
        for ref in _refs(data.get("mitigations")):
            control = self.context.resolve(ref, "control")
            if control is not None:
                kept.append({"control": control.pk})
            else:
                kept.append({"ref": ref})
                self._warn_nowhere(f"Abuse case '{label}'", "mitigations", [ref])
        return kept

    def _import_abuse_case(self, data: dict, position: int, exact_by_ref) -> None:
        abuse_ref = data.get("bom-ref") if isinstance(data.get("bom-ref"), str) else ""
        label = str(data.get("name") or abuse_ref or f"abuse case {position + 1}")
        flow_data, problems = normalize_flow_data(
            {
                "preconditions": data.get("preconditions"),
                "main_flow": data.get("mainFlow"),
                "detection_opportunities": data.get("detectionOpportunities"),
            },
            "abuse_case",
        )
        for problem in problems:
            self.context.warn(f"Abuse case '{label}': {problem} Left out.")
        abuser, abuser_ref = self._abuser(data.get("abuser"), label)
        abuse_case = AbuseCase.objects.create(
            threat_model=self.threat_model,
            name=label[:255],
            description=str(data.get("description") or ""),
            abuser=abuser,
            flow_data=flow_data,
            display_order=position,
        )
        remember_ref(abuse_case, abuse_ref)

        components, flows, extra_targets = [], [], []
        for ref in _refs(data.get("targets")):
            kind, row = self._component_or_flow(ref)
            if row is None:
                extra_targets.append(ref)
            elif kind == "components":
                components.append(row)
            else:
                flows.append(row)
        self._warn_nowhere(f"Abuse case '{label}'", "targets", extra_targets)
        threats, unlinked = self._threat_links(
            data, abuse_ref, components, flows, exact_by_ref.get(abuse_ref, []), label
        )
        set_abuse_case_links(
            abuse_case, components=components, flows=flows, threats=threats
        )

        _set_cyclonedx(abuse_case, "abuser_ref", abuser_ref)
        _set_cyclonedx(abuse_case, "extra_targets", extra_targets)
        _set_cyclonedx(abuse_case, "unlinked_realizes", unlinked)
        _set_cyclonedx(abuse_case, "mitigations", self._mitigations(data, label))
        abuse_case.save(update_fields=["format_metadata"])
        self.context.register(abuse_ref, "abusecase", abuse_case)
        self.context.count("abuse_cases")

    def _abuse_cases_of_use_cases(self) -> None:
        definitions = self.document.get("definitions") or {}
        links: dict[int, list] = {}
        abuse_cases: dict[int, AbuseCase] = {}
        for data in definitions.get("useCases") or []:
            if not isinstance(data, dict):
                continue
            use_case = self._use_case(data.get("bom-ref"))
            if use_case is None:
                continue
            properties = read_properties(data.get("properties"), PropertyOwner.USE_CASE)
            for ref in _flatten(properties.get("precogly:abuse-cases", [])):
                abuse_case = self.context.resolve(ref, "abusecase")
                if abuse_case is None:
                    self.context.warn(
                        f"Use case '{use_case.name}': abuse case '{ref}' was not "
                        "found; skipped."
                    )
                    continue
                abuse_cases[abuse_case.pk] = abuse_case
                linked = links.setdefault(abuse_case.pk, [])
                if use_case not in linked:
                    linked.append(use_case)
        for abuse_case_id, use_cases in links.items():
            set_abuse_case_links(abuse_cases[abuse_case_id], use_cases=use_cases)

    def run(self) -> None:
        self._use_case_objectives()
        self._blueprint_use_case_entries()
        self._asset_use_cases()
        self._save_use_case_targets()

        self.abstract_by_abuse = self._realized_by_abstract()
        exact_by_ref = self._scenarios_by_abuse_ref()
        raw = self.section.get("abuseCases")
        if raw is not None and not isinstance(raw, list):
            self.context.warn("threats.abuseCases is not a list and was skipped.")
            raw = []
        for position, data in enumerate(raw or []):
            if not isinstance(data, dict):
                self.context.warn(
                    f"Abuse case {position + 1} is not an object and was skipped."
                )
                continue
            self._import_abuse_case(data, position, exact_by_ref)
        self._abuse_cases_of_use_cases()


def import_abuse_cases(document: dict, threat_model, context) -> None:
    AbuseCaseImporter(document, threat_model, context).run()
