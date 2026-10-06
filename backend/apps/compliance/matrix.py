"""Compliance matrix for a threat model.

Groups every StandardRequirement in a framework under its two-letter family
(AC, AU, CM, ...) and lists the countermeasures and threats attached to it
inside one ThreatModel. See JJediny/precogly#6 for the acceptance criteria.
"""

from __future__ import annotations

from collections import defaultdict

from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render
from django.views.decorators.http import require_GET
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.threat_models.models import ThreatModel
from apps.threats.models import (
    ComponentInstanceThreat,
    CountermeasureThreatLink,
    DataFlowInstanceThreat,
    InstanceCountermeasure,
)

from .models import StandardFramework

DEFAULT_FRAMEWORK_NAME = "NIST 800-53 Rev 5"


def _family(section_code: str) -> str:
    return section_code.split("-", 1)[0] if "-" in section_code else section_code


def _truthy(value) -> bool:
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _resolve_framework(name_query: str) -> StandardFramework | None:
    return StandardFramework.objects.filter(name__icontains=name_query).first()


def _cdx_ctrl_ids(fm: dict | None) -> list[str]:
    """Return every ctrl_id-flavoured value stored on ``format_metadata``.

    The CycloneDX importer writes the canonical NIST id at
    ``format_metadata.cyclonedx.ctrl_id`` (or ``ctrlId``, ``nist_control_id``).
    A synced SSPP CDX can also carry the id at the top of the ``cyclonedx``
    block for older payloads. Read all of them so nothing is dropped silently.
    """
    if not fm:
        return []
    cdx = fm.get("cyclonedx") or {}
    ids: list[str] = []
    for key in ("ctrl_id", "ctrlId", "nist_control_id"):
        val = cdx.get(key)
        if val and val not in ids:
            ids.append(val)
    return ids


def _index_countermeasures(
    tm: ThreatModel,
) -> dict[str, list[InstanceCountermeasure]]:
    """Return ``{section_code: [InstanceCountermeasure, ...]}`` for one TM.

    Primary source is ``instance_standard_mappings``. Falls back to
    ``format_metadata['cyclonedx']['ctrl_id']`` (written by the CycloneDX
    importer) and additionally indexes the two-letter family prefix of any
    enhanced control id like ``AC-6(5)`` so a CM shows up under both.
    """
    idx: dict[str, list[InstanceCountermeasure]] = defaultdict(list)
    cms = (
        tm.countermeasures.all()
        .prefetch_related("instance_standard_mappings")
        .order_by("countermeasure_name")
    )
    for ic in cms:
        seen: set[str] = set()
        for mapping in ic.instance_standard_mappings.all():
            code = mapping.section_code
            if code and code not in seen:
                idx[code].append(ic)
                seen.add(code)
        for cid in _cdx_ctrl_ids(ic.format_metadata):
            if cid not in seen:
                idx[cid].append(ic)
                seen.add(cid)
            base = cid.split("(", 1)[0]
            if base != cid and base not in seen:
                idx[base].append(ic)
                seen.add(base)
    return idx


def _index_threats(
    tm: ThreatModel,
) -> dict[str, list[ComponentInstanceThreat | DataFlowInstanceThreat]]:
    """Return ``{section_code: [threat, ...]}`` for one TM.

    Two paths, unioned per requirement:

    * ``CountermeasureThreatLink`` → CM → ``instance_standard_mappings``.
    * Threat-side ``format_metadata['cyclonedx']['ctrl_id']`` (written by the
      SSPP CDX generator on every FPDF threat). This is the interim behaviour
      the prototype README warned about; delete it when the canonical
      ``ThreatStandard`` table lands (JJediny/precogly#9).
    """
    idx: dict[str, list[ComponentInstanceThreat | DataFlowInstanceThreat]] = (
        defaultdict(list)
    )
    seen_per_section: dict[str, set[tuple[str, int]]] = defaultdict(set)

    def _record(threat, code: str, kind: str) -> None:
        if not code:
            return
        key = (kind, threat.pk)
        if key in seen_per_section[code]:
            return
        idx[code].append(threat)
        seen_per_section[code].add(key)

    links = (
        CountermeasureThreatLink.objects.filter(countermeasure__threat_model=tm)
        .select_related("countermeasure", "component_threat", "flow_threat")
        .prefetch_related("countermeasure__instance_standard_mappings")
    )
    for link in links:
        threat = link.component_threat or link.flow_threat
        if threat is None:
            continue
        kind = "component" if link.component_threat else "flow"
        for mapping in link.countermeasure.instance_standard_mappings.all():
            _record(threat, mapping.section_code, kind)

    component_threats = ComponentInstanceThreat.objects.filter(
        component__threat_model=tm
    )
    for cit in component_threats:
        for cid in _cdx_ctrl_ids(cit.format_metadata):
            _record(cit, cid, "component")
            base = cid.split("(", 1)[0]
            if base != cid:
                _record(cit, base, "component")

    flow_threats = DataFlowInstanceThreat.objects.filter(
        data_flow__source_component__threat_model=tm
    )
    for dfit in flow_threats:
        for cid in _cdx_ctrl_ids(dfit.format_metadata):
            _record(dfit, cid, "flow")
            base = cid.split("(", 1)[0]
            if base != cid:
                _record(dfit, base, "flow")

    return idx


def _threat_name(threat) -> str:
    name = getattr(threat, "threat_name", None)
    return name or str(threat)


def _cm_payload(ic: InstanceCountermeasure, section_code: str) -> dict:
    """Project one CM into the matrix, including per-mapping and provenance."""
    mappings = [
        {
            "sufficiency": m.sufficiency,
            "section_code": m.section_code,
            "evidence_url": getattr(m, "evidence_url", "") or "",
        }
        for m in ic.instance_standard_mappings.all()
        if m.section_code == section_code
    ]

    fm = ic.format_metadata or {}
    cdx = fm.get("cyclonedx") or {}
    poam = cdx.get("poam") or {}
    inheritance = {
        "is_inherited": bool(cdx.get("is_inherited", ic.is_inherited)),
        "providing_system": cdx.get("providing_system")
        or ic.inherited_from_component_name
        or "",
        "responsibility_source": cdx.get("responsibility_source", ""),
        "control_type": cdx.get("control_type") or ic.control_nature or "",
    }
    poam_payload = {
        "poam_id": poam.get("poam_id", ""),
        "due_date": poam.get("due_date", ""),
    }

    return {
        "id": ic.id,
        "name": ic.countermeasure_name,
        "status": ic.status,
        "mappings": mappings,
        "inheritance": inheritance,
        "poam": poam_payload,
        "evidence_url": ic.evidence_url or "",
    }


def build_matrix(
    tm: ThreatModel,
    framework_name: str,
    include_empty: bool = False,
) -> dict:
    fw = _resolve_framework(framework_name)
    if fw is None:
        return {
            "threat_model": {"id": tm.id, "name": tm.name},
            "framework": None,
            "families": [],
            "warning": f"No compliance framework matches {framework_name!r}",
        }

    cm_index = _index_countermeasures(tm)
    threat_index = _index_threats(tm)

    families: dict[str, list[dict]] = defaultdict(list)
    for req in fw.requirements.all().order_by("section_code"):
        cms = cm_index.get(req.section_code, [])
        threats = threat_index.get(req.section_code, [])
        if not cms and not threats and not include_empty:
            continue

        cm_payload = [_cm_payload(ic, req.section_code) for ic in cms]
        threat_payload = [
            {
                "id": t.id,
                "kind": (
                    "component" if isinstance(t, ComponentInstanceThreat) else "flow"
                ),
                "name": _threat_name(t),
            }
            for t in threats
        ]

        families[_family(req.section_code)].append(
            {
                "section_code": req.section_code,
                "description": req.description,
                "countermeasures": cm_payload,
                "threats": threat_payload,
            }
        )

    return {
        "threat_model": {"id": tm.id, "name": tm.name},
        "framework": {"id": fw.id, "name": fw.name},
        "families": [
            {"family": fam, "requirements": reqs}
            for fam, reqs in sorted(families.items())
        ],
    }


def _resolve_tm(user, tm_id: int) -> ThreatModel:
    return get_object_or_404(ThreatModel.objects.visible_to(user), pk=tm_id)


class ComplianceMatrixApiView(APIView):
    """JSON compliance matrix for a single threat model.

    ``GET /api/threat-models/<tm_id>/compliance-matrix/[?framework=<name>][&include_empty=true]``
    """

    permission_classes = [IsAuthenticated]

    def get(self, request, tm_id: int):
        tm = _resolve_tm(request.user, tm_id)
        fw_name = request.query_params.get("framework", DEFAULT_FRAMEWORK_NAME)
        include_empty = _truthy(request.query_params.get("include_empty"))
        return Response(
            build_matrix(tm, framework_name=fw_name, include_empty=include_empty)
        )


@login_required
@require_GET
def compliance_matrix_html(request, tm_id: int):
    """Server-rendered HTML mirror of ``ComplianceMatrixApiView``.

    Same access rules — ``ThreatModel.objects.visible_to(request.user)`` — and
    the same payload, wrapped in a self-contained template so the matrix is
    reviewable without the SPA.
    """
    tm = _resolve_tm(request.user, tm_id)
    fw_name = request.GET.get("framework", DEFAULT_FRAMEWORK_NAME)
    include_empty = _truthy(request.GET.get("include_empty"))
    matrix = build_matrix(tm, framework_name=fw_name, include_empty=include_empty)
    return render(
        request,
        "compliance/matrix.html",
        {"matrix": matrix, "include_empty": include_empty},
    )
