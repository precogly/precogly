# 0002: Tool implementation order

Status: accepted
Date: 2026-07-29
Relates to: precogly/precogly discussion #221 ("MCP for Precogly"),
[0001](0001-service-token-model.md)

Tools are built in order of how much they teach per unit of unresolved design, not in the
order #221 lists them. `list_threat_models` is first and `import_threat_model` is last.

## Order

1. `list_threat_models`
2. `search_library` — settled as three tools, `search_threat_library`,
   `search_countermeasure_library` and `search_component_library`, filtering in the tool
   body rather than at the viewset ([0006](0006-catalog-search-filters-here.md))
3. `get_threat_model_threats`
4. `export_threat_model` — both formats
5. `get_threat_model`
6. `import_threat_model`

`generate_threats`, countermeasure status updates, and `get_threat_candidate_pool` follow
a working demo agent.

## Why list_threat_models is first

It is the only tool that exercises the whole stack — transport, auth, response shaping —
with nothing else unresolved.

- `ThreatModelViewSet` requires `IsAuthenticated, CanWrite`
  (`apps/threat_models/views.py:33`), not a special role.
- It inherits the default `PageNumberPagination` at 20 per page
  (`config/settings/base.py:182`), so there is no projection crisis to solve first.
- `ThreatModelListSerializer` (`apps/threat_models/serializers.py:675`) is flat: twelve
  fields, no nesting.
- `filterset_fields = ["organization"]` already exists on the viewset, so the explicit
  organization scoping that [0001](0001-service-token-model.md) depends on can be proved
  end-to-end on a read path, with no backend change.

That last point is why it beats every alternative. The organization story is the part of
the design most likely to be wrong, and this is the cheapest place to find out.

The projection for this tool dropped `frameworks`. `ThreatModelFieldsMixin.get_frameworks`
issues three queries per row — library-level mappings, instance-level mappings, then a
lookup to resolve the framework rows — so a twenty-row page costs sixty queries for a
field an agent choosing which model to open does not need.

That reasoning is wrong, and the field is now carried as bare names. The sixty queries are
not ours to avoid: `frameworks` is a `SerializerMethodField` listed in
`ThreatModelListSerializer.Meta.fields` (`apps/threat_models/serializers.py:683, :696`), so
the server computes it on every listing request whether or not this projection forwards the
result. A projection controls tokens and nothing else. Measured on the seeded listing — two
rows, so treat the ratio as indicative — the framework objects cost 68% on top of the rest
of the row and their names cost 18%. The ids are primary keys no tool accepts, and the
versions do not participate in the question the field is asked.

The mistake worth carrying forward is not the field. It is that a payload measurement was
taken to settle a capability question. Bytes were what got measured; whether the field was
the only route to something was not.

Its own docstring describes a walk from threat model through components and dataflows to
threats and countermeasures. The body does not do that: `InstanceCountermeasure` has a
direct `threat_model` foreign key (`apps/threats/models.py:524`), and the method filters
on it. The distinction matters because that key is also what makes a framework filter a
single query rather than a redesign.

Testing showed where the absence broke. Asked "which of our threat models are mapped to
SOC 2?", an agent holding only this tool answered that it could not, quoting the tool's own
description back: it "does not carry a model's contents, or the compliance frameworks it
maps to". The reasoning was correct and the refusal was fast, which is the description
working — and the question is a reasonable one that nothing in this order could answer.

Carrying the names answers it directly, which is what a local model did unprompted against
the raw response while [0005](0005-code-execution-over-tools.md) was being written. That
also shrinks what a server-side `?framework=` filter on the listing (#262) would buy: with
the names on every row, the filter is narrowing for large result sets rather than access to
something otherwise unreachable. Still worth raising, on weaker grounds than were recorded
here originally.

The field is incidence, not coverage — a model is listed under a framework when one
countermeasure maps to one requirement — so the tool description has to say so. Unqualified,
it invites "this model covers SOC 2", and trading an unanswerable question for a
confidently wrong one is not an improvement.

## Why search_library is not first

It was, in the first plan. One unresolved decision sat on it, which was enough to put it
second and was never enough to call it a poor place to learn the stack: the threat-library
rows nest `taxonomy_entries` per row. That is now settled by measurement — the entry keeps
`taxonomy_slug`, `external_id` and `title`, and the whole projection costs 57% of the raw
catalog — and the nesting turned out to be the reason these tools are worth having, since
no server-side search reaches those entries
([0006](0006-catalog-search-filters-here.md)).

Three further reasons were listed here and withdrawn.

That the endpoints are unpaginated, so the tool would have to impose its own bound rather
than proxy. They are unpaginated, but `search_fields` is set on all of them and `?search=`
narrows server-side, so a tool whose whole purpose is a query never asks for an unbounded
response. The bound is the server's after all.

That it needs the security-team role (`apps/threats/views.py:87`), so it would fail for
tokens working everywhere else. That was read off the viewset's `permission_classes` line
without reading the permission class. `IsSecurityTeam.has_permission` returns `True` for
`SAFE_METHODS` before consulting any membership (`apps/core/permissions.py:14-16`), so it
gates writes and not reads. A plain member of the demo organization gets 200 and five rows
from `/api/threat-library/?search=injection`, and 403 only on POST. A search tool only
ever reads.

That it spans three endpoints differing in permissions, filters, and shapes. The
permissions half of that is gone with the reason above — all three carry the same
read-open, write-gated class. The filters and shapes still differ, which is an argument
for three tools rather than one, and not an argument for building them later.

## Why get_threat_model is late

`GET /threat-models/{id}/report/` calls `build_report_data`
(`apps/threat_models/report_service.py:751`), which assembles eleven sections. The
`architecture` section embeds full `canvas_data` per diagram — every node, edge, and
coordinate (`report_service.py:119-132`). That is geometry with no value to a language
model, and shaping it is the hardest projection problem in the set. It is worth doing
once there are real token measurements from tools 1 through 4 to guide it, rather than
guessing.

## Trade-offs

- **The #221 demo agent needs `search_library` early**, and this order delivers it
  second rather than first. Accepted: one tool's delay costs less than learning the
  transport, auth, and shaping layers through the tool with the most unknowns. The
  argument has eroded with each withdrawal, and one reason of the original four now
  stands. It no longer justifies the ordering; what justifies it at this point is that
  `list_threat_models` is already built and did teach the stack. Had the permission
  reason been checked rather than assumed, the order would likely have been the other
  way round.
- **`import_threat_model` is the acceptance criterion in #221 and lands last.** It is
  also the only write, the only one that can damage data, and the only one blocked on a
  backend change. Building it after the read tools means its response shaping is the
  sixth of its kind rather than the first.

## Redesign on the new model (2026-10-08)

The schema alignment work (precogly/precogly#583, #584) changed what the planned tools
would read, so tools 3 to 6 and the follow-ups are redesigned before they are built.
Nothing new is built in that work; the four existing tools only changed shape:

- `list_threat_models` rows carry `methodologies`, `lifecycle_phase`, `approved_at` (the
  date, never the approval state, which a listing does not compute), `primary_system_name`,
  `serial_number`, `version` and `blueprint_count`; `risk_scoring_method` is one of
  `qualitative-matrix`, `owasp-risk-rating`, `fair`, `mozilla-rra`.
- `search_component_library` rows carry `kind` (the CycloneDX asset type) and the tool
  takes a `kind` filter matched against the effective kind.
- `search_countermeasure_library` matches the description too; the "name only" caveat
  is gone with the serializer gap that caused it.

What the planned tools become:

- `get_threat_model_threats`: one threat table. Each threat is a scenario with a `number`
  (`T7` on screen), a `targets` list (component, flow, zone or boundary refs, or
  whole-system), a rating (`methodology`, `level`, `score`, likelihood and impact), triage
  fields and the linked countermeasures by number. Takes an optional `blueprint` id, since
  a model may hold several blueprints. The two old lists (component threats, flow threats)
  do not exist any more.
- Countermeasure status updates: by countermeasure `number` (`C3`) or id, with `status` and
  the scope (`applies_to` targets, `implemented_by` components and party). Setting
  `platform` needs the Security Team role, enforced in the service the tool would call.
- `export_threat_model`: one format, CycloneDX 2.0 TM-BOM, from
  `GET /api/threat-models/{id}/export/cyclonedx/`. The TM-Library format is retired.
- `import_threat_model`: `POST` of a TM-BOM document; the answer is the new model's id
  and the import summary with its `warnings` list, which is where everything the file
  held that Precogly could not store is named.
- `get_threat_model`: planned on `build_report_data`, which the same work rewrote. The
  report now carries threats with targets and numbers, zones, boundaries, flows, ratings,
  assumptions as rows, business objectives and the review block, and it still embeds
  `canvas_data` per diagram, so the projection question from the section above stands.
- `generate_threats`: the model-level `POST /api/threat-models/{id}/generate-threats/`
  action exists for the UI; the tool would call it and return `{created, targets}`.

Any new per-model tool on the stdio transport keeps the count-and-total pattern:
`HTTPReader` reads one page of twenty and cannot ask for another, so a listing answers
with `total` beside the rows.
