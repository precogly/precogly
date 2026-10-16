# Changelog

All notable releases of Precogly are documented here.

## Unreleased

This release aligns Precogly's data model with the CycloneDX 2.0 Threat Modeling BOM (issues #583 and #584). What you draw, rate, and approve is what the export contains, and a file from any tool that writes the schema imports with warnings instead of errors.

### Breaking changes

- **Local development databases must be recreated.** The migrations assume no existing data. Run `docker compose down -v`, then `docker compose up`, and seed again.
- **Files exported by earlier versions do not import into the workspace.** There is no converter in the backend. To open such a file as it was, run the previous version of Precogly in Docker. The guest editor is the exception: it converts files saved by its earlier version when it opens them (see Guest editor below).
- **The TM-Library format is removed.** CycloneDX 2.0 TM-BOM is the one interchange format, in the signed-in workspace and the guest editor. The `import/tm-library` and `export/tm-library` endpoints are gone.
- **API paths renamed.** `/api/component-threats/` and `/api/flow-threats/` are one `/api/threats/`; `/api/trust-zones/` is `/api/zones/`; `/api/trust-boundaries/` is `/api/boundaries/`; `/api/data-flows/` and `/api/data-flow-assets/` are `/api/flows/` and `/api/flow-assets/`. The zone protection, `add_system`, `remove_system`, and `assign_system` actions are removed. Threat severity fields are replaced by `rating`; risk score columns by `inherent`, `residual`, and `target`; the risk `response` by `status` and a responses endpoint; flow and boundary authentication booleans by lists. `format_metadata` is read-only. The full table is in the [API overview](api/overview.md#changes-in-this-release).
- **MCP output fields changed.** `list_threat_models` returns `methodologies`, `lifecycle_phase`, `approved_at`, `primary_system_name`, `serial_number`, `version`, and `blueprint_count`, and `risk_scoring_method` uses the new values. Library components carry `kind`, and `search_component_library` takes a `kind` filter. Library countermeasures carry a `description`, and the countermeasure search matches it.
- **Library pack templates.** The template keys `authenticated` and the old `zoneType` family are refused; packs use `authentication` lists, spec zone types with an explicit `trustLevel`, `flowType`, `boundaryType`, and `kind`. All shipped packs are converted.
- **The shared magic-link payload** uses the unified threat shape: one list of threats with `number`, `display_number`, `whole_system`, and `targets`.

### Threats and countermeasures

- One threat table. A threat is one scenario with any number of targets: components, flows, zones, boundaries, or the whole system. It appears under each target in the analysis tree, marked shared, and counts once.
- Numbers: every threat is `T<n>` and every countermeasure `C<n>`, per model, never reused, kept through export and import, and searchable (`T7`).
- Ratings replace severities: one rating form for threats and risks with the qualitative matrix (1 to 25), OWASP Risk Rating, or a level picked directly; levels gain `info`; impact categories (including safety), estimated loss, currency, and range under Advanced. Residual risk lives on risks only.
- Countermeasure scope and provider: **Applies to** (components, flows, zones, boundaries; empty means the whole system), **Implemented by** (components and another party), **Source** (free text), and effectiveness with a "not assessed" state. Scope changes no threat's status; a control counts for a threat only when linked to it.
- Zone protections are retired. Nothing is inherited across zones any more; the "Inherited from" badge and the review dialog are gone.
- A waived countermeasure keeps its reason in a field of its own, `waiver_reason`, exported as `precogly:waiver-reason`. The reason used to be sent to the evidence URL field, which refused any text that was not a URL, so waiving with a reason never saved. The API does not require a reason; the screens ask for one.
- Controls that lose their last threat link are kept (unless untouched library output) and listed under **Controls not linked to any threat**, left out of gap and coverage figures.
- Library threats are generated when a node or flow is first placed, when a technology or flow type changes, or when a flow is reconnected, never on an ordinary save. Deleted library threats stay deleted; add one back from the library with **+ Add** in the Threats column. A pack upgrade changes nothing in any model and no longer breaks library links.
- Changing a component's technology keeps the component, its flows, and its threats with their numbers.
- One **threat actor** per threat: one of the model's threat actors, a common threat actor (State Actor, Hacktivist, Insider Threat, Competitor, Opportunist, Organized Crime), or free text. Picking a common one adds it to the model's threat actors, so it is reusable and exports with its CycloneDX persona archetype. Abuse cases pick from the same list, without free text. **Manage threat actors** creates and edits them. "Threat actor" replaces "Actor", "Abuser" and "persona" on screen; the API and the export keep `persona`.
- Threat and control statuses are enforced in the services, so the Security Team gate on platform status also applies to imports.

### Diagrams, zones, boundaries, flows

- A threat card in the diagram's side panel opens the threat modal, the same one as the threat analysis screen: rename, triage with a rationale, description, rating, categories, threat actor, sources, impact, objectives, targets and delete. Triaged threats sit under the cards on a collapsed "N triaged" line, from where they can be reopened. A card's countermeasure status follows the workspace rules (Planned asks for an owner, Waived for a reason), shows a status from an import such as In Progress instead of a blank, and offers Platform to the Security Team.
- Zones have a type (thirteen CycloneDX values, `trust` by default) and an optional trust level (0 to 100, trust and network zones only; no more default of 75).
- Boundaries have a type and crossing requirements shaped like the specification: authentication and authorization lists with the `none` rule, data validation, logging, monitoring, and a rate limit policy; two boundaries between the same zones are allowed. Whether a flow crosses a boundary is computed from the boundaries drawn.
- Flows have a type (`data`, `message`, `event`, `control`, `signal`, `energy`, `physical`, `process`, `financial`); protocol and encryption apply to the data-like types; authentication is a list of methods with an "Authenticated, method not specified" quick choice. Library threats apply per flow type.
- Components have a kind (the CycloneDX asset type), defaulting from their category.
- **Show flows** filters the canvas by flow type: the physical view.
- AI DFD generation asks the model for boundaries between zones (drawn as trust boundary edges with type, authentication and authorization), data store types, library kinds, one flow per direction, and trust levels by band. Actors get no zone, so no empty external zone is drawn.
- A System Scope box is a system or subsystem asset, optionally linked to an inventory system; saving a diagram no longer creates or deletes inventory systems. The per-component System select is gone.
- Blueprints: a model has one structural view by default and can have more. The switcher appears only with two or more; each blueprint has its own primary DFD. **Manage blueprints** adds, renames, reorders, and deletes with a preview.

### Risks

- Risks have a lifecycle status (identified, assessed, mitigated, accepted, transferred, retired), a statement, domains (including safety), business objectives, and a read-only exposure derived from the linked threats. The board groups by status; bulk update sets status or owner.
- Responses replace the single response dropdown: strategy, description, status, owner, target date, and, under Advanced, cost, priority, and the countermeasures the response relies on.
- Scoring methods are `qualitative-matrix` (default) and `owasp-risk-rating`; FAIR and Mozilla RRA are listed as not yet available. The method cannot change while the model has risks.

### Context, review, approval

- Assumptions are rows with a validity (unverified, verified, invalid, unknown) and, under More, a topic, owner, impact, validation method and date, and related components. They belong to a blueprint.
- Business objectives, with criticality and owner, can be linked from threats and risks.
- Methodologies on the model (STRIDE by default; spec values or a custom name). The STRIDE summary in reports shows only when STRIDE is among them.
- The scope lock is replaced by review and approval: **Mark reviewed**, **Approve** (Security Team), **Revoke**, with a sign-off view that lists unverified assumptions and open risks. A content digest decides **Changed since approval**; undoing the change restores the approval. Lifecycle phase, validity period, and review frequency sit under Advanced, and **Review due** shows when the validity period has passed. Closes #348.
- Each model has a primary system (optional) chosen from the inventory, or created in place; the **Systems** page under Settings shows which models use each system. A system that is some model's primary system cannot be deleted on its own; deleting one that is only linked from diagrams unlinks and deletes nothing inside models.
- Related models have a type (depends on, is a subsystem of, is related to, is superseded by) with loop checks; the Overview tab lists links in both directions.
- Every model has a serial number and a version; **Copy BOM-Link** copies `urn:cdx:<serial>/<version>`.
- Use cases and abuse cases are editable. A use case leads to abuse cases, an abuse case leads to threats, and threats lead to countermeasures; every link to the diagram, a threat actor, or a business objective is optional. Threat analysis gains a third view, **By Use Case**, with four numbered columns (use cases, abuse cases, threats, countermeasures) and gap badges that do not change the completion score. A threat's detail panel shows **From abuse cases**. Editing them shows **Changed since approval**, covered by the one-time change already listed above. Import and export read and write the links, with two new properties named `precogly:abuse-cases`. See [Use Cases and Abuse Cases](concepts/use-cases-and-abuse-cases.md) and the [API overview](api/overview.md).

### Import and export

- The adapter is rewritten on the pinned CycloneDX 2.0 schema (commit `f6dcf4d3`, 2026-10-07). Every export passes the schema and reference-integrity checks; every seeded model exports clean.
- Import never rejects a TM-BOM: schema findings and everything that cannot be stored become warnings, and the content is kept and written back on export. Import does not count as approval; the file's approval is shown as history. An imported model gets a fresh serial number; the original is kept, and BOM-Links resolve through it.
- Documents from other tools: scenarios with several targets become one threat with several targets (#533); a scenario naming several threats is split; actors that are flow ends become external actor components; per-scenario control links through `precogly:mitigates` (#529); several blueprints import in full (#538); a blueprint without a Precogly canvas gets a generated diagram (#288); the importing user's team owns the model (#337); compliance mappings resolve to installed frameworks or travel as snapshots (#342); impact descriptions round-trip (#343).
- A risk response's `targetDate` becomes the due date of each control it names that has no `precogly:due-date` of its own; with several responses the earliest wins.
- Import warnings say how to fix the file where they can (a missing required field, a standard's requirement under `definitions.requirements` instead of `definitions.standards[].requirements`, a `satisfies` entry that is not a reference, a date format, an unknown status), and one warning lists the custom properties Precogly does not read (most are written back on export, but not those on threat actors, visualizations and a few other objects). `satisfies` written as objects and compliance requirements under `definitions.requirements` are not valid 2.0 and are not imported.
- The `precogly:` property registry is one list, generated into the guest editor and printed in [Importing and Exporting](guides/importing-exporting.md).
- A threat typed in by hand exports the categories picked on it in its threat definition's `categories`, where other CycloneDX tools and the guest editor read them; a library threat's own categories stay in `precogly:instance-categories` on the scenario, since its definition is shared. On import, a custom threat's categories that name an installed taxonomy entry become editable entries on the threat instead of a locked snapshot.
- Passthrough keeps attack trees, attack paths, abuse cases, other tools' properties, and unknown fields; stale references are repaired on export with a warning.
- Values Precogly holds only in part are written back while the row still holds what it was imported as: an owner who is not a member (controls, risks, responses), an effectiveness rating, a response status stored as planned (such as `proposed`), a risk domain's priority and description, custom risk domains, and `satisfies` refs to engineering requirements. An imported file's `definitions.standards` is written back whole, with its refs, and mappings made in Precogly are added to it. What Precogly does not model is listed in [Importing and Exporting](guides/importing-exporting.md#what-precogly-does-not-model).

### Workspace

- One URL per tab (`/threat-models/<id>/overview`, `threat-analysis`, `risk-analysis`, `pentests`, `reports`) and per Threat Analysis view (`/threat-analysis/components`, `/use-cases`, `/table`). Reload keeps the tab and view; Back and Forward move between them. `?threat=T17` and `?countermeasure=C5` open the matching dialog.
- Overview: collapsible sections, with diagrams and **+ New DFD** beside the completion checklist at the top, a one-row Review, then three buttons (**System**, with Details and Context tabs; **Business objectives**; **Use cases**) that open dialogs, **Connections** (related models, library packs, team members, and a Blueprints card, formerly Connected Systems), and **Reference images**. The counts strip is gone.
- Threat Analysis: a threat row shows number, title and state; a countermeasure row shows the status dot with its word, number and name. Everything else is in a threat or countermeasure dialog. The screen opens on the first node with threats, and **Analyze Threats** in the DFD editor opens on the node or flow selected there. "Exposed" shows once per level: the tab badge, each tree row and each threat row.
- Overdue countermeasures: past their due date and not yet implemented, verified or platform. The Countermeasures column shows an **N overdue** chip that filters it; an **N overdue** button in the toolbar lists every overdue countermeasure of the model.

### Reports, CSV, Word, pentests, MCP

- Report sections start collapsed, and the report type is a dropdown beside the model's name.
- The Compliance and Full reports have a **Compliance Matrix**: for the framework you pick, one row per requirement with its state (Satisfied, Covered, Partial only, Not covered), the countermeasures mapped to it, their threats and an overdue mark. Coverage is stated against the installed pack, which may hold only part of a standard. It is also in the Word report and has its own CSV.

- Reports gain Review and approval, Business objectives, Countermeasure detail, and Unattached controls sections; one threat list with numbers and targets replaces the two lists by component and by flow; the Inherited countermeasures section is gone. Architecture shows zone and boundary types, trust levels, and crossing requirements.
- CSV and Word exports carry number and target columns and lose the inherited and residual severity columns; a new Assumptions CSV.
- The pentest scope groups test cases by target (component, flow, zone, boundary, system) with `T` and `C` numbers (#590).
- Dashboard counts include the `info` level.
- The STRIDE summary counts a threat under each of its STRIDE categories, so a threat with three categories shows in all three; the total is the number of active threats. Categories a custom threat kept from an import now count too. Each report threat carries `stride_categories` beside `stride_category`.
- MCP: see the breaking changes above; the roadmap's export tool is single-format.

### Guest editor

- Reads and writes the same TM-BOM shape as the backend, generated from the same spec lists. Threats with several targets, zones and boundaries as targets, whole-system threats, controls linked to several threats, numbers stored in the file, zone, flow, and boundary types, and the `info` level.
- A file keeps its serial number across saves; the version goes up when the content changed.
- Edits the first blueprint; further blueprints are kept and written back, with a notice. Problems while opening a file are listed on screen.
- Opens files saved by the earlier guest editor: the diagram layout, threat names, statuses and STRIDE categories, countermeasure links, session details, criticality, data asset ratings and out-of-scope items come across, with a notice to save the file in the current format.

### Library packs

- Pack upgrades update rows in place, so library links in models survive.
- Templates carry spec zone types with explicit trust levels, flow types, boundary types, component kinds, and authentication lists; the OT/ICS pack models Purdue levels as nested network zones with signal and control flows, device components, and a network boundary. A third sample model, "Sample LNG Process Control", is seeded.
- Threat joins can say which flow types a threat applies to (`flow_types`); an empty list means the data-like types.

### Credits

- The countermeasure `source` field, the `satisfies` import with snapshots for frameworks that are not installed, the evidence external reference, the overdue filter, and the CycloneDX POA&M groundwork came from PR #559 by [JJediny](https://github.com/JJediny) and were absorbed into this branch. The ported tests keep a note of their origin.
- The compliance matrix rebuilds the idea of PR #561 by [JJediny](https://github.com/JJediny) as a framework-neutral report section, with his access-isolation test and snapshot approach.
- The workspace simplification follows an outside UX review of the Overview and Threat Analysis screens.

---

## v0.4.0

**Release date:** September 15, 2026

The v0.4.0 release adds AI-powered DFD generation, a vendor-neutral AI/ML threat library, a redesigned threat triage workflow, and expanded AWS coverage.

### AI and library packs

- Added AI-powered DFD generation from architecture diagram images. A two-step flow uses a vision model to extract components, flows, and zones, then a text model generates canvas data with layout correction.
- Added vendor-neutral AI/ML threat library pack with 55 threats, 53 countermeasures, 12 components, and OWASP LLM/Agentic/MCP Top 10 taxonomies. Cross-pack AI references wired into the AWS pack.
- Expanded AWS library pack to 41 components with full taxonomy and compliance mappings, new DFD templates, and official AWS icons.
- Added STRIDE Worksheets pack with a STRIDE per Interaction table template for facilitating threat modeling sessions.

### Threat triage and control classification

- Replaced binary threat dismissal with a five-status triage workflow: Open, Accept, Mitigate, Delegate, Eliminate. Triaged threats require a decision rationale for audit traceability.
- Split the single `control_type` field into a multi-value `control_functions` list and a separate `control_nature` field (technical, administrative, or physical). Removed `procedural` from valid control function values.
- Migrated library packs and MCP server to the new control_functions/control_nature schema.

### CycloneDX TM-BOM interoperability

- Improved CycloneDX round-trip fidelity: triage status, control functions/nature, taxonomy categories, and assumptions now survive import and export via `precogly:*` properties.
- Improved CycloneDX import error messages with actionable detail about which entity failed.

### Security and OAuth

- Precogly now runs as an OAuth 2.1 authorization server.
- Added gitleaks support in CI and precommit.
- Fixed stored XSS via ComponentLibrary.icon_svg.

### DFD editor

- Added table node type with configurable size and text wrapping.
- Folded AI threat ranking into the Add Threat dialog and retired the standalone owl affordance.
- Added DFD notation switching (DFD3 / Yourdon-DeMarco).
- Allowed adding taxonomy entries to individual threat instances.

### Bug fixes

- Fixed guest editor import losing DFD layout by normalizing snake_case keys from backend export to camelCase.
- Fixed trust zone count inflation across multiple DFDs.
- Fixed CASCADE-delete on compliance requirement mappings.
- Fixed outdated and wrong MITRE taxonomy entries.
- Fixed image export cropping and added an export options dialog.
- Brought frontend CountermeasureStatus enums in sync with backend.

[View the full generated changelog](https://github.com/precogly/precogly/blob/main/CHANGELOG.md)
or [download v0.4.0](https://github.com/precogly/precogly/releases/tag/v0.4.0).

---

## v0.3.0

**Release date:** July 31, 2026

The v0.3.0 release expanded Precogly's interchange, AI-assisted modeling, risk,
reporting, and guest-editor workflows.

### Interchange and libraries

- Added CycloneDX 2.0 Threat Modeling BOM import and export alongside TM-Library JSON.
- Added full CAPEC, CWE, MITRE ATT&CK, and MITRE ATLAS taxonomy packs.
- Enriched exported models with Precogly metadata while retaining standard format compatibility.

### Threat modeling workflow

- Unified component and data-flow countermeasures into a shareable countermeasure model.
- Added countermeasure due dates, external ticket links, and history records.
- Added the risk register with table and Kanban views.
- Added the Pentests Scope workspace for deriving test priorities from a threat model.

### AI assistance

- Added grounded threat suggestions based on installed library packs.
- Added per-organization bring-your-own-model provider configuration.
- Added organization-level AI token usage tracking and reporting.

### DFD and guest editor

- Added DFD3 and Yourdon-DeMarco notation switching.
- Added threat visibility on the DFD canvas and improved canvas interactions.
- Expanded the guest editor with system context, threats, countermeasures, local
  CycloneDX save/open, image export, and Word report generation.

### Reports

- Added CSV exports for threats, countermeasures, risks, and compliance coverage.
- Added Word report generation for offline review.

[View the full generated changelog](https://github.com/precogly/precogly/blob/main/CHANGELOG.md)
or [download v0.3.0](https://github.com/precogly/precogly/releases/tag/v0.3.0).

---

## v0.2.0

**Release date:** May 26, 2026

35 merged PRs covering features, bug fixes, architecture improvements, and operational readiness.

### Features

- Delete functionality for components and countermeasures in Threat Analysis view ([#79](https://github.com/precogly/precogly/pull/79))
- Actor and attacker impact fields added to threat records ([#70](https://github.com/precogly/precogly/pull/70))
- Show/hide password toggle on login and signup forms ([#64](https://github.com/precogly/precogly/pull/64))
- Threat model import/export — added ThreatPersona/ThreatSource models, fixed round-trip fidelity ([#86](https://github.com/precogly/precogly/pull/86))
- Cross-framework requirement mappings for compliance overlays ([#50](https://github.com/precogly/precogly/pull/50))
- Improved threat model completion status indicators ([#84](https://github.com/precogly/precogly/pull/84))
- Threat libraries can now be imported without compliance packs ([#98](https://github.com/precogly/precogly/pull/98))
- Schema version added to pack.yaml with validation ([#95](https://github.com/precogly/precogly/pull/95))

### Bug Fixes

- Threat materialization on re-sync — generate threats for existing components/flows and recalculate risks on orphan deletion ([#63](https://github.com/precogly/precogly/pull/63))
- Compliance overlay instances not refreshed after pack update ([#60](https://github.com/precogly/precogly/pull/60))
- Library packs can be removed and re-added to threat models ([#57](https://github.com/precogly/precogly/pull/57))
- Data flow threats no longer auto-populated from unrelated library packs ([#46](https://github.com/precogly/precogly/pull/46))
- Filter threat picker by component's library ([#55](https://github.com/precogly/precogly/pull/55))
- Taxonomy pack slug mismatch fix ([#65](https://github.com/precogly/precogly/pull/65))
- String-list format in components-threats.yaml now rejected at validation time ([#74](https://github.com/precogly/precogly/pull/74))
- Pack version mismatch — sync_all_packs_from_source now correctly returns success=False ([#73](https://github.com/precogly/precogly/pull/73))
- Provider parsing, component matching, and UI fallback fix ([#48](https://github.com/precogly/precogly/pull/48))
- Form field overflow in modals ([#35](https://github.com/precogly/precogly/pull/35))
- Forgot password element positioning fix ([#36](https://github.com/precogly/precogly/pull/36))
- npm audit vulnerabilities resolved ([#62](https://github.com/precogly/precogly/pull/62))
- tsconfig baseUrl deprecation fix ([#67](https://github.com/precogly/precogly/pull/67))
- Validation improvements with messages bubbled up to frontend ([#78](https://github.com/precogly/precogly/pull/78))
- Component category enums unified, control_type values consistent across stack ([#87](https://github.com/precogly/precogly/pull/87))

### Architecture / Performance

- Pack resolution simplified — use filesystem as source of truth with O(1) path-based lookup ([#47](https://github.com/precogly/precogly/pull/47), [#54](https://github.com/precogly/precogly/pull/54))
- Pack directory structure simplified and libraries UI improved ([#89](https://github.com/precogly/precogly/pull/89))

### DevOps / Operational Readiness

- CI workflow added for PR checks — pytest (via docker compose) + tsc ([#90](https://github.com/precogly/precogly/pull/90), [#91](https://github.com/precogly/precogly/pull/91))
- Branch protection enabled on main (1 review required, status checks must pass)
- release-please workflow added for automated releases ([#93](https://github.com/precogly/precogly/pull/93))
- Version numbers reconciled across frontend, backend, and docs ([#92](https://github.com/precogly/precogly/pull/92))
- GitHub Milestones set up for roadmap visibility

### Documentation

- Added recipes section with IEC 62443 and EU banking recipes ([#44](https://github.com/precogly/precogly/pull/44))
- CONTRIBUTING.md added and updated ([#42](https://github.com/precogly/precogly/pull/42), [#49](https://github.com/precogly/precogly/pull/49))
- Docs for threat model import/export ([#68](https://github.com/precogly/precogly/pull/68))
- Docs for multiple DFD creation ([#76](https://github.com/precogly/precogly/pull/76))
- README updated with OWASP affiliation ([#71](https://github.com/precogly/precogly/pull/71))
- Discord link added to README ([#85](https://github.com/precogly/precogly/pull/85))

[View on GitHub](https://github.com/precogly/precogly/releases/tag/v0.2.0)

---

## v0.1.0 - First stable release

**Release date:** April 28, 2026

Initial public release of Precogly.

### Highlights

- Core threat modeling workflow
- DFD editor with nested components, trust zones, and trust boundaries
- Library packs (AWS, Azure, GCP)
- Threat analysis and reporting
- Import and export TM-BOM style JSON files
- Collaborative workspaces with roles and permissions
- Compliance mapping (DORA, CRA, ASVS, NIST CSF, SOC 2)
- Reference image support
- REST API with OpenAPI documentation

### Notes

- Early-stage release. APIs and data models may change.
- Recommended for evaluation and feedback, not production use.

[View on GitHub](https://github.com/precogly/precogly/releases/tag/v0.1.0)
